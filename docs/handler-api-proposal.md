# Handler API redesign (M5): proposal

Status: steps 1 and 2 of "Suggested order of work" are implemented on HTTP/1.1
(`src/http/exchange.zig`, `src/mailbox.zig`); step 3 (request bodies) waits
until after h2. Decisions taken on the **(decide)** items:

- The name is `Exchange` (h2/h3 use "stream" for something else).
- `response_timeout_s` is a separate config value for `later()` exchanges;
  a stream gets `request_timeout_s` between writes; `ex.setTimeout(seconds)`
  overrides either for one exchange.
- `handleBody` chunks (step 3) will always be copied by the handler, today's
  rule for `Request`.
- `sendfile`/`splice` through `writeBorrowed` waits for kTLS.

Differences from the text below, as implemented: `ex.respond(head, body)` and
`ex.startStream(head)` take a `Head { status, headers, content_length }`;
`writeBorrowed(bytes, release)` takes an optional `Release { ctx, func }`;
`resp.setContentLength(n)` must be called before `resp.stream()`; `abort()` on
a `later()` exchange that has not responded closes the connection without a
response; a `finish` short of the declared Content-Length aborts the exchange.

## What has to change, and what must not

Today a handler is one synchronous call:

```zig
pub fn handleRequest(self: *Handler, req: *per.Request, resp: *per.Response) void
```

The session parses a request, waits until the whole body is buffered (up to
`max_body_size`), calls the handler, and serialises `resp` into the worker's
`Out` buffer when it returns. `Request` and `Response` are one object per
worker, reused for every request. That shape is why the plaintext numbers in
PLAN.md are what they are: no allocation, no queue, no indirection, pipelined
responses batched into one write.

It can't express:

1. **Streaming responses**: a body produced over time or too large to hold
   (HTTP/1.1 chunked encoding, h2/h3 DATA frames as data becomes available).
2. **Streaming request bodies**: uploads larger than `max_body_size`, or
   handled as they arrive; also rejecting a request on its headers before the
   body is sent (`Expect: 100-continue` today always says yes).
3. **Trailers**, in both directions (gRPC needs response trailers).
4. **Responding later**: from another thread, after a database call, or
   after waiting on something; and with h2/h3 multiplexing, one slow
   request must not hold the connection.
5. A protocol-independent shape: the same handler behind HTTP/1.1, h2 and h3.

What must not change: the synchronous case keeps its cost. A handler that
fills `resp` and returns must not allocate, queue, or take a lock, on any
protocol.

## Proposal

### 1. The fast path stays as it is

`handleRequest(req, resp)` keeps its signature and meaning. If the handler
fills `resp` and returns, the response is complete, exactly as today. The
session checks one field on `resp` after the call to see whether the handler
asked for anything else. Existing handlers compile and behave unchanged.

### 2. `Exchange`: a request that outlives `handleRequest`

Inside `handleRequest`, a handler may turn the request into an exchange:

```zig
pub fn handleRequest(self: *Handler, req: *per.Request, resp: *per.Response) void {
    if (std.mem.eql(u8, req.getPath(), "/events")) {
        resp.addNewHeader("content-type", "text/event-stream") catch {};
        const ex = resp.stream() catch return; // head is sent now, body follows
        self.subscribers.add(ex);
        return;
    }
    if (std.mem.eql(u8, req.getPath(), "/report")) {
        const ex = resp.later() catch return; // nothing sent yet
        self.jobs.submit(ex, req.body);       // another thread responds
        return;
    }
    resp.setBodyBorrowed("hello");            // fast path, unchanged
}
```

- `resp.stream()` sends the status line and headers now, then the body is
  written with `ex.write(...)` and ended with `ex.finish(trailers)`.
- `resp.later()` sends nothing yet. Later, from any thread,
  `ex.respond(status, headers, body)` sends a complete response, or
  `ex.startStream(status, headers)` turns it into a stream.

`per.Exchange` is a small **value** handle `{ worker, slot, generation }`,
not a pointer. Every call checks the generation, so a handle kept after the
exchange ended (client gone, already finished) returns `error.Closed`
instead of touching freed memory. This is the lesson from the WebSocket
rework, where `*ws.Conn` is only valid until `handleWSDisconn` returns and
handlers have to manage that window themselves; a value handle removes the
hazard.

Exchange state lives in a per-worker slab sized from config
(`max_exchanges_per_worker`), like the connection slab: no allocation per
request, and a full slab makes `resp.stream()`/`resp.later()` return
`error.TooManyExchanges` (the handler can still answer synchronously, say
with 503).

### 3. Writing from any thread

`ex.write`, `ex.respond`, `ex.finish` may be called from any thread. They
take the exchange's lock, append to its send queue and post `(slot,
generation)` to the owning worker's mailbox, the same mechanism `ws.Conn.send`
uses today (deduplicated posts, a waker write only when called from another
thread, overflow triggers a full flush). Called on the worker thread itself
(inside a hook), the queue is drained in the same event-loop iteration
without a wakeup.

The queue holds:

- copied bytes, in pooled chunk buffers (same pool discipline as read
  buffers);
- borrowed bytes, `ex.writeBorrowed(bytes, ctx, release)`: zero-copy, and the
  worker calls `release(ctx)` on its own thread once they are written. This
  is the streaming equivalent of `setBodyBorrowed` (file chunks, cached
  blobs), and where `sendfile` slots in later for plaintext h1.

**Backpressure.** The queue is bounded (`max_exchange_queue_bytes`, like
`websocket_max_send_queue_bytes`). Over the limit `write` returns
`error.WouldBlock` and the exchange remembers that the producer is waiting;
when the queue drains below half, the worker calls the optional hook
`handleWritable(ex)` on its thread. The window that matters differs by
protocol (socket buffer for h1, stream and connection flow-control windows
for h2/h3), but the handler only sees "queue full" and "writable again".

### 4. Request bodies

By default bodies are buffered before `handleRequest`, as now.

A handler that wants the head first implements an optional hook:

```zig
pub fn handleHead(self: *Handler, req: *per.Request, resp: *per.Response) per.BodyMode
```

called once the headers are parsed. It returns:

- `.buffer`: continue as today (default when the hook is absent);
- `.reject`: `resp` is the answer (say 413 or 401); the body is not read.
  With `Expect: 100-continue` the client never sends it; without, h1 does a
  lingering close and h2/h3 reset the stream with `NO_ERROR` after the
  response (RFC 9113 §8.1);
- `.stream`: `handleRequest` is called immediately with an empty body, and
  the body arrives through `handleBody(ex, chunk: []const u8, end: ?Trailers)`
  on the worker thread. `100 Continue` is sent at this point and not before.

Streamed bodies get flow control from not reading (h1) or withholding
`WINDOW_UPDATE` (h2) or `MAX_STREAM_DATA` (h3) while the handler has not
consumed the previous chunk: `handleBody` returns `.more` or `.pause`, and a
paused exchange resumes with `ex.resumeBody()`. Chunks are slices into the
read buffer, valid only during the call, like `Request` today.

### 5. Trailers

- Request trailers: `req.trailers` when the body was buffered; the final
  `handleBody` call otherwise. Today the chunked decoder parses and drops
  them, so the parser change is small.
- Response trailers: `ex.finish(trailers)`. HTTP/1.1 sends them in the last
  chunk only when the response is chunked; RFC 9110 §6.5 lets a recipient
  drop them, so they are dropped for a response with `Content-Length`. h2/h3
  send a trailing HEADERS frame.

Trailers are a fixed-capacity `Headers` value (the same serialise-on-add
buffer as response headers), so no allocation.

### 6. HTTP/1.1 specifics

- **Framing.** `resp.stream()` uses `Content-Length` if the handler set one
  with `resp.setContentLength(n)` (and `write` then errors past `n`, while
  `finish` errors if short), otherwise `Transfer-Encoding: chunked` (HTTP/1.0
  clients: close-delimited). Chunk framing is written by the worker as it
  drains the queue: one chunk per drain, header and trailing CRLF in the
  same `writev`, so many small writes coalesce.
- **Pipelining.** Responses must go out in request order. While an exchange
  is pending on a connection, the session stops parsing further requests
  (bytes stay buffered, reading pauses: the existing backpressure) and
  resumes when it finishes. Head-of-line blocking is inherent to HTTP/1.1;
  this keeps it bounded and simple. Pipelined requests already parsed before
  the exchange started keep their responses in `Out` behind it.
- **Timeouts.** A pending exchange keeps the connection on the active list
  with `request_timeout_s` measured from the last progress (bytes written or
  `ex` activity), the same rule as stalled writes today. A separate
  `response_timeout_s` for `later()` may be needed **(decide)**.

### 7. Lifecycle and errors

- **The client goes away** (connection closed, h2 `RST_STREAM`, h3
  `STOP_SENDING`): the worker marks the exchange closed, calls the optional
  `handleAbort(ex)` hook on its thread, and later calls on the handle return
  `error.Closed`. Borrowed buffers still queued are released.
- **The handler forgets an exchange**: the timeout above ends it (h1: close
  the connection; h2/h3: `RST_STREAM(INTERNAL_ERROR)`), and `handleAbort`
  runs.
- **Errors after the head was sent** can't become a 500. h1 closes the
  connection without the final chunk (so the client sees a truncated body);
  h2/h3 reset the stream. `ex.abort()` does this explicitly.

### 8. Across protocols

| | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---|---|---|---|
| `handleRequest` returns, `resp` filled | head + body in `Out`, as now | HEADERS + DATA, batched per connection | same, per QUIC stream |
| `resp.stream()` | chunked or Content-Length | HEADERS, then DATA as written | same |
| `ex.finish(trailers)` | last chunk + trailers | DATA(END_STREAM), or trailing HEADERS | same |
| backpressure | socket buffer | stream + connection windows | stream + connection credit |
| several pending exchanges | one at a time per connection | one per stream, up to `SETTINGS_MAX_CONCURRENT_STREAMS` | per stream |
| WebSocket | Upgrade, `ws.Conn` | extended CONNECT (RFC 8441) | extended CONNECT (RFC 9220) |

For h2/h3, `handleRequest` and the `Exchange` are per stream; the frame
layers stay I/O-free and only see "this stream has queued data". The
synchronous fast path on h2 is still one call and no allocation: the
response is serialised into the connection's output (HPACK into the frame
buffer) when `handleRequest` returns, exactly as h1 serialises into `Out`.

WebSockets over h2/h3 are a bidirectional exchange, so `ws.Conn` can later
sit on top of `Exchange` instead of a socket. That is a follow-up, not part
of this change.

### 9. Cost of the fast path

What the synchronous case pays, compared with today: one branch on
`resp.mode` after `handleRequest` returns, and `handleHead` (when defined)
is one more direct call per request, resolved at compile time with
`@hasDecl` like the WebSocket hooks. No vtables, no allocation, no atomics.
The exchange slab, queues and mailbox entries are touched only by requests
that opt in. Verification: `zig build bench` (session cycle, currently about
199 ns per pipelined request) and the pipelined ×16 load test must not
regress beyond noise.

## Alternatives considered and rejected

**Async functions or `std.Io` futures per request.** Zig removed language
async after 0.10, and the `std.Io` evented implementations in 0.17 are
young. A coroutine (and stack) per request, or a future per response, costs
memory and indirection on every request, and ties the hot path to an API
that is still moving. The worker loops use raw syscalls for this reason
(decided in M1). This could be revisited as a layer *on top of* `Exchange`
once `std.Io` settles.

**A blocking `std.Io.Writer` for streaming.** Natural to use, but a write
that blocks stalls every connection on that worker. A non-blocking `Writer`
adapter over the exchange queue (returning `error.WriteFailed` on a full
queue) can be offered later for code that wants a `Writer`.

**Pull-based bodies** (the handler returns an iterator; the worker calls
`next()` when writable). This fits generated content but not data produced on
other threads, which still needs a push path. Kept in part: `handleWritable`
gives the pull behaviour on top of the push API.

**Making every response an exchange.** A single model is simpler to
describe, but the fast path would then queue and track state for every
request; the pipelined ×16 numbers depend on not doing that.

**A closure per deferred request** (`resp.later(ctx, callback)` with an
allocated context). Allocates per request and still needs the generation and
lifetime rules; the slab-backed handle covers the same need without the
allocation.

**Handing requests to a thread pool.** Breaks one worker per core with no
cross-thread handoff (PLAN.md design rules). Handlers that want a pool can
have one: `resp.later()` plus a submit is exactly that, without the server
moving connections between threads.

**Separate handler interfaces per protocol** (`handleH1`, `handleH2Stream`,
...). Every application would implement everything twice; protocol details
belong in the layers.

## Suggested order of work

1. `Exchange` slab, value handles, `resp.later()`/`ex.respond()` on
   HTTP/1.1 with the pipelining rule; the mailbox generalised from WebSocket
   slots to `(slot, generation)` entries.
2. `resp.stream()`, chunked framing, `write`/`writeBorrowed`/`finish`,
   backpressure and `handleWritable`; response trailers.
3. `handleHead`, `.reject` with correct 100-continue behaviour, `.stream`
   request bodies with `handleBody`; request trailers.
4. Timeouts and `handleAbort`; then the h2 frame layer is written against
   this API from the start.

Each step with the usual proof: split-invariance tests on the session (a
streamed response must produce the same bytes however the writes are
split), end-to-end tests on both backends and over TLS, and the fast-path
benchmarks above.

## Open questions

- **(decide)** Names: `Exchange` vs `Stream` (h2/h3 already use "stream"
  for something else, which argues for `Exchange`).
- **(decide)** Whether `response_timeout_s` is separate from
  `request_timeout_s` for `later()` exchanges (long polling wants a long
  one, everything else a short one), or set per exchange
  (`ex.setTimeout(seconds)`).
- **(decide)** Whether `handleBody` chunks should be allowed to outlive the
  call by pinning the read buffer (zero-copy for large uploads) or always be
  copied by the handler (simpler, today's rule).
- Whether to expose `sendfile`/`splice` through `writeBorrowed` on plaintext
  h1 only, or wait for kTLS so it works the same over TLS.
