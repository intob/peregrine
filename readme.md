# Peregrine - a high-performance HTTP server in pure Zig
The goal: the fastest HTTP/1.1, HTTP/2 and HTTP/3 server, with TLS 1.3 and WebSockets, written in pure Zig. The only dependency is Zig's standard library: no libc on Linux, no OpenSSL. Supports Linux (epoll, optionally io_uring) and BSD/MacOS (kqueue) systems. Requires Zig 0.17.

Priorities, in order:
- Reliability
- Performance
- Simplicity

Where it is today: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSockets and TLS 1.3 work on every backend. See [PLAN.md](PLAN.md) for the roadmap and the architecture: every protocol layer is an I/O-free state machine driven by per-core event loops, so the layers stack (TCP → TLS → HTTP/1.1 or HTTP/2; UDP → QUIC → HTTP/3) and the same code runs on every backend.

Currently, all heap allocations are made during startup. Internally, no heap allocations are made per-request unless pre-allocated buffers overflow (for example, a request body larger than a pooled read buffer, or a response that can't be written in one go).

Note: This project has just started, and is not yet a complete HTTP server implementation. See the [Roadmap](#roadmap). The API is likely to change. It is currently NOT FIT FOR PRODUCTION use.

## Features

- Simple API
- Support for HTTP/1.0 and HTTP/1.1
    - Keep-alive and pipelining (pipelined responses are batched into one write)
    - Request bodies: `Content-Length` and `Transfer-Encoding: chunked`
    - `Expect: 100-continue`, `HEAD`, automatic `Content-Length` and `Date`
    - Strict parsing that rejects request smuggling vectors (see `src/http/parser.zig`)
    - Request size limits, idle/request timeouts (slowloris-resistant)
- Support for HTTP/2 (RFC 9113), over TLS with ALPN and over cleartext with prior knowledge (h2c)
    - HPACK, flow control, up to 128 concurrent streams per connection, graceful GOAWAY
    - The same handler serves HTTP/1.1 and HTTP/2; h2spec passes (146/146 over TLS)
    - Defences against rapid reset, CONTINUATION floods, HPACK bombs, control-frame floods and zero-window stalls
- Support for HTTP/3 (RFC 9114) over QUIC version 1 (RFC 9000, 9001, 9002), written from scratch
    - The same handler serves HTTP/1.1, HTTP/2 and HTTP/3, from the same worker threads
    - CUBIC congestion control, key updates, Retry, stateless reset, GSO batching, per-worker UDP sockets steered by connection ID
    - `Alt-Svc` is added to every response so browsers find HTTP/3
    - Interop-tested with aioquic, curl (ngtcp2) and h2load
- Streaming and deferred responses: `resp.stream()` writes a body over time (chunked on HTTP/1.1, DATA frames on HTTP/2 and HTTP/3), `resp.later()` answers from any thread
- Streamed request bodies: `handleHead` accepts, rejects (before `100 Continue`) or streams a request on its headers; `handleBody` gets the body as it arrives, with no size limit and with trailers, and can pause it (flow control holds the client back)
- Support for WebSockets
- TLS 1.3, written from scratch on top of `std.crypto` (no OpenSSL)
    - X25519MLKEM768 (post-quantum hybrid), X25519 and P-256 key exchange, HelloRetryRequest
    - AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305
    - ECDSA P-256/P-384 and Ed25519 certificates, ALPN, KeyUpdate
    - HTTP/1.1, HTTP/2 and WebSockets over TLS, on every backend
- Cross-platform IO Multiplexing
    - Kqueue support for BSD and MacOS systems
    - Epoll support for Linux systems
    - io_uring support for Linux (opt-in, `.backend = .io_uring`)
- Multi-Worker Architecture
    - Automatic worker scaling based on CPU core count
    - Configurable worker-thread count
    - Each worker accepts its own connections (`SO_REUSEPORT` on Linux), pinned to a core
    - Thread-safe request handling

## Benchmarks
Plaintext "Hello, World!" on Linux (Docker on an M2 Pro: kernel 6.12, aarch64). Server on 6 cores (6 workers), `wrk -t6 -c256 -d10s` on the other 6, over loopback. Two runs each; numbers vary by about 10% between runs, so treat epoll and io_uring as equal here. Same machine for client and server, so these are relative, not absolute.

| Requests/sec | NGINX | Peregrine (epoll) | Peregrine (io_uring) |
|--------|-------|-----|-----|
| Keep-alive | 767k–944k | 956k–1.09M | 995k–1.07M |
| Pipelined ×16 | 1.24M–1.47M | 8.2M–9.4M | 8.5M–8.8M |

HTTP/3 against nginx 1.29 and Caddy 2.11, same setup, `h2load --alpn-list=h3 -t6` on the other 6 cores. CPU/req is the server's CPU time per request; at "-c10 -m100" h2load is the limit for peregrine.

| HTTP/3 | Peregrine | NGINX | Caddy |
|--------|-----------|-------|-------|
| "Hello", 10 connections × 100 streams | 316k–321k req/s, 1.9–2.1 µs/req | 221k–227k, 4.8–4.9 µs/req | 160k–179k, 31–33 µs/req |
| 64 KiB, 10 × 10 | 77k–78k req/s (4.7 GB/s), 40 µs/req | 11k–12k, 149–155 µs/req | 6.5k–6.7k, 387–403 µs/req |

Reproduce: `zig build bench-server -Dtarget=aarch64-linux` (the server takes `[workers] [auto|epoll|io_uring] [port]`), and `zig build bench` for parser micro-benchmarks (about 190 ns to parse a 437-byte browser request with 8 headers).

The previous version, run using wrk on an M2 Pro (macOS) with 1000 connections:

| Metric | NGINX | h2o | Zap (Facil.io) | Peregrine |
|--------|-------|-----|----------------|-----------|
| Requests/sec | 81,852 | 149,267 | 167,963 | **175,675** |
| Avg Latency | 12.19ms | 8.54ms | **4.84ms** | 5.64ms |
| Latency Stdev | 4.19ms | 8.87ms | 2.23ms | 412.57μs |
| Latency +/- Stdev | 74.74% | 90.81 | 78.32% | **93.00%** |

Facil.io is still superior to this library as it is battle-tested, production-ready and supports TLS. While working on this library, I've seen just how well-implemented and stable Facil.io is...

Note that these benchmarks simply measure serving static GET requests, and they do not indicate real-world performance unless you're only serving static files. For the previous-version tests, the response length was 6150 bytes.

## Performance optimisations

- Raw syscalls (no libc on Linux), non-blocking sockets, edge-triggered events
- Event-driven architecture, one event loop per core, no cross-thread handoff
- SIMD scanning for the end of the head, request-target and header values
- Zero-copy request parsing: headers, path and body are slices into the read buffer
- Vectored IO: pipelined responses go out in a single `writev`
- Zero heap allocations per-request
- Read buffers are pooled and only held while a connection has unprocessed bytes, so idle keep-alive connections use no buffer memory
- Zero-copy response bodies with `setBodyBorrowed`
- `Date` header formatted once per second, not per request
- Timeouts without a syscall per connection (deadline-ordered intrusive lists)
- Linux: `TCP_DEFER_ACCEPT` plus reading straight after accept
- Header case-insensitivity handled when searching, not parsing (unused headers are not transformed)
- Query only parsed on demand
- Optimised header, method and version parsing

## Architecture

### Server
- Server configuration and initialization
- Worker pool management
- Signal handling for graceful shutdown
- Platform-specific I/O handlers

### Worker threads
- Accept connections (own `SO_REUSEPORT` listener on Linux; a shared listener elsewhere)
- Manage connections, timeouts and backpressure
- Feed bytes to the per-connection state machine (`src/http/session.zig`), which parses and handles requests and serialises responses without doing any I/O itself
- Write responses

### WebSockets
- No separate threads: after the upgrade a connection stays on the worker that accepted it, so WebSockets scale with cores like HTTP does
- Frames are decoded by an I/O-free per-connection state machine (`src/ws/protocol.zig`): resumable across reads, several frames per read, fragments reassembled, pings answered, close handshake done by the server
- Output is queued per connection and written as the socket allows; a peer that stops reading is closed after `request_timeout_s`

### Signal handling
The server handles the following signals for graceful shutdown:
- SIGINT (Ctrl+C)
- SIGTERM

## Usage

### Run the counter example server natively
```bash
zig build run-counter
```

### Run the counter example in a Linux Docker container

#### x86_64
```bash
zig build -Dtarget=x86_64-linux-musl && \
docker build -t counter . -f ./example/counter/Dockerfile && \
docker run -p 3000:3000 counter
```
#### aarch64 (ARM)
```bash
zig build -Dtarget=aarch64-linux-musl && \
docker build -t counter . -f ./example/counter/Dockerfile && \
docker run -p 3000:3000 counter
```

### Serve HTTPS
```bash
zig build run-https
curl --cacert example/https/server.pem https://localhost:3443/
```
Pass the PEM certificate chain and private key in the config. They are parsed at startup and needn't outlive `init`:
```zig
const srv = try per.Server(Handler).init(gpa, 443, .{
    .tls = .{
        .cert_pem = cert_pem, // leaf first, then intermediates
        .key_pem = key_pem, // PKCS#8 or SEC1; ECDSA P-256/P-384 or Ed25519
        .alpn = &.{"http/1.1"}, // the default
    },
});
```
RSA certificates aren't supported yet. Session resumption and 0-RTT aren't either: every connection does a full handshake.

### Serve HTTP/2
Over TLS, add `"h2"` to the ALPN list; on a plaintext port, set `h2c` to accept the HTTP/2 connection preface (clients with prior knowledge, such as `curl --http2-prior-knowledge`). Both ports keep serving HTTP/1.1.
```zig
const srv = try per.Server(Handler).init(gpa, 443, .{
    .h2c = true,
    .tls = .{ .cert_pem = cert_pem, .key_pem = key_pem, .alpn = &.{ "h2", "http/1.1" } },
});
```
Handlers need no changes: a request on an HTTP/2 stream arrives as the same `Request`, with `host` taken from `:authority`.

### Serve HTTP/3
Set `http3` alongside `tls`: each worker then also serves HTTP/3 on a UDP socket (the TLS port by default), with the same certificate and handler, and every response carries `Alt-Svc: h3=":443"` so browsers switch over.
```zig
const srv = try per.Server(Handler).init(gpa, 443, .{
    .tls = .{ .cert_pem = cert_pem, .key_pem = key_pem, .alpn = &.{ "h2", "http/1.1" } },
    .http3 = .{}, // .retry = true validates client addresses first
});
```

### Stream or defer a response
`resp.stream()` sends the status and headers now and returns an `Exchange` for the body; `resp.later()` sends nothing until `ex.respond` or `ex.startStream`, from any thread. Handles are values that stay safe after the exchange ends (calls return `error.Closed`).
```zig
pub fn handleRequest(self: *Handler, req: *per.Request, resp: *per.Response) void {
    if (std.mem.eql(u8, req.getPath(), "/events")) {
        resp.addNewHeader("content-type", "text/event-stream") catch {};
        const ex = resp.stream() catch return;
        ex.write("data: hello\n\n") catch {};
        ex.finish(&.{}) catch {}; // or keep the handle and write later
        return;
    }
    if (std.mem.eql(u8, req.getPath(), "/report")) {
        const ex = resp.later() catch return;
        self.jobs.submit(ex); // another thread calls ex.respond(.{ .status = .ok }, body)
        return;
    }
    resp.setBodyBorrowed("hello"); // the synchronous path, as before
}
```
A full queue makes `ex.write` return `error.WouldBlock`; the optional `handleWritable(ex)` hook is called once it drains. `handleAbort(ex)` is called if the client leaves or the exchange times out (`response_timeout_s` for `later()`, `request_timeout_s` between writes).

### Stream or reject a request body
By default a body is received whole (up to `max_body_size`) before `handleRequest`. The optional `handleHead` hook decides on the headers alone: `.buffer` (the default), `.reject` (answer with `resp` and don't read the body; no `100 Continue` is sent), or `.stream`. A streamed request calls `handleRequest` at once with an empty body; once it takes an exchange, `handleBody` gets the body as it arrives, on the worker thread, with no size limit. The last call has `end` set, with the trailers.
```zig
pub fn handleHead(_: *Handler, req: *per.Request, resp: *per.Response) per.BodyMode {
    if (req.findHeader("authorization") == null) {
        resp.status = .unauthorized;
        return .reject;
    }
    return if (std.mem.eql(u8, req.getPath(), "/upload")) .stream else .buffer;
}

pub fn handleRequest(self: *Handler, req: *per.Request, resp: *per.Response) void {
    if (std.mem.eql(u8, req.getPath(), "/upload")) {
        // The body follows through handleBody; answer with ex.respond.
        _ = resp.later() catch { resp.status = .service_unavailable; };
        return;
    }
    // ...
}

pub fn handleBody(self: *Handler, ex: per.Exchange, chunk: []const u8, end: ?[]const per.Header) per.BodyAction {
    self.queue.push(chunk); // copied: `chunk` and `end` are valid during the call
    if (end != null) {
        ex.respond(.{ .status = .created }, "stored") catch {};
        return .more;
    }
    // Pause while the queue is long; another thread calls ex.resumeBody().
    return if (self.queue.len() > limit) .pause else .more;
}
```
While a body is paused the client is held back by the transport: HTTP/1.1 stops reading the socket, HTTP/2 withholds `WINDOW_UPDATE`, HTTP/3 `MAX_STREAM_DATA`. If the response ends before the body does, the rest is not read (HTTP/1.1 closes the connection; HTTP/2 and HTTP/3 reset the request stream with `NO_ERROR`). Trailers of a buffered body are in `req.trailers`.

### Implement a server
```zig
const std = @import("std");
const per = @import("peregrine");

const Handler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.allocator = allocator;
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    pub fn handleRequest(_: *Self, _: *per.Request, resp: *per.Response) void {
        resp.addNewHeader("content-type", "text/plain") catch {};
        resp.setBodyBorrowed("Kawww\n"); // static data: no copy
    }
};

pub fn main(init: std.process.Init) !void {
    const srv = try per.Server(Handler).init(init.gpa, 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks until shutdown
}

```

Using Zig's comptime metaprogramming, the Server is compiled with your handler interface. Simply implement the `init`, `deinit` and `handle` methods. Compile-time checks have your back.

The configuration is minimal, with reasonable defaults. Simply provide an allocator and port number. Optionally set parameters in the configuration struct.

The server will shutdown gracefully if an interrupt signal is received. Alternatively, you can call `Server.shutdown()`.

## Memory management model

### Request lifecycle
The server manages request and response buffers internally, reusing them across requests to avoid allocations. `Request` fields (path, headers, body, trailers) are slices into the connection's read buffer and are only valid until `handleRequest` returns; a streamed body's chunks only during each `handleBody` call. When a handler processes a request, it must copy any data it needs to retain, as the underlying buffers will be reused for subsequent requests.

Response headers are copied as they are added, so their values can be freed straight away. For the body:
- `setBody(buf)` copies into the worker's response buffer (`response_body_buffer_size`).
- `bodyWriteBuffer()` + `commitBody(len)` let you format straight into that buffer.
- `setBodyBorrowed(buf)` sends `buf` without copying. It must stay valid and unchanged until the response is sent, so use it for static or cached content.

### Handler responsibilities
- Handlers own and manage their internal memory
- Any data extracted from requests must be copied before the handler returns
- Handlers are shared across multiple worker threads

## Need to know

### Memory usage
Each worker thread gets it's own resources (obviously). By default, the number of worker threads is equal to the number of CPU cores. Therefore, the memory usage will depend on allocated buffer sizes, stack sizes, and the number of worker threads. You can adjust these parameters in the configuration struct. Default memory usage per worker (epoll backend):
```
Workers:    Read buffer pool:   256 x 16KB = 4MB
            Response buffer:    1MB
            Output buffer:      64KB
            Connection slab:    16384 connections, ~2MB
            Stack size:         1MB

            Total:              ~8MB
```
Read buffers are only held while a connection has unprocessed bytes, so many idle keep-alive connections don't need many buffers. If the pool runs out, buffers overflow to the heap and are freed afterwards.

With TLS, each worker also preallocates `tls.buffer_pool_size` (default 64) record input buffers of 17KB and output buffers of 64KB, held on the same terms; an established connection keeps only its keys (about 300 bytes).

### Response headers
`Content-Length`, `Date` and `Connection` are set by the server (no `Content-Length` on 1xx/204 responses; `HEAD` responses keep the length but omit the body). Adding any of them, or `Transfer-Encoding`, with `addNewHeader` is a compile error, so they can't be duplicated by accident. Set `resp.close = true` to close the connection after the response.

Header keys and values containing CR or LF are rejected (`error.InvalidHeader`), which prevents response splitting.

### Query params
`req.parseQuery()` returns `!?std.StringHashMap([]const u8)` - an error union containing an optional hash map. The semantics are:
- Returns error.OutOfMemory if hash map insertion fails
- Returns null in two cases:
    - No query string exists (no '?' in path)
    - Malformed query string (missing '=' between key-value pairs)
- Returns the populated hash map on successful parsing

The `Request.query` hash map is cleared on the call to `parseQuery()`. Accessing the query field without first calling `parseQuery()` will expose stale data from previous requests. Emptying the hash map has a cost, and we should only pay that price if we want to use the query, not unconditionally for each request.

Example usage:
```zig
if (try req.parseQuery()) |query| {
    // use query hash map
}
if (req.query.get("some-key")) |value| {
    // it's safe to access the map directly after calling parseQuery
}
```

### WebSockets
Implementing WebSockets is easy. Simply handle the upgrade request, and add the WS handler hooks. Check out the working example in `./example/websocket`.
```zig
pub fn handleRequest(self: *Self, req: *per.Request, resp: *per.Response) void {
    if (std.mem.eql(u8, req.getPath(), "/ws")) {
        // You must explicitly handle the upgrade to support websockets.
        per.ws.upgrader.handleUpgrade(self.allocator, req, resp) catch {};
        return;
    }
    self.dirServer.serve(req, resp) catch {};
}

pub fn handleWSConn(_: *Self, conn: *per.ws.Conn) void {
    std.debug.print("handle ws conn... {d}\n", .{conn.fd});
}

pub fn handleWSDisconn(_: *Self, conn: *per.ws.Conn) void {
    std.debug.print("handle ws disconn... {d}\n", .{conn.fd});
}

// Called with each complete message: text, binary, ping, pong or close.
// Fragments are reassembled, pings are answered and close frames echoed
// before the handler sees them.
pub fn handleWSFrame(_: *Self, conn: *per.ws.Conn, frame: *per.ws.Frame) void {
    if (frame.opcode != .text and frame.opcode != .binary) return;
    // Reply to the client (queued; written as the socket allows)
    conn.send("Hello client!", false) catch |err| {
        std.debug.print("error writing websocket: {any}\n", .{err});
    };
}
```

The hooks run on the worker thread that owns the connection. A `*per.ws.Conn` is valid from `handleWSConn` until `handleWSDisconn` returns; `conn.send`, `conn.ping` and `conn.close(code, reason)` may be called from any thread in that window (for example to broadcast from another connection's handler), so a handler that keeps handles in a table must remove them in `handleWSDisconn` under its own lock. `conn.user` is free for per-connection state. Messages larger than `websocket_max_message_size` fail the connection with close code 1009; `send` fails with `SendQueueFull` once `websocket_max_send_queue_bytes` are unsent.

## I need your feedback
I started this project as a way to learn Zig. As such, some of it will be garbage. I would value any feedback.

## This is no framework
This is not a framework for building web applications. This is purely a HTTP server designed from the ground up to be stable and performant. There are no built-in features such as routing or authentication. There are some utilities for common use-cases, such as serving a directory of static files, `util.DirServer`.

If you want a more substantial HTTP library, I suggest that you look at [Zap](https://github.com/zigzap/zap), built on [Facil.io](http://facil.io). Facil.io is an excellent battle-tested library written in C.

## Roadmap
Until these things are done, I don't think that this project can possibly be considered production-ready.

See [PLAN.md](PLAN.md) for the full checklist. In order:

1. TLS 1.3 follow-ups: io_uring support, fuzzing, faster handshakes, RSA certificates, resumption, kTLS on Linux
2. HTTP/2 follow-ups: RFC 9218 priorities, WebSockets over h2 (RFC 8441)
3. HTTP/3 follow-ups: connection migration, 0-RTT, pacing, ECN, PMTU discovery, GRO, the QPACK dynamic table, WebSockets over h3 (RFC 9220)
4. Throughout: `sendfile`, tuning io_uring until it beats epoll, WebSocket `permessage-deflate`, and verification with Autobahn, h2spec, quic-interop-runner, soak, adversarial and differential (HTTP Garden) testing
5. API reference

## Nice to have
- Windows support
- Templating util (possibly adapt util.DirServer to be composable)

## Thanks
Thank you to [Bo](https://github.com/boazsegev) for his advice (not all applied yet), and also for his library [Facil.io](https://facil.io). This served as a great model for robust server design, and a solid performance benchmark. The more I work on this project, the more I've come to appreciate Facil.io's astonishing performance under load.

Also, thanks to Karl Seguin for his excellent guide to [writing TCP servers in Zig](https://www.openmymind.net/TCP-Server-In-Zig-Part-1-Single-Threaded/). The start of this project was an exercise in learning Zig, and I found this guide to be very helpful for getting started.
