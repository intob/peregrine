# Peregrine: plan to finish the HTTP/1.1 server

Goal: the fastest HTTP/1.1 server possible, in pure Zig, std only. TLS comes later.
Target toolchain: **Zig 0.17**. Hot path: **raw syscalls** (decided).

Pure Zig is not the constraint. std covers raw syscalls, epoll/kqueue, io_uring and
SIMD (`@Vector`). The hot path is already well optimised. What's missing is
correctness under real traffic (the worker assumes one `read` = one whole request and
one `writev` = the whole response), and a few architectural choices that decide
whether it can be the *fastest*.

> Original findings were checked against `9361d4b` on Zig 0.16.0. Work is on the
> `http-core` branch, built and tested with Zig **0.17.0** on macOS (kqueue) and
> Linux 6.12 aarch64 in Docker (epoll).

## Status

| Phase | State |
|---|---|
| 0. Port to 0.17 | ✅ done |
| 1. Bug fixes | ✅ done |
| 2. Connection state machine | ✅ done |
| 3. HTTP/1.1 completeness | ✅ done except streaming responses (deferred, see below) |
| 4. Throughput architecture | 🟡 mostly done: io_uring works (opt-in) but isn't faster yet; sendfile, NUMA and WebSocket rework open |
| 5. Verification | 🟡 fuzzing and first benchmarks done; soak, adversarial and differential testing open |

New layout:

| File | Role |
|---|---|
| `src/sys.zig` | Raw syscall wrappers (direct to the kernel on Linux, libc on BSD) |
| `src/poller.zig` | epoll/kqueue: edge-triggered connections, level-triggered listener/waker |
| `src/http/parser.zig` | Zero-copy, strict request parser + chunked decoder |
| `src/http/session.zig` | I/O-free per-connection state machine, buffer pool, output batching |
| `src/http/worker.zig` | epoll/kqueue event loop: accept, read, process, write, timeouts |
| `src/http/worker_uring.zig` | io_uring event loop (Linux, opt-in) |
| `src/http/date.zig` | Cached IMF-fixdate `Date` header |
| `src/server_test.zig` | End-to-end tests over real sockets, run once per available backend |
| `bench/` | `zig build bench` (parser micro-benchmarks), `zig build bench-server` (load-test target) |

Test suite: 38 tests (`zig build test`), passing on macOS (kqueue), Linux with Docker's
default seccomp (epoll; io_uring is blocked there, so `.auto` falls back), and Linux
with io_uring permitted (epoll and io_uring end-to-end tests). To run the io_uring
tests in Docker, allow only `io_uring_setup`, `io_uring_enter` and `io_uring_register`
on top of Docker's default seccomp profile, rather than using `seccomp=unconfined`.

---

## Phase 0: port to Zig 0.17 ✅

- [x] `build.zig.zon`: `.name = .peregrine`, `.fingerprint`, `minimum_zig_version = "0.17.0"`
- [x] `build.zig`: `.root_module` everywhere; all 5 examples built; `b.args` →
      `run_cmd.addPassthruArgs()`; `zig build bench` step
- [x] `std.net` is gone: addresses come from `std.Io.net.IpAddress.parse` and are
      converted to `sockaddr` in `sys.zig`
- [x] `std.posix` no longer wraps the socket/poll syscalls: replaced by `src/sys.zig`
      (raw, uses `posix.system` + `posix.errno`) and `src/poller.zig`
- [x] `callconv(.C)` → `callconv(.c)`; signal handlers take `posix.SIG`
- [x] `GeneralPurposeAllocator` gone: examples use `main(init: std.process.Init)` and `init.gpa`
- [x] `alignedAlloc(u8, 16, n)` → `alignedAlloc(u8, .@"16", n)`
- [x] `std.time.Timer` gone: in-test benchmarks (100M-iteration loops in
      `zig build test`) removed; micro-benchmarks move to `zig build bench`
- [x] Also changed in 0.17 (not in the original list): the `**` array-repeat
      operator was removed (`@splat` / a comptime `repeat` helper), `@typeInfo`
      enums expose `field_names`, `std.meta.Int` → `@Int`, optimize modes are
      `.debug/.safe/.fast/.small`, `std.fs` file APIs → `std.Io.Dir` (used only at
      startup by the file/dir servers)
- [x] Existing rot: `root.zig` exported a nonexistent `ServerConfig` (now an alias of
      `Config`); examples used a stale `Server` signature (now `Server(Handler)`
      again, TLS mode removed until it lands as a transform layer)
- [x] **Decision:** raw syscalls behind `sys.zig`/`poller.zig`, not `std.Io`

**Done:** `zig build`, `zig build test` and all examples compile on 0.17.

---

## Phase 1: correctness bugs in the current code ✅

- [x] **Malformed header crashed the server** (`abc:` underflow). New parser
      handles empty values correctly; regression test `empty header value is valid`
- [x] **Header value OWS** trimmed on both sides (RFC 9112 §5)
- [x] **Header caps** removed (zero-copy slices; tested with a 4 KB cookie)
- [x] **Method parsing** matches the whole token; unknown methods → `501`
- [x] **Keep-alive** decided from the *current* request: HTTP/1.1 default
      persistent unless `Connection: close` (token list), HTTP/1.0 only with
      `keep-alive`
- [x] **Connection table overflow**: replaced by a per-worker slab indexed by slot,
      with generation counters so stale events for a reused slot are ignored
- [x] **`TCP_NODELAY`** now enabled. Instead of a syscall per accept, it's set on the
      listener, and a test verifies accepted sockets inherit it (Linux and macOS)
- [x] **Undefined kqueue event read**: the accept thread and its poll loop are gone
- [x] **WebSocket init race**: thread spawned after the struct is initialised
- [x] `accept_thread_count` underflow: option removed (no accept threads)
- [x] **1 ms poll timeouts**: workers block indefinitely with no connections, tick
      once per second otherwise; shutdown uses an eventfd/pipe waker
- [x] Found while porting:
  - [x] `SIGPIPE` wasn't ignored, so a client disconnecting mid-response could kill
        the process. Now ignored at startup
  - [x] WebSocket reader freed the frame payload on error (`errdefer`), a double free
  - [x] WebSocket server never closed sockets on error (fd leak)
  - [x] WebSocket payload-size check ran after reading, so oversized frames spun
  - [x] Unknown WebSocket opcodes were accepted
  - [x] Accepted sockets set `SO_SNDTIMEO`/`SO_RCVTIMEO` (no-ops on non-blocking
        sockets) and `SO_RCVBUF`/`SO_SNDBUF` (disables Linux autotuning). Removed:
        4 fewer syscalls per connection

---

## Phase 2: per-connection state machine ✅

- [x] Per-connection state (`Conn` in `worker.zig`, `Session` in `session.zig`):
      buffer, parse resume offset, chunked scanner state, pending write, request
      count, timer links
- [x] Connection slab preallocated (`max_connections_per_worker`, default 16384).
      Over capacity, new connections are accepted and closed (load shedding)
- [x] Read buffers come from a per-worker pool and are held **only while a connection
      has unprocessed bytes**, so idle keep-alive connections cost no buffer memory.
      Requests larger than the pool buffer temporarily get a heap buffer, up to
      the limits
- [x] Incremental parsing: `findHeadEnd` resumes where it stopped (SIMD LF scan);
      chunked bodies are validated incrementally and decoded in place once complete
- [x] Edge-triggered reads continue until `EAGAIN`, or a short read (nginx-style:
      saves one `read()` per event). All complete requests in the buffer are
      handled (pipelining), with responses in order
- [x] Write path: on a short write, unsent bytes are kept per connection (borrowed
      bodies by reference, worker-buffer bodies copied), and writing resumes on
      `EPOLLOUT`/`EVFILT_WRITE`. Write interest is registered once (no `epoll_ctl`
      toggling). Reading and parsing pause while output is pending (backpressure)
- [x] Pipelined responses coalesced into one `writev` (small bodies copied into the
      batch; a large one ends the batch)
- [x] Buffer compaction when a partial request reaches the end of the buffer
- [x] Close semantics: peer half-close still gets its responses, then close;
      `Connection: close` and error responses close after flushing
- [x] `Session` does no I/O: the worker feeds it bytes and writes its `Out`. A TLS
      layer can decrypt into the session buffer and encrypt `Out` without a second
      worker (TLS itself is not implemented)

**Done:**
- `session.zig` property test: 16 mixed pipelined requests (GET, Content-Length
  body, chunked body with extensions and trailers, 600-byte cookie, 3 KB response,
  leading empty line), fed byte-by-byte and in 199 random splits, gives
  byte-identical output. It caught a real bug: a lone `\r` of a leading empty line
  arriving in its own read.
- End-to-end test: 8 MB borrowed + 1 MB copied responses pipelined to a slow reader
  (partial-write path confirmed exercised), plus another connection served meanwhile.

---

## Phase 3: HTTP/1.1 completeness ✅ (one item deferred)

- [x] Request bodies: `Content-Length` (`Request.body`)
- [x] Request bodies: `Transfer-Encoding: chunked` (extensions and trailers are
      validated and discarded)
- [x] **Request smuggling defences**, each with a test: CL + TE rejected;
      duplicate/list/signed CL rejected; TE other than exactly `chunked` → 501;
      duplicate TE rejected; TE on HTTP/1.0 rejected; obs-fold, whitespace before
      `:`, bare CR, bare LF, NUL/control bytes rejected; chunk-size line, extension
      and trailer bare-LF rejected; missing/duplicate `Host` on HTTP/1.1 rejected
- [x] `Expect: 100-continue` (sent once, only while the body is outstanding;
      other expectations → 417)
- [ ] **Chunked / streaming responses: deferred.** The handler API is
      synchronous (`handleRequest` fills a Response and returns). Streaming needs
      an API decision first (a writer callback, or a resumable handler)
- [x] `HEAD`: headers with the body's `Content-Length`, no body. No body or
      Content-Length on 1xx/204, no body on 304
- [x] `Date` header formatted once per second per worker
- [x] `Content-Length` is always set by the server. Setting it (or `Date`,
      `Connection`, `Transfer-Encoding`) via `addNewHeader` is a **compile error**
- [x] Limits (`Config.limits`): request line → 414, head size or header count → 431,
      body → 413, unknown method → 501, unsupported version → 505
- [x] Timeouts without a syscall per connection: two intrusive deadline-ordered
      lists per worker (fixed timeout each, so appends keep them sorted, O(1)).
      Idle keep-alive (`keep_alive_timeout_s`, default 5) and request
      (`request_timeout_s`, default 10). The request deadline is **not** extended
      by further reads (slowloris), only by write progress. Tested
- [x] Error responses (`400`/`413`/`414`/`417`/`431`/`501`/`505`) with
      `connection: close`. Timeouts close without a `408`
- [x] Zero-copy parsing: `Header{ key, value }` slices into the read buffer
- [x] Response headers are serialised as they are added (one copy, values may be
      freed right away), with CR/LF injection rejected
- [x] **Lingering close** after an error response: `shutdown(SHUT_WR)`, then
      drain input until the client's FIN, 1 MB or the request timeout, in both
      backends. Test `error response survives an ongoing upload` checks that the
      client sees a clean FIN; with lingering disabled it fails with `ECONNRESET`

---

## Phase 4: architecture for top-tier throughput 🟡

- [x] **Linux first.** Full test suite runs on Linux (Docker, kernel 6.12)
- [x] **io_uring backend** (`worker_uring.zig`, `.backend = .io_uring`): multishot
      accept; recv with kernel-selected provided buffers (idle connections hold
      none; the session parses straight out of the kernel buffer and copies only
      leftovers); one recv armed at a time (backpressure); writes queued as SQEs so
      one `io_uring_enter` covers a whole batch; `SINGLE_ISSUER | DEFER_TASKRUN`;
      cancel-before-close with in-flight op counting. Same end-to-end tests as epoll
- [ ] **Make io_uring faster than epoll.** Measured equal within noise (see Phase 5),
      so `.auto` picks epoll. To try: multishot recv, registered (direct) fds,
      `send` instead of `writev` for single buffers, `send_zc` for large bodies,
      bigger completion batches, and back off re-arming accept on `EMFILE`
- [x] **Listener per worker with `SO_REUSEPORT`** on Linux (`SO_REUSEPORT_LB` where
      available), no accept thread, no cross-thread hand-off. macOS: workers share
      one listener in their own kqueues
- [x] `TCP_DEFER_ACCEPT` on Linux, plus reading straight after accept (saves an
      epoll round-trip per new connection)
- [x] Pin each worker to a core (`pin_workers`, Linux; picks from the allowed CPU
      set, so cpusets in containers work)
- [ ] NUMA-local allocation
- [x] Avoid body copies: `Response.setBodyBorrowed` (zero-copy, for static or cached
      data) and `bodyWriteBuffer`/`commitBody` (format straight into the buffer).
      `DirServer`/`FileServer` serve zero-copy. Default `response_body_buffer_size`
      cut from 10 MB to 1 MB per worker
- [ ] `sendfile` (or `splice`) for file-descriptor bodies
- [x] Precomputed fragments: status line, server headers and body go out in at most
      two iovecs per batch
- [ ] Make WebSockets multi-threaded, or run them on the HTTP workers' event loops.
      Also give the WebSocket reader per-connection state: like the old HTTP reader,
      it resets per event (drops a second frame in the same read) and treats
      `WouldBlock` mid-frame as an error. Bytes after the upgrade request are not
      forwarded to the WebSocket side

---

## Phase 5: verification and benchmarking 🟡

- [x] Fuzzing with Zig's built-in fuzzer: `fuzz: split invariance` in
      `session.zig` feeds arbitrary bytes, split arbitrarily, through the full state
      machine, checking no crash, no leak, and identical output to an unsplit run.
      About 322K runs on Linux, no failures (`zig build test --fuzz=300K`; on macOS
      the 0.17 fuzz runner hung at 0% CPU, so run it on Linux). Without `--fuzz` the
      corpus runs as a regression test
- [ ] Structure-aware fuzzing (grammar-based request generation) to reach deeper
      parser states than byte mutation does
- [ ] Differential parser testing against other servers (e.g. HTTP Garden) for
      smuggling and parsing discrepancies. Note: `h2spec` is HTTP/2-only, so not
      applicable here
- [ ] Response correctness checks (e.g. REDbot) for headers and caching semantics
- [ ] Soak test: hours at high concurrency, with steady RSS and fd count
- [ ] Adversarial load: slowloris (basic test exists), oversized headers,
      half-open connections, connection floods
- [ ] Benchmark methodology:
  - [x] Linux with isolated, pinned cores (server on CPUs 0–5, `wrk` on 6–11, one
        container, loopback). **Still to do: separate machines**, since loopback in
        a VM can't show NIC/interrupt effects
  - [x] `wrk` without pipelining, plus pipelined ×16 (TechEmpower plaintext style)
  - [ ] Latency percentiles under fixed request rate (`wrk2`), not just max
        throughput
  - [x] Baseline nginx. **Still to do:** h2o, a minimal raw-epoll C server, Zap
- [x] Readme benchmark table updated with the new methodology

First results (Docker on M2 Pro, Linux 6.12 aarch64, plaintext "Hello, World!", c=256,
two runs each; ±10% run to run):

| req/s | nginx | peregrine epoll | peregrine io_uring |
|---|---|---|---|
| keep-alive | 767k–944k | 956k–1.09M | 995k–1.07M |
| pipelined ×16 | 1.24M–1.47M | 8.2M–9.4M | 8.5M–8.8M |

Micro-benchmarks (`zig build bench`, M2 Pro): parsing a 437-byte browser request with
8 headers takes about 187 ns (about 2.1 GB/s); a full session cycle (parse, handler,
serialise) for pipelined requests takes about 199 ns per request. The keep-alive
numbers are probably limited by `wrk` on 6 cores; check with more client capacity
before optimising further.

---

## Later: TLS 1.3

- std 0.17 still ships only `std.crypto.tls.Client`, no server, so the hand-rolled
  server handshake on the `tls` branch remains necessary
- Plug it in as a transform layer around `Session` (see Phase 2). Don't keep a
  separate worker. `src/https/` is untouched on this branch and not compiled
- Consider kTLS on Linux (handshake in userspace, record encryption in the kernel)
  so `sendfile` keeps working over TLS
