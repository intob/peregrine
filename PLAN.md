# Peregrine roadmap

**Goal: the fastest HTTP/1.1, HTTP/2 and HTTP/3 server, with TLS 1.3 and WebSockets,
in pure Zig.** The only dependency is Zig's standard library. No libc on Linux, no
OpenSSL, no nghttp2/quiche.
Target toolchain: **Zig 0.17**. Platforms: Linux (epoll, io_uring), macOS/BSD (kqueue).

"Fastest" is measured, not claimed: each protocol gets a benchmark against the best
existing servers (nginx, h2o, and a raw-epoll C baseline for HTTP/1.1; h2o and nginx
for h2 and h3; uWebSockets for WebSockets), using the methodology in M7.

## Architecture

Every protocol layer is an **I/O-free state machine**: it takes bytes in, gives bytes
out and never makes a syscall. The worker event loops own sockets, buffers, timers and
syscalls. This keeps each layer testable byte by byte (split-invariance property tests
and fuzzing), lets the epoll/kqueue and io_uring backends share all protocol code, and
lets layers stack:

```
             TCP                                   UDP
              │                                     │
    TLS 1.3 records (src/tls/conn.zig)     QUIC packets + packet protection
              │                                     │   (handshake: src/tls/handshake.zig,
     ALPN ────┼──────────┐                          │    keys via the same key schedule)
              │          │                          │
  HTTP/1.1 Session   HTTP/2 frames + HPACK     HTTP/3 frames + QPACK
              │          │                          │
              └──────────┴───── Handler API ────────┘
                          │
            WebSocket: H1 Upgrade, H2 extended CONNECT (RFC 8441),
                       H3 extended CONNECT (RFC 9220)
```

Design rules that apply to every layer:

- **No per-request heap allocation** in steady state. Buffers come from per-worker
  pools and are held only while there are unprocessed bytes, so idle connections
  cost no buffer memory.
- **One worker per core, no cross-thread handoff.** A connection lives on the worker
  that accepted it (TCP: `SO_REUSEPORT` listener per worker; QUIC: connection IDs
  that encode the worker).
- **Zero-copy where possible**: parsed requests are slices into the read buffer;
  borrowed response bodies are written by reference; batching coalesces syscalls.
- **Strict parsing** with explicit limits on every length, count and time.
- The TLS handshake is separate from the record layer so QUIC (RFC 9001) can reuse it:
  the handshake consumes and produces handshake bytes per encryption level, and
  hands out traffic secrets; TCP wraps them in records, QUIC in CRYPTO frames.

## Status

| Milestone | State |
|---|---|
| M1. HTTP/1.1 core | ✅ done (streaming responses landed with the M5 handler API) |
| M2. Throughput architecture | 🟡 io_uring works (opt-in; faster than epoll for keep-alive requests, 4-5% behind for pipelined requests and uploads); sendfile done (plaintext, and TLS with kTLS); NUMA open |
| M3. WebSockets over HTTP/1.1 | ✅ reworked; benchmarked against uWebSockets (even on small messages, 15-20% less CPU at 16-64 KiB); Autobahn 301/301 strict on every backend, plain and TLS; decoder fuzzed; permessage-deflate open |
| M4. TLS 1.3 | ✅ HTTP and WebSockets on every backend (epoll, kqueue, io_uring), interop-tested, fuzzed; tables for P-256 and X25519, RSA-PSS, session tickets, kTLS, 0-RTT and SNI certificates done; the rest of "faster handshakes" open |
| M5. HTTP/2 | ✅ h2 over TLS (ALPN) and h2c on every backend, h2spec 146/146 over TLS, fuzzed, benchmarked; streamed request bodies on every protocol; WebSockets over h2 (RFC 8441); RFC 9218 priorities |
| M6. HTTP/3 and QUIC | 🟡 HTTP/3 over QUIC v1 on every backend, interop-tested (aioquic, curl/ngtcp2, h2load), benchmarked against nginx and Caddy; WebSockets over h3 (RFC 9220); 0-RTT; migration, pacing, ECN, PMTUD open |
| M7. Verification and benchmarking | 🟡 ongoing for each milestone |

Source layout:

| File | Role |
|---|---|
| `src/sys.zig` | Raw syscall wrappers (direct to the kernel on Linux, libc on BSD) |
| `src/poller.zig` | epoll/kqueue: edge-triggered connections, level-triggered listener/waker |
| `src/http/parser.zig` | Zero-copy, strict HTTP/1.1 request parser + chunked decoder |
| `src/http/session.zig` | I/O-free HTTP/1.1 connection state machine, buffer pool, output batching |
| `src/http/worker.zig` | epoll/kqueue event loop: accept, read, process, write, timeouts |
| `src/http/worker_uring.zig` | io_uring event loop (Linux, opt-in) |
| `src/http/date.zig` | Cached IMF-fixdate `Date` header |
| `src/http/exchange.zig` | `Exchange`: a request answered or streamed after `handleRequest` returns (per-worker slab, value handles, HTTP/1.1 framing) |
| `src/http/priority.zig` | RFC 9218 priority parameters, from the `priority` header or PRIORITY_UPDATE |
| `src/mailbox.zig` | How other threads tell a worker that a WebSocket or an exchange has output |
| `src/h2/hpack.zig` | HPACK (RFC 7541): tables, Huffman coding, strict limits |
| `src/h2/frame.zig` | HTTP/2 framing (RFC 9113): I/O-free parser and serialiser |
| `src/h2/conn.zig` | One HTTP/2 connection: streams, flow control, request assembly, responses through the handler API, defences |
| `src/ws/protocol.zig` | I/O-free WebSocket frame decoder and message assembler |
| `src/ws/conn.zig` | Per-connection WebSocket state: send queue, close handshake, cross-thread mailbox |
| `src/ws/upgrader.zig` | Accepting a WebSocket: 101 for an HTTP/1.1 Upgrade, 200 for an extended CONNECT on HTTP/2 and HTTP/3 |
| `src/tls/` | I/O-free TLS 1.3 server (M4): see below |
| `src/server_test.zig` | End-to-end tests over real sockets, run once per available backend |
| `bench/` | `zig build bench` (parser micro-benchmarks), `zig build bench-tls` (record protection), `zig build bench-server` (load-test target, plaintext or TLS), `zig build ws-load` (WebSocket load generator, Linux) |
| `docs/handler-api-proposal.md` | Proposed M5 handler API: streaming, deferred responses, trailers |

Tests run with `zig build test` on macOS (kqueue), Linux with Docker's default seccomp
(epoll; io_uring is blocked there, so `.auto` falls back), and Linux with io_uring
permitted. To run the io_uring tests in Docker, allow only `io_uring_setup`,
`io_uring_enter` and `io_uring_register` on top of Docker's default seccomp profile
rather than using `seccomp=unconfined`.

---

## M1. HTTP/1.1 core ✅

Done on the `http-core` branch (Zig 0.16 → 0.17 port, then a rewrite of the hot path).

- **Port to 0.17**: `std.net` and the `std.posix` socket wrappers are gone, so raw
  syscalls live behind `sys.zig`/`poller.zig` (decided: raw syscalls, not `std.Io`, on
  the hot path). Examples use `main(init: std.process.Init)`.
- **Correctness**: fixed the crash on `abc:` headers, OWS trimming, whole-token method
  matching (unknown → 501), keep-alive decided per request, a slab with generation
  counters instead of an fd-indexed table, `TCP_NODELAY` inherited from the listener,
  `SIGPIPE` ignored, no 1 ms poll timeouts (eventfd/pipe waker for shutdown).
- **Connection state machine** (`Session`): incremental, resumable parsing (SIMD LF
  scan); pipelining with responses coalesced into one `writev`; partial writes kept
  per connection and resumed on writability (backpressure: reading pauses while output
  is pending); pooled read buffers held only while bytes are unprocessed; peer
  half-close handled.
- **Protocol completeness**: `Content-Length` and chunked request bodies; request
  smuggling defences (CL+TE, duplicate/list/signed CL, TE other than `chunked`,
  obs-fold, bare CR/LF, control bytes, missing/duplicate `Host`), each with a test;
  `Expect: 100-continue`; `HEAD`, 1xx/204/304 body rules; cached `Date`; server-owned
  `Content-Length`/`Date`/`Connection` (setting them is a compile error); limits with
  414/431/413/501/505; idle and request timeouts on deadline-ordered intrusive lists
  (no syscall per connection, request deadline not extended by reads, so slowloris
  is bounded); lingering close after error responses; response header CR/LF injection
  rejected.
- **Deferred, then done in M5:** chunked/streaming responses, through
  `resp.stream()` and `resp.later()` (see M5).

Proof: a session property test feeds 16 mixed pipelined requests byte by byte and in
199 random splits and checks the output is byte-identical (it caught a real bug); an
end-to-end test pipelines 8 MB + 1 MB responses to a slow reader.

---

## M2. Throughput architecture 🟡

- [x] Linux first; full suite runs on Linux 6.12 (Docker)
- [x] **io_uring backend** (`worker_uring.zig`): multishot accept; recv with
      kernel-selected provided buffers, parsing straight out of the kernel buffer; one
      recv armed at a time (backpressure); writes queued as SQEs so one
      `io_uring_enter` covers a batch; `SINGLE_ISSUER | DEFER_TASKRUN`;
      cancel-before-close with in-flight op counting
- [ ] **Make io_uring faster than epoll.** Faster for keep-alive requests now,
      still behind for pipelined requests and uploads, so `.auto` picks epoll.
      Server CPU per request (Docker on the M2 Pro, 6 workers, `wrk -t6` on the
      other cores, two interleaved rounds, both fully optimised):

      | | io_uring before | io_uring after | epoll |
      |---|---|---|---|
      | "Hello", c=256 | 5.08-5.10 µs | 4.82-4.84 µs | 4.91-4.97 µs |
      | pipelined ×16, c=256 | 0.625 µs | 0.576-0.578 µs | 0.552-0.556 µs |
      | POST 12 KiB, c=64 | 9.45 µs | 8.54-8.65 µs | 7.99-8.20 µs |

  - [x] Plaintext HTTP/1.1 keeps one multishot receive armed across requests
        instead of a receive (and a poll the kernel arms) per request: -4% on
        "Hello". Input it brings while a response is being written, or that
        the session has no room for (a paused body, a pipelined burst: the
        kernel retries a multishot receive up to 32 times per pass, buffer
        after buffer), stays in its kernel buffers (`Conn.parked`) and goes
        in before anything more is received; holding partial input, being
        busy or upgraded cancels the multishot receive. Single-shot with
        `IORING_RECVSEND_POLL_FIRST` instead was no better than before
  - [x] The receive for the next request goes in the same submission as the
        response, not after its completion
  - [x] Receive buffers are posted from a LIFO stack, only as many as recent
        batches used (twice the most per batch, adapted each second, doubled
        on ENOBUFS), not all 256 cycling through the ring; and without
        incremental consumption, which packed requests into buffers back to
        back so that 12 KiB uploads were often split across two receives:
        uploads 9.3-9.5 → 8.5-8.8 µs
  - [x] `send`/`sendmsg` instead of `writev` (no VFS layer), and bodies up to
        1 KiB copied after the head so most responses are one buffer: within
        noise
  - [x] Tried and dropped: writing responses with a direct `writev` and only
        falling back to the ring (worse: an SQE and its completion cost less
        than the syscall); a smaller receive target (no change)
  - [ ] What is left is the kernel's receive copy: `__arch_copy_to_user` takes
        1.6-2x the time it does on epoll for the same bytes, even with one
        connection per worker, where both copy into a single hot buffer, so
        it isn't the buffers' cache footprint (epoll copies later, after its
        own wakeup and syscall). Fixed files would save `fget`/`fput` on each
        send (about 0.6%)
  - Fixed while doing this: closing a connection that held part of a request
    cancelled `.recv` when `.recv_plain` was armed, so a client that sent part
    of a request and went quiet kept its slot and fd past the timeout (test
    added)
  - Earlier, before the work above (12 KiB POST, plaintext, c=64: 12.4 µs of
    server CPU on io_uring against 6.7-7.1 on epoll; found with perf and
    counters, host under load, interleaved runs):
  - [x] About two thirds of these requests arrive in two receives. The rest went
        through a second kernel buffer and was copied after the first part;
        a connection holding partial input now receives straight into that
        buffer, as on epoll: 11.0-12.1 → 10.0-10.3 µs
  - [x] The kernel copies into the coldest buffer: the ring is FIFO over 256 ×
        16 KiB per worker, where epoll reuses hot pooled buffers (now the LIFO
        stack above)
  - [ ] The first part of a split request (4.3 KB on average) is still copied out
        of the kernel buffer. Holding the kernel buffer and receiving the rest into
        its tail would avoid that when the request fits. With the multishot
        receive, `perf stat` counts one receive per 12 KiB upload at c=64
- [x] Listener per worker with `SO_REUSEPORT` (`SO_REUSEPORT_LB` where available);
      macOS workers share one listener in their own kqueues
- [x] `TCP_DEFER_ACCEPT` plus reading straight after accept
- [x] Workers pinned to cores (`pin_workers`, respects the allowed CPU set)
- [x] Zero-copy bodies (`setBodyBorrowed`), format-in-place (`bodyWriteBuffer` /
      `commitBody`), status line + headers + body in at most two iovecs
- [x] **File bodies and sendfile**: `resp.sendFile(.{ fd, offset, len, close })`
      (`close`: the server closes the file once sent, or when the response is
      abandoned: HEAD, a reset, the connection closing, an exchange taken
      instead). Plaintext HTTP/1.1 sends the head, then sendfile(2) until done
      or EAGAIN (epoll/kqueue: the rest on the next writability edge;
      io_uring: straight from the write completion, the socket being
      non-blocking, with a one-shot POLLOUT poll when it is full). Where
      sendfile isn't supported (some BSDs, files it refuses) the file is
      read and written a buffer at a time. Over TLS (kTLS: see M4), HTTP/2
      (DATA frames read straight into the output, within the windows and
      the priority scheduler's budget) and HTTP/3 (into the QUIC stream up
      to `stream_buffer`) the file is read with pread as the connection takes
      it. A file that ends before its length closes the connection (h2/h3:
      resets the stream). `util.FileServer` and `util.DirServer` keep files
      up to `memory_max` (64 KiB) in memory and larger ones open. Proof:
      session tests (a range, HEAD, pipelining, owned files closed in every
      case), h2 tests (DATA through the windows, HEAD, a reset, teardown),
      h3 tests (300 KB through a 16 KB stream buffer, HEAD, STOP_SENDING,
      teardown), end-to-end on every backend over HTTP/1.1 with and without
      sendfile, TLS, h2c and HTTP/3 (8 MB, pipelined, read slowly, a
      truncated file); curl gets the identical 1 MiB over HTTP/1.1, TLS,
      h2, h2c and HTTP/3 on epoll and io_uring. Benchmark (Docker on the M2
      Pro, server on CPUs 0-3 with 4 workers, `wrk -t4 -c64` on 6-11, two
      rounds, host load ~6): 1 MiB from memory 104-105 µs server CPU per
      request (35K req/s), from the file 78-86 µs (36-39K req/s), on both
      epoll and io_uring; 64 KiB 10-11 µs from memory, 13-14 µs from the
      file (two syscalls instead of one writev), hence the 64 KiB threshold
      in the file servers. Over TLS with kTLS (M4) files use sendfile too
- [ ] NUMA-local allocation
- [ ] UDP fast path for QUIC (M6): `recvmmsg`/`sendmmsg`, `UDP_SEGMENT` (GSO) and
      `UDP_GRO`, io_uring equivalents

---

## M3. WebSockets over HTTP/1.1 ✅

The old `src/ws/` ran every WebSocket on one thread with its own poller, lost a second
frame in the same read, treated `WouldBlock` mid-frame as a disconnect, looped on
`write()`, dropped bytes that arrived with the upgrade request, and skipped most of
RFC 6455's validation. Reworked on the `ws-rework` branch:

- `protocol.Decoder` buffers input like `Session` (pooled, held only while bytes are
  unprocessed). An unfragmented message that fits is unmasked and delivered in place;
  larger or fragmented messages stream into a reassembly buffer bounded by
  `websocket_max_message_size`. Text is validated incrementally.
- `ws.Conn` adds a send queue (`shared`, under a mutex, appended by `send` from any
  thread) and a `wire` buffer owned by the worker (swapped in O(1)), pong replies, the
  close handshake, and failing with a close code.
- **No handoff**: after the 101 the connection stays in its worker's slab with a
  `ws.Conn` attached and reuses the worker's read/write/timeout machinery, on both
  backends. Reading pauses while output is stalled; a stalled write or a pending close
  handshake gets `request_timeout_s`; idle WebSockets have no timeout.
- **Cross-thread sends**: each worker has a `Mailbox`; `send` queues under the
  connection's mutex and posts the slot (deduplicated; wakes the worker only when
  called from another thread). Overflow is recorded and triggers a full flush rather
  than dropping a post.
- **Validation** (RFC 6455): masking, RSV bits, reserved opcodes, 64-bit length MSB,
  minimal length encoding, control frame rules, fragment sequencing, UTF-8, close
  codes, size limit. Failures send 1002/1007/1009/1011 and close once written.
- **API**: hooks take `*ws.Conn` (`handleWSConn`, `handleWSDisconn`,
  `handleWSFrame(conn, *Frame)`); `conn.send`, `conn.ping`, `conn.close(code, reason)`
  work from any thread until `handleWSDisconn` returns.

Tests: every malformed case; a random-split property test (52 frames, byte by byte and
199 splits, small and large buffers); end-to-end on every backend (frames in the
upgrade packet, several frames per read, fragmentation with an interleaved ping, 300 KB
messages, cross-thread sends, both close handshakes, violations, a client that stops
reading).

Still open:
- [ ] `permessage-deflate` (needs a pure-Zig raw DEFLATE compressor with context
      takeover; `std.compress.flate` covers decompression)
- [ ] Optional idle timeout / server keepalive pings
- [ ] io_uring: parse straight out of the provided buffer like the HTTP path does
- [x] **Autobahn testsuite** (25.10.1, `wstest -m fuzzingclient` against
      `bench-server`'s `/ws` echo, cases 1-10; 12 and 13 are
      permessage-deflate): 301 of 301 OK (3 of them INFORMATIONAL by
      design, the close-code cases 7.1.6 and 7.13.x), every close clean, on
      epoll and io_uring, over `ws://` and `wss://`. uWebSockets 20.74 on
      cases 1-7: 232 OK, 11 NON-STRICT. The image is amd64 only and runs
      under Rosetta; set `PYTHONUNBUFFERED=1`, or its progress lines lag
      far behind the case being run. What it found:
  - [x] A message bigger than `max_send_queue_bytes` (4 MiB) could never be
        sent: `send` returned SendQueueFull even on an empty queue, so 9.1.4
        to 9.2.6 (4-16 MiB echoes) waited for Autobahn's timeout. An empty
        queue now takes one frame of any size (the queue holds at most the
        limit or one frame), close to uWebSockets' rule (drop only when
        what is already buffered is over the limit)
  - [x] Fail fast on UTF-8 (6.4.2-6.4.4, NON-STRICT before): text is
        rejected as soon as the incomplete final sequence can't become
        valid (`f4 90`, `ed a0`, `e0 80`, ...), and a text frame held whole
        while it arrives is unmasked and checked as each piece lands, not
        once complete
- [x] **Fuzz target** `fuzz: ws decoder`: structure-aware, a stream of up to
      eight messages or mangled frames (bad RSV bits and opcodes, missing
      masks, oversized and non-minimal lengths, truncation). Valid streams
      (three in four) must decode to exactly the messages encoded: text
      built from 1-4 byte sequences, fragment boundaries anywhere (also
      inside sequences), pings between fragments. Every stream is decoded
      with a buffer that holds each frame whole and again with a 256-1024
      byte buffer read in arbitrary pieces (streamed, read in place), and
      both must deliver the same messages and fail the same way. On Linux
      with 3 jobs: 20 minutes before the fail-fast change, 10 after, no
      failures
- [x] **Benchmark against uWebSockets.** `bench/ws_load.zig` (`zig build
      ws-load`): threads with their own epoll, each connection upgrading
      over HTTP/1.1, then keeping `depth` masked messages in flight and
      answering each whole echo with another (written together with the
      others completed in the same read); echoes are checked for opcode,
      FIN and length, the first per connection byte by byte. uWebSockets'
      own `benchmarks/load_test.c` is single-threaded with one message in
      flight; six copies of it (one per client core, 20 bytes, 258
      connections) agree: peregrine 1.42M msg/s, uWebSockets 1.38M, both
      at 5.7 server cores.

      The first run showed large messages costing twice what they cost
      uWebSockets (256 KiB: 176-196 µs against 97-108). A message bigger
      than the read buffer was appended to an `ArrayList` that grew by
      remapping and, being over 64 KiB, was freed after every message, so
      each one was mapped, faulted in and unmapped (about a third of the
      profile, with workers contending for `mmap_lock`). Now:
  - [x] The reassembly buffer is sized once from the frame header
        (fragments grow it geometrically) and comes from a per-worker cache
        in `BufferPool` (`acquireLarge`/`releaseLarge`: best fit, at most 32
        buffers and 4 MiB, smaller ones dropped to make room for larger).
        It goes back once the message is delivered and no input is
        buffered, so idle connections still hold no buffers. With 8 slots
        and no eviction, 16 KiB messages filled the cache and every 64 KiB
        message after them missed it: io_uring then stalled at half its
        cores (`releaseIfIdle` runs after every receive there)
  - [x] While more of a frame is to come than the read buffer holds,
        `readSpace` returns the rest of the reassembly buffer, so the payload
        is read in place (io_uring receives into it instead of a provided
        buffer, `holdsPartialFrame`). Only for frames up to 512 KiB: the
        kernel's copy into a cold 1 MiB buffer cost 10-15% more than reading
        through the hot read buffer and copying (64 KiB and 256 KiB: 5-15%
        cheaper in place)
  - [ ] `send` copies the payload into the shared queue, and `shared`/`wire`
        keep their capacity for the life of the connection (a connection that
        once sent 1 MiB holds 2 MiB). They are appended from any thread, so
        the worker's cache can't hold them as it is
  - [ ] io_uring copies small frames out of the provided buffer (1 KiB text:
        1.45 µs against 1.33 on epoll); see "parse straight out of the
        provided buffer" above
  - [ ] Over TLS, and broadcast (one message to many connections)

      Echo (2026-10-29; Docker on the M2 Pro, Linux 6.12 aarch64; each server
      with 6 workers on CPUs 0-5, `ws-load` with 6 threads on 6-11, 8 s per
      case, two interleaved rounds, host load 2-12). uWebSockets 20.74 built
      with `-O3 -march=native -flto`, compression off, 16 MiB message and
      backpressure limits. CPU/msg is server CPU time per echoed message.

| | peregrine epoll msg/s | CPU/msg | io_uring msg/s | CPU/msg | uWebSockets msg/s | CPU/msg |
|---|---|---|---|---|---|---|
| 20 B, 256 conns, 1 in flight | 1.31M-1.34M | 4.24-4.28 µs | 1.31M-1.32M | 4.32-4.36 µs | 1.30M-1.33M | 4.24-4.27 µs |
| 20 B, 1024 conns, 1 in flight | 1.37M-1.39M | 4.15-4.17 µs | 1.41M-1.42M | 4.06-4.08 µs | 1.31M-1.35M | 4.24-4.32 µs |
| 20 B, 256 conns, 16 in flight | 19.5M-19.8M | 290-293 ns | 19.7M-19.9M | 290-291 ns | 17.2M-19.6M | 292-309 ns |
| 1 KiB text, 256 conns, 4 in flight | 4.26M-4.30M | 1.33-1.34 µs | 3.97M-3.98M | 1.45 µs | 3.96M-3.99M | 1.45-1.46 µs |
| 16 KiB, 64 conns, 4 in flight | 746k-761k | 7.65-7.78 µs | 695k-701k | 8.32-8.39 µs | 653k-654k | 9.07-9.10 µs |
| 64 KiB, 32 conns, 2 in flight | 250k-254k | 21.6-21.9 µs | 200k-234k | 23.9-25.0 µs | 207k-210k | 27.0-27.2 µs |
| 256 KiB, 16 conns, 2 in flight | 56.6k | 94-96 µs | 49.0k-60.3k | 77-106 µs | 53.3k-53.6k | 99 µs |
| 1 MiB, 16 conns, 1 in flight | 11.7k-12.7k | 383-458 µs | 11.5k-12.3k | 396-469 µs | 12.9k-13.3k | 400-407 µs |

      Before the changes above (same setup, epoll): 64 KiB 51-53 µs, 256 KiB
      146-187 µs, 1 MiB 735-833 µs.
- [x] WebSockets over HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220): see M5

---

## M4. TLS 1.3 🟡

std 0.17 ships only a TLS client (`std.crypto.tls.Client`), so the server side is
ours. We reuse std for primitives: AEADs, HKDF, X25519, P-256/P-384, ML-KEM, ECDSA,
Ed25519, `std.crypto.tls` enums and `hkdfExpandLabel`.

**Scope (first cut):** TLS 1.3 only (RFC 8446), server side, full handshake.

- Cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`. Server preference: AES-GCM when the CPU has AES
  instructions, ChaCha20 otherwise.
- Key exchange: X25519, secp256r1, and the hybrid **X25519MLKEM768** (what current
  browsers send first). HelloRetryRequest when the client offered a group we support
  but no key share for it.
- Certificates: ECDSA P-256/P-384, Ed25519 and RSA keys (PKCS#8, SEC1 or PKCS#1 PEM). The chain is
  sent as configured.
- ALPN (`http/1.1` now, `h2` in M5); SNI is accepted (one certificate for now).
- Middlebox compatibility: echo `legacy_session_id`, send one `change_cipher_spec`,
  ignore the client's.
- Alerts on every failure, `close_notify` on close, `KeyUpdate` handled (both
  directions), post-handshake messages other than KeyUpdate rejected.

**Design** (`src/tls/`):

| File | Role |
|---|---|
| `key_schedule.zig` | RFC 8446 §7.1 secrets, traffic keys, Finished keys, KeyUpdate. Generic over the hash. Tested against the RFC 8448 trace |
| `handshake.zig` | Server handshake state machine. Consumes handshake messages and produces handshake messages **per encryption level** (initial, handshake, application), and exposes traffic secrets as each level becomes available. No record framing, so QUIC can drive it unchanged |
| `record.zig` | Record protection: AEAD with per-record nonce (IV xor sequence number), record header as AAD, inner content type and padding removal, record size limits |
| `conn.zig` | `tls.Conn`: one TLS-over-TCP connection. Buffers ciphertext like `Session` does (pooled, held only while unprocessed), drives the handshake, decrypts application data for the HTTP/WebSocket layers and encrypts their output into a wire buffer |
| `credentials.zig` | PEM/DER loading of the certificate chain and private key; signing CertificateVerify |
| `p256.zig`, `x25519.zig` | Base-point tables: ECDSA P-256 signing, P-256 ECDHE key pairs, X25519 public keys |
| `rsa.zig` | RSA private keys and RSASSA-PSS signing |
| `ticket.zig` | Session tickets: resumption state sealed with a rotating key |
| `fuzz.zig` | Fuzz target over `tls.Conn`: a scripted client (see the checklist) |

The handshake keeps a running transcript hash, not the transcript, and its state is
freed when the handshake ends, so an established connection only holds two record
protection states (keys, IVs, sequence numbers, and for AES-GCM the expanded key
schedule and GHASH table, about 500 bytes each).

**Worker integration**: the TLS connection sits between the socket and the session
(or the WebSocket decoder). Reads go socket → `tls.Conn` (decrypt) → session buffer;
a record whose plaintext fits the free space is decrypted straight into it. Writes go
session `Out` → `tls.Conn` (encrypt into records of up to 16 KB) → socket. The
existing pending-output and backpressure machinery covers the ciphertext too: unsent
ciphertext counts as pending output, and plaintext not yet encrypted is kept like an
unsent response.

On io_uring, ciphertext lands in kernel-provided buffers (so idle connections still
hold no buffer), is copied into the `tls.Conn`, and every complete record is decrypted
before the kernel buffer goes back; a TLS input buffer holds one whole record, so what
is left always fits. Output is encrypted from the connection's `Out` as the wire
buffer drains, one write SQE at a time; alerts and close_notify use one direct write,
as on epoll, which is safe because no write SQE is in flight at those points.

Checklist:
- [x] Decide: rewrite as I/O-free layers in `src/tls/` instead of fixing the old
      `src/https/` prototype (it was blocking, had no bounds checks, used an empty AAD
      and no sequence-number nonce, and assumed one read per record). Prototype deleted
- [x] `key_schedule.zig`: every secret, key and IV of the RFC 8448 1-RTT trace
- [x] `record.zig`: seal/open reproduce RFC 8448's encrypted records byte for byte;
      round trips for every suite, KeyUpdate, tampering, replay, padding-only records
- [x] `handshake.zig`: strict ClientHello parsing (duplicate extensions, PSK not last,
      share/group mismatches, bad lengths, low-order points), negotiation, HRR, server
      flight, client Finished. The ServerHello for RFC 8448's ClientHello matches the
      RFC byte for byte; every group × suite is checked against an independent
      client-side computation
- [x] `credentials.zig`: PEM chains, PKCS#8 and SEC1 keys, checked against the leaf
- [x] `conn.zig`: records ↔ handshake ↔ application data, alerts (plaintext before
      keys exist), close_notify, KeyUpdate both ways, rejected 0-RTT skipped, garbage
      (say, plaintext HTTP) rejected from the first header
- [x] Handshake + 40 KB echo against `std.crypto.tls.Client` over a socketpair, for
      every suite × group with P-256 and P-384 certificates (with the client in
      middlebox compatibility mode, so the CCS path runs)
- [x] Random-split property test: a recorded session replayed byte by byte and in 99
      random splits gives identical handshake bytes and plaintext
- [x] `Config.tls` (PEM in memory, ALPN list), worker integration for HTTP and
      WebSockets on epoll/kqueue. End-to-end tests with std's client: keep-alive,
      pipelining, 8 MB and 1 MB responses through partial writes, close_notify on
      `Connection: close`, WebSocket echo (40 KB frames, cross-thread sends, close
      handshake), plaintext HTTP to a TLS port. Linux (epoll) and macOS (kqueue)
- [x] Interop with OpenSSL 4.0 `s_client`: all 9 suite × group combinations with
      certificate verification, HelloRetryRequest (client shares X448 only), KeyUpdate
      in both directions, Ed25519 certificates (std's client can't check those: its
      CertificateVerify scheme check has no Ed25519 case). curl 8.7 (LibreSSL) with ALPN
- [x] `example/https` (`zig build run-https`)
- [x] io_uring backend integration; every TLS end-to-end test runs on each backend
- [x] Fuzz target over `tls.Conn` (`src/tls/fuzz.zig`). A scripted client starts from
      a session recorded with std's client, swaps in key shares it holds the private
      keys for, mutates the ClientHello (lengths, extensions, key shares, PSK
      placement, the answer to a HelloRetryRequest), follows the server's replies to
      derive the real keys, and sends valid and invalid records (Finished variants,
      application data with padding, KeyUpdate, alerts, corrupted, oversized, empty
      and early-data records). The bytes are replayed with other read splits and
      record boundaries. Checked: no crash or out-of-bounds access; the output
      decrypts and verifies; every failure ends with a fatal alert, the one RFC 8446
      names where it names one; splits never change the output; a script without
      faults completes with its plaintext intact. Fuzzed on Linux (Docker, ReleaseSafe,
      6 instances) for 2 h 16 min of wall time (just over 2 h active), about 10.9M
      runs; the coverage-guided runs found 7 bugs in the harness's own model and none
      in the server. Found in the server while building the harness (pseudo-random
      inputs): padding could take the inner plaintext past 2^14 + 1 bytes (now
      record_overflow); a tag-only record got bad_record_mac instead of
      unexpected_message; 0-RTT data arriving after our HelloRetryRequest was
      rejected instead of skipped (§4.2.10). Also added: pre_shared_key without
      psk_key_exchange_modes is rejected (§4.2.9). Inputs that once failed are kept
      in `src/tls/testdata/fuzz/` and replayed by every `zig build test`; without
      `--fuzz` the harness also runs 64 PRNG-driven inputs. Coverage stays near 20% of
      the instrumented PCs in the test binary (which includes std and the rest of the
      library): 3180 PCs seen after the first minutes, 3269 at the end. The next gains
      need new script paths more than more hours.
      Run it: `zig build test --fuzz -Doptimize=ReleaseSafe -Dtest-filter="fuzz: tls"`
      on Linux. With several fuzz instances, run a short single-instance pass first
      (`--fuzz=200`): instances racing to create the coverage file panic in 0.17

First numbers (macOS, M2 Pro, all cores, `wrk -t4 -c64`, so wrk-bound and only
relative): keep-alive "Hello" over TLS 136k req/s vs. 146k plaintext; full handshakes
(new connection per request, X25519MLKEM768 + ECDSA P-256) about 6.2k/s. Handshake
cost is mostly std's P-256 signing and ML-KEM, which have no assembly fast paths:
profile before deciding what to optimise.

Linux numbers (Docker on M2 Pro, `bench-server ... tls`: 6 workers on CPUs 0-5, `wrk
-t6` with OpenSSL 3.3 on CPUs 6-11, keep-alive, AES-128-GCM, X25519; built with
`-Dcpu=apple_m2`, since generic aarch64 has no AES instructions and std falls back to
software AES). wrk does as much TLS work as the server, so throughput is partly
wrk-bound; server CPU per request is the better measure:

| | req/s | server CPU | CPU per request |
|---|---|---|---|
| "Hello", c=256, epoll | 295k-317k | 2.5 cores | 8.1-8.3 µs |
| GET 64 KiB, c=64, epoll | 97k-103k (5.9-6.3 GB/s) | 5.3 cores | 50-54 µs |
| POST 12 KiB, c=64, epoll | 281k-294k | 4.6 cores | 15.6-16.5 µs |
| "Hello", c=256, io_uring | 310k-314k | 2.7 cores | 8.5 µs |
| GET 64 KiB, c=64, io_uring | 96k-101k | 5.1 cores | 50-53 µs |
| POST 12 KiB, c=64, io_uring | 257k-261k | 4.8 cores | 18.5 µs |

Later in M4:
- [x] Faster record crypto: keep expanded AES key schedules (and GHASH's powers of
      H) per key instead of per record, and decrypt straight into the session buffer
      when the record fits. Smaller win than expected, because ARM's AES and PMULL
      instructions make the setup cheap: seal+open 3-4% faster for 32 B-4 KiB records,
      1% at 16 KiB, and skipping the copy saves about 3% at 16 KiB (`zig build
      bench-tls`). End to end, server CPU per request fell 1-9% for 64 KiB downloads
      and 12 KiB uploads, and throughput moved within noise (before: 8.3 / 55.6 /
      16.6 µs per request for hello / 64 KiB / upload; after: 8.1-8.3 / 50-54 /
      15.6-16.5). A fresh 16 KiB session buffer can't take a full record (16385 bytes
      with the content type), so those are still copied
- [x] **Faster AES-GCM** (`src/tls/aes_gcm.zig`, aarch64 with AES + PMULL; std's
      AES and GHASH elsewhere). std's AES-GCM ran at about 2.3 GB/s per direction per
      core on the M2 Pro: two passes, and AES rounds that run `aese` with a zero key
      and XOR each round key separately. Now one pass, 8 blocks at a time, round keys
      inside `aese`, one GHASH reduction per 8 blocks; output identical to std (tested
      against it). `zig build bench-tls`, seal+open AES-128-GCM: 16 KiB 14.2 → 3.7 µs
      (about 8.8 GB/s per direction, `openssl speed` gives 8.8), 1 KiB 1252 → 281 ns,
      32 B 284 → 65 ns; AES-256 3.3-4.6x. End to end (epoll, as above, two interleaved
      runs each): GET 64 KiB 87k-96k → 121k-130k req/s and 51-53 → 31 µs server CPU
      per request; POST 12 KiB 15.5 → 10.6-10.9 µs; "Hello" 8.0-8.2 → 7.7-8.0 µs.
      x86_64 (AES-NI + PCLMUL) would want the same treatment
- [x] io_uring + TLS: records are decrypted in place in the kernel's provided
      buffer, or straight into the session (`tls.Conn.borrowInput`); only a record
      that spans two receives is copied, up to its end, and a partial record at the
      end of a receive is kept. The split-invariance test replays every split
      copied and borrowed, with the borrowed buffer poisoned afterwards. The gain
      was within noise: the copy wasn't what made uploads slower on io_uring,
      because plaintext uploads have the same gap (see M2)
- [x] **Faster handshakes**, step 1: precomputed base-point tables.
      `zig build bench-tls -- handshake` times the server's side of a full
      handshake (ClientHello in, flight out) per group and certificate, and
      the primitives. On Linux (one core of the M2 Pro, two rounds), a
      P-256 certificate with X25519MLKEM768 (what browsers send) took
      197-208 µs, of which ECDSA P-256 signing was 114 µs, X25519 60 µs and
      ML-KEM-768 25 µs. The fixed-base multiplications were std's 4-bit
      window (P-256: 64 additions and 252 doublings) and the Montgomery
      ladder (X25519 key generation). `src/tls/p256.zig` and `x25519.zig`
      hold tables of 1..8 × 16^i × G for each of 65 signed 4-bit digits
      (P-256 in affine coordinates, 33 KB; Curve25519 as Edwards
      (y+x, y−x, 2dxy), 62 KB; built once on first use, one inversion
      each), so k × G is 65 mixed additions with a whole-row constant-time
      scan per digit. The X25519 public key is the u-coordinate of the
      Edwards result. Everything else is std's (fields, scalars, formulas,
      the hedged deterministic nonce), so signatures, key pairs and X25519
      public keys equal std's byte for byte (tested on 300+ random inputs,
      edge scalars, RFC 7748's vectors). The P-256 ECDHE shared secret now
      uses std's constant-time `mul`; it used the variable-time `mulPublic`
      on our ephemeral secret. Results (µs per handshake, before → after):
      P-256 cert with X25519MLKEM768 197-208 → 112-117 (1.8x), with X25519
      174-188 → 85 (2.1x), with P-256 310-317 → 178-204; ECDSA P-256 sign
      114 → 40, X25519 key pair + shared secret 60 → 41. Interop: OpenSSL
      3.5 verifies the CertificateVerify with each group, curl over HTTP/2
      and HTTP/3
- [ ] Faster handshakes, next: the X25519 shared secret (std's ladder,
      ~30 µs), P-256's variable-base `mul` for ECDHE, ML-KEM-768
      encapsulation (25 µs), the per-handshake allocations (handshake state,
      flight buffer); P-384 signing (315 µs) if P-384 certificates matter
- [x] Send KeyUpdate before the AES-GCM record limit: after 2^24 records under one
      key (the power of two below §5.5's 2^24.5), for every suite (only AES-GCM needs
      it, one rule is simpler), `update_not_requested`, only when the wire buffer has
      room so it never grows it. `Conn.key_update_limit` is lowered in tests, and
      std's TLS client follows the updates
- [ ] Known leniencies, all harmless for real clients: a KeyUpdate split across two
      records (allowed by RFC 8446 if neither spans a key change) is rejected;
      non-handshake records between the fragments of a handshake message are not
      (§5.1 says they MUST NOT appear); change_cipher_spec before ClientHello is
      dropped rather than rejected
- [x] **RSA certificates** (`src/tls/rsa.zig`): PKCS#1 and PKCS#8 keys of
      2048-4096 bits (two primes), signing `rsa_pss_rsae_sha256` only (every
      TLS 1.3 client must support it, RFC 8446 §9.1): EMSA-PSS with MGF1 and
      a 32-byte random salt, the private operation by the CRT with std's
      constant-time `std.crypto.ff` exponentiation, and every signature
      checked with the public exponent before it is sent (a CRT fault would
      otherwise reveal the factors). A key is checked at load by signing and
      verifying, and must match the certificate's modulus and exponent. No
      blinding (the exponentiation is constant time). Proof: signatures
      verify with std's PSS verifier (2048 and 4096 bits, several messages
      and salts), corrupted keys are rejected, std's TLS client completes
      every suite × group with RSA-2048 and RSA-4096 certificates; OpenSSL
      3.5 verifies the CertificateVerify with each group, curl over HTTP/2
      and HTTP/3 (`bench-server ... tls|h3 rsa`). Cost (macOS, `bench-tls --
      handshake`): about 1.2 ms per RSA-2048 handshake and 6.6 ms for
      RSA-4096, against OpenSSL's 0.55 ms and 3.8 ms per signature; std's
      generic big-number code is the limit. Not done: rsa_pss_rsae_sha384
      and _sha512 (a client that doesn't offer _sha256 gets
      handshake_failure, and none should), rsa_pss_pss_* keys, faster modular
      exponentiation
- [x] **Session tickets and resumption** (`src/tls/ticket.zig`, RFC 8446
      §4.6.1, §4.2.11), over TCP and QUIC, on by default
      (`TlsOptions.session_tickets`). Stateless: one NewSessionTicket after
      each handshake (resumed ones included) carries the resumption PSK,
      suite, issue time, age offset and transport, sealed with AES-256-GCM
      under a key derived from `ticket_key` (random per process unless set,
      so servers sharing it resume each other's sessions) and the current
      period of `ticket_lifetime_s` (default 1 day, at most 7); tickets from
      the current or previous period are accepted while younger than the
      lifetime. A ClientHello's pre_shared_key is parsed and checked (last
      extension, identities and 32-255-byte binders in step); only
      psk_dhe_ke is accepted (a resumed session keeps forward secrecy); the
      first of up to 8 identities that opens, for this transport and the
      suite's hash, is chosen and its binder must verify (over the
      transcript and the ClientHello up to the binders, so after a
      HelloRetryRequest too), or the handshake fails with decrypt_error;
      anything else gets a full handshake. A resumed handshake sends
      pre_shared_key in ServerHello and skips Certificate and
      CertificateVerify, which saves the signature: about 40 µs with an
      ECDSA P-256 certificate, 1 ms with RSA-2048. The obfuscated ticket age
      isn't checked (only 0-RTT needs it). Proof: ticket tests (round
      trip, expiry, rotation, every byte tampered, another key); a reference
      client in the handshake tests (independent key schedule) resumes with
      SHA-256 and SHA-384 suites, chains a second ticket, resumes after a
      HelloRetryRequest, and gets decrypt_error for a bad binder and a full
      handshake for psk_ke only, another key, expiry and a hash mismatch;
      HTTP/3 end-to-end tests receive one ticket. Interop on Linux: OpenSSL
      3.5 `s_client -sess_out/-sess_in` resumes ("Reused") with
      X25519MLKEM768, X25519 and P-256; aioquic 1.3 resumes over HTTP/3
      (io_uring). The TLS fuzz target (25 min on Linux, ReleaseSafe, 6
      instances: about 2.6M runs, 444 corpus inputs, no failures, after a
      harness fix in 110b869) covers the new handshake code and the
      pre_shared_key parsing. Since then the harness also runs half its
      scripts with tickets: it offers PSKs (tickets it seals under the
      server's key, valid, expired, for QUIC, under another key, with bad
      binders or binders of the wrong length, junk, up to 10 identities,
      with and without a HelloRetryRequest), predicts the identity the
      server resumes or the decrypt_error, follows the resumed key
      schedule, checks there is no certificate in a resumed flight, and
      opens the NewSessionTicket against the resumption secret. It found
      that a Finished sharing its record with more handshake bytes (a key
      change mid-record, §5.1) failed only after the ticket went out; now
      the server fails first. Fuzzed with tickets (472a9d2, 25 min on
      Linux, ReleaseSafe, 6 instances): 1.84M runs, 522 corpus inputs,
      3719 PCs seen, no failures
- [x] **0-RTT (early data)**, RFC 8446 §4.2.10 and §8, RFC 8470, RFC 9001
      §4.6. HTTP/1.1, HTTP/2 and HTTP/3, off by default
      (`TlsOptions.max_early_data`, with `replay_guard_size`). TLS: a
      ticket issued with 0-RTT on carries a random per-process `instance`,
      the suite and the ALPN protocol, and NewSessionTicket carries
      early_data with max_early_data_size; servers sharing a ticket key
      still resume each other's tickets, but early data only reaches the
      process that issued the ticket, so one `ticket.ReplayGuard` per
      process sees every replay. Accepted when the first PSK resumes, with
      the ticket's exact suite and ALPN, no HelloRetryRequest, a ticket age
      within 10 s of the client's, and a first binder the guard hasn't seen
      (entries kept 22 s, after which the age check refuses a replay; a
      full table refuses 0-RTT, never admits). The early key reads until
      EndOfEarlyData, which the client's Finished covers; more than
      max_early_data bytes is unexpected_message. HTTP: a request is early
      if it is handled before the handshake completes (one completed after
      it can't be a replay: a replayed ClientHello never finishes);
      `Request.early_data` says so. Safe methods (GET, HEAD, OPTIONS,
      TRACE) are handled at once, with responses at 0.5-RTT; on HTTP/1.1 any
      other method waits for the handshake and is parsed again then (no
      round trip lost), on HTTP/2 it gets 425 Too Early (HPACK state can't
      be rewound), as on HTTP/3. QUIC: 0-RTT packets open with the early
      key into the application space and streams flow before the
      handshake completes (responses at 0.5-RTT); the early key goes at
      the first 1-RTT packet; the ticket says max_early_data 0xffffffff
      (flow control limits it). `tls.Conn.readPlain` returns after the ClientHello that
      accepts 0-RTT so the worker can pick the protocol by ALPN before the
      early data. Proof: handshake tests with the reference client (key
      schedule, EndOfEarlyData, the same ClientHello twice, every refusal
      reason, messages out of place), the guard's tests, the fuzz harness
      (predicts acceptance, sends early data) and an accepted session
      through it for every suite, the HTTP/1.1, HTTP/2 and HTTP/3 policies;
      the fuzz target with 0-RTT (e1e9ea8, 25 min, 6 instances: 2.56M
      runs, 3889 PCs, no failures). Interop
      on epoll and io_uring (Linux, Docker): OpenSSL 3.3 `s_client
      -sess_in -early_data` with and without ALPN (early GET answered
      early, a later GET normally, an early POST after the handshake);
      curl 8.14 `--tls-earlydata` ("Server accepted 102 bytes of TLS
      early data"); HTTP/2 frames from python-h2 as OpenSSL 3.5 early data
      (GET answered early, POST 425); a proxy that records a client's
      first flight (ClientHello and early data) and replays it: the first
      gets the 0.5-RTT response, both replays only a resumed flight
      without early_data. HTTP/3: aioquic 1.3 resumes with a GET and a
      POST in 0-RTT (GET answered early, POST 425, the same POST after the
      handshake 200); a UDP proxy records aioquic's first datagrams
      (Initial, 0-RTT) and replays them once the connection is gone: a
      handshake answer and no 1-RTT packets. h3spec 77/77 and h2spec
      146/146 (TLS) still. Interop found two worker bugs, fixed: io_uring
      encrypted output only once established (a response at 0.5-RTT
      waited forever), and the epoll HTTP/2 path left decrypted input
      behind our queued SETTINGS until the next read (also a wait for the
      client's next packet on every new h2-over-TLS connection whose first
      flight carried requests). Not done: a 0-RTT client in the Zig tests
      (the in-memory QUIC test client and std's TLS client don't resume),
      so 0-RTT end to end is covered by the interop runs only; ngtcp2 (this
      curl can't export sessions between runs); buffering 0-RTT packets
      that arrive before the ClientHello completes (they are dropped and
      the client resends them as 1-RTT)
- [x] **Several certificates selected by SNI** (`TlsOptions.certificates`,
      RFC 6066 §3), over TCP and QUIC: the first certificate, the default
      first, whose subject alternative names cover the ClientHello's
      host_name (std's RFC 6125 matching: any case, one wildcard label);
      the default for an unknown name or none. An empty server_name in
      EncryptedExtensions when the name chose the certificate (full
      handshakes only); a malformed or doubled host_name fails. Tickets
      record the certificate index and resume (and take 0-RTT) only when
      the name selects the same certificate, so a session authenticated
      for one name never resumes as another. Proof: handshake tests (exact,
      any case, wildcard, its apex listed too, too deep, unknown, none,
      malformed; resumption across names); end to end on every backend with
      std's client, which checks the name; OpenSSL 3.5 `-servername` and
      aioquic over HTTP/3 on epoll and io_uring (`bench-server ... sni`).
      Linear in the number of certificates
- [ ] OCSP stapling
- [x] **kTLS on Linux** (`TlsOptions.ktls`, on by default): the sending side of
      an HTTP/1.1 connection goes to the kernel (TCP_ULP "tls", TLS_TX with the
      current key, IV split into salt and the rest, and record sequence number)
      just before its first file body, once our own records are written; from
      then on the file goes out with sendfile and everything else as plaintext
      writes, and the kernel makes the records. Receiving stays in user space.
      On demand rather than for every connection because, measured, kTLS only
      pays for files: our fused AES-GCM beats the kernel's GCM (AES and GHASH
      passes, plus the copy in) for bytes already in memory. Our own records
      then go out with sendmsg and a TLS_SET_RECORD_TYPE control message
      (close_notify and other alerts). KeyUpdate: ours (at the record limit,
      counted as an upper bound: one per write plus one per 16 KiB) or one the
      client requests is sent before any more data (a gate on every write path:
      a full socket waits like EAGAIN, POLLOUT on io_uring), then the kernel
      gets the next key (TLS_TX again: TLS 1.3 rekey, Linux 6.14 on); a kernel
      that refuses (6.12) means the connection is closed, with no alert since
      its records no longer match the client's keys. A missing `tls` module
      (ENOENT) turns kTLS off for the worker; an unsupported cipher just keeps
      that connection in user space. Proof: a test hands one end of a loopback
      pair to the kernel with a known key and nonzero sequence number and
      opens what it sends (data, a KeyUpdate, data under the next key, an
      alert) with our record layer, every suite; end-to-end on epoll and
      io_uring (responses, then files through sendfile over kTLS, close_notify
      through the kernel, and an 8 MB file with a KeyUpdate every 4 records:
      about 128 rekeys on 6.18, a close on 6.12); curl over HTTP/1.1 and h2
      (only HTTP/1.1 file connections switch: TlsTxSw); OpenSSL 3.3 KeyUpdate
      both ways after a file (`K` answered on 6.18, closed on 6.12). Docker
      Desktop's kernel has no kTLS, so this runs in a QEMU/HVF VM with Alpine's
      linux-virt kernels 6.12 and 6.18 (tls and the arm64 crypto modules
      loaded); the whole suite passes on both. Benchmark (6.18 VM, 4 workers,
      wrk -t4 -c32 over TLS in the same VM, two rounds): 1 MiB file 349-366 µs
      server CPU per request with kTLS against 477-521 µs read and encrypted
      in user space; in-memory bodies unchanged (64 KiB 33-35 µs, 1 MiB
      311-343 µs). With kTLS forced on every connection they cost 41-43 and
      399-452 µs, hence on demand. Also on real x86_64 hardware: a Hetzner
      VM with Ubuntu 24.04 (6.8.0-138, AES-NI), whole suite passes (rekey
      closes, as on 6.12). That box turned up an Ubuntu kernel bug: from
      6.8.0-136 (still in -147) the backport of "io_uring/kbuf: use
      mem_is_zero()" inverted the check on io_uring_buf_reg.resv, so every
      correct buffer ring registration gets EINVAL and the io_uring worker
      failed to start. The worker now registers the ring itself, retrying
      with a reserved word set (which a correct kernel refuses), and
      `available()` probes a buffer ring so anything else falls back to epoll
- [ ] TLS 1.2 (ECDHE + AEAD only) if real clients need it
- [ ] Differential testing with tlsfuzzer or BoringSSL's BoGo runner

---

## M5. HTTP/2 ⬜

Prerequisite: TLS with ALPN (M4). Also `h2c` with prior knowledge (no `Upgrade: h2c`,
which RFC 9113 deprecated).

- [x] **Handler API, steps 1 and 2** of `docs/handler-api-proposal.md`, on HTTP/1.1
      (`src/http/exchange.zig`, `src/mailbox.zig`): `resp.later()` and
      `resp.stream()` turn a request into an `Exchange`, a value handle
      `{slab, slot, generation}` into a per-worker slab; `ex.respond`,
      `ex.startStream`, `ex.write`, `ex.writeBorrowed` (released on the worker
      thread once written), `ex.finish(trailers)`, `ex.abort`, `ex.setTimeout` work
      from any thread through the worker's mailbox, now keyed by (kind, slot,
      generation) for WebSockets and exchanges alike. HTTP/1.1 framing (chunked with
      trailers, Content-Length, close-delimited for HTTP/1.0, nothing for HEAD) is
      written by the worker as the queue drains, one chunk per drain. Bounded queue
      with `handleWritable`; `handleAbort` when the client leaves or the exchange
      times out (`response_timeout_s` for `later()`, `request_timeout_s` between
      writes). Pipelining rule: parsing pauses while an exchange is pending. The
      synchronous path is unchanged: one branch on `resp.mode`, measured within
      noise (`zig build bench`, keep-alive and pipelined wrk)
- [x] **Handler API step 3** on HTTP/1.1, HTTP/2 and HTTP/3: an optional
      `handleHead(req, resp) BodyMode` runs once the head is parsed.
      `.buffer` is today's behaviour; `.reject` answers with `resp` without
      reading the body (no 100 Continue; h1 closes with a lingering close if
      a body was announced, h2 RST_STREAM(NO_ERROR), h3
      STOP_SENDING(H3_NO_ERROR)); `.stream` calls handleRequest at once, and
      once it takes an exchange the body goes to `handleBody(ex, chunk, end)`
      as it arrives, with no size limit, the trailers on the last call.
      `.pause` holds the client back through the transport until
      `ex.resumeBody()` (any thread): h1 stops reading the socket, h2 returns
      window only for delivered bytes (keeping at most a window of DATA),
      h3 leaves DATA unread in the QUIC stream (no MAX_STREAM_DATA). A
      response that ends before its body leaves the rest unread. Request
      trailers are kept (`req.trailers` when buffered; validated like other
      fields on h2/h3). The h1 chunked decoder gained a piece-by-piece mode
      (`ChunkedScanner.next`), trailer sections bounded by max_header_bytes.
      Proof: session tests under every split with and without pauses, a
      fuzz target (`fuzz: streamed body split invariance`), in-memory h2/h3
      tests (including that a paused body really holds the window), streamed
      and rejected requests in the h2 split-invariance script, end-to-end
      uploads beyond max_body_size on h1, TLS, h2c and HTTP/3, held and
      resumed from another thread, on kqueue, epoll and io_uring; h2spec
      146/146 over TLS and h3spec 77/77 also with `bench-server ... stream`
      (every body streamed). The fast path is unchanged (`zig build bench`
      and wrk keep-alive/pipelined within noise)
- [x] Frame layer (RFC 9113), `src/h2/frame.zig`: I/O-free `Reader` with the
      `Session` buffer discipline (pooled, held only while bytes are unprocessed,
      grown for a frame larger than a pool buffer), a parser for every frame type
      that checks lengths, flags, padding, stream identifiers and SETTINGS values
      and maps each violation to the RFC's connection or stream error code, and
      serialisers. Proof: a test per malformed case, split invariance, a fuzz
      target
- [x] HPACK (RFC 7541), `src/h2/hpack.zig`: static and dynamic tables, integer
      and string coding, a nibble-driven Huffman decoder generated at comptime from
      the Appendix B table (checked canonical and complete), an encoder with
      incremental indexing and Huffman-when-shorter. Limits: table size (a size
      update above what we advertised is a COMPRESSION_ERROR), header list size
      (decoding continues so the table stays in sync, then HeaderListTooLarge),
      field length. Proof: every Appendix C example byte for byte in both
      directions (C.2-C.6, with table contents and sizes), round-trip property
      tests, a fuzz target over the decoder
- [x] **Connection layer**, `src/h2/conn.zig`, I/O-free: preface, SETTINGS
      exchange and ack, PING, GOAWAY both ways (graceful: open streams finish, new
      ones are refused), stream states with a ring of recently closed streams to
      tell "closed" from "idle" (§5.1), `SETTINGS_MAX_CONCURRENT_STREAMS` with
      REFUSED_STREAM (the refused block is still decoded so HPACK stays in sync),
      connection and stream flow control with WINDOW_UPDATEs batched at half a
      window, request assembly (CONTINUATION, pseudo-headers, §8.2 and §8.3
      validation, content-length checks, trailers validated and dropped, a `host`
      header synthesised from `:authority`). Each stream maps to the handler API:
      the synchronous path serialises HEADERS+DATA when `handleRequest` returns
      with no allocation in steady state (a body the windows don't allow is copied
      to the stream's pending buffer); `later()`/`stream()` exchanges are drained
      per stream, trailers as a trailing HEADERS. RFC 7540 priorities are
      ignored; RFC 9218 ones order the output (below). Output backpressure: parsing stops above
      `out_limit` until the worker has written.
      Defences, each with a test: rapid reset (RST_STREAM budget per second),
      CONTINUATION flood (block bounded by `max_header_bytes`, and a block that
      never completes times out), HPACK bomb (header list size limit, 431, table
      in sync), SETTINGS/PING/empty-frame floods (control frames per second),
      zero-window stalls (stream reset after `request_timeout_s` without window;
      connection closed when its window is the cause). Proof: a scripted-client
      harness (each §8 rule, stream states, flow control, exchanges, GOAWAY),
      split invariance per stream, a fuzz target
- [x] **Worker integration** on epoll, kqueue and io_uring: ALPN "h2" over TLS
      (decided once the handshake completes, adopting application data from the
      same read), h2c with prior knowledge on plaintext listeners (`Config.h2c`:
      the first 24 bytes decide, HTTP/1.1 otherwise), the mailbox routes exchange
      posts and deadlines to the stream, GOAWAY on shutdown (one best-effort write
      per connection). Output is double-buffered (`out`/`wire`) so the connection
      runs while a write is in flight on io_uring; the connection is only run, not
      driven, inside receive loops (a recv armed with plaintext still untaken read
      as EOF). End-to-end tests on every backend over h2c: 100 concurrent streams
      plus HTTP/1.1 on the same port, 8 MB down and 1 MB up through flow control
      (frames straddling receive buffers), `later()` from another thread and
      `stream()` with trailers, GOAWAY on shutdown, the client's GOAWAY.
      Interop (curl --http2 and --http2-prior-knowledge, nghttp, OpenSSL s_client
      ALPN): all pass on macOS, Linux epoll and Linux io_uring (std's TLS client
      has no ALPN, so TLS+h2 is covered by interop rather than Zig tests)
- [x] **Priorities (RFC 9218)** on HTTP/2 and HTTP/3. `src/http/priority.zig`
      parses the `priority` field and PRIORITY_UPDATE values as a Structured
      Fields dictionary (RFC 9651): `u` (0-7) and `i`; unknown members, out of
      range and wrongly typed values ignored; a field that fails to parse
      ignored whole. h2: SETTINGS_NO_RFC7540_PRIORITIES=1 sent (the client's
      value validated); PRIORITY_UPDATE (0x10) with the §7.1 errors (on a
      stream, prioritising stream 0 or a push stream, idle prioritised
      streams plus open ones over MAX_CONCURRENT_STREAMS); an update for an
      idle stream is kept until it opens and wins over its header. `pumpAll`
      sends in priority order: by urgency, non-incremental streams in stream
      order, then the incremental ones of that urgency in turns of 16 KB. A
      stream that would send directly (a post, a window update, a synchronous
      response) yields while a more urgent one waits for room in `out_limit`
      or for the connection window. h3: PRIORITY_UPDATE (0xf0700, 0xf0701)
      on the control stream only (H3_FRAME_UNEXPECTED elsewhere; H3_ID_ERROR
      for a push ID, a non-request stream, or one beyond the stream limit);
      the priority goes to QUIC, whose send queue is ordered the same way
      (incremental streams take turns per packet; our control and QPACK
      streams first). A tunnel (WebSocket) counts as incremental, so it never
      holds later responses back (§10.1). Starvation is not a timeout: h2's
      stall reset now counts only a zero window, and an exchange whose output
      waits behind other streams has its deadline postponed instead of being
      reset (the worker's write timeout still covers a client that reads
      nothing). Proof: parser tests; h2 tests (the exact DATA order under the
      connection window and under `out_limit`, PRIORITY_UPDATE before and
      after a request, each error, a waiting exchange kept); h3 tests (the
      order across packets with an incremental pair interleaved, which fails
      with a FIFO send queue; updates before and after a request, each error,
      a waiting exchange kept); `priority` headers and PRIORITY_UPDATEs in the
      h2 split-invariance script and both connection fuzz targets (fuzzed
      together on Linux, ReleaseSafe, 6 instances, 25 min: about 8.2M runs,
      707 corpus inputs, 18.5% of instrumented PCs, no failures, after the
      first run found an older split-invariance bug: frames after a client's
      GOAWAY were read only when they arrived in the same read, fixed in
      534d861). Interop on
      Linux: nghttp 1.69 `--extpri` over h2c (u=0 first, the `u=1,i` pair
      alternating frame by frame, then u=5, then the rest of a u=7 stream that
      had started first), aioquic 1.3 over HTTP/3 with `priority` headers and
      a raw PRIORITY_UPDATE (the same order; the client's receive path drops
      30-40 of ~290 packets, and retransmissions reorder only the tail).
      h2spec (146/146 TLS, 145/146 h2c) and h3spec (77/77) unchanged; h2load
      before and after within noise.
      Not done: server-driven priorities (§8: a handler adjusting a
      response's priority)
- [x] **WebSockets over h2 (RFC 8441) and h3 (RFC 9220)**. With a handler that has `handleWSFrame`, both send
      SETTINGS_ENABLE_CONNECT_PROTOCOL; `:protocol` is otherwise an unknown
      pseudo-header (malformed), is only valid on CONNECT, and an extended
      CONNECT needs `:scheme` and `:path` like any request (a proxy's
      CONNECT is still 501). The request reaches `handleHead` and
      `handleRequest` at once with `req.method == .CONNECT` and
      `req.protocol`; `ws.upgrader.handleUpgrade` answers 200 (101 on
      HTTP/1.1), and the stream gets a `ws.Conn`, the same decoder, send
      queue and close handshake as HTTP/1.1, so handlers are unchanged.
      DATA carries the WebSocket bytes both ways (h3: DATA frames, unknown
      frame types skipped). A handler that answers otherwise gets an
      ordinary response, then RST_STREAM(NO_ERROR) / STOP_SENDING
      (H3_NO_ERROR), and the client's DATA is dropped, never buffered.
      Endings map like TCP: the close handshake, a failure (1002/1007/1009)
      or the client's END_STREAM/FIN ends our side once the output is
      written (END_STREAM/FIN, then a reset of the client's side if it is
      still open); the client's RST_STREAM/RESET_STREAM/STOP_SENDING drops
      it at once; `handleWSDisconn` follows in every case.
      Cross-thread sends: a `ws.Conn` now posts a caller-chosen mailbox
      entry; over h2/h3 that is a **tunnel slot** in the exchange slab
      (bound to connection and stream, never handed out, no handleAbort),
      so posts, mailbox overflow and the per-second deadline scan route to
      the stream with no new machinery. Each such WebSocket takes one of
      `max_exchanges_per_worker` (503 when none is free).
      Backpressure as on HTTP/1.1, through flow control: h2 holds the
      stream's WINDOW_UPDATE while the WebSocket's output is held back
      (window, or `out_limit`), h3 leaves DATA unread in the QUIC stream
      (no MAX_STREAM_DATA) while output exceeds `stream_buffer`. Timeouts
      as on HTTP/1.1: `request_timeout_s` while output is stalled or our
      close frame waits for the client's (the tunnel slot's deadline;
      h2's zero-window stall reset also applies), none when idle.
      Proof: in-memory h2 tests (the setting, validation, echo, ping,
      both close handshakes, END_STREAM on HEADERS and DATA, RST_STREAM,
      a 1002 failure, a refused CONNECT, a full slab (503), windows
      holding output, held
      output holding the client's window, a send from another thread, a
      stalled stream reset) and h3 tests (the setting, validation, echo,
      ping, both close handshakes, FIN, STOP_SENDING, a 1002 failure, a
      refused CONNECT, a send from another thread, 200 KB through a 16 KB
      stream buffer with input held behind it); WebSocket
      streams (split DATA, a message larger than a read buffer, fragments
      around a ping, both closes) in the h2 split-invariance script and
      both connection fuzz targets (fuzzed together on Linux, Docker,
      ReleaseSafe, 6 instances, 25 min: about 8.4M runs, 589 corpus
      inputs kept, no failures; 17.9% of the test binary's instrumented
      PCs seen); end-to-end over h2c and HTTP/3 on
      kqueue, epoll and io_uring (two WebSockets and requests interleaved
      on one connection, 100 KB echo, a send from another thread, both
      close handshakes). Interop on Linux epoll and io_uring: python-hyper
      h2 4.1 over TLS (ALPN) and h2c, aioquic 1.3 over HTTP/3 (three
      WebSockets plus a GET on one connection, text, ping, 300 KiB binary,
      a fragmented message, both close forms and a bare END_STREAM/FIN).
      h2spec (146/146 TLS, 145/146 h2c as before) and h3spec (77/77) are
      unchanged with the setting advertised. `bench-server` serves a
      WebSocket echo on `/ws`.
      Not done: browsers (Chrome and Firefox use RFC 8441; Firefox RFC
      9220) untested; no WebSocket benchmark yet (M3)
- [x] Verification: h2spec (all 146 cases): 146/146 over TLS, 145/146 over h2c,
      where the one failure (3.5/2, an invalid connection preface) is the
      cleartext port answering it as an HTTP/1.1 request (501, then close) rather
      than closing silently, inherent to serving both on one port. Split
      invariance and fuzz targets per layer (see above)
- [ ] **Unexplained h2spec result, not reproduced.** On 2026-10-28 (commit
      a51305d), one h2c run reported 144/146 (two failures) where 145/146 is
      expected. Setup: one `peregrine-test` container (io_uring seccomp
      profile) running `bench-server 2 io_uring 8443 tls stream` and
      `bench-server 2 io_uring 8080 plain stream` side by side, started 1.5 s
      before `summerwind/h2spec -h 127.0.0.1 -p 8080` (run right after the
      TLS pass on 8443, which gave 146/146). Only the summary line was kept,
      so the failing case names are unknown. Not seen again in 50+ reruns:
      the same two-server setup 5 times, and one server alone 15 times each
      for new/streamed, new/buffered and the base commit 9a3c182. Those
      reruns showed timing effects: 3.5/2 occasionally passes, and one run
      printed no summary at all. Likely a timing flake, but unproven. To
      retry: rerun that setup in a loop and keep the full output (every
      `×` line), e.g. 50 runs per backend, and with the host under load
- [x] Benchmark against nginx with h2load (h2o has no Alpine package; still to do).
      Docker on the M2 Pro, Linux 6.12, host under other load (load average 5-12,
      so ±10%): each server with 6 workers on CPUs 0-5, `h2load -t6` on CPUs 6-11,
      10 s per run, two interleaved rounds; nginx 1.26 with `http2 on`,
      TLSv1.3, `return 200` for "Hello, World!" and a 64 KiB file, otherwise
      defaults. CPU/req is the server's CPU time per request, the better measure:
      at `-c10 -m100` h2load itself is the bottleneck.

| | peregrine req/s | peregrine CPU/req | nginx req/s | nginx CPU/req |
|---|---|---|---|---|
| h2c "Hello", 10 conns × 100 streams | 527k-541k | 0.59-0.64 µs | 128k-148k | 4.5-4.9 µs |
| h2c "Hello", 256 conns × 1 stream | 410k-439k | 6.7-7.9 µs | 97k-103k | 15.7-16.1 µs |
| h2c 64 KiB, 10 conns × 10 streams | 193k-210k (12.6-13.8 GB/s) | 20.9-21.0 µs | 11.0k-13.1k | 111-112 µs |
| TLS "Hello", 10 × 100 | 515k-519k | 0.66-0.72 µs | 88k-95k | 4.2-4.8 µs |
| TLS "Hello", 256 × 1 | 160k-172k | 11.2-12.0 µs | 70k-70k | 29.9-30.8 µs |
| TLS 64 KiB, 10 × 10 | 64k-73k (4.2-4.8 GB/s) | 31.8-34.3 µs | 10.4k-11.6k | 131-139 µs |

      To do: h2o, a quiet machine, latency percentiles, and `-Dcpu` for x86_64
- [ ] Benchmark against h2o

## M6. HTTP/3 and QUIC 🟡

Done on the `m6-h3` branch, as I/O-free layers like the rest:

| File | Role |
|---|---|
| `src/quic/packet.zig` | Varints, long and short headers, packet numbers, Version Negotiation |
| `src/quic/protection.zig` | Initial secrets, packet and header protection from TLS secrets, key updates, Retry integrity tags |
| `src/quic/frame.zig` | Every QUIC frame, with the RFC's encoding errors and per-packet-type rules |
| `src/quic/transport_params.zig` | Client parameters checked, ours encoded |
| `src/quic/recovery.zig`, `sent.zig`, `ranges.zig`, `stream.zig` | RTT, loss and probe timeouts, CUBIC/NewReno; sent packets with frame records; reassembly, flow control and retransmission bookkeeping |
| `src/quic/conn.zig` | One server connection: packet number spaces, TLS over CRYPTO, ACKs, loss recovery, streams, key updates, closing |
| `src/quic/endpoint.zig`, `udp.zig` | A worker's UDP socket and connections: routing by connection ID, timers, VN, stateless reset, Retry, recvmmsg, GSO, BPF steering |
| `src/h3/qpack.zig`, `frame.zig`, `conn.zig` | QPACK (static table), HTTP/3 frames and SETTINGS, HTTP/3 over a QUIC connection through the handler API |
| `src/http/fields.zig` | Request field validation shared by HTTP/2 and HTTP/3 |

- [x] UDP workers: a socket per worker with `SO_REUSEPORT` and a classic BPF
      program on the group that picks the socket from the first byte of the
      Destination Connection ID; our 8-byte connection IDs start with the
      owning worker's index, so nothing crosses threads (Linux; macOS serves
      HTTP/3 from the first worker). epoll, kqueue and io_uring (multishot
      poll on the socket, a timeout SQE for the next QUIC timer)
- [x] QUIC transport (RFC 9000): headers, coalesced packets, every frame,
      transport parameters, stream states, flow control with credit at half a
      window, MAX_STREAMS as streams close, CONNECTION_CLOSE with closing and
      draining, idle timeout, stateless reset, Version Negotiation, Retry with
      an AEAD-sealed address-bound token (`Http3Options.retry`), the
      anti-amplification limit, PATH_CHALLENGE answered
- [x] QUIC-TLS (RFC 9001): the TLS handshake in QUIC mode (transport
      parameters both ways, ALPN required, no middlebox compatibility),
      packet and header protection with the fused AES-GCM, key updates both
      ways (ours after 2^22 packets). Every Appendix A vector is a test
- [x] Loss detection and congestion control (RFC 9002): packet and time
      thresholds, probe timeouts with backoff, persistent congestion, CUBIC
      (RFC 9438) with a NewReno option
- [ ] Pacing, ECN, PMTU discovery (DPLPMTUD); `max_datagram_size` is 1350
- [x] UDP batching: recvmmsg, GSO (datagrams nearly full are padded to the
      segment size so runs go out in one sendmsg). GRO still to do
- [x] HTTP/3 (RFC 9114) and QPACK (RFC 9204, static table, capacity 0):
      control and QPACK stream rules, frame sequencing, malformed and
      incomplete requests, 413/431/501 before the rest of the request with
      STOP_SENDING, later()/stream() exchanges with trailers, GOAWAY with a
      graceful close once responses are acknowledged
- [x] `Alt-Svc` on every HTTP/1.1, HTTP/2 and HTTP/3 response (preset
      header lines, no per-request cost)
- [ ] Connection migration: NEW_CONNECTION_ID, path validation (we
      advertise `disable_active_migration`; NAT rebinding is followed
      without validation)
- [x] 0-RTT: see M4
- [x] WebSockets over h3 (RFC 9220): see M5
- [x] Priorities (RFC 9218): see M5
- [ ] DATAGRAM (RFC 9221)
- [ ] QPACK dynamic table (better request header compression)
- [x] Verification: RFC 9001 vectors; in-memory tests of both layers with a
      QUIC test client written for them (handshake, 40-60 concurrent
      requests, 3 MB transfers both ways through flow control, 15% loss,
      key update, every transport and HTTP/3 error); end to end over UDP on
      every backend; interop with aioquic 1.3, curl 8.23 (ngtcp2 1.25 +
      OpenSSL 3.5) and h2load (nghttp2 1.70); `fuzz: h3 connection`
- [x] h3spec 0.1.14: 77/77 on kqueue, epoll and io_uring
- [ ] quic-interop-runner
- [x] Benchmark against nginx 1.29 (`http3 on`, `quic_gso on`) and Caddy 2.11

HTTP/3 benchmark (Docker on the M2 Pro, Linux 6.12; each server with 6
workers on CPUs 0-5, `h2load --alpn-list=h3 -t6` on CPUs 6-11, 10 s runs, two
rounds; host load 5-14, so ±15%). CPU/req is server CPU time per request.

| | peregrine req/s | CPU/req | nginx req/s | CPU/req | Caddy req/s | CPU/req |
|---|---|---|---|---|---|---|
| "Hello", 10 conns × 100 streams | 316k-321k | 1.9-2.1 µs | 221k-227k | 4.8-4.9 µs | 160k-179k | 31-33 µs |
| 64 KiB, 10 × 10 | 77k-78k (4.7 GB/s) | 40 µs | 11k-12k | 149-155 µs | 6.5k-6.7k | 387-403 µs |
| "Hello", 256 conns × 1 stream | 44k-130k | 16-20 µs | 74k-113k | 27-34 µs | 85k-95k | 62-68 µs |

At 256 × 1, h2load is the limit (it waits about 1.4 ms between requests on a
connection, for every server), so compare CPU/req there.

---

## M7. Verification and benchmarking 🟡

- [x] Fuzzing with Zig's built-in fuzzer: `fuzz: split invariance` in `session.zig`
      (about 322K runs on Linux, no failures; `zig build test --fuzz=300K`. On macOS
      the 0.17 fuzz runner hung at 0% CPU, so run it on Linux)
- [x] TLS fuzz target over `tls.Conn` (see M4)
- [ ] Structure-aware fuzzing (grammar-based request generation)
- [ ] Differential parser testing (HTTP Garden) for smuggling discrepancies
- [ ] Protocol suites: tlsfuzzer/BoGo (TLS), quic-interop-runner (QUIC/h3).
      Done: Autobahn (WebSockets, M3), h2spec (h2, M5), h3spec (h3, M6)
- [ ] Response correctness (REDbot)
- [x] **The occasional "1 tests leaked memory" on Linux** (seen twice on
      2026-10-28, never reproduced on demand): caught with the full log in a
      loop of io_uring runs (1 in 4). The HTTP/3 test client's `response`
      appended each whole DATA frame to the body, then returned
      error.Truncated for a frame still arriving without freeing it;
      `waitBody` polls it, so a read ending just inside a second DATA
      frame leaked the first. Test-only; `response` now frees on error
- [ ] Soak: hours at high concurrency, steady RSS and fd count
- [ ] Adversarial load: slowloris (basic test exists), oversized headers, half-open
      connections, connection floods, TLS handshake floods
- [ ] Benchmark methodology:
  - [x] Linux, isolated pinned cores (server on CPUs 0–5, `wrk` on 6–11), loopback.
        **Still to do: separate machines**
  - [x] `wrk` keep-alive, plus pipelined ×16 (TechEmpower plaintext style)
  - [ ] Latency percentiles at a fixed rate (`wrk2`)
  - [ ] TLS: handshakes/s per core. Throughput over TLS: first numbers in M4
  - [ ] h2/h3: h2load
  - [x] Baseline nginx; h2o, facil.io (what Zap wraps), uWebSockets and
        may-minihttp (HTTP/1.1, below). Still to do: a minimal raw-epoll C
        server, h2o 2.3 (2.2.6 was measured), h2/h3 against h2o
  - [x] `zig build bench`, `bench-tls` and `bench-server` build the library
        with `.fast` too. They imported the `peregrine` module, which keeps
        its own optimize mode (Debug by default), so without `-Doptimize` the
        library ran with runtime safety checks: about 5% more server CPU per
        pipelined request on epoll

HTTP/1.1 against other fast servers (2026-10-29; Docker on the M2 Pro, Linux 6.12
aarch64, plaintext "Hello, World!"; every server on CPUs 0-5 with 6 workers, `wrk -t6
-d8s` on 6-11; two interleaved rounds; CPU per request from the server's cgroup):

| | keep-alive c=256 | | pipelined ×16 c=256 | | keep-alive c=1024 | |
|---|---|---|---|---|---|---|
| | req/s | CPU/req | req/s | CPU/req | req/s | CPU/req |
| peregrine io_uring | 1.15M | 4.85 µs | 8.81M-8.88M | 0.58 µs | 1.22M | 4.68 µs |
| peregrine epoll | 1.14M-1.17M | 4.90-5.00 µs | 8.98M-9.00M | 0.55 µs | 1.19M-1.21M | 4.78-4.84 µs |
| uWebSockets 20.74 | 1.11M | 5.06 µs | 8.29M-8.30M | 0.64-0.65 µs | 1.16M | 4.91-4.93 µs |
| may-minihttp | 1.02M | 5.56 µs | 8.33M-8.34M | 0.58 µs | 1.10M | 5.21-5.23 µs |
| facil.io 0.7.6 | 0.98M-0.99M | 5.75-5.81 µs | 2.09M-2.15M | 2.79-2.87 µs | 1.00M | 5.72-5.74 µs |
| nginx 1.26 | 1.00M-1.01M | 5.69-5.72 µs | 1.26M-1.28M | 4.69-4.77 µs | 1.02M | 5.65 µs |
| h2o 2.2.6 | 0.88M-0.90M | 6.51-6.63 µs | 1.49M-1.52M | 3.96-4.03 µs | 0.92M | 6.29 µs |

Built from source in Alpine 3.21 (C/C++ with `-O3 -march=native`, Rust with
`target-cpu=native`): facil.io's `http_listen` with `fio_start(.threads = 1,
.workers = 6)`; uWebSockets' `App` on 6 threads (SO_REUSEPORT); may-minihttp's
hello example with 6 workers; h2o with `num-threads: 6` serving a static file; nginx
`return 200`. Response heads differ: peregrine 102 bytes, uWebSockets 119,
may-minihttp 113, facil.io 167, h2o 233.

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
