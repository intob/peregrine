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
| M1. HTTP/1.1 core | ✅ done (streaming responses deferred to the API redesign in M5) |
| M2. Throughput architecture | 🟡 io_uring works (opt-in, not yet faster than epoll); sendfile, NUMA open |
| M3. WebSockets over HTTP/1.1 | ✅ reworked; permessage-deflate, Autobahn, benchmarks open |
| M4. TLS 1.3 | 🟡 **in progress**: I/O-free handshake and record layer, integrated into the epoll/kqueue worker |
| M5. HTTP/2 | ⬜ next after TLS |
| M6. HTTP/3 and QUIC | ⬜ |
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
| `src/ws/protocol.zig` | I/O-free WebSocket frame decoder and message assembler |
| `src/ws/conn.zig` | Per-connection WebSocket state: send queue, close handshake, cross-thread mailbox |
| `src/ws/upgrader.zig` | The HTTP upgrade response |
| `src/tls/` | TLS 1.3 server (M4): see below |
| `src/server_test.zig` | End-to-end tests over real sockets, run once per available backend |
| `bench/` | `zig build bench` (parser micro-benchmarks), `zig build bench-server` (load-test target) |

`src/https/` is the old blocking TLS prototype. It is not compiled and will be deleted
once `src/tls/` covers it.

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
- **Deferred:** chunked/streaming responses. The handler API is synchronous
  (`handleRequest` fills a Response and returns). This becomes part of the handler API
  redesign in M5, because HTTP/2 and HTTP/3 need streaming and multiplexing anyway.

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
- [ ] **Make io_uring faster than epoll.** Equal within noise today, so `.auto` picks
      epoll. To try: multishot recv, registered (direct) fds, `send` instead of
      `writev` for one buffer, `send_zc` for large bodies, bigger completion batches,
      back off re-arming accept on `EMFILE`
- [x] Listener per worker with `SO_REUSEPORT` (`SO_REUSEPORT_LB` where available);
      macOS workers share one listener in their own kqueues
- [x] `TCP_DEFER_ACCEPT` plus reading straight after accept
- [x] Workers pinned to cores (`pin_workers`, respects the allowed CPU set)
- [x] Zero-copy bodies (`setBodyBorrowed`), format-in-place (`bodyWriteBuffer` /
      `commitBody`), status line + headers + body in at most two iovecs
- [ ] `sendfile`/`splice` for file bodies (plaintext only; over TLS needs kTLS, M4)
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
- [ ] Autobahn test suite, and a fuzz target over the decoder
- [ ] Benchmark: messages/s per core vs. uWebSockets
- [ ] WebSockets over HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220): M5 and M6

---

## M4. TLS 1.3 🟡 (in progress)

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
- Certificates: ECDSA P-256/P-384 and Ed25519 keys (PKCS#8 or SEC1 PEM). The chain is
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

The handshake keeps a running transcript hash, not the transcript, and its state is
freed when the handshake ends, so an established connection only holds two record
protection states (keys, IVs, sequence numbers).

**Worker integration** (epoll/kqueue): the TLS connection sits between the socket and
the session (or the WebSocket decoder). Reads go socket → `tls.Conn` (decrypt) →
session buffer. Writes go session `Out` → `tls.Conn` (encrypt into records of up to
16 KB) → socket. The existing pending-output and backpressure machinery covers the
ciphertext too: unsent ciphertext counts as pending output, and plaintext not yet
encrypted is kept like an unsent response.

Checklist:
- [x] Decide: rewrite as I/O-free layers in `src/tls/` instead of fixing `src/https/`
      (it was blocking, had no bounds checks, used an empty AAD and no sequence-number
      nonce, and assumed one read per record)
- [ ] `key_schedule.zig` + RFC 8448 test vectors
- [ ] `record.zig` + tests (round trip, tampering, padding, limits)
- [ ] `handshake.zig`: ClientHello parsing (strict, bounds-checked), negotiation,
      HRR, server flight, client Finished
- [ ] `credentials.zig`: PEM chain, PKCS#8/SEC1 keys
- [ ] `conn.zig`: records ↔ handshake ↔ application data, alerts, close_notify,
      KeyUpdate
- [ ] Handshake test against `std.crypto.tls.Client` (in-process, over a socketpair)
- [ ] `Config.tls`, worker integration for HTTP and WebSockets, end-to-end tests
- [ ] Interop check with curl and `openssl s_client`
- [ ] io_uring backend integration
- [ ] Random-split property test and fuzz target over `tls.Conn`
- [ ] Remove `src/https/`

Later in M4:
- [ ] Faster record crypto: keep expanded AES key schedules per connection instead of
      re-expanding per record (std's AEAD API takes raw keys), and decrypt straight
      into the session buffer
- [ ] RSA certificates (RSA-PSS signing: std has only verification)
- [ ] Session tickets and resumption (PSK-DHE); 0-RTT only with replay protection
- [ ] Several certificates selected by SNI; OCSP stapling
- [ ] **kTLS on Linux**: handshake in userspace, record crypto in the kernel, so
      `sendfile` works over TLS
- [ ] TLS 1.2 (ECDHE + AEAD only) if real clients need it
- [ ] Differential testing with tlsfuzzer or BoringSSL's BoGo runner

---

## M5. HTTP/2 ⬜

Prerequisite: TLS with ALPN (M4). Also `h2c` with prior knowledge (no `Upgrade: h2c`,
which RFC 9113 deprecated).

- [ ] **Handler API redesign**, shared by HTTP/1.1, h2 and h3: streaming responses
      (and chunked HTTP/1.1 responses, deferred from M1), streaming request bodies,
      trailers, and a handler that can respond later (needed for multiplexing). Keep
      the synchronous fast path for the simple case
- [ ] Frame layer (RFC 9113): I/O-free, same buffer discipline as `Session`
- [ ] HPACK (RFC 7541): static/dynamic tables, Huffman decode/encode, strict limits
- [ ] Streams: state machine, concurrency limits, priorities (RFC 9218
      `Priority` header and `PRIORITY_UPDATE`; ignore RFC 7540 priorities)
- [ ] Flow control (connection and stream windows), batching `WINDOW_UPDATE`s
- [ ] Defences: rapid reset (CVE-2023-44487), CONTINUATION flood, HPACK bomb,
      settings/ping floods, zero-window stalls
- [ ] Graceful shutdown with `GOAWAY`
- [ ] WebSockets over h2 (RFC 8441 extended CONNECT)
- [ ] Verification: h2spec, fuzzing, split-invariance property tests
- [ ] Benchmark against h2o and nginx (h2load)

## M6. HTTP/3 and QUIC ⬜

- [ ] UDP workers: socket per worker with `SO_REUSEPORT`; connection IDs encode the
      worker, and packets that land on the wrong worker are forwarded
- [ ] QUIC transport (RFC 9000): packet parsing, connection IDs, streams, flow
      control, connection close, stateless reset, version negotiation, Retry
      (address validation under load)
- [ ] QUIC-TLS (RFC 9001): drive `tls/handshake.zig` over CRYPTO frames; packet and
      header protection keys from the same key schedule
- [ ] Loss detection and congestion control (RFC 9002): NewReno first, then CUBIC;
      pacing
- [ ] UDP batching: GSO/GRO, `sendmmsg`/`recvmmsg`, io_uring
- [ ] HTTP/3 (RFC 9114) and QPACK (RFC 9204)
- [ ] `Alt-Svc` advertisement from h1/h2
- [ ] WebSockets over h3 (RFC 9220)
- [ ] Verification: quic-interop-runner, fuzzing
- [ ] Benchmark against h2o, nginx and quiche-based servers

---

## M7. Verification and benchmarking 🟡

- [x] Fuzzing with Zig's built-in fuzzer: `fuzz: split invariance` in `session.zig`
      (about 322K runs on Linux, no failures; `zig build test --fuzz=300K`. On macOS
      the 0.17 fuzz runner hung at 0% CPU, so run it on Linux)
- [ ] Structure-aware fuzzing (grammar-based request generation)
- [ ] Differential parser testing (HTTP Garden) for smuggling discrepancies
- [ ] Protocol suites: Autobahn (WebSockets), tlsfuzzer/BoGo (TLS), h2spec (h2),
      quic-interop-runner (QUIC/h3)
- [ ] Response correctness (REDbot)
- [ ] Soak: hours at high concurrency, steady RSS and fd count
- [ ] Adversarial load: slowloris (basic test exists), oversized headers, half-open
      connections, connection floods, TLS handshake floods
- [ ] Benchmark methodology:
  - [x] Linux, isolated pinned cores (server on CPUs 0–5, `wrk` on 6–11), loopback.
        **Still to do: separate machines**
  - [x] `wrk` keep-alive, plus pipelined ×16 (TechEmpower plaintext style)
  - [ ] Latency percentiles at a fixed rate (`wrk2`)
  - [ ] TLS: handshakes/s per core, and throughput over TLS
  - [ ] h2/h3: h2load
  - [x] Baseline nginx. Still to do: h2o, a minimal raw-epoll C server, Zap

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
