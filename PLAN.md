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
| M2. Throughput architecture | 🟡 io_uring works (opt-in, not yet faster than epoll); sendfile, NUMA open |
| M3. WebSockets over HTTP/1.1 | ✅ reworked; permessage-deflate, Autobahn, benchmarks open |
| M4. TLS 1.3 | ✅ HTTP and WebSockets on every backend (epoll, kqueue, io_uring), interop-tested, fuzzed; faster handshakes, resumption and kTLS are listed under "Later in M4" |
| M5. HTTP/2 | ✅ h2 over TLS (ALPN) and h2c on every backend, h2spec 146/146 over TLS, fuzzed, benchmarked; streamed request bodies on every protocol; WebSockets over h2 (RFC 8441) |
| M6. HTTP/3 and QUIC | 🟡 HTTP/3 over QUIC v1 on every backend, interop-tested (aioquic, curl/ngtcp2, h2load), benchmarked against nginx and Caddy; WebSockets over h3 (RFC 9220); migration, 0-RTT, pacing, ECN, PMTUD open |
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
| `src/mailbox.zig` | How other threads tell a worker that a WebSocket or an exchange has output |
| `src/h2/hpack.zig` | HPACK (RFC 7541): tables, Huffman coding, strict limits |
| `src/h2/frame.zig` | HTTP/2 framing (RFC 9113): I/O-free parser and serialiser |
| `src/h2/conn.zig` | One HTTP/2 connection: streams, flow control, request assembly, responses through the handler API, defences |
| `src/ws/protocol.zig` | I/O-free WebSocket frame decoder and message assembler |
| `src/ws/conn.zig` | Per-connection WebSocket state: send queue, close handshake, cross-thread mailbox |
| `src/ws/upgrader.zig` | Accepting a WebSocket: 101 for an HTTP/1.1 Upgrade, 200 for an extended CONNECT on HTTP/2 and HTTP/3 |
| `src/tls/` | I/O-free TLS 1.3 server (M4): see below |
| `src/server_test.zig` | End-to-end tests over real sockets, run once per available backend |
| `bench/` | `zig build bench` (parser micro-benchmarks), `zig build bench-tls` (record protection), `zig build bench-server` (load-test target, plaintext or TLS) |
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
- [ ] **Make io_uring faster than epoll.** Equal within noise for small requests,
      so `.auto` picks epoll. To try: multishot recv, registered (direct) fds, `send`
      instead of `writev` for one buffer, `send_zc` for large bodies, bigger
      completion batches, back off re-arming accept on `EMFILE`.
      Uploads are slower: a 12 KiB POST (plaintext, c=64) cost 12.4 µs of server
      CPU on io_uring against 6.7-7.1 on epoll. Found with perf and counters (Docker
      on the M2 Pro, host under load, interleaved runs):
  - [x] About two thirds of these requests arrive in two receives. The rest went
        through a second kernel buffer and was copied after the first part;
        a connection holding partial input now receives straight into that
        buffer, as on epoll: 11.0-12.1 → 10.0-10.3 µs
  - [ ] The kernel copies into the coldest buffer: the ring is FIFO over 256 ×
        16 KiB per worker, where epoll reuses hot pooled buffers. 16 buffers gave
        8.8-8.9 µs in one set of runs and were within noise of 256 in the next, so
        the default stays until it's measured on a quiet machine (a small ring
        trades this for ENOBUFS round trips under bursts)
  - [ ] The first part of a split request (4.3 KB on average) is still copied out
        of the kernel buffer. Holding the kernel buffer and receiving the rest into
        its tail would avoid that when the request fits
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
- [ ] Faster handshakes: measure on Linux; candidates are P-256 signing, ML-KEM
      encapsulation, and the per-handshake allocations (handshake state, flight buffer)
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
      per stream, trailers as a trailing HEADERS. Priorities (RFC 7540 and RFC
      9218) are accepted and ignored. Output backpressure: parsing stops above
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
- [ ] Priorities: RFC 9218 `priority` header is not parsed (ignored like the rest)
- [x] **WebSockets over h2 (RFC 8441) and h3 (RFC 9220)**, branch
      `ws-h2-h3`. With a handler that has `handleWSFrame`, both send
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
- [ ] 0-RTT (needs TLS session tickets, M4)
- [x] WebSockets over h3 (RFC 9220): see M5
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
  - [ ] TLS: handshakes/s per core. Throughput over TLS: first numbers in M4
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
