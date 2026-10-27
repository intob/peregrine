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
| M5. HTTP/2 | 🟡 HPACK, framing and the handler API (steps 1-2) done; connection layer next |
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
| `src/http/exchange.zig` | `Exchange`: a request answered or streamed after `handleRequest` returns (per-worker slab, value handles, HTTP/1.1 framing) |
| `src/mailbox.zig` | How other threads tell a worker that a WebSocket or an exchange has output |
| `src/h2/hpack.zig` | HPACK (RFC 7541): tables, Huffman coding, strict limits |
| `src/h2/frame.zig` | HTTP/2 framing (RFC 9113): I/O-free parser and serialiser |
| `src/ws/protocol.zig` | I/O-free WebSocket frame decoder and message assembler |
| `src/ws/conn.zig` | Per-connection WebSocket state: send queue, close handshake, cross-thread mailbox |
| `src/ws/upgrader.zig` | The HTTP upgrade response |
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
- [ ] WebSockets over HTTP/2 (RFC 8441) and HTTP/3 (RFC 9220): M5 and M6

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
- [ ] Handler API step 3 (`handleHead`, streamed request bodies, request trailers):
      after h2
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
