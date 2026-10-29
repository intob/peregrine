---
name: peregrine-loop
description: Drive Peregrine's roadmap (PLAN.md) to completion with parallel agents. This session integrates; implementers work in git worktrees; every change gets two reviewers (correctness against the RFCs, and an adversarial verifier) before it lands on main. Machine resources (the Mac's cores for benchmarks, Docker, two Raspberry Pis) are shared through locks. Use when asked to "continue the roadmap", "finish Peregrine", or run the Peregrine loop; pair with /loop for repeated rounds.
---

# The Peregrine loop

You are the **integrator**. You don't implement roadmap items yourself: you
pick them, brief agents, gate their work, land it on main and keep PLAN.md
true. Peregrine's goal and rules are at the top of `PLAN.md`; read the
Status table and the open items (`- [ ]`) before each round.

## One round

1. **Pick work.** Up to **3 implementation items** in flight at once, chosen
   so they touch different files (see "Lanes" below). Skip items marked as
   needing the user (a decision, credentials, a machine they haven't
   offered). Prefer items that close a milestone or back a "fastest" claim
   with a benchmark.
2. **Brief an implementer** for each: `Agent` with `isolation: "worktree"`,
   `subagent_type: "general-purpose"`, using the brief below. Run them in
   the background and keep working on the rest of the round.
3. **When an implementer reports**, start both reviewers on its branch in
   parallel (see "Reviewers"). Don't review it yourself first.
4. **Gate.** Every finding is fixed (send it back to the implementer with
   `SendMessage`) or argued false with evidence. Then the gates below pass
   on the rebased branch.
5. **Land.** Rebase onto `origin/main`, fast-forward main, push (the user
   wants finished work on main without asking: see memory). Update PLAN.md
   yourself from the implementer's notes: what was done, how it is proven,
   the numbers, what is still open. Commit messages end with the
   attribution line from the system prompt. Delete the worktree branch.
6. **Record** anything a future session would need and can't get from the
   repo in memory (tooling quirks, machine facts), not in PLAN.md.
7. Report one line per item to the user: landed / sent back / blocked and why.

If an item turns out bigger than one agent can finish, land what is done
and proven, then split the rest into new PLAN items.

## Lanes (parallel work that doesn't collide)

Roughly independent areas; at most one implementer per lane:

- **QUIC / HTTP/3** (`src/quic/`, `src/h3/`): pacing, ECN, DPLPMTUD,
  connection migration, DATAGRAM, QPACK dynamic table, GRO, quic-interop-runner.
- **TLS** (`src/tls/`): faster handshakes (X25519, P-256 ECDHE, ML-KEM,
  per-handshake allocations), OCSP stapling, BoGo/tlsfuzzer.
- **HTTP/1.1, h2 and the event loops** (`src/http/`, `src/h2/`): io_uring
  receive copy, NUMA, h2 benchmark against h2o, the unexplained h2spec run.
- **WebSockets** (`src/ws/`): send-queue copy and buffer retention, io_uring
  parsing from provided buffers, idle pings, broadcast and TLS benchmarks.
- **Verification and benchmarks** (`bench/`, M7): wrk2 latency percentiles,
  handshakes/s, soak, adversarial load, HTTP Garden, REDbot. These agents
  mostly run things; they hold locks for a long time, so give them one
  lane.

Two lanes may touch `src/server.zig` (config); tell implementers to keep
such edits small and you resolve conflicts while rebasing.

## Implementer brief (fill in, send as the prompt)

```
You are implementing one Peregrine roadmap item in your own git worktree.
Item: <quote the PLAN.md item and its context>
Read first: PLAN.md (goal, architecture rules, the milestone's section),
the files involved, and bench/scripts/ (shared harnesses and locks).
Rules: pure Zig 0.17 (/Applications/zig-aarch64-macos-0.17.0/zig); I/O-free
protocol layers; no per-request heap allocation in steady state; match the
surrounding code and comment style; zig fmt.
Done means:
- the change, with tests that fail without it (unit, end to end on every
  backend where it applies, a fuzz target for anything that parses input);
- macOS `zig test src/root.zig` and `bench/scripts/linux-test.sh` (epoll and
  io_uring) pass;
- the protocol suite for the area passes (Autobahn, h2spec, h3spec,
  interop clients: see memory and bench/scripts);
- if the item is about speed: numbers before and after, measured with the
  benchmark scripts under their locks, interleaved rounds;
- commit on your branch (don't push, don't edit PLAN.md).
Report: what changed and why, how it is proven (commands and results),
numbers, what is still open or was found along the way, and a draft of
the PLAN.md text for the item.
```

## Reviewers (both, in parallel, on every implementer's branch)

1. **Correctness review**: run the `code-review` skill at level `high` on
   the branch against `main`. It looks for bugs; tell it the RFCs that
   apply and Peregrine's architecture rules.
2. **Adversarial verifier**: `Agent` (`general-purpose`, its own worktree
   on the branch). Its job is to break the change, not to read it: write
   inputs and tests that should fail (malformed and split input, limits,
   other backends, TLS, every protocol the change touches), run the fuzz
   targets involved on a Pi or locally (`bench/scripts/fuzz.sh`, 15 minutes
   at least), and re-run any benchmark the implementer claims. It reports
   failing cases with reproductions, or "could not break it" with what it
   tried. New tests that pass are worth keeping: they go to the
   implementer.

This session caught real bugs only through the second kind: a compressor's
fixed Huffman codes built from 286 lengths instead of 288 passed its own
round-trip tests and failed Autobahn and a fuzzer.

## Gates before landing

- macOS tests, `bench/scripts/linux-test.sh` (epoll and io_uring), `zig fmt --check src bench build.zig`, `zig build`.
- The area's protocol suite: `bench/scripts/autobahn.sh` for WebSockets
  (plain and TLS, epoll and io_uring; with `deflate` for compression), and
  h2spec / h3spec / the interop clients for h2 and h3 (recipes in memory).
- New fuzz targets ran at least 15 minutes clean; a crash input is added
  to the corpus once fixed.
- Speed claims have before/after numbers from interleaved runs, with the
  host load noted.
- Both reviewers' findings resolved.

## Machines and locks

All shared through `bench/scripts/lock.sh` (locks in /tmp/peregrine-locks,
visible to every worktree). Never run two benchmarks at once, and never a
benchmark next to fuzzing or test containers: the numbers would be noise.

- **Mac (M2 Pro, 12 cores, Docker)**: tests, protocol suites, competitor
  images (`comp-uws*`, `comp-facil`, `comp-may`, `comp-h2o`, nginx in
  `peregrine-test`; uWS Dockerfiles in bench/competitors/uws). Benchmarks
  take `mac-bench` exclusively (`acquire`; ws-bench.sh does, after waiting
  for other peregrine containers); test, Autobahn, interop and local fuzz
  jobs hold it shared (`share`/`unshare`, builds included). The queue is
  fair: a benchmark that releases and re-acquires goes behind waiting
  jobs, so new scripts must use `share`, not `wait`. Native macOS test
  runs and builds count too: run them under `share` (e.g. `bash -c
  '"$LOCK" share mac-bench "zig test"; trap ... EXIT; zig test ...'`),
  or a benchmark next to them measures a loaded host.
  Other heavy work on this Mac (check `uptime`) skews numbers too.
- **Raspberry Pis 1 and 5** (`pi1-wg`, `pi5-wg`; Pi 5 Model B, 4 A76 cores,
  8 GB, gigabit LAN between them, 0.35 ms): the user's machines, lent when
  idle; pi1 runs PostgreSQL. Two uses:
  - fuzzing: `bench/scripts/fuzz.sh "<target>" 15 2 pi1-wg` (takes the
    Pi's lock, runs under `nice`);
  - separate-machine benchmarks (an open M7 item): `bench/scripts/pi.sh`:
    `lock`, `build`, `serve "4 epoll 8080 plain"` on pi5 (Linux 6.18 with
    kTLS), load from pi1 (`wrk`, `h2load`, `ws-load` against
    10.252.1.125:8080), `cpu` before and after for server CPU, `stop`,
    `unlock`. Gigabit limits throughput tests; CPU per request is the measure.
  Clean up after yourself: no servers left running, no files outside
  ~/peregrine-work.
- **Hetzner box** (`ssh bitch-box`, x86_64, live services, no sudo): x86 and
  Ubuntu-kernel tests only, under `nice`; never benchmarks (see memory).

## Things to keep

- `bench/scripts/` holds the harnesses; extend them rather than writing
  one-off scripts in scratch directories that the next session won't have.
- Commit and push straight to main once gated; the user may push too
  (rebase onto `origin/main`, never force).
- Measure before claiming; say when a number is noisy and why.
