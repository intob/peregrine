#!/bin/bash
# The test suite on Linux in Docker: epoll (Docker's default seccomp blocks
# io_uring, so .auto falls back) and io_uring (seccomp allowing it).
# Usage: linux-test.sh [extra zig test args, e.g. --test-filter "ws."]
set -e
source "$(dirname "$0")/env.sh"
"$LOCK" wait mac-bench
(cd "$ROOT" && "$ZIG" test src/root.zig -target aarch64-linux --test-no-exec -femit-bin="$OUT/linux-tests" "$@")
echo "== epoll";    docker run --rm --name lt-epoll-$TAG -v "$OUT":/t alpine:3.21 /t/linux-tests 2>&1 | tail -2
echo "== io_uring"; docker run --rm --name lt-uring-$TAG --security-opt seccomp="$SECCOMP" -v "$OUT":/t alpine:3.21 /t/linux-tests 2>&1 | tail -2
