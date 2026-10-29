#!/bin/bash
# Runs one fuzz target on Linux from the working tree: in Docker on the Mac
# (HOST=local) or on a Pi (HOST=pi1-wg / pi5-wg, see pi.sh). A short
# single-instance warm-up comes first: several instances racing to create
# the coverage file panic in 0.17. Prints the result; a failure leaves the
# input in .zig-cache/f/crash (replay it by adding the bytes to the
# target's corpus). The macOS fuzz runner hangs, hence Linux.
# Usage: fuzz.sh "fuzz: ws inflate" MINUTES JOBS [HOST]
source "$(dirname "$0")/env.sh"
T=$1; MIN=${2:-15}; JOBS=${3:-2}; HOST=${4:-local}
name=$(echo "$T" | tr -c 'a-zA-Z0-9\n' '-')
run="../zig/zig build test --fuzz=200 -Doptimize=ReleaseSafe -Dtest-filter='$T' > warmup.log 2>&1;
 rm -f .zig-cache/f/crash; timeout -s INT $((MIN * 60)) ../zig/zig build test --fuzz -j$JOBS -Doptimize=ReleaseSafe -Dtest-filter='$T' > fuzz.log 2>&1;
 echo exit=\$? >> fuzz.log; tr '\r' '\n' < fuzz.log | grep -E 'failed with|panic|error:' | head -5; tail -1 fuzz.log;
 if [ -f .zig-cache/f/crash ]; then echo CRASH; xxd -p .zig-cache/f/crash | tr -d '\n'; echo; else echo clean; fi"
if [ "$HOST" = local ]; then
    "$LOCK" share mac-bench "fuzz $T ($ROOT)"
    trap '"$LOCK" unshare mac-bench' EXIT
    D=$OUT/fuzz-$name; ZL=$(zig_linux) || exit 1
    mkdir -p "$D/w"; rm -rf "$D/w/src"; (cd "$ROOT" && tar -c src build.zig build.zig.zon) | tar -x -C "$D/w"
    docker run --rm --name "fuzz-$name-$TAG" -v "$D/w":/w/src -v "$ZL":/w/zig -v "$D/cache":/root/.cache/zig -w /w/src alpine:3.21 sh -c "$run"
else
    pi=${HOST%-wg}
    "$LOCK" acquire "$pi" "fuzz $T ($ROOT)"
    trap '"$LOCK" release "$pi"' EXIT
    (cd "$ROOT" && tar -c src build.zig build.zig.zon) | ssh "$HOST" "mkdir -p ~/peregrine-work/fuzz-$name/src && cd ~/peregrine-work/fuzz-$name/src && rm -rf src && tar -x && ln -sfn ~/peregrine-work/zig ../zig"
    # The script goes over stdin, so the remote shell expands nothing in it.
    echo "$run" | ssh "$HOST" "cd ~/peregrine-work/fuzz-$name/src && nice -n 10 sh -s"
fi
