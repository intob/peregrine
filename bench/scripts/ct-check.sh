#!/bin/bash
# Constant-time checks of the code on secrets in src/tls (P-256, X25519).
#   ct-check.sh [branches]   builds bench/ct/dudect.zig for each target
#                            (TARGETS, in ReleaseFast and ReleaseSafe) and
#                            fails on a forward conditional branch in p256,
#                            field_p256, x25519 or field25519 that
#                            bench/ct/allowed.txt doesn't allow (a select
#                            turned into a branch); shares mac-bench
#   ct-check.sh dudect [N]   then runs dudect (N samples per case, default
#                            200000) in Docker on one core for
#                            DUDECT_TARGETS (aarch64 natively, x86_64 under
#                            Rosetta), holding mac-bench exclusively; fails
#                            on max |t| > 4.5
# x86_64 below v3 is where LLVM turned masked selections into branches
# (2026-10-30): keep baseline and v2 in TARGETS.
source "$(dirname "$0")/env.sh"
MODE=${1:-branches}
N=${2:-200000}
TARGETS=${TARGETS:-"x86_64:baseline x86_64:x86_64_v2 x86_64:x86_64_v3 aarch64:baseline aarch64:apple_m2 aarch64:cortex_a76"}
DUDECT_TARGETS=${DUDECT_TARGETS:-"aarch64:apple_m2 x86_64:baseline"}
OPTS=${OPTS:-"ReleaseFast ReleaseSafe"}
D=$OUT/ct
mkdir -p "$D"
"$LOCK" share mac-bench "ct-check builds ($ROOT)"
trap '"$LOCK" unshare mac-bench' EXIT
status=0
for opt in $OPTS; do
    for t in $TARGETS; do
        arch=${t%%:*}; cpu=${t#*:}
        bin=$D/dudect-$arch-$cpu-$opt
        (cd "$ROOT" && "$ZIG" build-exe -O "$opt" -target "$arch-linux-musl" -mcpu="$cpu" \
            --dep peregrine -Mroot=bench/ct/dudect.zig -O "$opt" -Mperegrine=src/root.zig \
            -femit-bin="$bin" --cache-dir "$D/cache") || { status=1; continue; }
        objdump -d --no-show-raw-insn "$bin" > "$bin.s"
        echo "== branches: $arch $cpu $opt"
        python3 -I "$ROOT/bench/ct/branches.py" "$bin.s" "$arch" "$ROOT/bench/ct/allowed.txt" "$opt" || status=1
    done
done
"$LOCK" unshare mac-bench
trap - EXIT
if [ "$MODE" = dudect ]; then
    bench_lock "ct-check dudect ($ROOT)"
    echo "load: $(uptime)"
    # A static binary runs in any image of its architecture; the amd64 one
    # gets its own tag so alpine:3.21 stays arm64 (see the Linux test notes).
    docker image inspect peregrine-amd64 >/dev/null 2>&1 ||
        { docker pull -q --platform linux/amd64 alpine:3.21 >/dev/null && docker tag alpine:3.21 peregrine-amd64 &&
          docker pull -q --platform linux/arm64 alpine:3.21 >/dev/null; }
    for t in $DUDECT_TARGETS; do
        arch=${t%%:*}; cpu=${t#*:}
        case $arch in aarch64) img=alpine:3.21; plat=linux/arm64 ;; *) img=peregrine-amd64; plat=linux/amd64 ;; esac
        [ -x "$D/dudect-$arch-$cpu-ReleaseFast" ] || { echo "no build for $t"; status=1; continue; }
        echo "== dudect: $arch $cpu ReleaseFast, N=$N"
        docker run --rm --name "ct-dudect-$TAG" --platform $plat --cpuset-cpus=3 -v "$D":/t $img \
            /t/dudect-$arch-$cpu-ReleaseFast "$N" || status=1
    done
fi
[ $status = 0 ] && echo "ct-check: PASS" || echo "ct-check: FAIL"
exit $status
