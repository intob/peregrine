# Sourced by the other scripts: paths and toolchains.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
ZIG=${ZIG:-/Applications/zig-aarch64-macos-0.17.0/zig}
OUT=${OUT:-$ROOT/zig-out/scripts}
SECCOMP=$ROOT/bench/scripts/uring-seccomp.json # Docker's default plus io_uring_setup/enter/register
mkdir -p "$OUT"
# Container names carry this, so parallel agents don't collide.
TAG=${TAG:-$$}
LOCK=$ROOT/bench/scripts/lock.sh
# Containers these scripts start are named with one of these prefixes
# (linux-test, autobahn, fuzz, ws-bench, h2-bench, h3-interop and h3-ecn, h3-netem).
JOB_CONTAINERS='^(lt-|ab-|fuzz-|wsb-|h2b-|h3i-|h3n-)'

# For benchmarks, after taking mac-bench: wait for other jobs' containers
# (started before the lock was taken) to finish; after 15 minutes, name
# them and fail rather than hold the lock on a stale one.
wait_for_jobs() {
    local i=0
    while docker ps --format '{{.Names}}' | grep -qE "$JOB_CONTAINERS"; do
        if [ $((i += 1)) -gt 90 ]; then
            echo "still running after 15 min, giving up: $(docker ps --format '{{.Names}}' | grep -E "$JOB_CONTAINERS" | tr '\n' ' ')" >&2
            return 1
        fi
        sleep 10
    done
}

# The 12 cores for the calling benchmark: takes mac-bench exclusively (in
# the fair queue), releases it on exit after the script's own `on_exit` if
# it defines one, then waits for other jobs' containers.
bench_lock() {
    "$LOCK" acquire mac-bench "$1" || { echo "could not take mac-bench" >&2; exit 1; }
    trap 'declare -F on_exit >/dev/null && on_exit; "$LOCK" release mac-bench' EXIT
    wait_for_jobs || exit 1
}

# CPU time a container has used, in µs (its cgroup: every process in it).
cgroup_usec() { docker exec "$1" awk '/usage_usec/ {print $2}' /sys/fs/cgroup/cpu.stat; }

# Linux binaries for Docker on the M2 (aarch64 with its AES and SHA).
build_linux_bins() {
    (cd "$ROOT" && "$ZIG" build bench-server ws-load -Dtarget=aarch64-linux-musl -Dcpu=apple_m2 -p "$OUT/linux") >&2
}

# Zig for aarch64 Linux (fuzzing runs in Docker or on the Pis).
zig_linux() {
    local dir=$ROOT/zig-out/zig-linux
    if [ ! -x "$dir/zig" ]; then
        local url=https://ziglang.org/download/0.17.0/zig-aarch64-linux-0.17.0.tar.xz
        local sum=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8
        mkdir -p "$dir" && curl -fsSL "$url" -o "$dir.tar.xz" || return 1
        echo "$sum  $dir.tar.xz" | shasum -a 256 -c - >/dev/null || { echo "zig tarball checksum mismatch" >&2; return 1; }
        tar -xJf "$dir.tar.xz" -C "$dir" --strip-components=1 && rm "$dir.tar.xz"
    fi
    echo "$dir"
}
