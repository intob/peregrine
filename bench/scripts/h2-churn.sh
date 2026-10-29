#!/bin/bash
# HTTP/2 churn: bench/verify_server.zig in Docker, h2-churn.py clients
# (several processes) checking every byte, on epoll and io_uring, h2c and
# TLS. Small socket buffers (WMEM) make the server's writes partial.
# Usage: h2-churn.sh [SECONDS] [PROCS] [CONNS per proc] [server args...]
#   BACKENDS="epoll io_uring" MODES="h2c tls" WMEM="4096 4096 4096" BUILD=0
set -e
source "$(dirname "$0")/env.sh"
SECS=${1:-60}; PROCS=${2:-4}; CONNS=${3:-12}; shift 3 2>/dev/null || shift $#
BACKENDS=${BACKENDS:-epoll io_uring}
MODES=${MODES:-h2c tls}
"$LOCK" share mac-bench "h2-churn ($ROOT)"
trap '"$LOCK" unshare mac-bench' EXIT
if [ "${BUILD:-1}" = 1 ] && [ -z "$BINDIR" ]; then
    (cd "$ROOT" && "$ZIG" build verify-server -Dtarget=aarch64-linux-musl -Dcpu=apple_m2 -p "$OUT/linux") >&2
fi
status=0
for backend in $BACKENDS; do
    for mode in $MODES; do
        name=fuzz-churn-$TAG
        sysctl=()
        [ -n "$WMEM" ] && sysctl=(--sysctl "net.ipv4.tcp_wmem=$WMEM")
        [ -n "$RMEM" ] && sysctl+=(--sysctl "net.ipv4.tcp_rmem=$RMEM")
        docker run --rm -d --name "$name" --security-opt seccomp="$SECCOMP" "${sysctl[@]}" \
            -v "${BINDIR:-$OUT/linux/bin}":/b alpine:3.21 /b/verify-server 2 "$backend" 8443 \
            "$([ "$mode" = tls ] && echo tls || echo plain)" "$@" >/dev/null
        sleep 1
        echo "== $backend $mode $*"
        pids=()
        for p in $(seq 1 "$PROCS"); do
            docker run --rm --network container:"$name" -v "$ROOT/bench/scripts":/s peregrine-ws-interop \
                python3 /s/h2-churn.py 127.0.0.1 8443 "$mode" "$SECS" "$CONNS" > "$OUT/churn-$TAG-$p.log" 2>&1 &
            pids+=($!)
        done
        for pid in "${pids[@]}"; do wait "$pid" || status=1; done
        # Wrong bytes, torn frames and protocol errors first: they are the
        # point. Timeouts and resets of slow readers are counted.
        cat "$OUT"/churn-$TAG-[0-9]*.log > "$OUT/churn-$TAG-$backend-$mode.log"
        grep -E "wrong byte|length [0-9]+ !=|Protocol|FrameTooLarge|FlowControl|Invalid|Traceback" "$OUT/churn-$TAG-$backend-$mode.log" | grep -v "^  " | head -20
        grep -E "^FAIL" "$OUT/churn-$TAG-$backend-$mode.log" | sed -E 's/[0-9]+/N/g' | cut -c1-90 | sort | uniq -c | sort -rn | head -12
        grep -h "requests=" "$OUT"/churn-$TAG-[0-9]*.log
        if [ -z "$(docker ps -q -f name="^$name\$")" ]; then
            echo "SERVER DIED"; status=1; continue
        fi
        docker logs "$name" 2>&1 | grep -v "^listening" | head -20
        docker stop -t 1 "$name" >/dev/null
    done
done
exit $status
