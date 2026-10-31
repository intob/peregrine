#!/bin/bash
# What idle WebSockets cost the server: bench-server's RSS and anonymous
# memory while CONNS connections sit idle after each echoed MSGS messages of
# SIZE bytes (ws-burst.py, in the peregrine-ws-interop image): 1 s after the
# last echo and IDLE-1 s after it (IDLE at least 3); then after they echo again and close.
# Shares mac-bench (memory, not CPU, is measured).
# Usage: ws-idle.sh BINDIR BACKEND CONNS MSGS SIZE [deflate] (BINDIR holds a
# Linux bench-server: build_linux_bins, `$OUT/linux/bin`). IDLE=seconds (8).
source "$(dirname "$0")/env.sh"
bindir=$1; backend=$2; conns=$3; msgs=$4; size=$5; deflate=${6:-}
IDLE=${IDLE:-8}; [ "$IDLE" -lt 3 ] && IDLE=3
name=wsb-idle-$TAG
log=$OUT/ws-idle-$TAG.log
"$LOCK" share mac-bench "ws-idle ($ROOT)" || exit 1
# Interrupted or not, both containers go with the share.
trap 'docker stop -t 1 $name $name-cli >/dev/null 2>&1; "$LOCK" unshare mac-bench' EXIT
trap 'exit 1' INT TERM HUP
docker run --rm -d --name $name --ulimit nofile=65536:65536 --security-opt seccomp="$SECCOMP" \
    -v "$bindir":/b alpine:3.21 /b/bench-server 2 "$backend" 8080 plain $deflate >/dev/null || exit 1
sleep 1
mem() {
    docker exec $name sh -c 'grep VmRSS /proc/1/status; grep -E "^Anonymous" /proc/1/smaps_rollup' |
        awk '/VmRSS/ {r=$2} /Anonymous/ {a=$2} END {printf "RSS %d kB, anon %d kB", r, a}'
}
echo "$bindir $backend, $conns conns x $msgs x $size B ${deflate:-plain}: start $(mem)"
docker run --rm --name $name-cli --ulimit nofile=65536:65536 --network container:$name -v "$ROOT/bench/scripts":/s:ro \
    peregrine-ws-interop timeout $((IDLE + 600)) python3 -I /s/ws-burst.py 127.0.0.1 8080 "$conns" "$msgs" "$size" "$IDLE" $deflate \
    > "$log" 2>&1 &
pid=$!
until grep -q '^echoed' "$log" 2>/dev/null; do
    kill -0 $pid 2>/dev/null || { echo "  client gone:"; tail -5 "$log"; exit 1; }
    sleep 0.2
done
sleep 1; echo "  $(grep '^echoed' "$log"); idle 1 s: $(mem)"
sleep $((IDLE - 2)); echo "  idle $((IDLE - 1)) s: $(mem)"
wait $pid
grep -v WARNING "$log" | grep -v '^echoed' | tail -3 | sed 's/^/  /'
sleep 3; echo "  closed, +3 s: $(mem)"
