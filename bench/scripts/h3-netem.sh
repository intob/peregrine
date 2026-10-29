#!/bin/bash
# HTTP/3 behind a bottleneck, with and without pacing: two containers on a
# Docker network, the server's egress through tbf (RATE, a queue of QUEUE
# bytes) and the client's delayed DELAY (so the round trip is about DELAY).
# Each round: ten 1 MiB curl downloads, each on a new connection (slow
# start every time), then h2load with 4 connections × 40 × 1 MiB. Prints
# times, throughput and tbf's counters (its drop count is per skb, so a
# GSO batch counts once: compare times, not drops). Interleaves variants.
# Image: peregrine-h3load-netem (bench/h3/Dockerfile.netem, built if missing).
# Usage: h3-netem.sh [rounds 2] [rate 100mbit] [queue 40kb] [delay 20ms] [epoll|io_uring]
# 2026-10-29: queue 40kb (0.16 BDP): ten downloads 2.3 s paced, 6.4-6.8 s
# unpaced; h2load 8.7-9.0 MB/s vs 3.6-4.7. Queue 256kb: about even.
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
ROUNDS=${1:-2}; RATE=${2:-100mbit}; QUEUE=${3:-40kb}; DELAY=${4:-20ms}; B=${5:-epoll}
IMG=peregrine-h3load-netem
docker image inspect peregrine-h3load >/dev/null 2>&1 ||
    { echo "no peregrine-h3load image: docker build -t peregrine-h3load $ROOT/bench/h3"; exit 1; }
# Timing runs: the machine to ourselves (building included).
"$LOCK" acquire mac-bench "h3-netem ($ROOT)"
NET=h3n-$TAG; SRV=h3n-srv-$TAG; CLI=h3n-cli-$TAG
cleanup() {
    docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    "$LOCK" release mac-bench
}
trap cleanup EXIT
wait_for_jobs
docker image inspect $IMG >/dev/null 2>&1 ||
    docker build -q -t $IMG -f "$ROOT/bench/h3/Dockerfile.netem" "$ROOT/bench/h3" >/dev/null || exit 1
build_linux_bins || exit 1
docker network create "$NET" >/dev/null || exit 1
docker run -d --name "$CLI" --network "$NET" --cap-add NET_ADMIN --cpuset-cpus 6-11 $IMG sleep 3600 >/dev/null || exit 1
docker exec "$CLI" tc qdisc add dev eth0 root netem delay "$DELAY" limit 100000 || exit 1
stats() { docker exec "$SRV" tc -s qdisc show dev eth0 | awk '/Sent/{gsub(",","",$7); print $4, $7}'; }
uptime
for r in $(seq "$ROUNDS"); do
    for v in pace nopace; do
        arg=""; [ $v = nopace ] && arg=nopace
        docker run -d --name "$SRV" --network "$NET" --cap-add NET_ADMIN --cpuset-cpus 0-5 \
            --security-opt seccomp="$SECCOMP" -v "$BIN":/b $IMG /b/bench-server 4 "$B" 8443 h3 $arg >/dev/null || exit 1
        docker exec "$SRV" tc qdisc add dev eth0 root tbf rate "$RATE" burst 16kb limit "$QUEUE" || exit 1
        sleep 1
        read -r p0 d0 < <(stats)
        t=$(docker exec "$CLI" sh -c "for i in \$(seq 10); do curl -sk --http3-only -o /dev/null -w '%{time_total} %{size_download}\n' https://$SRV:8443/1m; done" |
            awk '$2 == 1048576 {t += $1; n++} END {printf "%d ok in %.2f s", n, t}')
        read -r p1 d1 < <(stats)
        h=$(docker exec "$CLI" h2load --alpn-list=h3 -t2 -c4 -m1 -n40 "https://$SRV:8443/1m" 2>&1 |
            awk '/^finished in/{f=$3; bw=$6} /^status codes:/{c=$3} END{printf "%s 2xx in %s %s", c, f, bw}')
        read -r p2 d2 < <(stats)
        printf "%-7s 10 x 1 MiB, new connections: %s, %4d drops / %5d pkts | 4 conns, 40 x 1 MiB: %s, %4d drops / %5d pkts\n" \
            $v "$t" $((d1 - d0)) $((p1 - p0)) "$h" $((d2 - d1)) $((p2 - p1))
        docker rm -f "$SRV" >/dev/null
    done
done
uptime
