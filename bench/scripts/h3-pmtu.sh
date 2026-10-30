#!/bin/bash
# PMTU discovery (DPLPMTUD, RFC 8899) over constrained paths: bench-server
# and the clients in two containers on a Docker network (veth pairs on a
# bridge, MTU 1500). Lowering the client's eth0 MTU makes a black hole: a
# veth drops frames larger than it takes (its MTU plus 4 bytes of VLAN
# slack), silently (no ICMP; we ignore ICMP anyway, IP_PMTUDISC_PROBE).
# But it lets GSO packets through whatever their segments' size
# (is_skb_forwardable), so the server's eth0 takes one segment per skb
# (gso_max_segs 1: segmented in software on the way out, as a NIC would
# before the wire). Lowering the server's MTU makes probes fail locally
# (EMSGSIZE). Each case on a fresh server:
#   1500        the Ethernet path: datagrams grow to 1472
#   client-1400 a 1376-byte path from the start: probes above it lost
#   client-1280 1256 bytes, under our 1350 start: the handshake still
#               completes (probe timeouts go at 1200), then a black hole
#               takes data to 1200 and the search finds 1241-1256
#   server-1400 the server's interface at 1400: probes refused locally
#   server-1300 at 1300, under our 1350 start: ordinary datagrams refused
#               too (EMSGSIZE, or EINVAL for a GSO run); they go again at
#               1200 at once (curl's 1 MiB in well under the second two
#               probe timeouts would take), then the search finds 1257-1272
#   server-1300-off  the same with discovery off (mtu=0): no DF, so the
#               kernel fragments the 1350-byte datagrams, which arrive
#   drop-1300   1500, then the client's MTU drops to 1300 2 s into a 6 s
#               h2load run (a black hole after validation): no request
#               fails, and the rate after the drop is reported
# aioquic (-s) reports the largest datagram it received (tcpdump would see
# GSO sends as one packet); curl and h2load check correctness and time.
# Prints PASS or FAIL per check; exits 1 if any failed.
# Image: peregrine-h3load-netem (iproute2; built if missing).
# Usage: h3-pmtu.sh [epoll|io_uring] [bench-server args, e.g. mtu=0]
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
B=${1:-epoll}; shift
IMG=peregrine-h3load-netem
NET=h3i-pmtu-$TAG; SRV=h3i-pmtu-srv-$TAG; CLI=h3i-pmtu-cli-$TAG
"$LOCK" share mac-bench "h3-pmtu $B ($ROOT)"
cleanup() {
    docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    "$LOCK" unshare mac-bench
}
trap cleanup EXIT
docker image inspect peregrine-h3load >/dev/null 2>&1 ||
    { echo "no peregrine-h3load image: docker build -t peregrine-h3load $ROOT/bench/h3"; exit 1; }
docker image inspect $IMG >/dev/null 2>&1 ||
    docker build -q -t $IMG -f "$ROOT/bench/h3/Dockerfile.netem" "$ROOT/bench/h3" >/dev/null || exit 1
build_linux_bins || exit 1
docker network create "$NET" >/dev/null || exit 1
fail=0
check() { # name, condition result, detail
    if [ "$2" = 1 ]; then echo "PASS $1 ($3)"; else echo "FAIL $1 ($3)"; fail=1; fi
}
start() { # server MTU [more bench-server args]
    docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
    docker run -d --name "$SRV" --network "$NET" --cap-add NET_ADMIN --security-opt seccomp="$SECCOMP" -v "$BIN":/b \
        $IMG sh -c "ip link set eth0 mtu $1 gso_max_segs 1 && exec /b/bench-server 2 $B 8443 h3 $ARGS ${2:-}" >/dev/null || exit 1
    docker run -d --name "$CLI" --network "$NET" --cap-add NET_ADMIN -v "$ROOT/bench/h3":/h3 $IMG sleep 3600 >/dev/null || exit 1
    sleep 1
    IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SRV")
    U=https://$IP:8443
}
cmtu() { docker exec "$CLI" ip link set eth0 mtu "$1"; }
x() { docker exec "$CLI" sh -c "$1" 2>&1; }
ARGS="$*"
# aioquic: two 1 MiB downloads in turn (the second at the size the search
# found); sets `largest`, `count` and `secs`.
aio() {
    local out
    out=$(x "timeout 60 python3 /h3/aioquic_client.py $IP 8443 /1m -n 2 --seq -s")
    largest=$(echo "$out" | sed -n 's/^largest datagram \([0-9]*\) (\([0-9]*\) of them)/\1/p')
    count=$(echo "$out" | sed -n 's/^largest datagram \([0-9]*\) (\([0-9]*\) of them)/\2/p')
    secs=$(echo "$out" | sed -n 's/^ok \(.*\)s/\1/p')
    oks=$(echo "$out" | grep -c '^/1m 200 1048576')
}
curl1m() { x "timeout 60 curl -sk --http3-only -o /dev/null -w '%{size_download} %{time_total}' $U/1m"; }
h2l() { x "timeout 120 h2load --alpn-list=h3 -t2 -n $1 -c2 -m2 $U/1m" | awk '/^status codes:/{s=$3} /^finished in/{t=$3} END{print s+0, t}'; }

uptime | sed 's/.*averages*: /load /'
for c in 1500 client-1400 client-1280 server-1400 server-1300 server-1300-off; do
    case $c in
    1500) start 1500 ;;
    client-*) start 1500; cmtu "${c#client-}" ;;
    server-*-off) m=${c#server-}; start "${m%-off}" mtu=0 ;;
    server-*) start "${c#server-}" ;;
    esac
    # The payload limit: the MTU less 28 bytes (plus the veth's slack of 4
    # at the client); the search stops within 16 bytes of it.
    case $c in
    1500) lo=1472 hi=1472 ;; client-1400) lo=1361 hi=1376 ;; server-1400) lo=1357 hi=1372 ;;
    client-1280) lo=1241 hi=1256 ;; server-1300) lo=1257 hi=1272 ;; server-1300-off) lo=1350 hi=1350 ;;
    esac
    aio
    check "$c aioquic 2 × 1 MiB, largest datagram $lo-$hi" "$([ "$oks" = 2 ] && [ "${largest:-0}" -ge $lo ] && [ "${largest:-0}" -le $hi ] && echo 1)" \
        "largest ${largest:-none}, ${count:-0} of them, ${secs:-?} s"
    r=$(curl1m)
    check "$c curl 1 MiB" "$([ "${r%% *}" = 1048576 ] && echo 1)" "$r s"
    if [ $c = server-1300 ]; then
        # No probe timeouts: a refused datagram goes again at once.
        check "$c curl 1 MiB without waiting for probe timeouts" "$(awk -v t="${r#* }" 'BEGIN { print (t < 0.5) ? 1 : 0 }')" "$r s"
    fi
    r=$(h2l 100)
    check "$c h2load 100 × 1 MiB" "$([ "${r%% *}" = 100 ] && echo 1)" "$r"
done
# A black hole after validation, during a run: two h2load runs back to
# back on fresh connections would each search afresh, so one 6 s run,
# with a 2 s one after it for the rate at 1300.
start 1500
docker exec -d "$CLI" sh -c "timeout 60 h2load --alpn-list=h3 -t2 -D6 -c2 -m2 $U/1m > /tmp/h2l.txt 2>&1"
sleep 2
cmtu 1300
for i in $(seq 60); do x "grep -q '^finished in' /tmp/h2l.txt" >/dev/null && break; sleep 1; done
r=$(x "cat /tmp/h2l.txt" | awk '/^requests:/{d=$8; f=$10+$12+$14} /^finished in/{t=$3 " " $4 "req/s " $6} END{print d+0, f+0, t}')
set -- $r
check "drop-1300 h2load 6 s of 1 MiB, MTU 1500 → 1300 at 2 s: none failed" "$([ "$1" -gt 0 ] && [ "$2" = 0 ] && echo 1)" "$1 done, $2 failed, $3 $4 $5"
r=$(x "timeout 60 h2load --alpn-list=h3 -t2 -D2 -c2 -m2 $U/1m" | awk '/^requests:/{d=$8; f=$10+$12+$14} /^finished in/{t=$4 "req/s " $6} END{print d+0, f+0, t}')
set -- $r
check "drop-1300 h2load 2 s at 1300" "$([ "$1" -gt 0 ] && [ "$2" = 0 ] && echo 1)" "$1 done, $2 failed, $3 $4"
aio
check "drop-1300 aioquic afterwards, largest 1261-1276" "$([ "$oks" = 2 ] && [ "${largest:-0}" -ge 1261 ] && [ "${largest:-0}" -le 1276 ] && echo 1)" \
    "largest ${largest:-none}, ${count:-0} of them, ${secs:-?} s"
[ $fail = 0 ] && echo "H3 PMTU ALL PASS ($B $ARGS)" || echo "H3 PMTU SOME FAILED ($B $ARGS)"
exit $fail
