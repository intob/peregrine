#!/bin/bash
# ECN (RFC 9000 §13.4) with real clients: bench-server in peregrine-h3-ecn
# (bench/h3/Dockerfile.ecn, built if missing), tcpdump on lo while a client
# runs, then the ECN codepoints of each direction's packets counted (per
# skb: a GSO send is one). ngtcp2's osslclient marks ECT(0) and validates
# our ACK_ECN counts, so it keeps marking only if ours are right; we keep
# marking only if its counts validate. A second pass marks CE with netem
# (`loss 2% ecn` on lo: CE for marked packets, drops for the rest). curl,
# h2load and aioquic don't mark what they send; the lines for them show
# what our validation made of their reports (curl reports the codepoints,
# the others don't). A last pass runs N osslclient connections (each
# under its own capture) through netem's NETEM (default: 20 ms and 30% of
# packets reordered): each must finish with both sides still marking at the
# end. Prints PASS or FAIL per check; exits 1 if any failed.
# Usage: [N=20] [NETEM="delay 20ms reorder 30%"] h3-ecn.sh [epoll|io_uring] [bench-server args]
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
B=${1:-epoll}; shift
RUNS=${N:-20}; NETEM=${NETEM:-delay 20ms reorder 30%}
IMG=peregrine-h3-ecn
N=h3i-ecn-$B-$TAG
"$LOCK" share mac-bench "h3-ecn $B ($ROOT)"
trap 'docker rm -f "$N" >/dev/null 2>&1; "$LOCK" unshare mac-bench' EXIT
docker image inspect peregrine-h3load-netem >/dev/null 2>&1 ||
    docker build -q -t peregrine-h3load-netem -f "$ROOT/bench/h3/Dockerfile.netem" "$ROOT/bench/h3" >/dev/null || exit 1
docker image inspect $IMG >/dev/null 2>&1 ||
    docker build -q -t $IMG -f "$ROOT/bench/h3/Dockerfile.ecn" "$ROOT/bench/h3" >/dev/null || exit 1
build_linux_bins || exit 1
docker run --rm -d --name "$N" --cap-add NET_ADMIN --security-opt seccomp="$SECCOMP" -v "$BIN":/b -v "$ROOT/bench/h3":/h3 \
    $IMG /b/bench-server 2 "$B" 8443 h3 "$@" >/dev/null || exit 1
sleep 1
docker logs "$N" 2>&1 | head -1
U=https://127.0.0.1:8443
fail=0
check() { # name, condition result
    if [ "$2" = 1 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi
}
# Runs a client under tcpdump; sets the counts of each codepoint per
# direction (s0 s1 s2 s3: from the server; c0..c3: from the client) and
# `out`, the client's last line of output.
capture() { # name, command
    docker exec -d "$N" sh -c "tcpdump -i lo -n -v -l udp port 8443 > /tmp/cap.txt 2>/dev/null"
    sleep 1
    out=$(docker exec "$N" sh -c "$2" 2>&1 | tail -1)
    sleep 0.5; docker exec "$N" pkill tcpdump; sleep 0.5
    # tcpdump -v: "IP (tos 0x2,ECT(0), ttl ...)", then "    A.port > B.port: UDP ...".
    read -r s0 s1 s2 s3 c0 c1 c2 c3 < <(docker exec "$N" cat /tmp/cap.txt | awk '
        /^[0-9:.]+ IP \(tos/ { match($0, /tos 0x[0-9a-f]+/); t = (index("0123456789abcdef", substr($0, RSTART + RLENGTH - 1, 1)) - 1) % 4; next }
        / > / && t != "" { n[(($1 ~ /\.8443$/) ? 0 : 4) + t]++; t = "" }
        END { for (i = 0; i < 8; i++) printf "%d ", n[i]; print "" }')
    # Of the server's last ten packets, how many were marked (ten if it
    # sent fewer than 15).
    last=$(docker exec "$N" cat /tmp/cap.txt | awk '
        /^[0-9:.]+ IP \(tos/ { match($0, /tos 0x[0-9a-f]+/); t = (index("0123456789abcdef", substr($0, RSTART + RLENGTH - 1, 1)) - 1) % 4; next }
        / > / && t != "" { if ($1 ~ /\.8443$/) l[k++ % 10] = t; t = "" }
        END { m = 0; for (i = 0; i < 10; i++) if (l[i] >= 2) m++; print (k < 15 ? 10 : m) }')
    [ -n "$1" ] && printf "     %-28s server not-ECT/ECT(0)/CE %s/%s/%s, client %s/%s/%s (%s)\n" "$1" "$s0" "$s2" "$s3" "$c0" "$c2" "$c3" "$out"
}
ossl="/opt/n/bin/osslclient -q --exit-on-all-streams-close 127.0.0.1 8443 $U/1m $U/1m $U/1m $U/1m >/dev/null; echo exit=\$?"
for pass in clean ce; do
    if [ $pass = ce ]; then
        docker exec "$N" tc qdisc add dev lo root netem loss 2% ecn || exit 1
        echo "== netem loss 2% ecn on lo"
    else
        echo "== clean loopback"
    fi
    capture "ngtcp2 osslclient 4 x 1 MiB" "$ossl"
    check "$pass: ngtcp2 finished" "$([ "$out" = exit=0 ] && echo 1)"
    check "$pass: ngtcp2 kept marking (our ACK_ECN counts validated)" "$([ "$c0" -le 2 ] && [ $((c2 + c3)) -gt 20 ] && echo 1)"
    check "$pass: we kept marking (ngtcp2's counts validated)" "$([ "$s2" -gt 20 ] && echo 1)"
    [ $pass = ce ] && check "$pass: CE marks on the path" "$([ $((s3 + c3)) -gt 0 ] && echo 1)"
    capture "curl 1 MiB" "curl -sk --http3-only -o /dev/null -w '%{http_code} %{size_download}' $U/1m"
    capture "h2load 300 x 64 KiB" "h2load --alpn-list=h3 -t1 -c1 -m10 -n300 $U/64k | grep '^status codes:'"
    capture "aioquic 5 x 1 MiB" "python3 /h3/aioquic_client.py 127.0.0.1 8443 /1m -n 5 | grep -c ' 200 1048576'"
done
docker exec "$N" tc qdisc replace dev lo root netem $NETEM || exit 1
echo "== $RUNS osslclient connections, netem $NETEM on lo"
bad=0
for r in $(seq "$RUNS"); do
    capture "" "timeout 60 $ossl"
    verdict=
    [ "$out" != exit=0 ] && verdict="$verdict client-failed($out)"
    [ "$last" -lt 7 ] && verdict="$verdict we-stopped-marking"
    [ "$c0" -gt 2 ] && verdict="$verdict ngtcp2-stopped-marking"
    if [ -n "$verdict" ]; then
        bad=$((bad + 1))
        printf "     %3d: server not-ECT/ECT(0)/CE %s/%s/%s, client %s/%s/%s, last ten marked %s:%s\n" "$r" "$s0" "$s2" "$s3" "$c0" "$c2" "$c3" "$last" "$verdict"
    fi
done
check "reordering: all $RUNS connections finished with ECN on both ways ($bad did not)" "$([ $bad = 0 ] && echo 1)"
[ $fail = 0 ] && echo "H3 ECN ALL PASS ($B $*)" || echo "H3 ECN SOME FAILED ($B $*)"
exit $fail
