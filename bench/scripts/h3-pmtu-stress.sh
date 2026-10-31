#!/bin/bash
# PMTU discovery under abuse (beyond h3-pmtu.sh): paths whose MTU changes
# again and again mid-transfer, the server's own interface shrinking under
# full GSO runs (EINVAL/EMSGSIZE locally), netem loss/delay/reordering and
# CE marking on top, key updates while the size changes, uploads, IPv6 and
# IPv4-mapped clients, and a jumbo network (8972-byte datagrams; mtu=65535,
# refused above the interface). Same topology as h3-pmtu.sh (server veth
# with gso_max_segs 1). Each case on a fresh server; every client run has
# a timeout. Prints PASS/FAIL per check (no failed or stalled request, the
# server still running); exits 1 if any failed.
# aioquic (bench/h3/pmtu_stress.py) decrypts nothing over 1500 bytes
# (PACKET_LENGTH_MAX in its _crypto.c) and sends nothing over it, so the
# search settles at about 1500 for it on a jumbo path; jumbo sizes are
# checked with h2load (ngtcp2), receiving 1501-2048 and larger datagrams
# in-process (server_test.zig, "verify PMTU: the server takes datagrams").
# Usage: [BUILD=0] h3-pmtu-stress.sh [epoll|io_uring] [case...]
#   cases: flap flap-h2load flap-ku upload srvdrop netem ce v6 mapped jumbo
#          big-recv compare (default: all but compare)
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
B=${1:-epoll}; shift
CASES=${*:-flap flap-h2load flap-ku upload srvdrop netem ce v6 mapped jumbo big-recv}
IMG=peregrine-h3load-netem
# The client's: the same with tcpdump (h3-ecn.sh's image).
CIMG=peregrine-h3-ecn
NET=h3i-pmtus-$TAG; SRV=h3i-pmtus-srv-$TAG; CLI=h3i-pmtus-cli-$TAG
"$LOCK" share mac-bench "h3-pmtu-stress $B ($ROOT)"
# Interrupted or not, the MTU schedule's subshells, the containers and the
# network go with the lock.
cleanup() {
    local p
    for p in $(jobs -p); do pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; done
    docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    "$LOCK" unshare mac-bench
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP
docker image inspect $IMG >/dev/null 2>&1 ||
    docker build -q -t $IMG -f "$ROOT/bench/h3/Dockerfile.netem" "$ROOT/bench/h3" >/dev/null || exit 1
docker image inspect $CIMG >/dev/null 2>&1 ||
    docker build -q -t $CIMG -f "$ROOT/bench/h3/Dockerfile.ecn" "$ROOT/bench/h3" >/dev/null || exit 1
[ "${BUILD:-1}" = 0 ] || build_linux_bins || exit 1
fail=0
check() { # name, condition result, detail
    if [ "$2" = 1 ]; then echo "PASS $1 ($3)"; else echo "FAIL $1 ($3)"; fail=1; fi
}
netup() { # [mtu] [ipv6]
    docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    local o=()
    [ -n "$1" ] && o+=(-o "com.docker.network.driver.mtu=$1")
    [ -n "$2" ] && o+=(--ipv6 --subnet "fd00:${TAG: -4}::/64")
    docker network create "${o[@]}" "$NET" >/dev/null || exit 1
}
start() { # server MTU, bench-server args...
    local m=$1; shift
    docker rm -f "$SRV" "$CLI" >/dev/null 2>&1
    docker run -d --name "$SRV" --network "$NET" --cap-add NET_ADMIN --security-opt seccomp="$SECCOMP" -v "$BIN":/b \
        $IMG sh -c "ip link set eth0 mtu $m gso_max_segs 1 && exec /b/bench-server 2 $B 8443 h3 $*" >/dev/null || exit 1
    docker run -d --name "$CLI" --network "$NET" --cap-add NET_ADMIN -v "$ROOT/bench/h3":/h3 $CIMG sleep 3600 >/dev/null || exit 1
    sleep 1
    IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SRV")
    IP6=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").GlobalIPv6Address}}" "$SRV")
}
cmtu() { docker exec "$CLI" ip link set eth0 mtu "$1"; }
smtu() { docker exec "$SRV" ip link set eth0 mtu "$1" gso_max_segs 1; }
x() { docker exec "$CLI" sh -c "$1" 2>&1; }
alive() { [ "$(docker inspect -f '{{.State.Running}}' "$SRV" 2>/dev/null)" = true ]; }
# Changes MTUs on a schedule in the background: "who:mtu@secs ..." (c: the
# client's eth0, s: the server's).
schedule() {
    local s
    for s in $1; do
        local who=${s%%:*} rest=${s#*:}
        (sleep "${rest#*@}"; if [ "$who" = c ]; then cmtu "${rest%@*}"; else smtu "${rest%@*}"; fi) &
    done
}
# tcpdump on the client while a command runs: sets `big`, the largest UDP
# payload from the server (its eth0 segments GSO runs, so these are
# datagrams), and `bign`, how many of that size.
dump() { # command
    docker exec -d "$CLI" sh -c "tcpdump -i eth0 -n -l udp and src port 8443 > /tmp/cap.txt 2>/dev/null"
    sleep 1
    x "$1" >/dev/null
    sleep 0.5; docker exec "$CLI" pkill tcpdump; sleep 0.5
    read -r big bign < <(docker exec "$CLI" cat /tmp/cap.txt | awk '{for (i = 1; i < NF; i++) if ($i == "length") print $(i + 1)}' |
        sort -n | uniq -c | tail -1 | awk '{print $2, $1}')
}
# aioquic stress run; sets r (its summary line), prints its log on failure
# and the requests done and largest datagram received per second.
stress() { # name, host, args...
    local name=$1 host=$2; shift 2
    local out
    out=$(x "timeout 90 python3 /h3/pmtu_stress.py $host 8443 $*")
    r=$(echo "$out" | grep '^done ' | tail -1)
    set -- $r
    check "$name" "$([ -n "$r" ] && [ "$4" = 0 ] && [ "$2" -gt 0 ] && alive && echo 1)" "${r:-no summary: $(echo "$out" | tail -3 | tr '\n' ' ')}"
    [ -n "$r" ] && [ "$4" = 0 ] || echo "$out" | grep -v '^t=' | tail -8 | sed 's/^/    /'
    echo "$out" | grep '^t=' | tr '\n' ' ' | sed 's/^/    /'; echo
}
h2l() { # name, duration, url
    local out name=$1
    out=$(x "timeout 90 h2load --alpn-list=h3 -t2 -D$2 -c2 -m2 $3")
    r=$(echo "$out" | awk '/^requests:/{d=$8; f=$10+$12+$14} /^finished in/{t=$4 " req/s " $6} END{print d+0, f+0, t}')
    set -- $r
    check "$name" "$([ "$1" -gt 0 ] && [ "$2" = 0 ] && alive && echo 1)" "$1 done, $2 failed, $3 $4 $5"
}
FLAP="c:1300@2 c:1500@4 c:1280@6 c:9000@8 c:1350@10 c:1500@12 c:1240@14 c:1500@16"
# IPv6 needs 1280 (a link under it loses its IPv6 addresses for good).
FLAP6="c:1300@2 c:1500@4 c:1280@6 c:9000@8 c:1350@10 c:1500@12 c:1280@14 c:1500@16"
JFLAP="c:1500@2 c:9000@4 c:1280@6 c:4000@8 c:9000@10 c:1400@12"

uptime | sed 's/.*averages*: /load /'
for c in $CASES; do
    case $c in
    flap) # downloads while the client's MTU flips every 2 s
        netup; start 1500; schedule "$FLAP"
        stress "flap: aioquic 4 × 1 MiB for 18 s, client MTU 1500/1300/1280/9000/1350/1240" "$IP" -c 4 --dur 18; wait ;;
    flap-h2load)
        netup; start 1500; schedule "$FLAP"
        h2l "flap: h2load 18 s, client MTU flapping" 18 "https://$IP:8443/1m"; wait ;;
    flap-ku) # the same with a key update every second
        netup; start 1500; schedule "$FLAP"
        stress "flap + key update every 1 s" "$IP" -c 4 --dur 18 --ku 1; wait ;;
    upload) # uploads (the server's ACKs and responses ride the flapping path)
        netup; start 1500; schedule "$FLAP"
        stress "flap: aioquic uploads of 1 MB" "$IP" -c 4 --dur 18 --path /up -d 1000000; wait
        netup; start 1500; schedule "$FLAP"
        stress "flap: uploads, aioquic at 1452-byte datagrams" "$IP" -c 2 --dur 18 --path /up -d 1000000 --mds 1452 --timeout 30; wait ;;
    srvdrop) # the server's interface shrinks under full-sized GSO runs
        netup; start 1500; schedule "s:1400@3 s:1500@7 s:1280@10 s:1500@14"
        h2l "srvdrop: h2load 18 s, server MTU 1500→1400→1500→1280→1500" 18 "https://$IP:8443/1m"; wait
        netup; start 1500; schedule "s:1400@3 s:1500@7 s:1280@10 s:1500@14"
        stress "srvdrop: aioquic 18 s" "$IP" -c 4 --dur 18; wait ;;
    netem) # loss, delay, reordering both ways, plus the flapping MTU
        for t in stress h2l; do
            netup; start 1500
            docker exec "$SRV" tc qdisc add dev eth0 root netem delay 10ms 2ms loss 1% reorder 5% limit 100000
            docker exec "$CLI" tc qdisc add dev eth0 root netem delay 10ms loss 1% limit 100000
            schedule "$FLAP"
            if [ $t = stress ]; then
                stress "netem 1%/10ms/reorder + flap: aioquic" "$IP" -c 4 --dur 18 --timeout 30
            else
                h2l "netem + flap: h2load" 18 "https://$IP:8443/1m"
            fi
            wait
        done ;;
    ce) # CE marks (netem ecn) on top of the flapping MTU
        for t in stress h2l; do
            netup; start 1500
            docker exec "$SRV" tc qdisc add dev eth0 root netem delay 5ms loss 3% ecn limit 100000
            schedule "$FLAP"
            if [ $t = stress ]; then stress "CE 3% + flap: aioquic" "$IP" -c 4 --dur 18; else h2l "CE 3% + flap: h2load" 18 "https://$IP:8443/1m"; fi
            wait
        done ;;
    v6) # IPv6: ceiling 1452; flapping as well
        netup "" 6; start 1500 ip=::
        stress "IPv6: aioquic" "$IP6" -c 2 --dur 4
        check "IPv6 largest datagram 1452" "$([ "$(echo "$r" | awk '{print $8}')" = 1452 ] && echo 1)" "$r"
        schedule "$FLAP6"
        stress "IPv6 + flap: aioquic" "$IP6" -c 4 --dur 18; wait
        netup "" 6; start 1500 ip=::; schedule "$FLAP6"
        h2l "IPv6 + flap: h2load" 18 "https://[$IP6]:8443/1m"; wait ;;
    mapped) # IPv4 clients on the dual-stack socket: 1472, IPv4-mapped
        netup "" 6; start 1500 ip=::
        stress "IPv4-mapped: aioquic" "$IP" -c 2 --dur 4
        check "IPv4-mapped largest datagram 1472" "$([ "$(echo "$r" | awk '{print $8}')" = 1472 ] && echo 1)" "$r"
        schedule "$FLAP"
        stress "IPv4-mapped + flap: aioquic" "$IP" -c 4 --dur 18; wait ;;
    jumbo) # a 9000-byte network, mtu=9000: 8972-byte datagrams (7 per GSO run)
        netup 9000; start 9000 mtu=9000
        dump "timeout 30 h2load --alpn-list=h3 -t1 -n 20 -c1 https://$IP:8443/1m"
        check "jumbo: h2load (ngtcp2), largest datagram 8972" "$([ "${big:-0}" = 8972 ] && [ "${bign:-0}" -gt 100 ] && echo 1)" "largest ${big:-none}, ${bign:-0} of them"
        schedule "$JFLAP"
        h2l "jumbo + flap 9000/1500/1280/4000/1400: h2load" 16 "https://$IP:8443/1m"; wait
        netup 9000; start 9000 mtu=9000; schedule "$JFLAP"
        stress "jumbo + flap: aioquic" "$IP" -c 4 --dur 16; wait
        netup 9000; start 9000 mtu=65535
        dump "timeout 30 h2load --alpn-list=h3 -t1 -n 20 -c1 https://$IP:8443/1m"
        check "jumbo, mtu=65535 (refused above the interface): h2load, largest datagram 8957-8972" "$([ "${big:-0}" -ge 8957 ] && [ "${big:-0}" -le 8972 ] && echo 1)" "largest ${big:-none}, ${bign:-0} of them" ;;
    big-recv) # aioquic sending 1500-byte datagrams (its largest) on a jumbo path
        netup 9000; start 9000 mtu=9000
        stress "big-recv: aioquic sending 1500-byte datagrams, uploads" "$IP" -c 2 --dur 5 --path /up -d 300000 --mds 1500 ;;
    compare) # PMTUD on vs off under 1% loss: completion time of 40 × 1 MiB, interleaved
        for round in 1 2 3; do
            for a in "" mtu=0; do
                netup; start 1500 $a
                docker exec "$SRV" tc qdisc add dev eth0 root netem delay 10ms loss 1% limit 100000
                t=$(x "timeout 120 h2load --alpn-list=h3 -t1 -n 40 -c2 -m2 https://$IP:8443/1m" | awk '/^finished in/{print $3, $4}')
                echo "compare round $round ${a:-pmtud}: 40 × 1 MiB at 1% loss, 10 ms: $t"
            done
        done ;;
    esac
done
[ $fail = 0 ] && echo "H3 PMTU STRESS ALL PASS ($B)" || echo "H3 PMTU STRESS SOME FAILED ($B)"
exit $fail
