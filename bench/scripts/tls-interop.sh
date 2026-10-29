#!/bin/bash
# TLS key-exchange interop in Docker: bench-server (TLS and HTTP/3 on one
# port) against OpenSSL's s_client (HTTP/1.1) and curl (HTTP/1.1, h2, h3),
# for each group, then 8 × 40 new h2 connections per group so reused
# connection and handshake states get exercised. Prints PASS/FAIL per
# check; exits 1 on any failure.
# Usage: tls-interop.sh [epoll|io_uring] (default: both)
# IMAGE: any image with OpenSSL 3.5+ (X25519MLKEM768) and curl with
# HTTP/3 (default peregrine-h3load: OpenSSL 3.5, curl 8.23 with ngtcp2).
# TLS_GROUPS overrides the groups (default "X25519 X25519MLKEM768").
source "$(dirname "$0")/env.sh"
IMAGE=${IMAGE:-peregrine-h3load}
GROUPS_=${TLS_GROUPS:-X25519 X25519MLKEM768}
backends=${1:-epoll io_uring}
"$LOCK" share mac-bench "tls-interop ($ROOT)"
trap '"$LOCK" unshare mac-bench' EXIT
build_linux_bins || exit 1
BIN=$OUT/linux/bin

# Runs in the container: $1 backend, $2 groups.
client='
/b/bench-server 2 "$1" 9443 h3 > /tmp/srv.log 2>&1 &
srv=$!
sleep 1
fail=0
check() { if [ "$2" = ok ]; then echo "PASS $1"; else echo "FAIL $1 ($3)"; fail=1; fi; }
for g in $2; do
    out=$(printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" |
        openssl s_client -connect 127.0.0.1:9443 -groups $g -alpn http/1.1 -brief -ign_eof 2>&1)
    grp=$(echo "$out" | grep -iE "Negotiated TLS1.3 group|Peer Temp Key" | head -1)
    st=$(echo "$out" | grep -m1 "^HTTP/1.1")
    echo "$st" | grep -q " 200" && echo "$grp" | grep -qi "${g}" && r=ok || r=bad
    check "openssl s_client $g http/1.1: $grp" $r "$st"
    for v in --http1.1 --http2 --http3-only; do
        res=$(curl -sk -v --curves $g $v https://127.0.0.1:9443/ -o /dev/null -w "%{http_code} %{http_version}" 2>/tmp/curl.err)
        used=$(grep -o "SSL connection using .*" /tmp/curl.err | head -1 | tr -d "\r")
        echo "$res" | grep -q "^200" && echo "$used" | grep -qi "/ ${g} /" && r=ok || r=bad
        check "curl $g $v: $res, $used" $r "$(tail -1 /tmp/curl.err | tr -d "\r")"
    done
    pids=""
    for j in 1 2 3 4 5 6 7 8; do
        (for i in $(seq 40); do curl -sk --curves $g --http2 https://127.0.0.1:9443/ -o /dev/null -w "%{http_code}\n"; done > /tmp/loop.$j) &
        pids="$pids $!"
    done
    wait $pids
    n=$(cat /tmp/loop.* | grep -c 200)
    [ "$n" = 320 ] && r=ok || r=bad
    check "curl $g --http2, 320 new connections: $n ok" $r "$n of 320"
    rm -f /tmp/loop.*
done
kill $srv 2>/dev/null
kill -0 $srv 2>/dev/null && wait $srv
exit $fail
'

status=0
for b in $backends; do
    echo "== $b"
    docker run --rm --name tls-interop-$b-$TAG --security-opt seccomp="$SECCOMP" -v "$BIN":/b "$IMAGE" \
        sh -c "$client" sh "$b" "$GROUPS_" || status=1
done
[ $status = 0 ] && echo "all PASS" || echo "some FAIL"
exit $status
