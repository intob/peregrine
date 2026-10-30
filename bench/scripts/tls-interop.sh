#!/bin/bash
# TLS key-exchange interop in Docker: bench-server (TLS and HTTP/3 on one
# port) against OpenSSL's s_client (HTTP/1.1) and curl (HTTP/1.1, h2, h3),
# for each group, then 480 new h2 connections per group, 160 at a time:
# more than the 2 workers keep free states for (64 each by default), so
# both reuse and the overflow paths run; and a HelloRetryRequest with
# each client. Prints PASS/FAIL per check, and the server's log if
# anything failed; exits 1 on any failure.
# Usage: tls-interop.sh [epoll|io_uring] (default: both)
# IMAGE: any image with OpenSSL 3.5+ (X25519MLKEM768) and curl with
# HTTP/3 (default peregrine-h3load: OpenSSL 3.5, curl 8.23 with ngtcp2).
# TLS_GROUPS overrides the groups (default "X25519 X25519MLKEM768"; P-256
# too).
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
for i in $(seq 100); do
    curl -sk -o /dev/null https://127.0.0.1:9443/ && break
    sleep 0.1
done
fail=0
check() { if [ "$2" = ok ]; then echo "PASS $1"; else echo "FAIL $1 ($3)"; fail=1; fi; }
for g in $2; do
    # How OpenSSL and curl print the group (P-256 has other names).
    case $g in P-256) name="P-256|prime256v1|secp256r1" ;; *) name=$g ;; esac
    out=$(printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" |
        openssl s_client -connect 127.0.0.1:9443 -groups $g -alpn http/1.1 -brief -ign_eof 2>&1)
    grp=$(echo "$out" | grep -iE "Negotiated TLS1.3 group|Peer Temp Key" | head -1)
    st=$(echo "$out" | grep -m1 "^HTTP/1.1")
    echo "$st" | grep -q " 200" && echo "$grp" | grep -qiE "$name" && r=ok || r=bad
    check "openssl s_client $g http/1.1: $grp" $r "$st"
    for v in --http1.1 --http2 --http3-only; do
        res=$(curl -sk -v --curves $g $v https://127.0.0.1:9443/ -o /dev/null -w "%{http_code} %{http_version}" 2>/tmp/curl.err)
        used=$(grep -o "SSL connection using .*" /tmp/curl.err | head -1 | tr -d "\r")
        echo "$res" | grep -q "^200" && echo "$used" | grep -qiE "/ ($name) /" && r=ok || r=bad
        check "curl $g $v: $res, $used" $r "$(tail -1 /tmp/curl.err | tr -d "\r")"
    done
    pids=""
    for j in $(seq 160); do
        (for i in 1 2 3; do curl -sk --curves $g --http2 https://127.0.0.1:9443/ -o /dev/null -w "%{http_code}\n"; done > /tmp/loop.$j) &
        pids="$pids $!"
    done
    wait $pids
    n=$(cat /tmp/loop.* | grep -c 200)
    [ "$n" = 480 ] && r=ok || r=bad
    check "curl $g --http2, 480 new connections, 160 at a time: $n ok" $r "$n of 480"
    rm -f /tmp/loop.*
done
# A HelloRetryRequest: the first share the clients send is for X448,
# which the server does not support, so it asks for X25519 and checks
# that ClientHello2 repeats ClientHello1.
out=$(printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" |
    openssl s_client -connect 127.0.0.1:9443 -servername localhost -groups X448:X25519 -alpn http/1.1 -brief -ign_eof 2>&1)
grp=$(echo "$out" | grep -iE "Negotiated TLS1.3 group|Peer Temp Key" | head -1)
echo "$out" | grep -q "^HTTP/1.1 200" && echo "$grp" | grep -qi X25519 && r=ok || r=bad
check "openssl s_client after a HelloRetryRequest (X448 share first): $grp" $r "$(echo "$out" | tail -2 | tr "\n" " ")"
res=$(curl -sk --curves X448:X25519 --http2 https://localhost:9443/ --resolve localhost:9443:127.0.0.1 -o /dev/null -w "%{http_code}" 2>&1)
[ "$res" = 200 ] && r=ok || r=bad
check "curl --http2 after a HelloRetryRequest (X448 share first): $res" $r "$res"
kill -0 $srv 2>/dev/null && r=ok || r=bad
check "bench-server still running" $r "it exited"
[ $fail = 0 ] || { echo "-- server log:"; tail -50 /tmp/srv.log; }
kill $srv 2>/dev/null
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
