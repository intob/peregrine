#!/bin/bash
# TLS key-exchange interop in Docker: bench-server (TLS and HTTP/3 on one
# port) against OpenSSL's s_client (HTTP/1.1) and curl (HTTP/1.1, h2, h3),
# for each group, then 480 new h2 connections per group, 160 at a time:
# more than the 2 workers keep free states for (64 each by default), so
# both reuse and the overflow paths run; a HelloRetryRequest with each
# client; and OCSP stapling (a second server with the test CA's
# certificates from src/tls/testdata/ocsp and `ocsp=DIR`): s_client
# -status over TCP and QUIC, curl --cert-status (which verifies the
# response against the CA) over HTTP/1.1, h2 and h3, by SNI too, and the
# response file replaced while the server runs (an unauthorised responder,
# a revocation, a new response). Prints PASS/FAIL per
# check, and the server's log if anything failed; exits 1 on any failure.
# Usage: tls-interop.sh [epoll|io_uring] (default: both)
# IMAGE: any image with OpenSSL 3.5+ (X25519MLKEM768, s_client -quic) and
# curl with HTTP/3 (default peregrine-h3load: OpenSSL 3.5, curl 8.23 with
# ngtcp2).
# TLS_GROUPS overrides the groups (default "X25519 X25519MLKEM768 P-256";
# empty: none, for the other checks alone).
# CERT=rsa: the RSA-2048 certificate (bench/rsa.pem) instead of ECDSA
# P-256, and s_client must report an rsa_pss_rsae_sha256 signature.
source "$(dirname "$0")/env.sh"
IMAGE=${IMAGE:-peregrine-h3load}
GROUPS_=${TLS_GROUPS-X25519 X25519MLKEM768 P-256}
CERT=${CERT:-ecdsa}
case $CERT in ecdsa) cert_arg= ;; rsa) cert_arg=rsa ;; *) echo "CERT: ecdsa or rsa"; exit 1 ;; esac
backends=${1:-epoll io_uring}
"$LOCK" share mac-bench "tls-interop ($ROOT)"
trap '"$LOCK" unshare mac-bench' EXIT
build_linux_bins || exit 1
BIN=$OUT/linux/bin

# Runs in the container: $1 backend, $2 groups, $3 "rsa" or empty.
client='
/b/bench-server 2 "$1" 9443 h3 $3 > /tmp/srv.log 2>&1 &
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
    if [ "$3" = rsa ]; then
        sig=$(echo "$out" | grep -iE "^(Peer )?signature type" | head -1)
        echo "$sig" | grep -qi "rsa_pss_rsae_sha256" && r=ok || r=bad
        check "openssl s_client $g: $sig" $r "$sig"
    fi
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

# OCSP stapling: the OCSP test certificates, responses read from
# /tmp/ocspd (checked for changes every second).
mkdir -p /tmp/ocspd
cp /ocsp/leaf-good.der /tmp/ocspd/leaf.der
cp /ocsp/sni-good.der /tmp/ocspd/sni.der
/b/bench-server 2 "$1" 9444 h3 ocsp=/tmp/ocspd > /tmp/ocsp.log 2>&1 &
osrv=$!
for i in $(seq 100); do
    curl -sk -o /dev/null https://127.0.0.1:9444/ && break
    sleep 0.1
done
# s_client -status: $1 the name (SNI), then more s_client arguments.
ostatus() {
    name=$1
    shift
    printf "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" |
        openssl s_client -connect 127.0.0.1:9444 -servername $name -CAfile /ocsp/ca.pem -verify_return_error -status -ign_eof "$@" 2>&1
}
# $1 the s_client output, $2 the serial number the response must be for.
stapled() {
    echo "$1" | grep -q "OCSP Response Status: successful" && echo "$1" | grep -q "Cert Status: good" &&
        echo "$1" | grep -qE "Serial Number: $2\$" && echo "$1" | grep -q "Verify return code: 0"
}
summary() { echo "$1" | grep -E "OCSP response:|Cert Status|Serial Number: 100|Hash Algorithm|^HTTP/1.1" | tr -s " " | tr "\n" " "; }
out=$(ostatus localhost -alpn http/1.1)
stapled "$out" 1001 && echo "$out" | grep -q "^HTTP/1.1 200" && r=ok || r=bad
check "openssl s_client -status http/1.1: $(summary "$out")" $r "$(echo "$out" | tail -3 | tr "\n" " ")"
out=$(ostatus ocsp.example -alpn h2)
stapled "$out" 1002 && echo "$out" | grep -q "ALPN protocol: h2" && r=ok || r=bad
check "openssl s_client -status h2, SNI ocsp.example: $(summary "$out")" $r "$(echo "$out" | tail -3 | tr "\n" " ")"
out=$(openssl s_client -quic -alpn h3 -connect 127.0.0.1:9444 -servername localhost -CAfile /ocsp/ca.pem -verify_return_error -status < /dev/null 2>&1)
stapled "$out" 1001 && r=ok || r=bad
check "openssl s_client -quic -alpn h3 -status: $(summary "$out")" $r "$(echo "$out" | tail -3 | tr "\n" " ")"
out=$(openssl s_client -quic -alpn h3 -connect 127.0.0.1:9444 -servername ocsp.example -CAfile /ocsp/ca.pem -verify_return_error -status < /dev/null 2>&1)
stapled "$out" 1002 && r=ok || r=bad
check "openssl s_client -quic -alpn h3 -status, SNI ocsp.example: $(summary "$out")" $r "$(echo "$out" | tail -3 | tr "\n" " ")"
# curl --cert-status verifies the response (signature, CertID, times)
# and fails without one: against the first server, which staples
# nothing, it must fail.
for v in --http1.1 --http2 --http3-only; do
    for name in localhost ocsp.example; do
        res=$(curl -s --cert-status --cacert /ocsp/ca.pem --resolve $name:9444:127.0.0.1 $v https://$name:9444/ -o /dev/null -w "%{http_code} %{http_version}" 2>&1)
        echo "$res" | grep -q "^200" && r=ok || r=bad
        check "curl --cert-status $v $name: $res" $r "$res"
    done
    res=$(curl -s --cert-status -k $v https://127.0.0.1:9443/ -o /dev/null -w "%{http_code}" 2>&1)
    code=$?
    [ $code != 0 ] && r=ok || r=bad
    check "curl --cert-status $v without a stapled response fails: exit $code" $r "$res"
done
# A response from a responder the CA did not authorise replacing the file
# is skipped (logged), the good one stays, and so it does for "unknown"; a
# current, signed revocation stops stapling (logged as an error); a new
# good one is stapled again (curl verifies it).
cp /ocsp/leaf-good-noeku.der /tmp/ocspd/tmp && mv /tmp/ocspd/tmp /tmp/ocspd/leaf.der
sleep 2.5
out=$(ostatus localhost -alpn http/1.1)
stapled "$out" 1001 && grep -q "leaf.der: signed by a responder that may not sign" /tmp/ocsp.log && r=ok || r=bad
check "a response from an unauthorised responder is skipped and logged, the last good one stays: $(summary "$out")" $r "$(grep OCSP /tmp/ocsp.log | tail -2)"
cp /ocsp/leaf-unknown.der /tmp/ocspd/tmp && mv /tmp/ocspd/tmp /tmp/ocspd/leaf.der
sleep 2.5
out=$(ostatus localhost -alpn http/1.1)
stapled "$out" 1001 && grep -q "leaf.der: the responder doesn.t know the certificate" /tmp/ocsp.log && r=ok || r=bad
check "an unknown status is logged, the last good one stays: $(summary "$out")" $r "$(grep OCSP /tmp/ocsp.log | tail -2)"
cp /ocsp/leaf-revoked.der /tmp/ocspd/tmp && mv /tmp/ocspd/tmp /tmp/ocspd/leaf.der
sleep 2.5
out=$(ostatus localhost -alpn http/1.1)
echo "$out" | grep -q "OCSP response: no response sent" && echo "$out" | grep -q "^HTTP/1.1 200" &&
    grep -q "^error.*leaf.der: the certificate is revoked" /tmp/ocsp.log && r=ok || r=bad
check "a revocation stops stapling, logged as an error: $(summary "$out")" $r "$(grep OCSP /tmp/ocsp.log | tail -2)"
cp /ocsp/leaf-good-ca384.der /tmp/ocspd/tmp && mv /tmp/ocspd/tmp /tmp/ocspd/leaf.der
sleep 2.5
out=$(ostatus localhost -alpn http/1.1)
stapled "$out" 1001 && echo "$out" | grep -q "ecdsa-with-SHA384" && r=ok || r=bad
check "a new response is picked up: $(summary "$out")" $r "$(echo "$out" | tail -3 | tr "\n" " ")"
res=$(curl -s --cert-status --cacert /ocsp/ca.pem --resolve localhost:9444:127.0.0.1 --http2 https://localhost:9444/ -o /dev/null -w "%{http_code}" 2>&1)
[ "$res" = 200 ] && r=ok || r=bad
check "curl --cert-status verifies the new response: $res" $r "$res"
# A response whose only CertID for the leaf uses SHA-256 (curl looks up a
# SHA-1 one and fails): refused, logged, the last good one stays.
cp /ocsp/leaf-good-sha256.der /tmp/ocspd/tmp && mv /tmp/ocspd/tmp /tmp/ocspd/leaf.der
sleep 2.5
res=$(curl -s --cert-status --cacert /ocsp/ca.pem --resolve localhost:9444:127.0.0.1 --http2 https://localhost:9444/ -o /dev/null -w "%{http_code}" 2>&1)
[ "$res" = 200 ] && grep -q "leaf.der: its CertID for this certificate uses SHA-2" /tmp/ocsp.log && r=ok || r=bad
check "a SHA-256 CertID is refused and logged, the last good one stays (curl --cert-status): $res" $r "$(grep OCSP /tmp/ocsp.log | tail -2)"
kill -0 $osrv 2>/dev/null && r=ok || r=bad
check "bench-server with OCSP still running" $r "it exited"
kill $osrv 2>/dev/null

kill -0 $srv 2>/dev/null && r=ok || r=bad
check "bench-server still running" $r "it exited"
[ $fail = 0 ] || { echo "-- server log:"; tail -50 /tmp/srv.log; echo "-- OCSP server log:"; tail -20 /tmp/ocsp.log; }
kill $srv 2>/dev/null
exit $fail
'

status=0
for b in $backends; do
    echo "== $b ($CERT)"
    docker run --rm --name tls-interop-$b-$TAG --security-opt seccomp="$SECCOMP" -v "$BIN":/b -v "$ROOT/src/tls/testdata/ocsp":/ocsp:ro "$IMAGE" \
        sh -c "$client" sh "$b" "$GROUPS_" "$cert_arg" || status=1
done
[ $status = 0 ] && echo "all PASS" || echo "some FAIL"
exit $status
