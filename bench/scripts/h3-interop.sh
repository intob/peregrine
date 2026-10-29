#!/bin/bash
# HTTP/3 interop against bench-server in Docker: curl (ngtcp2), aioquic and
# h2load from peregrine-h3load (bench/h3/Dockerfile), then h3spec when its
# image is there (h3spec:0.1.14, bench/h3/Dockerfile.h3spec). Prints PASS
# or FAIL per check; exits 1 if any failed.
# Usage: h3-interop.sh [epoll|io_uring] [bench-server args, e.g. nopace 0rtt]
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
B=${1:-epoll}; shift
docker image inspect peregrine-h3load >/dev/null 2>&1 ||
    { echo "no peregrine-h3load image: docker build -t peregrine-h3load $ROOT/bench/h3"; exit 1; }
"$LOCK" wait mac-bench
build_linux_bins || exit 1
N=h3i-$B-$TAG
docker run --rm -d --name "$N" --security-opt seccomp="$SECCOMP" -v "$BIN":/b -v "$ROOT/bench/h3":/h3 \
    peregrine-h3load /b/bench-server 4 "$B" 8443 h3 "$@" >/dev/null || exit 1
trap 'docker stop -t 1 "$N" >/dev/null' EXIT
sleep 1
docker logs "$N" 2>&1 | head -1
U=https://127.0.0.1:8443
x() { docker exec "$N" sh -c "$1" 2>&1; }
fail=0
check() { # name expected actual
    if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: expected '$2' got '$3'"; fail=1; fi
}
check "curl GET /" "3 200 Hello, World!" "$(x "curl -sk --http3-only -o /tmp/b -w '%{http_version} %{http_code}' $U/ && echo \" \$(cat /tmp/b)\"" | tr -d '\n')"
check "curl 64 KiB" "65536" "$(x "curl -sk --http3-only $U/64k | wc -c" | tr -d ' ')"
check "curl 1 MiB" "1048576" "$(x "curl -sk --http3-only $U/1m | wc -c" | tr -d ' ')"
check "curl POST 1 MiB" "3 200" "$(x "head -c 1048576 /dev/zero | curl -sk --http3-only --data-binary @- -o /dev/null -w '%{http_version} %{http_code}' $U/")"
check "curl 50 parallel 1 MiB" "50" "$(x "curl -sk --http3-only --parallel --parallel-max 50 \$(for i in \$(seq 50); do printf -- '-o /dev/null $U/1m '; done) -w '%{size_download}\n' | grep -c '^1048576\$'")"
check "aioquic 60 concurrent GETs" "60" "$(x "python3 /h3/aioquic_client.py 127.0.0.1 8443 /1m /64k / -n 20" | grep -c ' 200 ')"
check "aioquic 5 POSTs of 1 MiB" "5" "$(x "python3 /h3/aioquic_client.py 127.0.0.1 8443 / -n 5 -d 1048576" | grep -c ' 200 ')"
for args in "20000 -c10 -m100 $U/" "2000 -c10 -m10 $U/64k" "200 -c4 -m4 $U/1m"; do
    n=${args%% *}
    check "h2load -n $args" "$n" "$(x "h2load --alpn-list=h3 -t2 -n $args" | awk '/^status codes:/{print $3}')"
done
if docker image inspect h3spec:0.1.14 >/dev/null 2>&1; then
    check "h3spec" "0 failures" "$(docker run --rm --platform linux/amd64 --network container:"$N" h3spec:0.1.14 127.0.0.1 8443 --no-validate 2>&1 |
        sed -n 's/.* examples, \([0-9]* failures\).*/\1/p')"
else
    echo "SKIP h3spec (no h3spec:0.1.14 image)"
fi
[ $fail = 0 ] && echo "H3 INTEROP ALL PASS ($B $*)" || echo "H3 INTEROP SOME FAILED ($B $*)"
exit $fail
