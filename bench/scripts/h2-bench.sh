#!/bin/bash
# HTTP/2 and HTTP/3 benchmark with h2load in Docker on the Mac: each server
# with 6 workers on CPUs 0-5, `h2load -t6` on 6-11 in its network namespace,
# server CPU per request from its cgroup. A fresh server for every case;
# servers interleaved within each case, cases within each round. Needs the
# 12 cores to itself: holds mac-bench, prints the load average each round.
# Usage: h2-bench.sh h2c|tls|h3 [SERVER...]
#   SERVER: peregrine-epoll peregrine-uring nginx h2o (default: all four)
#   ROUNDS (2), DUR seconds per run (10), CASES (default "hello-10x100
#   hello-256x1 64k-10x10"; NAME-CONNSxSTREAMS, NAME hello or 64k)
#   NGINX_KEEPALIVE=default: nginx's keepalive_requests 1000 (see nginx.conf)
#   BUILD=0: use the peregrine binaries already in $OUT/linux/bin (A/B runs)
# Images: peregrine-h3load (h2load 1.70 with HTTP/3, nginx 1.30), comp-h2o23
# (docker build -t comp-h2o23 bench/competitors/h2o), peregrine-bench.
# Peregrine binaries from build_linux_bins (env.sh), built here first.
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
proto=$1; shift
case $proto in h2c) port=8080 mode=plain ;; tls) port=8443 mode=tls ;; h3) port=8443 mode=h3 ;;
*) sed -n '2,15p' "$0"; exit 1 ;; esac
servers=${*:-peregrine-epoll peregrine-uring nginx h2o}
ROUNDS=${ROUNDS:-2}; DUR=${DUR:-10}
CASES=${CASES:-hello-10x100 hello-256x1 64k-10x10}
[ "${BUILD:-1}" = 0 ] || build_linux_bins || exit 1
[ "$proto" = h2c ] && url=http://127.0.0.1:$port || url=https://127.0.0.1:$port
[ "$proto" = h3 ] && alpn=--alpn-list=h3 || alpn=

server() { # NAME -> "IMAGE|CMD"
    case $1 in
    peregrine-epoll) echo "peregrine-bench|/b/bench-server 6 epoll $port $mode" ;;
    peregrine-uring) echo "peregrine-bench|/b/bench-server 6 io_uring $port $mode" ;;
    nginx) local sed="true"
        [ "${NGINX_KEEPALIVE:-}" = default ] && sed="sed -i 's/^ *keepalive_requests/#&/' /tmp/nginx.conf"
        echo "peregrine-h3load|mkdir -p /tmp/www && head -c 65536 /dev/zero | tr '\\0' x > /tmp/www/64k && cp /bench/competitors/nginx/nginx.conf /tmp/ && $sed && exec nginx -c /tmp/nginx.conf" ;;
    h2o) echo "comp-h2o23|exec h2o -c /etc/h2o.conf" ;;
    *) return 1 ;;
    esac
}
cpu() { docker exec h2b-srv-$TAG awk '/usage_usec/ {print $2}' /sys/fs/cgroup/cpu.stat; }
h2load() { docker run --rm --cpuset-cpus 6-11 --network container:h2b-srv-$TAG peregrine-h3load:latest h2load $alpn "$@"; }

# The machine to itself: wait for other peregrine jobs, hold the lock.
"$LOCK" acquire mac-bench "h2-bench $proto ($ROOT)"
trap 'docker stop -t 1 h2b-srv-$TAG >/dev/null 2>&1; docker rm h2b-srv-$TAG >/dev/null 2>&1; "$LOCK" release mac-bench' EXIT
while docker ps --format '{{.Names}}' | grep -qE '^(lt-|ab-|fuzz-|wsb-|h2b-)'; do sleep 10; done
printf "%-16s %-6s %-13s %10s %8s %9s %11s\n" server proto case req/s GB/s cores CPU/req
for round in $(seq "$ROUNDS"); do
  echo "== round $round, load $(uptime | sed 's/.*averages*: //')"
  for c in $CASES; do
    path=/; [ "${c%%-*}" = 64k ] && path=/64k
    cs=${c#*-}; conns=${cs%x*}; streams=${cs#*x}
    for s in $servers; do
      spec=$(server "$s") || { echo "unknown server $s"; exit 1; }
      docker run -d --name h2b-srv-$TAG --cpuset-cpus 0-5 --ulimit nofile=65536:65536 \
        --security-opt seccomp="$SECCOMP" -v "$BIN":/b -v "$ROOT/bench":/bench:ro "${spec%%|*}" sh -c "${spec#*|}" >/dev/null || exit 1
      sleep 1.5
      h2load -t6 -c12 -m10 -D2 "$url$path" >/dev/null 2>&1 # warm-up
      t0=$(cpu)
      out=$(h2load -t6 -c"$conns" -m"$streams" -D"$DUR" "$url$path" 2>&1)
      t1=$(cpu 2>/dev/null)
      [ -n "$t1" ] || { echo "$s $proto $c: SERVER DIED"; docker logs --tail 30 h2b-srv-$TAG 2>&1; }
      docker stop -t 1 h2b-srv-$TAG >/dev/null; docker rm h2b-srv-$TAG >/dev/null
      [ -n "$t1" ] || continue
      secs=$(echo "$out" | sed -n 's/^finished in \([0-9.]*\)s.*/\1/p')
      rate=$(echo "$out" | sed -n 's/^finished in [0-9.]*s, \([0-9.]*\) req\/s.*/\1/p')
      ok=$(echo "$out" | sed -n 's/^requests: .* \([0-9]*\) succeeded.*/\1/p')
      if [ -z "$ok" ] || [ "$ok" = 0 ]; then echo "$s $proto $c: FAILED"; echo "$out" | tail -8; continue; fi
      gbs=-; [ "$path" = /64k ] && gbs=$(echo "scale=1; $rate * 65536 / 1000000000" | bc)
      printf "%-16s %-6s %-13s %10.0f %8s %9s %8s µs\n" "$s" "$proto" "$c" "$rate" "$gbs" \
        "$(echo "scale=2; ($t1 - $t0) / ($secs * 1000000)" | bc)" "$(echo "scale=2; ($t1 - $t0) / $ok" | bc)"
    done
  done
done
