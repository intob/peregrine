#!/bin/bash
# HTTP/2 and HTTP/3 benchmark with h2load in Docker on the Mac: each server
# with 6 workers pinned to CPUs 0-5, `h2load -t6` on 6-11 in its network
# namespace. A fresh server for every case, servers interleaved within each
# case, cases within each round; holds mac-bench, prints the load average
# each round. CPU per request is the server cgroup's CPU time over h2load's
# main phase (after a 2 s warm-up on the same connections) per request.
# Usage: h2-bench.sh h2c|tls|h3 [SERVER...]
#   SERVER: peregrine-epoll peregrine-uring nginx h2o (default: all four)
#   ROUNDS (2), DUR seconds per run (10), CASES (default "hello-10x100
#   hello-256x1 64k-10x10"): NAME-CONNSxSTREAMS, NAME hello, 64k (peregrine
#   from memory) or 64kfile (peregrine preads its file per response, as
#   nginx and h2o do for both 64k cases)
#   NGINX_KEEPALIVE=default: nginx's keepalive_requests 1000 (see nginx.conf)
#   BUILD=0: use the peregrine binaries already in $OUT/linux/bin (A/B runs)
# TLS and h3 runs pin TLS_AES_128_GCM_SHA256 and X25519 and check them.
# Images: peregrine-h3load (h2load 1.70 with HTTP/3, nginx 1.30), comp-h2o23
# (docker build -t comp-h2o23 bench/competitors/h2o), peregrine-bench.
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
usage() { sed -n '2,18p' "$0"; exit 1; }
proto=$1; shift
case $proto in h2c) port=8080 mode=plain ;; tls) port=8443 mode=tls ;; h3) port=8443 mode=h3 ;; *) usage ;; esac
servers=${*:-peregrine-epoll peregrine-uring nginx h2o}
ROUNDS=${ROUNDS:-2}; DUR=${DUR:-10}
CASES=${CASES:-hello-10x100 hello-256x1 64k-10x10}
for s in $servers; do case $s in peregrine-epoll | peregrine-uring | nginx | h2o) ;; *) echo "unknown server $s"; usage ;; esac; done
for c in $CASES; do [[ $c =~ ^(hello|64k|64kfile)-[1-9][0-9]*x[1-9][0-9]*$ ]] || { echo "bad case $c"; usage; }; done
[ "$proto" = h2c ] && url=http://127.0.0.1:$port || url=https://127.0.0.1:$port
tlsargs=(); [ "$proto" != h2c ] && tlsargs=(--tls13-ciphers=TLS_AES_128_GCM_SHA256 --groups=X25519)
[ "$proto" = h3 ] && tlsargs+=(--alpn-list=h3)
want_alpn=h2; [ "$proto" = h3 ] && want_alpn=h3

server() { # NAME -> "IMAGE|CMD"
    case $1 in
    peregrine-epoll) echo "peregrine-bench|exec /b/bench-server 6 epoll $port $mode" ;;
    peregrine-uring) echo "peregrine-bench|exec /b/bench-server 6 io_uring $port $mode" ;;
    nginx) local sed="true"
        [ "${NGINX_KEEPALIVE:-}" = default ] && sed="sed -i 's/^ *keepalive_requests/#&/' /tmp/nginx.conf"
        echo "peregrine-h3load|mkdir -p /tmp/www && head -c 65536 /dev/zero | tr '\\0' x > /tmp/www/64k && cp /bench/competitors/nginx/nginx.conf /tmp/ && $sed && exec nginx -c /tmp/nginx.conf" ;;
    h2o) echo "comp-h2o23|exec h2o -c /bench/competitors/h2o/h2o.conf" ;;
    esac
}
path_of() { # SERVER CASE-NAME
    case $2 in hello) echo / ;; 64k) echo /64k ;; 64kfile) [ "${1%-*}" = peregrine ] && echo /64k-file || echo /64k ;; esac
}
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
on_exit() {
    docker stop -t 1 h2b-cli-$TAG h2b-srv-$TAG >/dev/null 2>&1
    docker rm h2b-cli-$TAG h2b-srv-$TAG >/dev/null 2>&1
}

bench_lock "h2-bench $proto ($ROOT)"
[ "${BUILD:-1}" = 0 ] || build_linux_bins || exit 1
printf "%-16s %-5s %-14s %9s %6s %6s %9s %6s  %s\n" server proto case req/s GB/s cores CPU/req hdr/rsp tls
for round in $(seq "$ROUNDS"); do
  # The load average counts this benchmark's own VM threads too; the CPU of
  # everything outside Docker is the better sign of a busy Mac.
  others=$(ps -A -o %cpu=,comm= | awk '!/Virtualization|com\.docker|Docker Desktop/ {s += $1} END {printf "%.0f", s}')
  echo "== round $round, load $(uptime | sed 's/.*averages*: //'), outside Docker ${others}% CPU"
  for c in $CASES; do
    name=${c%%-*}; cs=${c#*-}; conns=${cs%x*}; streams=${cs#*x}
    for s in $servers; do
      spec=$(server "$s"); path=$(path_of "$s" "$name")
      docker run -d --name h2b-srv-$TAG --cpuset-cpus 0-5 --ulimit nofile=65536:65536 \
        --security-opt seccomp="$SECCOMP" -v "$BIN":/b -v "$ROOT/bench":/bench:ro "${spec%%|*}" sh -c "${spec#*|}" >/dev/null || exit 1
      sleep 1.5
      # -t: on a tty h2load's output is line-buffered, so its phase markers
      # arrive as they happen.
      docker run -d -t --name h2b-cli-$TAG --cpuset-cpus 6-11 --network container:h2b-srv-$TAG peregrine-h3load:latest \
        h2load "${tlsargs[@]}" -t6 -c"$conns" -m"$streams" --warm-up-time=2 -D"$DUR" "$url$path" >/dev/null || exit 1
      # The main phase, from h2load's own markers (the first thread's).
      t0= t1= w0= w1=
      while IFS= read -r line; do
        case $line in
        "Main benchmark duration is started"*) [ -z "$t0" ] && { t0=$(cgroup_usec h2b-srv-$TAG); w0=$(now); } ;;
        "Main benchmark duration is over"*) [ -z "$t1" ] && { t1=$(cgroup_usec h2b-srv-$TAG); w1=$(now); } ;;
        esac
      done < <(docker logs -f h2b-cli-$TAG 2>&1)
      rc=$(docker wait h2b-cli-$TAG); out=$(docker logs h2b-cli-$TAG 2>&1 | tr -d '\r'); docker rm h2b-cli-$TAG >/dev/null
      # A failed `docker exec` is not a dead server: ask Docker, and keep a
      # dead one (h2b-dead-*) with its log and h2load's output for a look.
      state=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' h2b-srv-$TAG 2>&1)
      if [ "${state%% *}" != running ]; then
        dead=h2b-dead-$TAG-$s-$c-$round
        echo "$s $proto $c: SERVER DIED ($state), kept as $dead"
        echo "$out" | tail -12; docker logs --tail 30 h2b-srv-$TAG 2>&1
        docker rename h2b-srv-$TAG "$dead"; continue
      fi
      docker stop -t 1 h2b-srv-$TAG >/dev/null; docker rm h2b-srv-$TAG >/dev/null
      # requests: N total, N started, N done, N succeeded, N failed, N errored, N timeout
      read -r ok failed errored timeout <<< "$(echo "$out" | sed -n 's/^requests: .* \([0-9]*\) succeeded, \([0-9]*\) failed, \([0-9]*\) errored, \([0-9]*\) timeout.*/\1 \2 \3 \4/p')"
      non2xx=$(echo "$out" | sed -n 's/^status codes: [0-9]* 2xx, \([0-9]*\) 3xx, \([0-9]*\) 4xx, \([0-9]*\) 5xx.*/\1 \2 \3/p' | awk '{print $1 + $2 + $3}')
      rate=$(echo "$out" | sed -n 's/^finished in [0-9.]*s, \([0-9.]*\) req\/s.*/\1/p')
      hdr=$(echo "$out" | sed -n 's/^traffic: .*(\([0-9]*\)) headers.*/\1/p')
      tls=-
      if [ "$proto" != h2c ]; then
        cipher=$(echo "$out" | sed -n 's/^Cipher: //p'); key=$(echo "$out" | sed -n 's/^Server Temp Key: \([^ ]*\).*/\1/p')
        alpn=$(echo "$out" | sed -n 's/^Application protocol: //p'); tls="$cipher $key $alpn"
      fi
      bad=
      [ "$rc" = 0 ] || bad+=" exit $rc"
      [ -n "$ok" ] && [ "$ok" != 0 ] || bad+=" no requests"
      [ "${failed:-0}${errored:-0}${timeout:-0}" = 000 ] || bad+=" failed $failed errored $errored timeout $timeout"
      [ "${non2xx:-0}" = 0 ] || bad+=" non-2xx $non2xx"
      if [ -z "$t0" ] || [ -z "$t1" ]; then bad+=" no main-phase CPU reading"
      elif [ "$(echo "($w1 - $w0) < $DUR * 0.9" | bc)" = 1 ]; then bad+=" main phase read over $(echo "$w1 - $w0" | bc) s"; fi
      [ "$proto" = h2c ] || [ "$tls" = "TLS_AES_128_GCM_SHA256 X25519 $want_alpn" ] || bad+=" negotiated: $tls"
      if [ -n "$bad" ]; then echo "$s $proto $c: FAILED:$bad"; echo "$out" | tail -6; continue; fi
      gbs=-; [ "$name" != hello ] && gbs=$(echo "scale=1; $rate * 65536 / 1000000000" | bc)
      printf "%-16s %-5s %-14s %9.0f %6s %6s %6s µs %6s  %s\n" "$s" "$proto" "$c" "$rate" "$gbs" \
        "$(echo "scale=2; ($t1 - $t0) / (($w1 - $w0) * 1000000)" | bc)" "$(echo "scale=2; ($t1 - $t0) / $ok" | bc)" \
        "$(echo "scale=1; $hdr / $ok" | bc)" "${tls/TLS_AES_128_GCM_SHA256/AES128GCM}"
    done
  done
done
