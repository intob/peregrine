#!/bin/bash
# TLS 1.3 handshake benchmark in Docker on the Mac: new connections per
# second, each a full handshake (or a resumption) and one request, and the
# server's CPU time per handshake from its cgroup. Each server runs with 1
# worker on CPU 0 alone ("per core") and with 6 workers on CPUs 0-5;
# tls-load (bench/tls_load.zig, 6 threads) runs on CPUs 6-11 in its network
# namespace. A fresh server for every run, servers interleaved within each
# case, cases within each round; holds mac-bench, prints the load average
# each round. CPU per handshake is the server cgroup's CPU time over
# tls-load's main phase (after a 2 s warm-up) per handshake completed in it.
# Two columns say who set the rate: the server's cores (below about 0.9 per
# worker it was not saturated, and the row is marked "<") and the client's
# (its own CPU time over the same phase; near 6.0 the client, not the
# server, set the rate, and the row is marked "!").
# Usage: tls-bench.sh [SERVER...]
#   SERVER: peregrine-epoll peregrine-uring nginx h2o (default: all four)
#   CASES (default "ecdsa-x25519 ecdsa-p256 ecdsa-mlkem ecdsa-x25519-resume
#   rsa-x25519 ecdsa-x25519-h2"): CERT-GROUP[-h2][-resume], CERT ecdsa
#   (P-256, bench/cert.pem) or rsa (RSA-2048, bench/rsa.pem), GROUP x25519,
#   p256 (secp256r1) or mlkem (X25519MLKEM768); HTTP/1.1 (one GET with
#   Connection: close) unless -h2 (one GET on stream 1)
#   WORKERS ("1 6"), ROUNDS (2), DUR seconds per run (8)
#   CONNS: connections in flight per server worker count ("1:48 6:384")
#   VERIFY: tls-load verifies the CertificateVerify signature of one full
#   handshake in N per thread, per server worker count ("1:1 6:32": every
#   one against 1 worker; std's ECDSA verify, about 130 µs, costs more than
#   peregrine's whole handshake, and against 6 server cores the client
#   has none to spare)
#   BUILD=0: use the binaries already in $OUT/linux/bin (A/B runs)
# Checked per run, or the run is FAILED and the script exits 1 at the end:
# tls-load's exit status; no connection errors (a timeout, an alert, a
# wrong Finished or signature, a certificate other than the case's, a
# non-200 response); TLS 1.3 with TLS_AES_128_GCM_SHA256 (the only suite
# offered), the case's group (the only one offered), signature scheme
# (ecdsa_secp256r1_sha256 or rsa_pss_rsae_sha256) and ALPN as the server
# negotiated them; signatures verified (all of them with VERIFY 1, at least
# half the expected share otherwise); every handshake full, or for -resume
# over 99% resumed; a server still running at the end; the main phase read
# over at least 90% of DUR.
# Servers, all TLS 1.3 only, same certificate and key, one session ticket
# per handshake, no access log, the workers pinned one per CPU, kTLS off
# (Docker's kernel has no tls module; peregrine is given `noktls` so a
# kernel with one gives the same comparison): peregrine's bench-server
# (epoll or io_uring); nginx 1.30.6 with OpenSSL 3.5.9 (peregrine-h3load,
# bench/competitors/nginx/nginx.conf, with `ssl_conf_command NumTickets 1`:
# OpenSSL sends two by default); h2o 2.3.0-DEV (comp-h2o23: docker build -t
# comp-h2o23 bench/competitors/h2o), whose TLS 1.3 is picotls over OpenSSL
# 3.3's libcrypto, without X25519MLKEM768 (its mlkem cases are skipped).
# Workers, certificate and tickets are set by editing a copy of each
# config. Responses: peregrine "Hello, World!" from memory, nginx `return
# 200`, h2o a static file (as in h2-bench.sh).
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
usage() { sed -n '2,51p' "$0"; exit 1; }
servers=${*:-peregrine-epoll peregrine-uring nginx h2o}
CASES=${CASES:-ecdsa-x25519 ecdsa-p256 ecdsa-mlkem ecdsa-x25519-resume rsa-x25519 ecdsa-x25519-h2}
WORKERS=${WORKERS:-1 6}; ROUNDS=${ROUNDS:-2}; DUR=${DUR:-8}
CONNS=${CONNS:-1:48 6:384}; VERIFY=${VERIFY:-1:1 6:32}
for s in $servers; do case $s in peregrine-epoll | peregrine-uring | nginx | h2o) ;; *) echo "unknown server $s"; usage ;; esac; done
for c in $CASES; do [[ $c =~ ^(ecdsa|rsa)-(x25519|p256|mlkem)(-h2)?(-resume)?$ ]] || { echo "bad case $c"; usage; }; done
for w in $WORKERS; do
  case $w in 1 | 6) ;; *) echo "WORKERS: 1 and/or 6"; usage ;; esac
  for v in CONNS VERIFY; do [[ " ${!v} " =~ \ $w:[1-9][0-9]*\  ]] || { echo "$v has no positive count for $w workers"; usage; }; done
done
per_workers() { echo "$1" | tr ' ' '\n' | sed -n "s/^$2://p"; } # LIST WORKERS

server() { # NAME WORKERS CERT -> "IMAGE|CMD"
    local cert=/bench/cert.pem key=/bench/key.pem rsa=
    [ "$3" = rsa ] && cert=/bench/rsa.pem key=/bench/rsa.key rsa=rsa
    local edit="s#/bench/cert.pem#$cert#; s#/bench/key.pem#$key#"
    case $1 in
    peregrine-epoll) echo "peregrine-bench|exec /b/bench-server $2 epoll 8443 tls noktls $rsa" ;;
    peregrine-uring) echo "peregrine-bench|exec /b/bench-server $2 io_uring 8443 tls noktls $rsa" ;;
    nginx) echo "peregrine-h3load|cp /bench/competitors/nginx/nginx.conf /tmp/ && sed -i 's/^worker_processes 6;/worker_processes $2;/; $edit; s/^\( *\)ssl_protocols TLSv1.3;/&\n\1ssl_conf_command NumTickets 1;/' /tmp/nginx.conf && exec nginx -c /tmp/nginx.conf" ;;
    h2o) local cpus=0; [ "$2" = 6 ] && cpus="0, 1, 2, 3, 4, 5"
        echo "comp-h2o23|cp /bench/competitors/h2o/h2o.conf /tmp/ && sed -i 's/^num-threads: .*/num-threads: [$cpus]/; $edit' /tmp/h2o.conf && exec h2o -c /tmp/h2o.conf" ;;
    esac
}
supported() { # SERVER CASE
    case $1-$2 in h2o-*-mlkem*) return 1 ;; esac
}
now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
on_exit() {
    docker stop -t 1 tlsb-cli-$TAG tlsb-srv-$TAG >/dev/null 2>&1
    docker rm tlsb-cli-$TAG tlsb-srv-$TAG >/dev/null 2>&1
}

bench_lock "tls-bench ($ROOT)"
[ "${BUILD:-1}" = 0 ] || build_linux_bins || exit 1
failures=0
printf "%-16s %2s %-20s %7s %6s %9s %6s %8s %7s %5s  %s\n" server w case hs/s cores CPU/hs client verified tickets cert negotiated
for round in $(seq "$ROUNDS"); do
  # The load average counts this benchmark's own VM threads too; the CPU of
  # everything outside Docker is the better sign of a busy Mac.
  others=$(ps -A -o %cpu=,comm= | awk '!/Virtualization|com\.docker|Docker Desktop/ {s += $1} END {printf "%.0f", s}')
  echo "== round $round, load $(uptime | sed 's/.*averages*: //'), outside Docker ${others}% CPU"
  for c in $CASES; do
    IFS=- read -r cert group _ <<< "$c"
    proto=http1; [[ $c == *-h2* ]] && proto=h2
    mode=full; [[ $c == *-resume ]] && mode=resume
    want_sig=ecdsa_secp256r1_sha256; [ "$cert" = rsa ] && want_sig=rsa_pss_rsae_sha256
    case $group in x25519) want_group=x25519 ;; p256) want_group=secp256r1 ;; mlkem) want_group=x25519_ml_kem768 ;; esac
    want_alpn=http/1.1; [ $proto = h2 ] && want_alpn=h2
    for w in $WORKERS; do
      cpus=0-5; [ "$w" = 1 ] && cpus=0
      conns=$(per_workers "$CONNS" "$w"); every=$(per_workers "$VERIFY" "$w")
      for s in $servers; do
        if ! supported "$s" "$c"; then printf "%-16s %2s %-20s %7s\n" "$s" "$w" "$c" "n/a"; continue; fi
        spec=$(server "$s" "$w" "$cert")
        docker run -d --name tlsb-srv-$TAG --cpuset-cpus $cpus --ulimit nofile=65536:65536 \
          --security-opt seccomp="$SECCOMP" -v "$BIN":/b -v "$ROOT/bench":/bench:ro "${spec%%|*}" sh -c "${spec#*|}" >/dev/null || exit 1
        sleep 1.5
        # -t: line-buffered output, so the phase markers arrive as they happen.
        docker run -d -t --name tlsb-cli-$TAG --cpuset-cpus 6-11 --network container:tlsb-srv-$TAG -v "$BIN":/b peregrine-bench:latest \
          timeout $((DUR + 30)) /b/tls-load 127.0.0.1 8443 6 "$conns" "$DUR" "$group" "$proto" "$mode" 2 "$cert" "$every" >/dev/null || exit 1
        t0= t1= w0= w1=
        while IFS= read -r line; do
          case $line in
          measuring*) [ -z "$t0" ] && { t0=$(cgroup_usec tlsb-srv-$TAG); w0=$(now); } ;;
          measured*) [ -z "$t1" ] && { t1=$(cgroup_usec tlsb-srv-$TAG); w1=$(now); } ;;
          esac
        done < <(docker logs -f tlsb-cli-$TAG 2>&1)
        rc=$(docker wait tlsb-cli-$TAG); out=$(docker logs tlsb-cli-$TAG 2>&1 | tr -d '\r'); docker rm tlsb-cli-$TAG >/dev/null
        # A failed `docker exec` is not a dead server: ask Docker, and keep a
        # dead one (tlsb-dead-*) with its log for a look.
        state=$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' tlsb-srv-$TAG 2>&1)
        if [ "${state%% *}" != running ]; then
          dead=tlsb-dead-$TAG-$s-$w-$c-$round
          echo "$s $w $c: FAILED: SERVER DIED ($state), kept as $dead"; failures=$((failures + 1))
          echo "$out" | tail -6; docker logs --tail 30 tlsb-srv-$TAG 2>&1
          docker rename tlsb-srv-$TAG "$dead"; continue
        fi
        docker stop -t 1 tlsb-srv-$TAG >/dev/null; docker rm tlsb-srv-$TAG >/dev/null
        # N conns, GROUP, PROTO, MODE: N handshakes in S s, R /s, N resumed, N signatures verified, T tickets each, N errors
        read -r n rate resumed verified tickets errors <<< "$(echo "$out" | sed -n 's/.*: \([0-9]*\) handshakes in [0-9.]* s, \([0-9]*\) \/s, \([0-9]*\) resumed, \([0-9]*\) signatures verified, \([0-9.]*\) tickets each, \([0-9]*\) errors.*/\1 \2 \3 \4 \5 \6/p')"
        # negotiated: TLSv1.3 SUITE GROUP SIG alpn ALPN certificate N B full|resumed
        full=$(echo "$out" | sed -n 's/^negotiated: \(.*\) certificate \([0-9]*\) B full$/\1|\2/p' | head -1)
        res=$(echo "$out" | sed -n 's/^negotiated: \(.*\) certificate 0 B resumed$/\1/p' | head -1)
        bad=
        [ "$rc" = 0 ] || bad+=" exit $rc"
        [ -n "$n" ] && [ "$n" != 0 ] || bad+=" no handshakes"
        [ "${errors:-1}" = 0 ] || bad+=" ${errors:-?} errors ($(echo "$out" | sed -n 's/^first error: //p' | head -1))"
        if [ -z "$t0" ] || [ -z "$t1" ]; then bad+=" no main-phase CPU reading"
        elif [ "$(echo "($w1 - $w0) < $DUR * 0.9" | bc)" = 1 ]; then bad+=" main phase read over $(echo "$w1 - $w0" | bc) s"; fi
        want="TLSv1.3 AES_128_GCM_SHA256 $want_group $want_sig alpn $want_alpn"
        [ "${full%|*}" = "$want" ] || bad+=" negotiated: ${full%|*} (want $want)"
        if [ $mode = full ]; then
          [ "${resumed:-1}" = 0 ] || bad+=" ${resumed:-?} resumed"
          if [ "$every" = 1 ]; then [ "${verified:-0}" = "$n" ] || bad+=" ${verified:-0} of $n signatures verified"
          elif [ -n "$n" ] && [ "$(echo "${verified:-0} * $every * 2 < $n" | bc)" = 1 ]; then bad+=" ${verified:-0} of $n signatures verified (1 in $every)"; fi
        else
          [ "$res" = "TLSv1.3 AES_128_GCM_SHA256 $want_group psk alpn $want_alpn" ] || bad+=" resumed: ${res:-none} (want $want_group psk $want_alpn)"
          [ -n "$n" ] && [ "$(echo "${resumed:-0} < $n * 0.99" | bc)" = 0 ] || bad+=" only ${resumed:-0} of $n resumed"
        fi
        if [ -n "$bad" ]; then echo "$s $w $c: FAILED:$bad"; echo "$out" | tail -4; failures=$((failures + 1)); continue; fi
        cores=$(echo "scale=2; ($t1 - $t0) / (($w1 - $w0) * 1000000)" | bc)
        client=$(echo "$out" | sed -n 's/^client: \([0-9.]*\) cores/\1/p')
        mark=
        [ "$(echo "$cores < 0.9 * $w" | bc)" = 1 ] && mark+="<"
        [ "$(echo "$client > 5.4" | bc)" = 1 ] && mark+="!"
        printf "%-16s %2s %-20s %7s %6s %6s µs %6s %8s %7s %5s  %s %s\n" "$s" "$w" "$c" "$rate" "$cores" \
          "$(echo "scale=1; ($t1 - $t0) / $n" | bc)" "$client" "$([ $mode = full ] && echo "$verified" || echo -)" "$tickets" \
          "${full#*|}" "$want_group $([ $mode = full ] && echo "$want_sig" || echo psk) $want_alpn" "$mark"
      done
    done
  done
done
[ "$failures" = 0 ] || { echo "$failures runs FAILED"; exit 1; }
