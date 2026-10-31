#!/bin/bash
# TLS 1.3 handshake benchmark on the two Pis (see pi.sh): the server on
# pi5, tls-load (4 threads) on pi1 over the LAN. New connections per
# second, each a full handshake and one HTTP/1.1 request, and the server's
# CPU time per handshake: the CPU seconds of every process of the server
# (/proc/PID/stat utime + stime, so nginx's workers count) read when
# tls-load prints "measuring" and "measured", over the wall time between.
# A fresh server for every run; within a round the servers alternate
# (the peregrine builds' order reversed every other round), then the
# competitors.
# Usage: pi-tls-bench.sh [SERVER...]
#   SERVER: this (the working tree), base (BASE, a git ref, built from
#   `git archive`), nginx, h2o. Default: this, base if BASE is set,
#   nginx, h2o.
#   BACKENDS ("epoll io_uring") for peregrine, WORKERS ("1 4"), ROUNDS (3),
#   DUR seconds per run (10), CERT (rsa: bench/rsa.pem, RSA-2048; or
#   ecdsa: bench/cert.pem, P-256), GROUP (x25519, p256, mlkem),
#   CONNS in flight per worker count ("1:48 4:192"), VERIFY 1 in N
#   signatures (1: all; RSA verification is cheap), BUILD=0 reuses the
#   binaries already on the Pis.
# Competitors on pi5 (installed by hand, 2026-10-31; their system services
# disabled): nginx 1.26.3 from apt (/usr/sbin/nginx, OpenSSL 3.5) and h2o
# 2.3.0-DEV built in ~/peregrine-work/h2o-src (H2O, neverbleed off, a static
# file). Configs are written into ~/peregrine-work/tlsb on each run: TLS 1.3
# only, the same certificate, one session ticket, no access log, workers
# pinned one per CPU. peregrine runs `bench-server W BACKEND 8443 tls
# noktls [rsa]`. Everything runs under `nice -n 5`.
# Holds both Pis (pi.sh lock), waits until neither Pi runs a fuzz job or a
# test binary and pi5's load is below 1, and marks a run VOID if one shows
# up during it. A run FAILS on a tls-load error, a connection error, a
# handshake that isn't the case's (TLS 1.3, AES_128_GCM, the group, the
# certificate's scheme), an unverified signature, or a CPU reading window
# more than 10% off DUR. Leaves nothing running.
source "$(dirname "$0")/env.sh"
SERVER=pi5-wg; CLIENT=pi1-wg; IP=10.252.1.125; W=peregrine-work/tlsb
BACKENDS=${BACKENDS:-epoll io_uring}; WORKERS=${WORKERS:-1 4}; ROUNDS=${ROUNDS:-3}; DUR=${DUR:-10}
CERT=${CERT:-rsa}; GROUP=${GROUP:-x25519}; CONNS=${CONNS:-1:48 4:192}; VERIFY=${VERIFY:-1}
H2O=${H2O:-/home/joey/peregrine-work/h2o-src/build/h2o}
servers=${*:-this ${BASE:+base} nginx h2o}
for s in $servers; do case $s in this | base | nginx | h2o) ;; *) sed -n '2,33p' "$0"; exit 1 ;; esac; done
[[ " $servers " == *" base "* ]] && [ -z "$BASE" ] && { echo "base needs BASE=REF"; exit 1; }
case $CERT in rsa) pem=rsa.pem key=rsa.key sig=rsa_pss_rsae_sha256 rsa=rsa ;; ecdsa) pem=cert.pem key=key.pem sig=ecdsa_secp256r1_sha256 rsa= ;; *) echo "CERT: rsa or ecdsa"; exit 1 ;; esac
case $GROUP in x25519) want_group=x25519 ;; p256) want_group=secp256r1 ;; mlkem) want_group=x25519_ml_kem768 ;; *) echo "GROUP: x25519, p256 or mlkem"; exit 1 ;; esac
CM="-o ControlMaster=auto -o ControlPath=$HOME/.ssh/cm-pitls-%C -o ControlPersist=120"
on() { local h=$1; shift; ssh $CM "$h" "$@"; }

"$LOCK" acquire pi1 "pi-tls-bench ($ROOT)" || exit 1
"$LOCK" acquire pi5 "pi-tls-bench ($ROOT)" || { "$LOCK" release pi1; exit 1; }
stop_all="pkill -INT -x bench-server; pkill -TERM -x h2o; pkill -QUIT -x nginx; sleep 0.5; true"
cleanup() {
    on $SERVER "$stop_all" 2>/dev/null; on $CLIENT 'pkill -x tls-load; true' 2>/dev/null
    ssh $CM -O exit $SERVER 2>/dev/null; ssh $CM -O exit $CLIENT 2>/dev/null
    "$LOCK" release pi5; "$LOCK" release pi1
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

if [ "${BUILD:-1}" != 0 ]; then
    # this and base for the Cortex-A76; tls-load from this tree for every server.
    build() { # DIR LABEL
        (cd "$1" && "$LOCK" share mac-bench "pi-tls-bench build ($ROOT)" &&
            "$ZIG" build bench-server tls-load -Dtarget=aarch64-linux-musl -Dcpu=cortex_a76 -p "$OUT/pi-tls/$2") >&2
    }
    build "$ROOT" this || exit 1
    if [ -n "$BASE" ]; then
        src=$OUT/pi-tls/base-src; rm -rf "$src"; mkdir -p "$src"
        git -C "$ROOT" archive "$BASE" | tar -x -C "$src" || exit 1
        echo "base: $BASE = $(git -C "$ROOT" rev-parse --short "$BASE")"
        build "$src" base || exit 1
    fi
    for h in $SERVER $CLIENT; do on $h "mkdir -p $W/this $W/base $W/ngx-tmp" || exit 1; done
    scp -q -o ControlPath="$HOME/.ssh/cm-pitls-%C" "$OUT/pi-tls/this/bin/tls-load" $CLIENT:$W/ || exit 1
    scp -q -o ControlPath="$HOME/.ssh/cm-pitls-%C" "$OUT/pi-tls/this/bin/bench-server" $SERVER:$W/this/ || exit 1
    [ -n "$BASE" ] && { scp -q -o ControlPath="$HOME/.ssh/cm-pitls-%C" "$OUT/pi-tls/base/bin/bench-server" $SERVER:$W/base/ || exit 1; }
fi
scp -q -o ControlPath="$HOME/.ssh/cm-pitls-%C" "$ROOT/bench/$pem" "$ROOT/bench/$key" $SERVER:$W/ || exit 1
on $SERVER "printf 'Hello, World!' > $W/hello.txt"

# Competitor configs for W workers on stdout.
nginx_conf() {
    cat <<EOF
worker_processes $1;
worker_cpu_affinity auto;
daemon off;
pid /home/joey/$W/nginx.pid;
error_log /home/joey/$W/nginx-error.log error;
events { worker_connections 4096; }
http {
    access_log off;
    client_body_temp_path /home/joey/$W/ngx-tmp/body;
    proxy_temp_path /home/joey/$W/ngx-tmp/proxy;
    fastcgi_temp_path /home/joey/$W/ngx-tmp/fastcgi;
    uwsgi_temp_path /home/joey/$W/ngx-tmp/uwsgi;
    scgi_temp_path /home/joey/$W/ngx-tmp/scgi;
    default_type text/plain;
    server_tokens off;
    server {
        listen 8443 ssl reuseport;
        ssl_certificate /home/joey/$W/$pem;
        ssl_certificate_key /home/joey/$W/$key;
        ssl_protocols TLSv1.3;
        ssl_conf_command NumTickets 1;
        location = / { return 200 "Hello, World!"; }
    }
}
EOF
}
h2o_conf() {
    cat <<EOF
num-threads: [$(awk -v n=$1 'BEGIN {for (i = 0; i < n; i++) printf "%s%d", (i ? ", " : ""), i}')]
tcp-reuseport: ON
send-server-name: OFF
error-log: /home/joey/$W/h2o-error.log
pid-file: /home/joey/$W/h2o.pid
listen:
  port: 8443
  ssl:
    certificate-file: /home/joey/$W/$pem
    key-file: /home/joey/$W/$key
    minimum-version: TLSv1.3
    neverbleed: OFF
file.etag: OFF
hosts:
  default:
    paths:
      /:
        file.file: /home/joey/$W/hello.txt
    file.mime.addtypes:
      text/plain: .txt
EOF
}
for w in $WORKERS; do
    nginx_conf $w | on $SERVER "cat > $W/nginx-$w.conf"
    h2o_conf $w | on $SERVER "cat > $W/h2o-$w.conf"
done

now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
# CPU seconds of every process named $1 on pi5.
cpu() { on $SERVER "t=\$(getconf CLK_TCK); for p in \$(pgrep -x $1); do cat /proc/\$p/stat; done | awk -v t=\$t '{s += \$14 + \$15} END {print s / t}'"; }
# A fuzz job or a test binary on either Pi (another agent's, started without the lock).
busy() {
    local a b
    a=$(on $SERVER 'pgrep -fa -- "--fuzz|/tests( |$)|zig (test|build)" | grep -v pgrep | head -2')
    b=$(on $CLIENT 'pgrep -fa -- "--fuzz|/tests( |$)|zig (test|build)" | grep -v pgrep | head -2')
    [ -n "$a$b" ] && { echo "busy: pi5 [$a] pi1 [$b]" | cut -c1-200; return 0; }
    return 1
}
wait_quiet() {
    local i l
    for i in $(seq 360); do
        if ! busy >/dev/null; then
            l=$(on $SERVER "cut -d' ' -f1 /proc/loadavg")
            [ "$(echo "$l < 1.0" | bc)" = 1 ] && return 0
        fi
        sleep 10
    done
    echo "Pis still busy after an hour: $(busy)"; return 1
}
per_workers() { echo "$1" | tr ' ' '\n' | sed -n "s/^$2://p"; }

failures=0
printf "%-5s %-9s %-6s %2s %7s %6s %10s %6s %11s\n" round backend server w hs/s cores CPU/hs client verified
# One run: ROUND BACKEND LABEL WORKERS PROCESS CMD
run() {
    local r=$1 b=$2 v=$3 w=$4 name=$5 cmd=$6 conns c0= c1= w0= w1= line out
    conns=$(per_workers "$CONNS" "$w")
    out=$(on $SERVER "cd $W && $stop_all; (nohup nice -n 5 $cmd > server.log 2>&1 &); sleep 1.5; pgrep -x $name > /dev/null || { echo NOT RUNNING; cat server.log; }")
    if [ -n "$out" ]; then echo "$r $b $v $w FAILED: $out"; failures=$((failures + 1)); return; fi
    out=
    while IFS= read -r line; do
        out+=$line$'\n'
        case $line in
        measuring*) [ -z "$c0" ] && { c0=$(cpu $name); w0=$(now); } ;;
        measured*) [ -z "$c1" ] && { c1=$(cpu $name); w1=$(now); } ;;
        esac
    done < <(on $CLIENT "cd $W && timeout $((DUR + 30)) nice -n 5 ./tls-load $IP 8443 4 $conns $DUR $GROUP http1 full 2 $CERT $VERIFY 2>&1; echo exit \$?")
    alive=$(on $SERVER "pgrep -x $name > /dev/null && echo yes")
    on $SERVER "$stop_all"
    local n secs rate resumed verified tickets errors neg client bad=
    read -r n secs rate resumed verified tickets errors <<< "$(echo "$out" | sed -n 's/.*: \([0-9]*\) handshakes in \([0-9.]*\) s, \([0-9]*\) \/s, \([0-9]*\) resumed, \([0-9]*\) signatures verified, \([0-9.]*\) tickets each, \([0-9]*\) errors.*/\1 \2 \3 \4 \5 \6 \7/p')"
    neg=$(echo "$out" | sed -n 's/^negotiated: //p' | head -1)
    client=$(echo "$out" | sed -n 's/^client: \([0-9.]*\) cores.*/\1/p')
    echo "$out" | grep -q '^exit 0$' || bad+=" tls-load $(echo "$out" | grep '^exit ')"
    [ "$alive" = yes ] || bad+=" server died"
    [ -n "$n" ] && [ "$n" != 0 ] || bad+=" no handshakes"
    [ "${errors:-1}" = 0 ] || bad+=" ${errors:-?} errors ($(echo "$out" | sed -n 's/^first error: //p' | head -1))"
    [ "${resumed:-1}" = 0 ] || bad+=" ${resumed:-?} resumed"
    [ "$VERIFY" != 1 ] || [ "${verified:-0}" = "$n" ] || bad+=" ${verified:-0} of $n signatures verified"
    [[ $neg == "TLSv1.3 AES_128_GCM_SHA256 $want_group $sig alpn http/1.1 "* ]] || bad+=" negotiated: $neg"
    if [ -z "$c0" ] || [ -z "$c1" ]; then bad+=" no CPU reading"
    elif [ "$(echo "($w1 - $w0) < $DUR * 0.9 || ($w1 - $w0) > $DUR * 1.1" | bc)" = 1 ]; then bad+=" CPU read over $(echo "$w1 - $w0" | bc) s"; fi
    if [ -n "$bad" ]; then echo "$r $b $v $w FAILED:$bad"; echo "$out" | tail -4; failures=$((failures + 1)); return; fi
    local cores us
    cores=$(echo "scale=4; ($c1 - $c0) / ($w1 - $w0)" | bc)
    us=$(echo "scale=1; $cores * 1000000 * $secs / $n" | bc)
    printf "%-5s %-9s %-6s %2s %7s %6.2f %7s µs %6s %11s\n" "$r" "$b" "$v" "$w" "$rate" "$cores" "$us" "$client" "$verified/$n"
    busy && echo "VOID: round $r ($v $b $w): a fuzz or test job ran on a Pi"
}
peregrine=$(for s in $servers; do case $s in this | base) echo -n "$s " ;; esac; done)
echo "== $CERT certificate, $GROUP, DUR $DUR s, conns $CONNS, verify 1 in $VERIFY"
for r in $(seq "$ROUNDS"); do
    wait_quiet || exit 1
    echo "== round $r: load pi5 $(on $SERVER uptime | sed 's/.*average: //'), pi1 $(on $CLIENT uptime | sed 's/.*average: //')"
    order=$peregrine; [ $((r % 2)) = 0 ] && order=$(echo $peregrine | awk '{for (i = NF; i > 0; i--) printf "%s ", $i}')
    for w in $WORKERS; do
        for b in $BACKENDS; do
            for v in $order; do run $r $b $v $w bench-server "./$v/bench-server $w $b 8443 tls noktls $rsa"; done
        done
        for s in $servers; do
            case $s in
            nginx) run $r - nginx $w nginx "/usr/sbin/nginx -c /home/joey/$W/nginx-$w.conf" ;;
            h2o) run $r - h2o $w h2o "$H2O -c /home/joey/$W/h2o-$w.conf" ;;
            esac
        done
    done
done
[ "$failures" = 0 ] || { echo "$failures runs FAILED"; exit 1; }
