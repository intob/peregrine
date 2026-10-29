#!/bin/bash
# Two Raspberry Pi 5s (4 Cortex-A76 cores, 8 GB) on one gigabit LAN, over
# WireGuard: pi5-wg (10.252.1.125 on the LAN; Linux 6.18 with kTLS) serves,
# pi1-wg (10.252.1.70; Linux 6.12; wrk, h2load, ws-load) loads it: the
# separate-machines benchmark. Both have ~/peregrine-work/zig (0.17). They
# are the user's machines with other jobs (pi1 runs PostgreSQL): use them
# when idle, clean up, `nice` long runs.
# Usage:
#   pi.sh lock / pi.sh unlock        hold both Pis for a benchmark (waits for fuzz runs)
#   pi.sh build                      bench-server and ws-load for the A76, copied to both
#   pi.sh serve "6 epoll 8080 plain" start bench-server on pi5 (args as bench-server's)
#   pi.sh load CMD...                run a load command on pi1, e.g.
#                                    pi.sh load wrk -t4 -c256 -d10s http://10.252.1.125:8080/
#                                    pi.sh load ./ws-load 10.252.1.125 8080 4 256 1 20 10
#   pi.sh cpu                        CPU seconds the server has used (diff around a run)
#   pi.sh stop                       stop the server
source "$(dirname "$0")/env.sh"
SERVER=pi5-wg; CLIENT=pi1-wg
case $1 in
lock) "$LOCK" acquire pi1 "pi bench ($ROOT)" && "$LOCK" acquire pi5 "pi bench ($ROOT)" ;;
unlock) "$LOCK" release pi5; "$LOCK" release pi1 ;;
build)
    (cd "$ROOT" && "$ZIG" build bench-server ws-load -Dtarget=aarch64-linux-musl -Dcpu=cortex_a76 -p "$OUT/pi") >&2 || exit 1
    for h in $SERVER $CLIENT; do scp -q "$OUT/pi/bin/bench-server" "$OUT/pi/bin/ws-load" "$h:peregrine-work/"; done ;;
serve)
    ssh $SERVER "cd ~/peregrine-work && pkill -INT -x bench-server; sleep 0.5; (nohup ./bench-server $2 > server.log 2>&1 &); sleep 1; cat server.log" ;;
load)
    shift; ssh $CLIENT "cd ~/peregrine-work && $*" ;;
cpu)
    ssh $SERVER 'p=$(pgrep -x bench-server) && awk -v t=$(getconf CLK_TCK) "{print (\$14 + \$15) / t}" /proc/$p/stat' ;;
stop)
    ssh $SERVER "pkill -INT -x bench-server; true" ;;
*) sed -n '2,21p' "$0"; exit 1 ;;
esac
