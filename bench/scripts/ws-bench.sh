#!/bin/bash
# WebSocket echo benchmark in Docker on the Mac: the server on CPUs 0-5,
# ws-load (6 threads) on 6-11 in its network namespace; server CPU per
# message from its cgroup. Needs the 12 cores to itself: check `uptime`,
# run nothing else, interleave rounds when comparing.
# Usage: ws-bench.sh LABEL IMAGE "SERVER CMD" "name|conns depth size [binary|text] [deflate]"...
# Peregrine: IMAGE peregrine-bench, CMD "/b/bench-server 6 epoll 8080 plain [deflate]"
# (binaries from build_linux_bins at /b). uWebSockets: comp-uws-ws "uws-ws-echo 6",
# comp-uws-ws-deflate "uws-ws-echo-deflate 6". DUR=seconds (default 8).
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
label=$1; img=$2; cmd=$3; shift 3
DUR=${DUR:-8}
# The machine to itself: wait for other peregrine jobs, hold the lock.
"$LOCK" acquire mac-bench "ws-bench $label ($ROOT)"
trap '"$LOCK" release mac-bench' EXIT
wait_for_jobs
docker run --rm -d --name wsb-srv-$TAG --cpuset-cpus 0-5 --ulimit nofile=65536:65536 \
  --security-opt seccomp="$SECCOMP" -v "$BIN":/b "$img" sh -c "$cmd" >/dev/null || exit 1
sleep 1.5
docker run --rm --cpuset-cpus 6-11 --network container:wsb-srv-$TAG -v "$BIN":/b peregrine-bench:latest \
  /b/ws-load 127.0.0.1 8080 2 8 4 20 1 >/dev/null 2>&1
for spec in "$@"; do
  name=${spec%%|*}; read -r -a args <<< "${spec#*|}"
  t0=$(docker exec wsb-srv-$TAG awk '/usage_usec/ {print $2}' /sys/fs/cgroup/cpu.stat)
  out=$(docker run --rm --cpuset-cpus 6-11 --network container:wsb-srv-$TAG -v "$BIN":/b peregrine-bench:latest \
    /b/ws-load 127.0.0.1 8080 6 "${args[0]}" "${args[1]}" "${args[2]}" "$DUR" "${args[3]:-binary}" /ws ${args[4]:-} 2>&1)
  rc=$?
  t1=$(docker exec wsb-srv-$TAG awk '/usage_usec/ {print $2}' /sys/fs/cgroup/cpu.stat)
  read -r msgs secs rate <<< "$(echo "$out" | sed -n 's/.*: \([0-9]*\) messages in \([0-9.]*\) s, \([0-9]*\) msg\/s.*/\1 \2 \3/p')"
  if [ $rc != 0 ] || [ -z "$msgs" ] || [ "$msgs" = 0 ]; then echo "$label $name: FAILED"; echo "$out" | tail -5; continue; fi
  printf "%-18s %-14s %10s msg/s  %5s cores  %6s ns/msg\n" "$label" "$name" "$rate" \
    "$(echo "scale=2; ($t1 - $t0) / ($secs * 1000000)" | bc)" "$(echo "scale=0; ($t1 - $t0) * 1000 / $msgs" | bc)"
done
docker stop -t 1 wsb-srv-$TAG >/dev/null
