#!/bin/bash
# Locks shared by every session and agent on this Mac (worktrees too), so
# benchmarks get the machine to themselves:
#   mac-bench  a benchmark on the Mac's 12 cores (ws-bench.sh takes it after
#              waiting for other peregrine containers to finish; Docker test,
#              Autobahn and fuzz jobs wait while it is held)
#   pi1, pi5   a Pi (fuzz.sh on a Pi takes it; a two-machine benchmark takes
#              both: pi.sh lock / pi.sh unlock)
# Usage: lock.sh acquire NAME [what] | release NAME | wait NAME | list
# A lock older than 3 hours is stale: `list` shows ages; release it by hand.
LOCKS=/tmp/peregrine-locks
mkdir -p "$LOCKS"
case $1 in
acquire)
    until mkdir "$LOCKS/$2" 2>/dev/null; do sleep 10; done
    echo "${3:-$PWD} since $(date '+%F %T')" > "$LOCKS/$2/owner" ;;
release) rm -rf "${LOCKS:?}/$2" ;;
wait) while [ -d "$LOCKS/$2" ]; do sleep 10; done ;;
list) for l in "$LOCKS"/*; do [ -d "$l" ] && echo "$(basename "$l"): $(cat "$l/owner" 2>/dev/null)"; done; true ;;
*) sed -n '2,11p' "$0"; exit 1 ;;
esac
