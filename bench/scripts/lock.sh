#!/bin/bash
# Locks shared by every session and agent on this Mac (worktrees too), so
# benchmarks get the machine to themselves:
#   mac-bench  the Mac's 12 cores: a benchmark holds it exclusively (acquire;
#              ws-bench.sh also waits for other peregrine containers); test,
#              Autobahn and local fuzz jobs share it (share), so they run side
#              by side but never next to a benchmark
#   pi1, pi5   a Pi (fuzz.sh on a Pi takes it; a two-machine benchmark takes
#              both: pi.sh lock / pi.sh unlock)
# Callers queue in arrival order: a benchmark that releases and acquires again
# goes behind the jobs already waiting to share, and a share that arrives
# after an acquire waits for that benchmark, so neither side starves.
# Usage: lock.sh acquire NAME [what] | release NAME   exclusive
#        lock.sh share NAME [what] | unshare NAME     shared, until unshare or until the calling script exits
#        lock.sh wait NAME                            wait for a turn to share, hold nothing
#        lock.sh list
# An exclusive lock older than 3 hours is stale: `list` shows ages; release it by hand.
LOCKS=${PEREGRINE_LOCKS:-/tmp/peregrine-locks}
mkdir -p "$LOCKS"

# A process that is gone leaves its tickets and shares behind; if ps can't see
# even this process (a sandbox), everything counts as alive.
alive() { ps -p "$1" >/dev/null 2>&1 || ! ps -p $$ >/dev/null 2>&1; }

prune() {
    local f
    for f in "$LOCKS/$1.q"/* "$LOCKS/$1.s"/*; do
        [ -f "$f" ] && ! alive "$(sed -n 1p "$f")" && rm -f "$f"
    done
}

# Waits for this caller's turn. A ticket (pid, mode, what) is named by arrival
# time, so the directory listing is the queue. Exclusive (x) goes once nothing
# is held and no ticket is older; shared (s) once no exclusive lock is held
# and no exclusive ticket is older. The lock or the share is taken before the
# ticket goes, so a later caller never slips in between.
queue() {
    local name=$1 mode=$2 q=$LOCKS/$1.q t older
    mkdir -p "$q" "$LOCKS/$name.s"
    me=$q/$(perl -MTime::HiRes=time -e 'printf "%.6f", time' 2>/dev/null || date +%s)-$$
    printf '%s\n%s\n%s\n' $$ "$mode" "$3" > "$me"
    trap 'rm -f "$me"' EXIT
    trap 'exit 1' INT TERM HUP
    while :; do
        alive $PPID || exit 1
        prune "$name"
        if [ ! -d "$LOCKS/$name" ]; then
            older=false
            for t in "$q"/*; do
                [ "$t" = "$me" ] && break
                [ -f "$t" ] || continue
                if [ "$mode" = x ] || [ "$(sed -n 2p "$t")" = x ]; then older=true; break; fi
            done
            if ! $older; then
                [ "$mode" = s ] && return 0
                [ -z "$(ls -A "$LOCKS/$name.s")" ] && mkdir "$LOCKS/$name" 2>/dev/null && return 0
            fi
        fi
        sleep 2
    done
}

case $1 in
acquire)
    queue "$2" x "${3:-$PWD}"
    echo "${3:-$PWD} since $(date '+%F %T')" > "$LOCKS/$2/owner" ;;
release) rm -rf "${LOCKS:?}/$2" ;;
share)
    queue "$2" s "${3:-$PWD}"
    printf '%s\n%s since %s\n' $PPID "${3:-$PWD}" "$(date '+%F %T')" > "$LOCKS/$2.s/$PPID" ;;
unshare) rm -f "$LOCKS/$2.s/$PPID" ;;
wait) queue "$2" s "wait ${3:-$PWD}" ;;
list)
    for l in "$LOCKS"/*; do
        [ -d "$l" ] || continue
        case $l in
        *.q | *.s) ;;
        *) echo "$(basename "$l"): $(cat "$l/owner" 2>/dev/null)" ;;
        esac
    done
    for f in "$LOCKS"/*.s/*; do [ -f "$f" ] && echo "$(basename "$(dirname "$f")" .s) shared: $(sed -n 2p "$f")"; done
    for f in "$LOCKS"/*.q/*; do [ -f "$f" ] && echo "$(basename "$(dirname "$f")" .q) queued ($(sed -n 2p "$f")): $(sed -n 3p "$f")"; done
    true ;;
*) sed -n '2,17p' "$0"; exit 1 ;;
esac
