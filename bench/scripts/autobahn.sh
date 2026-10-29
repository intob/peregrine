#!/bin/bash
# Autobahn testsuite (crossbario/autobahn-testsuite, amd64 under Rosetta)
# against bench-server's /ws echo. Prints the tally and any case that isn't
# OK, NON-STRICT or INFORMATIONAL; reports in $OUT/autobahn/reports-NAME.
# Usage: autobahn.sh BACKEND [plain|tls] ['["*"]' cases] [deflate|deflate-nct]
# Without deflate, cases 12-13 (compression) are excluded. About 3 minutes
# per 300 cases plain, longer over TLS.
source "$(dirname "$0")/env.sh"
BIN=$OUT/linux/bin
B=$1; M=${2:-plain}; CASES=${3:-'["*"]'}; X=${4:-}; N=$B-$M${X:+-$X}
EXCL='["12.*", "13.*"]'; [ -n "$X" ] && EXCL='[]'
scheme=ws; [ "$M" = tls ] && scheme=wss
A=$OUT/autobahn; mkdir -p "$A"; rm -rf "$A/reports-$N"
"$LOCK" share mac-bench "autobahn $N ($ROOT)"
trap '"$LOCK" unshare mac-bench' EXIT
cat > "$A/fc-$N.json" <<J
{ "outdir": "/ab/reports-$N", "servers": [{ "agent": "peregrine-$N", "url": "$scheme://127.0.0.1:8080/ws" }],
  "cases": $CASES, "exclude-cases": $EXCL, "exclude-agent-cases": {} }
J
docker run --rm -d --name ab-srv-$N-$TAG --ulimit nofile=65536:65536 --security-opt seccomp="$SECCOMP" -v "$BIN":/b \
  peregrine-bench /b/bench-server 2 "$B" 8080 "$M" $X >/dev/null || exit 1
sleep 1
# Unbuffered, or the log's progress lines lag far behind the case running.
docker run --rm -e PYTHONUNBUFFERED=1 --name ab-cli-$N-$TAG --platform linux/amd64 --network container:ab-srv-$N-$TAG \
  -v "$A":/ab crossbario/autobahn-testsuite wstest -m fuzzingclient -s /ab/fc-$N.json > "$A/run-$N.log" 2>&1
docker stop -t 1 ab-srv-$N-$TAG >/dev/null
python3 - "$A/reports-$N/index.json" <<'P'
import json, sys, collections
for agent, cases in json.load(open(sys.argv[1])).items():
    b = collections.Counter(v["behavior"] for v in cases.values()); c = collections.Counter(v["behaviorClose"] for v in cases.values())
    print(agent, len(cases), "cases; behavior", dict(b), "close", dict(c))
    for k, v in sorted(cases.items()):
        if v["behavior"] not in ("OK", "NON-STRICT", "INFORMATIONAL") or v["behaviorClose"] not in ("OK", "INFORMATIONAL"):
            print("  ", k, v["behavior"], v["behaviorClose"])
P
