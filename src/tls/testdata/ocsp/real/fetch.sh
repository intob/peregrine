#!/bin/bash
# How the files here were made (2026-10-31): for each host, fetch.sh HOST saves
# the chain it serves and its CA responder's answer for the leaf in
# $SCRATCH/real/HOST; then `python3 mkreal.py $SCRATCH/real .` writes
# NAME.chain.der and NAME.ocsp.der and prints the list for ocsp.zig.
h=$1; d=${SCRATCH:?}/real/$h; mkdir -p $d; cd $d
echo | timeout 15 openssl s_client -connect $h:443 -servername $h -status -showcerts > sc.txt 2>/dev/null
awk '/-----BEGIN CERTIFICATE-----/{n++} n>0{print > ("c" n ".pem")} /-----END CERTIFICATE-----/{}' sc.txt
[ -f c1.pem ] || { echo "$h: no certs"; exit 1; }
url=$(openssl x509 -in c1.pem -noout -ocsp_uri 2>/dev/null | head -1)
date -u +%s > time
if [ -n "$url" ] && [ -f c2.pem ]; then
  timeout 15 openssl ocsp -issuer c2.pem -cert c1.pem -url "$url" -no_nonce -respout resp.der -noverify > ocsp.txt 2>&1
fi
echo "$h url=$url $(ls c*.pem | wc -l) certs, resp=$(stat -f %z resp.der 2>/dev/null)"
