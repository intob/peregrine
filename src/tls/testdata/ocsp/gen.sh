#!/bin/bash
# Regenerates the OCSP stapling test data (OpenSSL 3+): a P-256 CA, two
# P-256 leaves it issued (localhost and 127.0.0.1; ocsp.example), OCSP
# responder certificates, and OCSP responses made with `openssl ocsp`.
# Responses are valid for 100 years except short.der (nextUpdate a minute
# after thisUpdate). After regenerating, set `testdata.this_update` in
# ../../ocsp.zig to leaf-good.der's thisUpdate (it is made first; the
# others follow within seconds).
#   ca.pem ca.key                 the CA (self-signed)
#   leaf.pem leaf.key             localhost, serial 0x1001; leaf-chain.pem: leaf, CA
#   sni.pem sni.key               ocsp.example, serial 0x1002; sni-chain.pem: sni, CA
# Signed by the CA (ECDSA P-256, SHA-256 unless said), its certificate
# included:
#   leaf-good.der                 leaf: good (SHA-1 CertID, responder by name)
#   leaf-good-sha256.der          leaf: good (SHA-256 CertID, responder by key hash)
#   leaf-good-ca384.der           leaf: good, signed with SHA-384, no certificates
#   leaf-revoked.der              leaf: revoked
#   leaf-unknown.der              leaf: unknown (not in the responder's index)
#   sni-good.der                  sni: good
#   both-good.der                 sni and leaf, in that order, in one response
#   short.der                     leaf: good, nextUpdate one minute after thisUpdate
# Signed by delegated responders (certificates the CA issued with
# id-kp-OCSPSigning, included in the response), leaf: good:
#   leaf-good-rsa.der             RSA-2048, PKCS#1 v1.5 with SHA-256
#   leaf-good-rsa512.der          RSA-2048, PKCS#1 v1.5 with SHA-512
#   leaf-good-pss.der             RSA-2048, RSA-PSS with SHA-256
#   leaf-good-p384.der            ECDSA P-384 with SHA-384
#   leaf-good-ed25519.der         Ed25519
#   leaf-good-shortlived.der      P-256, a responder certificate valid for a day
# Signed by responders that may not sign for the CA:
#   leaf-good-noeku.der           a certificate the CA issued without id-kp-OCSPSigning
#   leaf-good-rogue.der           a self-signed certificate with id-kp-OCSPSigning
#   leaf-good-forged.der          one with id-kp-OCSPSigning, issued in the CA's name by another key
#   leaf-good-renamed.der         one with id-kp-OCSPSigning, signed with the CA's key in another name
#   leaf-good-nocert.der          a delegated responder that left its certificate out
# Usage: gen.sh (in this directory)
set -e
cd "$(dirname "$0")"
OPENSSL=${OPENSSL:-openssl}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

ec() { $OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:${2:-P-256} -out "$1"; }
ec ca.key
$OPENSSL req -x509 -new -key ca.key -sha256 -days 36500 -subj "/CN=Peregrine OCSP Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
issue() { # name key serial extensions out [days]
    $OPENSSL req -new -key "$2" -subj "/CN=$1" -out "$T/$1.csr"
    printf "$4" > "$T/$1.ext"
    $OPENSSL x509 -req -in "$T/$1.csr" -CA ca.pem -CAkey ca.key -set_serial "$3" -days "${6:-36500}" -sha256 -extfile "$T/$1.ext" -out "$5"
}
leaf_ext='basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n'
ec leaf.key
issue localhost leaf.key 0x1001 "$(printf "$leaf_ext" "DNS:localhost,IP:127.0.0.1")" leaf.pem
ec sni.key
issue ocsp.example sni.key 0x1002 "$(printf "$leaf_ext" "DNS:ocsp.example")" sni.pem
cat leaf.pem ca.pem > leaf-chain.pem
cat sni.pem ca.pem > sni-chain.pem

# Responder certificates (kept in $T: only the responses are test data).
resp_ext='basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=OCSPSigning\n'
$OPENSSL genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/rsa.key"
issue "OCSP RSA" "$T/rsa.key" 0x2001 "$resp_ext" "$T/rsa.pem"
ec "$T/p384.key" P-384
issue "OCSP P-384" "$T/p384.key" 0x2002 "$resp_ext" "$T/p384.pem"
$OPENSSL genpkey -algorithm ED25519 -out "$T/ed25519.key"
issue "OCSP Ed25519" "$T/ed25519.key" 0x2003 "$resp_ext" "$T/ed25519.pem"
ec "$T/short.key"
issue "OCSP short-lived" "$T/short.key" 0x2004 "$resp_ext" "$T/short.pem" 1
ec "$T/noeku.key"
issue "OCSP no EKU" "$T/noeku.key" 0x2005 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n' "$T/noeku.pem"
ec "$T/rogue.key"
$OPENSSL req -x509 -new -key "$T/rogue.key" -sha256 -days 36500 -subj "/CN=Peregrine OCSP Test CA" \
    -addext "extendedKeyUsage=OCSPSigning" -out "$T/rogue.pem"

ec "$T/fakeca.key"
$OPENSSL req -x509 -new -key "$T/fakeca.key" -sha256 -days 36500 -subj "/CN=Peregrine OCSP Test CA" -out "$T/fakeca.pem"
ec "$T/forged.key"
$OPENSSL req -new -key "$T/forged.key" -subj "/CN=OCSP forged" -out "$T/forged.csr"
printf "$resp_ext" > "$T/forged.ext"
$OPENSSL x509 -req -in "$T/forged.csr" -CA "$T/fakeca.pem" -CAkey "$T/fakeca.key" -set_serial 0x2006 -days 36500 -sha256 -extfile "$T/forged.ext" -out "$T/forged.pem"
$OPENSSL req -x509 -new -key ca.key -sha256 -days 36500 -subj "/CN=Another Name" -out "$T/renamedca.pem"
ec "$T/renamed.key"
$OPENSSL req -new -key "$T/renamed.key" -subj "/CN=OCSP renamed" -out "$T/renamed.csr"
$OPENSSL x509 -req -in "$T/renamed.csr" -CA "$T/renamedca.pem" -CAkey ca.key -set_serial 0x2007 -days 36500 -sha256 -extfile "$T/forged.ext" -out "$T/renamed.pem"

# The responder's index (ca(1) format): leaf and sni valid; a revoked copy;
# an empty one (every certificate unknown).
exp=$($OPENSSL x509 -in leaf.pem -noout -enddate -dateopt iso_8601 | cut -d= -f2 | tr -d ' :-')
exp=${exp:0:14}Z
printf 'V\t%s\t\t1001\tunknown\t/CN=localhost\nV\t%s\t\t1002\tunknown\t/CN=ocsp.example\n' "$exp" "$exp" > "$T/index.txt"
printf 'R\t%s\t261001000000Z,keyCompromise\t1001\tunknown\t/CN=localhost\n' "$exp" > "$T/revoked.txt"
: > "$T/empty.txt"

respond() { # out index "validity and signing options" request-args...
    local out=$1 index=$2 opts=$3
    shift 3
    $OPENSSL ocsp -issuer ca.pem "$@" -no_nonce -reqout "$T/req.der" >/dev/null
    $OPENSSL ocsp -index "$index" -CA ca.pem -reqin "$T/req.der" $opts -respout "$out" >/dev/null
}
CA="-rsigner ca.pem -rkey ca.key -ndays 36500"
respond leaf-good.der "$T/index.txt" "$CA" -cert leaf.pem
respond leaf-revoked.der "$T/revoked.txt" "$CA" -cert leaf.pem
respond leaf-unknown.der "$T/empty.txt" "$CA" -cert leaf.pem
respond sni-good.der "$T/index.txt" "$CA" -cert sni.pem
respond both-good.der "$T/index.txt" "$CA" -cert sni.pem -cert leaf.pem
respond short.der "$T/index.txt" "-rsigner ca.pem -rkey ca.key -nmin 1" -cert leaf.pem
respond leaf-good-sha256.der "$T/index.txt" "$CA -resp_key_id" -sha256 -cert leaf.pem
respond leaf-good-ca384.der "$T/index.txt" "$CA -rmd sha384 -resp_no_certs" -cert leaf.pem
D="-ndays 36500"
respond leaf-good-rsa.der "$T/index.txt" "-rsigner $T/rsa.pem -rkey $T/rsa.key $D" -cert leaf.pem
respond leaf-good-rsa512.der "$T/index.txt" "-rsigner $T/rsa.pem -rkey $T/rsa.key -rmd sha512 $D" -cert leaf.pem
respond leaf-good-pss.der "$T/index.txt" "-rsigner $T/rsa.pem -rkey $T/rsa.key -rsigopt rsa_padding_mode:pss -rsigopt rsa_pss_saltlen:digest $D" -cert leaf.pem
respond leaf-good-p384.der "$T/index.txt" "-rsigner $T/p384.pem -rkey $T/p384.key -rmd sha384 $D" -cert leaf.pem
respond leaf-good-ed25519.der "$T/index.txt" "-rsigner $T/ed25519.pem -rkey $T/ed25519.key $D" -cert leaf.pem
respond leaf-good-shortlived.der "$T/index.txt" "-rsigner $T/short.pem -rkey $T/short.key $D" -cert leaf.pem
respond leaf-good-noeku.der "$T/index.txt" "-rsigner $T/noeku.pem -rkey $T/noeku.key $D" -cert leaf.pem
respond leaf-good-rogue.der "$T/index.txt" "-rsigner $T/rogue.pem -rkey $T/rogue.key $D" -cert leaf.pem
respond leaf-good-forged.der "$T/index.txt" "-rsigner $T/forged.pem -rkey $T/forged.key $D" -cert leaf.pem
respond leaf-good-renamed.der "$T/index.txt" "-rsigner $T/renamed.pem -rkey $T/renamed.key $D" -cert leaf.pem
respond leaf-good-nocert.der "$T/index.txt" "-rsigner $T/rsa.pem -rkey $T/rsa.key -resp_no_certs $D" -cert leaf.pem

