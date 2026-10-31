#!/usr/bin/env python3
# Adversarial OCSP responses for ocsp.zig's third verifier round, built as
# ../verify/gen.py builds its own (its der.py; leaf-good.der's times):
# responder certificates as CAs issue them (OCSP No Check, policies, AIA,
# key identifiers), names encoded differently but equal by RFC 5280's
# comparison, BER booleans, extensions past the sixteenth, and revocations
# from responders that may not sign. Each file is NAME.der; then it prints
# what `openssl ocsp -verify_other leaf,CA -CAfile ca.pem -attime` says
# about each, a minute after thisUpdate. Responder keys are made fresh in a
# temporary directory, so every run makes different bytes.
# Usage: gen.py (OpenSSL 3.4+; OPENSSL=path to choose one)
import os, sys, tempfile
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'verify'))
os.environ['BASE_T'] = '1793471106'  # testdata.this_update
from der import *

T = tempfile.mkdtemp()
P = os.path.join(HERE, '..') + '/'
BASE = int(os.environ['BASE_T'])
NOW = BASE + 60
ca = Cert(pem2der(P + 'ca.pem')[0])
leaf = Cert(pem2der(P + 'leaf.pem')[0])
B = base_parts()
REV = base_parts(P + 'leaf-revoked.der')
UNK = base_parts(P + 'leaf-unknown.der')
cases = {}
leaf_for = {}  # case -> leaf DER, when not leaf.pem

def key(name, *opts):
    path = os.path.join(T, name + '.key')
    run('genpkey', *opts, '-out', path)
    return path
K = {
    'ec': key('ec', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'),
    'rogue': key('rogue', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'),
    'ca': P + 'ca.key',
}

def resp_cert(k, exts=None, cn='Verify Responder', issuer_name=None, **kw):
    if exts is None: exts = [eku(EKU_OCSP)]
    return make_cert(issuer_name or ca.subject, name_cn(cn), spki_of(K[k]), K['ca'], exts=exts, **kw)

def deleg(name, k, cert_der, by='name', certs=None, responses=None, rid=None):
    c = Cert(cert_der)
    r = rid or (c.by_name() if by == 'name' else c.by_key())
    tbs = tbs_data(r, B['produced'], responses or B['responses'])
    cases[name] = response(tbs, ALG['ecdsa-sha256'], sign(K[k], tbs), certs=[cert_der] if certs is None else certs)

def issuer(name, responses=None, rid=None, certs=None):
    deleg(name, 'ca', ca.der, responses=responses, rid=rid, certs=certs)

def name_printable(cn):
    return seq(enc(0x31, seq(oid('2.5.4.3'), enc(0x13, cn.encode()))))

# Extensions as CAs write them.
def ski(k): return ext('2.5.29.14', enc(0x04, hashlib.sha1(Cert(resp_cert(k, [])).key_bits).digest()))
AKI = ext('2.5.29.35', seq(enc(0x80, hashlib.sha1(ca.key_bits).digest())))
NOCHECK = ext('1.3.6.1.5.5.7.48.1.5', NULL)
POLICIES = ext('2.5.29.32', seq(seq(oid('2.23.140.1.2.1')), seq(oid('1.3.6.1.4.1.99999.1'), seq(seq(oid('1.3.6.1.5.5.7.2.1'), enc(0x16, b'http://cps.example/'))))))
CRLDP = ext('2.5.29.31', seq(seq(enc(0xa0, enc(0xa0, enc(0x86, b'http://crl.example/ca.crl'))))))
AIA = ext('1.3.6.1.5.5.7.1.1', seq(seq(oid('1.3.6.1.5.5.7.48.2'), enc(0x86, b'http://ca.example/ca.der'))))
BC_EE = ext('2.5.29.19', seq(), critical=True)
KU_DS = ku(0x80, 7)
SAN = lambda crit=False: ext('2.5.29.17', seq(enc(0x82, b'ocsp.example')), critical=crit)
NC = ext('2.5.29.30', seq(enc(0xa0, seq(enc(0x82, b'example'))))), 

real_exts = [BC_EE, KU_DS, eku(EKU_OCSP), ski('ec'), AKI, NOCHECK, POLICIES, CRLDP, AIA]
deleg('deleg-like-a-ca-issues', 'ec', resp_cert('ec', real_exts))
deleg('deleg-like-a-ca-issues-bykey', 'ec', resp_cert('ec', real_exts), by='key')
deleg('deleg-nocheck-critical', 'ec', resp_cert('ec', [KU_DS, eku(EKU_OCSP), ext('1.3.6.1.5.5.7.48.1.5', NULL, critical=True)]))
deleg('deleg-policies-critical', 'ec', resp_cert('ec', [KU_DS, eku(EKU_OCSP), ext('2.5.29.32', seq(seq(oid('2.5.29.32.0'))), critical=True)]))
deleg('deleg-san-critical', 'ec', resp_cert('ec', [KU_DS, eku(EKU_OCSP), SAN(True)]))
deleg('deleg-name-constraints-critical', 'ec', resp_cert('ec', [KU_DS, eku(EKU_OCSP), ext('2.5.29.30', seq(enc(0xa0, seq(enc(0x82, b'example')))), critical=True)]))
# BOOLEAN TRUE as 0x01 (BER; DER says 0xff) on the critical keyUsage.
deleg('deleg-critical-ber-true', 'ec', resp_cert('ec', [seq(oid('2.5.29.15'), b'\x01\x01\x01', enc(0x04, enc(0x03, b'\x07\x80'))), eku(EKU_OCSP)]))
# keyUsage digitalSignature with unused bits 0 (trailing zero bits kept), two bytes, nonzero padding.
deleg('deleg-ku-unused-0', 'ec', resp_cert('ec', [ext('2.5.29.15', enc(0x03, b'\x00\x80'), critical=True), eku(EKU_OCSP)]))
deleg('deleg-ku-two-bytes', 'ec', resp_cert('ec', [ext('2.5.29.15', enc(0x03, b'\x07\x80\x00'), critical=True), eku(EKU_OCSP)]))
deleg('deleg-ku-padding-set', 'ec', resp_cert('ec', [ext('2.5.29.15', enc(0x03, b'\x07\x81'), critical=True), eku(EKU_OCSP)]))
# 16 harmless extensions, then extendedKeyUsage twice (RFC 5280 §4.2:
# MUST NOT; OpenSSL: invalid certificate).
fill = [ext('1.2.3.%d' % i, NULL) for i in range(16)]
deleg('deleg-eku-twice-after-16', 'ec', resp_cert('ec', fill + [eku('1.3.6.1.5.5.7.3.1'), eku(EKU_OCSP)]))
deleg('deleg-ku-twice-after-16', 'ec', resp_cert('ec', fill + [eku(EKU_OCSP), ku(0x80, 7), ku(0x20, 5)]))
deleg('deleg-eku-twice-first-16', 'ec', resp_cert('ec', [eku('1.3.6.1.5.5.7.3.1')] + fill + [eku(EKU_OCSP)]))
# Names equal by RFC 5280 §7.1 (PrintableString vs the CA's UTF8String).
issuer('responderid-printable', rid=enc(0xa1, name_printable('Peregrine OCSP Test CA')))
issuer('responderid-case', rid=enc(0xa1, name_cn('peregrine ocsp test ca')))
deleg('deleg-issuer-printable', 'ec', resp_cert('ec', issuer_name=name_printable('Peregrine OCSP Test CA')))
dp = resp_cert('ec', cn='Verify Responder')
deleg('deleg-responderid-printable', 'ec', dp, rid=enc(0xa1, name_printable('Verify Responder')))

# Revocations that must not count: from responders that may not sign, for
# another serial number.
deleg('revoked-by-noeku', 'ec', resp_cert('ec', [KU_DS]), responses=REV['responses'])
deleg('revoked-by-ku-no-ds', 'ec', resp_cert('ec', [ku(0x20, 5), eku(EKU_OCSP)]), responses=REV['responses'])
deleg('revoked-by-other-ca-same-name', 'ec', make_cert(ca.subject, name_cn('Verify Responder'), spki_of(K['ec']), K['rogue'], exts=[eku(EKU_OCSP)]), responses=REV['responses'])
deleg('revoked-by-expired-responder', 'ec', resp_cert('ec', not_before=NOW - 2 * 86400, not_after=NOW - 120), responses=REV['responses'])
deleg('revoked-by-self-signed', 'rogue', make_cert(name_cn('Verify Responder'), name_cn('Verify Responder'), spki_of(K['rogue']), K['rogue'], exts=[eku(EKU_OCSP)]), responses=REV['responses'])
deleg('unknown-by-noeku', 'ec', resp_cert('ec', [KU_DS]), responses=UNK['responses'])
_, rs, _, _ = rd(REV['responses'])
(_, single, _), = kids(rs)
cid, *rest = kids(single)
alg_, nh, kh, ser = kids(cid[1])
other = seq(seq(alg_[2], nh[2], kh[2], integer(0x1003)), *[x[2] for x in rest])
issuer('revoked-other-serial', responses=seq(other))
_, gs, _, _ = rd(B['responses'])
(_, gsingle, _), = kids(gs)
issuer('good-then-revoked', responses=seq(gsingle and kids(gs)[0][2], kids(rs)[0][2]))

for n, d in cases.items():
    open(os.path.join(HERE, n + '.der'), 'wb').write(d)
chain_pem = os.path.join(T, 'chain.pem')
open(chain_pem, 'w').write(der2pem(leaf.der) + der2pem(ca.der))
for n in sorted(cases):
    v, out = ossl_verify(os.path.join(HERE, n + '.der'), NOW, P + 'ca.pem', P + 'leaf.pem', chain_pem)
    if v == 'FAIL':
        st = [s for s in out.split(' | ') if 'leaf.pem:' in s or 'error' in s.lower() or 'fail' in s.lower()]
        v = 'FAIL ' + '; '.join(st)[:160]
    print('%-34s openssl: %s' % (n, v))
