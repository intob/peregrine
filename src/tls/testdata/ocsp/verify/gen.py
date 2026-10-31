#!/usr/bin/env python3
# Adversarial OCSP responses for ocsp.zig's "verify:" tests (second
# verifier round): responses built by hand from leaf-good.der's
# ResponseData (its producedAt and SingleResponse, so its times), signed by
# the test CA or by responder certificates made here, which the CA signs
# (valid from an hour before leaf-good.der's thisUpdate for 100 years
# unless the case says otherwise). Each file is NAME.der; after writing them
# it prints what `openssl ocsp -verify_other ... -CAfile ca.pem -attime`
# (curl --cert-status's OCSP_basic_verify) says about each, a minute after
# thisUpdate. Responder keys are made fresh in a temporary directory, so
# every run makes different bytes.
# Usage: gen.py (OpenSSL 3.4+; OPENSSL=path to choose one)
import os, sys, tempfile
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ['BASE_T'] = '1793471106'  # testdata.this_update
from der import *

HERE = os.path.dirname(os.path.abspath(__file__))
T = tempfile.mkdtemp()
P = TD + '/'
NOW = int(os.environ['BASE_T']) + 60
ca = Cert(pem2der(P + 'ca.pem')[0])
leaf = Cert(pem2der(P + 'leaf.pem')[0])
B = base_parts()
N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
cases = {}

def key(name, *opts):
    path = os.path.join(T, name + '.key')
    run('genpkey', *opts, '-out', path)
    return path
K = {
    'ec': key('ec', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'),
    'p384': key('p384', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384'),
    'p521': key('p521', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-521'),
    'rsa': key('rsa', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'),
    'rsa2041': key('rsa2041', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2041'),
    'rsa_e3': key('rsa_e3', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-pkeyopt', 'rsa_keygen_pubexp:3'),
    'rsa512': key('rsa512', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:512'),
    'ed': key('ed', '-algorithm', 'ED25519'),
    'rogue': key('rogue', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'),
    'ca': P + 'ca.key',
}

def resp_cert(k, exts=None, cn='Verify Responder', **kw):
    if exts is None: exts = [eku(EKU_OCSP)]
    return make_cert(ca.subject, name_cn(cn), spki_of(K[k]), K['ca'], exts=exts, **kw)

def deleg(name, k, cert_der, sig_alg='ecdsa-sha256', md='sha256', opts=(), by='name', certs=None,
          mangle=None, responses=None, version=b'', exts=b'', raw_certs=None, produced=None):
    c = Cert(cert_der)
    rid = c.by_name() if by == 'name' else c.by_key() if by == 'key' else by
    tbs = tbs_data(rid, produced or B['produced'], responses or B['responses'], version, exts)
    alg = ALG[sig_alg] if isinstance(sig_alg, str) else sig_alg
    sig = sign(K[k], tbs, md, opts)
    if mangle: sig = mangle(sig, tbs)
    cases[name] = response(tbs, alg, sig, certs=[cert_der] if certs is None else certs, raw_certs=raw_certs)

def issuer(name, **kw):
    deleg(name, 'ca', ca.der, **kw)

def ec_parse(sig):
    _, c, _, _ = rd(sig); (_, r, _), (_, s, _) = kids(c)
    return int.from_bytes(r, 'big'), int.from_bytes(s, 'big')
def ec_raw(rb, sb): return seq(enc(0x02, rb), enc(0x02, sb))
def ec_int(v): return integer(v)[2:]
def resign_until(pred, enc_fn):
    def m(sig, tbs):
        for _ in range(20000):
            r, s = ec_parse(sig)
            if pred(r): return enc_fn(r, s)
            sig = sign(K['ca'], tbs)
        raise Exception('no luck')
    return m
PSS = ['rsa_padding_mode:pss']

# Delegated responder certificates.
ec_ok = resp_cert('ec')
deleg('deleg-ok', 'ec', ec_ok)
deleg('deleg-bykey', 'ec', ec_ok, by='key')
deleg('bykey-whole-spki', 'ec', ec_ok, by=enc(0xa2, enc(0x04, hashlib.sha1(Cert(ec_ok).spki).digest())))
deleg('eku-critical-several', 'ec', resp_cert('ec', [eku('1.3.6.1.5.5.7.3.1', EKU_OCSP, critical=True)]))
deleg('eku-any-only', 'ec', resp_cert('ec', [eku('2.5.29.37.0')]))
deleg('ku-no-digital-signature', 'ec', resp_cert('ec', [ku(0x20, 5), eku(EKU_OCSP)]))
deleg('responder-not-yet-valid', 'ec', resp_cert('ec', not_before=NOW + 86400))
deleg('responder-expired', 'ec', resp_cert('ec', not_before=NOW - 2 * 86400, not_after=NOW - 120))
deleg('unknown-critical-extension', 'ec', resp_cert('ec', [eku(EKU_OCSP), ext('1.2.3.4', NULL, critical=True)]))
deleg('eku-twice', 'ec', resp_cert('ec', [eku('1.3.6.1.5.5.7.3.1'), eku(EKU_OCSP)]))
deleg('cert-tbs-alg-mismatch', 'ec', resp_cert('ec', tbs_sig_alg=ALG['ecdsa-sha384']))
deleg('critical-false-explicit', 'ec', resp_cert('ec', [seq(oid('2.5.29.37'), b'\x01\x01\x00', enc(0x04, seq(oid(EKU_OCSP))))]))
deleg('issuer-field-other-ca', 'ec', make_cert(name_cn('Another CA'), name_cn('Verify Responder'), spki_of(K['ec']), K['ca'], exts=[eku(EKU_OCSP)]))
deleg('other-ca-same-name', 'ec', make_cert(ca.subject, name_cn('Verify Responder'), spki_of(K['ec']), K['rogue'], exts=[eku(EKU_OCSP)]))
deleg('named-like-ca', 'ec', resp_cert('ec', cn='Peregrine OCSP Test CA'))
deleg('byname-ca-signed-by-delegate', 'ec', ec_ok, by=ca.by_name())
exp_copy = resp_cert('ec', not_before=NOW - 2 * 86400, not_after=NOW - 120)
deleg('expired-copy-first', 'ec', ec_ok, certs=[exp_copy, ec_ok])
deleg('valid-copy-first', 'ec', ec_ok, certs=[ec_ok, exp_copy])
deleg('cert-signed-ecdsa-sha1', 'ec', resp_cert('ec', sig_alg='ecdsa-sha1', md='sha1'))
rogue = make_cert(ca.subject, ca.subject, spki_of(K['rogue']), K['rogue'], exts=[eku(EKU_OCSP)])
issuer('rogue-ca-named-in-certs', certs=[rogue])
issuer('leaf-in-certs', certs=[leaf.der])

# Parts check doesn't parse; OpenSSL can't parse the response at all.
issuer('garbage-certs', raw_certs=b'\xa0\x03\x02\x01\x00')
deleg('garbage-after-responder', 'ec', ec_ok, raw_certs=enc(0xa0, seq(ec_ok, b'\x02\x01\x00')))
_, sc, _, _ = rd(B['responses']); single = kids(sc)[0][2]
_, sic, _, _ = rd(single)
issuer('garbage-single-extensions', responses=seq(seq(sic, enc(0xa1, NULL))))
issuer('garbage-response-extensions', exts=enc(0xa1, NULL))
issuer('version-explicit', version=enc(0xa0, integer(0)))

# Signature algorithms and keys.
rsa_ok = resp_cert('rsa')
deleg('rsa', 'rsa', rsa_ok, sig_alg='rsa-sha256')
deleg('rsa-key-ecdsa-oid', 'rsa', rsa_ok, sig_alg='ecdsa-sha256')
deleg('pss', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha256', 32), opts=PSS + ['rsa_pss_saltlen:32'])
deleg('pss-mgf-sha1', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha1', 32), opts=PSS + ['rsa_pss_saltlen:32', 'rsa_mgf1_md:sha1'])
deleg('pss-salt-20', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha256', 20), opts=PSS + ['rsa_pss_saltlen:20'])
deleg('pss-said-32-used-20', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha256', 32), opts=PSS + ['rsa_pss_saltlen:20'])
deleg('pss-said-32-used-max', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha256', 32), opts=PSS + ['rsa_pss_saltlen:max'])
deleg('pss-said-32-used-0', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha256', 32), opts=PSS + ['rsa_pss_saltlen:0'])
deleg('pss-hash-without-null', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha256', 32, null=False), opts=PSS + ['rsa_pss_saltlen:32'])
deleg('pss-trailer-1', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha256', 32, trailer=1), opts=PSS + ['rsa_pss_saltlen:32'])
deleg('pss-trailer-2', 'rsa', rsa_ok, sig_alg=pss_alg('sha256', 'sha256', 32, trailer=2), opts=PSS + ['rsa_pss_saltlen:32'])
deleg('pss-said-sha384-used-sha256', 'rsa', rsa_ok, sig_alg=pss_alg('sha384', 'sha384', 48), opts=PSS + ['rsa_pss_saltlen:32'])
deleg('rsa-sha1', 'rsa', rsa_ok, sig_alg='rsa-sha1', md='sha1')
deleg('rsa-md5', 'rsa', rsa_ok, sig_alg='rsa-md5', md='md5')
deleg('rsa-signature-longer', 'rsa', rsa_ok, sig_alg='rsa-sha256', mangle=lambda sig, tbs: b'\x00' + sig)
for sec in range(4000):
    prod = gtime(int(os.environ['BASE_T']) + sec)
    tbs = tbs_data(Cert(rsa_ok).by_name(), prod, B['responses'])
    sig = sign(K['rsa'], tbs)
    if sig[0] == 0:
        cases['rsa-signature-shorter'] = response(tbs, ALG['rsa-sha256'], sig[1:], certs=[rsa_ok])
        cases['rsa-signature-leading-zero'] = response(tbs, ALG['rsa-sha256'], sig, certs=[rsa_ok])
        break
deleg('rsa-e3', 'rsa_e3', resp_cert('rsa_e3'), sig_alg='rsa-sha256')
deleg('rsa-512', 'rsa512', resp_cert('rsa512'), sig_alg='rsa-sha256')
c2041 = resp_cert('rsa2041')
deleg('rsa-2041-pkcs1', 'rsa2041', c2041, sig_alg='rsa-sha256')
deleg('rsa-2041-pss', 'rsa2041', c2041, sig_alg=pss_alg('sha256', 'sha256', 32), opts=PSS + ['rsa_pss_saltlen:32'])
deleg('p521', 'p521', resp_cert('p521'), sig_alg='ecdsa-sha512', md='sha512')
deleg('p384-with-sha256', 'p384', resp_cert('p384'), sig_alg='ecdsa-sha256')
deleg('p256-with-sha512', 'ec', ec_ok, sig_alg='ecdsa-sha512', md='sha512')
ed_ok = resp_cert('ed')
deleg('ed25519-params', 'ed', ed_ok, sig_alg=seq(oid('1.3.101.112'), NULL), md=None)
issuer('ecdsa-high-s', mangle=lambda sig, tbs: (lambda r, s: ec_raw(ec_int(r), ec_int(N256 - s)))(*ec_parse(sig)))
issuer('ecdsa-r-zero', mangle=lambda sig, tbs: ec_raw(b'\x00', ec_int(ec_parse(sig)[1])))
issuer('ecdsa-s-plus-n', mangle=lambda sig, tbs: (lambda r, s: ec_raw(ec_int(r), ec_int(s + N256)))(*ec_parse(sig)))
issuer('ecdsa-s-minus-n', mangle=lambda sig, tbs: (lambda r, s: ec_raw(ec_int(r), integer(s - N256)[2:]))(*ec_parse(sig)))
issuer('ecdsa-trailing-byte', mangle=lambda sig, tbs: sig + b'\x00')
issuer('ecdsa-r-not-minimal', mangle=resign_until(lambda r: r < 2**247, lambda r, s: ec_raw(b'\x00' + r.to_bytes(31, 'big'), ec_int(s))))
issuer('ecdsa-r-negative', mangle=resign_until(lambda r: 2**247 <= r < 2**248, lambda r, s: ec_raw(r.to_bytes(31, 'big'), ec_int(s))))

for n, d in cases.items():
    open(os.path.join(HERE, n + '.der'), 'wb').write(d)
chain_pem = os.path.join(T, 'chain.pem')
open(chain_pem, 'w').write(der2pem(leaf.der) + der2pem(ca.der))
for n in sorted(cases):
    v, out = ossl_verify(os.path.join(HERE, n + '.der'), NOW, P + 'ca.pem', P + 'leaf.pem', chain_pem)
    print('%-32s openssl: %s' % (n, v))
