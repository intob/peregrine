# Minimal DER helpers + OCSP crafting via the openssl CLI.
import subprocess, tempfile, os, hashlib, base64
OPENSSL = os.environ.get('OPENSSL', 'openssl')

def rd(b, i=0):
    t = b[i]; l = b[i+1]; j = i+2
    if l & 0x80:
        n = l & 0x7f; l = int.from_bytes(b[j:j+n], 'big'); j += n
    return t, b[j:j+l], b[i:j+l], j+l

def enc(t, c):
    n = len(c)
    if n < 0x80: L = bytes([n])
    else:
        nb = n.to_bytes((n.bit_length()+7)//8, 'big'); L = bytes([0x80|len(nb)]) + nb
    return bytes([t]) + L + c

def kids(c):
    out = []; i = 0
    while i < len(c):
        t, cc, a, i = rd(c, i); out.append((t, cc, a))
    return out

def seq(*parts): return enc(0x30, b''.join(parts))
def oid(dotted):
    p = [int(x) for x in dotted.split('.')]
    out = bytes([p[0]*40 + p[1]])
    for v in p[2:]:
        bs = [v & 0x7f]; v >>= 7
        while v: bs.append(0x80 | (v & 0x7f)); v >>= 7
        out += bytes(reversed(bs))
    return enc(0x06, out)
NULL = b'\x05\x00'
def integer(v):
    if v == 0: return b'\x02\x01\x00'
    n = (v.bit_length() + 8) // 8
    return enc(0x02, v.to_bytes(n, 'big', signed=True))

def pem2der(path):
    s = open(path).read()
    out = []
    for blk in s.split('-----BEGIN ')[1:]:
        body = blk.split('-----', 1)[1].split('-----END')[0]
        out.append(base64.b64decode(''.join(body.split())))
    return out

def run(*args, inp=None):
    return subprocess.run([OPENSSL, *args], input=inp, capture_output=True, check=True).stdout

class Cert:
    def __init__(self, der):
        self.der = der
        _, c, _, _ = rd(der)
        k = kids(c)
        self.tbs = k[0][2]
        tk = kids(k[0][1])
        i = 1 if tk[0][0] == 0xa0 else 0
        self.serial = tk[i]; self.issuer = tk[i+2][2]; self.subject = tk[i+4][2]
        self.spki = tk[i+5][2]
        sk = kids(tk[i+5][1])
        self.key_bits = sk[1][1][1:]
    def by_name(self): return enc(0xa1, self.subject)
    def by_key(self): return enc(0xa2, enc(0x04, hashlib.sha1(self.key_bits).digest()))

def tmpw(d, name, data):
    p = os.path.join(d, name); open(p, 'wb').write(data); return p

def sign(key, data, md='sha256', opts=()):
    with tempfile.TemporaryDirectory() as d:
        p = tmpw(d, 'in', data)
        args = ['pkeyutl', '-sign', '-rawin', '-inkey', key, '-in', p]
        if md: args += ['-digest', md]
        for o in opts: args += ['-pkeyopt', o]
        return run(*args)

ALG = {
    'ecdsa-sha256': seq(oid('1.2.840.10045.4.3.2')),
    'ecdsa-sha384': seq(oid('1.2.840.10045.4.3.3')),
    'ecdsa-sha512': seq(oid('1.2.840.10045.4.3.4')),
    'ed25519': seq(oid('1.3.101.112')),
    'rsa-sha256': seq(oid('1.2.840.113549.1.1.11'), NULL),
    'rsa-sha384': seq(oid('1.2.840.113549.1.1.12'), NULL),
    'rsa-sha512': seq(oid('1.2.840.113549.1.1.13'), NULL),
    'rsa-sha1': seq(oid('1.2.840.113549.1.1.5'), NULL),
    'rsa-md5': seq(oid('1.2.840.113549.1.1.4'), NULL),
    'ecdsa-sha1': seq(oid('1.2.840.10045.4.1')),
}
HASH_OID = {'sha1': '1.3.14.3.2.26', 'sha256': '2.16.840.1.101.3.4.2.1', 'sha384': '2.16.840.1.101.3.4.2.2', 'sha512': '2.16.840.1.101.3.4.2.3'}
def pss_alg(h='sha256', mgf_h=None, salt=32, trailer=None, null=True):
    ha = seq(oid(HASH_OID[h]), NULL) if null else seq(oid(HASH_OID[h]))
    mh = mgf_h or h
    mgf = seq(oid('1.2.840.113549.1.1.8'), seq(oid(HASH_OID[mh]), NULL))
    p = enc(0xa0, ha) + enc(0xa1, mgf) + enc(0xa2, integer(salt))
    if trailer is not None: p += enc(0xa3, integer(trailer))
    return seq(oid('1.2.840.113549.1.1.10'), seq(p))

# Base response pieces from leaf-good.der
TD = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
def base_parts(path=TD + '/leaf-good.der'):
    b = open(path, 'rb').read()
    _, resp, _, _ = rd(b)
    status, explicit = kids(resp)
    (_, rb, _), = kids(explicit[1])
    o, octs = kids(rb)
    _, basic, _, _ = rd(octs[1])
    k = kids(basic)
    data = kids(k[0][1])
    # data: [responderID, producedAt, responses, (exts)]
    head = [x[2] for x in data]
    return {'responder': head[0], 'produced': head[1], 'responses': head[2], 'rest': head[3:], 'sig_alg': k[1][2], 'sig': k[2][2], 'certs': k[3][2] if len(k) > 3 else b''}

def tbs_data(responder, produced, responses, version=b'', exts=b''):
    return seq(version, responder, produced, responses, exts)

def response(tbs, sig_alg, sig_bytes, certs=None, raw_certs=None):
    parts = [tbs, sig_alg, enc(0x03, b'\x00' + sig_bytes)]
    if raw_certs is not None: parts.append(raw_certs)
    elif certs is not None: parts.append(enc(0xa0, seq(*certs)))
    basic = seq(*parts)
    return seq(b'\x0a\x01\x00', enc(0xa0, seq(oid('1.3.6.1.5.5.7.48.1.1'), enc(0x04, basic))))

import time, datetime
def gtime(t):
    return enc(0x18, datetime.datetime.fromtimestamp(t, datetime.UTC).strftime('%Y%m%d%H%M%SZ').encode())
def utime(t):
    return enc(0x17, datetime.datetime.fromtimestamp(t, datetime.UTC).strftime('%y%m%d%H%M%SZ').encode())
def name_cn(cn):
    return seq(enc(0x31, seq(oid('2.5.4.3'), enc(0x0c, cn.encode()))))
def ext(o, value, critical=False):
    return seq(oid(o), b'\x01\x01\xff' if critical else b'', enc(0x04, value))
EKU_OCSP = '1.3.6.1.5.5.7.3.9'
def eku(*oids, critical=False): return ext('2.5.29.37', seq(*[oid(o) for o in oids]), critical)
def ku(bits_byte, unused, critical=True): return ext('2.5.29.15', enc(0x03, bytes([unused, bits_byte])), critical)
def spki_of(keyfile):
    return run('pkey', '-in', keyfile, '-pubout', '-outform', 'DER')

def make_cert(issuer_name, subject_name, spki, signer_key, serial=0x3001, not_before=None, not_after=None,
              exts=(), sig_alg='ecdsa-sha256', md='sha256', sign_opts=(), tbs_sig_alg=None, raw_sig=None):
    now = int(os.environ.get('BASE_T', time.time()))
    nb = now - 3600 if not_before is None else not_before
    na = now + 36500 * 86400 if not_after is None else not_after
    alg = ALG[sig_alg] if isinstance(sig_alg, str) else sig_alg
    tbs = seq(enc(0xa0, integer(2)), integer(serial), tbs_sig_alg or alg, issuer_name,
              seq(gtime(nb) if nb >= 2524608000 else utime(nb), gtime(na) if na >= 2524608000 else utime(na)),
              subject_name, spki, enc(0xa3, seq(*exts)) if exts else b'')
    sig = raw_sig if raw_sig is not None else sign(signer_key, tbs, md, sign_opts)
    return seq(tbs, alg, enc(0x03, b'\x00' + sig))

def der2pem(der, label='CERTIFICATE'):
    b = base64.encodebytes(der).decode().replace('\n', '')
    return '-----BEGIN %s-----\n%s\n-----END %s-----\n' % (label, '\n'.join(b[i:i+64] for i in range(0, len(b), 64)), label)

def ossl_verify(resp_path, now, ca_pem, leaf_pem, chain_pem, extra=()):
    r = subprocess.run([OPENSSL, 'ocsp', '-respin', resp_path, '-issuer', ca_pem, '-cert', leaf_pem,
                        '-CAfile', ca_pem, '-verify_other', chain_pem, '-no_nonce', '-attime', str(now), *extra],
                       capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip().replace('\n', ' | ')
    return ('OK' if r.returncode == 0 and 'Response verify OK' in out and ': good' in out else 'FAIL'), out[:300]
