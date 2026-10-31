#!/usr/bin/env python3
"""Writes rsa_pss_vectors.txt, the known-answer tests for rsa.zig, from
Python's own integers and hashlib (independent of the Zig code):

  python3 -I rsa_pss_vectors.py SigGenPSS_186-3.txt > rsa_pss_vectors.txt

1. NIST CAVP's RSASSA-PSS signature generation vectors (FIPS 186-3,
   186-3rsatestvectors.zip, SigGenPSS_186-3.txt): the SHA-256 ones, for
   2048 bits (salt 20 bytes) and 3072 bits (salt 32 bytes). They give n, e
   and d; the factors are recovered here from e·d − 1 to make PKCS#1 keys.
2. Keys generated here for sizes and shapes the NIST ones don't cover:
   p < q, unbalanced primes, primes just past a limb-count boundary
   (1025, 1537 bits), RSA-4096 and odd modulus lengths, e = 3 and
   e = 2^32 − 1; each with PSS-SHA-256 signatures (32-byte salt)
   computed here.

Output lines: `key <PKCS#1 DER hex>`, then for that key
`pss <salt hex> <message hex> <signature hex>` (an empty message is `-`).
"""
import hashlib
import math
import random
import sys

rng = random.Random(0x7273612D707373)


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")  # a leading 0 when the top bit is set
    return b"\x02" + der_len(len(b)) + b


def pkcs1(n, e, d, p, q):
    body = b"".join(der_int(v) for v in (0, n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)))
    return b"\x30" + der_len(len(body)) + body


def mgf1(seed, length):
    out = b""
    c = 0
    while len(out) < length:
        out += hashlib.sha256(seed + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:length]


def pss_sign(n, d, msg, salt):
    mod_bits = n.bit_length()
    em_bits = mod_bits - 1
    em_len = (em_bits + 7) // 8
    h_len = 32
    m_hash = hashlib.sha256(msg).digest()
    h = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - len(salt) - h_len - 2) + b"\x01" + salt
    masked = bytearray(x ^ y for x, y in zip(db, mgf1(h, em_len - h_len - 1)))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    em = bytes(masked) + h + b"\xbc"
    k = (mod_bits + 7) // 8
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def factor(n, e, d):
    k = e * d - 1
    t = 0
    while k % 2 == 0:
        k //= 2
        t += 1
    while True:
        g = rng.randrange(2, n - 1)
        x = pow(g, k, n)
        if x in (1, n - 1):
            continue
        for _ in range(t):
            y = x * x % n
            if y == 1:
                p = math.gcd(x - 1, n)
                return p, n // p
            if y == n - 1:
                break
            x = y


def is_prime(v):
    if v < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if v % sp == 0:
            return v == sp
    r, s = v - 1, 0
    while r % 2 == 0:
        r //= 2
        s += 1
    for _ in range(40):
        a = rng.randrange(2, v - 1)
        x = pow(a, r, v)
        if x in (1, v - 1):
            continue
        for _ in range(s - 1):
            x = x * x % v
            if x == v - 1:
                break
        else:
            return False
    return True


def prime(bits, e):
    while True:
        v = rng.getrandbits(bits) | (3 << (bits - 2)) | 1  # top two bits: p·q has bits(p) + bits(q)
        if math.gcd(e, v - 1) == 1 and is_prime(v):
            return v


def emit_key(n, e, d, p, q):
    assert p * q == n and pow(pow(5, e, n), d, n) == 5
    print("key " + pkcs1(n, e, d, p, q).hex())


def emit_sig(salt, msg, sig):
    print("pss %s %s %s" % (salt.hex(), msg.hex() or "-", sig.hex()))


def nist(path):
    mod = None
    vals = {}
    keys = {}
    vectors = []
    for line in open(path):
        line = line.strip()
        if line.startswith("[mod"):
            mod = int(line.split("=")[1].strip(" ]"))
        elif "=" in line:
            name, v = (x.strip() for x in line.split("=", 1))
            vals[name] = v
            if name in ("n", "e", "d") and all(x in vals for x in ("n", "e", "d")) and name == "d":
                keys[mod] = tuple(int(vals[x], 16) for x in ("n", "e", "d"))
            if name == "SaltVal" and vals["SHAAlg"] == "SHA256":
                vectors.append((mod, bytes.fromhex(vals["SaltVal"]), bytes.fromhex(vals["Msg"]), bytes.fromhex(vals["S"])))
    for mod in sorted(keys):
        n, e, d = keys[mod]
        p, q = factor(n, e, d)
        p, q = max(p, q), min(p, q)
        print("# NIST CAVP SigGenPSS_186-3, mod = %d, SHA256" % mod)
        emit_key(n, e, d, p, q)
        for m, salt, msg, sig in vectors:
            if m == mod:
                # The salt and message as given; the signature as given and
                # as computed here, which must agree.
                assert pss_sign(n, d, msg, salt) == sig
                emit_sig(salt, msg, sig)


def generated():
    # (bits of p, bits of q, e, comment)
    shapes = [
        (1024, 1024, 65537, "RSA-2048"),
        (1024, 1024, 65537, "RSA-2048, p < q"),
        (1024, 1024, 3, "RSA-2048, e = 3"),
        (1024, 1024, 2**32 - 1, "RSA-2048, e = 2^32 - 1"),
        (1025, 1024, 65537, "RSA-2049: p of 1025 bits (24 limbs)"),
        (1100, 948, 65537, "RSA-2048, unbalanced, p > q"),
        (948, 1100, 65537, "RSA-2048, unbalanced, p < q"),
        (256, 1792, 65537, "RSA-2048, a 256-bit p"),
        (1028, 1028, 65537, "RSA-2056"),
        (1536, 1536, 65537, "RSA-3072"),
        (1536, 1536, 65537, "RSA-3072, p < q"),
        (1537, 1536, 65537, "RSA-3073: p of 1537 bits (32 limbs)"),
        (2048, 2048, 65537, "RSA-4096"),
        (2048, 2048, 65537, "RSA-4096, p < q"),
        (2048, 2047, 65537, "RSA-4095"),
        (2000, 2048, 3, "RSA-4048, unbalanced, e = 3"),
    ]
    for pb, qb, e, comment in shapes:
        while True:
            p, q = prime(pb, e), prime(qb, e)
            if p != q:
                break
        if "p < q" in comment:
            p, q = min(p, q), max(p, q)
        elif pb == qb:
            p, q = max(p, q), min(p, q)
        n = p * q
        d = pow(e, -1, math.lcm(p - 1, q - 1))
        print("# generated: " + comment)
        emit_key(n, e, d, p, q)
        for i in range(3):
            salt = bytes(32) if i == 0 else rng.randbytes(32)
            msg = b"" if i == 0 else rng.randbytes(rng.choice((3, 130, 300)))
            emit_sig(salt, msg, pss_sign(n, d, msg, salt))


print("# Known answers for rsa.zig: see rsa_pss_vectors.py")
nist(sys.argv[1])
generated()
