//! RSA private keys and RSASSA-PSS signing (RFC 8017) for TLS 1.3's
//! `rsa_pss_rsae_sha256`, the RSA scheme every TLS 1.3 client implements
//! (RFC 8446 §9.1). std has only RSA verification.
//!
//! The private-key operation uses the CRT (two half-size exponentiations)
//! over `mont.zig`'s fixed-size constant-time Montgomery arithmetic, sized
//! at compile time to the primes: 16 limbs for RSA-2048, 24 for RSA-3072,
//! 32 for RSA-4096 (other sizes take the next one up). Every signature is
//! checked with the public exponent before it is returned, so a fault in
//! the CRT can't hand out a value that reveals the factors. Until
//! 2026-10-31 this used std.crypto.ff (`rsa_verify.zig` keeps that as the
//! reference): RSA-2048 signing took about 1.1 ms.
const std = @import("std");
const mont = @import("./mont.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const min_bits = 2048;
pub const max_bits = 4096;
/// Largest signature (the modulus length).
pub const max_len = max_bits / 8;
pub const salt_len = Sha256.digest_length;

pub const Error = error{ InvalidKey, UnsupportedKey, SignatureFault };

pub const PrivateKey = struct {
    /// The modulus length in bytes (the signature length).
    len: usize,
    /// Big-endian, `len` bytes (for matching the certificate).
    n_bytes: [max_len]u8,
    /// The modulus length in bits.
    bits: usize,
    e: u32,
    crt: Crt,
    /// d mod (p − 1) and d mod (q − 1), big-endian, padded to the length
    /// of p and q so the exponentiation time doesn't depend on them.
    dp: [max_len / 2]u8,
    dq: [max_len / 2]u8,
    p_len: usize,
    q_len: usize,

    /// PKCS#1 RSAPrivateKey (RFC 8017 A.1.2), two primes.
    pub fn fromPkcs1(der: []const u8) Error!PrivateKey {
        var outer: Der = .{ .bytes = der };
        var seq: Der = .{ .bytes = try outer.read(0x30) };
        if (!std.mem.eql(u8, try seq.integer(), &.{})) return error.UnsupportedKey; // version 0
        const n = try seq.integer();
        const e = try seq.integer();
        _ = try seq.integer(); // d: the CRT values below are used instead
        const p = try seq.integer();
        const q = try seq.integer();
        const dp = try seq.integer();
        const dq = try seq.integer();
        const q_inv = try seq.integer();
        if (!seq.atEnd()) return error.UnsupportedKey; // multi-prime
        if (n.len > max_len or e.len == 0 or e.len > 4 or p.len > max_len / 2 or q.len > max_len / 2) return error.InvalidKey;
        // Odd moduli of at least 3 (Montgomery arithmetic needs them odd).
        for ([_][]const u8{ n, p, q }) |v| {
            if (v.len == 0 or v[v.len - 1] & 1 == 0 or (v.len == 1 and v[0] < 3)) return error.InvalidKey;
        }

        var key: PrivateKey = undefined;
        key.bits = 8 * n.len - @clz(n[0]);
        if (key.bits < min_bits or key.bits > max_bits) return error.UnsupportedKey;
        key.len = n.len;
        @memcpy(key.n_bytes[0..n.len], n);
        key.e = 0;
        for (e) |b| key.e = key.e << 8 | b;
        if (key.e < 3 or key.e & 1 == 0) return error.InvalidKey;
        key.p_len = p.len;
        key.q_len = q.len;
        if (dp.len > p.len or dq.len > q.len) return error.InvalidKey;
        key.dp = @splat(0);
        key.dq = @splat(0);
        @memcpy(key.dp[p.len - dp.len ..][0..dp.len], dp);
        @memcpy(key.dq[q.len - dq.len ..][0..dq.len], dq);
        // Limbs per prime, from the longer one.
        const prime_len = @max(p.len, q.len);
        key.crt = if (prime_len <= 128)
            .{ .l16 = try .init(n, p, q, q_inv) }
        else if (prime_len <= 192)
            .{ .l24 = try .init(n, p, q, q_inv) }
        else
            .{ .l32 = try .init(n, p, q, q_inv) };
        // The parts must make a working key: a signature that verifies.
        var sig: [max_len]u8 = undefined;
        _ = key.sign("key check", @splat(0), &sig) catch return error.InvalidKey;
        return key;
    }

    /// The public exponent, big-endian, without leading zeros.
    pub fn exponent(self: *const PrivateKey, buf: *[4]u8) []const u8 {
        std.mem.writeInt(u32, buf, self.e, .big);
        var i: usize = 0;
        while (buf[i] == 0) i += 1;
        return buf[i..];
    }

    pub fn modulus(self: *const PrivateKey) []const u8 {
        return self.n_bytes[0..self.len];
    }

    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
    pub fn sign(self: *const PrivateKey, msg: []const u8, salt: [salt_len]u8, out: *[max_len]u8) Error![]const u8 {
        const k = self.len;
        var em_buf: [max_len]u8 = @splat(0);
        const em = em_buf[0..k];
        encodePss(em, self.bits - 1, msg, &salt);
        const s = out[0..k];
        switch (self.crt) {
            inline else => |*crt| {
                crt.privateOp(self, em, s);
                // s^e must give the encoded message back.
                if (!crt.publicOpIs(self.e, s, em)) {
                    @memset(s, 0);
                    return error.SignatureFault;
                }
            },
        }
        return s;
    }

    /// s = m^d mod n for m below n (`len` bytes each), by the CRT. For
    /// tests: `sign` checks the result.
    pub fn privateOp(self: *const PrivateKey, m: []const u8, s: []u8) void {
        switch (self.crt) {
            inline else => |*crt| crt.privateOp(self, m, s),
        }
    }
};

/// The CRT parts for primes of up to 1024, 1536 or 2048 bits.
const Crt = union(enum) {
    l16: Parts(16),
    l24: Parts(24),
    l32: Parts(32),
};

fn Parts(comptime limbs: usize) type {
    return struct {
        const Self = @This();
        const Half = mont.Mont(limbs);
        const Full = mont.Mont(2 * limbs);

        p: Half,
        q: Half,
        /// For the check with the public exponent.
        n: Full,
        /// q⁻¹ mod p, outside the Montgomery domain: a Montgomery product
        /// with it leaves the domain.
        q_inv: Half.Int,

        fn init(n: []const u8, p: []const u8, q: []const u8, q_inv: []const u8) Error!Self {
            if (n.len > 16 * limbs or q_inv.len > 8 * limbs) return error.InvalidKey;
            const p_l = mont.fromBytes(limbs, p);
            const q_l = mont.fromBytes(limbs, q);
            const n_l = mont.fromBytes(2 * limbs, n);
            // n = p·q exactly: the CRT's result, below p·q, is then below
            // n, and m below n is below p·R and q·R (for `redc`).
            const pq = mont.mulAdd(limbs, &p_l, &q_l, &@as(Half.Int, @splat(0)));
            if (!std.mem.eql(u64, &pq, &n_l)) return error.InvalidKey;
            const qi = mont.fromBytes(limbs, q_inv);
            if (mont.lessThan(&qi, &p_l) == 0) return error.InvalidKey;
            return .{ .p = .init(p_l), .q = .init(q_l), .n = .init(n_l), .q_inv = qi };
        }

        /// m mod p (or q) in the Montgomery domain, for m below n:
        /// redc gives m·R⁻¹, and two products with R² make it m·R.
        fn reduce(h: *const Half, m: *const Full.Int) Half.Int {
            var x = h.redc(m);
            x = h.mul(&x, &h.r2);
            return h.mul(&x, &h.r2);
        }

        /// s = m2 + q·(q⁻¹·(m1 − m2) mod p) with m1 = m^dp mod p and
        /// m2 = m^dq mod q: below p·q = n, so no reduction is needed.
        fn privateOp(self: *const Self, key: *const PrivateKey, m_bytes: []const u8, s_bytes: []u8) void {
            @setRuntimeSafety(mont.safe);
            const m = mont.fromBytes(2 * limbs, m_bytes);
            var x = reduce(&self.p, &m);
            var m1 = self.p.pow(&x, key.dp[0..key.p_len]);
            x = reduce(&self.q, &m);
            var m2 = self.q.pow(&x, key.dq[0..key.q_len]);
            m2 = self.q.fromMont(&m2);
            // m2 (below q, so below R) into p's domain, then the difference.
            x = self.p.mul(&m2, &self.p.r2);
            x = self.p.sub(&m1, &x);
            var h = self.p.mul(&x, &self.q_inv);
            var s = mont.mulAdd(limbs, &self.q.m, &h, &m2);
            mont.toBytes(&s, s_bytes);
            std.crypto.secureZero(u64, &x);
            std.crypto.secureZero(u64, &m1);
            std.crypto.secureZero(u64, &m2);
            std.crypto.secureZero(u64, &h);
            std.crypto.secureZero(u64, &s);
        }

        /// Whether s^e mod n = em (the signature check; s and em public).
        fn publicOpIs(self: *const Self, e: u32, s_bytes: []const u8, em: []const u8) bool {
            const s = mont.fromBytes(2 * limbs, s_bytes);
            if (mont.lessThan(&s, &self.n.m) == 0) return false;
            const sm = self.n.mul(&s, &self.n.r2);
            const back = self.n.fromMont(&self.n.powPublic(&sm, e));
            return std.mem.eql(u64, &back, &mont.fromBytes(2 * limbs, em));
        }
    };
}

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-256 and the salt's length
/// (`sign` uses 32 bytes; the NIST vectors in the tests other lengths),
/// into `out` (the modulus length; the encoding is right-aligned).
pub fn encodePss(out: []u8, em_bits: usize, msg: []const u8, salt: []const u8) void {
    const h_len = Sha256.digest_length;
    const em_len = (em_bits + 7) / 8;
    @memset(out, 0);
    const em = out[out.len - em_len ..];
    var m_hash: [h_len]u8 = undefined;
    Sha256.hash(msg, &m_hash, .{});
    // H = Hash(0x00 * 8 || mHash || salt)
    var hash = Sha256.init(.{});
    hash.update(&@as([8]u8, @splat(0)));
    hash.update(&m_hash);
    hash.update(salt);
    var h: [h_len]u8 = undefined;
    hash.final(&h);
    // DB = PS || 0x01 || salt, masked with MGF1(H).
    const db = em[0 .. em_len - h_len - 1];
    db[db.len - salt.len - 1] = 0x01;
    @memcpy(db[db.len - salt.len ..], salt);
    var counter: u32 = 0;
    var pos: usize = 0;
    while (pos < db.len) : (counter += 1) {
        var t = Sha256.init(.{});
        t.update(&h);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, counter, .big);
        t.update(&c);
        var mask: [h_len]u8 = undefined;
        t.final(&mask);
        const n = @min(h_len, db.len - pos);
        for (db[pos..][0..n], mask[0..n]) |*d, x| d.* ^= x;
        pos += n;
    }
    db[0] &= @as(u8, 0xff) >> @intCast(8 * em_len - em_bits);
    em[db.len..][0..h_len].* = h;
    em[em_len - 1] = 0xbc;
}

pub const Der = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn atEnd(self: *const Der) bool {
        return self.pos >= self.bytes.len;
    }

    pub fn read(self: *Der, tag: u8) Error![]const u8 {
        if (self.pos + 2 > self.bytes.len or self.bytes[self.pos] != tag) return error.InvalidKey;
        var len: usize = self.bytes[self.pos + 1];
        self.pos += 2;
        if (len & 0x80 != 0) {
            const n = len & 0x7f;
            if (n == 0 or n > 2 or self.pos + n > self.bytes.len) return error.InvalidKey;
            len = 0;
            for (self.bytes[self.pos..][0..n]) |b| len = len << 8 | b;
            self.pos += n;
        }
        if (self.pos + len > self.bytes.len) return error.InvalidKey;
        defer self.pos += len;
        return self.bytes[self.pos..][0..len];
    }

    /// A non-negative INTEGER without its leading zero bytes.
    pub fn integer(self: *Der) Error![]const u8 {
        var v = try self.read(0x02);
        if (v.len == 0 or v[0] & 0x80 != 0) return error.InvalidKey;
        while (v.len > 0 and v[0] == 0) v = v[1..];
        return v;
    }
};

// -- Tests ------------------------------------------------------------

const rsa_std = std.crypto.Certificate.rsa;

fn verifyWithStd(key: *const PrivateKey, sig: []const u8, msg: []const u8) !void {
    var e_buf: [4]u8 = undefined;
    const pk = try rsa_std.PublicKey.fromBytes(key.exponent(&e_buf), key.modulus());
    switch (sig.len) {
        inline 256, 384, 512 => |len| try rsa_std.PSSSignature.verify(len, sig[0..len], msg, pk, Sha256),
        else => return error.UnexpectedLength,
    }
}

/// A PKCS#1 key from PEM (test helper; credentials.zig does the real
/// loading).
fn testKey(pem: []const u8, label: []const u8) !PrivateKey {
    const begin = try std.fmt.allocPrint(std.testing.allocator, "-----BEGIN {s}-----", .{label});
    defer std.testing.allocator.free(begin);
    const start = (std.mem.indexOf(u8, pem, begin) orelse return error.NoKey) + begin.len;
    const end = std.mem.indexOfPos(u8, pem, start, "-----END") orelse return error.NoKey;
    var buf: [4096]u8 = undefined;
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const n = try decoder.decode(&buf, pem[start..end]);
    var der: []const u8 = buf[0..n];
    if (std.mem.eql(u8, label, "PRIVATE KEY")) {
        // PKCS#8: version, algorithm, then the PKCS#1 key in an OCTET STRING.
        var outer: Der = .{ .bytes = der };
        var info: Der = .{ .bytes = try outer.read(0x30) };
        _ = try info.read(0x02);
        _ = try info.read(0x30);
        der = try info.read(0x04);
    }
    return PrivateKey.fromPkcs1(der);
}

test "rsa: PSS signatures verify with std, for 2048 and 4096-bit keys" {
    const cases = [_]struct { pem: []const u8, label: []const u8, len: usize }{
        .{ .pem = @embedFile("testdata/rsa2048.key"), .label = "PRIVATE KEY", .len = 256 },
        .{ .pem = @embedFile("testdata/rsa4096.rsa.key"), .label = "RSA PRIVATE KEY", .len = 512 },
    };
    for (cases) |case| {
        const key = try testKey(case.pem, case.label);
        try std.testing.expectEqual(case.len, key.len);
        try std.testing.expectEqual(@as(u32, 65537), key.e);
        var out: [max_len]u8 = undefined;
        const long: [300]u8 = @splat('a');
        for ([_][]const u8{ "", "message", &long }, 0..) |msg, i| {
            const sig = try key.sign(msg, @splat(@intCast(i)), &out);
            try verifyWithStd(&key, sig, msg);
            try std.testing.expectError(error.InvalidSignature, verifyWithStd(&key, sig, "other"));
        }
        // A different salt gives a different signature, both valid.
        var out2: [max_len]u8 = undefined;
        const a = try key.sign("m", @splat(1), &out);
        const b = try key.sign("m", @splat(2), &out2);
        try std.testing.expect(!std.mem.eql(u8, a, b));
    }
}

test "rsa: inconsistent and malformed keys are rejected" {
    const pem = @embedFile("testdata/rsa4096.rsa.key");
    const start = std.mem.indexOf(u8, pem, "KEY-----").? + 8;
    const end = std.mem.indexOf(u8, pem, "-----END").?;
    var buf: [4096]u8 = undefined;
    const n = try std.base64.standard.decoderWithIgnore(" \t\r\n").decode(&buf, pem[start..end]);
    _ = try PrivateKey.fromPkcs1(buf[0..n]);
    // Flip a bit in each part after the version: the key check fails, or
    // the part is malformed. The last byte is in qInv.
    var bad = buf;
    bad[n - 1] ^= 1;
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromPkcs1(bad[0..n]));
    bad = buf;
    bad[n - 300] ^= 0x10; // inside dQ
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromPkcs1(bad[0..n]));
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromPkcs1(buf[0 .. n - 1]));
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromPkcs1(""));
}
