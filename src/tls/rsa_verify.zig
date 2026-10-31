//! Checks of rsa.zig's signing beyond its own tests: known answers
//! (NIST CAVP's RSASSA-PSS SHA-256 vectors, and rsa_pss_vectors.py's for
//! the sizes and shapes NIST doesn't have), std's PSS verifier, and the
//! std.crypto.ff implementation it replaced (`Reference`, kept as it was
//! for these tests and for `zig build bench-tls -- handshake`): the same
//! signatures byte for byte on every test key, also with p and q
//! swapped, and raw inputs (0, 1, p, q and their neighbours, multiples of
//! p and q, n − 1, random) checked with std.crypto.ff's public-exponent
//! power. Faults injected into the CRT parts are caught by the check in
//! `sign`. `scale` multiplies the loop counts for long runs.
const std = @import("std");
const rsa = @import("./rsa.zig");
const ff = std.crypto.ff;
const Sha256 = std.crypto.hash.sha2.Sha256;
const testing = std.testing;

const scale = 1;

const max_bits = rsa.max_bits;
const max_len = rsa.max_len;
const min_bits = rsa.min_bits;
const salt_len = rsa.salt_len;
const Error = rsa.Error;
const Der = rsa.Der;
const Modulus = ff.Modulus(max_bits);
const Half = ff.Modulus(max_bits / 2);
const Uint = ff.Uint(max_bits);

/// rsa.zig's PrivateKey before 2026-10-31: the CRT over std.crypto.ff.
pub const Reference = struct {
    n: Modulus,
    /// The modulus length in bytes (the signature length).
    len: usize,
    /// Big-endian, `len` bytes (for matching the certificate).
    n_bytes: [max_len]u8,
    e: u32,
    p: Half,
    q: Half,
    /// q as an element mod n (for recombining the halves).
    q_n: Modulus.Fe,
    q_inv: Half.Fe,
    /// d mod (p − 1) and d mod (q − 1), big-endian, padded to the length
    /// of p and q so the exponentiation time doesn't depend on them.
    dp: [max_len / 2]u8,
    dq: [max_len / 2]u8,
    p_len: usize,
    q_len: usize,

    /// PKCS#1 RSAPrivateKey (RFC 8017 A.1.2), two primes.
    pub fn fromPkcs1(der: []const u8) Error!Reference {
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

        var key: Reference = undefined;
        key.n = Modulus.fromBytes(n, .big) catch return error.InvalidKey;
        const bits = key.n.bits();
        if (bits < min_bits or bits > max_bits) return error.UnsupportedKey;
        key.len = n.len;
        @memcpy(key.n_bytes[0..n.len], n);
        key.e = 0;
        for (e) |b| key.e = key.e << 8 | b;
        if (key.e < 3 or key.e & 1 == 0) return error.InvalidKey;
        key.p = Half.fromBytes(p, .big) catch return error.InvalidKey;
        key.q = Half.fromBytes(q, .big) catch return error.InvalidKey;
        key.p_len = p.len;
        key.q_len = q.len;
        key.q_n = Modulus.Fe.fromBytes(key.n, q, .big) catch return error.InvalidKey;
        key.q_inv = Half.Fe.fromBytes(key.p, q_inv, .big) catch return error.InvalidKey;
        if (dp.len > p.len or dq.len > q.len) return error.InvalidKey;
        key.dp = @splat(0);
        key.dq = @splat(0);
        @memcpy(key.dp[p.len - dp.len ..][0..dp.len], dp);
        @memcpy(key.dq[q.len - dq.len ..][0..dq.len], dq);
        // The parts must make a working key: a signature that verifies.
        var sig: [max_len]u8 = undefined;
        _ = key.sign("key check", @splat(0), &sig) catch return error.InvalidKey;
        return key;
    }

    /// The public exponent, big-endian, without leading zeros.
    pub fn exponent(self: *const Reference, buf: *[4]u8) []const u8 {
        std.mem.writeInt(u32, buf, self.e, .big);
        var i: usize = 0;
        while (buf[i] == 0) i += 1;
        return buf[i..];
    }

    pub fn modulus(self: *const Reference) []const u8 {
        return self.n_bytes[0..self.len];
    }

    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt.
    pub fn sign(self: *const Reference, msg: []const u8, salt: [salt_len]u8, out: *[max_len]u8) Error![]const u8 {
        const k = self.len;
        var em_buf: [max_len]u8 = @splat(0);
        const em = em_buf[0..k];
        rsa.encodePss(em, self.n.bits() - 1, msg, &salt);
        const s = out[0..k];
        try self.privateOp(em, s);
        // s^e must give the encoded message back.
        const sv = Modulus.Fe.fromBytes(self.n, s, .big) catch return error.SignatureFault;
        var e_buf: [4]u8 = undefined;
        const back = self.n.powWithEncodedPublicExponent(sv, self.exponent(&e_buf), .big) catch return error.SignatureFault;
        var check: [max_len]u8 = undefined;
        back.toBytes(check[0..k], .big) catch return error.SignatureFault;
        if (!std.mem.eql(u8, check[0..k], em)) {
            @memset(s, 0);
            return error.SignatureFault;
        }
        return s;
    }

    /// s = m^d mod n by the CRT: m^dp mod p and m^dq mod q, recombined
    /// as m2 + q · (q⁻¹ (m1 − m2) mod p).
    pub fn privateOp(self: *const Reference, m: []const u8, s: []u8) Error!void {
        const mu = Uint.fromBytes(m, .big) catch return error.SignatureFault;
        const m1 = self.p.powWithEncodedExponent(self.p.reduce(mu), self.dp[0..self.p_len], .big) catch return error.SignatureFault;
        const m2 = self.q.powWithEncodedExponent(self.q.reduce(mu), self.dq[0..self.q_len], .big) catch return error.SignatureFault;
        const h = self.p.mul(self.q_inv, self.p.sub(m1, self.p.reduce(m2.v)));
        var buf: [max_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &buf);
        h.toBytes(buf[0..self.len], .big) catch return error.SignatureFault;
        const h_n = Modulus.Fe.fromBytes(self.n, buf[0..self.len], .big) catch return error.SignatureFault;
        m2.toBytes(buf[0..self.len], .big) catch return error.SignatureFault;
        const m2_n = Modulus.Fe.fromBytes(self.n, buf[0..self.len], .big) catch return error.SignatureFault;
        const sv = self.n.add(self.n.mul(h_n, self.q_n), m2_n);
        sv.toBytes(s, .big) catch return error.SignatureFault;
    }
};

/// The PKCS#1 key in a PEM "RSA PRIVATE KEY" or "PRIVATE KEY" (PKCS#8)
/// block, as DER in `buf` (for the tests and the benchmark;
/// credentials.zig does the real loading).
pub fn pemToPkcs1(buf: []u8, pem: []const u8) ![]const u8 {
    const start = (std.mem.indexOf(u8, pem, "KEY-----") orelse return error.NoKey) + 8;
    const end = std.mem.indexOfPos(u8, pem, start, "-----END") orelse return error.NoKey;
    var der: []const u8 = buf[0..try std.base64.standard.decoderWithIgnore(" \t\r\n").decode(buf, pem[start..end])];
    if (std.mem.indexOf(u8, pem, "BEGIN PRIVATE KEY") != null) {
        // PKCS#8: version, algorithm, then the PKCS#1 key in an OCTET STRING.
        var outer: Der = .{ .bytes = der };
        var info: Der = .{ .bytes = try outer.read(0x30) };
        _ = try info.read(0x02);
        _ = try info.read(0x30);
        der = try info.read(0x04);
    }
    std.mem.copyForwards(u8, buf[0..der.len], der);
    return buf[0..der.len];
}

// -- Tests ------------------------------------------------------------

const rsa_std = std.crypto.Certificate.rsa;

/// Debug builds run the arithmetic about 100 times slower (half a second
/// per RSA-4096 signature): there, keys of 2400 bits and more (the
/// RSA-3072 and RSA-4096 shapes) get one signature against the reference
/// (none in the known answers), the raw inputs 0, 1, p, q and n − 1, two
/// of the faults, and aren't swapped. Release builds run everything.
const light = @import("builtin").mode == .debug;
const vectors = @embedFile("testdata/rsa_pss_vectors.txt");

/// std's PSS verifier, for moduli whose length in bits isn't 1 mod 8
/// (for those the encoded message is a byte shorter than the modulus,
/// and std's verifier asserts that it isn't: 2049 and 3073 bits here).
fn verifyWithStd(key: *const rsa.PrivateKey, sig: []const u8, msg: []const u8) !void {
    if (key.bits % 8 == 1) return;
    var e_buf: [4]u8 = undefined;
    const pk = try rsa_std.PublicKey.fromBytes(key.exponent(&e_buf), key.modulus());
    switch (sig.len) {
        inline 256, 257, 384, 385, 506, 512 => |len| try rsa_std.PSSSignature.verify(len, sig[0..len], msg, pk, Sha256),
        else => return error.UnexpectedLength,
    }
}

/// A PKCS#1 key's integers (without leading zeros).
const Parts = struct {
    n: []const u8,
    e: []const u8,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    q_inv: []const u8,

    fn parse(der: []const u8) !Parts {
        var outer: Der = .{ .bytes = der };
        var seq: Der = .{ .bytes = try outer.read(0x30) };
        _ = try seq.integer();
        var r: Parts = undefined;
        inline for (.{ "n", "e", "d", "p", "q", "dp", "dq", "q_inv" }) |f| @field(r, f) = try seq.integer();
        return r;
    }
};

/// DER for a PKCS#1 key from its integers.
fn encodeKey(buf: []u8, k: Parts) []const u8 {
    var body: [4096]u8 = undefined;
    var len: usize = 3;
    body[0..3].* = .{ 2, 1, 0 }; // version 0
    inline for (.{ "n", "e", "d", "p", "q", "dp", "dq", "q_inv" }) |f| {
        const v = @field(k, f);
        const pad: usize = if (v.len > 0 and v[0] & 0x80 != 0) 1 else 0;
        const l = v.len + pad;
        body[len] = 2;
        len += 1;
        if (l < 0x80) {
            body[len] = @intCast(l);
            len += 1;
        } else {
            body[len..][0..3].* = .{ 0x82, @intCast(l >> 8), @truncate(l) };
            len += 3;
        }
        if (pad == 1) body[len] = 0;
        len += pad;
        @memcpy(body[len..][0..v.len], v);
        len += v.len;
    }
    buf[0..4].* = .{ 0x30, 0x82, @intCast(len >> 8), @truncate(len) };
    @memcpy(buf[4..][0..len], body[0..len]);
    return buf[0 .. 4 + len];
}

/// The key with p and q exchanged: dP and dQ too, and p⁻¹ mod q as the
/// new qInv (q is prime: p^(q − 2) mod q, by std.crypto.ff).
fn swapped(buf: []u8, der: []const u8) ![]const u8 {
    const k = try Parts.parse(der);
    const q = try Half.fromBytes(k.q, .big);
    const p_mod_q = q.reduce(try ff.Uint(max_bits / 2).fromBytes(k.p, .big));
    var exp: [max_len / 2]u8 = undefined;
    const e = exp[0..k.q.len];
    @memcpy(e, k.q);
    var borrow: u16 = 2;
    var i = e.len;
    while (i > 0 and borrow != 0) {
        i -= 1;
        const v = @as(i16, e[i]) - @as(i16, @intCast(borrow));
        e[i] = @intCast(@mod(v, 256));
        borrow = if (v < 0) 1 else 0;
    }
    const inv = try q.powWithEncodedExponent(p_mod_q, e, .big);
    var inv_buf: [max_len / 2]u8 = undefined;
    try inv.toBytes(inv_buf[0..k.q.len], .big);
    var inv_bytes: []const u8 = inv_buf[0..k.q.len];
    while (inv_bytes.len > 0 and inv_bytes[0] == 0) inv_bytes = inv_bytes[1..];
    return encodeKey(buf, .{ .n = k.n, .e = k.e, .d = k.d, .p = k.q, .q = k.p, .dp = k.dq, .dq = k.dp, .q_inv = inv_bytes });
}

/// Whether `Reference` can load the key. std.crypto.ff's `reduce` takes
/// an integer of at least the modulus's limb count minus one (63-bit
/// limbs): with fewer, its copy loop counts below zero. The reference's
/// `p.reduce(m2)` (m2 mod q) hits that when q has fewer limbs than p, as
/// in two of the unbalanced test keys: in Debug and ReleaseSafe a panic
/// at key load, in ReleaseFast undefined behaviour. rsa.zig before
/// 2026-10-31 had the bug; the new code reduces with `redc`.
fn referenceWorks(der: []const u8) !bool {
    const k = try Parts.parse(der);
    const limbs = struct {
        fn of(v: []const u8) usize {
            return (8 * v.len - @clz(v[0]) + 62) / 63;
        }
    }.of;
    return limbs(k.q) >= limbs(k.p);
}

fn hex(buf: []u8, s: []const u8) ![]const u8 {
    if (std.mem.eql(u8, s, "-")) return buf[0..0];
    return std.fmt.hexToBytes(buf, s);
}

/// The test keys: those in rsa_pss_vectors.txt and testdata's PEM files,
/// as DER (in `store`).
fn testKeys(store: *[24][2600]u8, lens: *[24]usize) !usize {
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, vectors, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "key ")) continue;
        lens[count] = (try std.fmt.hexToBytes(&store[count], line[4..])).len;
        count += 1;
    }
    for ([_][]const u8{ @embedFile("testdata/rsa2048.key"), @embedFile("testdata/rsa4096.rsa.key") }) |pem| {
        lens[count] = (try pemToPkcs1(&store[count], pem)).len;
        count += 1;
    }
    return count;
}

test "rsa: known answers (NIST CAVP SigGenPSS SHA-256, rsa_pss_vectors.py)" {
    var key: rsa.PrivateKey = undefined;
    var ref: ?Reference = null;
    var keys: usize = 0;
    var sigs: usize = 0;
    var lines = std.mem.splitScalar(u8, vectors, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "key ")) {
            var der: [2600]u8 = undefined;
            const d = try std.fmt.hexToBytes(&der, line[4..]);
            key = try rsa.PrivateKey.fromPkcs1(d);
            const big = light and key.len > 300;
            ref = if (!big and try referenceWorks(d)) try Reference.fromPkcs1(d) else null;
            keys += 1;
        } else if (std.mem.startsWith(u8, line, "pss ")) {
            var fields = std.mem.splitScalar(u8, line[4..], ' ');
            var salt_buf: [64]u8 = undefined;
            var msg_buf: [512]u8 = undefined;
            var want_buf: [max_len]u8 = undefined;
            const salt = try hex(&salt_buf, fields.next().?);
            const msg = try hex(&msg_buf, fields.next().?);
            const want = try hex(&want_buf, fields.next().?);
            try testing.expectEqual(key.len, want.len);
            var out: [max_len]u8 = undefined;
            if (salt.len == rsa.salt_len) {
                try testing.expectEqualSlices(u8, want, try key.sign(msg, salt[0..rsa.salt_len].*, &out));
                if (ref) |*r| try testing.expectEqualSlices(u8, want, try r.sign(msg, salt[0..rsa.salt_len].*, &out));
                try verifyWithStd(&key, want, msg);
            } else {
                // NIST's 2048-bit vectors have a 20-byte salt: encode, then
                // the private operation.
                var em: [max_len]u8 = undefined;
                rsa.encodePss(em[0..key.len], key.bits - 1, msg, salt);
                key.privateOp(em[0..key.len], out[0..key.len]);
                try testing.expectEqualSlices(u8, want, out[0..key.len]);
            }
            sigs += 1;
        }
    }
    try testing.expectEqual(@as(usize, 18), keys);
    try testing.expectEqual(@as(usize, 68), sigs);
}

/// s^e mod n by std.crypto.ff.
fn publicOp(der: []const u8, s: []const u8, out: []u8) !void {
    const k = try Parts.parse(der);
    const n = try Modulus.fromBytes(k.n, .big);
    const back = try n.powWithEncodedPublicExponent(try Modulus.Fe.fromBytes(n, s, .big), k.e, .big);
    try back.toBytes(out, .big);
}

/// x·f + c (f small) as `out.len` big-endian bytes, or null if it doesn't fit.
fn mulSmall(out: []u8, x: []const u8, f: u16, c: i16) ?[]const u8 {
    var carry: i32 = c;
    var i = out.len;
    var j = x.len;
    while (i > 0) {
        i -= 1;
        var v: i32 = carry;
        if (j > 0) {
            j -= 1;
            v += @as(i32, x[j]) * f;
        }
        out[i] = @intCast(@mod(v, 256));
        carry = @divFloor(v, 256);
    }
    if (carry != 0 or j > 0) return null;
    return out;
}

test "rsa: the same as the std.crypto.ff implementation, many keys, also with p and q swapped" {
    var store: [24][2600]u8 = undefined;
    var lens: [24]usize = undefined;
    const count = try testKeys(&store, &lens);
    var prng = std.Random.DefaultPrng.init(0x727361);
    const rand = prng.random();
    var checked: usize = 0;
    var skipped: usize = 0;
    for (0..count) |i| {
        var swap_buf: [2600]u8 = undefined;
        const big = light and (try Parts.parse(store[i][0..lens[i]])).n.len > 300;
        const variants = [_][]const u8{ store[i][0..lens[i]], try swapped(&swap_buf, store[i][0..lens[i]]) };
        for (variants[0..if (big) 1 else 2]) |der| {
            const key = try rsa.PrivateKey.fromPkcs1(der);
            const ref: ?Reference = if (try referenceWorks(der)) try Reference.fromPkcs1(der) else null;
            if (ref == null) skipped += 1;
            const k = key.len;
            // Signatures, byte for byte.
            for (0..@as(usize, if (big) 1 else 2) * scale) |_| {
                var msg: [200]u8 = undefined;
                const m = msg[0..rand.uintAtMost(usize, msg.len)];
                rand.bytes(m);
                var salt: [rsa.salt_len]u8 = undefined;
                rand.bytes(&salt);
                var a: [max_len]u8 = undefined;
                var b: [max_len]u8 = undefined;
                const sig = try key.sign(m, salt, &a);
                if (ref) |*r| try testing.expectEqualSlices(u8, try r.sign(m, salt, &b), sig);
                try verifyWithStd(&key, a[0..k], m);
            }
            // Raw inputs below n: s^e must give them back (std.crypto.ff).
            const parts = try Parts.parse(der);
            var inputs: [24][max_len]u8 = undefined;
            var n_inputs: usize = 0;
            const factors = [_]struct { u16, i16 }{ .{ 1, 0 }, .{ 1, -1 }, .{ 1, 1 }, .{ 2, 0 }, .{ 3, 0 }, .{ 255, 7 }, .{ 65535, 0 } };
            for ([_][]const u8{ parts.p, parts.q }) |f| {
                for (factors[0..if (big) 1 else factors.len]) |c| {
                    if (mulSmall(inputs[n_inputs][0..k], f, c[0], c[1])) |_| {
                        // Keep it only if below n.
                        if (std.mem.order(u8, inputs[n_inputs][0..k], parts.n) == .lt) n_inputs += 1;
                    }
                }
            }
            const smalls = [_]i16{ 0, 1, 2 };
            for (smalls[0..if (big) 2 else 3]) |c| {
                _ = mulSmall(inputs[n_inputs][0..k], &.{}, 0, c).?;
                n_inputs += 1;
            }
            _ = mulSmall(inputs[n_inputs][0..k], parts.n, 1, -1).?;
            n_inputs += 1;
            for (0..scale) |_| {
                for (0..@as(usize, if (big) 0 else 2)) |_| {
                    rand.bytes(inputs[n_inputs][0..k]);
                    inputs[n_inputs][0] = 0;
                    n_inputs += 1;
                }
                for (inputs[0..n_inputs]) |*in| {
                    var s: [max_len]u8 = undefined;
                    key.privateOp(in[0..k], s[0..k]);
                    var back: [max_len]u8 = undefined;
                    try publicOp(der, s[0..k], back[0..k]);
                    try testing.expectEqualSlices(u8, in[0..k], back[0..k]);
                    checked += 1;
                }
                if (!big) n_inputs -= 2;
            }
        }
    }
    try testing.expectEqual(@as(usize, 20), count);
    // See referenceWorks: RSA-2048 unbalanced (p > q, and p < q swapped),
    // the 256-bit p swapped, RSA-4048 swapped (not in light builds).
    try testing.expectEqual(@as(usize, if (light) 3 else 4), skipped);
    // 20 raw inputs per key and round (18 edges, 2 random); light builds
    // give the 9 keys of 2400 bits and more 5 and no swapped twin.
    try testing.expectEqual(@as(usize, if (light) 22 * 20 + 9 * 5 else 40 * 20) * scale, checked);
}

test "rsa: a fault in the CRT is caught, and nothing is returned" {
    var store: [24][2600]u8 = undefined;
    var lens: [24]usize = undefined;
    const count = try testKeys(&store, &lens);
    for (store[0..count], lens[0..count]) |*der, len| {
        const good = try rsa.PrivateKey.fromPkcs1(der[0..len]);
        for (0..@as(usize, if (light and good.len > 300) 2 else 5)) |fault| {
            var key = good;
            switch (key.crt) {
                inline else => |*crt| switch (fault) {
                    0 => crt.q_inv[0] ^= 1,
                    1 => key.dq[key.q_len - 1] ^= 1,
                    2 => crt.q.m[1] ^= 4,
                    3 => crt.p.m0inv ^= 1 << 40,
                    else => crt.p.r2[1] ^= 1 << 7,
                },
            }
            var out: [max_len]u8 = @splat(0xaa);
            try testing.expectError(error.SignatureFault, key.sign("message", @splat(3), &out));
            try testing.expect(std.mem.allEqual(u8, out[0..key.len], 0));
        }
    }
}
