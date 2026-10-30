//! Adversarial differential checks of field_p256 and p256: every field
//! operation against an independent u512 reference mod p (on the
//! Montgomery representatives, with R⁻¹ as a constant), on limb patterns
//! at the carry and reduction limits and on long chains of operations
//! (each result fed back as an input); and the shared secret, key pairs
//! and key shares against std's P256 on structured scalars and points.
//! `scale` multiplies the loop counts for long runs.
const std = @import("std");
const field = @import("./field_p256.zig");
const p256 = @import("./p256.zig");
const Fe = field.Fe;
const P256 = std.crypto.ecc.P256;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const testing = std.testing;

const p: u256 = field.p;
const n: u256 = p256.n;
/// 2^−256 mod p.
const r_inv: u256 = blk: {
    @setEvalBranchQuota(100_000);
    // p is prime: a^(p − 2) = 1/a, by square and multiply.
    const pc: comptime_int = p;
    const base: comptime_int = (1 << 256) % pc;
    var e: comptime_int = pc - 2;
    var b: comptime_int = base;
    var r: comptime_int = 1;
    while (e > 0) : (e >>= 1) {
        if (e & 1 == 1) r = r * b % pc;
        b = b * b % pc;
    }
    break :blk r;
};
const inv2: u256 = (p + 1) / 2;

fn val(a: Fe) u256 {
    return @bitCast(a.l);
}

fn modp(x: u512) u256 {
    return @intCast(x % p);
}

fn refAdd(a: u256, b: u256) u256 {
    return modp(@as(u512, a) + b);
}
fn refSub(a: u256, b: u256) u256 {
    return modp(@as(u512, a) + p - b);
}
/// The Montgomery product a·b·2^−256.
fn refMul(a: u256, b: u256) u256 {
    return modp(@as(u512, modp(@as(u512, a) * b)) * r_inv);
}

const limb_patterns = [_]u64{
    0,                     1,                     2,                     3,
    0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff,
    0x0000_0001_0000_0000, 0x0000_0000_ffff_ffff, 0xffff_ffff_0000_0000, 0xffff_ffff_0000_0001,
    0x0000_0000_ffff_fffe, 0xffff_fffe_ffff_ffff, 0x0000_0001_ffff_ffff, 0xffff_ffff_0000_0002,
    0xfffe_ffff_ffff_ffff, 0x8000_0000_0000_0001,
};

/// A value below p made of limb patterns (the field's inputs are below p).
fn adversarial(r: std.Random) Fe {
    var l: [4]u64 = undefined;
    for (&l) |*x| {
        x.* = switch (r.uintLessThan(u8, 4)) {
            0 => r.int(u64),
            1, 2 => limb_patterns[r.uintLessThan(usize, limb_patterns.len)],
            else => limb_patterns[r.uintLessThan(usize, limb_patterns.len)] +% r.uintAtMost(u64, 3) -% r.uintAtMost(u64, 3),
        };
    }
    var v: u256 = @bitCast(l);
    if (v >= p) v = if (r.boolean()) v - p else p - 1 - (v - p) % p;
    return .{ .l = @bitCast(v) };
}

/// Raise for long runs.
const scale = 1;

fn iters(default: usize) usize {
    return default * scale;
}

fn expectBelowP(a: Fe) !void {
    if (val(a) >= p) {
        std.debug.print("not reduced: {x}\n", .{val(a)});
        return error.NotReduced;
    }
}

fn checkOps(a: Fe, b: Fe) !void {
    const va = val(a);
    const vb = val(b);
    const results = [_]struct { Fe, u256 }{
        .{ a.add(b), refAdd(va, vb) },
        .{ a.sub(b), refSub(va, vb) },
        .{ a.dbl(), refAdd(va, va) },
        .{ a.neg(), refSub(0, va) },
        .{ a.half(), modp(@as(u512, va) * inv2) },
        .{ a.mul(b), refMul(va, vb) },
        .{ a.sq(), refMul(va, va) },
    };
    for (results, 0..) |res, i| {
        if (val(res[0]) != res[1]) {
            std.debug.print("op {} on {x}, {x}: {x}, expected {x}\n", .{ i, va, vb, val(res[0]), res[1] });
            return error.Mismatch;
        }
    }
    const m4 = Fe.mulN(4, .{ a, b, a, b }, .{ b, a, a, b });
    try testing.expectEqual(refMul(va, vb), val(m4[0]));
    try testing.expectEqual(refMul(va, vb), val(m4[1]));
    try testing.expectEqual(refMul(va, va), val(m4[2]));
    try testing.expectEqual(refMul(vb, vb), val(m4[3]));
    const s3 = Fe.sqN(3, .{ a, b, a });
    try testing.expectEqual(refMul(va, va), val(s3[0]));
    try testing.expectEqual(refMul(vb, vb), val(s3[1]));
    try testing.expectEqual(refMul(va, va), val(s3[2]));
    try testing.expectEqual(@as(u64, @intFromBool(va == 0)), a.isZero());
    // The encoding is the represented value, a·2^−256.
    try testing.expectEqual(modp(@as(u512, va) * r_inv), std.mem.readInt(u256, &a.toBytes(), .big));
}

test "verify: field_p256 ops on adversarial limb patterns vs u512 reference" {
    var prng = std.Random.DefaultPrng.init(0x9256);
    const r = prng.random();
    // Every pair of values made of one or two patterns (reduced below p).
    for (limb_patterns) |x| for (limb_patterns) |y| {
        const vals = [_]u256{ @bitCast([4]u64{ x, x, x, x }), @bitCast([4]u64{ x, y, y, y }), @bitCast([4]u64{ y, y, y, x }), @bitCast([4]u64{ x, y, x, y }) };
        for (vals) |v1| for (vals) |v2| {
            try checkOps(.{ .l = @bitCast(v1 % p) }, .{ .l = @bitCast(v2 % p) });
        };
    };
    // Every value in [p − 2^11, p), [0, 2^11), and around 2^255, 2^224,
    // 2^192, 2^96, 2^256 − 2^224 and R mod p, against a few partners.
    const partners = [_]Fe{ .{ .l = @bitCast(p - 1) }, .{ .l = .{ 0, 0, 0, 0 } }, .{ .l = .{ 1, 0, 0, 0 } }, .{ .l = @bitCast(@as(u256, 1 << 255)) }, Fe.one, .{ .l = @bitCast(p - (1 << 224)) } };
    const centres = [_]u256{ p, 0, 1 << 255, 1 << 224, 1 << 192, 1 << 96, 1 << 64, (1 << 256) - (1 << 224), (0 -% p), p - (1 << 192), p >> 1 };
    for (centres) |c| {
        var d: u256 = 0;
        while (d < (1 << 12)) : (d += 1) {
            const v = c -% (1 << 11) +% d;
            if (v >= p) continue;
            for (partners) |b| try checkOps(.{ .l = @bitCast(v) }, b);
        }
    }
    for (0..iters(30_000)) |_| try checkOps(adversarial(r), adversarial(r));
    // Inversion, on patterns too.
    for (0..iters(300)) |_| {
        const a = adversarial(r);
        const va = val(a);
        const want: u256 = if (va == 0) 0 else Fe.one.l[0] | (@as(u256, Fe.one.l[1]) << 64) | (@as(u256, Fe.one.l[2]) << 128) | (@as(u256, Fe.one.l[3]) << 192);
        try testing.expectEqual(want, refMul(refMul(val(a.invSquare()), va), va));
        try testing.expectEqual(want, refMul(val(a.invert()), va));
    }
}

test "verify: long chains of field_p256 ops, outputs fed back, vs u512 reference" {
    var prng = std.Random.DefaultPrng.init(0x5eed256);
    const r = prng.random();
    for (0..iters(200)) |_| {
        var regs: [6]Fe = undefined;
        var refs: [6]u256 = undefined;
        for (&regs, &refs) |*x, *v| {
            x.* = adversarial(r);
            v.* = val(x.*);
        }
        for (0..5000) |_| {
            const i = r.uintLessThan(usize, 6);
            const j = r.uintLessThan(usize, 6);
            const k = r.uintLessThan(usize, 6);
            switch (r.uintLessThan(u8, 9)) {
                0 => {
                    regs[k] = regs[i].add(regs[j]);
                    refs[k] = refAdd(refs[i], refs[j]);
                },
                1, 2 => {
                    regs[k] = regs[i].sub(regs[j]);
                    refs[k] = refSub(refs[i], refs[j]);
                },
                3 => {
                    regs[k] = regs[i].mul(regs[j]);
                    refs[k] = refMul(refs[i], refs[j]);
                },
                4 => {
                    regs[k] = regs[i].sq();
                    refs[k] = refMul(refs[i], refs[i]);
                },
                5 => {
                    regs[k] = regs[i].half();
                    refs[k] = modp(@as(u512, refs[i]) * inv2);
                },
                6 => {
                    const m = Fe.mulN(3, .{ regs[i], regs[j], regs[k] }, .{ regs[j], regs[k], regs[i] });
                    const rm = [3]u256{ refMul(refs[i], refs[j]), refMul(refs[j], refs[k]), refMul(refs[k], refs[i]) };
                    if (i == j or j == k or i == k) {
                        // Aliased destinations: keep what was written last.
                        regs[i] = m[0];
                        refs[i] = rm[0];
                        regs[j] = m[1];
                        refs[j] = rm[1];
                        regs[k] = m[2];
                        refs[k] = rm[2];
                    } else {
                        regs[i], regs[j], regs[k] = m;
                        refs[i], refs[j], refs[k] = rm;
                    }
                },
                7 => {
                    // Push toward the limits: 0 − x, then add p − 1.
                    regs[k] = regs[i].neg().add(.{ .l = @bitCast(p - 1) });
                    refs[k] = refAdd(refSub(0, refs[i]), p - 1);
                },
                else => {
                    const c = r.uintLessThan(u64, 2);
                    regs[k].cMov(regs[i], c);
                    if (c == 1) refs[k] = refs[i];
                },
            }
            for (regs, refs) |x, v| {
                try expectBelowP(x);
                try testing.expectEqual(v, val(x));
            }
        }
    }
}

const le = p256.le;
const be = p256.be;

/// A peer key on the curve: k × G, or a point whose x is made of limb
/// patterns (when x³ − 3x + b is a square), or a small multiple of G.
fn peerKey(r: std.Random) [65]u8 {
    switch (r.uintLessThan(u8, 3)) {
        0 => {
            while (true) {
                const fx = P256.Fe.fromBytes(adversarial(r).toBytes(), .big) catch continue;
                const y = P256.recoverY(fx, r.boolean()) catch continue;
                return (P256{ .x = fx, .y = y }).toUncompressedSec1();
            }
        },
        1 => return (P256.basePoint.mul(le(r.uintAtMost(u256, 64) + 1), .little) catch unreachable).toUncompressedSec1(),
        else => return (P256.basePoint.mul(le(r.uintLessThan(u256, n - 1) + 1), .little) catch unreachable).toUncompressedSec1(),
    }
}

/// A scalar with structure: around n and its multiples' wraps, long runs
/// of equal digits, a flipped bit, or random.
fn structuredScalar(r: std.Random) u256 {
    return switch (r.uintLessThan(u8, 6)) {
        0 => n -% r.uintAtMost(u256, 40) +% r.uintAtMost(u256, 40),
        1 => r.uintAtMost(u256, 1 << 12),
        2 => @as(u256, 0) -% r.uintAtMost(u256, 1 << 12),
        3 => blk: {
            const pat = [_]u8{ 0x00, 0xff, 0x88, 0x77, 0x55, 0xaa, 0x80, 0x7f, 0x08, 0xf8 };
            var b: [32]u8 = @splat(pat[r.uintLessThan(usize, pat.len)]);
            b[r.uintLessThan(usize, 32)] ^= @as(u8, 1) << r.int(u3);
            break :blk std.mem.readInt(u256, &b, .little);
        },
        4 => (0 -% n) *% r.uintAtMost(u256, 3) +% r.uintAtMost(u256, 16) -% 8,
        else => r.int(u256),
    };
}

test "verify: p256 shared secret, key pairs and key shares vs std, random and structured" {
    var prng = std.Random.DefaultPrng.init(0x256256);
    const r = prng.random();
    for (0..iters(4000)) |i| {
        const s = structuredScalar(r);
        const pk = peerKey(r);
        try p256.expectSameAsStd(be(s), &pk);
        // The fixed base, for the same scalar.
        const ours = p256.publicKey(be(s));
        if (P256.basePoint.mul(be(s), .big)) |t| {
            try testing.expectEqualSlices(u8, &t.toUncompressedSec1(), &try ours);
        } else |err| try testing.expectError(err, ours);
        if (i % 8 == 0) {
            // Both sides of an exchange.
            var seed: [32]u8 = undefined;
            r.bytes(&seed);
            const a = try p256.keyShare(seed, &pk);
            const kp = try p256.keyPair(seed);
            const kp_std = try Ecdsa.KeyPair.generateDeterministic(seed);
            try testing.expectEqualSlices(u8, &kp_std.public_key.toUncompressedSec1(), &a.public_key);
            try testing.expectEqualSlices(u8, &kp.public_key, &a.public_key);
            try testing.expectEqualSlices(u8, &try p256.sharedSecret(kp.secret_key, &pk), &a.shared_secret);
        }
    }
}
