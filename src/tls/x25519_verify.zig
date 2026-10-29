//! Adversarial differential checks of field25519 and x25519.sharedSecret:
//! every field operation against an independent u512 reference mod p, on
//! limb patterns at the carry limits and on long chains of operations
//! (each result fed back as an input), and the shared secret against
//! std's X25519. `scale` multiplies the loop counts for long runs.
const std = @import("std");
const field = @import("./field25519.zig");
const x25519 = @import("./x25519.zig");
const Fe = field.Fe;
const X25519 = std.crypto.dh.X25519;
const testing = std.testing;

const p: u256 = (1 << 255) - 19;

fn val(a: Fe) u256 {
    return @bitCast(a.l);
}

fn canon(a: Fe) u256 {
    return std.mem.readInt(u256, &a.toBytes(), .little);
}

fn modp(x: u512) u256 {
    return @intCast(x % p);
}

fn refAdd(a: u256, b: u256) u256 {
    return modp(@as(u512, a) + b);
}
fn refSub(a: u256, b: u256) u256 {
    // a − b mod p, both below 2^256 < 3p.
    return modp(@as(u512, a) + 3 * @as(u512, p) - b);
}
fn refMul(a: u256, b: u256) u256 {
    return modp(@as(u512, a) * b);
}

const limb_patterns = [_]u64{
    0,                     1,                     2,                     18,                    19,
    37,                    38,                    39,                    121665,                121666,
    0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_ffda, 0xffff_ffff_ffff_ffd9, 0xffff_ffff_ffff_ffec,
    0xffff_ffff_ffff_ffed, 0xffff_ffff_ffff_ffee, 0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff, 0x0000_0001_0000_0000,
    0xffff_ffff_0000_0000, 0x0000_0000_ffff_ffff,
};

fn adversarial(r: std.Random) Fe {
    var a: Fe = undefined;
    for (&a.l) |*x| {
        x.* = switch (r.uintLessThan(u8, 4)) {
            0 => r.int(u64),
            1, 2 => limb_patterns[r.uintLessThan(usize, limb_patterns.len)],
            else => limb_patterns[r.uintLessThan(usize, limb_patterns.len)] +% r.uintAtMost(u64, 3) -% r.uintAtMost(u64, 3),
        };
    }
    return a;
}

/// Raise for long runs.
const scale = 1;

fn iters(default: usize) usize {
    return default * scale;
}

fn checkOps(a: Fe, b: Fe) !void {
    const va = val(a);
    const vb = val(b);
    const ra = modp(va);
    try testing.expectEqual(ra, canon(a));
    try testing.expectEqual(refAdd(va, vb), canon(a.add(b)));
    try testing.expectEqual(refSub(va, vb), canon(a.sub(b)));
    try testing.expectEqual(refMul(va, vb), canon(a.mul(b)));
    try testing.expectEqual(refMul(va, va), canon(a.sq()));
    try testing.expectEqual(refAdd(vb, refMul(va, 121666)), canon(a.mulAdd121666(b)));
    const m4 = Fe.mulN(4, .{ a, b, a, b }, .{ b, a, a, b });
    try testing.expectEqual(refMul(va, vb), canon(m4[0]));
    try testing.expectEqual(refMul(va, vb), canon(m4[1]));
    try testing.expectEqual(refMul(va, va), canon(m4[2]));
    try testing.expectEqual(refMul(vb, vb), canon(m4[3]));
    const s2 = Fe.sqN(2, .{ a, b });
    try testing.expectEqual(refMul(va, va), canon(s2[0]));
    try testing.expectEqual(refMul(vb, vb), canon(s2[1]));
    // Canonical output: toBytes below p, top bit clear.
    try testing.expect(canon(a) < p);
}

test "verify: field ops on adversarial limb patterns vs u512 reference" {
    var prng = std.Random.DefaultPrng.init(0xadc0ffee);
    const r = prng.random();
    // Every pair of all-pattern values with equal limbs.
    for (limb_patterns) |x| for (limb_patterns) |y| {
        try checkOps(.{ .l = .{ x, x, x, x } }, .{ .l = .{ y, y, y, y } });
        try checkOps(.{ .l = .{ x, y, y, y } }, .{ .l = .{ y, x, x, x } });
        try checkOps(.{ .l = .{ y, y, y, x } }, .{ .l = .{ x, x, x, y } });
    };
    // Every value in [2^256 − 2^16, 2^256) and [p − 2^10, p + 2^10] and
    // [2^255 − 2^10, 2^255 + 2^10] against a few partners.
    const partners = [_]Fe{ .{ .l = .{ ~@as(u64, 0), ~@as(u64, 0), ~@as(u64, 0), ~@as(u64, 0) } }, .{ .l = .{ 0, 0, 0, 0 } }, .{ .l = .{ 37, 0, 0, 0 } }, .{ .l = .{ 0xffff_ffff_ffff_ffda, ~@as(u64, 0), ~@as(u64, 0), ~@as(u64, 0) } } };
    var i: u256 = 0;
    while (i < (1 << 16)) : (i += 1) {
        const a: Fe = .{ .l = @bitCast(~@as(u256, 0) - i) };
        for (partners) |b| try checkOps(a, b);
    }
    const centres = [_]u256{ p, 1 << 255, 2 * p, 0 };
    for (centres) |c| {
        var d: u256 = 0;
        while (d < 2048) : (d += 1) {
            const a: Fe = .{ .l = @bitCast(c -% 1024 +% d) };
            for (partners) |b| try checkOps(a, b);
        }
    }
    for (0..iters(200_000)) |_| try checkOps(adversarial(r), adversarial(r));
}

test "verify: long chains of field ops, outputs fed back, vs u512 reference" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    for (0..iters(200)) |_| {
        var regs: [6]Fe = undefined;
        var refs: [6]u256 = undefined;
        for (&regs, &refs) |*x, *v| {
            x.* = adversarial(r);
            v.* = modp(val(x.*));
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
                    regs[k] = regs[i].mulAdd121666(regs[j]);
                    refs[k] = refAdd(refs[j], refMul(refs[i], 121666));
                },
                6 => {
                    const m = Fe.mulN(3, .{ regs[i], regs[j], regs[k] }, .{ regs[j], regs[k], regs[i] });
                    const rm = [3]u256{ refMul(refs[i], refs[j]), refMul(refs[j], refs[k]), refMul(refs[k], refs[i]) };
                    regs[i] = m[0];
                    regs[j] = m[1];
                    regs[k] = m[2];
                    refs[i] = rm[0];
                    refs[j] = rm[1];
                    refs[k] = rm[2];
                    if (i == j or j == k or i == k) {
                        // Aliased destinations: recompute the reference
                        // from what was written last.
                        for (&refs, regs) |*v, x| v.* = modp(val(x));
                    }
                },
                7 => {
                    // Push toward the limits: 0 − x, then add maximal.
                    regs[k] = Fe.zero.sub(regs[i]).add(.{ .l = .{ ~@as(u64, 0), ~@as(u64, 0), ~@as(u64, 0), ~@as(u64, 0) } });
                    refs[k] = refAdd(refSub(0, refs[i]), modp(~@as(u256, 0)));
                },
                else => {
                    const c = r.uintLessThan(u64, 2);
                    Fe.cSwap(&regs[i], &regs[j], c);
                    if (c == 1) std.mem.swap(u256, &refs[i], &refs[j]);
                },
            }
            for (regs, refs) |x, v| try testing.expectEqual(v, canon(x));
        }
    }
}

fn expectSameAsStd(sk: [32]u8, u: [32]u8) !void {
    const theirs = X25519.scalarmult(sk, u);
    const ours = x25519.sharedSecret(sk, u);
    if (theirs) |t| {
        const o = ours catch |e| {
            std.debug.print("sk {x} u {x}: std ok, ours {}\n", .{ sk, u, e });
            return error.Mismatch;
        };
        if (!std.mem.eql(u8, &t, &o)) {
            std.debug.print("sk {x} u {x}: std {x} ours {x}\n", .{ sk, u, t, o });
            return error.Mismatch;
        }
    } else |err| try testing.expectError(err, ours);
}

test "verify: x25519 shared secret vs std, random and structured" {
    var prng = std.Random.DefaultPrng.init(0x25519);
    const r = prng.random();
    for (0..iters(20_000)) |n| {
        var sk: [32]u8 = undefined;
        var u: [32]u8 = undefined;
        r.bytes(&sk);
        switch (n % 5) {
            0 => r.bytes(&u),
            1 => {
                const a = adversarial(r);
                inline for (0..4) |i| std.mem.writeInt(u64, u[i * 8 ..][0..8], a.l[i], .little);
            },
            2 => {
                var k = sk;
                k[0] ^= 0x5a;
                u = x25519.publicKey(k);
            },
            3 => {
                // Small u, or u near p and 2^255.
                const v: u256 = switch (r.uintLessThan(u8, 3)) {
                    0 => r.uintLessThan(u256, 1 << 16),
                    1 => p -% 512 +% r.uintLessThan(u256, 1024),
                    else => (1 << 256) -% 1024 +% r.uintLessThan(u256, 1024),
                };
                std.mem.writeInt(u256, &u, v, .little);
            },
            else => {
                r.bytes(&u);
                // Scalars with long runs of equal bits (swap masks stay put
                // or flip every step).
                sk = if (r.boolean()) @splat(if (r.boolean()) 0xff else 0) else @splat(if (r.boolean()) 0x55 else 0xaa);
                sk[r.uintLessThan(usize, 32)] ^= @as(u8, 1) << r.int(u3);
            },
        }
        try expectSameAsStd(sk, u);
    }
}
