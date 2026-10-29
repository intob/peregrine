//! GF(2^255 − 19) in four 64-bit limbs, for the X25519 shared secret's
//! Montgomery ladder (`x25519.zig`).
//!
//! std's field (radix 2^51, five limbs) needs 25 64×64-bit products per
//! multiplication; here it is 16, plus 4 to fold the high half back with
//! 2^256 ≡ 38. Values are kept below 2^256, not reduced mod p: additions
//! and subtractions fold their carry or borrow (twice, the second time
//! into the low limb only, which can't carry), and only `toBytes` reduces
//! fully. Every operation is straight-line code: no branches or table
//! lookups on the values.
//!
//! The ladder is latency-bound, not multiplier-bound: on the M2 its speed
//! depended more on the order of the step's operations than on the field
//! code. `mulN` and `sqN` interleave independent products stage by stage,
//! which helps the CPU overlap them.
//!
//! Runtime safety is off in every function: its overflow checks would be
//! branches on carries of secret values (never taken, since the bounds
//! hold, but branches all the same); the tests check the bounds against
//! std's field and a u512 reference.
const std = @import("std");

pub const Fe = struct {
    /// Little-endian: the value is l[0] + l[1]·2^64 + l[2]·2^128 + l[3]·2^192.
    l: [4]u64,

    pub const zero: Fe = .{ .l = .{ 0, 0, 0, 0 } };
    pub const one: Fe = .{ .l = .{ 1, 0, 0, 0 } };

    /// RFC 7748 §5: the top bit is ignored; values from p to 2^255 − 1
    /// (non-canonical) are accepted as they are.
    pub fn fromBytes(s: [32]u8) Fe {
        @setRuntimeSafety(false);
        var l: [4]u64 = undefined;
        inline for (0..4) |i| l[i] = std.mem.readInt(u64, s[i * 8 ..][0..8], .little);
        l[3] &= 0x7fff_ffff_ffff_ffff;
        return .{ .l = l };
    }

    /// The canonical encoding (fully reduced mod p).
    pub fn toBytes(a: Fe) [32]u8 {
        @setRuntimeSafety(false);
        var l = a.l;
        // Fold bit 255 (2^255 ≡ 19): v < 2^255 + 19.
        const top = l[3] >> 63;
        l[3] &= 0x7fff_ffff_ffff_ffff;
        const v = @as(u256, @bitCast(l)) + top * 19;
        // v ≥ p exactly when v + 19 reaches 2^255; then v − p < 38.
        const t = v + 19;
        const ge = t >> 255;
        const mask = 0 -% ge;
        const r: [4]u64 = @bitCast((v & ~mask) | ((t - (ge << 255)) & mask));
        var out: [32]u8 = undefined;
        inline for (0..4) |i| std.mem.writeInt(u64, out[i * 8 ..][0..8], r[i], .little);
        return out;
    }

    pub inline fn add(a: Fe, b: Fe) Fe {
        @setRuntimeSafety(false);
        const s = @addWithOverflow(@as(u256, @bitCast(a.l)), @as(u256, @bitCast(b.l)));
        // 2^256 ≡ 38. If this carries too, the low limb is below 38.
        const t = @addWithOverflow(s[0], @as(u256, s[1]) * 38);
        var r: [4]u64 = @bitCast(t[0]);
        r[0] += @as(u64, t[1]) * 38;
        return .{ .l = r };
    }

    pub inline fn sub(a: Fe, b: Fe) Fe {
        @setRuntimeSafety(false);
        const s = @subWithOverflow(@as(u256, @bitCast(a.l)), @as(u256, @bitCast(b.l)));
        // A borrow added 2^256; take 38 back. If this borrows too, the low
        // limb is at least 2^64 − 38.
        const t = @subWithOverflow(s[0], @as(u256, s[1]) * 38);
        var r: [4]u64 = @bitCast(t[0]);
        r[0] -= @as(u64, t[1]) * 38;
        return .{ .l = r };
    }

    /// b + 121666·a (the ladder's a24 term, as in std's ladder).
    pub inline fn mulAdd121666(a: Fe, b: Fe) Fe {
        @setRuntimeSafety(false);
        var lo: [5]u64 = undefined;
        var hi: [5]u64 = undefined;
        hi[0] = 0;
        lo[4] = 0;
        inline for (0..4) |i| {
            const p = @as(u128, a.l[i]) * 121666;
            lo[i] = @truncate(p);
            hi[i + 1] = @intCast(p >> 64);
        }
        const r = @as(u320, @bitCast(lo)) + @as(u320, @bitCast(hi)) + @as(u256, @bitCast(b.l));
        return fold(r);
    }

    /// r mod 2^256 + 38·(r >> 256), for r < 2^320 with a small top limb.
    inline fn fold(r: u320) Fe {
        @setRuntimeSafety(false);
        const c: u64 = @truncate(r >> 256);
        const s = @addWithOverflow(@as(u256, @truncate(r)), @as(u256, c * 38));
        var o: [4]u64 = @bitCast(s[0]);
        o[0] += @as(u64, s[1]) * 38;
        return .{ .l = o };
    }

    /// t_lo + 38·t_hi for n 512-bit products: the multiplications by 38
    /// first, then the carry chains.
    inline fn reduceN(comptime n: usize, t: [n][8]u64) [n]Fe {
        @setRuntimeSafety(false);
        var lo: [n][5]u64 = undefined;
        var hi: [n][5]u64 = undefined;
        inline for (0..4) |i| {
            inline for (0..n) |k| {
                const p = @as(u128, t[k][i + 4]) * 38;
                lo[k][i] = @truncate(p);
                hi[k][i + 1] = @intCast(p >> 64);
            }
        }
        var out: [n]Fe = undefined;
        inline for (0..n) |k| {
            hi[k][0] = 0;
            lo[k][4] = 0;
            // Below 39·2^256, so the top limb is at most 38.
            const low: u256 = @bitCast(t[k][0..4].*);
            out[k] = fold(@as(u320, low) + @as(u320, @bitCast(lo[k])) + @as(u320, @bitCast(hi[k])));
        }
        return out;
    }

    /// a[k]·b[k] for each k, interleaved.
    pub inline fn mulN(comptime n: usize, a: [n]Fe, b: [n]Fe) [n]Fe {
        @setRuntimeSafety(false);
        // Row i of each product is a_i·b: its low and high words.
        var lo: [n][4][5]u64 = undefined;
        var hi: [n][4][5]u64 = undefined;
        inline for (0..4) |i| {
            inline for (0..4) |j| {
                inline for (0..n) |k| {
                    const p = @as(u128, a[k].l[i]) * b[k].l[j];
                    lo[k][i][j] = @truncate(p);
                    hi[k][i][j + 1] = @intCast(p >> 64);
                }
            }
        }
        var rows: [n][4]u320 = undefined;
        inline for (0..4) |i| {
            inline for (0..n) |k| {
                hi[k][i][0] = 0;
                lo[k][i][4] = 0;
                rows[k][i] = @as(u320, @bitCast(lo[k][i])) + @as(u320, @bitCast(hi[k][i]));
            }
        }
        // The rows summed as a tree, for shorter carry chains.
        var t: [n][8]u64 = undefined;
        inline for (0..n) |k| {
            const r01 = @as(u384, rows[k][0]) + (@as(u384, rows[k][1]) << 64);
            const r23 = @as(u384, rows[k][2]) + (@as(u384, rows[k][3]) << 64);
            t[k] = @bitCast(@as(u512, r01) + (@as(u512, r23) << 128));
        }
        return reduceN(n, t);
    }

    /// a[k]² for each k, interleaved.
    pub inline fn sqN(comptime n: usize, a: [n]Fe) [n]Fe {
        @setRuntimeSafety(false);
        // The cross products a_i·a_j (i < j) in two groups of rows, then
        // doubled; then the squares a_i².
        var lo: [n][7]u64 = undefined;
        var hi: [n][7]u64 = undefined;
        var lo2: [n][7]u64 = undefined;
        var hi2: [n][7]u64 = undefined;
        var p23: [n]u128 = undefined;
        var s: [n][8]u64 = undefined;
        inline for (0..n) |k| {
            lo[k] = @splat(0);
            hi[k] = @splat(0);
            lo2[k] = @splat(0);
            hi2[k] = @splat(0);
        }
        // a_0·a_j at word j.
        inline for (1..4) |j| {
            inline for (0..n) |k| {
                const p = @as(u128, a[k].l[0]) * a[k].l[j];
                lo[k][j] = @truncate(p);
                hi[k][j + 1] = @intCast(p >> 64);
            }
        }
        // a_1·a_j at word 1 + j, and a_2·a_3 at word 5.
        inline for (2..4) |j| {
            inline for (0..n) |k| {
                const p = @as(u128, a[k].l[1]) * a[k].l[j];
                lo2[k][1 + j] = @truncate(p);
                hi2[k][2 + j] = @intCast(p >> 64);
            }
        }
        inline for (0..n) |k| p23[k] = @as(u128, a[k].l[2]) * a[k].l[3];
        inline for (0..4) |i| {
            inline for (0..n) |k| {
                const p = @as(u128, a[k].l[i]) * a[k].l[i];
                s[k][2 * i] = @truncate(p);
                s[k][2 * i + 1] = @intCast(p >> 64);
            }
        }
        var t: [n][8]u64 = undefined;
        inline for (0..n) |k| {
            const c0 = @as(u448, @bitCast(lo[k])) + @as(u448, @bitCast(hi[k]));
            const c1 = @as(u448, @bitCast(lo2[k])) + @as(u448, @bitCast(hi2[k])) + (@as(u448, p23[k]) << 320);
            // The cross products sum to below 2^511, and with the squares
            // to below 2^512: neither wraps.
            const cross = (@as(u512, c0) + @as(u512, c1)) << 1;
            t[k] = @bitCast(cross + @as(u512, @bitCast(s[k])));
        }
        return reduceN(n, t);
    }

    pub inline fn mul(a: Fe, b: Fe) Fe {
        @setRuntimeSafety(false);
        return mulN(1, .{a}, .{b})[0];
    }

    pub inline fn sq(a: Fe) Fe {
        @setRuntimeSafety(false);
        return sqN(1, .{a})[0];
    }

    fn sqn(a: Fe, n: usize) Fe {
        @setRuntimeSafety(false);
        var r = a;
        for (0..n) |_| r = r.sq();
        return r;
    }

    /// a^(p − 2): 1/a, or 0 for 0 (std's addition chain).
    pub fn invert(a: Fe) Fe {
        @setRuntimeSafety(false);
        var t0 = a.sq();
        var t1 = t0.sqn(2).mul(a);
        t0 = t0.mul(t1);
        t1 = t1.mul(t0.sq());
        t1 = t1.mul(t1.sqn(5));
        var t2 = t1.sqn(10).mul(t1);
        t2 = t2.mul(t2.sqn(20)).sqn(10);
        t1 = t1.mul(t2);
        t2 = t1.sqn(50).mul(t1);
        return t1.mul(t2.mul(t2.sqn(100)).sqn(50)).sqn(5).mul(t0);
    }

    /// a = b if c is 1 (c is 0 or 1), in constant time.
    pub inline fn cMov(a: *Fe, b: Fe, c: u64) void {
        @setRuntimeSafety(false);
        const mask = 0 -% c;
        inline for (0..4) |i| a.l[i] ^= (a.l[i] ^ b.l[i]) & mask;
    }

    /// Swaps a and b if c is 1 (c is 0 or 1), in constant time.
    pub inline fn cSwap(a: *Fe, b: *Fe, c: u64) void {
        @setRuntimeSafety(false);
        const mask = 0 -% c;
        inline for (0..4) |i| {
            const x = (a.l[i] ^ b.l[i]) & mask;
            a.l[i] ^= x;
            b.l[i] ^= x;
        }
    }
};

const testing = std.testing;
const StdFe = std.crypto.ecc.Curve25519.Fe;

/// A value below 2^256 as std's field element (std's limbs take 255 bits:
/// fold the top bit).
fn toStd(a: Fe) StdFe {
    var bytes: [32]u8 = undefined;
    inline for (0..4) |i| std.mem.writeInt(u64, bytes[i * 8 ..][0..8], a.l[i], .little);
    const top = bytes[31] >> 7;
    var r = StdFe.fromBytes(bytes);
    if (top == 1) r = r.add(StdFe{ .limbs = .{ 19, 0, 0, 0, 0 } });
    return r;
}

/// Checks every operation on a and b against std's field.
fn expectOpsMatch(a: Fe, b: Fe) !void {
    const sa = toStd(a);
    const sb = toStd(b);
    try testing.expectEqualSlices(u8, &sa.toBytes(), &a.toBytes());
    try testing.expectEqualSlices(u8, &sa.add(sb).toBytes(), &a.add(b).toBytes());
    try testing.expectEqualSlices(u8, &sa.sub(sb).toBytes(), &a.sub(b).toBytes());
    try testing.expectEqualSlices(u8, &sa.mul(sb).toBytes(), &a.mul(b).toBytes());
    try testing.expectEqualSlices(u8, &sa.sq().toBytes(), &a.sq().toBytes());
    try testing.expectEqualSlices(u8, &sb.add(sa.mul32(121666)).toBytes(), &a.mulAdd121666(b).toBytes());
    const three = Fe.mulN(3, .{ a, b, a }, .{ b, b, a });
    try testing.expectEqualSlices(u8, &sa.mul(sb).toBytes(), &three[0].toBytes());
    try testing.expectEqualSlices(u8, &sb.sq().toBytes(), &three[1].toBytes());
    try testing.expectEqualSlices(u8, &sa.sq().toBytes(), &three[2].toBytes());
    const two = Fe.sqN(2, .{ b, a });
    try testing.expectEqualSlices(u8, &sb.sq().toBytes(), &two[0].toBytes());
    try testing.expectEqualSlices(u8, &sa.sq().toBytes(), &two[1].toBytes());
    var x = a;
    var y = b;
    Fe.cSwap(&x, &y, 0);
    try testing.expectEqual(a, x);
    Fe.cSwap(&x, &y, 1);
    try testing.expectEqual(b, x);
    try testing.expectEqual(a, y);
    x.cMov(a, 0);
    try testing.expectEqual(b, x);
    x.cMov(a, 1);
    try testing.expectEqual(a, x);
    // Results of every operation stay valid inputs.
    try testing.expectEqualSlices(u8, &sa.sub(sb).mul(sa.add(sb)).toBytes(), &a.sub(b).mul(a.add(b)).toBytes());
}

/// Field elements at the edges of what the limbs hold.
const edge_values = [_][4]u64{
    .{ 0, 0, 0, 0 },
    .{ 1, 0, 0, 0 },
    .{ 18, 0, 0, 0 },
    .{ 19, 0, 0, 0 },
    .{ 37, 0, 0, 0 },
    .{ 38, 0, 0, 0 },
    // p − 1, p, p + 1
    .{ 0xffff_ffff_ffff_ffec, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff },
    .{ 0xffff_ffff_ffff_ffed, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff },
    .{ 0xffff_ffff_ffff_ffee, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff },
    // 2^255 − 1, 2^255, 2p − 1, 2p = 2^256 − 38, 2^256 − 1
    .{ 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff },
    .{ 0, 0, 0, 0x8000_0000_0000_0000 },
    .{ 0xffff_ffff_ffff_ffd9, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff },
    .{ 0xffff_ffff_ffff_ffda, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff },
    .{ 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff },
    .{ 0, 0xffff_ffff_ffff_ffff, 0, 0xffff_ffff_ffff_ffff },
    .{ 0xffff_ffff_ffff_ffff, 0, 0xffff_ffff_ffff_ffff, 0 },
};

test "field25519: every operation equals std's, on edge and random values" {
    for (edge_values) |x| {
        for (edge_values) |y| try expectOpsMatch(.{ .l = x }, .{ .l = y });
    }
    var prng = std.Random.DefaultPrng.init(0x2551);
    const random = prng.random();
    for (0..2000) |_| {
        var a: Fe = undefined;
        var b: Fe = undefined;
        random.bytes(std.mem.asBytes(&a.l));
        random.bytes(std.mem.asBytes(&b.l));
        try expectOpsMatch(a, b);
        // Values made mostly of all-ones or zero limbs.
        for (&a.l, &b.l) |*x, *y| {
            if (random.boolean()) x.* = if (random.boolean()) 0 else std.math.maxInt(u64);
            if (random.boolean()) y.* = if (random.boolean()) 0 else std.math.maxInt(u64);
        }
        try expectOpsMatch(a, b);
    }
    // Inversion, and the encodings.
    for (0..100) |_| {
        var a: Fe = undefined;
        random.bytes(std.mem.asBytes(&a.l));
        try testing.expectEqualSlices(u8, &toStd(a).invert().toBytes(), &a.invert().toBytes());
        var bytes: [32]u8 = undefined;
        random.bytes(&bytes);
        try testing.expectEqualSlices(u8, &StdFe.fromBytes(bytes).toBytes(), &Fe.fromBytes(bytes).toBytes());
    }
    try testing.expectEqualSlices(u8, &Fe.zero.toBytes(), &Fe.zero.invert().toBytes());
}

// Fuzz target: field operations on any 64 bytes equal std's.
fn fuzzField(_: void, smith: *std.testing.Smith) anyerror!void {
    var a: Fe = undefined;
    var b: Fe = undefined;
    smith.bytes(std.mem.asBytes(&a.l));
    smith.bytes(std.mem.asBytes(&b.l));
    try expectOpsMatch(a, b);
}

test "fuzz: field25519 against std" {
    try std.testing.fuzz({}, fuzzField, .{ .corpus = &.{
        std.mem.asBytes(&edge_values[6]) ++ std.mem.asBytes(&edge_values[13]),
    } });
}
