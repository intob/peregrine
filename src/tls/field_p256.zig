//! GF(p) for P-256, p = 2^256 − 2^224 + 2^192 + 2^96 − 1, in four 64-bit
//! limbs in the Montgomery domain (R = 2^256), for `p256.zig`'s point
//! arithmetic.
//!
//! std's field (fiat-crypto's word-by-word Montgomery code) multiplies
//! by p's limbs in each of the four reduction steps (12 extra products)
//! and squares with a full multiplication. Here the reduction uses p's
//! shape: p ≡ −1 mod 2^64, so each step's quotient is the low limb q,
//! and q·p + q = q·(2^96 + p3·2^192) with p3 = 2^64 − 2^32 + 1 — one
//! product per step. A square takes 10 products instead of 16. Values
//! stay fully reduced (below p) after every operation, so equality and
//! zero tests read the limbs. Every operation on values is straight-line
//! code: no branches or table lookups on them (`fromBytes`' range check
//! and `eql` are for public values only).
//!
//! `mulN` and `sqN` interleave independent products, as in
//! `field25519.zig`, but unlike X25519's ladder the P-256 point
//! arithmetic on the M2 is limited by instruction throughput (the carry
//! chains), not by dependencies: running the fixed-base and
//! variable-base multiplications interleaved gained nothing. What
//! counted was fewer instructions: one carry chain per reduction step
//! (`qc`), multiplication row by row (CIOS), the dedicated square.
//!
//! Runtime safety is on only in Debug builds (where the tests trap any
//! bound that doesn't hold): elsewhere its overflow checks would be
//! branches on carries of secret values.
const std = @import("std");
const builtin = @import("builtin");

/// Runtime safety for code on secret values: see the top.
pub const safe = builtin.mode == .debug;

const p_int = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
pub const p: u256 = p_int;
const p3: u64 = 0xffffffff00000001;
/// R² mod p: multiplying by it (with a reduction) enters the domain.
const r2: Fe = .{ .l = @bitCast(@as(u256, (1 << 512) % p_int)) };

pub const Fe = struct {
    /// Little-endian limbs of a·R mod p, below p.
    l: [4]u64,

    pub const zero: Fe = .{ .l = .{ 0, 0, 0, 0 } };
    pub const one: Fe = fromInt(1);
    /// The curve's b.
    pub const b: Fe = fromInt(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b);

    /// x (below p) at compile time.
    pub fn fromInt(comptime x: u256) Fe {
        comptime std.debug.assert(x < p);
        return .{ .l = @bitCast(@as(u256, @intCast((@as(u512, x) << 256) % p))) };
    }

    /// Big-endian bytes; `error.NonCanonical` for p and above (as std's
    /// `Fe.fromBytes`). Branches on the range check: for public values.
    pub fn fromBytes(s: [32]u8) error{NonCanonical}!Fe {
        const v = std.mem.readInt(u256, &s, .big);
        if (v >= p) return error.NonCanonical;
        return mul(.{ .l = @bitCast(v) }, r2);
    }

    /// Big-endian bytes of the value.
    pub fn toBytes(a: Fe) [32]u8 {
        var out: [32]u8 = undefined;
        std.mem.writeInt(u256, &out, @bitCast(redc(@as(u256, @bitCast(a.l))).l), .big);
        return out;
    }

    inline fn val(a: Fe) u256 {
        return @bitCast(a.l);
    }

    /// r − p if r ≥ p, for r = c·2^256 + lo below 2p.
    inline fn subP(lo: u256, c: u1) Fe {
        @setRuntimeSafety(safe);
        const d = @subWithOverflow(lo, p);
        // r < p exactly when there is no carry and lo − p borrows.
        const keep: u256 = 0 -% @as(u256, d[1] & ~c);
        return .{ .l = @bitCast((lo & keep) | (d[0] & ~keep)) };
    }

    pub inline fn add(a: Fe, b_: Fe) Fe {
        @setRuntimeSafety(safe);
        const s = @addWithOverflow(a.val(), b_.val());
        return subP(s[0], s[1]);
    }

    pub inline fn sub(a: Fe, b_: Fe) Fe {
        @setRuntimeSafety(safe);
        const d = @subWithOverflow(a.val(), b_.val());
        // A borrow added 2^256: add p back (the sum wraps to a − b + p).
        return .{ .l = @bitCast(d[0] +% (p & (0 -% @as(u256, d[1])))) };
    }

    pub inline fn dbl(a: Fe) Fe {
        return a.add(a);
    }

    /// a/2: (a + p)/2 for an odd a.
    pub inline fn half(a: Fe) Fe {
        @setRuntimeSafety(safe);
        const odd: u256 = a.l[0] & 1;
        return .{ .l = @bitCast(@as(u256, @truncate((@as(u257, a.val()) + (p & (0 -% odd))) >> 1))) };
    }

    pub inline fn neg(a: Fe) Fe {
        return zero.sub(a);
    }

    /// q·p + q = q·(2^96 + p3·2^192), shifted down a limb: q·2^32 +
    /// q·p3·2^128, as four limbs that don't overlap (one carry chain to
    /// add). q·p3 = q·2^64 − q·2^32 + q.
    inline fn qc(q: u64) u256 {
        @setRuntimeSafety(safe);
        const hi: u64 = @intCast((@as(u128, q) * p3) >> 64);
        return @bitCast([4]u64{ q << 32, q >> 32, q -% (q << 32), hi });
    }

    /// Montgomery reduction: t·2^−256 mod p, for t < p·2^256. Four
    /// steps of t = (t + q·p) / 2^64 with q = t mod 2^64: q·p + q drops
    /// the low limb, so a step is t / 2^64 + qc(q).
    inline fn redc(a0: u512) Fe {
        @setRuntimeSafety(safe);
        const a1: u449 = @as(u449, @intCast(a0 >> 64)) + qc(@truncate(a0));
        const a2: u386 = @as(u386, @intCast(a1 >> 64)) + qc(@truncate(a1));
        const a3: u323 = @as(u323, @intCast(a2 >> 64)) + qc(@truncate(a2));
        const a4: u260 = @as(u260, @intCast(a3 >> 64)) + qc(@truncate(a3));
        // Below (t + 2^256·p) / 2^256 < 2p.
        return subP(@truncate(a4), @intCast(a4 >> 256));
    }

    /// a[k]·b[k] for each k, interleaved: row by row, each row a_i·b
    /// added and then one reduction step (CIOS).
    pub inline fn mulN(comptime n: usize, a: [n]Fe, b_: [n]Fe) [n]Fe {
        @setRuntimeSafety(safe);
        // Below 2p after each step: acc + a_i·b < 2^257 + 2^320, and
        // (that + q·p) / 2^64 < 2^257 + p.
        var acc: [n]u322 = @splat(0);
        inline for (0..4) |i| {
            var lo: [n][5]u64 = undefined;
            var hi: [n][5]u64 = undefined;
            inline for (0..4) |j| {
                inline for (0..n) |k| {
                    const pr = @as(u128, a[k].l[i]) * b_[k].l[j];
                    lo[k][j] = @truncate(pr);
                    hi[k][j + 1] = @intCast(pr >> 64);
                }
            }
            inline for (0..n) |k| {
                hi[k][0] = 0;
                lo[k][4] = 0;
                acc[k] += @as(u320, @bitCast(lo[k])) + @as(u320, @bitCast(hi[k]));
                acc[k] = (acc[k] >> 64) + qc(@truncate(acc[k]));
            }
        }
        var out: [n]Fe = undefined;
        inline for (0..n) |k| out[k] = subP(@truncate(acc[k]), @intCast(acc[k] >> 256));
        return out;
    }

    /// a[k]² for each k, interleaved.
    pub inline fn sqN(comptime n: usize, a: [n]Fe) [n]Fe {
        @setRuntimeSafety(safe);
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
                const pr = @as(u128, a[k].l[0]) * a[k].l[j];
                lo[k][j] = @truncate(pr);
                hi[k][j + 1] = @intCast(pr >> 64);
            }
        }
        // a_1·a_j at word 1 + j, and a_2·a_3 at word 5.
        inline for (2..4) |j| {
            inline for (0..n) |k| {
                const pr = @as(u128, a[k].l[1]) * a[k].l[j];
                lo2[k][1 + j] = @truncate(pr);
                hi2[k][2 + j] = @intCast(pr >> 64);
            }
        }
        inline for (0..n) |k| p23[k] = @as(u128, a[k].l[2]) * a[k].l[3];
        inline for (0..4) |i| {
            inline for (0..n) |k| {
                const pr = @as(u128, a[k].l[i]) * a[k].l[i];
                s[k][2 * i] = @truncate(pr);
                s[k][2 * i + 1] = @intCast(pr >> 64);
            }
        }
        var out: [n]Fe = undefined;
        inline for (0..n) |k| {
            const c0 = @as(u448, @bitCast(lo[k])) + @as(u448, @bitCast(hi[k]));
            const c1 = @as(u448, @bitCast(lo2[k])) + @as(u448, @bitCast(hi2[k])) + (@as(u448, p23[k]) << 320);
            // The cross products sum to below 2^511, and with the squares
            // to below 2^512: neither wraps.
            const cross = (@as(u512, c0) + @as(u512, c1)) << 1;
            out[k] = redc(cross + @as(u512, @bitCast(s[k])));
        }
        return out;
    }

    pub inline fn mul(a: Fe, b_: Fe) Fe {
        return mulN(1, .{a}, .{b_})[0];
    }

    pub inline fn sq(a: Fe) Fe {
        return sqN(1, .{a})[0];
    }

    fn sqn(a: Fe, n: usize) Fe {
        var r = a;
        for (0..n) |_| r = r.sq();
        return r;
    }

    /// a^(p − 3) = 1/a², or 0 for 0: Brian Smith's addition chain (as in
    /// BoringSSL's `fiat_p256_inv_square`), 255 squares and 11
    /// multiplications. 1/a² is what affine x = X/Z² needs.
    pub fn invSquare(a: Fe) Fe {
        const x2 = a.sq().mul(a); // 2^2 − 1
        const x3 = x2.sq().mul(a); // 2^3 − 1
        const x6 = x3.sqn(3).mul(x3); // 2^6 − 1
        const x12 = x6.sqn(6).mul(x6); // 2^12 − 1
        const x15 = x12.sqn(3).mul(x3); // 2^15 − 1
        const x30 = x15.sqn(15).mul(x15); // 2^30 − 1
        const x32 = x30.sqn(2).mul(x2); // 2^32 − 1
        var r = x32.sqn(32).mul(a); // 2^64 − 2^32 + 1
        r = r.sqn(128).mul(x32); // 2^192 − 2^160 + 2^128 + 2^32 − 1
        r = r.sqn(32).mul(x32); // 2^224 − 2^192 + 2^160 + 2^64 − 1
        r = r.sqn(30).mul(x30); // 2^254 − 2^222 + 2^190 + 2^94 − 1
        return r.sqn(2); // 2^256 − 2^224 + 2^192 + 2^96 − 4 = p − 3
    }

    /// 1/a, or 0 for 0.
    pub fn invert(a: Fe) Fe {
        return a.invSquare().mul(a);
    }

    /// 1 if a is zero, else 0, in constant time.
    pub inline fn isZero(a: Fe) u64 {
        const x = a.l[0] | a.l[1] | a.l[2] | a.l[3];
        return ((x | (0 -% x)) >> 63) ^ 1;
    }

    /// For public values.
    pub fn eql(a: Fe, b_: Fe) bool {
        return a.val() == b_.val();
    }

    /// a = b if c is 1 (c is 0 or 1), in constant time.
    pub inline fn cMov(a: *Fe, b_: Fe, c: u64) void {
        const mask = 0 -% c;
        inline for (0..4) |i| a.l[i] ^= (a.l[i] ^ b_.l[i]) & mask;
    }
};

const testing = std.testing;
const StdFe = std.crypto.ecc.P256.Fe;

fn toStd(a: Fe) StdFe {
    return StdFe.fromBytes(a.toBytes(), .big) catch unreachable;
}

/// Checks every operation on a and b against std's field.
fn expectOpsMatch(a: Fe, b: Fe) !void {
    const sa = toStd(a);
    const sb = toStd(b);
    try testing.expectEqualSlices(u8, &sa.add(sb).toBytes(.big), &a.add(b).toBytes());
    try testing.expectEqualSlices(u8, &sa.sub(sb).toBytes(.big), &a.sub(b).toBytes());
    try testing.expectEqualSlices(u8, &sa.neg().toBytes(.big), &a.neg().toBytes());
    try testing.expectEqualSlices(u8, &sa.dbl().toBytes(.big), &a.dbl().toBytes());
    try testing.expectEqualSlices(u8, &sa.toBytes(.big), &a.half().dbl().toBytes());
    try testing.expectEqualSlices(u8, &sa.mul(sb).toBytes(.big), &a.mul(b).toBytes());
    try testing.expectEqualSlices(u8, &sa.sq().toBytes(.big), &a.sq().toBytes());
    const three = Fe.mulN(3, .{ a, b, a }, .{ b, b, a });
    try testing.expectEqualSlices(u8, &sa.mul(sb).toBytes(.big), &three[0].toBytes());
    try testing.expectEqualSlices(u8, &sb.sq().toBytes(.big), &three[1].toBytes());
    try testing.expectEqualSlices(u8, &sa.sq().toBytes(.big), &three[2].toBytes());
    const two = Fe.sqN(2, .{ b, a });
    try testing.expectEqualSlices(u8, &sb.sq().toBytes(.big), &two[0].toBytes());
    try testing.expectEqualSlices(u8, &sa.sq().toBytes(.big), &two[1].toBytes());
    try testing.expectEqual(@intFromBool(sa.isZero()), a.isZero());
    var x = a;
    x.cMov(b, 0);
    try testing.expectEqual(a, x);
    x.cMov(b, 1);
    try testing.expectEqual(b, x);
    // Results stay below p (in the domain): every limb pattern the
    // operations return is a valid input.
    for ([_]Fe{ a.add(b), a.sub(b), a.mul(b), a.sq(), a.neg(), a.half() }) |r| try testing.expect(r.val() < p);
}

/// Values at the edges of what the limbs hold (all below p).
pub const edge_values = [_]u256{
    0,
    1,
    2,
    p - 1,
    p - 2,
    (1 << 255),
    (1 << 224),
    (1 << 192),
    (1 << 96),
    (1 << 64) - 1,
    (1 << 128) - 1,
    (1 << 192) - 1,
    p - (1 << 64),
    p - (1 << 96),
    (1 << 256) - (1 << 224),
    0xffffffff_00000000_ffffffff_ffffffff_00000000_ffffffff_ffffffff_ffffffff,
};

/// Field elements whose Montgomery limbs are v (below p).
fn raw(v: u256) Fe {
    return .{ .l = @bitCast(v) };
}

test "field_p256: every operation equals std's, on edge and random values" {
    for (edge_values) |x| {
        for (edge_values) |y| try expectOpsMatch(raw(x), raw(y));
    }
    var prng = std.Random.DefaultPrng.init(0x256f);
    const random = prng.random();
    for (0..2000) |_| {
        var a: Fe = .{ .l = @bitCast(random.uintLessThan(u256, p)) };
        var b: Fe = .{ .l = @bitCast(random.uintLessThan(u256, p)) };
        try expectOpsMatch(a, b);
        // Limbs of all ones or zeros, kept below p.
        for (&a.l, &b.l) |*x, *y| {
            if (random.boolean()) x.* = if (random.boolean()) 0 else std.math.maxInt(u64);
            if (random.boolean()) y.* = if (random.boolean()) 0 else std.math.maxInt(u64);
        }
        if (a.val() >= p) a.l[3] = 0;
        if (b.val() >= p) b.l[3] = 0;
        try expectOpsMatch(a, b);
    }
    // Inversion, and the encodings.
    for (0..100) |_| {
        const a: Fe = .{ .l = @bitCast(random.uintLessThan(u256, p)) };
        try testing.expectEqualSlices(u8, &toStd(a).invert().toBytes(.big), &a.invert().toBytes());
        try testing.expectEqualSlices(u8, &toStd(a).invert().sq().toBytes(.big), &a.invSquare().toBytes());
        var bytes: [32]u8 = undefined;
        random.bytes(&bytes);
        if (StdFe.fromBytes(bytes, .big)) |s| {
            try testing.expectEqualSlices(u8, &s.toBytes(.big), &(try Fe.fromBytes(bytes)).toBytes());
        } else |err| try testing.expectError(err, Fe.fromBytes(bytes));
    }
    try testing.expectEqual(Fe.zero, Fe.zero.invert());
    try testing.expectEqual(Fe.one, Fe.one.invert());
    var pb: [32]u8 = undefined;
    std.mem.writeInt(u256, &pb, p, .big);
    try testing.expectError(error.NonCanonical, Fe.fromBytes(pb));
    std.mem.writeInt(u256, &pb, p - 1, .big);
    try testing.expectEqualSlices(u8, &pb, &(try Fe.fromBytes(pb)).toBytes());
    try testing.expectEqualSlices(u8, &std.crypto.ecc.P256.B.toBytes(.big), &Fe.b.toBytes());
}

// Fuzz target: field operations on any two values below p equal std's.
fn fuzzField(_: void, smith: *std.testing.Smith) anyerror!void {
    var a: Fe = undefined;
    var b: Fe = undefined;
    smith.bytes(std.mem.asBytes(&a.l));
    smith.bytes(std.mem.asBytes(&b.l));
    // Reduce into the domain's range the way a value could be: below p.
    if (a.val() >= p) a = raw(a.val() - p);
    if (b.val() >= p) b = raw(b.val() - p);
    try expectOpsMatch(a, b);
}

test "fuzz: field_p256 against std" {
    try std.testing.fuzz({}, fuzzField, .{ .corpus = &.{
        std.mem.asBytes(&raw(p - 1).l) ++ std.mem.asBytes(&raw((1 << 256) - (1 << 224)).l),
    } });
}
