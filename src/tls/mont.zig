//! Fixed-size Montgomery arithmetic for RSA (`rsa.zig`): integers of
//! `n` 64-bit limbs, little-endian, modulo an odd m below R = 2^(64n).
//! RSA-2048's CRT halves are 16 limbs, RSA-3072's 24 and RSA-4096's 32.
//!
//! std.crypto.ff is generic over the size at run time, in 63-bit limbs
//! (17 for 1024 bits), with loops it can't unroll. Here the size is
//! known at compile time: each row of products is unrolled and summed
//! with one carry chain per half (see `row`). Multiplication goes row by
//! row with the reduction in each row (2n² products); squaring computes
//! each cross product once (about n²/2 + 1.5n products, plus n² for the
//! reduction); exponentiation is a fixed 5-bit window. On the M2, 1024
//! bits: a multiplication 200 ns, a square 175 ns, an exponentiation
//! with a 1024-bit exponent 232 µs (std.crypto.ff: about 520 µs).
//!
//! Everything on values is constant time: no branches or memory indices
//! depend on them. The final subtraction and the window's table lookup
//! select with masks that go through an empty asm barrier (as in
//! `field_p256.zig`: LLVM turns masked selections into selects, and on
//! x86_64 below v3 those into branches). Lengths (the limb count, the
//! exponent's byte length) are public. Runtime safety is on only in
//! Debug builds, where the tests trap any bound that doesn't hold:
//! elsewhere its overflow checks would branch on secret carries.
const std = @import("std");
const builtin = @import("builtin");

/// Runtime safety for code on secret values: see the top.
pub const safe = builtin.mode == .debug;

/// Bits per window of the exponentiation: 16 squarings per 5 bits, 1 in
/// 5 multiplications by a table entry, 32 entries scanned per lookup.
pub const window = 5;

/// 0 − bit (all ones for 1) for a bit that may be secret, hidden from
/// the optimizer behind an empty asm.
const mask = @import("./field_p256.zig").Fe.mask64;

/// d = a − b over n limbs; the borrow out.
inline fn subBorrow(comptime n: usize, a: *const [n]u64, b: *const [n]u64, d: *[n]u64) u1 {
    @setRuntimeSafety(safe);
    var borrow: u1 = 0;
    for (0..n) |i| {
        const s1 = @subWithOverflow(a[i], b[i]);
        const s2 = @subWithOverflow(s1[0], borrow);
        d[i] = s2[0];
        borrow = s1[1] | s2[1];
    }
    return borrow;
}

/// 1 if a == b, else 0, without a branch.
inline fn eqBit(a: u64, b: u64) u64 {
    const x = a ^ b;
    return ((x | (0 -% x)) >> 63) ^ 1;
}

pub fn Mont(comptime n: usize) type {
    return struct {
        const Self = @This();
        pub const limbs = n;
        pub const Int = [n]u64;
        pub const Wide = [2 * n]u64;

        m: Int,
        /// −m⁻¹ mod 2^64.
        m0inv: u64,
        /// R mod m: 1 in the Montgomery domain.
        one: Int,
        /// R² mod m: a Montgomery multiplication by it enters the domain.
        r2: Int,

        /// For an odd m (which may be secret: constant time in its value).
        pub fn init(m: Int) Self {
            @setRuntimeSafety(safe);
            std.debug.assert(m[0] & 1 == 1);
            // m⁻¹ mod 2^64 by Newton's iteration: each step doubles the
            // correct low bits (m·m ≡ 1 mod 8 for odd m: 3 bits to start).
            var inv: u64 = m[0];
            for (0..5) |_| inv *%= 2 -% m[0] *% inv;
            var self: Self = .{ .m = m, .m0inv = 0 -% inv, .one = undefined, .r2 = undefined };
            // R mod m and R² mod m by doubling from 1, 64n times each.
            var x: Int = @splat(0);
            x[0] = 1;
            x = self.reduceOnce(x, 0);
            for (0..64 * n) |_| x = self.dbl(&x);
            self.one = x;
            for (0..64 * n) |_| x = self.dbl(&x);
            self.r2 = x;
            return self;
        }

        /// a − m if a + c·R ≥ m, else a, for a + c·R below 2m.
        inline fn reduceOnce(self: *const Self, a: Int, c: u64) Int {
            @setRuntimeSafety(safe);
            var d: Int = undefined;
            const borrow = subBorrow(n, &a, &self.m, &d);
            // a + c·R < m exactly when there is no carry and a − m borrows.
            const keep = mask(borrow & ~c & 1);
            var r: Int = undefined;
            for (0..n) |i| r[i] = (a[i] & keep) | (d[i] & ~keep);
            return r;
        }

        /// 2a mod m, for a below m.
        fn dbl(self: *const Self, a: *const Int) Int {
            @setRuntimeSafety(safe);
            var s: Int = undefined;
            var c: u64 = 0;
            for (0..n) |i| {
                s[i] = a[i] << 1 | c;
                c = a[i] >> 63;
            }
            return self.reduceOnce(s, c);
        }

        /// a − b mod m, for a and b below m.
        pub fn sub(self: *const Self, a: *const Int, b: *const Int) Int {
            @setRuntimeSafety(safe);
            var d: Int = undefined;
            const borrow = subBorrow(n, a, b, &d);
            // A borrow added R: add m back (the sum wraps to a − b + m).
            const add_m = mask(borrow);
            var c: u1 = 0;
            for (0..n) |i| {
                const s1 = @addWithOverflow(d[i], self.m[i] & add_m);
                const s2 = @addWithOverflow(s1[0], c);
                d[i] = s2[0];
                c = s1[1] | s2[1];
            }
            return d;
        }

        /// Up to 32 limbs, the products of a row are summed as two
        /// integers of n + 2 limbs (`row`), which LLVM adds with one carry
        /// chain each (adcs on aarch64); beyond that it handles such wide
        /// integers badly (30x slower at 64 limbs), and `mulCios` is used.
        const rows = n <= 32;
        const Acc = @Int(.unsigned, 64 * (n + 2));

        /// Σ a[j]·b·2^(64j) for j in from..to, as the sum of two integers:
        /// the products' low halves and their high halves a limb up.
        inline fn row(comptime from: usize, comptime to: usize, a: anytype, b: u64) Acc {
            @setRuntimeSafety(safe);
            var lo: [n + 2]u64 = @splat(0);
            var hi: [n + 2]u64 = @splat(0);
            inline for (from..to) |j| {
                const p = @as(u128, a[j]) * b;
                lo[j] = @truncate(p);
                hi[j + 1] = @intCast(p >> 64);
            }
            return @as(Acc, @bitCast(lo)) + @as(Acc, @bitCast(hi));
        }

        /// a·b·R⁻¹ mod m, for a below R and b below m (a·b/R + m < 2m
        /// before the final subtraction). Row by row with the reduction
        /// in each: t = (t + a·b[i] + u·m) / 2^64 with u chosen to clear
        /// the low limb; t stays below R + m.
        pub fn mul(self: *const Self, a: *const Int, b: *const Int) Int {
            @setRuntimeSafety(safe);
            if (!rows) return self.mulCios(a, b);
            var t: Acc = 0;
            for (0..n) |i| {
                t += row(0, n, a, b[i]);
                const u = @as(u64, @truncate(t)) *% self.m0inv;
                t += row(0, n, &self.m, u);
                t >>= 64;
            }
            const l: [n + 2]u64 = @bitCast(t);
            return self.reduceOnce(l[0..n].*, l[n]);
        }

        /// `mul` limb by limb (CIOS: two carry chains through each row),
        /// for more than 32 limbs.
        pub fn mulCios(self: *const Self, a: *const Int, b: *const Int) Int {
            @setRuntimeSafety(safe);
            var t: Int = @splat(0);
            var t_hi: u64 = 0; // t's bit 64n (0 or 1)
            for (0..n) |i| {
                const bi = b[i];
                var x: u128 = @as(u128, a[0]) * bi + t[0];
                var c1: u64 = @intCast(x >> 64);
                const u = @as(u64, @truncate(x)) *% self.m0inv;
                var y: u128 = @as(u128, u) * self.m[0] + @as(u64, @truncate(x));
                var c2: u64 = @intCast(y >> 64);
                for (1..n) |j| {
                    x = @as(u128, a[j]) * bi + t[j] + c1;
                    c1 = @intCast(x >> 64);
                    y = @as(u128, u) * self.m[j] + @as(u64, @truncate(x)) + c2;
                    c2 = @intCast(y >> 64);
                    t[j - 1] = @truncate(y);
                }
                const s: u128 = @as(u128, t_hi) + c1 + c2;
                t[n - 1] = @truncate(s);
                t_hi = @intCast(s >> 64);
            }
            return self.reduceOnce(t, t_hi);
        }

        /// a²·R⁻¹ mod m, for a below m: `mul`'s rows, but row i adds
        /// a[i]·(a[i]·2^(64i) + 2·Σ_{j>i} a[j]·2^(64j)), so each cross
        /// product is computed once (n(n + 1)/2 + n products instead of
        /// n², plus n² for the reduction).
        pub fn sqr(self: *const Self, a: *const Int) Int {
            @setRuntimeSafety(safe);
            @setEvalBranchQuota(20 * n * n);
            if (!rows) return self.mulCios(a, a);
            // 2a, limb by limb (d[n] is its top bit).
            var d: [n + 1]u64 = undefined;
            d[0] = a[0] << 1;
            inline for (1..n) |j| d[j] = a[j] << 1 | a[j - 1] >> 63;
            d[n] = a[n - 1] >> 63;
            var t: Acc = 0;
            inline for (0..n) |i| {
                // Row i's multiplier limbs from i up: a[i], then those of
                // 2a without a[i]'s top bit (a[i]² isn't doubled).
                var w: [n + 1]u64 = d;
                w[i] = a[i];
                if (i + 1 < n) w[i + 1] = a[i + 1] << 1;
                t += row(i, if (i + 1 < n) n + 1 else n, &w, a[i]);
                const u = @as(u64, @truncate(t)) *% self.m0inv;
                t += row(0, n, &self.m, u);
                t >>= 64;
            }
            const l: [n + 2]u64 = @bitCast(t);
            return self.reduceOnce(l[0..n].*, l[n]);
        }

        /// t·R⁻¹ mod m, for t below m·R.
        pub fn redc(self: *const Self, t_in: *const Wide) Int {
            @setRuntimeSafety(safe);
            var t = t_in.*;
            var hi: u64 = 0; // the carry into t[i + n] from the rows before
            for (0..n) |i| {
                const u = t[i] *% self.m0inv;
                var c: u64 = 0;
                inline for (0..n) |j| {
                    const x = @as(u128, u) * self.m[j] + t[i + j] + c;
                    t[i + j] = @truncate(x);
                    c = @intCast(x >> 64);
                }
                const s = @as(u128, t[i + n]) + c + hi;
                t[i + n] = @truncate(s);
                hi = @intCast(s >> 64);
            }
            return self.reduceOnce(t[n..].*, hi);
        }

        /// From the Montgomery domain: a·R⁻¹ mod m.
        pub fn fromMont(self: *const Self, a: *const Int) Int {
            var one: Int = @splat(0);
            one[0] = 1;
            return self.mul(a, &one);
        }

        /// The table entry at a secret index: every entry is read.
        inline fn select(table: *const [1 << window]Int, d: u64) Int {
            @setRuntimeSafety(safe);
            var r: Int = @splat(0);
            for (table, 0..) |*e, i| {
                const keep = mask(eqBit(i, d));
                for (&r, e) |*l, x| l.* |= x & keep;
            }
            return r;
        }

        /// The `window` bits of a big-endian exponent from bit `pos` up
        /// (bits beyond its top are 0). `pos` is public.
        inline fn digit(e: []const u8, pos: usize) u64 {
            @setRuntimeSafety(safe);
            const byte = pos / 8;
            var v: u64 = 0;
            if (byte < e.len) v = e[e.len - 1 - byte];
            if (byte + 1 < e.len) v |= @as(u64, e[e.len - 2 - byte]) << 8;
            return (v >> @intCast(pos % 8)) & ((1 << window) - 1);
        }

        /// x^e (Montgomery domain in and out) for a secret base x below m
        /// and a secret exponent e (big-endian; its length is public).
        /// Constant time: a fixed window from the top, `window` squarings
        /// and one multiplication by a table entry (scanned in full) per
        /// window, the leading zero windows included.
        pub fn pow(self: *const Self, x: *const Int, e: []const u8) Int {
            @setRuntimeSafety(safe);
            var table: [1 << window]Int = undefined;
            defer std.crypto.secureZero(u64, @ptrCast(&table));
            table[0] = self.one;
            table[1] = x.*;
            for (2..table.len) |i| {
                table[i] = if (i % 2 == 0) self.sqr(&table[i / 2]) else self.mul(&table[i - 1], x);
            }
            const windows = (8 * e.len + window - 1) / window;
            if (windows == 0) return self.one;
            var acc = select(&table, digit(e, (windows - 1) * window));
            var i = windows - 1;
            while (i > 0) {
                i -= 1;
                for (0..window) |_| acc = self.sqr(&acc);
                var entry = select(&table, digit(e, i * window));
                acc = self.mul(&acc, &entry);
                std.crypto.secureZero(u64, &entry);
            }
            return acc;
        }

        /// x^e for a public exponent (left to right, branching on its
        /// bits), Montgomery domain in and out; e ≥ 1.
        pub fn powPublic(self: *const Self, x: *const Int, e: u32) Int {
            std.debug.assert(e != 0);
            var acc = x.*;
            var bit: u5 = @intCast(31 - @clz(e));
            while (bit > 0) {
                bit -= 1;
                acc = self.sqr(&acc);
                if ((e >> bit) & 1 == 1) acc = self.mul(&acc, x);
            }
            return acc;
        }
    };
}

/// Little-endian limbs of a big-endian number of at most 8·limbs bytes.
pub fn fromBytes(comptime limbs: usize, bytes: []const u8) [limbs]u64 {
    std.debug.assert(bytes.len <= 8 * limbs);
    var r: [limbs]u64 = @splat(0);
    for (bytes, 0..) |b, i| {
        const pos = bytes.len - 1 - i;
        r[pos / 8] |= @as(u64, b) << @intCast(8 * (pos % 8));
    }
    return r;
}

/// The value as `out.len` big-endian bytes (the limbs above must be 0).
pub fn toBytes(limbs: []const u64, out: []u8) void {
    for (out, 0..) |*b, i| {
        const pos = out.len - 1 - i;
        b.* = if (pos / 8 < limbs.len) @truncate(limbs[pos / 8] >> @intCast(8 * (pos % 8))) else 0;
    }
}

/// a·b + c as an integer (no reduction), constant time.
pub fn mulAdd(comptime n: usize, a: *const [n]u64, b: *const [n]u64, c: *const [n]u64) [2 * n]u64 {
    @setRuntimeSafety(safe);
    var t: [2 * n]u64 = @splat(0);
    t[0..n].* = c.*;
    for (0..n) |i| {
        var carry: u64 = 0;
        for (0..n) |j| {
            const x = @as(u128, a[j]) * b[i] + t[i + j] + carry;
            t[i + j] = @truncate(x);
            carry = @intCast(x >> 64);
        }
        // Rows before this one reached t[i + n − 1]: t[i + n] is still 0.
        t[i + n] = carry;
    }
    return t;
}

/// 1 if a < b, else 0, constant time.
pub fn lessThan(comptime n: usize, a: *const [n]u64, b: *const [n]u64) u64 {
    var d: [n]u64 = undefined;
    return subBorrow(n, a, b, &d);
}

// -- Tests ------------------------------------------------------------

const testing = std.testing;

/// Little-endian limbs as an integer (for the reference arithmetic).
fn toInt(comptime T: type, limbs: []const u64) T {
    var r: T = 0;
    var i = limbs.len;
    while (i > 0) {
        i -= 1;
        r = r << 64 | limbs[i];
    }
    return r;
}

fn fromInt(comptime n: usize, x: anytype) [n]u64 {
    var r: [n]u64 = undefined;
    var v = x;
    for (&r) |*l| {
        l.* = @truncate(v);
        v >>= 64;
    }
    return r;
}

/// A value below `bound` (which may be up to 2^(64n)) of one of several
/// shapes: uniform, limbs of all ones or zeros, just below the bound,
/// small.
fn sample(comptime U: type, rand: std.Random, bound: U, k: usize) U {
    const n = @bitSizeOf(U) / 64;
    var l: [n]u64 = undefined;
    for (&l) |*x| x.* = switch (k % 3) {
        0 => rand.int(u64),
        1 => if (rand.boolean()) ~@as(u64, 0) else 0,
        else => if (rand.boolean()) ~@as(u64, 0) else rand.int(u64),
    };
    const v: U = @bitCast(l);
    return switch (k % 7) {
        5 => bound - 1 - (v % @min(bound, 3)),
        6 => v % @min(bound, 1 << 70),
        else => v % bound,
    };
}

/// Every operation of Mont(n) against integer arithmetic, on structured
/// values, for each modulus (odd, below R).
fn checkAgainstInts(comptime n: usize, moduli: []const @Int(.unsigned, 64 * n), rounds: usize) !void {
    const M = Mont(n);
    const U = @Int(.unsigned, 64 * n);
    const W = @Int(.unsigned, 128 * n);
    var prng = std.Random.DefaultPrng.init(0x6d6f6e74 + n);
    const rand = prng.random();
    for (moduli) |m_int| {
        const mod = M.init(@bitCast(m_int));
        const r: W = (@as(W, 1) << (64 * n)) % m_int;
        try testing.expectEqual(@as(U, @intCast(r)), @as(U, @bitCast(mod.one)));
        try testing.expectEqual(@as(U, @intCast(r * r % m_int)), @as(U, @bitCast(mod.r2)));
        // R⁻¹ from the Montgomery product of 1 and 1.
        var one: M.Int = @splat(0);
        one[0] = 1;
        const r_inv: W = @as(U, @bitCast(mod.mul(&one, &one)));
        try testing.expectEqual(@as(W, 1 % m_int), r_inv * r % m_int);
        for (0..rounds) |k| {
            const a_int = sample(U, rand, m_int, k);
            const b_int = sample(U, rand, m_int, k / 7);
            const a: M.Int = @bitCast(a_int);
            const b: M.Int = @bitCast(b_int);
            const want: U = @intCast(@as(W, a_int) * b_int % m_int * r_inv % m_int);
            try testing.expectEqual(want, @as(U, @bitCast(mod.mul(&a, &b))));
            try testing.expectEqual(want, @as(U, @bitCast(mod.mulCios(&a, &b))));
            const want_sq: U = @intCast(@as(W, a_int) * a_int % m_int * r_inv % m_int);
            try testing.expectEqual(want_sq, @as(U, @bitCast(mod.sqr(&a))));
            try testing.expectEqual(@as(U, @intCast((@as(W, a_int) + m_int - b_int) % m_int)), @as(U, @bitCast(mod.sub(&a, &b))));
            // mul takes a first factor up to R − 1.
            const big = sample(U, rand, ~@as(U, 0), k) | (1 << (64 * n - 1));
            const want_big: U = @intCast(@as(W, big) * b_int % m_int * r_inv % m_int);
            try testing.expectEqual(want_big, @as(U, @bitCast(mod.mul(&@bitCast(big), &b))));
            try testing.expectEqual(want_big, @as(U, @bitCast(mod.mulCios(&@bitCast(big), &b))));
            // redc of a double-width value below m·R.
            const wide: W = (@as(W, sample(U, rand, ~@as(U, 0), k + 1)) << (64 * n) | sample(U, rand, ~@as(U, 0), k + 2)) % (@as(W, m_int) << (64 * n));
            const want_redc: U = @intCast(wide % m_int * r_inv % m_int);
            try testing.expectEqual(want_redc, @as(U, @bitCast(mod.redc(&@bitCast(wide)))));
            // The plain integer helpers.
            const x_add = sample(U, rand, ~@as(U, 0), k + 3);
            const c: M.Int = @bitCast(x_add);
            try testing.expectEqual(@as(W, big) * x_add + x_add, @as(W, @bitCast(mulAdd(n, &@bitCast(big), &c, &c))));
            try testing.expectEqual(@as(u64, @intFromBool(a_int < b_int)), lessThan(n, &a, &b));
            try testing.expectEqual(@as(u64, @intFromBool(x_add < big)), lessThan(n, &c, &@as(M.Int, @bitCast(big))));
            try testing.expectEqual(@as(u64, 0), lessThan(n, &c, &c));
        }
        // pow against square and multiply on integers, for exponents of
        // several byte lengths (window boundaries) and patterns.
        for (0..@max(8, rounds / 10)) |k| {
            var e_buf: [11]u8 = undefined;
            rand.bytes(&e_buf);
            if (k % 5 == 0) e_buf = @splat(0xff);
            if (k % 5 == 1) e_buf = @splat(0);
            if (k % 5 == 2) e_buf[0] = 0;
            const e = e_buf[0 .. k % (e_buf.len + 1)];
            const x_int = sample(U, rand, m_int, k);
            var want: W = 1 % m_int;
            for (e) |byte| {
                for (0..8) |bit| {
                    want = want * want % m_int;
                    if ((byte >> @intCast(7 - bit)) & 1 == 1) want = want * x_int % m_int;
                }
            }
            const x_m = mod.mul(&@bitCast(x_int), &mod.r2);
            try testing.expectEqual(@as(U, @intCast(want)), @as(U, @bitCast(mod.fromMont(&mod.pow(&x_m, e)))));
            const e32: u32 = if (k == 0) 1 else if (k == 1) 65537 else rand.int(u32) | 1;
            var want_pub: W = 1;
            var bit: u6 = 32;
            while (bit > 0) {
                bit -= 1;
                want_pub = want_pub * want_pub % m_int;
                if ((e32 >> @intCast(bit)) & 1 == 1) want_pub = want_pub * x_int % m_int;
            }
            try testing.expectEqual(@as(U, @intCast(want_pub % m_int)), @as(U, @bitCast(mod.fromMont(&mod.powPublic(&x_m, e32)))));
        }
    }
}

/// Moduli for n limbs: odd, with the top bit set or clear, R − 1, small,
/// and random ones.
fn testModuli(comptime n: usize, seed: u64) [8]@Int(.unsigned, 64 * n) {
    const U = @Int(.unsigned, 64 * n);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    var r: [8]U = undefined;
    r[0] = ~@as(U, 0);
    r[1] = (1 << (64 * n - 1)) + 1;
    r[2] = 3;
    r[3] = (@as(U, 1) << 64) + 13;
    for (r[4..]) |*m| {
        var l: [n]u64 = undefined;
        for (&l) |*x| x.* = rand.int(u64);
        m.* = @as(U, @bitCast(l)) | 1;
    }
    r[4] |= 1 << (64 * n - 1);
    r[5] = r[5] >> (64 * (n / 2) + 7) | 1; // a short modulus (an unbalanced prime)
    r[6] |= ((1 << 64) - 1) << (64 * n - 64); // top limb all ones
    return r;
}

test "mont: against integer arithmetic, at the limits" {
    try checkAgainstInts(4, &.{
        (1 << 256) - 189, // the largest 256-bit prime
        0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    }, 400);
    try checkAgainstInts(4, &testModuli(4, 1), 300);
    try checkAgainstInts(2, &testModuli(2, 3), 300);
    try checkAgainstInts(16, &testModuli(16, 4), 60);
    try checkAgainstInts(24, &testModuli(24, 5), 20);
    try checkAgainstInts(32, &testModuli(32, 6), 20);
    // 64 limbs (RSA-4096's n, for the public-exponent check) takes the
    // CIOS path checked above; u8192 reference arithmetic would add two
    // minutes of compile time. rsa.zig's tests cover it.
}

test "mont: limbs and bytes" {
    const bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    const l = fromBytes(3, &bytes);
    try testing.expectEqual(@as(u64, 0x0405060708090a0b), l[0]);
    try testing.expectEqual(@as(u64, 0x010203), l[1]);
    try testing.expectEqual(@as(u64, 0), l[2]);
    var out: [13]u8 = undefined;
    toBytes(&l, &out);
    try testing.expectEqualSlices(u8, &([_]u8{ 0, 0 } ++ bytes), &out);
}
