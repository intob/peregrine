//! Adversarial checks of `rsa.zig` over `mont.zig`, independent of both:
//! the reference arithmetic is std.math.big (and std.crypto.ff through
//! `rsa_verify.Reference` where it works).
//!
//! - "fuzz: rsa mont": every Mont(n) operation used by RSA (and the
//!   sizes around them) on fuzzer-chosen moduli and operands, against
//!   big integers.
//! - Random keys generated here (primes by sieve and Fermat tests with
//!   std.crypto.ff, the CRT parts with std.math.big): 2048 to 4096 bits,
//!   odd sizes, balanced and very unbalanced primes, p < q and p > q,
//!   primes just above and below multiples of 64 bits (and of 1024 and
//!   1536 bits, where the limb count changes), tiny primes, several e.
//!   Signatures equal the reference's byte for byte; raw private
//!   operations on edge and random inputs give m^d mod n (std.math.big).
//!   `RSA_KEYS=N` in the environment sets the number of keys and
//!   `RSA_SEED=S` the seed (defaults: 24 keys, 4 in Debug), `RSA_SHAPE=K`
//!   one shape only (8: RSA-2048, two 1024-bit primes).
//! - Malformed keys are rejected without a panic.
//! - A fault in any part of the key state gives SignatureFault and a
//!   zeroed output, or the correct signature: never a wrong one.
const std = @import("std");
const builtin = @import("builtin");
const rsa = @import("./rsa.zig");
const mont = @import("./mont.zig");
const rsa_verify = @import("./rsa_verify.zig");
const credentials = @import("./credentials.zig");
const ff = std.crypto.ff;
const Managed = std.math.big.int.Managed;
const Limb = std.math.big.Limb;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const max_len = rsa.max_len;
const debug = builtin.mode == .debug;

// -- Big integers (std.math.big) ----------------------------------------

/// A big-endian byte string as an integer.
fn fromBe(a: Allocator, bytes: []const u8) !Managed {
    var r = try Managed.initCapacity(a, bytes.len / 8 + 2);
    @memset(r.limbs, 0);
    for (bytes, 0..) |b, i| {
        const pos = bytes.len - 1 - i;
        r.limbs[pos / 8] |= @as(Limb, b) << @intCast(8 * (pos % 8));
    }
    r.normalize(r.limbs.len);
    return r;
}

/// Little-endian 64-bit limbs as an integer.
fn fromLimbs(a: Allocator, limbs: []const u64) !Managed {
    var r = try Managed.initCapacity(a, limbs.len + 1);
    @memset(r.limbs, 0);
    for (limbs, 0..) |l, i| r.limbs[i] = l;
    r.normalize(r.limbs.len);
    return r;
}

/// The integer as `out.len` big-endian bytes; false if it doesn't fit.
fn toBe(x: *const Managed, out: []u8) bool {
    const limbs = x.limbs[0..x.len()];
    if (8 * limbs.len > out.len + 8 or x.bitCountAbs() > 8 * out.len) return false;
    for (out, 0..) |*b, i| {
        const pos = out.len - 1 - i;
        b.* = if (pos / 8 < limbs.len) @truncate(limbs[pos / 8] >> @intCast(8 * (pos % 8))) else 0;
    }
    return true;
}

/// Whether the limbs (little-endian) equal the integer.
fn limbsEql(limbs: []const u64, x: *const Managed) bool {
    const xl = x.limbs[0..x.len()];
    for (limbs, 0..) |l, i| {
        const want: u64 = if (i < xl.len) xl[i] else 0;
        if (l != want) return false;
    }
    return xl.len <= limbs.len or (xl.len == 1 and xl[0] == 0);
}

/// Scratch for modular arithmetic: the product and quotient are reused.
const Arith = struct {
    a: Allocator,
    prod: Managed,
    quo: Managed,

    fn init(a: Allocator) !Arith {
        return .{ .a = a, .prod = try Managed.init(a), .quo = try Managed.init(a) };
    }

    fn deinit(c: *Arith) void {
        c.prod.deinit();
        c.quo.deinit();
    }

    /// out = x mod m.
    fn mod(c: *Arith, out: *Managed, x: *const Managed, m: *const Managed) !void {
        try c.quo.divTrunc(out, x, m);
    }

    /// out = x·y mod m (out may be x or y).
    fn mulMod(c: *Arith, out: *Managed, x: *const Managed, y: *const Managed, m: *const Managed) !void {
        try c.prod.mul(x, y);
        try c.quo.divTrunc(out, &c.prod, m);
    }

    /// out = x^e mod m, left to right over e's bits.
    fn powMod(c: *Arith, out: *Managed, x: *const Managed, e: *const Managed, m: *const Managed) !void {
        var base = try Managed.init(c.a);
        defer base.deinit();
        try c.mod(&base, x, m);
        try out.set(1);
        const el = e.limbs[0..e.len()];
        var i = e.bitCountAbs();
        while (i > 0) {
            i -= 1;
            try c.mulMod(out, out, out, m);
            if ((el[i / 64] >> @intCast(i % 64)) & 1 == 1) try c.mulMod(out, out, &base, m);
        }
    }

    /// out = x·2^shift mod m.
    fn shlMod(c: *Arith, out: *Managed, x: *const Managed, shift: usize, m: *const Managed) !void {
        try c.prod.shiftLeft(x, shift);
        try c.quo.divTrunc(out, &c.prod, m);
    }
};

/// e⁻¹ mod m for a small e coprime to m: (1 + k·m)/e with k = −m⁻¹ mod e.
fn invSmall(c: *Arith, out: *Managed, e: u32, m: *const Managed) !bool {
    var e_big = try Managed.initSet(c.a, e);
    defer e_big.deinit();
    var r = try Managed.init(c.a);
    defer r.deinit();
    try c.mod(&r, m, &e_big);
    const m_mod_e = try r.toInt(u64);
    const inv = invU64(m_mod_e, e) orelse return false;
    const k = (e - inv) % e;
    var km = try Managed.initSet(c.a, k);
    defer km.deinit();
    try c.prod.mul(&km, m);
    try c.prod.addScalar(&c.prod, 1);
    try c.quo.divTrunc(&r, &c.prod, &e_big);
    if (!r.eqlZero()) return error.NotExact;
    try out.copy(c.quo.toConst());
    return true;
}

/// a⁻¹ mod m (m ≤ 2^32), or null if they aren't coprime.
fn invU64(a: u64, m: u64) ?u64 {
    var r0: i128 = @intCast(m);
    var r1: i128 = @intCast(a % m);
    var t0: i128 = 0;
    var t1: i128 = 1;
    while (r1 != 0) {
        const q = @divFloor(r0, r1);
        const r2 = r0 - q * r1;
        r0 = r1;
        r1 = r2;
        const t2 = t0 - q * t1;
        t0 = t1;
        t1 = t2;
    }
    if (r0 != 1) return null;
    return @intCast(@mod(t0, @as(i128, @intCast(m))));
}

// -- Fuzz target: Mont(n) against big integers ----------------------------

var fuzz_mem: [16 << 20]u8 = undefined;

fn fuzzMont(_: void, smith: *testing.Smith) anyerror!void {
    const sizes = [_]usize{ 1, 2, 4, 16, 24, 32, 48, 64 };
    switch (smith.index(sizes.len)) {
        inline 0...sizes.len - 1 => |i| try fuzzMontN(sizes[i], smith),
        else => unreachable,
    }
}

/// A value below the bound of a fuzzer-chosen shape: its bytes reduced,
/// the bound minus a small number, a small number, or its bytes.
fn fuzzValue(comptime n: usize, smith: *testing.Smith, c: *Arith, bound: *const Managed) !Managed {
    var l: [n]u64 = undefined;
    smith.bytes(std.mem.asBytes(&l));
    var x = try fromLimbs(c.a, &l);
    switch (smith.index(4)) {
        0, 3 => try c.mod(&x, &x, bound),
        1 => {
            const small = try Managed.initSet(c.a, l[0] % 4 + 1);
            try x.sub(bound, &small);
            if (!x.isPositive()) try x.set(0);
        },
        else => {
            try x.set(l[0] % 4);
            try c.mod(&x, &x, bound);
        },
    }
    return x;
}

fn fuzzMontN(comptime n: usize, smith: *testing.Smith) !void {
    const M = mont.Mont(n);
    var fba = std.heap.FixedBufferAllocator.init(&fuzz_mem);
    const a = fba.allocator();
    var c = try Arith.init(a);

    // An odd modulus of the fuzzer's bits, shortened by up to 64n − 2
    // bits (a short prime in a wide Mont), at least 3.
    var m: M.Int = undefined;
    smith.bytes(std.mem.asBytes(&m));
    const shift = smith.valueRangeLessThan(u16, 0, 64 * n - 1);
    var m_big = try fromLimbs(a, &m);
    try m_big.shiftRight(&m_big, shift);
    @memset(&m, 0);
    for (m_big.limbs[0..m_big.len()], 0..) |l, i| m[i] = l;
    m[0] |= 1;
    if (n == 1 and m[0] == 1) m[0] = 3;
    if (n > 1 and m[0] == 1 and std.mem.allEqual(u64, m[1..], 0)) m[0] = 3;
    m_big = try fromLimbs(a, &m);
    const mod = M.init(m);

    // R mod m, R² mod m, −m⁻¹ mod 2^64.
    var one_big = try Managed.initSet(a, 1);
    var want = try Managed.init(a);
    try c.shlMod(&want, &one_big, 64 * n, &m_big);
    try testing.expect(limbsEql(&mod.one, &want));
    try c.shlMod(&want, &one_big, 128 * n, &m_big);
    try testing.expect(limbsEql(&mod.r2, &want));
    try testing.expectEqual(~@as(u64, 0), mod.m0inv *% m[0]);

    const x = try fuzzValue(n, smith, &c, &m_big);
    const y = try fuzzValue(n, smith, &c, &m_big);
    var xl: M.Int = @splat(0);
    var yl: M.Int = @splat(0);
    for (x.limbs[0..x.len()], 0..) |l, i| xl[i] = l;
    for (y.limbs[0..y.len()], 0..) |l, i| yl[i] = l;

    var got = try Managed.init(a);
    var back = try Managed.init(a);
    const Check = struct {
        /// out < m and out·R ≡ want (mod m).
        fn mont(cc: *Arith, out: *const M.Int, w: *const Managed, mb: *const Managed, g: *Managed, b: *Managed) !void {
            g.* = try fromLimbs(cc.a, out);
            try testing.expect(g.order(mb.*) == .lt);
            try cc.shlMod(b, g, 64 * n, mb);
            var wm = try Managed.init(cc.a);
            try cc.mod(&wm, w, mb);
            try testing.expect(b.eql(wm));
        }
    };

    // mul, mulCios and sqr.
    try c.prod.mul(&x, &y);
    want = try c.prod.clone();
    const p1 = mod.mul(&xl, &yl);
    try Check.mont(&c, &p1, &want, &m_big, &got, &back);
    const p2 = mod.mulCios(&xl, &yl);
    try testing.expectEqualSlices(u64, &p1, &p2);
    try c.prod.mul(&x, &x);
    want = try c.prod.clone();
    try Check.mont(&c, &mod.sqr(&xl), &want, &m_big, &got, &back);

    // mul with a first factor of any value below R.
    var big_l: M.Int = undefined;
    smith.bytes(std.mem.asBytes(&big_l));
    const big = try fromLimbs(a, &big_l);
    try c.prod.mul(&big, &y);
    want = try c.prod.clone();
    try Check.mont(&c, &mod.mul(&big_l, &yl), &want, &m_big, &got, &back);
    try testing.expectEqualSlices(u64, &mod.mul(&big_l, &yl), &mod.mulCios(&big_l, &yl));

    // sub.
    try want.add(&x, &m_big);
    try want.sub(&want, &y);
    try c.mod(&want, &want, &m_big);
    try testing.expect(limbsEql(&mod.sub(&xl, &yl), &want));

    // redc of a value below m·R, and fromMont.
    var wide: M.Wide = undefined;
    smith.bytes(std.mem.asBytes(&wide));
    var t = try fromLimbs(a, &wide);
    var mr = try Managed.init(a);
    try mr.shiftLeft(&m_big, 64 * n);
    try c.mod(&t, &t, &mr);
    @memset(&wide, 0);
    for (t.limbs[0..t.len()], 0..) |l, i| wide[i] = l;
    try Check.mont(&c, &mod.redc(&wide), &t, &m_big, &got, &back);
    try Check.mont(&c, &mod.fromMont(&xl), &x, &m_big, &got, &back);

    // pow (the sizes RSA's CRT uses and below) on an exponent of up to
    // 256 bytes, and powPublic.
    const xm = mod.mul(&xl, &mod.r2);
    if (n <= 32) {
        var e_buf: [256]u8 = undefined;
        const e_len = smith.slice(&e_buf);
        const e = e_buf[0..e_len];
        const e_big = try fromBe(a, e);
        var xe = try Managed.init(a);
        try c.powMod(&xe, &x, &e_big, &m_big);
        try c.shlMod(&want, &xe, 64 * n, &m_big);
        const r = mod.pow(&xm, e);
        try testing.expect(limbsEql(&r, &want));
    }
    const e32 = smith.value(u32) | 1;
    const e32_big = try Managed.initSet(a, e32);
    var xe = try Managed.init(a);
    try c.powMod(&xe, &x, &e32_big, &m_big);
    try c.shlMod(&want, &xe, 64 * n, &m_big);
    try testing.expect(limbsEql(&mod.powPublic(&xm, e32), &want));

    // The plain integer helpers.
    try c.prod.mul(&big, &y);
    try c.prod.add(&c.prod, &x);
    try testing.expect(limbsEql(&mont.mulAdd(n, &big_l, &yl, &xl), &c.prod));
    try testing.expectEqual(@as(u64, @intFromBool(x.order(y) == .lt)), mont.lessThan(n, &xl, &yl));
    try testing.expectEqual(@as(u64, @intFromBool(big.order(m_big) == .lt)), mont.lessThan(n, &big_l, &m));
}

test "fuzz: rsa mont" {
    try testing.fuzz({}, fuzzMont, .{ .corpus = &.{
        &@as([600]u8, @splat(0xff)),
        &@as([600]u8, @splat(0)),
        &@as([1200]u8, @splat(0x80)),
    } });
}

// -- Random keys ----------------------------------------------------------

/// The odd primes below 2^14, for sieving.
const small_primes = blk: {
    @setEvalBranchQuota(4_000_000);
    const limit = 1 << 14;
    var composite: [limit]bool = @splat(false);
    var list: [1900]u16 = undefined;
    var count: usize = 0;
    var i: usize = 3;
    while (i < limit) : (i += 2) {
        if (composite[i]) continue;
        list[count] = i;
        count += 1;
        var j = i * i;
        while (j < limit) : (j += 2 * i) composite[j] = true;
    }
    break :blk list[0..count].*;
};

const Fermat = ff.Modulus(2048);

/// Fermat tests to bases 2, 3, 5 and 7 (for random candidates of 21 bits
/// and more that passed the sieve, as good as Miller-Rabin).
fn fermat(c: []const u8) bool {
    const m = Fermat.fromBytes(c, .big) catch return false;
    var nm1_buf: [256]u8 = undefined;
    const nm1 = nm1_buf[0..c.len];
    @memcpy(nm1, c);
    nm1[c.len - 1] -= 1; // c is odd
    for ([_]u8{ 2, 3, 5, 7 }) |base| {
        const b = Fermat.Fe.fromPrimitive(u8, m, base) catch return false;
        const r = m.powWithEncodedPublicExponent(b, nm1, .big) catch return false;
        if (!r.eql(m.one())) return false;
    }
    return true;
}

/// How a prime's search starts: anywhere of its length (top two bits
/// set), at its length's bottom (2^(b−1) + 1 up), or just below 2^b.
const Start = enum { random, low, high };

/// A prime of exactly `bits` bits (2 to 2048), big-endian in `out`.
fn genPrime(out: *[256]u8, bits: usize, start: Start, rand: std.Random) []const u8 {
    const len = (bits + 7) / 8;
    const p = out[0..len];
    if (bits <= 32) {
        // Trial division: a random odd start of that length, then up
        // (down from the top for `high`), wrapping within the length.
        if (bits == 2) {
            out[0] = 3;
            return out[0..1];
        }
        const lo: u64 = @as(u64, 1) << @intCast(bits - 1);
        const hi: u64 = (@as(u64, 1) << @intCast(bits)) - 1;
        var v: u64 = switch (start) {
            .random => rand.intRangeAtMost(u64, lo, hi) | 1,
            .low => lo + 1,
            .high => hi,
        };
        while (true) {
            var prime = true;
            var d: u64 = 3;
            while (d * d <= v) : (d += 2) {
                if (v % d == 0) {
                    prime = false;
                    break;
                }
            }
            if (prime) break;
            if (start == .high) v -= 2 else v += 2;
            if (v > hi) v = lo + 1;
            if (v < lo) v = hi;
        }
        var b8: [8]u8 = undefined;
        std.mem.writeInt(u64, &b8, v, .big);
        @memcpy(p, b8[8 - len ..]);
        return p;
    }
    const window = 8192; // candidates per sieve (odd offsets 0, 2, ...)
    while (true) {
        // The start.
        switch (start) {
            .random => {
                rand.bytes(p);
                p[0] &= @as(u8, 0xff) >> @intCast(8 * len - bits);
                const top = bits - 1 - 8 * (len - 1); // the top bit's position in p[0]
                p[0] |= @as(u8, 1) << @intCast(top);
                if (top > 0) p[0] |= @as(u8, 1) << @intCast(top - 1) else p[1] |= 0x80;
            },
            .low => {
                @memset(p, 0);
                p[0] = @as(u8, 1) << @intCast(bits - 1 - 8 * (len - 1));
                p[len - 1] |= 1;
                // A random offset below 2^16, so low primes differ.
                const off: usize = rand.int(u16) & 0xfffe;
                addSmall(p, off);
            },
            .high => {
                @memset(p, 0xff);
                p[0] = @as(u8, 0xff) >> @intCast(8 * len - bits);
                // Start 2·window + a random amount below 2^b.
                subSmall(p, 2 * window + @as(usize, rand.int(u16) & 0xfffe));
            },
        }
        p[len - 1] |= 1;
        // Residues mod the small primes, then sieve the window.
        var res: [small_primes.len]u32 = undefined;
        for (small_primes, &res) |sp, *r| {
            var acc: u32 = 0;
            for (p) |b| acc = (acc * 256 + b) % sp;
            r.* = acc;
        }
        var composite: [window]bool = @splat(false);
        for (small_primes, res) |sp, r| {
            // Offsets j with r + 2j ≡ 0 (mod sp): j ≡ −r·2⁻¹.
            const inv2 = (sp + 1) / 2;
            var j: usize = @intCast((@as(u64, sp - r) % sp) * inv2 % sp);
            while (j < window) : (j += sp) composite[j] = true;
        }
        var cand: [256]u8 = undefined;
        for (0..window) |j| {
            if (composite[j]) continue;
            @memcpy(cand[0..len], p);
            addSmall(cand[0..len], 2 * j);
            // Still `bits` long (the high start can't carry out; the
            // others start far below 2^b).
            if (bitLen(cand[0..len]) != bits) break;
            if (fermat(cand[0..len])) {
                @memcpy(p, cand[0..len]);
                return p;
            }
        }
    }
}

fn addSmall(x: []u8, v: usize) void {
    var carry: usize = v;
    var i = x.len;
    while (i > 0 and carry != 0) {
        i -= 1;
        const s = @as(usize, x[i]) + (carry & 0xff);
        x[i] = @truncate(s);
        carry = (carry >> 8) + (s >> 8);
    }
}

fn subSmall(x: []u8, v: usize) void {
    var borrow: usize = v;
    var i = x.len;
    while (i > 0 and borrow != 0) {
        i -= 1;
        const sub = borrow & 0xff;
        borrow >>= 8;
        if (x[i] >= sub) {
            x[i] -= @intCast(sub);
        } else {
            x[i] = @intCast(@as(usize, x[i]) + 256 - sub);
            borrow += 1;
        }
    }
}

/// A key's integers (big-endian, no leading zeros) and its DER.
const Key = struct {
    n: []const u8,
    e: u32,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    q_inv: []const u8,
    der: []const u8,
};

fn trimmed(b: []const u8) []const u8 {
    var v = b;
    while (v.len > 0 and v[0] == 0) v = v[1..];
    return v;
}

/// The integer's minimal big-endian bytes, allocated.
fn bytesOf(a: Allocator, x: *const Managed) ![]const u8 {
    const buf = try a.alloc(u8, 8 * x.len() + 1);
    if (!toBe(x, buf)) return error.TooBig;
    return trimmed(buf);
}

/// DER for a PKCS#1 key from raw INTEGER contents (written as given,
/// with a 0 pad byte when the top bit is set): `version` and `extra`
/// (another INTEGER after qInv) let tests build malformed keys.
fn encodeDer(a: Allocator, version: []const u8, ints: []const []const u8, extra: ?[]const u8) ![]const u8 {
    var body: std.ArrayList(u8) = .empty;
    const all_len = ints.len + 1 + @intFromBool(extra != null);
    for (0..all_len) |i| {
        const v = if (i == 0) version else if (i <= ints.len) ints[i - 1] else extra.?;
        const pad: usize = if (v.len > 0 and v[0] & 0x80 != 0) 1 else 0;
        try body.append(a, 0x02);
        try derLen(a, &body, v.len + pad);
        if (pad == 1) try body.append(a, 0);
        try body.appendSlice(a, v);
    }
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, 0x30);
    try derLen(a, &out, body.items.len);
    try out.appendSlice(a, body.items);
    return out.items;
}

fn derLen(a: Allocator, out: *std.ArrayList(u8), len: usize) !void {
    if (len < 0x80) return out.append(a, @intCast(len));
    if (len < 0x100) return out.appendSlice(a, &.{ 0x81, @intCast(len) });
    return out.appendSlice(a, &.{ 0x82, @intCast(len >> 8), @truncate(len) });
}

fn keyDer(a: Allocator, k: Key) ![]const u8 {
    var e_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &e_buf, k.e, .big);
    return encodeDer(a, &.{0}, &.{ k.n, trimmed(&e_buf), k.d, k.p, k.q, k.dp, k.dq, k.q_inv }, null);
}

/// A key from two primes and e, or null if e isn't coprime to p − 1
/// and q − 1.
fn makeKey(c: *Arith, p_bytes: []const u8, q_bytes: []const u8, e: u32) !?Key {
    const a = c.a;
    const p = try fromBe(a, p_bytes);
    const q = try fromBe(a, q_bytes);
    var one = try Managed.initSet(a, 1);
    var pm1 = try Managed.init(a);
    try pm1.sub(&p, &one);
    var qm1 = try Managed.init(a);
    try qm1.sub(&q, &one);
    var n = try Managed.init(a);
    try n.mul(&p, &q);
    var phi = try Managed.init(a);
    try phi.mul(&pm1, &qm1);
    var d = try Managed.init(a);
    var dp = try Managed.init(a);
    var dq = try Managed.init(a);
    if (!try invSmall(c, &dp, e, &pm1)) return null;
    if (!try invSmall(c, &dq, e, &qm1)) return null;
    if (!try invSmall(c, &d, e, &phi)) return null;
    // qInv = q^(p − 2) mod p.
    var pm2 = try Managed.init(a);
    try pm2.sub(&pm1, &one);
    var q_inv = try Managed.init(a);
    try c.powMod(&q_inv, &q, &pm2, &p);
    var k: Key = .{
        .n = try bytesOf(a, &n),
        .e = e,
        .d = try bytesOf(a, &d),
        .p = trimmed(p_bytes),
        .q = trimmed(q_bytes),
        .dp = try bytesOf(a, &dp),
        .dq = try bytesOf(a, &dq),
        .q_inv = try bytesOf(a, &q_inv),
        .der = undefined,
    };
    k.der = try keyDer(a, k);
    return k;
}

const shape_count = 10;

/// The prime lengths of a key shape: n of 2048 to 4096 bits, each prime
/// of at most 2048 bits (rsa.zig's limit), at least 2.
fn shape(rand: std.Random, which: usize) [2]usize {
    const boundaries = [_]usize{ 512, 576, 640, 704, 768, 832, 896, 960, 1024, 1088, 1152, 1216, 1280, 1344, 1408, 1472, 1536, 1600, 1664, 1728, 1792, 1856, 1920, 1984, 2048 };
    return switch (which % shape_count) {
        // Balanced, any total length.
        0 => blk: {
            const total = rand.intRangeAtMost(usize, 2049, 4096);
            break :blk .{ (total + 1) / 2, total / 2 };
        },
        // The common sizes and the lengths where the limb count changes.
        1 => blk: {
            const sizes = [_][2]usize{ .{ 1024, 1024 }, .{ 1536, 1536 }, .{ 2048, 2048 }, .{ 1025, 1024 }, .{ 1023, 1026 }, .{ 1537, 1536 }, .{ 1535, 1537 }, .{ 1025, 1025 }, .{ 1537, 1537 }, .{ 2047, 2049 - 2047 + 1024 }, .{ 1024, 1025 }, .{ 2048, 2047 } };
            break :blk sizes[rand.uintLessThan(usize, sizes.len)];
        },
        // One prime a bit either side of a multiple of 64 bits.
        2, 3 => blk: {
            const b = boundaries[rand.uintLessThan(usize, boundaries.len)];
            const bp: usize = @min(2048, b + rand.intRangeAtMost(usize, 0, 2) - 1);
            const lo = if (bp >= 2049) 2 else 2049 - bp;
            const hi: usize = @min(2048, 4096 - bp);
            break :blk .{ bp, rand.intRangeAtMost(usize, lo, @max(lo, hi)) };
        },
        // Very unbalanced: a long prime and a short one.
        4 => blk: {
            const bp = rand.intRangeAtMost(usize, 1700, 2048);
            break :blk .{ bp, rand.intRangeAtMost(usize, 2049 - bp, 2049 - bp + 300) };
        },
        // A tiny prime (2 to 64 bits) and one of 2047 or 2048 bits (n of
        // 2048 bits at most 2049 + 64).
        5 => blk: {
            const bq = rand.intRangeAtMost(usize, 2, 64);
            break :blk .{ 2048, bq };
        },
        // Both near the top: RSA-4096 and just under.
        6 => blk: {
            const bp = rand.intRangeAtMost(usize, 1990, 2048);
            break :blk .{ bp, rand.intRangeAtMost(usize, 1990, 2048) };
        },
        // RSA-2048 as generated by every tool: two 1024-bit primes (16
        // limbs each), started at random or just below 2^1024.
        8 => .{ 1024, 1024 },
        // Anything allowed.
        else => blk: {
            const bp = rand.intRangeAtMost(usize, 2, 2048);
            const lo: usize = if (bp >= 2049) 2 else @max(2, 2049 - bp);
            break :blk .{ bp, rand.intRangeAtMost(usize, lo, @as(usize, @min(2048, 4097 - bp))) };
        },
    };
}

fn envInt(name: []const u8, default: u64) u64 {
    const v = testing.environ.getPosix(name) orelse return default;
    return std.fmt.parseInt(u64, v, 0) catch default;
}

/// Inputs for the raw private operation: edges around 0, n, p and q,
/// multiples of p and q, and random values below n.
fn rawInputs(c: *Arith, k: Key, rand: std.Random, list: *std.ArrayList(Managed)) !void {
    const a = c.a;
    const n = try fromBe(a, k.n);
    const p = try fromBe(a, k.p);
    const q = try fromBe(a, k.q);
    for ([_]i64{ 0, 1, 2, 3, -1, -2 }) |v| {
        var x = try Managed.initSet(a, @abs(v));
        if (v < 0) try x.sub(&n, &x);
        try list.append(a, x);
    }
    for ([_]*const Managed{ &p, &q }) |f| {
        for ([_]i64{ 0, 1, -1 }) |off| {
            var x = try f.clone();
            const o = try Managed.initSet(a, @abs(off));
            if (off > 0) try x.add(&x, &o) else if (off < 0) try x.sub(&x, &o);
            try list.append(a, x);
        }
        // Random multiples (≡ 0 mod f), and those minus 1 (≡ −1 mod f).
        for (0..2) |i| {
            var r_bytes: [max_len]u8 = undefined;
            rand.bytes(r_bytes[0..k.n.len]);
            var r = try fromBe(a, r_bytes[0..k.n.len]);
            var x = try Managed.init(a);
            try c.mod(&x, &r, &n);
            var rem = try Managed.init(a);
            try c.mod(&rem, &x, f);
            try x.sub(&x, &rem);
            if (i == 1 and !x.eqlZero()) try x.sub(&x, &try Managed.initSet(a, 1));
            try list.append(a, x);
        }
    }
    // q·(p − 1): ≡ 0 mod q, ≡ −q mod p.
    var x = try Managed.init(a);
    try x.sub(&p, &try Managed.initSet(a, 1));
    try x.mul(&x, &q);
    try list.append(a, x);
    // Random below n, and of all-ones or all-zero limbs.
    for (0..3) |i| {
        var r_bytes: [max_len]u8 = undefined;
        const nb = r_bytes[0..k.n.len];
        rand.bytes(nb);
        if (i == 1) {
            for (nb, 0..) |*b, j| b.* = if ((j / 8) % 2 == 0) 0xff else 0;
        }
        var r = try fromBe(a, nb);
        try c.mod(&r, &r, &n);
        try list.append(a, r);
    }
}

/// Every check on one key; prints the key on failure.
fn checkKey(c: *Arith, k: Key, rand: std.Random, full_pows: usize) !void {
    errdefer {
        std.debug.print("rsa_stress: failing key (p {} bits, q {} bits, e {}):\n", .{ bitLen(k.p), bitLen(k.q), k.e });
        std.debug.print("key ", .{});
        for (k.der) |b| std.debug.print("{x:0>2}", .{b});
        std.debug.print("\n", .{});
    }
    const a = c.a;
    const key = try rsa.PrivateKey.fromPkcs1(k.der);
    const len = k.n.len;
    try testing.expectEqual(len, key.len);
    const ref_ok = referenceWorks(k.p, k.q);
    const ref: ?rsa_verify.Reference = if (ref_ok) try rsa_verify.Reference.fromPkcs1(k.der) else null;
    const n = try fromBe(a, k.n);
    const d = try fromBe(a, k.d);
    const e_big = try Managed.initSet(a, k.e);

    // Signatures: the reference's byte for byte, and s^e = EM.
    for (0..2) |_| {
        var msg: [100]u8 = undefined;
        const m = msg[0..rand.uintAtMost(usize, msg.len)];
        rand.bytes(m);
        var salt: [rsa.salt_len]u8 = undefined;
        rand.bytes(&salt);
        var out: [max_len]u8 = undefined;
        const sig = try key.sign(m, salt, &out);
        if (ref) |*r| {
            var out2: [max_len]u8 = undefined;
            try testing.expectEqualSlices(u8, try r.sign(m, salt, &out2), sig);
        }
        var em: [max_len]u8 = undefined;
        try rsa.encodePss(em[0..len], key.bits - 1, m, &salt);
        const s = try fromBe(a, sig);
        var back = try Managed.init(a);
        try c.powMod(&back, &s, &e_big, &n);
        var back_bytes: [max_len]u8 = undefined;
        try testing.expect(toBe(&back, back_bytes[0..len]));
        try testing.expectEqualSlices(u8, em[0..len], back_bytes[0..len]);
    }

    // Raw private operations: s < n and s^e = m; m^d for some; the
    // reference's result.
    var inputs: std.ArrayList(Managed) = .empty;
    try rawInputs(c, k, rand, &inputs);
    var full: usize = 0;
    for (inputs.items, 0..) |*x, i| {
        if (x.order(n) != .lt or !x.isPositive()) continue;
        var m_bytes: [max_len]u8 = undefined;
        try testing.expect(toBe(x, m_bytes[0..len]));
        var s_bytes: [max_len]u8 = undefined;
        try key.privateOp(m_bytes[0..len], s_bytes[0..len]);
        const s = try fromBe(a, s_bytes[0..len]);
        try testing.expect(s.order(n) == .lt);
        var back = try Managed.init(a);
        try c.powMod(&back, &s, &e_big, &n);
        if (!back.eql(x.*)) {
            std.debug.print("rsa_stress: raw input {} gives a wrong s\n", .{i});
            return error.TestUnexpectedResult;
        }
        // m^d mod n in full for the first input and some others.
        if (full < full_pows and (i == 0 or rand.uintLessThan(usize, inputs.items.len) < full_pows)) {
            var want = try Managed.init(a);
            try c.powMod(&want, x, &d, &n);
            try testing.expect(want.eql(s));
            full += 1;
        }
        if (ref) |*r| {
            var s2: [max_len]u8 = undefined;
            try r.privateOp(m_bytes[0..len], s2[0..len]);
            try testing.expectEqualSlices(u8, s2[0..len], s_bytes[0..len]);
        }
    }
}

fn bitLen(b: []const u8) usize {
    const v = trimmed(b);
    if (v.len == 0) return 0;
    return 8 * v.len - @clz(v[0]);
}

/// As rsa_verify's: std.crypto.ff's `reduce` needs q to have at least
/// p's count of 63-bit limbs.
fn referenceWorks(p: []const u8, q: []const u8) bool {
    return (bitLen(q) + 62) / 63 >= (bitLen(p) + 62) / 63;
}

/// A pool of primes by length and start, so keys share some primes (and
/// pairs give new moduli) while others are new.
const Pool = struct {
    entries: std.ArrayList(struct { bits: usize, start: Start, bytes: []const u8 }) = .empty,

    fn get(pool: *Pool, a: Allocator, bits: usize, start: Start, rand: std.Random) ![]const u8 {
        if (rand.boolean()) {
            for (pool.entries.items) |e| {
                if (e.bits == bits and e.start == start and rand.boolean()) return e.bytes;
            }
        }
        var buf: [256]u8 = undefined;
        const p = try a.dupe(u8, genPrime(&buf, bits, start, rand));
        try pool.entries.append(a, .{ .bits = bits, .start = start, .bytes = p });
        return p;
    }
};

test "rsa: random keys of every shape, against the reference and big integers" {
    const keys = envInt("RSA_KEYS", if (debug) 4 else 24);
    const seed = envInt("RSA_SEED", 0x5253415f4d4f4e54);
    const only_shape: ?usize = if (testing.environ.getPosix("RSA_SHAPE") != null) envInt("RSA_SHAPE", 0) else null;
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    var arena_state = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena_state.deinit();
    var pool_arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer pool_arena.deinit();
    var pool: Pool = .{};
    const es = [_]u32{ 65537, 3, 17, 0xffffffff, 0 };
    var made: usize = 0;
    var shapes: [shape_count]usize = @splat(0);
    var by_limbs: [3]usize = @splat(0);
    var tries: usize = 0;
    var swapped_order: usize = 0;
    while (made < keys) : (tries += 1) {
        _ = arena_state.reset(.retain_capacity);
        var c = try Arith.init(arena_state.allocator());
        // RSA_SHAPE=K: only shape K (8 is RSA-2048's).
        const which = if (only_shape) |k| k else tries;
        const bits = shape(rand, which);
        const starts = [_]Start{ .random, .random, .low, .high };
        // RSA-2048's shape needs n of 2048 bits: no `low` starts.
        const pick: []const Start = if (which % shape_count == 8) &.{ .random, .high } else &starts;
        const sp = pick[rand.uintLessThan(usize, pick.len)];
        const sq = pick[rand.uintLessThan(usize, pick.len)];
        const p = try pool.get(pool_arena.allocator(), bits[0], sp, rand);
        const q = try pool.get(pool_arena.allocator(), bits[1], sq, rand);
        if (std.mem.eql(u8, p, q)) continue;
        var e = es[rand.uintLessThan(usize, es.len)];
        if (e == 0) e = rand.int(u32) | 1 | (1 << 31);
        // Either order: p < q or p > q.
        const swap = rand.boolean();
        const k = (try makeKey(&c, if (swap) q else p, if (swap) p else q, e)) orelse continue;
        const n_bits = bitLen(k.n);
        if (n_bits < rsa.min_bits or n_bits > rsa.max_bits) continue;
        if (k.p.len > max_len / 2 or k.q.len > max_len / 2) continue;
        if (std.mem.order(u8, k.p, k.q) == .lt) swapped_order += 1;
        try checkKey(&c, k, rand, if (debug) 1 else 3);
        made += 1;
        shapes[which % shape_count] += 1;
        const pl = @max(k.p.len, k.q.len);
        by_limbs[if (pl <= 128) 0 else if (pl <= 192) 1 else 2] += 1;
    }
    if (keys >= 100) std.debug.print("rsa_stress: {} keys (seed {x}), {} primes, shapes {any}, limbs 16/24/32 {any}, p < q {}\n", .{ made, seed, pool.entries.items.len, shapes, by_limbs, swapped_order });
}

// -- Malformed keys -------------------------------------------------------

fn expectRejected(der: []const u8) !void {
    if (rsa.PrivateKey.fromPkcs1(der)) |_| {
        return error.TestUnexpectedResult;
    } else |err| switch (err) {
        error.InvalidKey, error.UnsupportedKey => {},
        error.SignatureFault => return error.TestUnexpectedResult,
    }
}

/// A minimal big-endian byte string of x + delta (delta small, may be
/// negative), allocated.
fn plus(a: Allocator, x: []const u8, delta: i64) ![]const u8 {
    var v = try fromBe(a, x);
    const dv = try Managed.initSet(a, @abs(delta));
    if (delta >= 0) try v.add(&v, &dv) else try v.sub(&v, &dv);
    if (!v.isPositive()) try v.set(0);
    const b = try bytesOf(a, &v);
    return if (b.len == 0) &.{0} else b;
}

test "rsa: malformed keys are rejected without a panic" {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var c = try Arith.init(a);
    var prng = std.Random.DefaultPrng.init(0x6261646b);
    const rand = prng.random();

    var pb: [256]u8 = undefined;
    var qb: [256]u8 = undefined;
    var p3b: [256]u8 = undefined;
    const p = try a.dupe(u8, genPrime(&pb, 1024, .random, rand));
    const q = try a.dupe(u8, genPrime(&qb, 1024, .random, rand));
    const p3 = try a.dupe(u8, genPrime(&p3b, 1024, .random, rand));
    const good = (try makeKey(&c, p, q, 65537)).?;
    _ = try rsa.PrivateKey.fromPkcs1(good.der);
    var e_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &e_buf, good.e, .big);
    const e = trimmed(&e_buf);
    const K = struct { n: []const u8, e: []const u8, d: []const u8, p: []const u8, q: []const u8, dp: []const u8, dq: []const u8, qi: []const u8 };
    const base: K = .{ .n = good.n, .e = e, .d = good.d, .p = good.p, .q = good.q, .dp = good.dp, .dq = good.dq, .qi = good.q_inv };
    const enc = struct {
        fn f(al: Allocator, k: K) ![]const u8 {
            return encodeDer(al, &.{0}, &.{ k.n, k.e, k.d, k.p, k.q, k.dp, k.dq, k.qi }, null);
        }
    }.f;
    var bad = std.ArrayList([]const u8).empty;
    var v = base;
    // p·q ≠ n.
    v = base;
    v.n = try plus(a, base.n, 2);
    try bad.append(a, try enc(a, v));
    v = base;
    v.n = try plus(a, base.n, -2);
    try bad.append(a, try enc(a, v));
    // Another prime for p, with n = p'·q but the old CRT values.
    {
        const k2 = (try makeKey(&c, p3, q, 65537)).?;
        v = base;
        v.n = k2.n;
        v.p = k2.p;
        try bad.append(a, try enc(a, v));
    }
    // qInv wrong: +1, 0, 1, p, p − 1, p + 1, p⁻¹ mod q (the other way
    // round), longer than p.
    for ([_]i64{ 1, -1 }) |dlt| {
        v = base;
        v.qi = try plus(a, base.qi, dlt);
        try bad.append(a, try enc(a, v));
    }
    for ([_][]const u8{ &.{0}, &.{1}, base.p, try plus(a, base.p, -1), try plus(a, base.p, 1), base.n }) |qi| {
        v = base;
        v.qi = qi;
        try bad.append(a, try enc(a, v));
    }
    {
        const swapped_key = (try makeKey(&c, q, p, 65537)).?;
        v = base;
        v.qi = swapped_key.q_inv;
        try bad.append(a, try enc(a, v));
    }
    // dP or dQ wrong, 0, 1, or longer than the prime.
    for ([_][]const u8{ &.{0}, &.{1}, try plus(a, base.dp, 2), base.n }) |dp| {
        v = base;
        v.dp = dp;
        try bad.append(a, try enc(a, v));
        v = base;
        v.dq = dp;
        try bad.append(a, try enc(a, v));
    }
    // p = q (n = p², qInv doesn't exist: 1 and 0).
    {
        var pp = try fromBe(a, base.p);
        try pp.mul(&pp, &pp);
        for ([_][]const u8{ &.{1}, &.{0}, base.qi }) |qi| {
            v = base;
            v.n = try bytesOf(a, &pp);
            v.q = base.p;
            v.dq = base.dp;
            v.qi = qi;
            try bad.append(a, try enc(a, v));
        }
    }
    // p or q even (n = p'·q to match), p = 1, q = 1 (with n = p), p = 2.
    {
        const pe = try plus(a, base.p, 1);
        var nn = try fromBe(a, pe);
        try nn.mul(&nn, &try fromBe(a, base.q));
        v = base;
        v.p = pe;
        v.n = try bytesOf(a, &nn);
        try bad.append(a, try enc(a, v));
        v = base;
        v.q = try plus(a, base.q, 1);
        try bad.append(a, try enc(a, v));
        v = base;
        v.p = &.{1};
        v.n = base.q;
        try bad.append(a, try enc(a, v));
        v = base;
        v.q = &.{1};
        v.n = base.p;
        try bad.append(a, try enc(a, v));
        v = base;
        v.p = &.{2};
        try bad.append(a, try enc(a, v));
    }
    // e = 0, 1, 2, 4, even, huge (5 bytes, 2^32 + 1), 2^32 − 1 (with the
    // CRT values for 65537), empty.
    for ([_][]const u8{ &.{0}, &.{1}, &.{2}, &.{4}, &.{ 1, 0, 0 }, &.{ 1, 0, 0, 0, 1 }, &.{ 0xff, 0xff, 0xff, 0xff }, &.{ 1, 0, 0, 0, 0, 0, 0, 0, 1 }, &.{} }) |ev| {
        v = base;
        v.e = ev;
        try bad.append(a, try enc(a, v));
    }
    // Missing or extra parts, versions 1 and 2, negative integers.
    try bad.append(a, try encodeDer(a, &.{0}, &.{ base.n, base.e, base.d, base.p, base.q, base.dp, base.dq }, null));
    try bad.append(a, try encodeDer(a, &.{0}, &.{ base.n, base.e, base.d, base.p, base.q, base.dp, base.dq, base.qi }, &.{5}));
    try bad.append(a, try encodeDer(a, &.{1}, &.{ base.n, base.e, base.d, base.p, base.q, base.dp, base.dq, base.qi }, null));
    try bad.append(a, try encodeDer(a, &.{2}, &.{ base.n, base.e, base.d, base.p, base.q, base.dp, base.dq, base.qi }, null));
    {
        // Negative p: its encoding without the pad byte.
        const der = try a.dupe(u8, good.der);
        if (std.mem.indexOf(u8, der, &.{ 0x00, base.p[0], base.p[1], base.p[2] })) |i| {
            der[i] = 0xff;
            try bad.append(a, der);
        }
    }
    // Truncations and corruptions of every DER header byte.
    for ([_]usize{ 0, 1, 2, 3, 4, 7, 10, 100, good.der.len - 1 }) |l| try bad.append(a, good.der[0..l]);
    for (0..12) |i| {
        const der = try a.dupe(u8, good.der);
        der[i] ^= 0x80;
        try bad.append(a, der);
        const der2 = try a.dupe(u8, good.der);
        der2[i] = 0xff;
        try bad.append(a, der2);
    }
    for (bad.items, 0..) |der, i| {
        expectRejected(der) catch |err| {
            std.debug.print("rsa_stress: malformed key {} accepted\n", .{i});
            return err;
        };
    }

    // Keys of sizes outside 2048 to 4096 bits: 1024 and 2047 bits (real
    // primes); 4097 and 8192 bits, and a prime over 2048 bits (odd
    // factors, as the length checks come first).
    for ([_][2]usize{ .{ 512, 512 }, .{ 1024, 1023 } }) |sz| {
        var b1: [256]u8 = undefined;
        var b2: [256]u8 = undefined;
        const pp = genPrime(&b1, sz[0], .random, rand);
        const qq = genPrime(&b2, sz[1], .random, rand);
        const k = (try makeKey(&c, pp, qq, 65537)).?;
        try testing.expectError(error.UnsupportedKey, rsa.PrivateKey.fromPkcs1(k.der));
    }
    for ([_][2]usize{ .{ 2049, 2048 }, .{ 2048, 2049 }, .{ 4096, 4096 }, .{ 2200, 1000 }, .{ 1000, 2200 } }) |sz| {
        var b1: [512]u8 = undefined;
        var b2: [512]u8 = undefined;
        const pp = b1[0 .. (sz[0] + 7) / 8];
        const qq = b2[0 .. (sz[1] + 7) / 8];
        for ([_][]u8{ pp, qq }, sz) |f, bits| {
            rand.bytes(f);
            f[0] &= @as(u8, 0xff) >> @intCast(8 * f.len - bits);
            f[0] |= @as(u8, 1) << @intCast(bits - 1 - 8 * (f.len - 1));
            f[f.len - 1] |= 1;
        }
        var nn = try fromBe(a, pp);
        try nn.mul(&nn, &try fromBe(a, qq));
        const nb = try bytesOf(a, &nn);
        try expectRejected(try encodeDer(a, &.{0}, &.{ nb, e, nb, pp, qq, pp, qq, qq }, null));
    }

    // The d in the file isn't used: a wrong one is accepted (the CRT
    // parts make a working key).
    v = base;
    v.d = try plus(a, base.d, 2);
    _ = try rsa.PrivateKey.fromPkcs1(try enc(a, v));
    // dP + (p − 1) (the same exponent mod p − 1, still p's length) works.
    {
        var dp2 = try fromBe(a, base.dp);
        try dp2.add(&dp2, &try fromBe(a, try plus(a, base.p, -1)));
        const b = try bytesOf(a, &dp2);
        if (b.len <= base.p.len) {
            v = base;
            v.dp = b;
            _ = try rsa.PrivateKey.fromPkcs1(try enc(a, v));
        }
    }
    // A weak but working key: p = 3, q of 2046 bits.
    {
        var qb2: [256]u8 = undefined;
        while (true) {
            const qq = genPrime(&qb2, 2046, .random, rand);
            const k = (try makeKey(&c, &.{3}, qq, 65537)) orelse continue;
            const key = try rsa.PrivateKey.fromPkcs1(k.der);
            try testing.expectEqual(@as(usize, 1), key.p_len);
            try checkKey(&c, k, rand, 1);
            break;
        }
    }
}

test "rsa: an 8192-bit key in PEM is rejected by the credentials loader" {
    // A modulus of 8192 bits (the factors needn't be prime for the length
    // checks): PKCS#1 and PKCS#8, through Credentials.fromPem.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var n: [1024]u8 = @splat(0xab);
    var half: [512]u8 = @splat(0xcd);
    n[1023] |= 1;
    half[511] |= 1;
    const der = try encodeDer(a, &.{0}, &.{ &n, &.{ 1, 0, 1 }, &n, &half, &half, &half, &half, &half }, null);
    var pkcs8: std.ArrayList(u8) = .empty;
    {
        var body: std.ArrayList(u8) = .empty;
        try body.appendSlice(a, &.{ 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04 });
        try derLen(a, &body, der.len);
        try body.appendSlice(a, der);
        try pkcs8.append(a, 0x30);
        try derLen(a, &pkcs8, body.items.len);
        try pkcs8.appendSlice(a, body.items);
    }
    for ([_]struct { []const u8, []const u8 }{ .{ "RSA PRIVATE KEY", der }, .{ "PRIVATE KEY", pkcs8.items } }) |c| {
        const b64 = try a.alloc(u8, std.base64.standard.Encoder.calcSize(c[1].len));
        _ = std.base64.standard.Encoder.encode(b64, c[1]);
        const pem = try std.fmt.allocPrint(a, "-----BEGIN {s}-----\n{s}\n-----END {s}-----\n", .{ c[0], b64, c[0] });
        if (credentials.Credentials.fromPem(testing.allocator, credentials.testdata.rsa2048_cert, pem)) |cr| {
            var cred = cr;
            cred.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
        try expectRejected(der);
    }
}

// -- Faults ---------------------------------------------------------------

test "rsa: a fault anywhere in the key state is caught or harmless" {
    // Every limb of every CRT part (and dP, dQ, e) flipped in one random
    // bit: sign gives the correct signature or SignatureFault with a
    // zeroed output, never a wrong signature.
    var store: [2][4096]u8 = undefined;
    const pems = [_][]const u8{ credentials.testdata.rsa2048_key, credentials.testdata.rsa4096_key };
    var prng = std.Random.DefaultPrng.init(0x6661756c74);
    const rand = prng.random();
    var faults: usize = 0;
    var caught: usize = 0;
    for (pems[0..if (debug) 1 else 2], 0..) |pem, ki| {
        const der = try rsa_verify.pemToPkcs1(&store[ki], pem);
        const good = try rsa.PrivateKey.fromPkcs1(der);
        var want_buf: [max_len]u8 = undefined;
        const want = try good.sign("message", @splat(7), &want_buf);
        const stride: usize = if (debug) 7 else 1;
        switch (good.crt) {
            inline else => |crt_good, tag| {
                const Parts = @TypeOf(crt_good);
                inline for (.{ "p", "q", "n" }) |half| {
                    inline for (.{ "m", "one", "r2" }) |field| {
                        const len = @field(@field(crt_good, half), field).len;
                        var i: usize = 0;
                        while (i < len) : (i += stride) {
                            var key = good;
                            const crt = &@field(key.crt, @tagName(tag));
                            @field(@field(crt, half), field)[i] ^= @as(u64, 1) << rand.int(u6);
                            try expectSafe(&key, want, &faults, &caught);
                        }
                    }
                    var key = good;
                    @field(@field(key.crt, @tagName(tag)), half).m0inv ^= @as(u64, 1) << rand.int(u6);
                    try expectSafe(&key, want, &faults, &caught);
                }
                inline for (.{ "q_inv", "p_r3", "q_r3" }) |field| {
                    var i: usize = 0;
                    while (i < @field(crt_good, field).len) : (i += stride) {
                        var key = good;
                        @field(@field(key.crt, @tagName(tag)), field)[i] ^= @as(u64, 1) << rand.int(u6);
                        try expectSafe(&key, want, &faults, &caught);
                    }
                }
                _ = Parts;
            },
        }
        var i: usize = 0;
        while (i < good.p_len) : (i += stride) {
            var key = good;
            key.dp[i] ^= @as(u8, 1) << rand.int(u3);
            try expectSafe(&key, want, &faults, &caught);
            key = good;
            key.dq[i] ^= @as(u8, 1) << rand.int(u3);
            try expectSafe(&key, want, &faults, &caught);
        }
        var key = good;
        key.e ^= 2;
        try expectSafe(&key, want, &faults, &caught);
    }
    try testing.expect(caught > faults / 2);
}

fn expectSafe(key: *const rsa.PrivateKey, want: []const u8, faults: *usize, caught: *usize) !void {
    faults.* += 1;
    var out: [max_len]u8 = @splat(0xaa);
    if (key.sign("message", @splat(7), &out)) |sig| {
        try testing.expectEqualSlices(u8, want, sig);
    } else |err| {
        try testing.expectEqual(error.SignatureFault, err);
        try testing.expect(std.mem.allEqual(u8, out[0..key.len], 0));
        caught.* += 1;
    }
}
