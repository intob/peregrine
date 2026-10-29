//! X25519 for the server's key share on every handshake: the public key
//! with a precomputed table, and the shared secret with a faster ladder.
//!
//! std computes the public key with the Montgomery ladder: 255 steps. Here
//! it is the u-coordinate of the clamped secret × B on the equivalent
//! Edwards curve (u = (1 + y) / (1 − y)), with a table of B as in
//! `p256.zig`: 1..8 × 16^i × B for each of 65 signed 4-bit digits, as
//! (y + x, y − x, 2d·x·y), so k × B is 65 mixed additions of 7
//! multiplications each, plus one inversion. Lookups scan the whole row.
//! The table is built with std's Edwards25519, then held, and the sums
//! made, in `field25519.zig`'s faster field (see below).
//!
//! The shared secret (the client's point varies) is std's Montgomery
//! ladder, step for step, over a faster field (`field25519.zig`: four
//! 64-bit limbs instead of five 51-bit ones), with the step's operations
//! ordered and interleaved so the longest dependency chains start first.
const std = @import("std");
const sys = @import("../sys.zig");
const field = @import("./field25519.zig");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Fe = Edwards25519.Fe;
const X25519 = std.crypto.dh.X25519;

/// The table's field and points use `field25519`'s limbs, like the ladder.
const F = field.Fe;
const Niels = struct { ypx: F, ymx: F, xy2d: F };
const identity = Niels{ .ypx = F.one, .ymx = F.one, .xy2d = F.zero };
/// Extended coordinates: x = X/Z, y = Y/Z, x·y = T/Z.
const Point = struct { x: F, y: F, z: F, t: F };

const rows = 65;
const Row = [8]Niels;

var table: [rows]Row = undefined;
var table_ready = std.atomic.Value(bool).init(false);
var table_mutex: sys.Mutex = .{};

fn baseTable() *const [rows]Row {
    if (table_ready.load(.acquire)) return &table;
    table_mutex.lock();
    defer table_mutex.unlock();
    if (!table_ready.load(.monotonic)) {
        buildTable();
        table_ready.store(true, .release);
    }
    return &table;
}

/// Row i holds j × 16^i × B for j = 1..8; one inversion for the table.
fn buildTable() void {
    var points: [rows * 8]Edwards25519 = undefined;
    var base = Edwards25519.basePoint;
    base.is_base = false;
    for (0..rows) |i| {
        var p = base;
        for (0..8) |j| {
            points[i * 8 + j] = p;
            p = p.add(base);
        }
        base = base.dbl().dbl().dbl().dbl();
    }
    var prefix: [rows * 8]Fe = undefined;
    prefix[0] = points[0].z;
    for (1..points.len) |i| prefix[i] = prefix[i - 1].mul(points[i].z);
    var inv = prefix[points.len - 1].invert();
    var i = points.len - 1;
    while (true) : (i -= 1) {
        const zinv = if (i == 0) inv else inv.mul(prefix[i - 1]);
        inv = inv.mul(points[i].z);
        const x = points[i].x.mul(zinv);
        const y = points[i].y.mul(zinv);
        table[i / 8][i % 8] = .{
            .ypx = .fromBytes(y.add(x).toBytes()),
            .ymx = .fromBytes(y.sub(x).toBytes()),
            .xy2d = .fromBytes(x.mul(y).mul(Fe.edwards25519d2).toBytes()),
        };
        if (i == 0) break;
    }
}

/// p + q, q from the table (twisted Edwards, a = −1: complete).
fn madd(p: Point, q: Niels) Point {
    const abc = F.mulN(3, .{ p.y.sub(p.x), p.y.add(p.x), p.t }, .{ q.ymx, q.ypx, q.xy2d });
    const d = p.z.add(p.z);
    const e = abc[1].sub(abc[0]);
    const f = d.sub(abc[2]);
    const g = d.add(abc[2]);
    const h = abc[1].add(abc[0]);
    const r = F.mulN(4, .{ e, g, f, e }, .{ f, h, g, h });
    return .{ .x = r[0], .y = r[1], .z = r[2], .t = r[3] };
}

/// A scalar below 2^253 as 65 digits in [-8, 8), the last 0 or 1.
fn recode(s: [32]u8) [rows]i8 {
    var e: [rows]i8 = undefined;
    for (s, 0..) |x, i| {
        e[i * 2] = @as(i8, @as(u4, @truncate(x)));
        e[i * 2 + 1] = @as(i8, @as(u4, @truncate(x >> 4)));
    }
    var carry: i8 = 0;
    for (e[0 .. rows - 1]) |*x| {
        x.* += carry;
        carry = (x.* + 8) >> 4;
        x.* -= carry * 16;
    }
    e[rows - 1] = carry;
    return e;
}

/// s × B in constant time, for a scalar reduced mod L.
fn mulBase(s: [32]u8) Point {
    const t = baseTable();
    const e = recode(s);
    var q: Point = .{ .x = F.zero, .y = F.one, .z = F.one, .t = F.zero };
    for (e, t) |d, *row| {
        const negative: u8 = @bitCast(d >> 7);
        const abs: u8 = (@as(u8, @bitCast(d)) ^ negative) -% negative;
        var p = identity;
        for (row, 1..) |entry, j| {
            const c: u64 = (@as(u64, abs ^ @as(u8, @intCast(j))) -% 1) >> 63;
            p.ypx.cMov(entry.ypx, c);
            p.ymx.cMov(entry.ymx, c);
            p.xy2d.cMov(entry.xy2d, c);
        }
        // −(x, y) is (−x, y): y + x and y − x swap, 2d·x·y flips sign.
        const n: u64 = negative & 1;
        const ypx = p.ypx;
        p.ypx.cMov(p.ymx, n);
        p.ymx.cMov(ypx, n);
        p.xy2d.cMov(F.zero.sub(p.xy2d), n);
        q = madd(q, p);
    }
    return q;
}

/// The public key for an X25519 secret key: the same as std's
/// `X25519.recoverPublicKey`.
pub fn publicKey(secret_key: [32]u8) [32]u8 {
    var s = secret_key;
    Edwards25519.scalar.clamp(&s);
    // B has order L, so the clamped scalar works reduced.
    const p = mulBase(Edwards25519.scalar.reduce(s));
    // u = (1 + y) / (1 − y) = (Z + Y) / (Z − Y).
    return p.z.add(p.y).mul(p.z.sub(p.y).invert()).toBytes();
}

/// The X25519 function (RFC 7748 §5): the same as std's
/// `X25519.scalarmult`, including `error.IdentityElement` when the result
/// is zero (a low-order point). In constant time: the scalar's bits only
/// make masks for conditional swaps.
pub fn sharedSecret(secret_key: [32]u8, public_key: [32]u8) error{IdentityElement}![32]u8 {
    var s = secret_key;
    Edwards25519.scalar.clamp(&s);
    defer std.crypto.secureZero(u8, &s);
    const x1 = F.fromBytes(public_key);
    var x2 = F.one;
    var z2 = F.zero;
    var x3 = x1;
    var z3 = F.one;
    var swap: u64 = 0;
    // Clamping clears bit 255 and sets bit 254, as in std's ladder.
    var pos: usize = 254;
    while (true) : (pos -= 1) {
        const bit: u64 = (s[pos >> 3] >> @as(u3, @truncate(pos))) & 1;
        swap ^= bit;
        F.cSwap(&x2, &x3, swap);
        F.cSwap(&z2, &z3, swap);
        swap = bit;
        // RFC 7748's step: x3 = (DA + CB)², z3 = x1·(DA − CB)²,
        // x2 = AA·BB, z2 = E·(BB + 121666·E). The chains through DA and
        // CB to z3, and through AA and BB to z2, are the longest, so they
        // come first; x2 last.
        const a = x2.add(z2);
        const b = x2.sub(z2);
        const d = x3.sub(z3);
        const c = x3.add(z3);
        const da_cb = F.mulN(2, .{ d, c }, .{ a, b });
        const aa_bb = F.sqN(2, .{ a, b });
        const t = F.sqN(2, .{ da_cb[0].sub(da_cb[1]), da_cb[0].add(da_cb[1]) });
        const e = aa_bb[0].sub(aa_bb[1]);
        const r = F.mulN(3, .{ x1, e, aa_bb[0] }, .{ t[0], e.mulAdd121666(aa_bb[1]), aa_bb[1] });
        z3 = r[0];
        z2 = r[1];
        x3 = t[1];
        x2 = r[2];
        if (pos == 0) break;
    }
    F.cSwap(&x2, &x3, swap);
    F.cSwap(&z2, &z3, swap);
    const out = x2.mul(z2.invert()).toBytes();
    var acc: u8 = 0;
    for (out) |byte| acc |= byte;
    if (acc == 0) return error.IdentityElement;
    return out;
}

test "x25519: public keys equal std's, including RFC 7748's" {
    const testing = std.testing;
    // RFC 7748 §6.1: Alice's and Bob's key pairs.
    const alice_sk = [32]u8{ 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a };
    const alice_pk = [32]u8{ 0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a };
    const bob_sk = [32]u8{ 0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb };
    const bob_pk = [32]u8{ 0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f };
    try testing.expectEqualSlices(u8, &alice_pk, &publicKey(alice_sk));
    try testing.expectEqualSlices(u8, &bob_pk, &publicKey(bob_sk));
    var prng = std.Random.DefaultPrng.init(0x25519);
    const random = prng.random();
    for (0..300 + 3) |i| {
        var sk: [32]u8 = switch (i) {
            0 => @splat(0),
            1 => @splat(0xff),
            2 => @splat(0x88),
            else => undefined,
        };
        if (i > 2) random.bytes(&sk);
        try testing.expectEqualSlices(u8, &X25519.recoverPublicKey(sk), &publicKey(sk));
    }
}

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "x25519: shared secrets match RFC 7748's vectors, iterated 1 and 1000 times" {
    const testing = std.testing;
    // §5.2
    try testing.expectEqualSlices(u8, &hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"), &try sharedSecret(
        hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
        hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
    ));
    try testing.expectEqualSlices(u8, &hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"), &try sharedSecret(
        hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
        hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
    ));
    // §5.2's iterations: k = X25519(k, u), u = the old k.
    var k: [32]u8 = @splat(0);
    k[0] = 9;
    var u = k;
    for (1..1001) |i| {
        const next = try sharedSecret(k, u);
        u = k;
        k = next;
        if (i == 1) try testing.expectEqualSlices(u8, &hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), &k);
    }
    try testing.expectEqualSlices(u8, &hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), &k);
    // §6.1: both sides of a Diffie-Hellman exchange.
    const shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    const alice_sk = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const bob_sk = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    try testing.expectEqualSlices(u8, &shared, &try sharedSecret(alice_sk, publicKey(bob_sk)));
    try testing.expectEqualSlices(u8, &shared, &try sharedSecret(bob_sk, publicKey(alice_sk)));
}

/// Expects the same result as std's `X25519.scalarmult`, error or bytes.
fn expectSameAsStd(secret_key: [32]u8, public_key: [32]u8) !void {
    const theirs = X25519.scalarmult(secret_key, public_key);
    const ours = sharedSecret(secret_key, public_key);
    if (theirs) |t| {
        try std.testing.expectEqualSlices(u8, &t, &try ours);
    } else |err| {
        try std.testing.expectError(err, ours);
    }
}

/// u-coordinates of points of small order: on Curve25519 (orders 1, 2 and
/// 8, and p − 1 of order 4) and its twist (1, of order 4). Each gives a
/// zero shared secret.
const low_order = [_][32]u8{
    hex("0000000000000000000000000000000000000000000000000000000000000000"),
    hex("0100000000000000000000000000000000000000000000000000000000000000"),
    hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
    hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
};

/// u; u + p when that is below 2^255 (a non-canonical encoding); and both
/// with bit 255 set (which X25519 ignores).
fn encodings(u: [32]u8) [4][32]u8 {
    const p: u256 = (1 << 255) - 19;
    const v = std.mem.readInt(u256, &u, .little);
    var out: [4][32]u8 = .{ u, u, u, u };
    if (v < 19) std.mem.writeInt(u256, &out[1], v + p, .little);
    out[2][31] |= 0x80;
    out[3] = out[1];
    out[3][31] |= 0x80;
    return out;
}

test "x25519: shared secrets equal std's: random, non-canonical and low-order points" {
    const testing = std.testing;
    var prng = std.Random.DefaultPrng.init(0x7748);
    const random = prng.random();
    const scalars = [_][32]u8{ @splat(0), @splat(0xff), @splat(0x55), hex("0800000000000000000000000000000000000000000000000000000000000040") };
    for (low_order) |u| {
        for (encodings(u)) |e| {
            for (scalars) |sk| try expectSameAsStd(sk, e);
            for (0..20) |_| {
                var sk: [32]u8 = undefined;
                random.bytes(&sk);
                try testing.expectError(error.IdentityElement, sharedSecret(sk, e));
                try expectSameAsStd(sk, e);
            }
        }
    }
    // Every non-canonical u from p to 2^255 − 1, with and without bit 255.
    for (0..19) |i| {
        var u: [32]u8 = @splat(0xff);
        u[31] = 0x7f;
        u[0] = 0xed + @as(u8, @intCast(i));
        for (encodings(u)) |e| {
            for (scalars) |sk| try expectSameAsStd(sk, e);
            var sk: [32]u8 = undefined;
            random.bytes(&sk);
            try expectSameAsStd(sk, e);
        }
    }
    for (0..1000) |i| {
        var sk: [32]u8 = undefined;
        var u: [32]u8 = undefined;
        random.bytes(&sk);
        random.bytes(&u);
        switch (i % 4) {
            0 => {},
            1 => u[31] |= 0x80,
            // Limbs of all ones or all zeros.
            2 => for (0..4) |j| {
                if (random.boolean()) @memset(u[j * 8 ..][0..8], if (random.boolean()) 0xff else 0);
            },
            else => @memset(u[1..], 0),
        }
        try expectSameAsStd(sk, u);
        // A point on the curve, as a peer's public key would be.
        try expectSameAsStd(sk, publicKey(u));
    }
}

// Fuzz target: any scalar and point give std's result.
fn fuzzSharedSecret(_: void, smith: *std.testing.Smith) anyerror!void {
    var sk: [32]u8 = undefined;
    var u: [32]u8 = undefined;
    smith.bytes(&sk);
    smith.bytes(&u);
    try expectSameAsStd(sk, u);
}

test "fuzz: x25519 shared secret against std" {
    try std.testing.fuzz({}, fuzzSharedSecret, .{ .corpus = &.{
        &(@as([32]u8, @splat(0x11)) ++ low_order[2]),
        &(@as([32]u8, @splat(0xff)) ++ @as([32]u8, @splat(0xff))),
    } });
}
