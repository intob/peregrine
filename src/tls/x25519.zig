//! X25519 public keys with a precomputed table, for the server's key share
//! on every handshake.
//!
//! std computes the public key with the Montgomery ladder: 255 steps. Here
//! it is the u-coordinate of the clamped secret × B on the equivalent
//! Edwards curve (u = (1 + y) / (1 − y)), with a table of B as in
//! `p256.zig`: 1..8 × 16^i × B for each of 65 signed 4-bit digits, as
//! (y + x, y − x, 2d·x·y), so k × B is 65 mixed additions of 7
//! multiplications each, plus one inversion. Lookups scan the whole row.
//! The shared secret still uses std's ladder (the client's point varies).
const std = @import("std");
const sys = @import("../sys.zig");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Fe = Edwards25519.Fe;
const X25519 = std.crypto.dh.X25519;

const Niels = struct { ypx: Fe, ymx: Fe, xy2d: Fe };
const identity = Niels{ .ypx = Fe.one, .ymx = Fe.one, .xy2d = Fe.zero };

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
        table[i / 8][i % 8] = .{ .ypx = y.add(x), .ymx = y.sub(x), .xy2d = x.mul(y).mul(Fe.edwards25519d2) };
        if (i == 0) break;
    }
}

/// p + q, q from the table (twisted Edwards, a = −1: complete).
fn madd(p: Edwards25519, q: Niels) Edwards25519 {
    const a = p.y.sub(p.x).mul(q.ymx);
    const b = p.y.add(p.x).mul(q.ypx);
    const c = p.t.mul(q.xy2d);
    const d = p.z.add(p.z);
    const e = b.sub(a);
    const f = d.sub(c);
    const g = d.add(c);
    const h = b.add(a);
    return .{ .x = e.mul(f), .y = g.mul(h), .z = f.mul(g), .t = e.mul(h) };
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
fn mulBase(s: [32]u8) Edwards25519 {
    const t = baseTable();
    const e = recode(s);
    var q = Edwards25519.identityElement;
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
        p.xy2d.cMov(p.xy2d.neg(), n);
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
