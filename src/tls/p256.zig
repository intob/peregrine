//! P-256 with a precomputed table for the base point, for the two
//! operations a TLS server does with it on every handshake: the ECDSA
//! signature in CertificateVerify, and the ECDHE key pair.
//!
//! std multiplies the base point with a 4-bit window: 64 additions and 252
//! doublings. Here a table holds 1..8 × 16^i × G for each of a scalar's 65
//! signed 4-bit digits, in affine coordinates (33 KB, built once on first
//! use), so k × G is 65 mixed additions and no doublings. Each lookup scans
//! its whole row and negates by a mask, so the time doesn't depend on the
//! scalar. Field and scalar arithmetic, the point formulas and the
//! deterministic nonce are std's, so signatures equal std's byte for byte.
const std = @import("std");
const sys = @import("../sys.zig");
const P256 = std.crypto.ecc.P256;
const Fe = P256.Fe;
const Scalar = P256.scalar.Scalar;
const Affine = @TypeOf(P256.basePoint.affineCoordinates());
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

const rows = 65;
const Row = [8]Affine;

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

/// Row i holds j × 16^i × G for j = 1..8. Converted to affine with one
/// inversion for the whole table (Montgomery's trick).
fn buildTable() void {
    var points: [rows * 8]P256 = undefined;
    var base = P256.basePoint;
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
        table[i / 8][i % 8] = .{ .x = points[i].x.mul(zinv), .y = points[i].y.mul(zinv) };
        if (i == 0) break;
    }
}

/// A little-endian scalar as 65 digits in [-8, 8), the last 0 or 1.
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

/// s × G in constant time, for a little-endian scalar. The identity if s
/// is a multiple of the order (callers reject it).
pub fn mulBase(s: [32]u8) P256 {
    const t = baseTable();
    const e = recode(s);
    var q = P256.identityElement;
    for (e, t) |d, *row| {
        const negative: u8 = @bitCast(d >> 7);
        const abs: u8 = (@as(u8, @bitCast(d)) ^ negative) -% negative;
        // The identity (x = 0) when the digit is 0: addMixed then keeps q.
        var p = Affine.identityElement;
        for (row, 1..) |entry, j| {
            const c: u1 = @truncate((@as(u32, abs ^ @as(u8, @intCast(j))) -% 1) >> 31);
            p.x.cMov(entry.x, c);
            p.y.cMov(entry.y, c);
        }
        p.y.cMov(p.y.neg(), @truncate(negative));
        q = q.addMixed(p);
    }
    return q;
}

/// std's hedged deterministic nonce (ecdsa.zig's `deterministicScalar`,
/// for P-256 with SHA-256): HMAC-DRBG over the hash, the secret key and
/// the noise.
fn deterministicScalar(h: [32]u8, secret_key: [32]u8, noise: [32]u8) Scalar {
    var k: [32]u8 = @splat(0);
    var m: [32 + 1 + 32 + 32 + 32]u8 = @splat(0);
    var t: [32]u8 = undefined;
    const m_v = m[0..32];
    const m_i = &m[32];
    @memset(m_v, 0x01);
    m_i.* = 0x00;
    m[33..65].* = noise;
    m[65..97].* = secret_key;
    m[97..129].* = h;
    Hmac.create(&k, &m, &k);
    Hmac.create(m_v, m_v, &k);
    m_i.* = 0x01;
    Hmac.create(&k, &m, &k);
    Hmac.create(m_v, m_v, &k);
    while (true) {
        Hmac.create(m_v, m_v, &k);
        t = m_v.*;
        if (Scalar.fromBytes(t, .big)) |s| return s else |_| {}
        m_i.* = 0x00;
        Hmac.create(&k, m[0..33], &k);
        Hmac.create(m_v, m_v, &k);
    }
}

fn reduce(bytes: [32]u8) Scalar {
    return Scalar.fromBytes48(@as([16]u8, @splat(0)) ++ bytes, .big);
}

/// ECDSA with SHA-256: the same signature as std's `KeyPair.sign` with the
/// same noise.
pub fn sign(key_pair: Ecdsa.KeyPair, msg: []const u8, noise: [32]u8) !Ecdsa.Signature {
    var h: [32]u8 = undefined;
    Sha256.hash(msg, &h, .{});
    const z = reduce(h);
    const secret = key_pair.secret_key.bytes;
    const k = deterministicScalar(h, secret, noise);
    const p = mulBase(k.toBytes(.little));
    const r = reduce(p.affineCoordinates().x.toBytes(.big));
    if (r.isZero()) return error.IdentityElement;
    const s = k.invert().mul(z.add(r.mul(try Scalar.fromBytes(secret, .big))));
    if (s.isZero()) return error.IdentityElement;
    return .{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
}

pub const KeyPair = struct {
    /// Big-endian.
    secret_key: [32]u8,
    /// Uncompressed SEC1.
    public_key: [65]u8,
};

/// The key pair std's `generateDeterministic` makes from the same seed.
pub fn keyPair(seed: [32]u8) !KeyPair {
    const secret = deterministicScalar(@splat(0), @splat(0x01), seed);
    const p = mulBase(secret.toBytes(.little));
    try p.rejectIdentity();
    return .{ .secret_key = secret.toBytes(.big), .public_key = p.toUncompressedSec1() };
}

const testing = std.testing;

test "p256: k × G from the table equals std's, for random and edge scalars" {
    var prng = std.Random.DefaultPrng.init(0x256);
    const random = prng.random();
    const n_minus_1 = (try Scalar.fromBytes(@splat(0), .little)).sub(Scalar.one).toBytes(.little);
    var edges = [_][32]u8{ @splat(0), @splat(0x88), @splat(0x77), n_minus_1, @splat(0) };
    edges[0][0] = 1;
    edges[4][31] = 0x80;
    for (0..300 + edges.len) |i| {
        var s: [32]u8 = undefined;
        if (i < edges.len) {
            s = edges[i];
        } else {
            random.bytes(&s);
            s = Scalar.fromBytes48(@as([16]u8, @splat(0)) ++ s, .little).toBytes(.little);
        }
        const ours = mulBase(s);
        const theirs = try P256.basePoint.mul(s, .little);
        try testing.expect(ours.equivalent(theirs));
    }
    // A multiple of the order gives the identity.
    try testing.expectError(error.IdentityElement, mulBase(@splat(0)).rejectIdentity());
}

test "p256: signatures and key pairs equal std's" {
    var prng = std.Random.DefaultPrng.init(0x5167);
    const random = prng.random();
    for (0..50) |_| {
        var seed: [32]u8 = undefined;
        random.bytes(&seed);
        const kp = try Ecdsa.KeyPair.generateDeterministic(seed);
        const ours = try keyPair(seed);
        try testing.expectEqualSlices(u8, &kp.secret_key.bytes, &ours.secret_key);
        try testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), &ours.public_key);
        var buf: [130]u8 = undefined;
        random.bytes(&buf);
        const msg = buf[0..random.uintAtMost(usize, buf.len)];
        var noise: [32]u8 = undefined;
        random.bytes(&noise);
        const sig = try sign(kp, msg, noise);
        const expected = try kp.sign(msg, noise);
        try testing.expectEqualSlices(u8, &expected.toBytes(), &sig.toBytes());
        try sig.verify(msg, kp.public_key);
    }
}
