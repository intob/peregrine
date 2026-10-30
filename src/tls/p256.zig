//! P-256 for what a TLS server does with it on every handshake: the ECDSA
//! signature in CertificateVerify, and the ECDHE key pair and shared
//! secret (secp256r1 key shares).
//!
//! std's `mul` doubles 252 times and adds 64 times with complete
//! projective formulas (Renes–Costello–Batina: 14 multiplications per
//! doubling and per addition, b included) over fiat-crypto's field. Here:
//!
//! - The field is `field_p256.zig`: Montgomery reduction specialised to
//!   p's shape and a dedicated square (std's field multiplies by p's
//!   limbs and squares with a multiplication).
//! - Points are Jacobian (x = X/Z², y = Y/Z³): a doubling is 4
//!   multiplications and 4 squares (a = −3), an addition of a table
//!   point with its Z² and Z³ stored 11 and 3, a mixed addition 8 and 3,
//!   grouped in independent products (`mulN`, `sqN`).
//! - Affine coordinates take one inversion by Fermat's little theorem
//!   (an addition chain for 1/Z²) instead of std's divsteps, and a key
//!   share (`keyShare`: our public key and the shared secret) takes one
//!   inversion for both.
//!
//! The variable base (the peer's share) is a signed 4-bit window: a table
//! of 1..8 × P, 64 times four doublings and one addition. The fixed base
//! (key pairs and signatures) is a table of 1..8 × 16^i × G for each of a
//! scalar's 65 signed digits, in affine coordinates (33 KB, built once on
//! first use), so k × G is 65 mixed additions and no doublings.
//!
//! Jacobian addition formulas are incomplete: they fail when an input is
//! the identity or both inputs are equal. Both multiplications handle an
//! identity input with constant-time selections; then, for any 256-bit
//! scalar, the equal case can't happen in the fixed-base sum, and
//! happens in the variable-base loop only for the scalar n − 2, at its
//! last addition, which also computes the doubling and selects it (see
//! `mulVar` and `mulBase`). Lookups scan every table entry, signs
//! are applied by masks, and runtime safety is on only in Debug builds
//! (as in the field), so the time doesn't depend on the scalar. Scalars
//! and their digits are zeroed after use.
//!
//! Results equal std's byte for byte, errors included (see the tests and
//! `p256_verify.zig`); the scalar field and the deterministic nonce are
//! std's.
const std = @import("std");
const sys = @import("../sys.zig");
const field = @import("./field_p256.zig");
const F = field.Fe;
const P256 = std.crypto.ecc.P256;
const Scalar = P256.scalar.Scalar;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// The group order.
const n: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

/// Jacobian coordinates: x = X/Z², y = Y/Z³. Z = 0 is the identity.
const Point = struct {
    x: F,
    y: F,
    z: F,

    const identity: Point = .{ .x = F.one, .y = F.one, .z = F.zero };

    fn cMov(p: *Point, q: Point, c: u64) void {
        p.x.cMov(q.x, c);
        p.y.cMov(q.y, c);
        p.z.cMov(q.z, c);
    }
};

const Affine = struct { x: F, y: F };

/// A variable-base table entry: Jacobian, with Z² and Z³ for the addition.
const Entry = struct {
    x: F,
    y: F,
    z: F,
    zz: F,
    zzz: F,

    fn fromPoint(p: Point) Entry {
        const zz = p.z.sq();
        return .{ .x = p.x, .y = p.y, .z = p.z, .zz = zz, .zzz = zz.mul(p.z) };
    }

    fn point(e: Entry) Point {
        return .{ .x = e.x, .y = e.y, .z = e.z };
    }
};

/// 2p (dbl-2004-hmv, a = −3): 4 multiplications, 4 squares, and fewer
/// additions than dbl-2001-b's 3 and 5 (on the M2 the field is limited
/// by instruction throughput, additions included). The identity (Z = 0)
/// stays the identity.
fn dbl(p: Point) Point {
    @setRuntimeSafety(field.safe);
    const y2 = p.y.dbl();
    const s = F.sqN(2, .{ p.z, y2 }); // δ = Z², 4γ = 4Y²
    const z3 = y2.mul(p.z); // 2·Y·Z
    const t = F.mulN(2, .{ p.x.sub(s[0]), s[1] }, .{ p.x.add(s[0]), p.x }); // (X − δ)(X + δ), 4β = 4XY²
    const g = s[1].sq().half(); // 8γ²
    const alpha = t[0].dbl().add(t[0]);
    const x3 = alpha.sq().sub(t[1].dbl());
    const y3 = alpha.mul(t[1].sub(x3)).sub(g);
    return .{ .x = x3, .y = y3, .z = z3 };
}

/// p + q and its H and r (add-1998-cmo-2 with q's Z² and Z³ stored): 11
/// multiplications, 3 squares. Wrong when p or q is the identity (Z = 0)
/// or p = q (then H = r = 0); right when p = −q (Z3 = 0).
fn add(p: Point, q: Entry) struct { Point, F, F } {
    @setRuntimeSafety(field.safe);
    const zz = p.z.sq();
    const a = F.mulN(4, .{ p.x, p.y, q.y, p.z }, .{ q.zz, q.zzz, p.z, q.z }); // U1, S1, Y2·Z1, Z1·Z2
    const b = F.mulN(2, .{ q.x, a[2] }, .{ zz, zz }); // U2, S2
    const h = b[0].sub(a[0]);
    const r = b[1].sub(a[1]);
    const hr = F.sqN(2, .{ h, r });
    const z3 = a[3].mul(h);
    const c = F.mulN(2, .{ h, a[0] }, .{ hr[0], hr[0] }); // H³, V = U1·H²
    const x3 = hr[1].sub(c[0]).sub(c[1].dbl());
    const d = F.mulN(2, .{ r, a[1] }, .{ c[1].sub(x3), c[0] });
    return .{ .{ .x = x3, .y = d[0].sub(d[1]), .z = z3 }, h, r };
}

/// p + q for an affine q (madd-1998-cmo with Z2 = 1): 8 multiplications,
/// 3 squares. Wrong when p is the identity or p = q.
fn addMixed(p: Point, q: Affine) Point {
    @setRuntimeSafety(field.safe);
    const a = F.sqN(1, .{p.z})[0];
    const yz = q.y.mul(p.z);
    const b = F.mulN(2, .{ q.x, yz }, .{ a, a }); // U2, S2
    const h = b[0].sub(p.x);
    const r = b[1].sub(p.y);
    const hr = F.sqN(2, .{ h, r });
    const z3 = p.z.mul(h);
    const c = F.mulN(2, .{ h, p.x }, .{ hr[0], hr[0] }); // H³, V = X1·H²
    const x3 = hr[1].sub(c[0]).sub(c[1].dbl());
    const d = F.mulN(2, .{ r, p.y }, .{ c[1].sub(x3), c[0] });
    return .{ .x = x3, .y = d[0].sub(d[1]), .z = z3 };
}

const rows = 65;

/// A little-endian scalar as 65 digits in [-8, 8), the last 0 or 1.
fn recode(s: [32]u8) [rows]i8 {
    // Overflow checks would branch on secret values (field.safe).
    @setRuntimeSafety(field.safe);
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

/// A digit's sign (1 if negative), its absolute value, and 1 if it is 0.
inline fn digitParts(d: i8) struct { u64, u8, u64 } {
    @setRuntimeSafety(field.safe);
    const negative: u8 = @bitCast(d >> 7);
    const abs: u8 = (@as(u8, @bitCast(d)) ^ negative) -% negative;
    return .{ negative & 1, abs, (@as(u64, abs) -% 1) >> 63 };
}

/// 1 if a == b, else 0, in constant time (small values).
inline fn eqMask(a: u8, b: u8) u64 {
    return (@as(u64, a ^ b) -% 1) >> 63;
}

/// 1..8 × p, for an affine p on the curve. No exceptional sums: jp ≠ ±p
/// for 1 < j < n − 1.
fn varTable(p: Affine) [8]Entry {
    @setRuntimeSafety(field.safe);
    const p1: Point = .{ .x = p.x, .y = p.y, .z = F.one };
    const e1: Entry = .{ .x = p.x, .y = p.y, .z = F.one, .zz = F.one, .zzz = F.one };
    var t: [8]Entry = undefined;
    t[0] = e1;
    const p2 = dbl(p1);
    const p3 = add(p2, e1)[0];
    const p4 = dbl(p2);
    const p5 = add(p4, e1)[0];
    const p6 = dbl(p3);
    const p7 = add(p6, e1)[0];
    const p8 = dbl(p4);
    inline for (.{ p2, p3, p4, p5, p6, p7, p8 }, 1..) |pt, i| t[i] = Entry.fromPoint(pt);
    return t;
}

/// One step of `mulVar`: 16·q + d·p, with t = 1..8 × p. `last` for the
/// last step, the only one where q can equal d·p.
fn varStep(q_: Point, t: *const [8]Entry, d: i8, comptime last: bool) Point {
    @setRuntimeSafety(field.safe);
    const q = dbl(dbl(dbl(dbl(q_))));
    const negative, const abs, const is_zero = digitParts(d);
    var entry: Entry = .{ .x = F.one, .y = F.one, .z = F.zero, .zz = F.zero, .zzz = F.zero };
    for (t, 1..) |te, j| {
        const c = eqMask(abs, @intCast(j));
        entry.x.cMov(te.x, c);
        entry.y.cMov(te.y, c);
        entry.z.cMov(te.z, c);
        entry.zz.cMov(te.zz, c);
        entry.zzz.cMov(te.zzz, c);
    }
    entry.y.cMov(entry.y.neg(), negative);
    const sum, const h, const r = add(q, entry);
    var next = sum;
    const q_zero = q.z.isZero();
    // q = entry (s = n − 2): the doubling. The identity cases below
    // take precedence (H and r mean nothing then).
    if (last) next.cMov(dbl(entry.point()), h.isZero() & r.isZero());
    next.cMov(entry.point(), q_zero);
    next.cMov(q, is_zero);
    return next;
}

/// s × p in constant time, for any 256-bit little-endian s, and p on the
/// curve. The identity if s is a multiple of n.
///
/// Left to right: Q = K × p, and each step is Q ← 16·Q + d·p. Each
/// prefix K is s / 16^i rounded down or up (the digits below sum to less
/// than 8/15 of 16^i in absolute value), so before the last step
/// 0 ≤ K ≤ s/16 + 1 and 16·K < 2^256 + 16 < 2n. The addition sees equal
/// points when 16·K ≡ d (mod n): K = d = 0 (Q is the identity:
/// selected), or 16·K = n + d, which n ≡ 1 (mod 16) makes d = −1 and
/// the new prefix n − 2: only s itself, at the last step, can be that.
/// There the doubling is selected (H = r = 0). (16·K ≡ −d gives the
/// identity, Z = 0, which the formulas get right: s = n.)
fn mulVar(p: Affine, s: [32]u8) Point {
    @setRuntimeSafety(field.safe);
    const t = varTable(p);
    var e = recode(s);
    defer std.crypto.secureZero(i8, &e);
    var q = Point.identity;
    q.cMov(t[0].point(), @as(u8, @bitCast(e[rows - 1])));
    var i: usize = rows - 1;
    while (i > 1) {
        i -= 1;
        q = varStep(q, &t, e[i], false);
    }
    return varStep(q, &t, e[0], true);
}

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

/// Row i holds j × 16^i × G for j = 1..8, made with std's formulas and
/// converted to affine with one inversion for the whole table
/// (Montgomery's trick).
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
    var prefix: [rows * 8]P256.Fe = undefined;
    prefix[0] = points[0].z;
    for (1..points.len) |i| prefix[i] = prefix[i - 1].mul(points[i].z);
    var inv = prefix[points.len - 1].invert();
    var i = points.len - 1;
    while (true) : (i -= 1) {
        const zinv = if (i == 0) inv else inv.mul(prefix[i - 1]);
        inv = inv.mul(points[i].z);
        table[i / 8][i % 8] = .{
            .x = F.fromBytes(points[i].x.mul(zinv).toBytes(.big)) catch unreachable,
            .y = F.fromBytes(points[i].y.mul(zinv).toBytes(.big)) catch unreachable,
        };
        if (i == 0) break;
    }
}

/// s × G in constant time, for any 256-bit little-endian s. The identity
/// if s is a multiple of n.
///
/// Q = K × G is the sum of the digits below position i, |K| < 8/15·16^i:
/// adding d·16^i·G (d ≠ 0) could meet ±Q only if K ∓ d·16^i ≡ 0 (mod n),
/// and below the last position |K ∓ d·16^i| < 8.6·16^63 < n, so K would
/// be ±d·16^i, which is too big. At the last position (d = 1, 16^64 ≡ c =
/// 2^256 − n), K = s − 2^256 ≡ s − c: Q = c·G only for s ≡ 2c (s = 2c,
/// whose last digit is 0; 2c + n > 2^256), and Q = −c·G only for s = n,
/// whose sum is the identity (Z = 0), as it should be. So only an
/// identity Q needs handling (selected).
fn mulBase(s: [32]u8) Point {
    @setRuntimeSafety(field.safe);
    const t = baseTable();
    var e = recode(s);
    defer std.crypto.secureZero(i8, &e);
    var q = Point.identity;
    for (e, t) |d, *row| q = baseStep(q, row, d);
    return q;
}

/// One step of `mulBase`: q + d·16^i·G, with row i of the table.
fn baseStep(q: Point, row: *const Row, d: i8) Point {
    @setRuntimeSafety(field.safe);
    const negative, const abs, const is_zero = digitParts(d);
    var a: Affine = .{ .x = F.zero, .y = F.zero };
    for (row, 1..) |entry, j| {
        const c = eqMask(abs, @intCast(j));
        a.x.cMov(entry.x, c);
        a.y.cMov(entry.y, c);
    }
    a.y.cMov(a.y.neg(), negative);
    var next = addMixed(q, a);
    next.cMov(.{ .x = a.x, .y = a.y, .z = F.one }, q.z.isZero());
    next.cMov(q, is_zero);
    return next;
}

/// Affine x, big-endian; `error.IdentityElement` for the identity.
fn affineX(p: Point) error{IdentityElement}![32]u8 {
    if (p.z.isZero() == 1) return error.IdentityElement;
    return p.x.mul(p.z.invSquare()).toBytes();
}

/// Uncompressed SEC1; `error.IdentityElement` for the identity.
fn toUncompressedSec1(p: Point) error{IdentityElement}![65]u8 {
    if (p.z.isZero() == 1) return error.IdentityElement;
    const zi2 = p.z.invSquare();
    const xy = F.mulN(2, .{ p.x, zi2 }, .{ zi2, p.z });
    var out: [65]u8 = undefined;
    out[0] = 4;
    out[1..33].* = xy[0].toBytes();
    out[33..65].* = p.y.mul(zi2.mul(xy[1])).toBytes();
    return out;
}

pub const Error = error{ InvalidEncoding, NonCanonical, IdentityElement };

/// The ECDHE shared secret for our secret key (big-endian) and the peer's
/// uncompressed SEC1 public key: the affine x of secret × peer,
/// big-endian. The same bytes and errors as std's
/// `P256.fromSec1(public_key)`, `mul(secret_key, .big)` and affine x,
/// except that only the uncompressed form is accepted (RFC 8446
/// §4.2.8.2): `error.NonCanonical` for a coordinate ≥ p,
/// `error.InvalidEncoding` for any other form or a point off the curve,
/// `error.IdentityElement` for a secret that is a multiple of n. In
/// constant time with respect to the secret; the checks on the public key
/// branch.
pub fn sharedSecret(secret_key: [32]u8, public_key: []const u8) Error![32]u8 {
    const peer = try decodePoint(public_key);
    var s: [32]u8 = undefined;
    for (secret_key, 0..) |byte, i| s[31 - i] = byte;
    defer std.crypto.secureZero(u8, &s);
    return affineX(mulVar(peer, s));
}

/// An uncompressed SEC1 point on the curve (see `sharedSecret`).
fn decodePoint(public_key: []const u8) Error!Affine {
    if (public_key.len != 65 or public_key[0] != 4) return error.InvalidEncoding;
    const x = try F.fromBytes(public_key[1..33].*);
    const y = try F.fromBytes(public_key[33..65].*);
    // y² = x³ − 3x + b. The identity has no affine form, and (0, 0) is
    // not on the curve, so every point that passes has order n.
    if (!y.sq().eql(x.sq().mul(x).sub(x.dbl().add(x)).add(F.b))) return error.InvalidEncoding;
    return .{ .x = x, .y = y };
}

pub const KeyShare = struct {
    /// Uncompressed SEC1.
    public_key: [65]u8,
    /// Big-endian.
    shared_secret: [32]u8,
};

/// The server's secp256r1 key share: the public key of `keyPair(seed)`
/// and the shared secret of its secret key with the peer's public key
/// (`sharedSecret`), equal to both, with one inversion for both results.
pub fn keyShare(seed: [32]u8, public_key: []const u8) Error!KeyShare {
    const peer = try decodePoint(public_key);
    var secret = deterministicScalar(@splat(0), @splat(0x01), seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
    var s = secret.toBytes(.little);
    defer std.crypto.secureZero(u8, &s);
    const g = mulBase(s);
    const q = mulVar(peer, s);
    // The secret is in [1, n − 1]: neither is the identity.
    if ((g.z.isZero() | q.z.isZero()) == 1) return error.IdentityElement;
    // 1/(Zg·Zq), then each inverse from it (Montgomery's trick).
    const w = g.z.mul(q.z).invert();
    const inv = F.mulN(2, .{ w, w }, .{ q.z, g.z }); // 1/Zg, 1/Zq
    const sq = F.sqN(2, inv); // 1/Zg², 1/Zq²
    const m = F.mulN(3, .{ g.x, q.x, sq[0] }, .{ sq[0], sq[1], inv[0] }); // xg, xq, 1/Zg³
    var out: KeyShare = .{ .public_key = undefined, .shared_secret = m[1].toBytes() };
    out.public_key[0] = 4;
    out.public_key[1..33].* = m[0].toBytes();
    out.public_key[33..65].* = g.y.mul(m[2]).toBytes();
    return out;
}

/// std's hedged deterministic nonce (ecdsa.zig's `deterministicScalar`,
/// for P-256 with SHA-256): HMAC-DRBG over the hash, the secret key and
/// the noise.
fn deterministicScalar(h: [32]u8, secret_key: [32]u8, noise: [32]u8) Scalar {
    var k: [32]u8 = @splat(0);
    var m: [32 + 1 + 32 + 32 + 32]u8 = @splat(0);
    var t: [32]u8 = undefined;
    defer {
        std.crypto.secureZero(u8, &k);
        std.crypto.secureZero(u8, &m);
        std.crypto.secureZero(u8, &t);
    }
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
    var k = deterministicScalar(h, secret, noise);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
    var kb = k.toBytes(.little);
    defer std.crypto.secureZero(u8, &kb);
    const r = reduce(try affineX(mulBase(kb)));
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

/// The public key (uncompressed SEC1) for a big-endian secret key: the
/// same as std's `basePoint.mul(secret_key, .big)`, including
/// `error.IdentityElement` for a multiple of n.
pub fn publicKey(secret_key: [32]u8) error{IdentityElement}![65]u8 {
    var s: [32]u8 = undefined;
    for (secret_key, 0..) |byte, i| s[31 - i] = byte;
    defer std.crypto.secureZero(u8, &s);
    return toUncompressedSec1(mulBase(s));
}

/// The key pair std's `generateDeterministic` makes from the same seed.
pub fn keyPair(seed: [32]u8) !KeyPair {
    var secret = deterministicScalar(@splat(0), @splat(0x01), seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&secret));
    var s = secret.toBytes(.little);
    defer std.crypto.secureZero(u8, &s);
    return .{ .secret_key = secret.toBytes(.big), .public_key = try toUncompressedSec1(mulBase(s)) };
}

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// Little-endian bytes of v.
fn le(v: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, v, .little);
    return out;
}

/// Big-endian bytes of v.
fn be(v: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, v, .big);
    return out;
}

/// Scalars at the edges: small, around n and its multiples' wraps, around
/// 2^256 − n (= 16^64 mod n) and twice it, and digit patterns.
pub const edge_scalars = blk: {
    const c: u256 = 0 -% n;
    break :blk [_]u256{
        0,                                                                  1,                2,                 3,              7,                                                                  8,
        9,                                                                  15,               16,                17,             n - 1,                                                              n - 2,
        n - 3,                                                              n - 8,            n - 9,             n - 16,         n - 17,                                                             n,
        n + 1,                                                              n + 2,            0 -% @as(u256, 1), c,              c - 1,                                                              c + 1,
        2 *% c,                                                             2 *% c -% 1,      2 *% c +% 1,       n - c,          (n - 1) / 2,                                                        (n + 1) / 2,
        (n - 1) / 16,                                                       (n - 1) / 16 + 1, 1 << 255,          (1 << 255) - 1, 0x8888888888888888888888888888888888888888888888888888888888888888, 0x7777777777777777777777777777777777777777777777777777777777777777,
        0xf0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0,
    };
};

test "p256: k × G from the table equals std's, for random and edge scalars" {
    var prng = std.Random.DefaultPrng.init(0x256);
    const random = prng.random();
    for (0..300 + edge_scalars.len) |i| {
        var s: [32]u8 = undefined;
        if (i < edge_scalars.len) s = le(edge_scalars[i]) else random.bytes(&s);
        const ours = toUncompressedSec1(mulBase(s));
        if (P256.basePoint.mul(s, .little)) |theirs| {
            try testing.expectEqualSlices(u8, &theirs.toUncompressedSec1(), &try ours);
        } else |err| try testing.expectError(err, ours);
    }
    try testing.expectError(error.IdentityElement, toUncompressedSec1(mulBase(le(n))));
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

/// Expects the same result as std, bytes or error: `fromSec1`, `mul` with
/// the big-endian secret, affine x. Forms other than uncompressed must be
/// rejected (std accepts them).
pub fn expectSameAsStd(secret_key: [32]u8, public_key: []const u8) !void {
    const ours = sharedSecret(secret_key, public_key);
    if (public_key.len != 65 or public_key[0] != 4) return testing.expectError(error.InvalidEncoding, ours);
    const theirs = blk: {
        const pk = P256.fromSec1(public_key) catch |err| break :blk err;
        const q = pk.mul(secret_key, .big) catch |err| break :blk err;
        break :blk q.affineCoordinates().x.toBytes(.big);
    };
    if (theirs) |t| {
        const o = ours catch |err| {
            std.debug.print("sk {x} pk {x}: std ok, ours {}\n", .{ secret_key, public_key, err });
            return error.Mismatch;
        };
        if (!std.mem.eql(u8, &t, &o)) {
            std.debug.print("sk {x} pk {x}: std {x}, ours {x}\n", .{ secret_key, public_key, t, o });
            return error.Mismatch;
        }
    } else |err| try testing.expectError(err, ours);
}

/// k × G, uncompressed (std's).
fn stdPublic(k: u256) [65]u8 {
    return (P256.basePoint.mul(le(k), .little) catch unreachable).toUncompressedSec1();
}

test "p256: shared secrets match NIST's ECDH test vectors (CAVS ECC CDH, P-256)" {
    // KAS ECC CDH primitive test vectors (SP 800-56A), P-256, COUNT 0 and 1.
    const vectors = [_][4][]const u8{
        .{
            "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
            "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
            "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b23028af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
            "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
        },
        .{
            "809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7aeb29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3",
            "38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5",
            "119f2f047902782ab0c9e27a54aff5eb9b964829ca99c06b02ddba95b0a3f6d08f52b726664cac366fc98ac7a012b2682cbd962e5acb544671d41b9445704d1d",
            "057d636096cb80b67a8c038c890e887d1adfa4195e9b3ce241c8a778c59cda67",
        },
    };
    for (vectors) |v| {
        var peer: [65]u8 = undefined;
        peer[0] = 4;
        _ = try std.fmt.hexToBytes(peer[1..], v[0]);
        var d: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&d, v[1]);
        var ours: [65]u8 = undefined;
        ours[0] = 4;
        _ = try std.fmt.hexToBytes(ours[1..], v[2]);
        var z: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&z, v[3]);
        try testing.expectEqualSlices(u8, &z, &try sharedSecret(d, &peer));
        var dl: [32]u8 = undefined;
        for (d, 0..) |byte, i| dl[31 - i] = byte;
        try testing.expectEqualSlices(u8, &ours, &try toUncompressedSec1(mulBase(dl)));
    }
}

test "p256: Wycheproof's ECDH vectors (raw points): edge cases, invalid curves, other forms" {
    const data = @embedFile("testdata/wycheproof_ecdh_secp256r1_ecpoint.txt");
    var lines = std.mem.tokenizeScalar(u8, data, '\n');
    var counts: [3]usize = @splat(0);
    while (lines.next()) |line| {
        if (line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const id = fields.next().?;
        const result = fields.next().?;
        _ = fields.next(); // flags
        const public_hex = fields.next().?;
        var public_buf: [65]u8 = undefined;
        const public = if (public_hex[0] == '-') public_buf[0..0] else try std.fmt.hexToBytes(&public_buf, public_hex);
        var secret: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&secret, fields.next().?);
        const ours = sharedSecret(secret, public);
        errdefer std.debug.print("tcId {s}: {s}, ours {any}\n", .{ id, result, ours });
        if (std.mem.eql(u8, result, "valid")) {
            var shared: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&shared, fields.next().?);
            try testing.expectEqualSlices(u8, &shared, &try ours);
            counts[0] += 1;
        } else if (std.mem.eql(u8, result, "invalid")) {
            if (ours) |_| return error.Accepted else |_| {}
            counts[1] += 1;
        } else {
            // Compressed points: TLS 1.3 allows only the uncompressed form.
            try testing.expectError(error.InvalidEncoding, ours);
            counts[2] += 1;
        }
        try expectSameAsStd(secret, public);
    }
    try testing.expectEqual([3]usize{ 330, 24, 1 }, counts);
}

test "p256: shared secrets equal std's: edge scalars, small multiples, random points" {
    var prng = std.Random.DefaultPrng.init(0xec0d);
    const random = prng.random();
    // Peers: G and small multiples, −G, (n − k)·G, random points.
    var peers: [24][65]u8 = undefined;
    for (0..8) |k| peers[k] = stdPublic(k + 1);
    for (0..8) |k| peers[8 + k] = stdPublic(n - 1 - k);
    for (peers[16..]) |*pk| pk.* = stdPublic(random.uintLessThan(u256, n - 1) + 1);
    for (peers) |pk| {
        for (edge_scalars) |s| try expectSameAsStd(be(s), &pk);
        for (0..10) |_| {
            var sk: [32]u8 = undefined;
            random.bytes(&sk);
            try expectSameAsStd(sk, &pk);
        }
    }
    // Both sides of an exchange agree.
    for (0..50) |_| {
        var seed: [32]u8 = undefined;
        random.bytes(&seed);
        const a = try keyPair(seed);
        random.bytes(&seed);
        const b = try keyPair(seed);
        try testing.expectEqualSlices(u8, &try sharedSecret(a.secret_key, &b.public_key), &try sharedSecret(b.secret_key, &a.public_key));
        try expectSameAsStd(a.secret_key, &b.public_key);
    }
}

test "p256: a key share is keyPair's public key and sharedSecret's secret" {
    var prng = std.Random.DefaultPrng.init(0x5ea5);
    const random = prng.random();
    for (0..200) |i| {
        var seed: [32]u8 = undefined;
        random.bytes(&seed);
        var peer = stdPublic(if (i < 8) i + 1 else random.uintLessThan(u256, n - 1) + 1);
        if (i % 10 == 9) peer[1 + random.uintLessThan(usize, 64)] ^= 1;
        const kp = try keyPair(seed);
        const kp_std = try Ecdsa.KeyPair.generateDeterministic(seed);
        const share = keyShare(seed, &peer);
        if (sharedSecret(kp.secret_key, &peer)) |shared| {
            const ks = try share;
            try testing.expectEqualSlices(u8, &kp.public_key, &ks.public_key);
            try testing.expectEqualSlices(u8, &kp_std.public_key.toUncompressedSec1(), &ks.public_key);
            try testing.expectEqualSlices(u8, &shared, &ks.shared_secret);
            try expectSameAsStd(kp.secret_key, &peer);
        } else |err| try testing.expectError(err, share);
    }
    try testing.expectError(error.InvalidEncoding, keyShare(@splat(1), stdPublic(1)[0..33]));
}

test "p256: the scalar n − 2 (the one equal-points sum) and its neighbours" {
    // The last addition adds −P to −P: the doubling must be selected.
    for (0..30) |k| {
        const pk = stdPublic(k + 1);
        for ([_]u256{ n - 2, n - 3, n - 1, n - 18, n - 34 }) |s| try expectSameAsStd(be(s), &pk);
        // (n − 2)·(k + 1)·G = −2(k + 1)·G, which has 2(k + 1)·G's x.
        try testing.expectEqualSlices(u8, stdPublic(2 * (k + 1))[1..33], &try sharedSecret(be(n - 2), &pk));
    }
}

test "p256: invalid peer keys are rejected as std rejects them" {
    var prng = std.Random.DefaultPrng.init(0xbad);
    const random = prng.random();
    const sk = be(0x1234567890abcdef);
    const g = stdPublic(1);
    // Other forms: identity, compressed, hybrid, wrong lengths.
    const bad = [_][]const u8{
        &.{},
        &.{0},
        &.{4},
        g[0..64],
        &(g ++ [_]u8{0}),
        &([_]u8{2} ++ g[1..33].*),
        &([_]u8{3} ++ g[1..33].*),
        &([_]u8{6} ++ g[1..].*),
        &([_]u8{7} ++ g[1..].*),
        &([_]u8{0} ++ g[1..].*),
        &([_]u8{5} ++ g[1..].*),
    };
    for (bad) |pk| try testing.expectError(error.InvalidEncoding, sharedSecret(sk, pk));
    // Coordinates ≥ p, off the curve, (0, 0), y negated off by one.
    var pk = g;
    for ([_]u256{ field.p, field.p + 1, 0 -% @as(u256, 1) }) |v| {
        pk = g;
        pk[1..33].* = be(v);
        try expectSameAsStd(sk, &pk);
        try testing.expectError(error.NonCanonical, sharedSecret(sk, &pk));
        pk = g;
        pk[33..65].* = be(v);
        try expectSameAsStd(sk, &pk);
        try testing.expectError(error.NonCanonical, sharedSecret(sk, &pk));
    }
    pk = g;
    @memset(pk[1..], 0);
    try expectSameAsStd(sk, &pk);
    try testing.expectError(error.InvalidEncoding, sharedSecret(sk, &pk));
    for (0..2000) |i| {
        pk = stdPublic(random.uintLessThan(u256, n - 1) + 1);
        switch (i % 4) {
            // A flipped bit anywhere.
            0 => pk[1 + random.uintLessThan(usize, 64)] ^= @as(u8, 1) << random.int(u3),
            // y + 1, or x with y unchanged.
            1 => pk[33..65].* = be(std.mem.readInt(u256, pk[33..65], .big) +% 1),
            2 => pk[1..33].* = be(std.mem.readInt(u256, pk[1..33], .big) +% 1),
            // Random bytes.
            else => random.bytes(pk[1..]),
        }
        try expectSameAsStd(sk, &pk);
    }
}

// Fuzz target: any secret and peer key give std's result.
fn fuzzSharedSecret(_: void, smith: *std.testing.Smith) anyerror!void {
    var sk: [32]u8 = undefined;
    var pk: [65]u8 = undefined;
    smith.bytes(&sk);
    smith.bytes(&pk);
    // Mostly points on the curve, as a peer's share would be.
    if (pk[0] & 0x80 == 0) {
        var k: [32]u8 = pk[1..33].*;
        k[0] &= 0x7f;
        pk = toUncompressedSec1(mulBase(k)) catch pk;
    } else pk[0] = 4;
    try expectSameAsStd(sk, &pk);
}

test "fuzz: p256 shared secret against std" {
    try std.testing.fuzz({}, fuzzSharedSecret, .{ .corpus = &.{
        &(be(n - 2) ++ stdPublic(5)),
        &(be(n - 1) ++ [_]u8{0x84} ++ @as([64]u8, @splat(0xff))),
    } });
}

// Adversarial checks of the incompleteness argument (`mulVar`, `mulBase`):
// an integer model of both sums that reports every addition whose inputs
// are equal or opposite, run over scalars built to sit on the boundaries
// (around n, 2^256 − n and their multiples, 2^256, digit runs that push the
// running sum to its limits, sums constructed to meet ±d·16^i or ±d·P); and
// the real point arithmetic, instrumented to report what its additions see
// (H = 0), checked against the model, the unwatched code and std.

/// Raise for long runs (the loop counts multiply).
const verify_scale = 1;

/// What the additions of one multiplication met: equal or opposite
/// non-identity inputs, and whether that was at the last step.
const Exceptional = struct {
    equal: u32 = 0,
    opposite: u32 = 0,
    /// The first exceptional step (variable base: digit index; fixed
    /// base: row), or none.
    first_step: ?usize = null,
    last_equal: u32 = 0,
    last_opposite: u32 = 0,

    fn note(x: *Exceptional, step: usize, last: bool, equal: bool) void {
        if (x.first_step == null) x.first_step = step;
        if (equal) {
            x.equal += 1;
            if (last) x.last_equal += 1;
        } else {
            x.opposite += 1;
            if (last) x.last_opposite += 1;
        }
    }
};

/// The model of `mulVar`'s sum: before step i (digit d_i), Q = 16·K where
/// K is the value of the digits above i. Equal inputs when 16·K ≡ d_i,
/// opposite when 16·K ≡ −d_i (mod n), for 16·K ≢ 0 and d_i ≠ 0.
fn modelVar(s: u256) Exceptional {
    const e = recode(le(s));
    var x: Exceptional = .{};
    var k: i600 = e[rows - 1];
    var i: usize = rows - 1;
    while (i > 0) {
        i -= 1;
        const q = @mod(16 * k, n);
        const d = e[i];
        if (q != 0 and d != 0) {
            if (q == @mod(@as(i600, d), n)) x.note(i, i == 0, true);
            if (q == @mod(-@as(i600, d), n)) x.note(i, i == 0, false);
        }
        // K exactly (not reduced): the argument's bounds are on K itself.
        k = 16 * k + d;
    }
    std.debug.assert(k == s);
    return x;
}

/// The model of `mulBase`'s sum: before row i, Q = D·G with D the value of
/// the digits below i; adding d_i·16^i·G meets ±Q when D ≡ ±d_i·16^i.
fn modelBase(s: u256) Exceptional {
    const e = recode(le(s));
    var x: Exceptional = .{};
    var dsum: i600 = 0;
    for (e, 0..) |d, i| {
        const term: i600 = @as(i600, d) << @intCast(4 * i);
        const qm = @mod(dsum, n);
        if (qm != 0 and d != 0) {
            if (qm == @mod(term, n)) x.note(i, i == rows - 1, true);
            if (qm == @mod(-term, n)) x.note(i, i == rows - 1, false);
        }
        dsum += term;
    }
    std.debug.assert(dsum == s);
    return x;
}

/// The cases the argument allows: equal inputs only at the variable base's
/// last step for s = n − 2 (the doubling is selected), opposite inputs only
/// at the last step for s = n (the identity, which the formulas give).
fn expectModelAllowed(s: u256) !void {
    const v = modelVar(s);
    const b = modelBase(s);
    const v_ok = (v.equal == 0 or (s == n - 2 and v.equal == 1 and v.last_equal == 1)) and
        (v.opposite == 0 or (s == n and v.opposite == 1 and v.last_opposite == 1));
    const b_ok = b.equal == 0 and (b.opposite == 0 or (s == n and b.opposite == 1 and b.last_opposite == 1));
    if (!v_ok or !b_ok) {
        std.debug.print("scalar {x}: variable base {any}, fixed base {any}\n", .{ s, v, b });
        return error.UnhandledExceptionalAddition;
    }
}

/// `mulVar` with its additions watched: the same result, and what each
/// addition's inputs were (H = 0 with both inputs non-identity).
fn mulVarWatched(p: Affine, s: [32]u8, x: *Exceptional) Point {
    const t = varTable(p);
    const e = recode(s);
    var q = Point.identity;
    q.cMov(t[0].point(), @as(u8, @bitCast(e[rows - 1])));
    var i: usize = rows - 1;
    while (i > 0) {
        i -= 1;
        const q4 = dbl(dbl(dbl(dbl(q))));
        const negative, const abs, const is_zero = digitParts(e[i]);
        if (q4.z.isZero() == 0 and is_zero == 0) {
            var entry = t[abs - 1];
            if (negative == 1) entry.y = entry.y.neg();
            _, const h, const r = add(q4, entry);
            if (h.isZero() == 1) x.note(i, i == 0, r.isZero() == 1);
        }
        q = if (i == 0) varStep(q, &t, e[i], true) else varStep(q, &t, e[i], false);
    }
    return q;
}

/// `mulBase` with its additions watched.
fn mulBaseWatched(s: [32]u8, x: *Exceptional) Point {
    const t = baseTable();
    const e = recode(s);
    var q = Point.identity;
    for (e, t, 0..) |d, *row, i| {
        const negative, const abs, const is_zero = digitParts(d);
        if (q.z.isZero() == 0 and is_zero == 0) {
            var a = row[abs - 1];
            if (negative == 1) a.y = a.y.neg();
            // H = U2 − X1, r = S2 − Y1 (as in addMixed).
            const zz = q.z.sq();
            const h = a.x.mul(zz).sub(q.x);
            const r = a.y.mul(zz.mul(q.z)).sub(q.y);
            if (h.isZero() == 1) x.note(i, i == rows - 1, r.isZero() == 1);
        }
        q = baseStep(q, row, d);
    }
    return q;
}

/// The real arithmetic on s: what its additions met agrees with the model,
/// and the results with the unwatched code and (when `full`: it is the
/// slow part) std.
fn expectWatched(s: u256, peer: Affine, peer_sec1: *const [65]u8, full: bool) !void {
    var xv: Exceptional = .{};
    var xb: Exceptional = .{};
    const qv = mulVarWatched(peer, le(s), &xv);
    const qb = mulBaseWatched(le(s), &xb);
    const mv = modelVar(s);
    const mb = modelBase(s);
    if (xv.equal != mv.equal or xv.opposite != mv.opposite or xb.equal != mb.equal or xb.opposite != mb.opposite) {
        std.debug.print("scalar {x} peer {x}: watched {any} {any}, model {any} {any}\n", .{ s, peer_sec1, xv, xb, mv, mb });
        return error.ModelMismatch;
    }
    try expectModelAllowed(s);
    try testing.expectEqualDeep(affineX(mulVar(peer, le(s))), affineX(qv));
    const ours_b = toUncompressedSec1(qb);
    try testing.expectEqualDeep(toUncompressedSec1(mulBase(le(s))), ours_b);
    if (!full) return;
    try expectSameAsStd(be(s), peer_sec1);
    if (P256.basePoint.mul(le(s), .little)) |theirs| {
        try testing.expectEqualSlices(u8, &theirs.toUncompressedSec1(), &try ours_b);
    } else |err| try testing.expectError(err, ours_b);
}

/// i600 → u256 mod 2^256.
fn wrap(v: i600) u256 {
    return @truncate(@as(u600, @bitCast(v)));
}

/// Scalars on the argument's boundaries, by kind.
pub fn boundaryScalar(r: std.Random, kind: u8) u256 {
    const c: u256 = 0 -% n; // 2^256 − n = 16^64 mod n
    const small = r.uintAtMost(u256, 1 << 20);
    return switch (kind) {
        // n − j, n + j, 2^256 − j, j.
        0 => n -% small,
        1 => n +% small,
        2 => 0 -% small,
        3 => small,
        // m·c ± j, m·n ± j (wrapping).
        4 => c *% r.uintAtMost(u256, 17) +% small -% (1 << 19),
        5 => n *% r.uintAtMost(u256, 3) +% r.uintAtMost(u256, 64) -% 32,
        // The fixed-base sum at row i at its extremes: every digit below
        // i equal to −8 or 7 (D = −8/15·(16^i − 1) or 7/15·(16^i − 1)),
        // any digit at i, the rest random or zero.
        6 => blk: {
            const i: usize = r.uintAtMost(u8, 64);
            const d: i600 = @as(i600, r.uintAtMost(u8, 15)) - 8;
            const run: i600 = if (r.boolean()) 7 else -8;
            var v: i600 = 0;
            for (0..i) |j| v += run << @intCast(4 * j);
            v += d << @intCast(4 * i);
            if (r.boolean() and i < 63) v += @as(i600, r.int(u256) >> @intCast(4 * (i + 1))) << @intCast(4 * (i + 1));
            break :blk wrap(v);
        },
        // The variable base's prefixes next to m·n/16: K·16^i with 16·K
        // near m·n ± d (truncated to 256 bits), plus random low digits.
        7 => blk: {
            const i: usize = r.uintAtMost(u8, 4);
            const m: i600 = @as(i600, r.uintAtMost(u8, 2)) + 1;
            const d: i600 = @as(i600, r.uintAtMost(u8, 16)) - 8;
            const k: i600 = @divFloor(m * n + d, 16) + r.uintAtMost(u8, 4) - 2;
            const low: i600 = r.uintAtMost(u32, (@as(u32, 1) << @intCast(4 * i)) - 1);
            break :blk wrap((k << @intCast(4 * i)) + low);
        },
        // Digit strings: runs of one digit with others mixed in.
        8 => blk: {
            const digits = [_]i8{ -8, -7, -1, 0, 1, 7, 4, -4 };
            const fill = digits[r.uintLessThan(usize, digits.len)];
            var v: i600 = 0;
            for (0..64) |j| {
                const dj: i600 = if (r.uintLessThan(u8, 8) == 0) digits[r.uintLessThan(usize, digits.len)] else fill;
                v += dj << @intCast(4 * j);
            }
            break :blk wrap(v);
        },
        // n − d·16^i − e·16^j.
        9 => blk: {
            const i: usize = r.uintAtMost(u8, 63);
            const j: usize = r.uintAtMost(u8, 63);
            const d: u256 = r.uintAtMost(u8, 15);
            const e: u256 = r.uintAtMost(u8, 15);
            break :blk n -% (d << @intCast(4 * i)) -% (e << @intCast(4 * j));
        },
        // Bytes of nibble-boundary patterns with a few flipped bits.
        10 => blk: {
            const pat = [_]u8{ 0x00, 0xff, 0x88, 0x77, 0x80, 0x7f, 0x08, 0xf8, 0x8f, 0xf7 };
            var b: [32]u8 = undefined;
            for (&b) |*x| x.* = pat[r.uintLessThan(usize, pat.len)];
            for (0..r.uintAtMost(u8, 3)) |_| b[r.uintLessThan(usize, 32)] ^= @as(u8, 1) << r.int(u3);
            break :blk std.mem.readInt(u256, &b, .little);
        },
        else => r.int(u256),
    };
}

test "verify: the incompleteness argument's integer model, on boundary scalars" {
    // The cases it says do happen, do.
    try testing.expectEqual(@as(u32, 1), modelVar(n - 2).last_equal);
    try testing.expectEqual(@as(u32, 1), modelVar(n).last_opposite);
    try testing.expectEqual(@as(u32, 1), modelBase(n).last_opposite);
    var prng = std.Random.DefaultPrng.init(0x7e57_ad5e);
    const r = prng.random();
    for (0..verify_scale * 20_000) |i| try expectModelAllowed(boundaryScalar(r, @intCast(i % 12)));
    for (edge_scalars) |s| try expectModelAllowed(s);
    // Every scalar within 2^12 of n, 2^256, m·(2^256 − n) and 2n mod 2^256.
    for (0..1 << 13) |j| {
        const d: u256 = @as(u256, j) -% (1 << 12);
        for ([_]u256{ n, 0, 0 -% n, 2 *% (0 -% n), n *% 2 }) |centre| try expectModelAllowed(centre +% d);
    }
}

// Fuzz target: boundary scalars (the kind and the generator's seed from the
// input) on peers that are small multiples of G or k × G, through the
// watched arithmetic, the model and std.
fn fuzzBoundary(_: void, smith: *std.testing.Smith) anyerror!void {
    var in: [1 + 8 + 1 + 32]u8 = undefined;
    smith.bytes(&in);
    var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, in[1..9], .little));
    const s = boundaryScalar(prng.random(), in[0] % 12);
    var k = std.mem.readInt(u256, in[10..42], .little) % (n - 1) + 1;
    if (in[9] & 0x80 == 0) k = in[9] % 64 + 1;
    const pk = stdPublic(k);
    try expectWatched(s, try decodePoint(&pk), &pk, true);
}

test "fuzz: p256 boundary scalars, watched, against std" {
    try std.testing.fuzz({}, fuzzBoundary, .{ .corpus = &.{
        &([_]u8{0} ++ @as([41]u8, @splat(0))),
        &([_]u8{7} ++ @as([41]u8, @splat(0x5a))),
    } });
}

test "verify: peers with small or extreme coordinates, on and off the curve, as std" {
    // x in [0, 400) and (p − 400, p): both points when x³ − 3x + b is a
    // square, and the same x with y off by one (on another curve: an
    // invalid-curve point, whose equation has another b).
    const sk = [_]u256{ 0x1234567890abcdef, n - 2, n - 1, 1, (n - 1) / 2 };
    var found: usize = 0;
    for (0..800) |i| {
        const xv: u256 = if (i < 400) i else field.p - (i - 399);
        const fx = P256.Fe.fromBytes(be(xv), .big) catch unreachable;
        for ([_]bool{ false, true }) |odd| {
            const y = P256.recoverY(fx, odd) catch continue;
            found += 1;
            var pk: [65]u8 = (P256{ .x = fx, .y = y }).toUncompressedSec1();
            for (sk) |s| try expectSameAsStd(be(s), &pk);
            pk[33..65].* = be(std.mem.readInt(u256, pk[33..65], .big) +% 1);
            try expectSameAsStd(be(sk[0]), &pk);
            try testing.expectError(error.InvalidEncoding, sharedSecret(be(sk[0]), &pk));
        }
        // y = 0 (order 2 on a curve with that b) and small y.
        for ([_]u256{ 0, 1, 2 }) |yv| {
            var pk: [65]u8 = undefined;
            pk[0] = 4;
            pk[1..33].* = be(xv);
            pk[33..65].* = be(yv);
            try expectSameAsStd(be(sk[0]), &pk);
        }
    }
    try testing.expect(found > 300);
}

test "verify: the point arithmetic meets only the exceptional additions the model predicts" {
    var prng = std.Random.DefaultPrng.init(0x7e57_ad5f);
    const r = prng.random();
    // Peers: small multiples of G, −G, random points.
    var peers: [6][65]u8 = undefined;
    for (&peers, 0..) |*pk, k| pk.* = switch (k) {
        0 => stdPublic(1),
        1 => stdPublic(2),
        2 => stdPublic(n - 1),
        3 => stdPublic(7),
        else => stdPublic(r.uintLessThan(u256, n - 1) + 1),
    };
    for (0..verify_scale * 600) |i| {
        const pk = &peers[i % peers.len];
        try expectWatched(boundaryScalar(r, @intCast(i % 12)), try decodePoint(pk), pk, i % 4 == 0);
    }
    // The predicted cases themselves, on every peer: s = n − 2 meets equal
    // inputs at the last step (only), s = n opposite ones.
    for (peers) |pk| {
        const peer = try decodePoint(&pk);
        var x: Exceptional = .{};
        _ = mulVarWatched(peer, le(n - 2), &x);
        try testing.expectEqual(@as(?usize, 0), x.first_step);
        try testing.expectEqual(@as(u32, 1), x.last_equal);
        for ([_]u256{ n - 2, n, n - 1, n + 1, n - 3, 0 -% @as(u256, 1) }) |s| try expectWatched(s, peer, &pk, true);
    }
}
