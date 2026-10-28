//! Micro-benchmarks for TLS record protection. Run with `zig build bench-tls`
//! (always built with -O fast). `zig build bench-tls -- handshake` times the
//! server's side of full handshakes instead (see `handshakes`).
//!
//! "std AEAD" seals and opens each record the way record.zig did before it
//! kept expanded keys: std's AEAD API with the raw key, which expands the
//! AES key schedule and GHASH's powers of H on every call.
const std = @import("std");
const per = @import("peregrine");
const record = per.internal.tls_record;
const sys = per.internal.sys;
const Protection = record.Protection;

fn report(name: []const u8, size: usize, iterations: usize, ns: u64) void {
    const per_op = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(iterations));
    const gbps = @as(f64, @floatFromInt(size * iterations)) / @as(f64, @floatFromInt(ns));
    std.debug.print("{s:<44} {d:>6} B  {d:>8.1} ns/record  {d:>6.2} GB/s\n", .{ name, size, per_op, gbps });
}

/// What record.zig's seal did before: std's AEAD with a raw key.
fn stdSeal(comptime A: type, p: *Protection, out: []u8, data_len: usize) usize {
    const inner_len = data_len + 1;
    out[0..5].* = .{ 23, 3, 3, 0, 0 };
    std.mem.writeInt(u16, out[3..5], @intCast(inner_len + record.tag_len), .big);
    const inner = out[record.header_len..][0..inner_len];
    inner[data_len] = 23;
    A.encrypt(inner, out[record.header_len + inner_len ..][0..record.tag_len], inner, out[0..record.header_len], nonce(p), p.aead.key[0..A.key_length].*);
    p.seq += 1;
    return record.header_len + inner_len + record.tag_len;
}

fn stdOpen(comptime A: type, p: *Protection, rec: []u8) !void {
    const body = rec[record.header_len..];
    const ct = body[0 .. body.len - record.tag_len];
    try A.decrypt(ct, ct, body[ct.len..][0..record.tag_len].*, rec[0..record.header_len], nonce(p), p.aead.key[0..A.key_length].*);
    p.seq += 1;
}

fn nonce(p: *const Protection) [12]u8 {
    var n = p.iv;
    var seq: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq, p.seq, .big);
    for (n[4..], seq) |*b, s| b.* ^= s;
    return n;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var args = init.args.iterate();
    _ = args.next();
    if (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "handshake")) return handshakes();
        std.debug.print("unknown argument: {s}\n", .{arg});
        return error.InvalidArgument;
    }
    var buf: [record.max_record]u8 = undefined;
    var out: [record.max_plaintext + 1]u8 = undefined;
    const secret: [48]u8 = @splat(7);
    inline for (.{ record.Suite.aes_128_gcm_sha256, record.Suite.aes_256_gcm_sha384 }) |suite| {
        const A = suite.Aead();
        for ([_]usize{ 32, 256, 1024, 4096, record.max_plaintext }) |size| {
            const iterations: usize = @max(20_000, 400_000_000 / (size + 200));
            @memset(buf[record.header_len..][0..size], 'a');
            // Seal then open: one record each way, as a server does per
            // request/response pair.
            {
                var tx: Protection = .init(suite, secret[0..suite.hashLen()]);
                var rx: Protection = .init(suite, secret[0..suite.hashLen()]);
                const start = sys.nanoTimestamp();
                for (0..iterations) |_| {
                    const n = stdSeal(A, &tx, &buf, size);
                    try stdOpen(A, &rx, buf[0..n]);
                }
                report(@tagName(suite) ++ " std AEAD, seal+open", size, iterations, sys.nanoTimestamp() - start);
            }
            {
                var tx: Protection = .init(suite, secret[0..suite.hashLen()]);
                var rx: Protection = .init(suite, secret[0..suite.hashLen()]);
                const start = sys.nanoTimestamp();
                for (0..iterations) |_| {
                    const n = tx.seal(&buf, .application_data, buf[record.header_len..][0..size]);
                    _ = try rx.open(buf[0..n]);
                }
                report(@tagName(suite) ++ " expanded key, seal+open", size, iterations, sys.nanoTimestamp() - start);
            }
            {
                // Open into another buffer, as readPlain does when the
                // plaintext fits, against open in place plus a copy.
                var tx: Protection = .init(suite, secret[0..suite.hashLen()]);
                var rx: Protection = .init(suite, secret[0..suite.hashLen()]);
                var rx2: Protection = .init(suite, secret[0..suite.hashLen()]);
                var t_copy: u64 = 0;
                var t_into: u64 = 0;
                for (0..iterations) |_| {
                    const n = tx.seal(&buf, .application_data, buf[record.header_len..][0..size]);
                    var copy: [record.max_record]u8 = undefined;
                    @memcpy(copy[0..n], buf[0..n]);
                    var start = sys.nanoTimestamp();
                    const opened = try rx.open(buf[0..n]);
                    @memcpy(out[0..opened.data.len], opened.data);
                    t_copy += sys.nanoTimestamp() - start;
                    start = sys.nanoTimestamp();
                    std.mem.doNotOptimizeAway(try rx2.openInto(copy[0..n], &out));
                    t_into += sys.nanoTimestamp() - start;
                }
                report(@tagName(suite) ++ " open in place + copy", size, iterations, t_copy);
                report(@tagName(suite) ++ " openInto", size, iterations, t_into);
            }
        }
    }
}

// -- Handshakes ---------------------------------------------------------------

const handshake = per.internal.tls_handshake;
const credentials = per.internal.tls_credentials;
const p256 = per.internal.tls_p256;
const x25519 = per.internal.tls_x25519;
const tls = std.crypto.tls;
const X25519 = std.crypto.dh.X25519;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;

/// Drops the handshake's output: only the server's CPU time is measured.
const NullSink = struct {
    pub const Error = error{};
    pub fn handshakeData(_: *NullSink, _: handshake.Level, _: []const u8) Error!void {}
    pub fn changeCipherSpec(_: *NullSink) Error!void {}
    pub fn writeSecret(_: *NullSink, _: handshake.Level, _: record.Suite, _: []const u8) Error!void {}
    pub fn readSecret(_: *NullSink, _: handshake.Level, _: record.Suite, _: []const u8) Error!void {}
};

/// A browser-like ClientHello offering one group, with a key share for it.
fn clientHello(buf: []u8, group: tls.NamedGroup, share: []const u8) []const u8 {
    var w: Writer = .{ .buf = buf };
    w.int(u8, 1);
    const msg = w.begin(u24);
    w.int(u16, 0x0303);
    w.fill(32, 0x11); // random
    w.int(u8, 32);
    w.fill(32, 0x22); // legacy_session_id (middlebox compatibility)
    w.int(u16, 2);
    w.int(u16, 0x1301);
    w.int(u8, 1);
    w.int(u8, 0);
    const exts = w.begin(u16);
    w.int(u16, @backingInt(tls.ExtensionType.supported_versions));
    w.int(u16, 3);
    w.int(u8, 2);
    w.int(u16, 0x0304);
    w.int(u16, @backingInt(tls.ExtensionType.supported_groups));
    w.int(u16, 4);
    w.int(u16, 2);
    w.int(u16, @backingInt(group));
    w.int(u16, @backingInt(tls.ExtensionType.signature_algorithms));
    w.int(u16, 10);
    w.int(u16, 8);
    for ([_]u16{ 0x0403, 0x0503, 0x0807, 0x0804 }) |sa| w.int(u16, sa);
    w.int(u16, @backingInt(tls.ExtensionType.key_share));
    w.int(u16, @intCast(share.len + 6));
    w.int(u16, @intCast(share.len + 4));
    w.int(u16, @backingInt(group));
    w.int(u16, @intCast(share.len));
    w.bytes(share);
    w.int(u16, @backingInt(tls.ExtensionType.application_layer_protocol_negotiation));
    w.int(u16, 5);
    w.int(u16, 3);
    w.int(u8, 2);
    w.bytes("h2");
    w.end(u16, exts);
    w.end(u24, msg);
    return w.buf[0..w.pos];
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn bytes(w: *Writer, b: []const u8) void {
        @memcpy(w.buf[w.pos..][0..b.len], b);
        w.pos += b.len;
    }

    fn fill(w: *Writer, n: usize, v: u8) void {
        @memset(w.buf[w.pos..][0..n], v);
        w.pos += n;
    }

    fn int(w: *Writer, comptime T: type, v: T) void {
        std.mem.writeInt(T, w.buf[w.pos..][0..@divExact(@bitSizeOf(T), 8)], v, .big);
        w.pos += @divExact(@bitSizeOf(T), 8);
    }

    fn begin(w: *Writer, comptime T: type) usize {
        const at = w.pos;
        w.pos += @divExact(@bitSizeOf(T), 8);
        return at;
    }

    fn end(w: *Writer, comptime T: type, at: usize) void {
        std.mem.writeInt(T, w.buf[at..][0..@divExact(@bitSizeOf(T), 8)], @intCast(w.pos - at - @divExact(@bitSizeOf(T), 8)), .big);
    }
};

fn reportOp(name: []const u8, iterations: usize, ns: u64) void {
    const us = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(iterations)) / 1000.0;
    std.debug.print("{s:<44} {d:>9.1} µs  {d:>9.0} /s\n", .{ name, us, 1_000_000.0 / us });
}

/// The server's side of a full handshake (ClientHello in, its flight
/// out: key exchange, key schedule, CertificateVerify signature), for each
/// group and certificate type; then the primitives that dominate it.
fn handshakes() !void {
    const gpa = std.heap.smp_allocator;
    const td = credentials.testdata;
    var seeds: [64 * 6]u8 = undefined;
    sys.randomBytes(&seeds);
    const x_kp = X25519.KeyPair.generateDeterministic(seeds[0..32].*);
    const p_kp = try P256.KeyPair.generateDeterministic(seeds[32..64].*);
    const m_kp = try MLKem768.KeyPair.generateDeterministic(seeds[64..128].*);
    var hybrid: [MLKem768.PublicKey.encoded_length + X25519.public_length]u8 = undefined;
    hybrid[0..MLKem768.PublicKey.encoded_length].* = m_kp.public_key.toBytes();
    hybrid[MLKem768.PublicKey.encoded_length..].* = x_kp.public_key;
    const p_share = p_kp.public_key.toUncompressedSec1();
    const groups = [_]struct { tls.NamedGroup, []const u8 }{
        .{ .x25519, &x_kp.public_key },
        .{ .secp256r1, &p_share },
        .{ .x25519_ml_kem768, &hybrid },
    };
    const certs = [_]struct { []const u8, []const u8, []const u8 }{
        .{ "ECDSA P-256", td.p256_cert, td.p256_key },
        .{ "ECDSA P-384", td.p384_cert, td.p384_key },
        .{ "Ed25519", td.ed25519_cert, td.ed25519_key },
        .{ "RSA-2048", td.rsa2048_cert, td.rsa2048_key },
        .{ "RSA-4096", td.rsa4096_cert, td.rsa4096_key },
    };
    var entropy: [handshake.entropy_len]u8 = undefined;
    sys.randomBytes(&entropy);
    var hello_buf: [2048]u8 = undefined;
    for (certs) |c| {
        var creds = try credentials.Credentials.fromPem(gpa, c[1], c[2]);
        defer creds.deinit();
        for (groups) |g| {
            const config: handshake.Config = .{ .credentials = &creds, .alpn = &.{"h2"} };
            const hello = clientHello(&hello_buf, g[0], g[1]);
            const iterations: usize = if (std.mem.startsWith(u8, c[0], "RSA")) 100 else 2000;
            const start = sys.nanoTimestamp();
            for (0..iterations) |_| {
                var hs = handshake.Handshake.init(gpa, &config, &entropy);
                defer hs.deinit();
                var sink: NullSink = .{};
                try hs.feed(.initial, hello, &sink);
                if (!hs.isRetrying() and hs.isDone()) unreachable;
            }
            var name_buf: [64]u8 = undefined;
            reportOp(try std.fmt.bufPrint(&name_buf, "handshake {s}, {s}", .{ c[0], @tagName(g[0]) }), iterations, sys.nanoTimestamp() - start);
        }
    }
    std.debug.print("\n", .{});
    const n = 2000;
    var seed: [32]u8 = @splat(5);
    {
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            seed[0] = @truncate(i);
            const kp = X25519.KeyPair.generateDeterministic(seed);
            std.mem.doNotOptimizeAway(try X25519.scalarmult(kp.secret_key, x_kp.public_key));
        }
        reportOp("X25519 key pair + shared secret (std)", n, sys.nanoTimestamp() - start);
    }
    {
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            seed[0] = @truncate(i);
            std.mem.doNotOptimizeAway(x25519.publicKey(seed));
            std.mem.doNotOptimizeAway(try X25519.scalarmult(seed, x_kp.public_key));
        }
        reportOp("X25519 key pair (table) + shared secret", n, sys.nanoTimestamp() - start);
    }
    {
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            seed[0] = @truncate(i);
            const pk = try P256.PublicKey.fromSec1(&p_share);
            const kp = try P256.KeyPair.generateDeterministic(seed);
            const point = try pk.p.mulPublic(kp.secret_key.bytes, .big);
            std.mem.doNotOptimizeAway(point.affineCoordinates().x.toBytes(.big));
            std.mem.doNotOptimizeAway(kp.public_key.toUncompressedSec1());
        }
        reportOp("P-256 key pair + shared secret (std)", n, sys.nanoTimestamp() - start);
    }
    {
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            seed[0] = @truncate(i);
            const pk = try P256.PublicKey.fromSec1(&p_share);
            const kp = try p256.keyPair(seed);
            const point = try pk.p.mul(kp.secret_key, .big);
            std.mem.doNotOptimizeAway(point.affineCoordinates().x.toBytes(.big));
        }
        reportOp("P-256 key pair (table) + shared secret (ct)", n, sys.nanoTimestamp() - start);
    }
    {
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            seed[0] = @truncate(i);
            const ek = try MLKem768.PublicKey.fromBytes(hybrid[0..MLKem768.PublicKey.encoded_length]);
            std.mem.doNotOptimizeAway(ek.encapsDeterministic(&seed));
        }
        reportOp("ML-KEM-768 encapsulation (with key decoding)", n, sys.nanoTimestamp() - start);
    }
    const msg: [130]u8 = @splat(0x20);
    {
        const kp = try P256.KeyPair.generateDeterministic(seeds[128..160].*);
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            seed[0] = @truncate(i);
            std.mem.doNotOptimizeAway(try kp.sign(&msg, seed));
        }
        reportOp("ECDSA P-256 sign (std)", n, sys.nanoTimestamp() - start);
    }
    {
        const kp = try P256.KeyPair.generateDeterministic(seeds[128..160].*);
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            seed[0] = @truncate(i);
            std.mem.doNotOptimizeAway(try p256.sign(kp, &msg, seed));
        }
        reportOp("ECDSA P-256 sign (table)", n, sys.nanoTimestamp() - start);
    }
    {
        const kp = try P384.KeyPair.generateDeterministic(seeds[160..208].*);
        var noise: [P384.noise_length]u8 = @splat(5);
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            noise[0] = @truncate(i);
            std.mem.doNotOptimizeAway(try kp.sign(&msg, noise));
        }
        reportOp("ECDSA P-384 sign", n, sys.nanoTimestamp() - start);
    }
    {
        const kp = try Ed25519.KeyPair.generateDeterministic(seeds[208..240].*);
        const start = sys.nanoTimestamp();
        for (0..n) |i| {
            seed[0] = @truncate(i);
            std.mem.doNotOptimizeAway(try kp.sign(&msg, seed));
        }
        reportOp("Ed25519 sign", n, sys.nanoTimestamp() - start);
    }
}
