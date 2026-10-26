//! Server certificate chain and private key: PEM/DER loading and signing.
const std = @import("std");
const Certificate = std.crypto.Certificate;
const SignatureScheme = std.crypto.tls.SignatureScheme;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

pub const max_signature_len = EcdsaP384Sha384.Signature.der_encoded_length_max;
pub const noise_len = EcdsaP384Sha384.noise_length;

pub const PrivateKey = union(enum) {
    ecdsa_p256: EcdsaP256Sha256.KeyPair,
    ecdsa_p384: EcdsaP384Sha384.KeyPair,
    ed25519: Ed25519.KeyPair,

    /// The only scheme each key type is used with in TLS 1.3.
    pub fn scheme(self: *const PrivateKey) SignatureScheme {
        return switch (self.*) {
            .ecdsa_p256 => .ecdsa_secp256r1_sha256,
            .ecdsa_p384 => .ecdsa_secp384r1_sha384,
            .ed25519 => .ed25519,
        };
    }

    /// Signs `msg`; the result is in the encoding TLS uses (DER for ECDSA).
    /// `noise` hardens the deterministic nonce against fault attacks.
    pub fn sign(self: *const PrivateKey, msg: []const u8, noise: [noise_len]u8, out: *[max_signature_len]u8) ![]const u8 {
        switch (self.*) {
            inline .ecdsa_p256, .ecdsa_p384 => |kp| {
                const sig = try kp.sign(msg, noise[0..@TypeOf(kp.secret_key).encoded_length].*);
                var der: [@TypeOf(sig).der_encoded_length_max]u8 = undefined;
                const enc = sig.toDer(&der);
                @memcpy(out[0..enc.len], enc);
                return out[0..enc.len];
            },
            .ed25519 => |kp| {
                const sig = try kp.sign(msg, noise[0..Ed25519.noise_length].*);
                const bytes = sig.toBytes();
                @memcpy(out[0..bytes.len], &bytes);
                return out[0..bytes.len];
            },
        }
    }

    fn publicKeyMatches(self: *const PrivateKey, parsed: Certificate.Parsed) bool {
        const pub_key = parsed.pubKey();
        return switch (self.*) {
            .ecdsa_p256 => |kp| parsed.pub_key_algo == .X9_62_id_ecPublicKey and
                parsed.pub_key_algo.X9_62_id_ecPublicKey == .X9_62_prime256v1 and
                std.mem.eql(u8, pub_key, &kp.public_key.toUncompressedSec1()),
            .ecdsa_p384 => |kp| parsed.pub_key_algo == .X9_62_id_ecPublicKey and
                parsed.pub_key_algo.X9_62_id_ecPublicKey == .secp384r1 and
                std.mem.eql(u8, pub_key, &kp.public_key.toUncompressedSec1()),
            .ed25519 => |kp| parsed.pub_key_algo == .curveEd25519 and
                std.mem.eql(u8, pub_key, &kp.public_key.toBytes()),
        };
    }
};

pub const Credentials = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    /// DER certificates, leaf first.
    chain: []const []const u8,
    key: PrivateKey,

    /// Loads a PEM certificate chain (leaf first) and a PEM private key
    /// (PKCS#8 "PRIVATE KEY", or SEC1 "EC PRIVATE KEY"). Checks that the key
    /// belongs to the leaf certificate.
    pub fn fromPem(allocator: std.mem.Allocator, cert_pem: []const u8, key_pem: []const u8) !Self {
        var chain: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (chain.items) |c| allocator.free(c);
            chain.deinit(allocator);
        }
        var it: PemIterator = .{ .data = cert_pem };
        while (try it.next()) |block| {
            if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
            const der = try block.decode(allocator);
            errdefer allocator.free(der);
            try chain.append(allocator, der);
        }
        if (chain.items.len == 0) return error.NoCertificate;

        var key_it: PemIterator = .{ .data = key_pem };
        const key = while (try key_it.next()) |block| {
            const sec1 = std.mem.eql(u8, block.label, "EC PRIVATE KEY");
            if (!sec1 and !std.mem.eql(u8, block.label, "PRIVATE KEY")) continue;
            var buf: [512]u8 = undefined;
            const der = try block.decodeInto(&buf);
            defer std.crypto.secureZero(u8, der);
            break if (sec1) try parseSec1(der, null) else try parsePkcs8(der);
        } else return error.NoPrivateKey;

        const leaf: Certificate = .{ .buffer = chain.items[0], .index = 0 };
        const parsed = leaf.parse() catch return error.InvalidCertificate;
        if (!key.publicKeyMatches(parsed)) return error.KeyCertificateMismatch;

        return .{
            .allocator = allocator,
            .chain = try chain.toOwnedSlice(allocator),
            .key = key,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.chain) |c| self.allocator.free(c);
        self.allocator.free(self.chain);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key));
    }
};

const PemBlock = struct {
    label: []const u8,
    body: []const u8,

    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");

    fn decode(self: PemBlock, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, decoder.calcSizeUpperBound(self.body.len));
        errdefer allocator.free(buf);
        const n = decoder.decode(buf, self.body) catch return error.InvalidPem;
        return allocator.realloc(buf, n);
    }

    fn decodeInto(self: PemBlock, buf: []u8) ![]u8 {
        if (decoder.calcSizeUpperBound(self.body.len) > buf.len) return error.InvalidPem;
        const n = decoder.decode(buf, self.body) catch return error.InvalidPem;
        return buf[0..n];
    }
};

const PemIterator = struct {
    data: []const u8,
    pos: usize = 0,

    fn next(self: *PemIterator) !?PemBlock {
        const begin = "-----BEGIN ";
        const start = std.mem.indexOfPos(u8, self.data, self.pos, begin) orelse return null;
        const label_start = start + begin.len;
        const label_end = std.mem.indexOfPos(u8, self.data, label_start, "-----") orelse return error.InvalidPem;
        const label = self.data[label_start..label_end];
        const body_start = label_end + 5;
        var end_marker_buf: [64]u8 = undefined;
        const end_marker = std.fmt.bufPrint(&end_marker_buf, "-----END {s}-----", .{label}) catch return error.InvalidPem;
        const body_end = std.mem.indexOfPos(u8, self.data, body_start, end_marker) orelse return error.InvalidPem;
        self.pos = body_end + end_marker.len;
        return .{ .label = label, .body = self.data[body_start..body_end] };
    }
};

// -- DER --------------------------------------------------------------

const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_secp384r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };

const Der = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn atEnd(self: *const Der) bool {
        return self.pos >= self.bytes.len;
    }

    fn peekTag(self: *const Der) ?u8 {
        return if (self.atEnd()) null else self.bytes[self.pos];
    }

    /// Reads one element with the given tag and returns its contents.
    fn read(self: *Der, tag: u8) ![]const u8 {
        if (self.pos + 2 > self.bytes.len or self.bytes[self.pos] != tag) return error.InvalidKey;
        var len: usize = self.bytes[self.pos + 1];
        self.pos += 2;
        if (len & 0x80 != 0) {
            const n = len & 0x7f;
            if (n == 0 or n > 2 or self.pos + n > self.bytes.len) return error.InvalidKey;
            len = 0;
            for (self.bytes[self.pos..][0..n]) |b| len = len << 8 | b;
            self.pos += n;
        }
        if (self.pos + len > self.bytes.len) return error.InvalidKey;
        defer self.pos += len;
        return self.bytes[self.pos..][0..len];
    }
};

const Curve = enum { p256, p384 };

fn curveFromOid(oid: []const u8) !Curve {
    if (std.mem.eql(u8, oid, &oid_prime256v1)) return .p256;
    if (std.mem.eql(u8, oid, &oid_secp384r1)) return .p384;
    return error.UnsupportedKey;
}

/// PKCS#8 PrivateKeyInfo (RFC 5208 / RFC 8410).
fn parsePkcs8(der: []const u8) !PrivateKey {
    var outer: Der = .{ .bytes = der };
    var info: Der = .{ .bytes = try outer.read(0x30) };
    _ = try info.read(0x02); // version
    var alg: Der = .{ .bytes = try info.read(0x30) };
    const oid = try alg.read(0x06);
    const private = try info.read(0x04);
    if (std.mem.eql(u8, oid, &oid_ec_public_key)) {
        const curve = try curveFromOid(try alg.read(0x06));
        return parseSec1(private, curve);
    }
    if (std.mem.eql(u8, oid, &oid_ed25519)) {
        var inner: Der = .{ .bytes = private };
        const seed = try inner.read(0x04);
        if (seed.len != Ed25519.KeyPair.seed_length) return error.InvalidKey;
        return .{ .ed25519 = try Ed25519.KeyPair.generateDeterministic(seed[0..32].*) };
    }
    return error.UnsupportedKey;
}

/// SEC1 ECPrivateKey (RFC 5915). The curve comes from the PKCS#8 wrapper
/// or from the optional parameters field.
fn parseSec1(der: []const u8, outer_curve: ?Curve) !PrivateKey {
    var outer: Der = .{ .bytes = der };
    var key: Der = .{ .bytes = try outer.read(0x30) };
    _ = try key.read(0x02); // version
    const private = try key.read(0x04);
    var curve = outer_curve;
    if (key.peekTag() == 0xa0) {
        var params: Der = .{ .bytes = try key.read(0xa0) };
        const c = try curveFromOid(try params.read(0x06));
        if (curve != null and curve.? != c) return error.InvalidKey;
        curve = c;
    }
    return switch (curve orelse return error.InvalidKey) {
        .p256 => .{ .ecdsa_p256 = try ecKeyPair(EcdsaP256Sha256, private) },
        .p384 => .{ .ecdsa_p384 = try ecKeyPair(EcdsaP384Sha384, private) },
    };
}

fn ecKeyPair(comptime Scheme: type, private: []const u8) !Scheme.KeyPair {
    const len = Scheme.SecretKey.encoded_length;
    if (private.len > len) return error.InvalidKey;
    // Left-pad in case leading zero bytes were dropped.
    var bytes: [len]u8 = @splat(0);
    @memcpy(bytes[len - private.len ..], private);
    defer std.crypto.secureZero(u8, &bytes);
    const sk = Scheme.SecretKey.fromBytes(bytes) catch return error.InvalidKey;
    return Scheme.KeyPair.fromSecretKey(sk) catch return error.InvalidKey;
}

// -- Tests ------------------------------------------------------------

pub const testdata = struct {
    pub const p256_cert = @embedFile("testdata/p256.pem");
    pub const p256_key = @embedFile("testdata/p256.key");
    pub const p256_sec1_key = @embedFile("testdata/p256.sec1.key");
    pub const p384_cert = @embedFile("testdata/p384.pem");
    pub const p384_key = @embedFile("testdata/p384.key");
    pub const ed25519_cert = @embedFile("testdata/ed25519.pem");
    pub const ed25519_key = @embedFile("testdata/ed25519.key");
};

test "load every supported key type and sign" {
    const cases = [_]struct { cert: []const u8, key: []const u8, scheme: SignatureScheme }{
        .{ .cert = testdata.p256_cert, .key = testdata.p256_key, .scheme = .ecdsa_secp256r1_sha256 },
        .{ .cert = testdata.p256_cert, .key = testdata.p256_sec1_key, .scheme = .ecdsa_secp256r1_sha256 },
        .{ .cert = testdata.p384_cert, .key = testdata.p384_key, .scheme = .ecdsa_secp384r1_sha384 },
        .{ .cert = testdata.ed25519_cert, .key = testdata.ed25519_key, .scheme = .ed25519 },
    };
    for (cases) |case| {
        var creds = try Credentials.fromPem(std.testing.allocator, case.cert, case.key);
        defer creds.deinit();
        try std.testing.expectEqual(1, creds.chain.len);
        try std.testing.expectEqual(case.scheme, creds.key.scheme());
        var buf: [max_signature_len]u8 = undefined;
        const sig = try creds.key.sign("message", @splat(3), &buf);
        // Check the signature verifies with the certificate's key.
        const parsed = try (Certificate{ .buffer = creds.chain[0], .index = 0 }).parse();
        switch (creds.key) {
            .ecdsa_p256 => {
                const pk = try EcdsaP256Sha256.PublicKey.fromSec1(parsed.pubKey());
                try (try EcdsaP256Sha256.Signature.fromDer(sig)).verify("message", pk);
            },
            .ecdsa_p384 => {
                const pk = try EcdsaP384Sha384.PublicKey.fromSec1(parsed.pubKey());
                try (try EcdsaP384Sha384.Signature.fromDer(sig)).verify("message", pk);
            },
            .ed25519 => {
                const pk = try Ed25519.PublicKey.fromBytes(parsed.pubKey()[0..32].*);
                try Ed25519.Signature.fromBytes(sig[0..64].*).verify("message", pk);
            },
        }
    }
}

test "reject mismatched key, missing blocks and garbage" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.KeyCertificateMismatch, Credentials.fromPem(a, testdata.p256_cert, testdata.p384_key));
    try std.testing.expectError(error.NoCertificate, Credentials.fromPem(a, testdata.p256_key, testdata.p256_key));
    try std.testing.expectError(error.NoPrivateKey, Credentials.fromPem(a, testdata.p256_cert, testdata.p256_cert));
    try std.testing.expectError(error.InvalidPem, Credentials.fromPem(a, "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----", testdata.p256_key));
    try std.testing.expectError(error.InvalidKey, Credentials.fromPem(a, testdata.p256_cert, "-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----"));
}
