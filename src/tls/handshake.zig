//! TLS 1.3 server handshake (RFC 8446), independent of record framing.
//!
//! The handshake consumes handshake messages and produces handshake
//! messages per encryption level, and hands out traffic secrets as each level
//! becomes available. TLS over TCP wraps the output in records
//! (`conn.zig`); QUIC (RFC 9001) carries the same bytes in CRYPTO frames.
//!
//! Output goes to a sink, called in protocol order:
//!   sink.handshakeData(level: Level, bytes: []const u8) !void
//!   sink.changeCipherSpec() !void       (TCP middlebox compatibility only)
//!   sink.writeSecret(level: Level, suite: Suite, secret: []const u8) !void
//!   sink.readSecret(level: Level, suite: Suite, secret: []const u8) !void
//!
//! Scope: full handshakes with certificate authentication, no PSK, no 0-RTT,
//! no client certificates.
const std = @import("std");
const tls = std.crypto.tls;
const record = @import("./record.zig");
const errors = @import("./errors.zig");
const credentials = @import("./credentials.zig");
const Credentials = credentials.Credentials;
const Error = errors.Error;
const Suite = record.Suite;
const NamedGroup = tls.NamedGroup;
const HandshakeType = tls.HandshakeType;
const ExtensionType = tls.ExtensionType;
const X25519 = std.crypto.dh.X25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

/// Encryption levels (QUIC epochs, without 0-RTT).
pub const Level = enum(u2) { initial, handshake, application };

pub const Config = struct {
    credentials: *const Credentials,
    /// ALPN protocol names in server preference order. Empty: no ALPN.
    alpn: []const []const u8 = &.{},
    /// In preference order.
    suites: []const Suite = default_suites,
    /// In preference order. Key shares the client sent are preferred over
    /// a better group that would need a HelloRetryRequest.
    groups: []const NamedGroup = &.{ .x25519_ml_kem768, .x25519, .secp256r1 },
};

const has_aes = switch (@import("builtin").cpu.arch) {
    .x86_64 => std.Target.x86.featureSetHas(@import("builtin").cpu.features, .aes),
    .aarch64 => std.Target.aarch64.featureSetHas(@import("builtin").cpu.features, .aes),
    else => false,
};

/// AES-GCM first when the CPU has AES instructions, ChaCha20 otherwise.
pub const default_suites: []const Suite = if (has_aes)
    &.{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }
else
    &.{ .chacha20_poly1305_sha256, .aes_128_gcm_sha256, .aes_256_gcm_sha384 };

/// Random bytes the handshake consumes: server random, key exchange seeds
/// and signature noise. Passed in so the handshake stays deterministic
/// under test.
pub const entropy_len = 32 + 32 + 32 + 32 + credentials.noise_len;

/// Largest handshake message accepted from a client.
pub const max_message_len = 1 << 16;

const State = enum { client_hello, client_hello_retry, client_finished, done };

const Transcript = union(enum) {
    sha256: Sha256,
    sha384: Sha384,

    fn init(suite: Suite) Transcript {
        return switch (suite.hashLen()) {
            32 => .{ .sha256 = .init(.{}) },
            else => .{ .sha384 = .init(.{}) },
        };
    }

    fn update(self: *Transcript, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*h| h.update(bytes),
        }
    }

    fn current(self: *const Transcript, out: *[record.max_hash_len]u8) []const u8 {
        switch (self.*) {
            inline else => |h| {
                var copy = h;
                const T = @TypeOf(h);
                copy.final(out[0..T.digest_length]);
                return out[0..T.digest_length];
            },
        }
    }
};

pub const Handshake = struct {
    const Self = @This();

    config: *const Config,
    allocator: std.mem.Allocator,
    state: State = .client_hello,
    entropy: [entropy_len]u8,
    /// A handshake message split across feed calls.
    partial: std.ArrayList(u8) = .empty,

    suite: Suite = undefined,
    transcript: Transcript = undefined,
    /// Group chosen in a HelloRetryRequest.
    retry_group: ?NamedGroup = null,
    session_id_buf: [32]u8 = undefined,
    session_id_len: u8 = 0,
    sent_ccs: bool = false,

    /// Negotiated ALPN protocol (points into the config), if any.
    alpn: ?[]const u8 = null,
    /// The client offered 0-RTT data; it is rejected, so the record layer
    /// must skip it.
    early_data_offered: bool = false,

    client_handshake_secret: [record.max_hash_len]u8 = undefined,
    client_app_secret: [record.max_hash_len]u8 = undefined,
    /// The client's Finished, computed once the server flight is sent.
    expected_finished: [record.max_hash_len]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, config: *const Config, entropy: *const [entropy_len]u8) Self {
        return .{ .allocator = allocator, .config = config, .entropy = entropy.* };
    }

    pub fn deinit(self: *Self) void {
        self.partial.deinit(self.allocator);
        std.crypto.secureZero(u8, &self.entropy);
        std.crypto.secureZero(u8, &self.client_handshake_secret);
        std.crypto.secureZero(u8, &self.client_app_secret);
    }

    pub fn isDone(self: *const Self) bool {
        return self.state == .done;
    }

    /// A HelloRetryRequest was sent; ClientHello2 hasn't been handled yet.
    pub fn isRetrying(self: *const Self) bool {
        return self.state == .client_hello_retry;
    }

    /// Handles handshake bytes received at `level`.
    pub fn feed(self: *Self, level: Level, data: []const u8, sink: anytype) (Error || SinkError(@TypeOf(sink)))!void {
        var rest = data;
        while (rest.len > 0) {
            if (self.partial.items.len == 0) {
                if (try messageLen(rest)) |n| {
                    const key_change = try self.handleMessage(level, rest[0..n], sink);
                    rest = rest[n..];
                    // RFC 8446 §5.1: messages before a key change must end
                    // on a record boundary.
                    if (key_change and rest.len > 0) return error.UnexpectedMessage;
                    continue;
                }
            }
            if (self.partial.items.len + rest.len > max_message_len + 4) return error.DecodeError;
            self.partial.appendSlice(self.allocator, rest) catch return error.InternalError;
            rest = &.{};
            while (try messageLen(self.partial.items)) |n| {
                const key_change = try self.handleMessage(level, self.partial.items[0..n], sink);
                const left = self.partial.items.len - n;
                std.mem.copyForwards(u8, self.partial.items[0..left], self.partial.items[n..]);
                self.partial.shrinkRetainingCapacity(left);
                if (key_change and left > 0) return error.UnexpectedMessage;
            }
        }
        if (self.state == .done) self.partial.clearAndFree(self.allocator);
    }

    fn messageLen(data: []const u8) Error!?usize {
        if (data.len < 4) return null;
        const len = std.mem.readInt(u24, data[1..4], .big);
        if (len > max_message_len) return error.DecodeError;
        return if (data.len >= 4 + len) 4 + len else null;
    }

    /// Returns true if the message caused a change of read keys.
    fn handleMessage(self: *Self, level: Level, msg: []const u8, sink: anytype) !bool {
        const msg_type: HandshakeType = @fromBackingInt(msg[0]);
        switch (self.state) {
            .client_hello, .client_hello_retry => {
                if (level != .initial or msg_type != .client_hello) return error.UnexpectedMessage;
                try self.handleClientHello(msg, sink);
                return self.state == .client_finished;
            },
            .client_finished => {
                if (level != .handshake or msg_type != .finished) return error.UnexpectedMessage;
                try self.handleFinished(msg, sink);
                return true;
            },
            .done => return error.UnexpectedMessage,
        }
    }

    // -- ClientHello ----------------------------------------------------

    fn handleClientHello(self: *Self, msg: []const u8, sink: anytype) !void {
        const hello = try ClientHello.parse(msg[4..]);
        const retry = self.state == .client_hello_retry;

        if (!hello.tls13) return error.ProtocolVersion;
        if (retry) {
            if (hello.early_data) return error.IllegalParameter;
            if (!std.mem.eql(u8, hello.session_id, self.session_id_buf[0..self.session_id_len]))
                return error.IllegalParameter;
            if (!listHas(u16, hello.suites, @backingInt(self.suite))) return error.IllegalParameter;
        } else {
            self.suite = for (self.config.suites) |s| {
                if (listHas(u16, hello.suites, @backingInt(s))) break s;
            } else return error.HandshakeFailure;
            self.session_id_len = @intCast(hello.session_id.len);
            @memcpy(self.session_id_buf[0..hello.session_id.len], hello.session_id);
            self.early_data_offered = hello.early_data;
        }

        const sig_algs = hello.signature_algorithms orelse return error.MissingExtension;
        if (!listHas(u16, sig_algs, @backingInt(self.config.credentials.key.scheme())))
            return error.HandshakeFailure;
        const groups = hello.supported_groups orelse return error.MissingExtension;
        const shares = hello.key_shares orelse return error.MissingExtension;

        // Every key share must be for an offered group, at most once each.
        var it = KeyShareIterator{ .data = shares };
        var seen: [16]u16 = undefined;
        var seen_len: usize = 0;
        while (try it.next()) |share| {
            if (!listHas(u16, groups, @backingInt(share.group))) return error.IllegalParameter;
            for (seen[0..seen_len]) |g| if (g == @backingInt(share.group)) return error.IllegalParameter;
            if (seen_len == seen.len) return error.IllegalParameter;
            seen[seen_len] = @backingInt(share.group);
            seen_len += 1;
        }

        // Prefer a group the client sent a share for; otherwise ask for one.
        var chosen: ?KeyShare = null;
        if (self.retry_group) |g| {
            // After a HelloRetryRequest the client must send exactly the
            // requested share.
            it = .{ .data = shares };
            const share = (try it.next()) orelse return error.IllegalParameter;
            if (share.group != g or (try it.next()) != null) return error.IllegalParameter;
            chosen = share;
        } else for (self.config.groups) |g| {
            it = .{ .data = shares };
            while (try it.next()) |share| {
                if (share.group == g) {
                    chosen = share;
                    break;
                }
            }
            if (chosen != null) break;
        }

        if (!retry) {
            self.transcript = .init(self.suite);
        }

        if (chosen == null) {
            if (retry) return error.IllegalParameter;
            const group = for (self.config.groups) |g| {
                if (listHas(u16, groups, @backingInt(g))) break g;
            } else return error.HandshakeFailure;
            return self.sendHelloRetryRequest(msg, group, sink);
        }

        if (self.config.alpn.len > 0) {
            if (hello.alpn) |offered| {
                self.alpn = try selectAlpn(self.config.alpn, offered);
            }
        }

        self.transcript.update(msg);
        try self.sendServerFlight(chosen.?, sink);
    }

    fn sendHelloRetryRequest(self: *Self, client_hello: []const u8, group: NamedGroup, sink: anytype) !void {
        // RFC 8446 §4.4.1: the first ClientHello is replaced in the
        // transcript by a synthetic message_hash message.
        var hash_buf: [record.max_hash_len]u8 = undefined;
        self.transcript.update(client_hello);
        const ch1_hash = self.transcript.current(&hash_buf);
        self.transcript = .init(self.suite);
        self.transcript.update(&.{ @backingInt(HandshakeType.message_hash), 0, 0, @intCast(ch1_hash.len) });
        self.transcript.update(ch1_hash);

        var buf: [128]u8 = undefined;
        var w: Writer = .{ .buf = &buf };
        const hdr = w.beginMessage(.server_hello);
        w.int(u16, 0x0303);
        w.bytes(&tls.hello_retry_request_sequence);
        w.int(u8, self.session_id_len);
        w.bytes(self.session_id_buf[0..self.session_id_len]);
        w.int(u16, @backingInt(self.suite));
        w.int(u8, 0);
        const exts = w.begin(u16);
        w.int(u16, @backingInt(ExtensionType.key_share));
        w.int(u16, 2);
        w.int(u16, @backingInt(group));
        w.int(u16, @backingInt(ExtensionType.supported_versions));
        w.int(u16, 2);
        w.int(u16, 0x0304);
        w.end(u16, exts);
        w.endMessage(hdr);

        self.transcript.update(w.written());
        try sink.handshakeData(.initial, w.written());
        try self.compatCcs(sink);
        self.retry_group = group;
        self.state = .client_hello_retry;
    }

    fn compatCcs(self: *Self, sink: anytype) !void {
        // RFC 8446 §D.4: a client in middlebox compatibility mode sends a
        // non-empty session ID and expects one change_cipher_spec.
        if (self.session_id_len > 0 and !self.sent_ccs) {
            self.sent_ccs = true;
            try sink.changeCipherSpec();
        }
    }

    // -- Server flight ----------------------------------------------------

    fn sendServerFlight(self: *Self, share: KeyShare, sink: anytype) !void {
        var kx: KeyExchange = .{};
        defer std.crypto.secureZero(u8, &kx.shared_buf);
        try kx.run(share, &self.entropy);

        // ServerHello
        var sh_buf: [256 + MLKem768.ciphertext_length]u8 = undefined;
        var w: Writer = .{ .buf = &sh_buf };
        const hdr = w.beginMessage(.server_hello);
        w.int(u16, 0x0303);
        w.bytes(self.entropy[0..32]);
        w.int(u8, self.session_id_len);
        w.bytes(self.session_id_buf[0..self.session_id_len]);
        w.int(u16, @backingInt(self.suite));
        w.int(u8, 0);
        const exts = w.begin(u16);
        w.int(u16, @backingInt(ExtensionType.key_share));
        const ks = w.begin(u16);
        w.int(u16, @backingInt(share.group));
        const kx_len = w.begin(u16);
        w.bytes(kx.publicShare());
        w.end(u16, kx_len);
        w.end(u16, ks);
        w.int(u16, @backingInt(ExtensionType.supported_versions));
        w.int(u16, 2);
        w.int(u16, 0x0304);
        w.end(u16, exts);
        w.endMessage(hdr);
        self.transcript.update(w.written());
        try sink.handshakeData(.initial, w.written());
        try self.compatCcs(sink);

        switch (self.suite) {
            inline else => |s| try self.sendEncryptedFlight(s, kx.sharedSecret(), sink),
        }
        self.state = .client_finished;
    }

    fn sendEncryptedFlight(self: *Self, comptime suite: Suite, shared_secret: []const u8, sink: anytype) !void {
        const ks = suite.Schedule();
        var hash_buf: [record.max_hash_len]u8 = undefined;

        const early = ks.earlySecret();
        var hs = ks.handshakeSecret(early, shared_secret);
        defer std.crypto.secureZero(u8, &hs);
        const hello_hash = self.transcript.current(&hash_buf);
        var c_hs = ks.deriveSecret(hs, "c hs traffic", hello_hash);
        var s_hs = ks.deriveSecret(hs, "s hs traffic", hello_hash);
        defer std.crypto.secureZero(u8, &s_hs);
        defer std.crypto.secureZero(u8, &c_hs);
        try sink.writeSecret(.handshake, suite, &s_hs);
        try sink.readSecret(.handshake, suite, &c_hs);

        const creds = self.config.credentials;
        var chain_len: usize = 0;
        for (creds.chain) |c| chain_len += 3 + c.len + 2;
        const flight_len = 64 + 300 + chain_len + credentials.max_signature_len + record.max_hash_len;
        const flight = self.allocator.alloc(u8, flight_len) catch return error.InternalError;
        defer self.allocator.free(flight);
        var w: Writer = .{ .buf = flight };

        // EncryptedExtensions
        var start = w.pos;
        var hdr = w.beginMessage(.encrypted_extensions);
        const exts = w.begin(u16);
        if (self.alpn) |proto| {
            w.int(u16, @backingInt(ExtensionType.application_layer_protocol_negotiation));
            w.int(u16, @intCast(2 + 1 + proto.len));
            w.int(u16, @intCast(1 + proto.len));
            w.int(u8, @intCast(proto.len));
            w.bytes(proto);
        }
        w.end(u16, exts);
        w.endMessage(hdr);
        self.transcript.update(w.buf[start..w.pos]);

        // Certificate
        start = w.pos;
        hdr = w.beginMessage(.certificate);
        w.int(u8, 0); // certificate_request_context
        const list = w.begin(u24);
        for (creds.chain) |c| {
            w.int(u24, @intCast(c.len));
            w.bytes(c);
            w.int(u16, 0); // extensions
        }
        w.end(u24, list);
        w.endMessage(hdr);
        self.transcript.update(w.buf[start..w.pos]);

        // CertificateVerify
        start = w.pos;
        const cert_hash = self.transcript.current(&hash_buf);
        const context = "TLS 1.3, server CertificateVerify";
        var content: [64 + context.len + 1 + record.max_hash_len]u8 = undefined;
        @memset(content[0..64], 0x20);
        @memcpy(content[64..][0..context.len], context);
        content[64 + context.len] = 0;
        @memcpy(content[64 + context.len + 1 ..][0..cert_hash.len], cert_hash);
        var sig_buf: [credentials.max_signature_len]u8 = undefined;
        const sig = creds.key.sign(
            content[0 .. 64 + context.len + 1 + cert_hash.len],
            self.entropy[128..][0..credentials.noise_len].*,
            &sig_buf,
        ) catch return error.InternalError;
        hdr = w.beginMessage(.certificate_verify);
        w.int(u16, @backingInt(creds.key.scheme()));
        w.int(u16, @intCast(sig.len));
        w.bytes(sig);
        w.endMessage(hdr);
        self.transcript.update(w.buf[start..w.pos]);

        // Finished
        start = w.pos;
        const verify = ks.finishedVerifyData(s_hs, self.transcript.current(&hash_buf));
        hdr = w.beginMessage(.finished);
        w.bytes(&verify);
        w.endMessage(hdr);
        self.transcript.update(w.buf[start..w.pos]);

        try sink.handshakeData(.handshake, w.written());

        // Application secrets cover the transcript through server Finished.
        var master = ks.masterSecret(hs);
        defer std.crypto.secureZero(u8, &master);
        const fin_hash = self.transcript.current(&hash_buf);
        var s_ap = ks.deriveSecret(master, "s ap traffic", fin_hash);
        defer std.crypto.secureZero(u8, &s_ap);
        const c_ap = ks.deriveSecret(master, "c ap traffic", fin_hash);
        @memcpy(self.client_app_secret[0..ks.hash_len], &c_ap);
        @memcpy(self.client_handshake_secret[0..ks.hash_len], &c_hs);
        self.expected_finished[0..ks.hash_len].* = ks.finishedVerifyData(c_hs, fin_hash);
        try sink.writeSecret(.application, suite, &s_ap);
    }

    // -- Client Finished ----------------------------------------------------

    fn handleFinished(self: *Self, msg: []const u8, sink: anytype) !void {
        const hash_len = self.suite.hashLen();
        const body = msg[4..];
        if (body.len != hash_len) return error.DecodeError;
        if (!std.crypto.timing_safe.eql([record.max_hash_len]u8, padHash(body), padHash(self.expected_finished[0..hash_len])))
            return error.DecryptError;
        self.transcript.update(msg);
        try sink.readSecret(.application, self.suite, self.client_app_secret[0..hash_len]);
        std.crypto.secureZero(u8, &self.client_app_secret);
        std.crypto.secureZero(u8, &self.client_handshake_secret);
        self.state = .done;
    }

    fn padHash(h: []const u8) [record.max_hash_len]u8 {
        var out: [record.max_hash_len]u8 = @splat(0);
        @memcpy(out[0..h.len], h);
        return out;
    }
};

fn SinkError(comptime S: type) type {
    return switch (@typeInfo(S)) {
        .pointer => |p| p.child.Error,
        else => S.Error,
    };
}

fn selectAlpn(server: []const []const u8, offered: []const u8) Error![]const u8 {
    // Validate the client's list first: non-empty names, exact framing.
    var pos: usize = 0;
    while (pos < offered.len) {
        const len = offered[pos];
        if (len == 0 or pos + 1 + len > offered.len) return error.DecodeError;
        pos += 1 + len;
    }
    for (server) |proto| {
        pos = 0;
        while (pos < offered.len) {
            const len = offered[pos];
            if (std.mem.eql(u8, offered[pos + 1 ..][0..len], proto)) return proto;
            pos += 1 + len;
        }
    }
    return error.NoApplicationProtocol;
}

fn listHas(comptime T: type, list: []const u8, value: T) bool {
    const size = @divExact(@bitSizeOf(T), 8);
    var i: usize = 0;
    while (i + size <= list.len) : (i += size) {
        if (std.mem.readInt(T, list[i..][0..size], .big) == value) return true;
    }
    return false;
}

// -- Key exchange -----------------------------------------------------------

const KeyExchange = struct {
    share_buf: [MLKem768.ciphertext_length + X25519.public_length]u8 = undefined,
    share_len: usize = 0,
    shared_buf: [64]u8 = undefined,
    shared_len: usize = 0,

    fn publicShare(self: *const KeyExchange) []const u8 {
        return self.share_buf[0..self.share_len];
    }

    fn sharedSecret(self: *const KeyExchange) []const u8 {
        return self.shared_buf[0..self.shared_len];
    }

    fn x25519(self: *KeyExchange, client: []const u8, seed: *const [32]u8) Error!void {
        if (client.len != X25519.public_length) return error.IllegalParameter;
        const kp = X25519.KeyPair.generateDeterministic(seed.*);
        const shared = X25519.scalarmult(kp.secret_key, client[0..32].*) catch return error.IllegalParameter;
        @memcpy(self.share_buf[self.share_len..][0..32], &kp.public_key);
        self.share_len += 32;
        @memcpy(self.shared_buf[self.shared_len..][0..32], &shared);
        self.shared_len += 32;
    }

    fn run(self: *KeyExchange, share: KeyShare, entropy: *const [entropy_len]u8) Error!void {
        switch (share.group) {
            .x25519 => try self.x25519(share.key_exchange, entropy[32..64]),
            .secp256r1 => {
                // Only the uncompressed form is allowed (RFC 8446 §4.2.8.2).
                if (share.key_exchange.len != 65 or share.key_exchange[0] != 4) return error.IllegalParameter;
                const pk = EcdsaP256Sha256.PublicKey.fromSec1(share.key_exchange) catch return error.IllegalParameter;
                const kp = EcdsaP256Sha256.KeyPair.generateDeterministic(entropy[64..96].*) catch return error.InternalError;
                const point = pk.p.mulPublic(kp.secret_key.bytes, .big) catch return error.IllegalParameter;
                const shared = point.affineCoordinates().x.toBytes(.big);
                const public = kp.public_key.toUncompressedSec1();
                @memcpy(self.share_buf[0..public.len], &public);
                self.share_len = public.len;
                @memcpy(self.shared_buf[0..shared.len], &shared);
                self.shared_len = shared.len;
            },
            .x25519_ml_kem768 => {
                // ML-KEM-768 encapsulation key then X25519 share, in both
                // directions; the secret is ML-KEM's then X25519's.
                const ek_len = MLKem768.PublicKey.encoded_length;
                if (share.key_exchange.len != ek_len + X25519.public_length) return error.IllegalParameter;
                const ek = MLKem768.PublicKey.fromBytes(share.key_exchange[0..ek_len]) catch return error.IllegalParameter;
                const enc = ek.encapsDeterministic(entropy[96..128]);
                @memcpy(self.share_buf[0..enc.ciphertext.len], &enc.ciphertext);
                self.share_len = enc.ciphertext.len;
                @memcpy(self.shared_buf[0..enc.shared_secret.len], &enc.shared_secret);
                self.shared_len = enc.shared_secret.len;
                try self.x25519(share.key_exchange[ek_len..], entropy[32..64]);
            },
            else => return error.IllegalParameter,
        }
    }
};

// -- ClientHello parsing ------------------------------------------------------

pub const KeyShare = struct {
    group: NamedGroup,
    key_exchange: []const u8,
};

const KeyShareIterator = struct {
    data: []const u8,
    pos: usize = 0,

    fn next(self: *KeyShareIterator) Error!?KeyShare {
        if (self.pos == self.data.len) return null;
        var r: Reader = .{ .data = self.data[self.pos..] };
        const group: NamedGroup = @fromBackingInt(try r.int(u16));
        const kx = try r.vector(u16);
        if (kx.len == 0) return error.DecodeError;
        self.pos += r.pos;
        return .{ .group = group, .key_exchange = kx };
    }
};

const ClientHello = struct {
    session_id: []const u8,
    /// Raw u16 lists.
    suites: []const u8,
    supported_groups: ?[]const u8 = null,
    signature_algorithms: ?[]const u8 = null,
    /// The client_shares vector contents.
    key_shares: ?[]const u8 = null,
    /// The ProtocolNameList contents.
    alpn: ?[]const u8 = null,
    tls13: bool = false,
    early_data: bool = false,
    psk: bool = false,
    psk_modes: bool = false,

    fn parse(body: []const u8) Error!ClientHello {
        var r: Reader = .{ .data = body };
        _ = try r.int(u16); // legacy_version: ignored when supported_versions is present
        _ = try r.take(32); // random
        const session_id = try r.vector(u8);
        if (session_id.len > 32) return error.IllegalParameter;
        const suites = try r.vector(u16);
        if (suites.len == 0 or suites.len % 2 != 0) return error.DecodeError;
        const compression = try r.vector(u8);
        if (compression.len != 1 or compression[0] != 0) return error.IllegalParameter;
        var hello: ClientHello = .{ .session_id = session_id, .suites = suites };
        // A TLS 1.3 ClientHello always has extensions (supported_versions).
        if (r.pos == body.len) return error.ProtocolVersion;
        const exts_data = try r.vector(u16);
        if (r.pos != body.len) return error.DecodeError;

        var exts: Reader = .{ .data = exts_data };
        var seen: [64]u16 = undefined;
        var seen_len: usize = 0;
        while (exts.pos < exts_data.len) {
            const ext_type: ExtensionType = @fromBackingInt(try exts.int(u16));
            const ext = try exts.vector(u16);
            for (seen[0..seen_len]) |t| if (t == @backingInt(ext_type)) return error.IllegalParameter;
            if (seen_len == seen.len) return error.DecodeError;
            seen[seen_len] = @backingInt(ext_type);
            seen_len += 1;
            var e: Reader = .{ .data = ext };
            switch (ext_type) {
                .supported_versions => {
                    const versions = try e.vector(u8);
                    if (versions.len == 0 or versions.len % 2 != 0) return error.DecodeError;
                    hello.tls13 = listHas(u16, versions, 0x0304);
                },
                .supported_groups => {
                    const groups = try e.vector(u16);
                    if (groups.len == 0 or groups.len % 2 != 0) return error.DecodeError;
                    hello.supported_groups = groups;
                },
                .signature_algorithms => {
                    const algs = try e.vector(u16);
                    if (algs.len == 0 or algs.len % 2 != 0) return error.DecodeError;
                    hello.signature_algorithms = algs;
                },
                .key_share => {
                    const shares = try e.vector(u16);
                    var it: KeyShareIterator = .{ .data = shares };
                    while (try it.next()) |_| {}
                    hello.key_shares = shares;
                },
                .application_layer_protocol_negotiation => {
                    const protos = try e.vector(u16);
                    if (protos.len == 0) return error.DecodeError;
                    hello.alpn = protos;
                },
                .early_data => hello.early_data = true,
                .psk_key_exchange_modes => {
                    hello.psk_modes = true;
                    continue;
                },
                .pre_shared_key => {
                    // Must be last (RFC 8446 §4.2.11). Ignored: PSKs are
                    // not supported, so a full handshake follows.
                    if (exts.pos != exts_data.len) return error.IllegalParameter;
                    hello.psk = true;
                    continue;
                },
                else => continue,
            }
            if (e.pos != ext.len) return error.DecodeError;
        }
        // A PSK offer needs its key exchange modes (§4.2.9).
        if (hello.psk and !hello.psk_modes) return error.MissingExtension;
        return hello;
    }
};

const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.data.len - self.pos < n) return error.DecodeError;
        defer self.pos += n;
        return self.data[self.pos..][0..n];
    }

    fn int(self: *Reader, comptime T: type) Error!T {
        const size = @divExact(@bitSizeOf(T), 8);
        const bytes = try self.take(size);
        return std.mem.readInt(T, bytes[0..size], .big);
    }

    /// A vector with a T-sized length prefix.
    fn vector(self: *Reader, comptime T: type) Error![]const u8 {
        const len = try self.int(T);
        return self.take(len);
    }
};

/// Writes into a buffer known to be large enough.
const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.pos];
    }

    fn bytes(self: *Writer, b: []const u8) void {
        @memcpy(self.buf[self.pos..][0..b.len], b);
        self.pos += b.len;
    }

    fn int(self: *Writer, comptime T: type, v: T) void {
        std.mem.writeInt(T, self.buf[self.pos..][0..@divExact(@bitSizeOf(T), 8)], v, .big);
        self.pos += @divExact(@bitSizeOf(T), 8);
    }

    /// Reserves a length prefix; returns its position for `end`.
    fn begin(self: *Writer, comptime T: type) usize {
        const at = self.pos;
        self.pos += @divExact(@bitSizeOf(T), 8);
        return at;
    }

    fn end(self: *Writer, comptime T: type, at: usize) void {
        const size = @divExact(@bitSizeOf(T), 8);
        std.mem.writeInt(T, self.buf[at..][0..size], @intCast(self.pos - at - size), .big);
    }

    fn beginMessage(self: *Writer, t: HandshakeType) usize {
        self.int(u8, @backingInt(t));
        return self.begin(u24);
    }

    fn endMessage(self: *Writer, at: usize) void {
        self.end(u24, at);
    }
};

// -- Tests ------------------------------------------------------------------

const testHex = @import("./key_schedule.zig").testHex;

/// Records sink calls for inspection.
pub const TestSink = struct {
    pub const Error = error{OutOfMemory};
    pub const Event = union(enum) {
        data: struct { level: Level, bytes: []u8 },
        ccs,
        write_secret: struct { level: Level, suite: Suite, secret: []u8 },
        read_secret: struct { level: Level, suite: Suite, secret: []u8 },
    };

    allocator: std.mem.Allocator,
    events: std.ArrayList(Event) = .empty,

    pub fn deinit(self: *TestSink) void {
        for (self.events.items) |e| switch (e) {
            .data => |d| self.allocator.free(d.bytes),
            .write_secret => |s| self.allocator.free(s.secret),
            .read_secret => |s| self.allocator.free(s.secret),
            .ccs => {},
        };
        self.events.deinit(self.allocator);
    }

    pub fn handshakeData(self: *TestSink, level: Level, bytes: []const u8) TestSink.Error!void {
        try self.events.append(self.allocator, .{ .data = .{ .level = level, .bytes = try self.allocator.dupe(u8, bytes) } });
    }

    pub fn changeCipherSpec(self: *TestSink) TestSink.Error!void {
        try self.events.append(self.allocator, .ccs);
    }

    pub fn writeSecret(self: *TestSink, level: Level, suite: Suite, secret: []const u8) TestSink.Error!void {
        try self.events.append(self.allocator, .{ .write_secret = .{ .level = level, .suite = suite, .secret = try self.allocator.dupe(u8, secret) } });
    }

    pub fn readSecret(self: *TestSink, level: Level, suite: Suite, secret: []const u8) TestSink.Error!void {
        try self.events.append(self.allocator, .{ .read_secret = .{ .level = level, .suite = suite, .secret = try self.allocator.dupe(u8, secret) } });
    }
};

const rfc8448_client_hello = testHex(
    \\01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
    \\ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
    \\02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
    \\00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
    \\12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
    \\00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
    \\3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
    \\af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
    \\02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
    \\02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
);

fn rfc8448Entropy() [entropy_len]u8 {
    var e: [entropy_len]u8 = @splat(0x42);
    e[0..32].* = testHex("a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28");
    e[32..64].* = testHex("b1 58 0e ea df 6d d5 89 b8 ef 4f 2d 56 52 57 8c c8 10 e9 98 01 91 ec 8d 05 83 08 ce a2 16 a2 1e");
    return e;
}

fn testCredentials() !Credentials {
    const td = credentials.testdata;
    return Credentials.fromPem(std.testing.allocator, td.p256_cert, td.p256_key);
}

test "ServerHello and handshake secrets match RFC 8448" {
    var creds = try testCredentials();
    defer creds.deinit();
    const config: Config = .{ .credentials = &creds, .suites = &.{.aes_128_gcm_sha256}, .groups = &.{.x25519} };
    const entropy = rfc8448Entropy();
    var hs = Handshake.init(std.testing.allocator, &config, &entropy);
    defer hs.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();

    // Fed in two pieces to exercise reassembly.
    try hs.feed(.initial, rfc8448_client_hello[0..50], &sink);
    try std.testing.expectEqual(0, sink.events.items.len);
    try hs.feed(.initial, rfc8448_client_hello[50..], &sink);

    const ev = sink.events.items;
    try std.testing.expectEqual(5, ev.len);
    try std.testing.expectEqual(Level.initial, ev[0].data.level);
    try std.testing.expectEqualSlices(u8, &testHex(
        \\02 00 00 56 03 03 a6 af 06 a4 12 18 60
        \\dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
        \\d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
        \\76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
        \\dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04
    ), ev[0].data.bytes);
    // No session ID, so no compatibility change_cipher_spec.
    try std.testing.expectEqual(Level.handshake, ev[1].write_secret.level);
    try std.testing.expectEqualSlices(u8, &testHex("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"), ev[1].write_secret.secret);
    try std.testing.expectEqualSlices(u8, &testHex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"), ev[2].read_secret.secret);
    // EncryptedExtensions, Certificate, CertificateVerify, Finished.
    try std.testing.expectEqual(Level.handshake, ev[3].data.level);
    var r: Reader = .{ .data = ev[3].data.bytes };
    for ([_]HandshakeType{ .encrypted_extensions, .certificate, .certificate_verify, .finished }) |t| {
        try std.testing.expectEqual(@backingInt(t), (try r.take(1))[0]);
        _ = try r.take(try r.int(u24));
    }
    try std.testing.expectEqual(r.data.len, r.pos);
    try std.testing.expectEqual(Level.application, ev[4].write_secret.level);
    try std.testing.expect(!hs.isDone());
}

/// Builds a ClientHello with the given suites, groups and key shares.
pub fn buildClientHello(buf: []u8, opts: struct {
    suites: []const u16 = &.{0x1301},
    groups: []const NamedGroup = &.{.x25519},
    shares: []const KeyShare = &.{},
    sig_algs: []const u16 = &.{0x0403},
    session_id: []const u8 = "",
    alpn: ?[]const u8 = null,
    versions: []const u16 = &.{0x0304},
    extra: []const u8 = "",
}) []const u8 {
    var w: Writer = .{ .buf = buf };
    const hdr = w.beginMessage(.client_hello);
    w.int(u16, 0x0303);
    w.bytes(&@as([32]u8, @splat(1)));
    w.int(u8, @intCast(opts.session_id.len));
    w.bytes(opts.session_id);
    w.int(u16, @intCast(opts.suites.len * 2));
    for (opts.suites) |s| w.int(u16, s);
    w.int(u8, 1);
    w.int(u8, 0);
    const exts = w.begin(u16);
    w.int(u16, @backingInt(ExtensionType.supported_versions));
    w.int(u16, @intCast(1 + opts.versions.len * 2));
    w.int(u8, @intCast(opts.versions.len * 2));
    for (opts.versions) |v| w.int(u16, v);
    w.int(u16, @backingInt(ExtensionType.supported_groups));
    w.int(u16, @intCast(2 + opts.groups.len * 2));
    w.int(u16, @intCast(opts.groups.len * 2));
    for (opts.groups) |g| w.int(u16, @backingInt(g));
    w.int(u16, @backingInt(ExtensionType.signature_algorithms));
    w.int(u16, @intCast(2 + opts.sig_algs.len * 2));
    w.int(u16, @intCast(opts.sig_algs.len * 2));
    for (opts.sig_algs) |s| w.int(u16, s);
    w.int(u16, @backingInt(ExtensionType.key_share));
    const ks_ext = w.begin(u16);
    const ks_list = w.begin(u16);
    for (opts.shares) |s| {
        w.int(u16, @backingInt(s.group));
        w.int(u16, @intCast(s.key_exchange.len));
        w.bytes(s.key_exchange);
    }
    w.end(u16, ks_list);
    w.end(u16, ks_ext);
    if (opts.alpn) |a| {
        w.int(u16, @backingInt(ExtensionType.application_layer_protocol_negotiation));
        w.int(u16, @intCast(2 + a.len));
        w.int(u16, @intCast(a.len));
        w.bytes(a);
    }
    w.bytes(opts.extra);
    w.end(u16, exts);
    w.endMessage(hdr);
    return w.written();
}

fn expectHelloError(expected: anyerror, hello: []const u8, config: *const Config) !void {
    const entropy: [entropy_len]u8 = @splat(9);
    var hs = Handshake.init(std.testing.allocator, config, &entropy);
    defer hs.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();
    try std.testing.expectError(expected, hs.feed(.initial, hello, &sink));
}

test "ClientHello negotiation failures" {
    var creds = try testCredentials();
    defer creds.deinit();
    const config: Config = .{ .credentials = &creds, .alpn = &.{ "h2", "http/1.1" } };
    const pub_key = X25519.recoverPublicKey(@splat(5));
    const share: []const KeyShare = &.{.{ .group = .x25519, .key_exchange = &pub_key }};
    var buf: [2048]u8 = undefined;

    try expectHelloError(error.ProtocolVersion, buildClientHello(&buf, .{ .shares = share, .versions = &.{0x0303} }), &config);
    try expectHelloError(error.HandshakeFailure, buildClientHello(&buf, .{ .shares = share, .suites = &.{0xc02b} }), &config);
    try expectHelloError(error.HandshakeFailure, buildClientHello(&buf, .{ .shares = share, .sig_algs = &.{0x0804} }), &config);
    try expectHelloError(error.HandshakeFailure, buildClientHello(&buf, .{ .shares = &.{}, .groups = &.{.ffdhe2048} }), &config);
    // A share for a group the client didn't list.
    try expectHelloError(error.IllegalParameter, buildClientHello(&buf, .{ .shares = share, .groups = &.{.secp256r1} }), &config);
    // Two shares for the same group.
    try expectHelloError(error.IllegalParameter, buildClientHello(&buf, .{ .shares = &.{ share[0], share[0] } }), &config);
    // Wrong share length.
    try expectHelloError(error.IllegalParameter, buildClientHello(&buf, .{ .shares = &.{.{ .group = .x25519, .key_exchange = "short" }} }), &config);
    // A low-order X25519 point gives an all-zero secret.
    try expectHelloError(error.IllegalParameter, buildClientHello(&buf, .{ .shares = &.{.{ .group = .x25519, .key_exchange = &@as([32]u8, @splat(0)) }} }), &config);
    try expectHelloError(error.NoApplicationProtocol, buildClientHello(&buf, .{ .shares = share, .alpn = "\x08spdy/3.1" }), &config);
    try expectHelloError(error.DecodeError, buildClientHello(&buf, .{ .shares = share, .alpn = "\x09spdy/3.1" }), &config);
    // Duplicate extension.
    try expectHelloError(error.IllegalParameter, buildClientHello(&buf, .{ .shares = share, .extra = "\x00\x2b\x00\x03\x02\x03\x04" }), &config);
    // pre_shared_key not last.
    try expectHelloError(error.IllegalParameter, buildClientHello(&buf, .{ .shares = share, .extra = "\x00\x29\x00\x00\x00\x15\x00\x00" }), &config);
    // pre_shared_key without psk_key_exchange_modes (§4.2.9).
    try expectHelloError(error.MissingExtension, buildClientHello(&buf, .{ .shares = share, .extra = "\x00\x29\x00\x00" }), &config);
    // Truncated.
    const hello = buildClientHello(&buf, .{ .shares = share });
    var cut: [2048]u8 = undefined;
    @memcpy(cut[0..hello.len], hello);
    std.mem.writeInt(u24, cut[1..4], @intCast(hello.len - 4 - 10), .big);
    try expectHelloError(error.DecodeError, cut[0 .. hello.len - 10], &config);
    // A second message in the same flight after ClientHello.
    @memcpy(cut[0..hello.len], hello);
    @memcpy(cut[hello.len..][0..4], "\x14\x00\x00\x00");
    try expectHelloError(error.UnexpectedMessage, cut[0 .. hello.len + 4], &config);
    // Wrong first message.
    try expectHelloError(error.UnexpectedMessage, "\x14\x00\x00\x00", &config);
}

test "HelloRetryRequest when no usable key share was sent" {
    var creds = try testCredentials();
    defer creds.deinit();
    const config: Config = .{ .credentials = &creds, .groups = &.{.x25519} };
    const entropy: [entropy_len]u8 = @splat(9);
    var hs = Handshake.init(std.testing.allocator, &config, &entropy);
    defer hs.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();

    var buf: [2048]u8 = undefined;
    const p256 = try EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(4));
    const p256_share = p256.public_key.toUncompressedSec1();
    const session_id: [32]u8 = @splat(0xab);
    const ch1 = buildClientHello(&buf, .{
        .groups = &.{ .secp256r1, .x25519 },
        .shares = &.{.{ .group = .secp256r1, .key_exchange = &p256_share }},
        .session_id = &session_id,
    });
    try hs.feed(.initial, ch1, &sink);
    try std.testing.expectEqual(2, sink.events.items.len);
    const hrr = sink.events.items[0].data.bytes;
    try std.testing.expectEqualSlices(u8, &tls.hello_retry_request_sequence, hrr[6..38]);
    try std.testing.expectEqualSlices(u8, &session_id, hrr[39..71]);
    try std.testing.expect(sink.events.items[1] == .ccs);

    // A retry that still lacks the requested share fails.
    {
        var hs2 = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs2.deinit();
        var sink2: TestSink = .{ .allocator = std.testing.allocator };
        defer sink2.deinit();
        try hs2.feed(.initial, ch1, &sink2);
        try std.testing.expectError(error.IllegalParameter, hs2.feed(.initial, ch1, &sink2));
    }

    const x = X25519.recoverPublicKey(@splat(5));
    const ch2 = buildClientHello(&buf, .{
        .groups = &.{ .secp256r1, .x25519 },
        .shares = &.{.{ .group = .x25519, .key_exchange = &x }},
        .session_id = &session_id,
    });
    try hs.feed(.initial, ch2, &sink);
    // ServerHello, then no second change_cipher_spec.
    try std.testing.expect(sink.events.items[2] == .data);
    try std.testing.expect(sink.events.items[3] == .write_secret);
}

test "every group and suite completes against a reference client computation" {
    var creds = try testCredentials();
    defer creds.deinit();
    const groups = [_]NamedGroup{ .x25519, .secp256r1, .x25519_ml_kem768 };
    const suites = [_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 };
    for (groups) |group| for (suites) |suite| {
        const config: Config = .{ .credentials = &creds, .suites = &.{suite}, .groups = &.{group}, .alpn = &.{"http/1.1"} };
        var entropy: [entropy_len]u8 = undefined;
        for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();

        // Client side key shares, as std's TLS client computes them.
        const x_kp = X25519.KeyPair.generateDeterministic(@splat(11));
        const p_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(12));
        const m_kp = try MLKem768.KeyPair.generateDeterministic(@splat(13));
        var share_buf: [MLKem768.PublicKey.encoded_length + 32]u8 = undefined;
        const share: []const u8 = switch (group) {
            .x25519 => &x_kp.public_key,
            .secp256r1 => blk: {
                const s = p_kp.public_key.toUncompressedSec1();
                @memcpy(share_buf[0..s.len], &s);
                break :blk share_buf[0..s.len];
            },
            else => blk: {
                const ek = m_kp.public_key.toBytes();
                @memcpy(share_buf[0..ek.len], &ek);
                @memcpy(share_buf[ek.len..][0..32], &x_kp.public_key);
                break :blk &share_buf;
            },
        };
        var buf: [4096]u8 = undefined;
        const hello = buildClientHello(&buf, .{
            .suites = &.{@backingInt(suite)},
            .groups = &.{group},
            .shares = &.{.{ .group = group, .key_exchange = share }},
            .alpn = "\x02h2\x08http/1.1",
        });
        try hs.feed(.initial, hello, &sink);
        try std.testing.expectEqualStrings("http/1.1", hs.alpn.?);

        // Recompute the server's handshake secret from the client side.
        const sh = sink.events.items[0].data.bytes;
        var r: Reader = .{ .data = sh[4..] };
        _ = try r.take(2 + 32);
        _ = try r.vector(u8);
        try std.testing.expectEqual(@backingInt(suite), try r.int(u16));
        _ = try r.take(1);
        var exts: Reader = .{ .data = try r.vector(u16) };
        var server_share: []const u8 = "";
        while (exts.pos < exts.data.len) {
            const t = try exts.int(u16);
            var e: Reader = .{ .data = try exts.vector(u16) };
            if (t == @backingInt(ExtensionType.key_share)) {
                try std.testing.expectEqual(@backingInt(group), try e.int(u16));
                server_share = try e.vector(u16);
            }
        }
        var shared_buf: [64]u8 = undefined;
        const shared: []const u8 = switch (group) {
            .x25519 => blk: {
                shared_buf[0..32].* = try X25519.scalarmult(x_kp.secret_key, server_share[0..32].*);
                break :blk shared_buf[0..32];
            },
            .secp256r1 => blk: {
                const pk = try EcdsaP256Sha256.PublicKey.fromSec1(server_share);
                shared_buf[0..32].* = (try pk.p.mulPublic(p_kp.secret_key.bytes, .big)).affineCoordinates().x.toBytes(.big);
                break :blk shared_buf[0..32];
            },
            else => blk: {
                const ct_len = MLKem768.ciphertext_length;
                shared_buf[0..32].* = try m_kp.secret_key.decaps(server_share[0..ct_len]);
                shared_buf[32..64].* = try X25519.scalarmult(x_kp.secret_key, server_share[ct_len..][0..32].*);
                break :blk &shared_buf;
            },
        };

        switch (suite) {
            inline else => |s| {
                const ks = s.Schedule();
                var t = ks.Hash.init(.{});
                t.update(hello);
                t.update(sh);
                var h: [ks.hash_len]u8 = undefined;
                var t2 = t;
                t2.final(&h);
                const hs_secret = ks.handshakeSecret(ks.earlySecret(), shared);
                const s_hs = ks.deriveSecret(hs_secret, "s hs traffic", &h);
                const c_hs = ks.deriveSecret(hs_secret, "c hs traffic", &h);
                try std.testing.expectEqualSlices(u8, &s_hs, sink.events.items[1].write_secret.secret);

                // Check the server Finished, then answer with ours.
                const flight = sink.events.items[3].data.bytes;
                const fin_at = flight.len - 4 - ks.hash_len;
                t.update(flight[0..fin_at]);
                var t3 = t;
                t3.final(&h);
                try std.testing.expectEqualSlices(u8, &ks.finishedVerifyData(s_hs, &h), flight[fin_at + 4 ..]);
                t.update(flight[fin_at..]);
                t.final(&h);
                var fin: [4 + ks.hash_len]u8 = undefined;
                fin[0..4].* = .{ 0x14, 0, 0, ks.hash_len };
                fin[4..].* = ks.finishedVerifyData(c_hs, &h);

                // A wrong Finished is a decrypt_error; the right one completes.
                var bad = fin;
                bad[10] ^= 1;
                var hs_bad = hs;
                hs_bad.partial = .empty;
                try std.testing.expectError(error.DecryptError, hs_bad.feed(.handshake, &bad, &sink));
                try std.testing.expectError(error.UnexpectedMessage, hs.feed(.initial, &fin, &sink));
                try hs.feed(.handshake, &fin, &sink);
                try std.testing.expect(hs.isDone());
                const last = sink.events.items[sink.events.items.len - 1].read_secret;
                try std.testing.expectEqual(Level.application, last.level);
            },
        }
    };
}
