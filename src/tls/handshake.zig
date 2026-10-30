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
//!   sink.transportParameters(client: []const u8) ![]const u8   (QUIC only)
//!
//! With `Config.quic` (RFC 9001 §8), the client's quic_transport_parameters
//! extension is required and handed to the sink, which returns ours for
//! EncryptedExtensions; ALPN is required; the legacy session ID must be
//! empty, so no change_cipher_spec is ever sent.
//!
//! Scope: full handshakes with certificate authentication, resumption
//! with session tickets (`Config.tickets`, PSK with (EC)DHE only), and
//! 0-RTT on resumption (`Config.max_early_data`); no client certificates.
//!
//! 0-RTT: with early data accepted the client's early traffic secret goes
//! to the sink (`.early`) right after ClientHello. Over TCP the
//! handshake read key follows only at EndOfEarlyData; over QUIC both are
//! installed at once (QUIC has no EndOfEarlyData, RFC 9001 §8.3).
const std = @import("std");
const tls = std.crypto.tls;
const record = @import("./record.zig");
const errors = @import("./errors.zig");
const credentials = @import("./credentials.zig");
const p256_base = @import("./p256.zig");
const x25519_base = @import("./x25519.zig");
const ticket = @import("./ticket.zig");
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

/// Encryption levels: QUIC's packet number spaces, then 0-RTT (which QUIC
/// sends in the application space).
pub const Level = enum(u2) { initial, handshake, application, early };

pub const Config = struct {
    /// The default certificate.
    credentials: *const Credentials,
    /// More certificates, chosen by the ClientHello's server_name (RFC
    /// 6066): the first, the default included, whose names match it
    /// (`Credentials.matchesHost`); the default when none does or no name
    /// is sent. At most 254.
    sni_credentials: []const Credentials = &.{},
    /// ALPN protocol names in server preference order. Empty: no ALPN.
    alpn: []const []const u8 = &.{},
    /// In preference order.
    suites: []const Suite = default_suites,
    /// In preference order. Key shares the client sent are preferred over
    /// a better group that would need a HelloRetryRequest.
    groups: []const NamedGroup = &.{ .x25519_ml_kem768, .x25519, .secp256r1 },
    /// QUIC (RFC 9001) rather than TLS over TCP.
    quic: bool = false,
    /// Session tickets: one is sent after each handshake, and a ClientHello
    /// offering a valid one resumes without certificate authentication.
    tickets: ?*const ticket.Keys = null,
    /// 0-RTT (RFC 8446 §4.2.10): with tickets and `replay`, tickets allow
    /// up to this many bytes of early data, accepted from a client that
    /// resumes one this process issued (see `ticket`). 0: off, and early
    /// data offered is skipped.
    max_early_data: u32 = 0,
    replay: ?*ticket.ReplayGuard = null,

    fn earlyData(self: *const Config) bool {
        return self.max_early_data > 0 and self.replay != null and self.tickets != null;
    }
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
pub const entropy_len = 32 + 32 + 32 + 32 + credentials.noise_len + 12 + 4;
/// Where the session ticket's AEAD nonce and age offset are.
const entropy_ticket = 32 + 32 + 32 + 32 + credentials.noise_len;

/// Largest handshake message accepted from a client.
pub const max_message_len = 1 << 16;

const State = enum { client_hello, client_hello_retry, end_of_early_data, client_finished, done };

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

/// Zeroes a buffer, then frees it. `rawFree`, because `free` overwrites
/// the memory first in safe builds, which would hide the zeroing from
/// tests (in fast builds nothing does).
fn freeZeroed(allocator: std.mem.Allocator, buf: []u8) void {
    if (buf.len == 0) return;
    std.crypto.secureZero(u8, buf);
    allocator.rawFree(buf, .of(u8), @returnAddress());
}

pub const Handshake = struct {
    const Self = @This();

    config: *const Config,
    allocator: std.mem.Allocator,
    state: State = .client_hello,
    entropy: [entropy_len]u8,
    /// A handshake message split across feed calls.
    partial: std.ArrayList(u8) = .empty,
    /// Where the encrypted flight is assembled. Like `partial`, kept for
    /// the next handshake by `release` and `reinit`.
    flight: []u8 = &.{},

    suite: Suite = undefined,
    transcript: Transcript = undefined,
    /// Group chosen in a HelloRetryRequest.
    retry_group: ?NamedGroup = null,
    /// After a HelloRetryRequest: a digest of what ClientHello2 must repeat
    /// (see `repeatedDigest`).
    retry_digest: [32]u8 = undefined,
    session_id_buf: [32]u8 = undefined,
    session_id_len: u8 = 0,
    sent_ccs: bool = false,

    /// Negotiated ALPN protocol (points into the config), if any.
    alpn: ?[]const u8 = null,
    /// The certificate for this handshake, its index (0: the default, i:
    /// `sni_credentials[i - 1]`), and whether server_name chose it.
    creds: *const Credentials = undefined,
    creds_index: u8 = 0,
    sni_matched: bool = false,
    /// QUIC: our transport parameters, as the sink returned them; sent in
    /// EncryptedExtensions.
    transport_params: []const u8 = &.{},
    /// The client offered 0-RTT data. Unless accepted, the record layer
    /// must skip it.
    early_data_offered: bool = false,
    /// 0-RTT accepted: early data is coming under the early traffic key.
    early_accepted: bool = false,

    /// A session ticket was accepted (the resumption PSK is in `psk`).
    resumed: bool = false,
    psk_identity: u16 = 0,
    psk: [record.max_hash_len]u8 = undefined,
    /// Kept until the client's Finished, for the resumption secret.
    master_secret: [record.max_hash_len]u8 = undefined,

    client_handshake_secret: [record.max_hash_len]u8 = undefined,
    client_app_secret: [record.max_hash_len]u8 = undefined,
    /// The client's Finished, computed once the server flight is sent.
    expected_finished: [record.max_hash_len]u8 = undefined,

    pub fn init(allocator: std.mem.Allocator, config: *const Config, entropy: *const [entropy_len]u8) Self {
        return .{ .allocator = allocator, .config = config, .entropy = entropy.* };
    }

    pub fn deinit(self: *Self) void {
        self.release(0);
    }

    /// Ends a handshake (finished or failed) whose state will be reused
    /// (conn.zig's `Pools`): zeroes all of it, secrets, transcript and the
    /// buffers' whole capacity (they held the ClientHello, with any
    /// ticket and binders, and the flight), and frees buffers larger than
    /// `keep` bytes. `reinit` makes it usable again.
    pub fn release(self: *Self, keep: usize) void {
        const allocator = self.allocator;
        var partial = self.partial;
        // Cleared first: in safe builds clearing marks the items undefined.
        partial.clearRetainingCapacity();
        if (partial.capacity > keep) {
            freeZeroed(allocator, partial.allocatedSlice());
            partial = .empty;
        } else {
            std.crypto.secureZero(u8, partial.allocatedSlice());
        }
        var flight = self.flight;
        if (flight.len > keep) {
            freeZeroed(allocator, flight);
            flight = &.{};
        } else {
            std.crypto.secureZero(u8, flight);
        }
        std.crypto.secureZero(u8, std.mem.asBytes(self));
        self.allocator = allocator;
        self.partial = partial;
        self.flight = flight;
    }

    /// `init` again for a released state, keeping its buffers, so that a
    /// handshake on a reused state allocates nothing.
    pub fn reinit(self: *Self, config: *const Config, entropy: *const [entropy_len]u8) void {
        const partial = self.partial;
        const flight = self.flight;
        self.* = .init(self.allocator, config, entropy);
        self.partial = partial;
        self.flight = flight;
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
                    const key_change = try self.handleMessage(level, rest[0..n], rest.len > n, sink);
                    rest = rest[n..];
                    // RFC 8446 §5.1: messages before a key change must end
                    // on a record boundary.
                    if (key_change and rest.len > 0) return error.UnexpectedMessage;
                    continue;
                }
            }
            if (self.partial.items.len + rest.len > max_message_len + 4) return error.DecodeError;
            self.appendPartial(rest) catch return error.InternalError;
            rest = &.{};
            while (try messageLen(self.partial.items)) |n| {
                const key_change = try self.handleMessage(level, self.partial.items[0..n], self.partial.items.len > n, sink);
                const left = self.partial.items.len - n;
                std.mem.copyForwards(u8, self.partial.items[0..left], self.partial.items[n..]);
                self.partial.shrinkRetainingCapacity(left);
                if (key_change and left > 0) return error.UnexpectedMessage;
            }
        }
        if (self.state == .done) self.partial.clearRetainingCapacity();
    }

    /// Appends to `partial`, growing it by hand so that the old buffer is
    /// zeroed before it is freed (it can hold a ticket and binders).
    fn appendPartial(self: *Self, bytes: []const u8) !void {
        const p = &self.partial;
        if (p.capacity - p.items.len < bytes.len) {
            const new = try self.allocator.alloc(u8, @max(p.items.len + bytes.len, 2 * p.capacity));
            const len = p.items.len;
            @memcpy(new[0..len], p.items);
            freeZeroed(self.allocator, p.allocatedSlice());
            p.items = new[0..len];
            p.capacity = new.len;
        }
        p.appendSliceAssumeCapacity(bytes);
    }

    fn messageLen(data: []const u8) Error!?usize {
        if (data.len < 4) return null;
        const len = std.mem.readInt(u24, data[1..4], .big);
        if (len > max_message_len) return error.DecodeError;
        return if (data.len >= 4 + len) 4 + len else null;
    }

    /// Returns true if the message caused a change of read keys. `more`:
    /// bytes follow it in the same record.
    fn handleMessage(self: *Self, level: Level, msg: []const u8, more: bool, sink: anytype) !bool {
        const msg_type: HandshakeType = @fromBackingInt(msg[0]);
        switch (self.state) {
            .client_hello, .client_hello_retry => {
                if (level != .initial or msg_type != .client_hello) return error.UnexpectedMessage;
                try self.handleClientHello(msg, sink);
                return self.state == .client_finished or self.state == .end_of_early_data;
            },
            .end_of_early_data => {
                if (level != .early or msg_type != .end_of_early_data) return error.UnexpectedMessage;
                if (msg.len != 4) return error.DecodeError;
                if (more) return error.UnexpectedMessage;
                self.handleEndOfEarlyData(msg);
                try sink.readSecret(.handshake, self.suite, self.client_handshake_secret[0..self.suite.hashLen()]);
                return true;
            },
            .client_finished => {
                if (level != .handshake or msg_type != .finished) return error.UnexpectedMessage;
                // Finished always changes keys (§5.1): fail before acting
                // on it, rather than after sending a session ticket.
                if (more) return error.UnexpectedMessage;
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
        if (self.config.quic) {
            // RFC 9001 §8.4: QUIC has no middlebox compatibility mode.
            if (hello.session_id.len != 0) return error.IllegalParameter;
            // §8.2: the extension is mandatory.
            if (hello.quic_transport_params == null) return error.MissingExtension;
        }
        if (retry) {
            if (hello.early_data) return error.IllegalParameter;
            if (!std.mem.eql(u8, hello.session_id, self.session_id_buf[0..self.session_id_len]))
                return error.IllegalParameter;
            if (!listHas(u16, hello.suites, @backingInt(self.suite))) return error.IllegalParameter;
            const digest = repeatedDigest(hello);
            if (!std.mem.eql(u8, &digest, &self.retry_digest)) return error.IllegalParameter;
        } else {
            self.suite = for (self.config.suites) |s| {
                if (listHas(u16, hello.suites, @backingInt(s))) break s;
            } else return error.HandshakeFailure;
            self.session_id_len = @intCast(hello.session_id.len);
            @memcpy(self.session_id_buf[0..hello.session_id.len], hello.session_id);
            self.early_data_offered = hello.early_data;
            self.chooseCredentials(hello.server_name);
        }

        // Without a PSK the certificate must be usable (checked again once
        // a ticket was looked at).
        if (!hello.psk) try self.checkSignatureScheme(hello);
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
            self.retry_digest = repeatedDigest(hello);
            return self.sendHelloRetryRequest(msg, group, sink);
        }

        if (self.config.alpn.len > 0) {
            if (hello.alpn) |offered| {
                self.alpn = try selectAlpn(self.config.alpn, offered);
            }
        }
        if (self.config.quic) {
            // §8.1: a QUIC handshake must agree on an application protocol.
            if (self.alpn == null) return error.NoApplicationProtocol;
            const Sink = switch (@typeInfo(@TypeOf(sink))) {
                .pointer => |p| p.child,
                else => @TypeOf(sink),
            };
            // Only QUIC sinks have transport parameters; a QUIC config with
            // a TCP sink is a programming error.
            if (!@hasDecl(Sink, "transportParameters")) return error.InternalError;
            self.transport_params = try sink.transportParameters(hello.quic_transport_params.?);
        }

        self.resumed = false;
        if (hello.psk) try self.choosePsk(&hello, msg);
        if (!self.resumed) try self.checkSignatureScheme(hello);
        self.transcript.update(msg);
        if (self.early_accepted) try self.sendEarlySecret(sink);
        try self.sendServerFlight(chosen.?, sink);
    }

    /// RFC 8446 §4.1.2: ClientHello2 is ClientHello1 but for key_share,
    /// early_data, cookie, pre_shared_key and padding. A digest of every
    /// other extension, in order (types, lengths and bodies); the suites
    /// and session ID are compared directly. server_name matters most:
    /// ClientHello1's chose the certificate.
    fn repeatedDigest(hello: ClientHello) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        // Framing was checked by `ClientHello.parse`.
        var exts: Reader = .{ .data = hello.extensions };
        while (exts.pos < hello.extensions.len) {
            const at = exts.pos;
            const ext_type: ExtensionType = @fromBackingInt(exts.int(u16) catch unreachable);
            _ = exts.vector(u16) catch unreachable;
            switch (ext_type) {
                .key_share, .early_data, .cookie, .pre_shared_key, .padding => {},
                else => h.update(hello.extensions[at..exts.pos]),
            }
        }
        return h.finalResult();
    }

    fn checkSignatureScheme(self: *const Self, hello: ClientHello) Error!void {
        const sig_algs = hello.signature_algorithms orelse return error.MissingExtension;
        if (!listHas(u16, sig_algs, @backingInt(self.creds.key.scheme())))
            return error.HandshakeFailure;
    }

    /// The certificate server_name asks for (see `Config.sni_credentials`).
    fn chooseCredentials(self: *Self, server_name: ?[]const u8) void {
        self.creds = self.config.credentials;
        self.creds_index = 0;
        self.sni_matched = false;
        const name = server_name orelse return;
        if (self.config.credentials.matchesHost(name)) {
            self.sni_matched = true;
            return;
        }
        for (self.config.sni_credentials, 0..) |*c, i| {
            if (i >= 254) break;
            if (c.matchesHost(name)) {
                self.creds = c;
                self.creds_index = @intCast(i + 1);
                self.sni_matched = true;
                return;
            }
        }
    }

    /// RFC 8446 §4.2.11: the first identity that is one of our tickets,
    /// still valid, for this transport and with the suite's hash, is
    /// resumed if its binder verifies (otherwise the handshake fails).
    /// Anything else gets a full handshake. Only psk_dhe_ke is supported,
    /// so a resumed session still has forward secrecy.
    fn choosePsk(self: *Self, hello: *const ClientHello, msg: []const u8) Error!void {
        const keys = self.config.tickets orelse return;
        if (!hello.psk_dhe) return;
        var ids: Reader = .{ .data = hello.psk_identities };
        var binders: Reader = .{ .data = hello.psk_binders };
        var index: u16 = 0;
        while (ids.pos < ids.data.len) : (index += 1) {
            const identity = try ids.vector(u16);
            const obfuscated_age = try ids.int(u32);
            const binder = try binders.vector(u8);
            if (index >= 8) return; // look at a few, not every one offered
            const state = keys.open(identity) orelse continue;
            if (state.quic != self.config.quic) continue;
            // Authenticated with another certificate (another name).
            if (state.cert != self.creds_index) continue;
            const suite: Suite = @fromBackingInt(state.suite);
            if (suite.hashLen() != self.suite.hashLen() or state.psk_len != self.suite.hashLen()) continue;
            // The binder covers the ClientHello up to the binders.
            var t = self.transcript;
            t.update(msg[0 .. 4 + hello.binders_offset]);
            var hash_buf: [record.max_hash_len]u8 = undefined;
            const hash = t.current(&hash_buf);
            switch (self.suite) {
                inline else => |s| {
                    const ks = s.Schedule();
                    var early = ks.earlySecretPsk(state.pskSlice());
                    defer std.crypto.secureZero(u8, &early);
                    var binder_key = ks.deriveSecret(early, "res binder", &ks.empty_hash);
                    defer std.crypto.secureZero(u8, &binder_key);
                    const expected = ks.finishedVerifyData(binder_key, hash);
                    if (binder.len != ks.hash_len or !std.crypto.timing_safe.eql([ks.hash_len]u8, binder[0..ks.hash_len].*, expected))
                        return error.DecryptError;
                },
            }
            self.resumed = true;
            self.psk_identity = index;
            @memcpy(self.psk[0..state.psk_len], state.pskSlice());
            // Early data is under the first PSK offered (§4.2.10).
            self.early_accepted = index == 0 and hello.early_data and self.acceptEarly(keys, &state, obfuscated_age, binder);
            return;
        }
    }

    /// 0-RTT with a resumed ticket (§4.2.10): it allows early data and
    /// was issued by this process, for the same suite and ALPN protocol;
    /// the client's ticket age is close to ours (§8.3); and this
    /// ClientHello wasn't seen before (§8.2).
    fn acceptEarly(self: *const Self, keys: *const ticket.Keys, state: *const ticket.State, obfuscated_age: u32, binder: []const u8) bool {
        if (!self.config.earlyData() or !state.early or state.instance != keys.instance) return false;
        if (state.suite != @backingInt(self.suite) or state.alpn != self.alpnIndex()) return false;
        const now = keys.now();
        const client_age_s: i64 = (obfuscated_age -% state.age_add) / 1000;
        if (@abs(now - state.issued - client_age_s) > ticket.ReplayGuard.max_age_skew_s) return false;
        return self.config.replay.?.admit(binder, now);
    }

    /// The negotiated protocol as a ticket records it: its index in the
    /// configuration plus one, or 0.
    fn alpnIndex(self: *const Self) u8 {
        const proto = self.alpn orelse return 0;
        for (self.config.alpn, 0..) |p, i| {
            if (std.mem.eql(u8, p, proto)) return @intCast(@min(i + 1, 255));
        }
        return 0;
    }

    /// client_early_traffic_secret, over the ClientHello (§7.1).
    fn sendEarlySecret(self: *Self, sink: anytype) !void {
        var hash_buf: [record.max_hash_len]u8 = undefined;
        const hello_hash = self.transcript.current(&hash_buf);
        switch (self.suite) {
            inline else => |s| {
                const ks = s.Schedule();
                var early = ks.earlySecretPsk(self.psk[0..ks.hash_len]);
                defer std.crypto.secureZero(u8, &early);
                var c_e = ks.deriveSecret(early, "c e traffic", hello_hash);
                defer std.crypto.secureZero(u8, &c_e);
                try sink.readSecret(.early, s, &c_e);
            },
        }
    }

    /// The end of early data over TCP: the client's Finished covers it.
    fn handleEndOfEarlyData(self: *Self, msg: []const u8) void {
        self.transcript.update(msg);
        var hash_buf: [record.max_hash_len]u8 = undefined;
        const hash = self.transcript.current(&hash_buf);
        switch (self.suite) {
            inline else => |s| {
                const ks = s.Schedule();
                self.expected_finished[0..ks.hash_len].* = ks.finishedVerifyData(self.client_handshake_secret[0..ks.hash_len].*, hash);
            },
        }
        self.state = .client_finished;
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
        if (self.resumed) {
            w.int(u16, @backingInt(ExtensionType.pre_shared_key));
            w.int(u16, 2);
            w.int(u16, self.psk_identity);
        }
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
        self.state = if (self.early_accepted and !self.config.quic) .end_of_early_data else .client_finished;
    }

    fn sendEncryptedFlight(self: *Self, comptime suite: Suite, shared_secret: []const u8, sink: anytype) !void {
        const ks = suite.Schedule();
        var hash_buf: [record.max_hash_len]u8 = undefined;

        var early = if (self.resumed) ks.earlySecretPsk(self.psk[0..ks.hash_len]) else ks.earlySecret();
        defer std.crypto.secureZero(u8, &early);
        var hs = ks.handshakeSecret(early, shared_secret);
        defer std.crypto.secureZero(u8, &hs);
        const hello_hash = self.transcript.current(&hash_buf);
        var c_hs = ks.deriveSecret(hs, "c hs traffic", hello_hash);
        var s_hs = ks.deriveSecret(hs, "s hs traffic", hello_hash);
        defer std.crypto.secureZero(u8, &s_hs);
        defer std.crypto.secureZero(u8, &c_hs);
        try sink.writeSecret(.handshake, suite, &s_hs);
        // Over TCP, early data comes first (see `handleEndOfEarlyData`).
        if (!self.early_accepted or self.config.quic) try sink.readSecret(.handshake, suite, &c_hs);

        const creds = self.creds;
        var chain_len: usize = 0;
        for (creds.chain) |c| chain_len += 3 + c.len + 2;
        const flight_len = 64 + 300 + self.transport_params.len + chain_len + credentials.max_signature_len + record.max_hash_len;
        if (self.flight.len < flight_len) {
            const new = self.allocator.alloc(u8, flight_len) catch return error.InternalError;
            freeZeroed(self.allocator, self.flight);
            self.flight = new;
        }
        var w: Writer = .{ .buf = self.flight[0..flight_len] };

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
        if (self.config.quic) {
            w.int(u16, @backingInt(ExtensionType.quic_transport_parameters));
            w.int(u16, @intCast(self.transport_params.len));
            w.bytes(self.transport_params);
        }
        if (self.early_accepted) {
            w.int(u16, @backingInt(ExtensionType.early_data));
            w.int(u16, 0);
        }
        if (self.sni_matched and !self.resumed) {
            // RFC 6066 §3: the name chose the certificate.
            w.int(u16, @backingInt(ExtensionType.server_name));
            w.int(u16, 0);
        }
        w.end(u16, exts);
        w.endMessage(hdr);
        self.transcript.update(w.buf[start..w.pos]);

        // A resumed session is authenticated by the PSK.
        if (!self.resumed) try self.writeCertificate(&w, &hash_buf);

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
        @memcpy(self.master_secret[0..ks.hash_len], &master);
        const fin_hash = self.transcript.current(&hash_buf);
        var s_ap = ks.deriveSecret(master, "s ap traffic", fin_hash);
        defer std.crypto.secureZero(u8, &s_ap);
        const c_ap = ks.deriveSecret(master, "c ap traffic", fin_hash);
        @memcpy(self.client_app_secret[0..ks.hash_len], &c_ap);
        @memcpy(self.client_handshake_secret[0..ks.hash_len], &c_hs);
        self.expected_finished[0..ks.hash_len].* = ks.finishedVerifyData(c_hs, fin_hash);
        try sink.writeSecret(.application, suite, &s_ap);
    }

    /// Certificate and CertificateVerify.
    fn writeCertificate(self: *Self, w: *Writer, hash_buf: *[record.max_hash_len]u8) Error!void {
        const creds = self.creds;
        var start = w.pos;
        var hdr = w.beginMessage(.certificate);
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
        const cert_hash = self.transcript.current(hash_buf);
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
        if (self.config.tickets) |keys| try self.sendTicket(keys, sink);
        std.crypto.secureZero(u8, &self.master_secret);
        self.state = .done;
    }

    /// NewSessionTicket (§4.6.1): the resumption PSK, sealed in the ticket.
    fn sendTicket(self: *Self, keys: *const ticket.Keys, sink: anytype) !void {
        var hash_buf: [record.max_hash_len]u8 = undefined;
        const hash = self.transcript.current(&hash_buf);
        const nonce = [_]u8{0}; // one ticket per connection
        var state: ticket.State = .{
            .suite = @backingInt(self.suite),
            .issued = keys.now(),
            .age_add = std.mem.readInt(u32, self.entropy[entropy_ticket + 12 ..][0..4], .big),
            .quic = self.config.quic,
            .early = self.config.earlyData(),
            .instance = keys.instance,
            .alpn = self.alpnIndex(),
            .cert = self.creds_index,
            .psk_len = @intCast(self.suite.hashLen()),
            .psk = @splat(0),
        };
        defer std.crypto.secureZero(u8, &state.psk);
        switch (self.suite) {
            inline else => |s| {
                const ks = s.Schedule();
                var res = ks.deriveSecret(self.master_secret[0..ks.hash_len].*, "res master", hash);
                defer std.crypto.secureZero(u8, &res);
                state.psk[0..ks.hash_len].* = ks.resumptionPsk(res, &nonce);
            },
        }
        var sealed_buf: [ticket.max_len]u8 = undefined;
        const sealed = keys.seal(&state, self.entropy[entropy_ticket..][0..12].*, &sealed_buf);
        var buf: [32 + ticket.max_len]u8 = undefined;
        var w: Writer = .{ .buf = &buf };
        const hdr = w.beginMessage(.new_session_ticket);
        w.int(u32, keys.lifetime_s);
        w.int(u32, state.age_add);
        w.int(u8, nonce.len);
        w.bytes(&nonce);
        w.int(u16, @intCast(sealed.len));
        w.bytes(sealed);
        const exts = w.begin(u16);
        if (state.early) {
            // QUIC limits 0-RTT by flow control instead (RFC 9001 §4.6.1).
            w.int(u16, @backingInt(ExtensionType.early_data));
            w.int(u16, 4);
            w.int(u32, if (self.config.quic) 0xffffffff else self.config.max_early_data);
        }
        w.end(u16, exts);
        w.endMessage(hdr);
        try sink.handshakeData(.application, w.written());
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
        // The public key from a table, the shared secret from our ladder
        // (both equal std's).
        const public = x25519_base.publicKey(seed.*);
        const shared = x25519_base.sharedSecret(seed.*, client[0..32].*) catch return error.IllegalParameter;
        @memcpy(self.share_buf[self.share_len..][0..32], &public);
        self.share_len += 32;
        @memcpy(self.shared_buf[self.shared_len..][0..32], &shared);
        self.shared_len += 32;
    }

    fn run(self: *KeyExchange, share: KeyShare, entropy: *const [entropy_len]u8) Error!void {
        switch (share.group) {
            .x25519 => try self.x25519(share.key_exchange, entropy[32..64]),
            .secp256r1 => {
                // Our public key and the shared secret, in constant time
                // (both equal std's). Only the uncompressed form of a
                // point on the curve is accepted (RFC 8446 §4.2.8.2).
                var ks = p256_base.keyShare(entropy[64..96].*, share.key_exchange) catch |err| return switch (err) {
                    error.InvalidEncoding, error.NonCanonical => error.IllegalParameter,
                    error.IdentityElement => error.InternalError,
                };
                defer std.crypto.secureZero(u8, &ks.shared_secret);
                @memcpy(self.share_buf[0..ks.public_key.len], &ks.public_key);
                self.share_len = ks.public_key.len;
                @memcpy(self.shared_buf[0..ks.shared_secret.len], &ks.shared_secret);
                self.shared_len = ks.shared_secret.len;
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
    /// The host_name in server_name (RFC 6066 §3).
    server_name: ?[]const u8 = null,
    /// The quic_transport_parameters extension's contents.
    quic_transport_params: ?[]const u8 = null,
    /// The whole extensions block.
    extensions: []const u8 = "",
    tls13: bool = false,
    early_data: bool = false,
    psk: bool = false,
    psk_modes: bool = false,
    /// psk_dhe_ke offered (the only mode supported).
    psk_dhe: bool = false,
    /// The pre_shared_key extension's identities and binders vectors'
    /// contents, and where the binders vector starts in the body.
    psk_identities: []const u8 = "",
    psk_binders: []const u8 = "",
    binders_offset: usize = 0,

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
        hello.extensions = exts_data;

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
                .server_name => {
                    // ServerNameList: name_type, then a host_name; one of
                    // each type at most, others ignored.
                    var list: Reader = .{ .data = try e.vector(u16) };
                    if (list.data.len == 0) return error.DecodeError;
                    while (list.pos < list.data.len) {
                        const name_type = try list.int(u8);
                        const name = try list.vector(u16);
                        if (name_type != 0) continue;
                        if (name.len == 0 or hello.server_name != null) return error.IllegalParameter;
                        hello.server_name = name;
                    }
                },
                .quic_transport_parameters => {
                    hello.quic_transport_params = ext;
                    continue;
                },
                .psk_key_exchange_modes => {
                    const modes = try e.vector(u8);
                    if (modes.len == 0) return error.DecodeError;
                    hello.psk_modes = true;
                    hello.psk_dhe = std.mem.indexOfScalar(u8, modes, 1) != null;
                },
                .pre_shared_key => {
                    // Must be last (RFC 8446 §4.2.11).
                    if (exts.pos != exts_data.len) return error.IllegalParameter;
                    hello.psk = true;
                    hello.psk_identities = try e.vector(u16);
                    hello.binders_offset = body.len - exts_data.len + exts.pos - ext.len + e.pos;
                    hello.psk_binders = try e.vector(u16);
                    // As many binders (32-255 bytes) as identities.
                    var ids: Reader = .{ .data = hello.psk_identities };
                    var bs: Reader = .{ .data = hello.psk_binders };
                    if (ids.data.len == 0) return error.DecodeError;
                    while (ids.pos < ids.data.len) {
                        if ((try ids.vector(u16)).len == 0) return error.DecodeError;
                        _ = try ids.int(u32);
                        const b = try bs.vector(u8);
                        if (b.len < 32) return error.DecodeError;
                    }
                    if (bs.pos != bs.data.len) return error.IllegalParameter;
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

/// Expects a released state to hold nothing of its last handshake: every
/// byte zero but the allocator and the buffers' bookkeeping, the buffers'
/// whole capacity zero, and none larger than `keep`.
pub fn expectReleased(hs: *const Handshake, keep: usize) !void {
    const bytes = std.mem.asBytes(hs);
    for (bytes, 0..) |b, i| {
        const kept = inline for (.{ "allocator", "partial", "flight" }) |name| {
            const at = @offsetOf(Handshake, name);
            if (i >= at and i < at + @sizeOf(@FieldType(Handshake, name))) break true;
        } else false;
        if (!kept and b != 0) {
            std.debug.print("byte {d} of the released state is {x}\n", .{ i, b });
            return error.TestExpectedEqual;
        }
    }
    try std.testing.expectEqual(0, hs.partial.items.len);
    try std.testing.expect(std.mem.allEqual(u8, hs.partial.allocatedSlice(), 0));
    try std.testing.expect(std.mem.allEqual(u8, hs.flight, 0));
    try std.testing.expect(hs.partial.capacity <= keep);
    try std.testing.expect(hs.flight.len <= keep);
}

/// Counts frees of memory that wasn't zeroed first (std.testing.allocator
/// overwrites memory as it frees it, so it can't tell). Refuses to remap,
/// so a growing buffer is copied and its old memory freed here, seen.
const ZeroCheckingAllocator = struct {
    child: std.mem.Allocator,
    unzeroed_frees: usize = 0,

    fn allocator(self: *ZeroCheckingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *ZeroCheckingAllocator = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *ZeroCheckingAllocator = @ptrCast(@alignCast(ctx));
        if (new_len < memory.len and !std.mem.allEqual(u8, memory[new_len..], 0)) self.unzeroed_frees += 1;
        return self.child.rawResize(memory, alignment, new_len, ra);
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *ZeroCheckingAllocator = @ptrCast(@alignCast(ctx));
        if (!std.mem.allEqual(u8, memory, 0)) self.unzeroed_frees += 1;
        self.child.rawFree(memory, alignment, ra);
    }
};

test "buffers are zeroed before they are freed: growing, replaced, released" {
    const td = credentials.testdata;
    var p256 = try testCredentials();
    defer p256.deinit();
    var rsa = try Credentials.fromPem(std.testing.allocator, td.rsa2048_cert, td.rsa2048_key);
    defer rsa.deinit();
    const small: Config = .{ .credentials = &p256, .groups = &.{.x25519} };
    // A longer chain and signature: a larger flight than the first one.
    const large: Config = .{ .credentials = &rsa, .groups = &.{.x25519} };
    const entropy: [entropy_len]u8 = @splat(7);
    const x = X25519.recoverPublicKey(@splat(5));
    var buf: [24 * 1024]u8 = undefined;
    var extra_buf: [4 + 20000]u8 = @splat(0);
    std.mem.writeInt(u16, extra_buf[0..2], 21, .big);
    std.mem.writeInt(u16, extra_buf[2..4], 20000, .big);
    // Larger than the kept size, and fed in pieces so its buffer grows.
    const hello = buildClientHello(&buf, .{ .shares = &.{.{ .group = .x25519, .key_exchange = &x }}, .sig_algs = &.{ 0x0403, 0x0804 }, .extra = &extra_buf });
    var zc: ZeroCheckingAllocator = .{ .child = std.testing.allocator };
    var hs = Handshake.init(zc.allocator(), &small, &entropy);
    for ([_]*const Config{ &small, &large }) |config| {
        hs.reinit(config, &entropy);
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        var pos: usize = 0;
        while (pos < hello.len) : (pos += 700) try hs.feed(.initial, hello[pos..@min(pos + 700, hello.len)], &sink);
        try std.testing.expect(hs.flight.len > 0);
        if (config == &small) hs.release(16 * 1024);
    }
    hs.deinit();
    try std.testing.expectEqual(0, zc.unzeroed_frees);
}

/// Expects a reused state to start like a new one.
pub fn expectFresh(hs: *const Handshake, config: *const Config, entropy: *const [entropy_len]u8) !void {
    const t = std.testing;
    const fresh = Handshake.init(hs.allocator, config, entropy);
    try t.expectEqual(fresh.config, hs.config);
    try t.expectEqualSlices(u8, &fresh.entropy, &hs.entropy);
    try t.expectEqual(fresh.state, hs.state);
    try t.expectEqual(0, hs.partial.items.len);
    try t.expectEqual(fresh.retry_group, hs.retry_group);
    try t.expectEqual(fresh.session_id_len, hs.session_id_len);
    try t.expectEqual(fresh.sent_ccs, hs.sent_ccs);
    try t.expectEqual(fresh.alpn, hs.alpn);
    try t.expectEqual(fresh.creds_index, hs.creds_index);
    try t.expectEqual(fresh.sni_matched, hs.sni_matched);
    try t.expectEqual(fresh.transport_params.len, hs.transport_params.len);
    try t.expectEqual(fresh.early_data_offered, hs.early_data_offered);
    try t.expectEqual(fresh.early_accepted, hs.early_accepted);
    try t.expectEqual(fresh.resumed, hs.resumed);
    try t.expectEqual(fresh.psk_identity, hs.psk_identity);
}

test "release: nothing of the last handshake survives; big buffers are freed" {
    var creds = try testCredentials();
    defer creds.deinit();
    const config: Config = .{ .credentials = &creds, .groups = &.{.x25519} };
    const entropy: [entropy_len]u8 = @splat(7);
    const x = X25519.recoverPublicKey(@splat(5));
    var buf: [24 * 1024]u8 = undefined;
    // A padding extension (21) of `pad` bytes makes the ClientHello span
    // records: 0 keeps it small, 20000 makes it larger than the kept size.
    for ([_]usize{ 0, 20000 }) |pad| {
        var extra_buf: [4 + 20000]u8 = @splat(0);
        std.mem.writeInt(u16, extra_buf[0..2], 21, .big);
        std.mem.writeInt(u16, extra_buf[2..4], @intCast(pad), .big);
        const hello = buildClientHello(&buf, .{
            .shares = &.{.{ .group = .x25519, .key_exchange = &x }},
            .session_id = &@as([32]u8, @splat(0x33)),
            .extra = extra_buf[0 .. 4 + pad],
        });
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        for (0..2) |_| {
            var sink: TestSink = .{ .allocator = std.testing.allocator };
            defer sink.deinit();
            // In two pieces, so the reassembly buffer holds the message.
            try hs.feed(.initial, hello[0 .. hello.len / 2], &sink);
            try hs.feed(.initial, hello[hello.len / 2 ..], &sink);
            try std.testing.expect(hs.partial.capacity >= hello.len);
            try std.testing.expect(hs.flight.len > 0);
            hs.release(16 * 1024);
            try expectReleased(&hs, 16 * 1024);
            hs.reinit(&config, &entropy);
            try expectFresh(&hs, &config, &entropy);
        }
    }
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
    try expectHelloError(error.MissingExtension, buildClientHello(&buf, .{ .shares = share, .extra = "\x00\x29\x00\x2c\x00\x07\x00\x01x\x00\x00\x00\x00\x00\x21\x20" ++ @as([32]u8, @splat(0)) }), &config);
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

/// A padding extension of `n` zero bytes.
fn paddingExt(comptime n: u16) []const u8 {
    return &[_]u8{ 0, 21, n >> 8, n & 0xff } ++ @as([n]u8, @splat(0));
}

test "HelloRetryRequest: ClientHello2 may change only what RFC 8446 §4.1.2 lets it" {
    const td = credentials.testdata;
    var default = try testCredentials();
    defer default.deinit();
    var more = [_]Credentials{try .fromPem(std.testing.allocator, td.sni_a_cert, td.sni_a_key)};
    defer for (&more) |*c| c.deinit();
    const config: Config = .{ .credentials = &default, .sni_credentials = &more, .groups = &.{.x25519}, .alpn = &.{ "h2", "http/1.1" } };
    const entropy: [entropy_len]u8 = @splat(9);
    const x = X25519.recoverPublicKey(@splat(5));
    const share: []const KeyShare = &.{.{ .group = .x25519, .key_exchange = &x }};
    const sni = comptime sniExt("a.example");
    const modes = comptime pskModes(&.{1});
    const Hello = struct {
        extra: []const u8 = sni,
        groups: []const NamedGroup = &.{ .secp256r1, .x25519 },
        alpn: ?[]const u8 = "\x02h2",
        sig_algs: []const u16 = &.{0x0403},
        versions: []const u16 = &.{0x0304},
    };
    const cases = [_]struct { ch1: Hello = .{}, ch2: Hello, ok: bool }{
        .{ .ch2 = .{}, .ok = true },
        // Allowed: padding added, resized or removed; early_data removed.
        .{ .ch2 = .{ .extra = sni ++ comptime paddingExt(40) }, .ok = true },
        .{ .ch1 = .{ .extra = sni ++ comptime paddingExt(10) ++ &early_data_ext }, .ch2 = .{ .extra = sni ++ comptime paddingExt(300) }, .ok = true },
        .{ .ch1 = .{ .extra = sni ++ comptime paddingExt(10) }, .ch2 = .{}, .ok = true },
        // server_name dropped or changed: the certificate was chosen by
        // ClientHello1's.
        .{ .ch2 = .{ .extra = "" }, .ok = false },
        .{ .ch2 = .{ .extra = comptime sniExt("b.example") }, .ok = false },
        .{ .ch2 = .{ .alpn = "\x08http/1.1" }, .ok = false },
        .{ .ch2 = .{ .alpn = null }, .ok = false },
        .{ .ch2 = .{ .groups = &.{.x25519} }, .ok = false },
        .{ .ch2 = .{ .sig_algs = &.{ 0x0403, 0x0804 } }, .ok = false },
        .{ .ch2 = .{ .versions = &.{ 0x0304, 0x0303 } }, .ok = false },
        // Any other extension: added, or in another order.
        .{ .ch2 = .{ .extra = sni ++ modes }, .ok = false },
        .{ .ch1 = .{ .extra = sni ++ modes }, .ch2 = .{ .extra = modes ++ sni }, .ok = false },
    };
    var buf: [2048]u8 = undefined;
    for (cases) |case| {
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        // No key share: a HelloRetryRequest.
        const a = case.ch1;
        try hs.feed(.initial, buildClientHello(&buf, .{ .groups = a.groups, .alpn = a.alpn, .sig_algs = a.sig_algs, .versions = a.versions, .extra = a.extra }), &sink);
        try std.testing.expect(hs.isRetrying());
        const c = case.ch2;
        const ch2 = buildClientHello(&buf, .{ .groups = c.groups, .shares = share, .alpn = c.alpn, .sig_algs = c.sig_algs, .versions = c.versions, .extra = c.extra });
        if (case.ok) {
            try hs.feed(.initial, ch2, &sink);
            const facts = try flightFacts(&sink);
            try std.testing.expect(facts.sni_ack);
        } else {
            try std.testing.expectError(error.IllegalParameter, hs.feed(.initial, ch2, &sink));
        }
    }
    // A ticket's binders and age are recomputed in ClientHello2: see the
    // resumption tests with a HelloRetryRequest.
}

test "HelloRetryRequest over QUIC: a ClientHello2 without ClientHello1's ALPN is refused" {
    var creds = try testCredentials();
    defer creds.deinit();
    const config: Config = .{ .credentials = &creds, .groups = &.{.x25519}, .alpn = &.{"h3"}, .quic = true };
    const entropy: [entropy_len]u8 = @splat(9);
    var hs = Handshake.init(std.testing.allocator, &config, &entropy);
    defer hs.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();
    const tp = [_]u8{ 0, 57, 0, 3, 0x01, 0x01, 0x10 };
    var buf: [2048]u8 = undefined;
    try hs.feed(.initial, buildClientHello(&buf, .{ .alpn = "\x02h3", .extra = &tp }), &sink);
    try std.testing.expect(hs.isRetrying());
    const x = X25519.recoverPublicKey(@splat(5));
    const ch2 = buildClientHello(&buf, .{ .shares = &.{.{ .group = .x25519, .key_exchange = &x }}, .extra = &tp });
    try std.testing.expectError(error.IllegalParameter, hs.feed(.initial, ch2, &sink));
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

// -- Resumption ---------------------------------------------------------------

var resume_test_now: i64 = 5_000_000;

fn resumeTestClock() i64 {
    return resume_test_now;
}

/// psk_key_exchange_modes with the given modes.
fn pskModes(comptime modes: []const u8) []const u8 {
    return .{ 0x00, 0x2d, 0x00, modes.len + 1, modes.len } ++ modes;
}

/// The client side of a handshake over X25519, computed independently of
/// the server: checks the server's flight (certificate or not) and returns
/// the session ticket and its PSK.
fn RefClient(comptime suite: Suite) type {
    const ks = suite.Schedule();
    return struct {
        const Ticket = struct { identity: [ticket.max_len]u8, identity_len: usize, age_add: u32, psk: ks.Secret, max_early: ?u32 = null };

        kp: X25519.KeyPair,
        transcript: ks.Hash = ks.Hash.init(.{}),
        psk: ?ks.Secret = null,
        /// Sent in the same record as Finished: `finish` then checks the
        /// server fails on it, sending nothing, and returns FinishedRejected.
        after_finished: []const u8 = "",
        /// `finish` expects 0-RTT accepted: the early traffic secret first,
        /// and EndOfEarlyData before Finished.
        early: bool = false,

        fn init() @This() {
            return .{ .kp = X25519.KeyPair.generateDeterministic(@splat(21)) };
        }

        /// A ClientHello with `extra` extensions; with a ticket, the
        /// pre_shared_key extension (last) and its binder. `share` false
        /// sends no key share (a HelloRetryRequest follows).
        fn hello(c: *@This(), buf: []u8, extra: []const u8, t: ?*const Ticket, share: bool) []const u8 {
            var ext_buf: [1024]u8 = undefined;
            var w: Writer = .{ .buf = &ext_buf };
            w.bytes(extra);
            if (t) |tk| {
                w.int(u16, @backingInt(ExtensionType.pre_shared_key));
                const e = w.begin(u16);
                const ids = w.begin(u16);
                w.int(u16, @intCast(tk.identity_len));
                w.bytes(tk.identity[0..tk.identity_len]);
                w.int(u32, 1000 +% tk.age_add);
                w.end(u16, ids);
                w.int(u16, 1 + ks.hash_len);
                w.int(u8, ks.hash_len);
                w.bytes(&@as(ks.Secret, @splat(0)));
                w.end(u16, e);
            }
            const msg = buildClientHello(buf, .{
                .suites = &.{@backingInt(suite)},
                .shares = if (share) &.{.{ .group = .x25519, .key_exchange = &c.kp.public_key }} else &.{},
                .extra = w.written(),
            });
            if (t) |tk| {
                // The binder: over the transcript so far and this message
                // up to the binders.
                c.psk = tk.psk;
                const early = ks.earlySecretPsk(&tk.psk);
                const binder_key = ks.deriveSecret(early, "res binder", &ks.empty_hash);
                var th = c.transcript;
                th.update(msg[0 .. msg.len - 3 - ks.hash_len]);
                var h: ks.Secret = undefined;
                th.final(&h);
                @memcpy(@constCast(msg[msg.len - ks.hash_len ..]), &ks.finishedVerifyData(binder_key, &h));
            }
            return msg;
        }

        /// After a HelloRetryRequest: the transcript restarts with
        /// message_hash(ClientHello1) and the HelloRetryRequest.
        fn retried(c: *@This(), hello1: []const u8, hrr: []const u8) void {
            var h: ks.Secret = undefined;
            ks.Hash.hash(hello1, &h, .{});
            c.transcript = ks.Hash.init(.{});
            c.transcript.update(&.{ @backingInt(HandshakeType.message_hash), 0, 0, ks.hash_len });
            c.transcript.update(&h);
            c.transcript.update(hrr);
        }

        /// Runs the rest of the handshake from the server's events (from
        /// `first` on); `resumed` says whether the flight must skip the
        /// certificate. Returns the ticket the server sent afterwards.
        fn finish(c: *@This(), hs: *Handshake, sink: *TestSink, hello_msg: []const u8, first_event: usize, resumed: bool) !Ticket {
            const ev = sink.events.items;
            var first = first_event;
            try std.testing.expectEqual(c.early, hs.early_accepted);
            if (c.early) {
                // client_early_traffic_secret over the ClientHello.
                var th = c.transcript;
                th.update(hello_msg);
                var h: ks.Secret = undefined;
                th.final(&h);
                const c_e = ks.deriveSecret(ks.earlySecretPsk(&c.psk.?), "c e traffic", &h);
                const rs = ev[first].read_secret;
                try std.testing.expectEqual(Level.early, rs.level);
                try std.testing.expectEqualSlices(u8, &c_e, rs.secret);
                first += 1;
            }
            const sh = ev[first].data.bytes;
            var r: Reader = .{ .data = sh[4..] };
            _ = try r.take(2 + 32);
            _ = try r.vector(u8);
            try std.testing.expectEqual(@backingInt(suite), try r.int(u16));
            _ = try r.take(1);
            var exts: Reader = .{ .data = try r.vector(u16) };
            var server_share: []const u8 = "";
            var selected: ?u16 = null;
            while (exts.pos < exts.data.len) {
                const t = try exts.int(u16);
                var e: Reader = .{ .data = try exts.vector(u16) };
                if (t == @backingInt(ExtensionType.key_share)) {
                    _ = try e.int(u16);
                    server_share = try e.vector(u16);
                } else if (t == @backingInt(ExtensionType.pre_shared_key)) {
                    selected = try e.int(u16);
                }
            }
            try std.testing.expectEqual(if (resumed) @as(?u16, 0) else null, selected);
            const shared = try X25519.scalarmult(c.kp.secret_key, server_share[0..32].*);
            c.transcript.update(hello_msg);
            c.transcript.update(sh);
            var h: ks.Secret = undefined;
            var t2 = c.transcript;
            t2.final(&h);
            const early = if (resumed) ks.earlySecretPsk(&c.psk.?) else ks.earlySecret();
            const hs_secret = ks.handshakeSecret(early, &shared);
            const s_hs = ks.deriveSecret(hs_secret, "s hs traffic", &h);
            const c_hs = ks.deriveSecret(hs_secret, "c hs traffic", &h);
            try std.testing.expectEqualSlices(u8, &s_hs, ev[first + 1].write_secret.secret);
            // With 0-RTT the handshake read key waits for EndOfEarlyData.
            if (!c.early) try std.testing.expectEqualSlices(u8, &c_hs, ev[first + 2].read_secret.secret);
            // EncryptedExtensions (early_data if accepted), then the
            // certificate unless resumed.
            const flight = ev[first + @as(usize, if (c.early) 2 else 3)].data.bytes;
            var fr: Reader = .{ .data = flight };
            var types: [4]u8 = undefined;
            var n: usize = 0;
            while (fr.pos < flight.len) : (n += 1) {
                types[n] = (try fr.take(1))[0];
                const body = try fr.take(try fr.int(u24));
                if (types[n] != 8) continue;
                var er: Reader = .{ .data = body };
                var ee_exts: Reader = .{ .data = try er.vector(u16) };
                var early_ext = false;
                while (ee_exts.pos < ee_exts.data.len) {
                    const t = try ee_exts.int(u16);
                    const e = try ee_exts.vector(u16);
                    if (t == @backingInt(ExtensionType.early_data)) {
                        try std.testing.expectEqual(0, e.len);
                        early_ext = true;
                    }
                }
                try std.testing.expectEqual(c.early, early_ext);
            }
            const expect_types: []const u8 = if (resumed) &.{ 8, 20 } else &.{ 8, 11, 15, 20 };
            try std.testing.expectEqualSlices(u8, expect_types, types[0..n]);
            const fin_at = flight.len - 4 - ks.hash_len;
            c.transcript.update(flight[0..fin_at]);
            var t3 = c.transcript;
            t3.final(&h);
            try std.testing.expectEqualSlices(u8, &ks.finishedVerifyData(s_hs, &h), flight[fin_at + 4 ..]);
            c.transcript.update(flight[fin_at..]);
            if (c.early) {
                const eoed = [_]u8{ @backingInt(HandshakeType.end_of_early_data), 0, 0, 0 };
                const at = sink.events.items.len;
                try hs.feed(.early, &eoed, sink);
                const rs = sink.events.items[at].read_secret;
                try std.testing.expectEqual(Level.handshake, rs.level);
                try std.testing.expectEqualSlices(u8, &c_hs, rs.secret);
                c.transcript.update(&eoed);
            }
            var t4 = c.transcript;
            t4.final(&h);
            const master = ks.masterSecret(hs_secret);
            var fin: [4 + ks.hash_len]u8 = undefined;
            fin[0..4].* = .{ 0x14, 0, 0, ks.hash_len };
            fin[4..].* = ks.finishedVerifyData(c_hs, &h);
            const before = sink.events.items.len;
            if (c.after_finished.len > 0) {
                var rec: [4 + ks.hash_len + 64]u8 = undefined;
                @memcpy(rec[0..fin.len], &fin);
                @memcpy(rec[fin.len..][0..c.after_finished.len], c.after_finished);
                try std.testing.expectError(error.UnexpectedMessage, hs.feed(.handshake, rec[0 .. fin.len + c.after_finished.len], sink));
                try std.testing.expectEqual(before, sink.events.items.len);
                return error.FinishedRejected;
            }
            try hs.feed(.handshake, &fin, sink);
            try std.testing.expect(hs.isDone());
            c.transcript.update(&fin);
            c.transcript.final(&h);
            const res = ks.deriveSecret(master, "res master", &h);
            // read_secret(application), then the NewSessionTicket.
            const nst = sink.events.items[before + 1].data;
            try std.testing.expectEqual(Level.application, nst.level);
            var nr: Reader = .{ .data = nst.bytes };
            try std.testing.expectEqual(@backingInt(HandshakeType.new_session_ticket), (try nr.take(1))[0]);
            _ = try nr.take(3);
            try std.testing.expectEqual(@as(u32, 24 * 3600), try nr.int(u32));
            var out: Ticket = .{ .identity = undefined, .identity_len = 0, .age_add = try nr.int(u32), .psk = undefined };
            const nonce = try nr.vector(u8);
            const id = try nr.vector(u16);
            const nst_exts = try nr.vector(u16);
            if (nst_exts.len > 0) {
                // early_data, with max_early_data_size.
                try std.testing.expectEqual(8, nst_exts.len);
                try std.testing.expectEqual(@backingInt(ExtensionType.early_data), std.mem.readInt(u16, nst_exts[0..2], .big));
                try std.testing.expectEqual(4, std.mem.readInt(u16, nst_exts[2..4], .big));
                out.max_early = std.mem.readInt(u32, nst_exts[4..8], .big);
            }
            @memcpy(out.identity[0..id.len], id);
            out.identity_len = id.len;
            out.psk = ks.resumptionPsk(res, nonce);
            return out;
        }
    };
}

test "Finished sharing its record fails before keys or a ticket go out" {
    // RFC 8446 §5.1: a message before a key change must end its record.
    var creds = try testCredentials();
    defer creds.deinit();
    var keys = ticket.Keys.init(@splat(9));
    keys.now = resumeTestClock;
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    const C = RefClient(.aes_128_gcm_sha256);
    const config = resumeConfig(&creds, &keys, &.{.aes_128_gcm_sha256});
    // A KeyUpdate, or the first bytes of one.
    for ([_][]const u8{ &.{ 24, 0, 0, 1, 0 }, &.{24} }) |extra| {
        var buf: [4096]u8 = undefined;
        var c = C.init();
        c.after_finished = extra;
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        const hello1 = c.hello(&buf, pskModes(&.{1}), null, true);
        try hs.feed(.initial, hello1, &sink);
        try std.testing.expectError(error.FinishedRejected, c.finish(&hs, &sink, hello1, 0, false));
    }
}

fn resumeConfig(creds: *const Credentials, keys: *const ticket.Keys, suites: []const Suite) Config {
    return .{ .credentials = creds, .suites = suites, .groups = &.{.x25519}, .tickets = keys };
}

test "resumption: a ticket from a full handshake resumes, with or without a HelloRetryRequest" {
    var creds = try testCredentials();
    defer creds.deinit();
    var keys = ticket.Keys.init(@splat(9));
    keys.now = resumeTestClock;
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    inline for (.{ Suite.aes_128_gcm_sha256, Suite.aes_256_gcm_sha384 }) |suite| {
        const C = RefClient(suite);
        const config = resumeConfig(&creds, &keys, &.{suite});
        var buf: [4096]u8 = undefined;
        // Full handshake: a ticket.
        var c = C.init();
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        const hello1 = c.hello(&buf, pskModes(&.{1}), null, true);
        try hs.feed(.initial, hello1, &sink);
        const t1 = try c.finish(&hs, &sink, hello1, 0, false);

        // Resumed with it, and a new ticket that resumes too.
        var t = t1;
        for (0..2) |_| {
            var c2 = C.init();
            var hs2 = Handshake.init(std.testing.allocator, &config, &entropy);
            defer hs2.deinit();
            var sink2: TestSink = .{ .allocator = std.testing.allocator };
            defer sink2.deinit();
            const hello2 = c2.hello(&buf, pskModes(&.{ 0, 1 }), &t, true);
            try hs2.feed(.initial, hello2, &sink2);
            t = try c2.finish(&hs2, &sink2, hello2, 0, true);
        }

        // After a HelloRetryRequest (no key share at first): the binder
        // covers message_hash(ClientHello1) and the HelloRetryRequest.
        {
            var c3 = C.init();
            var hs3 = Handshake.init(std.testing.allocator, &config, &entropy);
            defer hs3.deinit();
            var sink3: TestSink = .{ .allocator = std.testing.allocator };
            defer sink3.deinit();
            var buf1: [4096]u8 = undefined;
            const ch1 = c3.hello(&buf1, pskModes(&.{1}), &t1, false);
            try hs3.feed(.initial, ch1, &sink3);
            try std.testing.expect(hs3.isRetrying());
            c3.retried(ch1, sink3.events.items[0].data.bytes);
            const ch2 = c3.hello(&buf, pskModes(&.{1}), &t1, true);
            try hs3.feed(.initial, ch2, &sink3);
            _ = try c3.finish(&hs3, &sink3, ch2, 1, true);
        }
    }
}

test "resumption: bad binders fail; unusable tickets get a full handshake" {
    var creds = try testCredentials();
    defer creds.deinit();
    var keys = ticket.Keys.init(@splat(9));
    keys.now = resumeTestClock;
    resume_test_now = 5_000_000;
    defer resume_test_now = 5_000_000;
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 17 +% 3);
    const C = RefClient(.aes_128_gcm_sha256);
    const config = resumeConfig(&creds, &keys, &.{.aes_128_gcm_sha256});
    var buf: [4096]u8 = undefined;
    var c = C.init();
    var hs = Handshake.init(std.testing.allocator, &config, &entropy);
    defer hs.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();
    const hello1 = c.hello(&buf, pskModes(&.{1}), null, true);
    try hs.feed(.initial, hello1, &sink);
    const t = try c.finish(&hs, &sink, hello1, 0, false);

    const Case = enum { bad_binder, psk_ke_only, other_keys, expired, sha384 };
    for ([_]Case{ .bad_binder, .psk_ke_only, .other_keys, .expired, .sha384 }) |case| {
        var cfg = config;
        var other = keys;
        other.master[0] ^= 1;
        var tk = t;
        switch (case) {
            .other_keys => cfg.tickets = &other,
            .expired => resume_test_now += 24 * 3600 + 1,
            .sha384 => cfg.suites = &.{.aes_256_gcm_sha384},
            else => {},
        }
        defer resume_test_now = 5_000_000;
        var c2 = C.init();
        var hs2 = Handshake.init(std.testing.allocator, &cfg, &entropy);
        defer hs2.deinit();
        var sink2: TestSink = .{ .allocator = std.testing.allocator };
        defer sink2.deinit();
        const modes = if (case == .psk_ke_only) pskModes(&.{0}) else pskModes(&.{1});
        var hello2: []const u8 = undefined;
        if (case == .sha384) {
            // A SHA-256 ticket offered in a SHA-384 handshake.
            const C384 = RefClient(.aes_256_gcm_sha384);
            var c384 = C384.init();
            var t384: C384.Ticket = .{ .identity = tk.identity, .identity_len = tk.identity_len, .age_add = tk.age_add, .psk = @splat(1) };
            hello2 = c384.hello(&buf, modes, &t384, true);
            try hs2.feed(.initial, hello2, &sink2);
            try std.testing.expect(!hs2.resumed);
            continue;
        }
        hello2 = c2.hello(&buf, modes, &tk, true);
        if (case == .bad_binder) {
            @constCast(hello2)[hello2.len - 1] ^= 1;
            try std.testing.expectError(error.DecryptError, hs2.feed(.initial, hello2, &sink2));
            continue;
        }
        try hs2.feed(.initial, hello2, &sink2);
        // A full handshake (the certificate is sent).
        c2.psk = null;
        _ = try c2.finish(&hs2, &sink2, hello2, 0, false);
        tk = undefined;
    }
}

/// The early_data extension, empty (in a ClientHello).
const early_data_ext = [_]u8{ 0, 42, 0, 0 };

/// A full handshake, then a ticket from it.
fn issueTicket(comptime suite: Suite, config: *const Config, entropy: *const [entropy_len]u8, extra: []const u8) !RefClient(suite).Ticket {
    var buf: [4096]u8 = undefined;
    var c = RefClient(suite).init();
    var hs = Handshake.init(std.testing.allocator, config, entropy);
    defer hs.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.deinit();
    const hello = c.hello(&buf, extra, null, true);
    try hs.feed(.initial, hello, &sink);
    return c.finish(&hs, &sink, hello, 0, false);
}

test "0-RTT: accepted once per ClientHello, with EndOfEarlyData before Finished" {
    var creds = try testCredentials();
    defer creds.deinit();
    var keys = ticket.Keys.init(@splat(9));
    keys.now = resumeTestClock;
    keys.instance = 77;
    var guard = try ticket.ReplayGuard.init(std.testing.allocator, 64);
    defer guard.deinit();
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    inline for (.{ Suite.aes_128_gcm_sha256, Suite.aes_256_gcm_sha384 }) |suite| {
        const C = RefClient(suite);
        var config = resumeConfig(&creds, &keys, &.{suite});
        config.max_early_data = 16384;
        config.replay = &guard;
        const t = try issueTicket(suite, &config, &entropy, pskModes(&.{1}));
        try std.testing.expectEqual(@as(?u32, 16384), t.max_early);

        var buf: [4096]u8 = undefined;
        var c = C.init();
        c.early = true;
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        const hello = c.hello(&buf, comptime pskModes(&.{1}) ++ early_data_ext, &t, true);
        try hs.feed(.initial, hello, &sink);
        const t2 = try c.finish(&hs, &sink, hello, 0, true);
        // A ticket from a resumed session allows 0-RTT too.
        try std.testing.expectEqual(@as(?u32, 16384), t2.max_early);

        // The same ClientHello again: resumed, without early data.
        var c2 = C.init();
        var hs2 = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs2.deinit();
        var sink2: TestSink = .{ .allocator = std.testing.allocator };
        defer sink2.deinit();
        c2.psk = c.psk;
        try hs2.feed(.initial, hello, &sink2);
        try std.testing.expect(hs2.resumed and hs2.early_data_offered and !hs2.early_accepted);
        _ = try c2.finish(&hs2, &sink2, hello, 0, true);
    }
}

test "0-RTT: refused unless this process issued the ticket for this suite and protocol, at about the age claimed" {
    var creds = try testCredentials();
    defer creds.deinit();
    var keys = ticket.Keys.init(@splat(9));
    keys.now = resumeTestClock;
    keys.instance = 77;
    resume_test_now = 5_000_000;
    defer resume_test_now = 5_000_000;
    var guard = try ticket.ReplayGuard.init(std.testing.allocator, 64);
    defer guard.deinit();
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    const suite = Suite.aes_128_gcm_sha256;
    const C = RefClient(suite);
    var config = resumeConfig(&creds, &keys, &.{ suite, .chacha20_poly1305_sha256 });
    config.alpn = &.{ "a", "b" };
    config.max_early_data = 16384;
    config.replay = &guard;
    const alpn_a = [_]u8{ 0, 16, 0, 4, 0, 2, 1, 'a' };
    const alpn_b = [_]u8{ 0, 16, 0, 4, 0, 2, 1, 'b' };
    const t = try issueTicket(suite, &config, &entropy, comptime pskModes(&.{1}) ++ alpn_a);
    var no_early = config;
    no_early.max_early_data = 0;
    const t_off = try issueTicket(suite, &no_early, &entropy, comptime pskModes(&.{1}) ++ alpn_a);
    try std.testing.expectEqual(@as(?u32, null), t_off.max_early);

    const Case = enum { off_at_issue, off_now, other_instance, other_alpn, other_suite, client_age_ahead, client_age_behind, ok };
    for (std.enums.values(Case)) |case| {
        var cfg = config;
        var other = keys;
        other.instance = 78;
        var tk = if (case == .off_at_issue) t_off else t;
        var extra: []const u8 = comptime pskModes(&.{1}) ++ early_data_ext ++ alpn_a;
        switch (case) {
            .off_now => cfg.max_early_data = 0,
            .other_instance => cfg.tickets = &other,
            .other_alpn => extra = comptime pskModes(&.{1}) ++ early_data_ext ++ alpn_b,
            .other_suite => cfg.suites = &.{.chacha20_poly1305_sha256},
            // The client says 1 s; ours is 1 + 11 s, or the client's is.
            .client_age_ahead => tk.age_add -%= 11_000,
            .client_age_behind => resume_test_now += 12,
            else => {},
        }
        defer resume_test_now = 5_000_000;
        var buf: [4096]u8 = undefined;
        var hs = Handshake.init(std.testing.allocator, &cfg, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        if (case == .other_suite) {
            // The ticket's hash, another suite: resumable, but not 0-RTT.
            const Cc = RefClient(.chacha20_poly1305_sha256);
            var cc = Cc.init();
            const tc: Cc.Ticket = .{ .identity = tk.identity, .identity_len = tk.identity_len, .age_add = tk.age_add, .psk = tk.psk };
            try hs.feed(.initial, cc.hello(&buf, extra, &tc, true), &sink);
        } else {
            var c = C.init();
            try hs.feed(.initial, c.hello(&buf, extra, &tk, true), &sink);
        }
        try std.testing.expect(hs.resumed and hs.early_data_offered);
        try std.testing.expectEqual(case == .ok, hs.early_accepted);
    }
}

test "0-RTT: EndOfEarlyData is the only handshake message under the early key" {
    var creds = try testCredentials();
    defer creds.deinit();
    var keys = ticket.Keys.init(@splat(9));
    keys.now = resumeTestClock;
    var guard = try ticket.ReplayGuard.init(std.testing.allocator, 64);
    defer guard.deinit();
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    const suite = Suite.aes_128_gcm_sha256;
    var config = resumeConfig(&creds, &keys, &.{suite});
    config.max_early_data = 100;
    config.replay = &guard;
    const t = try issueTicket(suite, &config, &entropy, pskModes(&.{1}));
    const fin = [_]u8{ 20, 0, 0, 32 } ++ @as([32]u8, @splat(0));
    const cases = [_]struct { level: Level, bytes: []const u8, err: anyerror }{
        .{ .level = .early, .bytes = &fin, .err = error.UnexpectedMessage },
        .{ .level = .early, .bytes = &.{ 5, 0, 0, 1, 0 }, .err = error.DecodeError },
        .{ .level = .early, .bytes = &.{ 5, 0, 0, 0, 20 }, .err = error.UnexpectedMessage },
        .{ .level = .handshake, .bytes = &.{ 5, 0, 0, 0 }, .err = error.UnexpectedMessage },
        .{ .level = .handshake, .bytes = &fin, .err = error.UnexpectedMessage },
    };
    for (cases, 0..) |case, i| {
        var buf: [4096]u8 = undefined;
        var c = RefClient(suite).init();
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        // A fresh binder each time (the guard admits each once).
        var tk = t;
        tk.age_add +%= @intCast(i);
        const hello = c.hello(&buf, comptime pskModes(&.{1}) ++ early_data_ext, &tk, true);
        try hs.feed(.initial, hello, &sink);
        try std.testing.expect(hs.early_accepted);
        try std.testing.expectError(case.err, hs.feed(case.level, case.bytes, &sink));
    }
}

/// A server_name extension for `host`.
fn sniExt(comptime host: []const u8) []const u8 {
    const n = host.len;
    return .{ 0, 0, 0, n + 5, 0, n + 3, 0, 0, n } ++ host;
}

/// The leaf certificate and whether EncryptedExtensions acknowledged
/// server_name, from the server's encrypted flight.
fn flightFacts(sink: *const TestSink) !struct { leaf: ?[]const u8, sni_ack: bool } {
    var leaf: ?[]const u8 = null;
    var ack = false;
    for (sink.events.items) |ev| {
        const d = switch (ev) {
            .data => |d| d,
            else => continue,
        };
        if (d.level != .handshake) continue;
        var r: Reader = .{ .data = d.bytes };
        while (r.pos < d.bytes.len) {
            const t = (try r.take(1))[0];
            const body = try r.take(try r.int(u24));
            var b: Reader = .{ .data = body };
            switch (t) {
                8 => {
                    var exts: Reader = .{ .data = try b.vector(u16) };
                    while (exts.pos < exts.data.len) {
                        const et = try exts.int(u16);
                        _ = try exts.vector(u16);
                        if (et == @backingInt(ExtensionType.server_name)) ack = true;
                    }
                },
                11 => {
                    _ = try b.vector(u8); // certificate_request_context
                    var list: Reader = .{ .data = try b.vector(u24) };
                    leaf = try list.vector(u24);
                },
                else => {},
            }
        }
    }
    return .{ .leaf = leaf, .sni_ack = ack };
}

test "SNI: the certificate whose names match, else the default; server_name acknowledged when it chose" {
    const td = credentials.testdata;
    var default = try testCredentials();
    defer default.deinit();
    var more = [_]Credentials{
        try .fromPem(std.testing.allocator, td.sni_a_cert, td.sni_a_key),
        try .fromPem(std.testing.allocator, td.sni_wild_cert, td.sni_wild_key),
    };
    defer for (&more) |*c| c.deinit();
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    const config: Config = .{ .credentials = &default, .sni_credentials = &more, .groups = &.{.x25519} };
    const cases = [_]struct { extra: []const u8, want: *const Credentials, ack: bool }{
        .{ .extra = comptime sniExt("a.example"), .want = &more[0], .ack = true },
        .{ .extra = comptime sniExt("A.EXAMPLE"), .want = &more[0], .ack = true },
        .{ .extra = comptime sniExt("www.b.example"), .want = &more[1], .ack = true },
        .{ .extra = comptime sniExt("b.example"), .want = &more[1], .ack = true },
        .{ .extra = comptime sniExt("localhost"), .want = &default, .ack = true },
        .{ .extra = comptime sniExt("x.www.b.example"), .want = &default, .ack = false },
        .{ .extra = "", .want = &default, .ack = false },
    };
    for (cases) |case| {
        var buf: [4096]u8 = undefined;
        var c = RefClient(.aes_128_gcm_sha256).init();
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        try hs.feed(.initial, c.hello(&buf, case.extra, null, true), &sink);
        const facts = try flightFacts(&sink);
        try std.testing.expectEqualSlices(u8, case.want.chain[0], facts.leaf.?);
        try std.testing.expectEqual(case.ack, facts.sni_ack);
    }
    // A malformed or doubled host_name.
    for ([_][]const u8{ &.{ 0, 0, 0, 2, 0, 0 }, &.{ 0, 0, 0, 5, 0, 3, 0, 0, 0 }, &.{ 0, 0, 0, 12, 0, 10, 0, 0, 2, 'a', 'b', 0, 0, 2, 'c', 'd' } }) |bad| {
        var buf: [4096]u8 = undefined;
        var c = RefClient(.aes_128_gcm_sha256).init();
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        try std.testing.expect(std.meta.isError(hs.feed(.initial, c.hello(&buf, bad, null, true), &sink)));
    }
}

test "SNI: a ticket resumes only for a name that selects the same certificate" {
    const td = credentials.testdata;
    var default = try testCredentials();
    defer default.deinit();
    var more = [_]Credentials{
        try .fromPem(std.testing.allocator, td.sni_a_cert, td.sni_a_key),
        try .fromPem(std.testing.allocator, td.sni_wild_cert, td.sni_wild_key),
    };
    defer for (&more) |*c| c.deinit();
    var keys = ticket.Keys.init(@splat(9));
    keys.now = resumeTestClock;
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    const suite = Suite.aes_128_gcm_sha256;
    var config = resumeConfig(&default, &keys, &.{suite});
    config.sni_credentials = &more;
    const t = try issueTicket(suite, &config, &entropy, comptime pskModes(&.{1}) ++ sniExt("www.b.example"));
    const cases = [_]struct { extra: []const u8, resumed: bool }{
        .{ .extra = comptime pskModes(&.{1}) ++ sniExt("other.b.example"), .resumed = true },
        .{ .extra = comptime pskModes(&.{1}) ++ sniExt("a.example"), .resumed = false },
        .{ .extra = comptime pskModes(&.{1}) ++ sniExt("localhost"), .resumed = false },
        .{ .extra = comptime pskModes(&.{1}), .resumed = false },
    };
    for (cases) |case| {
        var buf: [4096]u8 = undefined;
        var c = RefClient(suite).init();
        var hs = Handshake.init(std.testing.allocator, &config, &entropy);
        defer hs.deinit();
        var sink: TestSink = .{ .allocator = std.testing.allocator };
        defer sink.deinit();
        try hs.feed(.initial, c.hello(&buf, case.extra, &t, true), &sink);
        try std.testing.expectEqual(case.resumed, hs.resumed);
        // No acknowledgement on a resumed handshake.
        try std.testing.expectEqual(!case.resumed and case.extra.len > 6, (try flightFacts(&sink)).sni_ack);
    }
}
