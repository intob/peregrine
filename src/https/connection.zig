const std = @import("std");
const parser = @import("./parser.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const hkdf = std.crypto.kdf.hkdf;
const hkdf_expand = @import("./hkdf_expand.zig");

pub const ConnectionState = enum {
    @"01_ClientHello",
    @"02_WaitClientFinished",
    @"03_Connected",
};

pub const ServerKey = union(enum) {
    ecdhe: std.crypto.dh.X25519.KeyPair,
    psk: struct { // Pre-Shared Key
        identity: []const u8,
        key: []const u8,
    },
    hybrid: struct { // Post-quantum
        ecdhe: [32]u8,
        kyber: [768]u8,
    },
    none: void, // No key exchange data
};

const HashKeys = union(enum) {
    SHA256: struct {
        traffic_secret: [32]u8,
        handshake_key: [32]u8,

        pub fn getAes128Key(self: @This()) [16]u8 {
            var key: [16]u8 = undefined;
            @memcpy(&key, self.handshake_key[0..16]);
            return key;
        }
    },
    SHA384: struct {
        traffic_secret: [48]u8,
        handshake_key: [48]u8,

        pub fn getAes256Key(self: @This()) [32]u8 {
            var key: [32]u8 = undefined;
            @memcpy(&key, self.handshake_key[0..32]);
            return key;
        }
    },
};

const Hash = enum { SHA256, SHA384 };

pub const Connection = struct {
    allocator: std.mem.Allocator,
    state: ConnectionState,
    requests: u16,
    client_random: [32]u8,
    legacy_session_id: ?[32]u8,
    server_key: ServerKey,
    cipher_suite: parser.CipherSuite,
    hash: Hash,
    client_key_share: parser.KeyShare,
    handshake_to_digest: std.ArrayList(u8),
    shared_secret: std.ArrayList(u8),
    client_hash_keys: HashKeys,
    client_handshake_iv: [12]u8,
    server_hash_keys: HashKeys,
    server_handshake_iv: [12]u8,

    pub fn init(self: *Connection, allocator: std.mem.Allocator) void {
        self.allocator = allocator;
        self.state = .@"01_ClientHello";
        self.server_key = .{ .none = {} };
        self.handshake_to_digest = std.ArrayList(u8).init(allocator);
        self.shared_secret = std.ArrayList(u8).init(allocator);
    }

    pub fn deinit(self: *Connection) void {
        self.handshake_to_digest.deinit();
        self.shared_secret.deinit();
    }

    pub fn reset(self: *Connection) void {
        self.state = .@"01_ClientHello";
        self.requests = 0;
        self.server_key = .{ .none = {} };
        self.handshake_to_digest.clearAndFree();
        self.shared_secret.clearAndFree();
    }

    pub fn generateKey(self: *Connection) !void {
        switch (self.client_key_share.group) {
            .x25519 => {
                self.server_key = .{ .ecdhe = std.crypto.dh.X25519.KeyPair.generate() };
            },
            else => return error.UnsupportedGroup,
        }
    }

    pub fn deriveKeys(self: *Connection) !void {
        switch (self.client_key_share.group) {
            .x25519 => try self.deriveX25519SharedSecret(),
            else => return error.KeyTypeNotImplemented,
        }
        switch (self.hash) {
            .SHA256 => {
                var hello_digest: [32]u8 = undefined;
                Sha256.hash(self.handshake_to_digest.items, &hello_digest, .{});
                try self.deriveHashSecrets(hkdf.HkdfSha256, 32, &hello_digest, getEmptyHash(Sha256));
            },
            .SHA384 => {
                var hello_digest: [48]u8 = undefined;
                Sha384.hash(self.handshake_to_digest.items, &hello_digest, .{});
                const HkdfSha384 = hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
                try self.deriveHashSecrets(HkdfSha384, 48, &hello_digest, getEmptyHash(Sha384));
            },
        }
    }

    fn deriveX25519SharedSecret(self: *Connection) !void {
        var client_key: [32]u8 = undefined;
        @memcpy(client_key[0..], self.client_key_share.key_exchange[0..]);
        const shared_secret = try std.crypto.dh.X25519.scalarmult(self.server_key.ecdhe.secret_key, client_key);
        try self.shared_secret.appendSlice(shared_secret[0..]);
    }

    fn deriveHashSecrets(
        self: *Connection,
        comptime HkdfType: type,
        comptime hash_len: usize,
        hello_digest: []const u8,
        empty_hash: [hash_len]u8,
    ) !void {
        const zeros = [_]u8{0} ** hash_len;
        const early_secret = HkdfType.extract(&[_]u8{0x00}, &zeros);
        var derived_secret: [hash_len]u8 = undefined;
        hkdf_expand.hkdfExpandLabel(HkdfType, hash_len, &derived_secret, early_secret, "derived", &empty_hash);
        const handshake_secret = HkdfType.extract(derived_secret[0..], self.shared_secret.items);
        var server_traffic_secret: [hash_len]u8 = undefined;
        hkdf_expand.hkdfExpandLabel(HkdfType, hash_len, &server_traffic_secret, handshake_secret, "s hs traffic", hello_digest);
        const server_keys = deriveTrafficKeys(HkdfType, hash_len, server_traffic_secret);
        self.server_handshake_iv = server_keys.iv;
        var client_traffic_secret: [hash_len]u8 = undefined;
        hkdf_expand.hkdfExpandLabel(HkdfType, hash_len, &client_traffic_secret, handshake_secret, "c hs traffic", hello_digest);
        const client_keys = deriveTrafficKeys(HkdfType, hash_len, client_traffic_secret);
        self.client_handshake_iv = client_keys.iv;
        switch (hash_len) {
            32 => {
                self.server_hash_keys = .{
                    .SHA256 = .{
                        .traffic_secret = server_traffic_secret,
                        .handshake_key = server_keys.key,
                    },
                };
                self.client_hash_keys = .{
                    .SHA256 = .{
                        .traffic_secret = client_traffic_secret,
                        .handshake_key = client_keys.key,
                    },
                };
            },
            48 => {
                self.server_hash_keys = .{
                    .SHA384 = .{
                        .traffic_secret = server_traffic_secret,
                        .handshake_key = server_keys.key,
                    },
                };
                self.client_hash_keys = .{
                    .SHA384 = .{
                        .traffic_secret = client_traffic_secret,
                        .handshake_key = client_keys.key,
                    },
                };
            },
            else => error.UnsupportedHashLen,
        }
    }
};

fn getEmptyHash(comptime T: type) [T.digest_length]u8 {
    return comptime blk: {
        @setEvalBranchQuota(10000);
        var hash: [T.digest_length]u8 = undefined;
        var hasher = T.init(.{});
        hasher.final(&hash);
        break :blk hash;
    };
}

fn deriveTrafficKeys(
    comptime HkdfType: type,
    comptime hash_len: usize,
    traffic_secret: [hash_len]u8,
) struct { key: [hash_len]u8, iv: [12]u8 } {
    var key: [hash_len]u8 = undefined;
    var iv: [12]u8 = undefined;
    hkdf_expand.hkdfExpandLabel(HkdfType, hash_len, &key, traffic_secret, "key", "");
    hkdf_expand.hkdfExpandLabel(HkdfType, 12, &iv, traffic_secret, "iv", "");
    return .{ .key = key, .iv = iv };
}
