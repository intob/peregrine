const std = @import("std");
const parser = @import("./parser.zig");

pub const ConnectionState = enum {
    @"01_ClientHello",
    @"02_",
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
        handshake_iv: [12]u8,
    },
    SHA384: struct {
        traffic_secret: [48]u8,
        handshake_key: [48]u8,
        handshake_iv: [12]u8,
    },
};

const Hash = enum {
    SHA256,
    SHA384,
};

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
    server_hash_keys: HashKeys,

    pub fn init(self: *Connection, allocator: std.mem.Allocator) void {
        self.allocator = allocator;
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
        self.handshake_to_digest.clearRetainingCapacity();
        self.shared_secret.clearRetainingCapacity();
    }

    pub fn generateKey(self: *Connection, group: parser.CryptoGroup) !void {
        switch (group) {
            .x25519 => {
                self.server_key = .{ .ecdhe = std.crypto.dh.X25519.KeyPair.generate() };
            },
            else => return error.UnsupportedGroup,
        }
    }
};
