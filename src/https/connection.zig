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

pub const Connection = struct {
    allocator: std.mem.Allocator,
    state: ConnectionState,
    requests: u16,
    client_random: [32]u8,
    server_key: ServerKey,

    pub fn init(self: *Connection, allocator: std.mem.Allocator) void {
        self.allocator = allocator;
        self.server_key = .{ .none = {} };
    }

    pub fn deinit(_: *Connection) void {}

    pub fn reset(self: *Connection) void {
        self.state = .@"01_ClientHello";
        self.requests = 0;
        self.server_key = .{ .none = {} };
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
