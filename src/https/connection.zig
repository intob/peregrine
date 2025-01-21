const std = @import("std");
const parser = @import("./parser.zig");

pub const ConnectionState = enum {
    @"01_ClientHello",
    @"02_",
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    state: ConnectionState,
    requests: u16,
    client_random: [32]u8,
    supported_groups: std.ArrayList(parser.CryptoGroup),

    pub fn init(self: *Connection, allocator: std.mem.Allocator) void {
        self.allocator = allocator;
        self.supported_groups = std.ArrayList(parser.CryptoGroup).init(allocator);
    }

    pub fn deinit(self: *Connection) void {
        self.supported_groups.deinit();
    }

    pub fn reset(self: *Connection) void {
        self.state = .@"01_ClientHello";
        self.requests = 0;
        self.supported_groups.clearRetainingCapacity();
    }
};
