const std = @import("std");

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,

    pub fn fromByte(byte: u8) ?Opcode {
        return std.meta.intToEnum(Opcode, @as(u4, @truncate(byte))) catch null;
    }

    pub fn toString(self: Opcode) []const u8 {
        return switch (self) {
            .continuation => "continuation",
            .text => "text",
            .binary => "binary",
            .close => "close",
            .ping => "ping",
            .pong => "pong",
            _ => "unknown",
        };
    }
};

pub const Frame = struct {
    allocator: std.mem.Allocator,
    fin: bool,
    opcode: Opcode,
    mask: bool,
    payload_len: usize,
    masking_key: ?[4]u8,
    payload: []align(16) u8,

    pub fn init(allocator: std.mem.Allocator, payload_size: usize) !*@This() {
        const self = try allocator.create(@This());
        const aligned_payload_size = std.mem.alignForward(usize, payload_size, 16);
        self.allocator = allocator;
        self.payload = try allocator.alignedAlloc(u8, 16, aligned_payload_size);
        return self;
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.payload);
        self.allocator.destroy(self);
    }

    pub fn getPayload(self: *@This()) []const u8 {
        return self.payload[0..self.payload_len];
    }
};
