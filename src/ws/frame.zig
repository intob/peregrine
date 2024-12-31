const std = @import("std");

pub const Frame = struct {
    allocator: std.mem.Allocator,
    fin: bool,
    opcode: u4,
    mask: bool,
    payload_len: usize,
    masking_key: ?[4]u8,
    payload: []align(16) u8,

    pub fn init(allocator: std.mem.Allocator, payload_size: usize) !*@This() {
        const self = try allocator.create(@This());
        self.allocator = allocator;
        self.payload = try allocator.alignedAlloc(u8, 16, payload_size);
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
