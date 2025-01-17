const std = @import("std");
const posix = std.posix;

pub const TLSAdapter = struct {
    const Self = @This();

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    pub fn read(_: *Self, fd: posix.socket_t, buf: []u8) !usize {
        return posix.read(fd, buf);
    }
};
