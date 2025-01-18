const std = @import("std");
const posix = std.posix;
const Request = @import("../request.zig").Request;
const Header = @import("../header.zig").Header;
const Method = @import("../method.zig").Method;
const Version = @import("../version.zig").Version;

pub const TLSReader = struct {
    const Self = @This();

    buf: []align(64) u8,
    pos: usize align(64) = 0, // Current position in buffer
    len: usize align(64) = 0, // Amount of valid data in buffer
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize) !*Self {
        const next_pow2 = try std.math.ceilPowerOfTwo(usize, buffer_size);
        const aligned = std.mem.alignForward(usize, next_pow2, 64);
        const reader = try allocator.create(Self);
        reader.* = .{
            .allocator = allocator,
            .buf = try allocator.alignedAlloc(u8, 64, aligned),
        };
        return reader;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.buf);
        self.allocator.destroy(self);
    }

    pub inline fn reset(self: *Self) void {
        self.pos = 0;
        self.len = 0;
    }

    pub fn read(self: *Self, fd: posix.socket_t, want: usize) ![]const u8 {
        if (self.len - self.pos < want) {
            const n = try posix.read(fd, self.buf[self.pos..]);
            if (n == 0) return error.EOF;
            self.len += n;
            if (self.len - self.pos < want) {
                return error.NotEnoughRead;
            }
        }
        defer self.pos += want;
        return self.buf[self.pos .. self.pos + want];
    }
};
