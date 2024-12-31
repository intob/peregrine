const std = @import("std");
const posix = std.posix;
const Frame = @import("./frame.zig").Frame;

pub const WebsocketReader = struct {
    allocator: std.mem.Allocator,
    buffer: []align(16) u8,
    pos: usize = 0,
    len: usize = 0,

    const Self = @This();
    const MIN_FRAME_SIZE = 2;

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize) !*Self {
        const reader = try allocator.create(Self);
        reader.* = .{
            .allocator = allocator,
            .buffer = try allocator.alignedAlloc(u8, 16, buffer_size),
        };
        return reader;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.buffer);
        self.allocator.destroy(self);
    }

    pub fn readFrame(self: *Self, fd: posix.socket_t, f: *Frame) !void {
        self.pos = 0;
        self.len = 0;
        try self.ensureBytes(fd, MIN_FRAME_SIZE);
        const first_byte = self.buffer[self.pos];
        const second_byte = self.buffer[self.pos + 1];
        self.pos += 2;
        f.fin = (first_byte & 0x80) == 0x80;
        f.opcode = @truncate(first_byte & 0x0F);
        f.mask = (second_byte & 0x80) == 0x80;
        f.payload_len = switch (second_byte & 0x7F) {
            126 => try self.readU16(fd),
            127 => try self.readU64(fd),
            else => |len| len,
        };
        if (f.mask) {
            try self.ensureBytes(fd, 4);
            f.masking_key = .{
                self.buffer[self.pos],
                self.buffer[self.pos + 1],
                self.buffer[self.pos + 2],
                self.buffer[self.pos + 3],
            };
            self.pos += 4;
        }
        try self.ensureBytes(fd, f.payload_len);
        if (f.payload_len > f.payload.len) {
            return error.PayloadLargerThanBuffer;
        }
        errdefer self.allocator.free(f.payload);
        @memcpy(f.payload[0..f.payload_len], self.buffer[self.pos..][0..f.payload_len]);
        if (f.mask) {
            const mask = f.masking_key.?;
            for (0..f.payload_len) |i| {
                f.payload[i] = f.payload[i] ^ mask[i & 3];
            }
        }
    }

    fn ensureBytes(self: *Self, fd: posix.socket_t, needed: usize) !void {
        while (self.len - self.pos < needed) {
            if (self.pos > (self.buffer.len / 2)) {
                std.mem.copyForwards(u8, self.buffer[0..], self.buffer[self.pos..self.len]);
                self.len -= self.pos;
                self.pos = 0;
            }
            const n = try posix.read(fd, self.buffer[self.len..]);
            if (n == 0) return error.EOF;
            self.len += n;
        }
    }

    fn readU16(self: *Self, fd: posix.socket_t) !u16 {
        try self.ensureBytes(fd, 2);
        const result = std.mem.readInt(u16, self.buffer[self.pos..][0..2], .big);
        self.pos += 2;
        return result;
    }

    fn readU64(self: *Self, fd: posix.socket_t) !u64 {
        try self.ensureBytes(fd, 8);
        const result = std.mem.readInt(u64, self.buffer[self.pos..][0..8], .big);
        self.pos += 8;
        return result;
    }
};
