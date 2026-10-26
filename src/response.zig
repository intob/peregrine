const std = @import("std");
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

/// This response is reused for every request on a worker. The server resets
/// it before calling handleRequest.
///
/// Headers are serialised as they are added, so their values are copied and
/// may be freed as soon as addHeader returns. The server adds Content-Length,
/// Date and Connection itself.
pub const Response = struct {
    const Self = @This();

    status: Status = .ok,
    /// Close the connection after this response is sent.
    close: bool = false,
    is_ws_upgrade: bool = false,
    /// Serialised "key: value\r\n" lines.
    header_buf: []u8,
    header_len: usize = 0,
    /// The body to send. Set it with setBody (copies) or setBodyBorrowed.
    body: []const u8 = "",
    body_buf: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, body_size: usize, header_size: usize) !*Self {
        const resp = try allocator.create(Self);
        errdefer allocator.destroy(resp);
        const body_buf = try allocator.alloc(u8, body_size);
        errdefer allocator.free(body_buf);
        resp.* = .{
            .allocator = allocator,
            .body_buf = body_buf,
            .header_buf = try allocator.alloc(u8, header_size),
        };
        return resp;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.body_buf);
        self.allocator.free(self.header_buf);
        self.allocator.destroy(self);
    }

    /// Add a header. Prefer addNewHeader, which rejects server-managed
    /// headers at compile time.
    pub fn addHeader(self: *Self, header: Header) !void {
        // Reject CR/LF to prevent response splitting.
        if (std.mem.indexOfAny(u8, header.key, "\r\n:") != null or header.key.len == 0) {
            return error.InvalidHeader;
        }
        if (std.mem.indexOfAny(u8, header.value, "\r\n") != null) return error.InvalidHeader;
        const needed = header.key.len + 2 + header.value.len + 2;
        if (self.header_len + needed > self.header_buf.len) return error.HeadersFull;
        var buf = self.header_buf[self.header_len..];
        @memcpy(buf[0..header.key.len], header.key);
        buf = buf[header.key.len..];
        buf[0..2].* = ": ".*;
        @memcpy(buf[2..][0..header.value.len], header.value);
        buf[2 + header.value.len ..][0..2].* = "\r\n".*;
        self.header_len += needed;
    }

    pub fn addNewHeader(self: *Self, comptime key: []const u8, value: []const u8) !void {
        try self.addHeader(Header.init(key, value));
    }

    /// Copies `buf` into the worker's response buffer.
    pub fn setBody(self: *Self, buf: []const u8) !usize {
        if (buf.len > self.body_buf.len) {
            return error.ResponseBodyBufferTooSmall;
        }
        @memcpy(self.body_buf[0..buf.len], buf);
        self.body = self.body_buf[0..buf.len];
        return buf.len;
    }

    /// Sends `buf` without copying it. It must stay valid and unchanged until
    /// the response is sent, which happens before this worker calls
    /// handleRequest again. Use it for static or cached content.
    pub fn setBodyBorrowed(self: *Self, buf: []const u8) void {
        self.body = buf;
    }

    /// Returns a slice of the response buffer to write a body into directly.
    /// Call commitBody with the number of bytes written.
    pub fn bodyWriteBuffer(self: *Self) []u8 {
        return self.body_buf;
    }

    pub fn commitBody(self: *Self, len: usize) void {
        self.body = self.body_buf[0..len];
    }

    pub fn headerBytes(self: *const Self) []const u8 {
        return self.header_buf[0..self.header_len];
    }

    pub inline fn reset(self: *Self) void {
        self.status = .ok;
        self.close = false;
        self.is_ws_upgrade = false;
        self.header_len = 0;
        self.body = "";
    }
};

test "headers are serialised on add" {
    var r = try Response.init(std.testing.allocator, 16, 128);
    defer r.deinit();
    try r.addNewHeader("Content-Type", "text/plain");
    try r.addNewHeader("X-A", "b");
    try std.testing.expectEqualStrings("Content-Type: text/plain\r\nX-A: b\r\n", r.headerBytes());
}

test "header injection is rejected" {
    var r = try Response.init(std.testing.allocator, 16, 128);
    defer r.deinit();
    try std.testing.expectError(error.InvalidHeader, r.addNewHeader("X", "a\r\nSet-Cookie: x"));
    try std.testing.expectError(error.InvalidHeader, r.addHeader(.{ .key = "X\r\n", .value = "a" }));
}

test "header buffer overflow" {
    var r = try Response.init(std.testing.allocator, 16, 8);
    defer r.deinit();
    try std.testing.expectError(error.HeadersFull, r.addNewHeader("Key", "value"));
}
