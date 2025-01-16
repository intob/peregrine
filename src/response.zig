const std = @import("std");
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

/// This response is reused.
/// The reset method is called by the worker, so library users do not need to think about it.
/// IMPORTANT:
/// If a field is added, it MUST be reset by the reset() method.
pub const Response = struct {
    const Self = @This();
    const VERSION = "HTTP/1.1 ";

    status: Status align(64) = .ok,
    headers: [32]Header align(64) = undefined,
    headers_len: usize align(64) = 0,
    body: []align(64) u8,
    body_len: usize align(64) = 0,
    is_ws_upgrade: bool align(64) = false,
    status_buf: []align(64) u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, body_size: usize) !*Self {
        const next_pow2 = try std.math.ceilPowerOfTwo(usize, body_size);
        const aligned = std.mem.alignForward(usize, next_pow2, 64);
        const resp = try allocator.create(Self);
        const status_size = try resp.calcStatusBufferSize();
        resp.* = .{
            .allocator = allocator,
            .body = try allocator.alignedAlloc(u8, 64, aligned),
            .status_buf = try allocator.alignedAlloc(u8, 64, status_size),
        };
        @memcpy(resp.status_buf[0..VERSION.len], VERSION);
        return resp;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.body);
        self.allocator.free(self.status_buf);
        self.allocator.destroy(self);
    }

    pub fn addHeader(self: *Self, header: Header) !void {
        if (self.headers_len >= self.headers.len) {
            return error.HeadersFull;
        }
        self.headers[self.headers_len] = header;
        self.headers_len += 1;
    }

    pub fn addNewHeader(self: *Self, comptime key: []const u8, value: []const u8) !void {
        if (self.headers_len >= self.headers.len) {
            return error.HeadersFull;
        }
        self.headers[self.headers_len] = try Header.init(key, value);
        self.headers_len += 1;
    }

    pub fn serialiseStatusAndHeaders(self: *Self) !usize {
        var n: usize = VERSION.len;
        const status = self.status.toString();
        @memcpy(self.status_buf[n .. n + status.len], status);
        n += status.len;
        self.status_buf[n] = '\r';
        self.status_buf[n + 1] = '\n';
        n += 2;
        var i: usize = 0;
        while (i < self.headers_len) : (i += 1) {
            const key = self.headers[i].key();
            @memcpy(self.status_buf[n .. n + key.len], key);
            n += key.len;
            self.status_buf[n] = ':';
            self.status_buf[n + 1] = ' ';
            n += 2;
            const val = self.headers[i].value();
            @memcpy(self.status_buf[n .. n + val.len], val);
            n += val.len;
            self.status_buf[n] = '\r';
            self.status_buf[n + 1] = '\n';
            n += 2;
        }
        return n;
    }

    pub fn setBody(self: *Self, buf: []const u8) !usize {
        if (buf.len > self.body.len) {
            std.debug.print("buf len: {d}, resp body len: {d}\n", .{ buf.len, self.body.len });
            return error.ResponseBodyBufferTooSmall;
        }
        @memcpy(self.body[0..buf.len], buf);
        self.body_len = buf.len;
        return buf.len;
    }

    /// This is called automatically before Handler.handle.
    /// The response is reused so that no allocations are required per request.
    /// All fields must be reset to prevent exposing stale data.
    pub inline fn reset(self: *Self) void {
        self.status = Status.ok;
        self.headers_len = 0;
        self.is_ws_upgrade = false;
    }

    fn calcStatusBufferSize(self: *Self) !usize {
        const headers_size = (65 + 256 + 4) * self.headers.len;
        const resp_buf_size = headers_size + "HTTP/1.1 500 Internal Server Error\r\n".len;
        return std.mem.alignForward(usize, resp_buf_size, 16);
    }
};

test "serialise" {
    var r = try Response.init(std.testing.allocator, 1024);
    defer r.deinit();
    r.headers[0] = try Header.init("Content-Type", "total/rubbish");
    r.headers[1] = try Header.init("Content-Length", "0");
    r.headers_len = 2;
    const n = try r.serialiseStatusAndHeaders();
    const expected = "HTTP/1.1 200 OK\r\nContent-Type: total/rubbish\r\nContent-Length: 0\r\n";
    try std.testing.expectEqualStrings(expected, r.status_buf[0..n]);
    try std.testing.expectEqual(expected.len, n);
}

test "benchmark serialisation" {
    const allocator = std.testing.allocator;
    var resp = try Response.init(allocator, 1024);
    defer resp.deinit();
    resp.headers[0] = try Header.init("Content-Type", "total/rubbish");
    resp.headers[1] = try Header.init("Content-Length", "11");
    resp.headers[2] = try Header.init("Etag", "32456756753456");
    resp.headers[3] = try Header.init("Some-Other", "HJFLAEKGJELIUO");
    resp.headers_len = 4;
    const iterations: usize = 100_000_000;
    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const size = try resp.serialiseStatusAndHeaders();
        std.mem.doNotOptimizeAway(size);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average serialization time: {d}ns\n", .{avg_ns});
}

test "benchmark add new header" {
    const allocator = std.testing.allocator;
    var resp = try Response.init(allocator, 1024);
    defer resp.deinit();
    const iterations: usize = 10_000_000;
    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        inline for (0..resp.headers.len) |_| {
            try resp.addNewHeader("key", "value");
        }
        resp.headers_len = 0;
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}
