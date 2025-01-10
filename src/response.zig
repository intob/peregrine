const std = @import("std");
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

const VERSION = "HTTP/1.1 ";

/// This response is reused.
/// The reset method is called by the worker, so library users do not need to think about it.
/// IMPORTANT:
/// If a field is added, it MUST be reset by the reset() method.
pub const Response = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    status: Status = .ok,
    headers: [32]Header = undefined,
    headers_len: usize = 0,
    body: []align(64) u8,
    body_len: usize = 0,
    is_ws_upgrade: bool = false,

    pub fn init(allocator: std.mem.Allocator, body_size: usize) !*Self {
        const next_pow2 = try std.math.ceilPowerOfTwo(usize, body_size);
        const aligned = std.mem.alignForward(usize, next_pow2, 64);
        const resp = try allocator.create(Self);
        resp.* = .{
            .allocator = allocator,
            .body = try allocator.alignedAlloc(u8, 64, aligned),
        };
        return resp;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.body);
        self.allocator.destroy(self);
    }

    pub fn addHeader(self: *Self, header: Header) !void {
        if (self.headers_len >= self.headers.len) {
            return error.HeadersFull;
        }
        self.headers[self.headers_len] = header;
        self.headers_len += 1;
    }

    // Benchmarks show that duplicating addHeader is 10% faster than inlining it,
    // not sure why.
    pub fn addNewHeader(self: *Self, comptime key: []const u8, value: []const u8) !void {
        if (self.headers_len >= self.headers.len) {
            return error.HeadersFull;
        }
        self.headers[self.headers_len] = try Header.init(key, value);
        self.headers_len += 1;
    }

    pub fn serialiseStatusAndHeaders(self: *Self, buf: []u8) !usize {
        var n: usize = 0;
        @memcpy(buf[n .. n + VERSION.len], VERSION);
        n += VERSION.len;
        const status = self.status.toString();
        @memcpy(buf[n .. n + status.len], status);
        n += status.len;
        buf[n] = '\r';
        buf[n + 1] = '\n';
        n += 2;
        var i: usize = 0;
        while (i < self.headers_len) : (i += 1) {
            const key = self.headers[i].key();
            @memcpy(buf[n .. n + key.len], key);
            n += key.len;
            buf[n] = ':';
            buf[n + 1] = ' ';
            n += 2;
            const value = self.headers[i].value();
            @memcpy(buf[n .. n + value.len], value);
            n += value.len;
            buf[n] = '\r';
            buf[n + 1] = '\n';
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
        self.body_len = 0;
        self.is_ws_upgrade = false;
    }
};

test "serialise" {
    var allocator = std.testing.allocator;
    var r = try Response.init(allocator, 1024);
    defer r.deinit();
    r.headers[0] = try Header.init("Content-Type", "total/rubbish");
    r.headers[1] = try Header.init("Content-Length", "0");
    r.headers_len = 2;
    var buf = try allocator.alloc(u8, 128);
    defer allocator.free(buf);
    const n = try r.serialiseHeaders(&buf);
    const expected = "HTTP/1.1 200 OK\r\nContent-Type: total/rubbish\r\nContent-Length: 0\r\n";
    try std.testing.expectEqualStrings(expected, buf[0..n]);
    try std.testing.expectEqual(expected.len, n);
}

test "benchmark serialise" {
    const allocator = std.testing.allocator;
    var resp = try Response.init(allocator, 1024);
    defer resp.deinit();
    resp.headers[0] = try Header.init("Content-Type", "total/rubbish");
    resp.headers[1] = try Header.init("Content-Length", "11");
    resp.headers[2] = try Header.init("Etag", "32456756753456");
    resp.headers[3] = try Header.init("Some-Other", "HJFLAEKGJELIUO");
    resp.headers_len = 4;
    var buffer = try allocator.alloc(u8, 1024);
    defer allocator.free(buffer);
    const iterations: usize = 100_000_000;
    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const size = try resp.serialiseHeaders(&buffer);
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
