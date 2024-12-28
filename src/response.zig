const std = @import("std");
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

const VERSION = "HTTP/1.1 ";

/// This response is reused.
/// The reset method is called by the worker, so library users do not need to think about it.
/// IMPORTANT:
/// If a field is added, it MUST be reset by the reset() method.
pub const Response = struct {
    allocator: std.mem.Allocator,
    status: Status,
    headers: std.ArrayList(Header),
    body: []align(16) u8,
    body_len: usize,
    hijacked: bool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, body_size: usize) !*Self {
        const resp = try allocator.create(Self);
        resp.* = .{
            .allocator = allocator,
            .status = Status.ok,
            .headers = std.ArrayList(Header).init(allocator),
            .body = try allocator.alignedAlloc(u8, 16, std.mem.alignForward(usize, body_size, 16)),
            .body_len = 0,
            .hijacked = false,
        };
        return resp;
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.allocator.free(self.body);
        self.allocator.destroy(self);
    }

    pub fn serialiseHeaders(self: *Self, bufRef: *[]u8) !usize {
        @setRuntimeSafety(false);
        var buf = bufRef.*;
        var n: usize = 0;
        @memcpy(buf[n .. n + VERSION.len], VERSION);
        n += VERSION.len;
        const status = self.status.toString();
        @memcpy(buf[n .. n + status.len], status);
        n += status.len;
        buf[n] = '\r';
        buf[n + 1] = '\n';
        n += 2;
        for (self.headers.items) |h| {
            const key = h.key();
            @memcpy(buf[n .. n + key.len], key);
            n += key.len;
            buf[n] = ':';
            buf[n + 1] = ' ';
            n += 2;
            const value = h.value();
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

    /// Prevent the response from being sent by the worker.
    /// This allows a library user to take complete control of the response.
    /// This could be useful for some specific performance-critical scenarios.
    /// If this is called, the caller becomes responsible for closing the socket.
    pub fn hijack(self: *Self) void {
        self.hijacked = true;
    }

    /// This is called automatically before Handler.handle.
    /// The response is reused so that no allocations are required per request.
    /// All fields must be reset to prevent exposing stale data.
    pub fn reset(self: *Self) void {
        self.status = Status.ok;
        self.headers.clearRetainingCapacity();
        self.body_len = 0;
        self.hijacked = false;
    }
};

test "serialise" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var r = try Response.init(allocator, 1024);
    try r.headers.append(try Header.init(.{ .key = "Content-Type", .value = "total/rubbish" }));
    try r.headers.append(try Header.init(.{ .key = "Content-Length", .value = "0" }));

    var buf = try allocator.alloc(u8, 128);
    const n = try r.serialiseHeaders(&buf);

    const expected = "HTTP/1.1 200 OK\r\nContent-Type: total/rubbish\r\nContent-Length: 0\r\n";

    try std.testing.expectEqualStrings(expected, buf[0..n]);
    try std.testing.expectEqual(expected.len, n);
}

test "benchmark serialise" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    try benchmark(allocator);
}

fn benchmark(allocator: std.mem.Allocator) !void {
    var resp = try Response.init(allocator, 1024);
    defer resp.deinit();
    try resp.headers.append(try Header.init(.{ .key = "Content-Type", .value = "total/rubbish" }));
    try resp.headers.append(try Header.init(.{ .key = "Content-Length", .value = "11" }));
    try resp.headers.append(try Header.init(.{ .key = "Etag", .value = "32456756753456" }));
    var buffer = try allocator.alloc(u8, 1024);
    defer allocator.free(buffer);
    const iterations: usize = 10_000_000;
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
