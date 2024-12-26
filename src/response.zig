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
        var buf = bufRef.*;
        var n: usize = 0;
        // Explicitly unroll loop, as compiler doesn't.
        // Benchmarks show that it's significantly faster.
        inline for ([_][]const u8{ VERSION, self.status.toString(), "\n" }) |part| {
            @memcpy(buf[n .. n + part.len], part);
            n += part.len;
        }
        // Headers
        for (self.headers.items) |h| {
            // Explicitly unroll loop, as compiler doesn't.
            // Benchmarks show that it's significantly faster.
            inline for ([_][]const u8{ h.key(), ": ", h.value(), "\n" }) |part| {
                @memcpy(buf[n .. n + part.len], part);
                n += part.len;
            }
        }
        // New line
        buf[n] = '\n';
        return n + 1;
    }

    pub fn setBody(self: *Self, buf: []const u8) !void {
        if (buf.len > self.body.len) {
            return error.ResponseBodyBufferTooSmall;
        }
        @memcpy(self.body[0..buf.len], buf);
        self.body_len = buf.len;
    }

    /// Prevent the response from being sent by the worker.
    /// This allows a library user to take complete control of the
    /// response. This could be useful for some specific performance-critical
    /// scenarios.
    /// Note: The worker uses Vectored IO to write the headers and body
    /// simultaneously. If you don't reimplement that, you could actually lose
    /// performance.
    pub fn hijack(self: *Self) void {
        self.hijacked = true;
    }

    /// This is called automatically before on_request.
    /// The response is reused so that no allocations are required per request.
    /// All fields must be reset to prevent leaks across responses.
    pub fn reset(self: *Self) void {
        self.status = Status.ok;
        self.headers.clearRetainingCapacity();
        self.body_len = 0;
        self.hijacked = false;
    }
};

test "serialise without body" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var r = try Response.init(allocator, 1024);
    try r.headers.append(try Header.init(.{ .key = "Content-Type", .value = "total/rubbish" }));
    try r.headers.append(try Header.init(.{ .key = "Content-Length", .value = "0" }));

    var buf = try allocator.alloc(u8, 128);
    const n = try r.serialiseHeaders(&buf);

    const expected = "HTTP/1.0 200 OK\nContent-Type: total/rubbish\nContent-Length: 0\n\n";

    try std.testing.expectEqualStrings(expected, buf[0..n]);
}

test "serialise with body" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var r = try Response.init(allocator, 1024);
    try r.headers.append(try Header.init(.{ .key = "Content-Type", .value = "total/rubbish" }));
    try r.headers.append(try Header.init(.{ .key = "Content-Length", .value = "13" }));

    var buf = try allocator.alloc(u8, 128);
    const len_headers = try r.serialiseHeaders(&buf);

    const body = "test response";
    @memcpy(buf[len_headers .. len_headers + body.len], body);

    const expected = "HTTP/1.0 200 OK\nContent-Type: total/rubbish\nContent-Length: 13\n\ntest response";

    try std.testing.expectEqualStrings(expected, buf[0 .. len_headers + body.len]);
}

test "benchmark serialise" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    try benchmark(allocator);
}

fn benchmark(allocator: std.mem.Allocator) !void {
    var resp = try Response.init(allocator, 1024);
    defer resp.deinit();
    try resp.headers.append(Header{ .key = "Content-Type", .value = "total/rubbish" });
    try resp.headers.append(Header{ .key = "Content-Length", .value = "11" });
    try resp.headers.append(Header{ .key = "Etag", .value = "32456756753456" });

    var buffer = try allocator.alloc(u8, 1024);
    defer allocator.free(buffer);

    // Ensure the result isn't optimized away
    var timer = try std.time.Timer.start();
    const iterations: usize = 100_000_000;

    var total_size: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const size = try resp.serialiseHeaders(&buffer);
        std.mem.doNotOptimizeAway(size);
        total_size += size;
    }

    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);

    std.debug.print("Average serialization time: {d}ns\n", .{avg_ns});
    std.debug.print("Average message size: {d} bytes\n", .{@divFloor(total_size, iterations)});
}
