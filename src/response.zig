const std = @import("std");
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

const VERSION = "HTTP/1.0 ";

pub const Response = struct {
    allocator: std.mem.Allocator,
    status: Status,
    headers: std.ArrayList(Header),
    body: ?[]const u8 = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const resp = try allocator.create(Self);
        resp.* = .{
            .allocator = allocator,
            .status = Status.ok,
            .headers = std.ArrayList(Header).init(allocator),
        };
        return resp;
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.allocator.destroy(self);
    }

    pub fn serialise(self: *Self, bufRef: *[]u8) !usize {
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
            inline for ([_][]const u8{ h.key, ": ", h.value, "\n" }) |part| {
                @memcpy(buf[n .. n + part.len], part);
                n += part.len;
            }
        }
        // New line
        buf[n] = '\n';
        n += 1;
        // Body
        if (self.body) |body| {
            @memcpy(buf[n .. n + body.len], body);
            n += body.len;
        }
        return n;
    }
};

test "serialise without body" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const r = try Response.init(allocator);
    try r.*.headers.append(Header{ .key = "Content-Type", .value = "total/rubbish" });
    try r.*.headers.append(Header{ .key = "Content-Length", .value = "0" });

    var buf = try allocator.alloc(u8, 128);
    const n = try r.serialise(&buf);

    const expected = "HTTP/1.0 200 OK\nContent-Type: total/rubbish\nContent-Length: 0\n\n";

    try std.testing.expectEqualStrings(expected, buf[0..n]);
}

test "serialise with body" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const r = try Response.init(allocator);
    r.*.body = "test response";
    try r.*.headers.append(Header{ .key = "Content-Type", .value = "total/rubbish" });
    try r.*.headers.append(Header{ .key = "Content-Length", .value = "13" });

    var buf = try allocator.alloc(u8, 128);
    const n = try r.serialise(&buf);

    const expected = "HTTP/1.0 200 OK\nContent-Type: total/rubbish\nContent-Length: 13\n\ntest response";

    try std.testing.expectEqualStrings(expected, buf[0..n]);
}

test "benchmark serialise" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    try benchmark(allocator);
}

fn benchmark(allocator: std.mem.Allocator) !void {
    var resp = try Response.init(allocator);
    defer resp.deinit();
    resp.*.body = "Hello world";
    try resp.*.headers.append(Header{ .key = "Content-Type", .value = "total/rubbish" });
    try resp.*.headers.append(Header{ .key = "Content-Length", .value = "11" });
    try resp.*.headers.append(Header{ .key = "Etag", .value = "32456756753456" });

    var buffer = try allocator.alloc(u8, 1024);
    defer allocator.free(buffer);

    // Ensure the result isn't optimized away
    var timer = try std.time.Timer.start();
    const iterations: usize = 100_000_000;

    var total_size: usize = 0;
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const size = try resp.serialise(&buffer);
        std.mem.doNotOptimizeAway(size);
        total_size += size;
    }

    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);

    std.debug.print("Average serialization time: {d}ns\n", .{avg_ns});
    std.debug.print("Average message size: {d} bytes\n", .{@divFloor(total_size, iterations)});
}
