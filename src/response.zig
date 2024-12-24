const std = @import("std");
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

const VERSION = "HTTP/1.0";

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
        // Version and status
        var n: usize = 0;
        for ([_][]const u8{ VERSION, " ", self.status.toString(), "\n" }) |part| {
            @memcpy(buf[n .. n + part.len], part);
            n += part.len;
        }

        // Headers
        for (self.headers.items) |h| {
            for ([_][]const u8{ h.key, ": ", h.value, "\n" }) |part| {
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

    const r = try Response.init(allocator, Status.ok);
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

    const r = try Response.init(allocator, Status.ok);
    r.*.body = "test response";
    try r.*.headers.append(Header{ .key = "Content-Type", .value = "total/rubbish" });
    try r.*.headers.append(Header{ .key = "Content-Length", .value = "13" });

    var buf = try allocator.alloc(u8, 128);
    const n = try r.serialise(&buf);

    const expected = "HTTP/1.0 200 OK\nContent-Type: total/rubbish\nContent-Length: 13\n\ntest response";

    try std.testing.expectEqualStrings(expected, buf[0..n]);
}
