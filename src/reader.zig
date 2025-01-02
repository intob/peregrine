const std = @import("std");
const posix = std.posix;
const Request = @import("./request.zig").Request;
const Header = @import("./header.zig").Header;
const Method = @import("./method.zig").Method;
const Version = @import("./version.zig").Version;

pub const RequestReader = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    buf: []align(16) u8,
    pos: usize = 0, // Current position in buffer
    len: usize = 0, // Amount of valid data in buffer
    start: usize = 0, // Start of unprocessed data
    compact_threshold: usize = 0,

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize) !*Self {
        const next_pow2 = try std.math.ceilPowerOfTwo(usize, buffer_size);
        const aligned = std.mem.alignForward(usize, next_pow2, 16);
        const reader = try allocator.create(Self);
        reader.* = .{
            .allocator = allocator,
            .buf = try allocator.alignedAlloc(u8, 16, aligned),
            .compact_threshold = (aligned * 3) / 4,
        };
        return reader;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.buf);
        self.allocator.destroy(self);
    }

    pub fn readRequest(self: *Self, fd: posix.socket_t, req: *Request) !void {
        try self.parseRequestLine(fd, req);
        try self.parseHeaders(fd, req);
    }

    inline fn parseRequestLine(self: *Self, fd: posix.socket_t, req: *Request) !void {
        const n = try self.readLine(fd);
        if (n < "GET / HTTP/1.1".len) return error.InvalidRequest;
        // Go back by 2 to account for line ending
        const line = self.buf[self.start - n - 2 .. self.start - 2];
        // Parse method and version first
        req.method = try Method.parse(line[0..8]);
        const version_start = n - 8;
        req.version = try Version.parse(line[version_start..]);
        // Path and query is everything between method and version
        const path_start = req.method.toLength() + 1;
        const path_and_query = line[path_start .. version_start - 1];
        if (std.mem.indexOfScalar(u8, path_and_query, '?')) |query_start| {
            req.query_raw_len = path_and_query.len - (query_start + 1);
            @memcpy(req.query_raw[0..req.query_raw_len], path_and_query[query_start + 1 ..]);
            req.path_len = query_start;
            @memcpy(req.path[0..query_start], path_and_query[0..query_start]);
        } else {
            req.query_raw_len = 0;
            req.path_len = path_and_query.len;
            @memcpy(req.path[0..req.path_len], path_and_query);
        }
    }

    inline fn parseHeaders(self: *Self, fd: posix.socket_t, req: *Request) !void {
        while (true) {
            const n = try self.readLine(fd);
            if (n == 0) break;
            if (n < "a: b".len) return error.InvalidHeader;
            if (req.headers_len >= req.headers.len) return error.TooManyHeaders;
            const raw = self.buf[self.start - n - 2 .. self.start - 2];
            req.headers[req.headers_len] = try Header.parse(raw);
            req.headers_len += 1;
        }
    }

    fn readLine(self: *Self, fd: posix.socket_t) !usize {
        var line_len: usize = 0;
        const Vector = @Vector(16, u8);
        const newline: Vector = @splat(@as(u8, '\n'));
        if (self.pos >= self.len) {
            const available = self.buf.len - self.len;
            if (available == 0) return error.LineTooLong;

            const read_amount = try posix.readv(fd, &[_]posix.iovec{
                .{ .base = @ptrCast(&self.buf[self.len]), .len = available },
            });
            if (read_amount == 0) return line_len;
            self.len += read_amount;
        }
        while (self.pos + 16 <= self.len) {
            const chunk = self.buf[self.pos..][0..16];
            const vec: Vector = @as(Vector, chunk.*);
            const matches = vec == newline;
            const mask = @as(u16, @bitCast(matches));

            if (mask != 0) {
                const offset = @ctz(mask);
                line_len += offset - 1;
                self.pos += offset + 1;
                self.start = self.pos;
                return line_len;
            }
            self.pos += 16;
            line_len += 16;
            if (self.pos > self.compact_threshold) {
                self.compact();
            }
        }
        const remaining = self.len - self.pos;
        if (remaining > 0) {
            if (indexOf(self.buf[self.pos..self.len], '\n')) |offset| {
                line_len += offset - 1;
                self.pos += offset + 1;
                self.start = self.pos;
                return line_len;
            }
            self.pos += remaining;
            line_len += remaining;
        }
        return line_len;
    }

    inline fn compact(self: *Self) void {
        if (self.start == 0) return;
        const len = self.len - self.start;
        std.mem.copyForwards(u8, self.buf[0..len], self.buf[self.start..self.len]);
        self.len = len;
        self.pos -= self.start;
        self.start = 0;
    }
};

// Explicitly not scalar because we're searching through less than 16 bytes
inline fn indexOf(haystack: []const u8, needle: u8) ?usize {
    var i: usize = 0;
    while (i < haystack.len) : (i += 1) {
        if (haystack[i] == needle) return i;
    }
    return null;
}

test "test parse GET request" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    var reader = try RequestReader.init(std.testing.allocator, 4096);
    defer reader.deinit();
    const request_data =
        "GET /path/to/resource HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "User-Agent: test-client\r\n" ++
        "Accept: */*\r\n" ++
        "Connection: keep-alive\r\n\r\n";
    @memcpy(reader.buf[0..request_data.len], request_data);
    reader.pos = 0;
    reader.start = 0;
    reader.len = request_data.len;
    req.reset();
    try reader.readRequest(0, req);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/path/to/resource", req.getPath());
    try std.testing.expectEqual(Version.@"HTTP/1.1", req.version);
    try std.testing.expectEqual(4, req.headers_len);
    try std.testing.expectEqualStrings("Host", req.headers[0].key());
    try std.testing.expectEqualStrings("example.com", req.headers[0].value());
    try std.testing.expectEqualStrings("User-Agent", req.headers[1].key());
    try std.testing.expectEqualStrings("test-client", req.headers[1].value());
    try std.testing.expectEqualStrings("Accept", req.headers[2].key());
    try std.testing.expectEqualStrings("*/*", req.headers[2].value());
    try std.testing.expectEqualStrings("Connection", req.headers[3].key());
    try std.testing.expectEqualStrings("keep-alive", req.headers[3].value());
}

test "benchmark read line" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    var reader = try RequestReader.init(std.testing.allocator, 1024);
    defer reader.deinit();
    const raw = "Header-1: header-1-value\r\nHeader-2: header-2-value";
    const iterations: usize = 100_000_000;
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    @memcpy(reader.buf[0..raw.len], raw);
    while (i < iterations) : (i += 1) {
        reader.pos = 0;
        reader.start = 0;
        reader.len = raw.len;
        _ = try reader.readLine(0);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

test "benchmark read and parse headers" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    var reader = try RequestReader.init(std.testing.allocator, 1024);
    defer reader.deinit();
    const raw = "Header-1: header-1-value\r\nHeader-2: header-2-value\r\nHeader-3: header-3-value\r\n\r\n";
    const iterations: usize = 10_000_000;
    var i: usize = 0;
    @memcpy(reader.buf[0..raw.len], raw);
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        reader.pos = 0;
        reader.start = 0;
        reader.len = raw.len;
        req.reset();
        try reader.parseHeaders(0, req);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

test "benchmark parse GET request" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    var reader = try RequestReader.init(std.testing.allocator, 4096);
    defer reader.deinit();
    const request_data =
        "GET /path/to/resource HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "User-Agent: test-client\r\n" ++
        "Accept: */*\r\n" ++
        "Connection: keep-alive\r\n\r\n";
    @memcpy(reader.buf[0..request_data.len], request_data);
    const iterations: usize = 50_000_000;
    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        reader.pos = 0;
        reader.start = 0;
        reader.len = request_data.len;
        req.reset();
        try reader.readRequest(0, req);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average request parse time: {d}ns\n", .{avg_ns});
}
