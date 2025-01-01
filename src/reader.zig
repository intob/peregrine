const std = @import("std");
const posix = std.posix;
const Request = @import("./request.zig").Request;
const Header = @import("./header.zig").Header;
const Method = @import("./method.zig").Method;
const Version = @import("./version.zig").Version;
const alignment = @import("./alignment.zig");

pub const RequestReader = struct {
    allocator: std.mem.Allocator,
    buffer: []align(16) u8,
    pos: usize = 0, // Current position in buffer
    len: usize = 0, // Amount of valid data in buffer
    start: usize = 0, // Start of unprocessed data

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize) !*Self {
        const aligned = std.mem.alignForward(usize, alignment.nextPowerOf2(buffer_size), 16);
        const reader = try allocator.create(Self);
        reader.* = .{
            .allocator = allocator,
            .buffer = try allocator.alignedAlloc(u8, 16, aligned),
        };
        return reader;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.buffer);
        self.allocator.destroy(self);
    }

    pub fn readRequest(self: *Self, fd: posix.socket_t, req: *Request) !void {
        const n = try self.readLine(fd);
        if (n == 0) return error.EOF;
        if (n < 14) return error.InvalidRequest; // GET / HTTP/1.1\n
        try parseRequestLine(req, self.buffer[self.start - n .. self.start]);
        try self.readHeaders(fd, req);
    }

    pub fn readHeaders(self: *Self, fd: posix.socket_t, req: *Request) !void {
        while (true) {
            const n = try self.readLine(fd);
            if (n < 2) return error.UnexpectedEOF;
            // Check for empty line (header section terminator)
            if (n == 2 and self.buffer[self.start - 2] == '\r' and self.buffer[self.start - 1] == '\n') {
                break; // End of headers
            }
            if (n == 1 and self.buffer[self.start - 1] == '\n') {
                break; // Handle bare LF (lenient parsing)
            }
            if (req.headers_len >= req.headers.len) {
                return error.TooManyHeaders;
            }
            const line_end_len: usize = if (self.buffer[self.start - 2] == '\r' and self.buffer[self.start - 1] == '\n') 2 else 1;
            req.headers[req.headers_len] = try Header.parse(self.buffer[self.start - n .. self.start - line_end_len]);
            req.headers_len += 1;
        }
    }

    pub inline fn reset(self: *Self) void {
        self.pos = 0;
        self.len = 0;
        self.start = 0;
    }

    pub fn readLine(self: *Self, fd: posix.socket_t) !usize {
        var line_len: usize = 0;
        const Vector = @Vector(16, u8);
        const newline: Vector = @splat(@as(u8, '\n'));

        // Prefetch data if buffer is empty
        if (self.pos >= self.len) {
            const available = self.buffer.len - self.len;
            if (available == 0) return error.LineTooLong;

            // Read larger chunks to reduce system calls
            const read_amount = try posix.readv(fd, &[_]posix.iovec{
                .{ .base = @ptrCast(&self.buffer[self.len]), .len = available },
            });
            if (read_amount == 0) return line_len;
            self.len += read_amount;
        }

        // Process aligned chunks using SIMD
        while (self.pos + 16 <= self.len) {
            // Direct vector load without memcpy
            const vec: Vector = @as(Vector, self.buffer[self.pos..][0..16].*);
            const matches = vec == newline;
            const mask = @as(u16, @bitCast(matches));

            if (mask != 0) {
                const offset = @ctz(mask);
                self.pos += offset + 1;
                self.start = self.pos;
                return line_len + offset + 1;
            }

            self.pos += 16;
            line_len += 16;

            // Compact only when necessary
            if (self.pos > (self.buffer.len * 3) / 4) {
                self.compact();
            }
        }

        // Optimize remaining bytes handling
        const remaining = self.len - self.pos;
        if (remaining > 0) {
            if (std.mem.indexOfScalar(u8, self.buffer[self.pos..self.len], '\n')) |offset| {
                self.pos += offset + 1;
                self.start = self.pos;
                return line_len + offset + 1;
            }
            self.pos += remaining;
            line_len += remaining;
        }

        return line_len;
    }

    inline fn compact(self: *Self) void {
        if (self.start == 0) return;
        const len = self.len - self.start;
        std.mem.copyForwards(u8, self.buffer[0..len], self.buffer[self.start..self.len]);
        self.len = len;
        self.pos -= self.start;
        self.start = 0;
    }
};

fn parseRequestLine(req: *Request, buffer: []const u8) !void {
    if (buffer.len < 14) return error.InvalidRequest; // GET / HTTP/1.1

    // Check line ending using single comparison
    const line_end = switch (buffer[buffer.len - 2]) {
        '\r' => buffer.len - 2,
        '\n' => buffer.len - 1,
        else => if (buffer[buffer.len - 1] == '\n')
            buffer.len - 1
        else
            return error.InvalidRequest,
    };

    // Validate HTTP version position and space separator
    const version_start = line_end - 8;
    if (version_start < 6 or buffer[version_start - 1] != ' ') {
        return error.InvalidRequest;
    }

    // Parse method and version first
    req.method = try Method.parse(buffer[0..8]);
    req.version = try Version.parse(buffer[version_start..line_end]);

    // Path and query is everything between method and version
    const path_start = req.method.toLength() + 1;
    const path_and_query = buffer[path_start .. version_start - 1];
    if (std.mem.indexOfScalar(u8, path_and_query, '?')) |query_start| {
        req.query_raw_len = path_and_query.len - (query_start + 1);
        @memcpy(req.query_raw[0..req.query_raw_len], path_and_query[query_start + 1 ..]);
        req.path_len = query_start;
        @memcpy(req.path[0..req.path_len], path_and_query[0..query_start]);
    } else {
        req.query_raw_len = 0;
        req.path_len = path_and_query.len;
        @memcpy(req.path[0..req.path_len], path_and_query);
    }
}

test "benchmark read line" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    var reader = try RequestReader.init(std.testing.allocator, 1024);
    defer reader.deinit();
    const raw = "Header-1: header-1-value\r\nHeader-2: header-2-value\r\nHeader-3: header-3-value\r\n\r\n";
    const iterations: usize = 10_000_000;
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    @memcpy(reader.buffer[0..raw.len], raw);
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
    @memcpy(reader.buffer[0..raw.len], raw);
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        reader.pos = 0;
        reader.start = 0;
        reader.len = raw.len;
        reader.len = raw.len;
        req.reset();
        try reader.readHeaders(0, req);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

test "test parse request line" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    const line = "GET /some-random-path HTTP/1.1\r\n";
    try parseRequestLine(req, line[0..]);
    try std.testing.expectEqual(Version.@"HTTP/1.1", req.version);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/some-random-path", req.getPath());
    try std.testing.expectEqual(0, req.query_raw_len);
}

test "test parse request line with query" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var req = try Request.init(allocator);
    defer req.deinit();
    const line = "GET /some-random-path?some=test&another=test2 HTTP/1.1\r\n";
    try parseRequestLine(req, line[0..]);
    try std.testing.expectEqual(Version.@"HTTP/1.1", req.version);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/some-random-path", req.getPath());
    _ = try req.parseQuery();
    if (req.query.get("some")) |val| {
        try std.testing.expectEqualStrings("test", val);
    } else return error.QueryNotParsed;
    if (req.query.get("another")) |val| {
        try std.testing.expectEqualStrings("test2", val);
    } else return error.QueryNotParsed;
}

test "test parse request line bare LF" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var req = try Request.init(allocator);
    defer req.deinit();
    const line = "POST /some-random-path HTTP/1.0\n";
    try parseRequestLine(req, line[0..]);
    try std.testing.expectEqual(Version.@"HTTP/1.0", req.version);
    try std.testing.expectEqual(Method.POST, req.method);
    try std.testing.expectEqualStrings("/some-random-path", req.getPath());
}

test "benchmark parse request line" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var req = try Request.init(allocator);
    defer req.deinit();
    const line = "GET /some-random-path?some=test HTTP/1.1\r\n";
    const iterations: usize = 100_000_000;
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        try parseRequestLine(req, line[0..]);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

test "benchmark parse GET request" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var req = try Request.init(allocator);
    defer req.deinit();
    var reader = try RequestReader.init(allocator, 4096);
    defer reader.deinit();
    const request_data =
        "GET /path/to/resource HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "User-Agent: test-client\r\n" ++
        "Accept: */*\r\n" ++
        "Connection: keep-alive\r\n\r\n";
    @memcpy(reader.buffer[0..request_data.len], request_data);
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
