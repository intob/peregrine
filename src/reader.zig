const std = @import("std");
const posix = std.posix;
const Request = @import("./request.zig").Request;
const Header = @import("./header.zig").Header;
const Method = @import("./method.zig").Method;
const Version = @import("./version.zig").Version;

pub const RequestReader = struct {
    allocator: std.mem.Allocator,
    buffer: []align(16) u8,
    pos: usize = 0, // Current position in buffer
    len: usize = 0, // Amount of valid data in buffer
    start: usize = 0, // Start of unprocessed data

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize) !*Self {
        const aligned_size = std.mem.alignForward(usize, buffer_size, 16);
        const reader = try allocator.create(Self);
        reader.* = .{
            .allocator = allocator,
            .buffer = try allocator.alignedAlloc(u8, 16, aligned_size),
        };
        return reader;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.buffer);
        self.allocator.destroy(self);
    }

    pub fn readRequest(self: *Self, socket: posix.socket_t, req: *Request) !void {
        req.socket = socket;
        const n = try self.readLine(socket);
        if (n == 0) return error.EOF;
        if (n < "GET / HTTP/1.1".len) return error.InvalidRequest;
        try parseRequestLine(req, self.buffer[self.start - n .. self.start]);
        try self.readHeaders(socket, req);
    }

    pub fn readHeaders(self: *Self, socket: posix.socket_t, req: *Request) !void {
        while (true) {
            const n = try self.readLine(socket);
            if (n == 0) return error.UnexpectedEOF;
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
            const line_end_len: usize = if (n >= 2 and
                self.buffer[self.start - 2] == '\r' and
                self.buffer[self.start - 1] == '\n') 2 else 1;
            req.headers[req.headers_len] = try Header.parse(self.buffer[self.start - n .. self.start - line_end_len]);
            req.headers_len += 1;
        }
    }

    pub inline fn reset(self: *Self) void {
        self.pos = 0;
        self.len = 0;
        self.start = 0;
    }

    pub fn readLine(self: *Self, socket: posix.socket_t) !usize {
        var line_len: usize = 0;
        const Vector = @Vector(16, u8);
        const newline: Vector = @splat(@as(u8, '\n'));
        while (true) {
            if (self.pos > (self.buffer.len / 2)) {
                self.compact();
            }
            if (self.pos >= self.len) {
                const available = self.buffer.len - self.len;
                if (available == 0) return error.LineTooLong;
                const read_amount = try posix.read(socket, self.buffer[self.len..]);
                if (read_amount == 0) return line_len;
                self.len += read_amount;
            }
            // Process 16 bytes at a time
            while (self.pos + 16 <= self.len) {
                var chunk: [16]u8 align(16) = undefined;
                @memcpy(&chunk, self.buffer[self.pos..][0..16]);
                const vec: Vector = chunk;
                const matches = vec == newline;
                const mask = @as(u16, @bitCast(matches));
                if (mask != 0) {
                    const offset = @ctz(mask);
                    line_len += offset + 1;
                    self.pos += offset + 1;
                    self.start = self.pos;
                    return line_len;
                }
                self.pos += 16;
                line_len += 16;
            }
            // Handle remaining bytes
            while (self.pos < self.len) {
                if (self.buffer[self.pos] == '\n') {
                    self.pos += 1;
                    line_len += 1;
                    self.start = self.pos;
                    return line_len;
                }
                self.pos += 1;
                line_len += 1;
            }
        }
    }

    fn compact(self: *Self) void {
        if (self.start == 0) return;
        const len = self.len - self.start;
        std.mem.copyForwards(u8, self.buffer[0..len], self.buffer[self.start..self.len]);
        self.len = len;
        self.pos -= self.start;
        self.start = 0;
    }
};

// This has been optimised to take advantage of the fixed length of HTTP/1.x
// version. This saves us one search for the final ' ' marking the path ending.
// This implementation also handles both CRLF and bare LF line endings.
// As HTTP/2 is a binary protocol, it will be handled in a different path.
fn parseRequestLine(req: *Request, buffer: []const u8) !void {
    // Find first space for method end
    const method_end = std.mem.indexOfScalar(u8, buffer, ' ') orelse return error.InvalidRequest;
    if (method_end > "OPTIONS".len) return error.InvalidRequest;
    // Find version start from the end (looking for last space)
    const line_end = if (buffer[buffer.len - 2] == '\r' and buffer[buffer.len - 1] == '\n')
        buffer.len - 2 // CRLF ending
    else if (buffer[buffer.len - 1] == '\n')
        buffer.len - 1 // LF ending
    else
        return error.InvalidRequest;
    if (line_end < method_end + 10) return error.InvalidRequest;
    // HTTP version is fixed length, so we can calculate version_start
    const version_start = line_end - 8; // Length of "HTTP/1.x"
    if (buffer[version_start - 1] != ' ') return error.InvalidRequest;
    // Parse method and version first
    req.method = try Method.parse(buffer[0..method_end]);
    req.version = try Version.parse(buffer[version_start..line_end]);
    // Path is everything between method and version
    const path_start = method_end + 1;
    const path_end = version_start - 1;
    req.path_len = path_end - path_start;
    @memcpy(req.path_buf[0..req.path_len], buffer[path_start..path_end]);
}

test "benchmark read and parse headers" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var req = try Request.init(allocator);
    defer req.deinit();
    var reader = try RequestReader.init(allocator, 1024);
    const raw = "Header-1: header-1-value\r\nHeader-2: header-2-value\r\nHeader-3: header-3-value\r\n\r\n";
    const iterations: usize = 10_000_000;
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        reader.reset();
        @memcpy(reader.buffer[0..raw.len], raw);
        reader.len = raw.len;
        req.reset();
        try reader.readHeaders(0, req);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

test "test parse request line" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var req = try Request.init(allocator);
    defer req.deinit();
    const line = "GET /some-random-path?some=test HTTP/1.1\r\n";
    try parseRequestLine(req, line[0..]);
    try std.testing.expectEqual(Version.@"HTTP/1.1", req.version);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/some-random-path?some=test", req.getPath());
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

test "benchmark HTTP GET request parsing" {
    const allocator = std.testing.allocator;
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
    const pipe_fds = try posix.pipe();
    const read_fd = pipe_fds[0];
    const write_fd = pipe_fds[1];
    defer posix.close(read_fd);
    defer posix.close(write_fd);
    const iterations: usize = 1_000_000;
    var timer = try std.time.Timer.start();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        _ = try posix.write(write_fd, request_data);
        reader.reset();
        req.reset();
        try reader.readRequest(read_fd, req);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average request parse time: {d}ns\n", .{avg_ns});
}
