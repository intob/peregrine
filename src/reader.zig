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
        self.reset();
        req.socket = socket;
        const n = try self.readLine(socket);
        if (n < "GET / HTTP/1.1".len) { // Fast path
            return error.InvalidRequest;
        }
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
            req.headers[req.headers_len] = try Header.parse(self.buffer[self.start - n .. self.start]);
            req.headers_len += 1;
        }
    }

    // Not yet used, but could be useful. Will leave it here for now.
    pub fn skipHeaders(self: *Self, socket: posix.socket_t) !void {
        var header_lines: usize = 0;
        while (true) {
            while (self.pos < self.len) {
                const c = self.buffer[self.pos];
                self.pos += 1;
                switch (c) {
                    '\n' => {
                        header_lines += 1;
                        if (header_lines == 2) return; // Empty line found
                    },
                    '\r' => {}, // Skip carriage returns
                    else => header_lines = 0, // Reset on any other character
                }
            }
            const available = self.buffer.len - self.len;
            if (available == 0) {
                self.compact();
            }
            const read_amount = try posix.read(socket, self.buffer[self.len..]);
            if (read_amount == 0) return;
            self.len += read_amount;
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

fn parseRequestLine(req: *Request, buffer: []const u8) !void {
    const method_end = std.mem.indexOfScalar(u8, buffer, ' ') orelse return error.InvalidRequest;
    if (method_end > "OPTIONS".len) return error.InvalidRequest;
    const path_start = method_end + 1;
    const path_end = if (path_start < buffer.len)
        std.mem.indexOfScalarPos(u8, buffer, path_start, ' ') orelse return error.InvalidRequest
    else
        return error.InvalidRequest;
    const version_start = path_end + 1;
    if (version_start + 8 > buffer.len) return error.InvalidRequest;
    const version_end = if (version_start < buffer.len)
        std.mem.indexOfScalarPos(u8, buffer, version_start, '\r') orelse return error.InvalidRequest
    else
        return error.InvalidRequest;
    req.method = try Method.parse(buffer[0..method_end]);
    req.path_len = path_end - path_start;
    @memcpy(req.path_buf[0..req.path_len], buffer[path_start..path_end]);
    req.version = try Version.parse(buffer[version_start..version_end]);
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
