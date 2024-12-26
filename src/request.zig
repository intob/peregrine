const std = @import("std");
const posix = std.posix;
const Method = @import("./method.zig").Method;
const Header = @import("./header.zig").Header;

/// This request is reused.
/// It is reset by the worker before each request is read.
/// Library users do not need to call the reset method.
/// IMPORTANT:
/// If a field is added, it MUST be reset by the reset() method.
pub const Request = struct {
    allocator: std.mem.Allocator,
    socket: std.posix.socket_t,
    method: Method,
    path_buf: [256]u8,
    path_len: usize,
    headers: [32]Header,
    headers_len: usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const r = try allocator.create(Self);
        r.* = .{
            .allocator = allocator,
            .socket = 0,
            .method = Method.GET,
            .path_buf = [_]u8{0} ** 256,
            .path_len = 0,
            .headers = undefined,
            .headers_len = 0,
        };
        return r;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    pub fn getHeaders(self: *Self) []Header {
        return self.headers[0..self.headers_len];
    }

    pub inline fn getPath(self: *Self) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    // Socket, method, path_buf and path_len will always be overwritten by the
    // request reader.
    // See below. No need to reset them here also.
    // This method should be called BEFORE the call to RequestReader.readRequest.
    pub fn reset(self: *Self) void {
        self.headers_len = 0;
    }
};

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
        const parsed = try parseMethodAndPath(self.buffer[self.start - n .. self.start]);
        req.method = parsed.method;
        req.path_len = parsed.path.len;
        @memcpy(req.path_buf[0..parsed.path.len], parsed.path);
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

fn parseMethodAndPath(buffer: []const u8) !struct { method: Method, path: []const u8 } {
    const method_end = std.mem.indexOfScalar(u8, buffer, ' ') orelse return error.InvalidRequest;
    if (method_end > "OPTIONS".len) return error.InvalidRequest;
    const path_start = method_end + 1;
    const path_end = if (path_start < buffer.len)
        std.mem.indexOfScalarPos(u8, buffer, path_start, ' ') orelse return error.InvalidRequest
    else
        return error.InvalidRequest;
    return .{
        .method = try Method.parse(buffer[0..method_end]),
        .path = buffer[path_start..path_end],
    };
}
