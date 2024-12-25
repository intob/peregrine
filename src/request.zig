const std = @import("std");
const posix = std.posix;

pub const Method = enum(u2) {
    GET,
    POST,
    OPTIONS,

    fn parse(bytes: []const u8) !Method {
        if (bytes.len > 7) return error.MethodUnsupported;
        const first = bytes[0];
        switch (first) {
            'P' => return if (std.mem.eql(u8, bytes, "POST")) Method.POST else error.MethodUnsupported,
            'O' => return if (std.mem.eql(u8, bytes, "OPTIONS")) Method.OPTIONS else error.MethodUnsupported,
            'G' => return if (bytes.len == 3) Method.GET else error.MethodUnsupported,
            else => return error.MethodUnsupported,
        }
    }

    fn parseFast(bytes: []const u8) !Method {
        if (bytes.len == 3 and bytes[0] == 'G') {
            return Method.GET;
        }
        return Method.parse(bytes); // fallback to normal parsing
    }
};

pub const Request = struct {
    method: Method,
    path_buf: [256]u8,
    path_len: usize,
    body: ?[]const u8 = null,

    pub inline fn getPath(self: *const Request) []const u8 {
        return self.path_buf[0..self.path_len];
    }
};

pub const RequestReader = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
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
        defer self.start = 0;
        defer self.pos = 0;
        defer self.len = 0;

        const n = try self.readLine(socket);
        if (n < "GET / HTTP/1.1".len) { // Fast path
            return error.InvalidRequest;
        }

        // Use the actual data from start position
        const request_line = self.buffer[self.start - n .. self.start];
        const parsed = try parseMethodAndPath(request_line);
        req.method = parsed.method;
        req.path_len = parsed.path.len;
        @memcpy(req.path_buf[0..parsed.path.len], parsed.path);
    }

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

            // Need more data
            const available = self.buffer.len - self.len;
            if (available == 0) {
                self.compact();
            }

            const read_amount = try posix.read(socket, self.buffer[self.len..]);
            if (read_amount == 0) return;
            self.len += read_amount;
        }
    }

    pub fn reset(self: *Self) void {
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
    // Find first space
    const method_end = std.mem.indexOfScalar(u8, buffer, ' ') orelse return error.InvalidRequest;
    if (method_end > "OPTIONS".len) return error.InvalidRequest;

    // Find second space
    const path_start = method_end + 1;
    const path_end = if (path_start < buffer.len)
        std.mem.indexOfScalarPos(u8, buffer, path_start, ' ') orelse return error.InvalidRequest
    else
        return error.InvalidRequest;

    return .{
        .method = try Method.parseFast(buffer[0..method_end]),
        .path = buffer[path_start..path_end],
    };
}
