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
            'G' => return if (bytes.len == 3) Method.GET else error.MethodUnsupported,
            'P' => return if (std.mem.eql(u8, bytes, "POST")) Method.POST else error.MethodUnsupported,
            'O' => return if (std.mem.eql(u8, bytes, "OPTIONS")) Method.OPTIONS else error.MethodUnsupported,
            else => return error.MethodUnsupported,
        }
    }
};

pub const Request = struct {
    method: Method,
    path_buf: [256]u8,
    path_len: usize,
    body: ?[]const u8 = null,
};

pub const RequestReader = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
    pos: usize = 0, // Current position in buffer
    len: usize = 0, // Amount of valid data in buffer
    start: usize = 0, // Start of unprocessed data

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize) !*Self {
        const reader = try allocator.create(Self);
        reader.* = .{
            .allocator = allocator,
            .buffer = try allocator.alloc(u8, buffer_size),
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

        // Consume the rest of the headers until we hit an empty line
        while (true) {
            const header_len = try self.readLine(socket);
            if (header_len <= 2) { // Just \r\n
                break;
            }
        }
    }

    pub fn readLine(self: *Self, socket: posix.socket_t) !usize {
        var line_len: usize = 0;
        while (true) {
            // Compact if buffer is more than half full
            if (self.pos > (self.buffer.len / 2)) {
                self.compact();
            }

            // Read more data if needed
            if (self.pos >= self.len) {
                const available = self.buffer.len - self.len;
                if (available == 0) return error.LineTooLong;

                const read_amount = try posix.read(socket, self.buffer[self.len..]);
                if (read_amount == 0) return line_len;
                self.len += read_amount;
            }

            // Process current buffer
            while (self.pos < self.len) {
                const byte = self.buffer[self.pos];
                self.pos += 1;
                line_len += 1;

                if (byte == '\n') {
                    // Store current position as start for next read
                    self.start = self.pos;
                    return line_len;
                }
            }
        }
    }

    fn compact(self: *Self) void {
        if (self.start == 0) return;

        const unprocessed = self.buffer[self.start..self.len];
        if (unprocessed.len > 0) {
            @memcpy(self.buffer[0..unprocessed.len], unprocessed);
        }
        self.len = unprocessed.len;
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
        .method = try Method.parse(buffer[0..method_end]),
        .path = buffer[path_start..path_end],
    };
}
