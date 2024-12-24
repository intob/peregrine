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
    path: []const u8,
    body: ?[]const u8 = null,
};

pub const RequestReader = struct {
    allocator: std.mem.Allocator,
    buffer: []u8,
    pos: usize = 0, // Current position in buffer
    len: usize = 0, // Amount of valid data in buffer

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

    pub fn readRequest(self: *Self, socket: posix.socket_t) !?Request {
        const n = try self.readLine(socket);
        if (n < "GET / HTTP/1.1".len) { // Fast path
            return error.InvalidRequest;
        }
        const mp = try parseMethodAndPath(self.buffer[0..n]);
        return .{
            .method = mp.method,
            .path = mp.path,
        };
        // TODO: parse body of POST request
    }

    pub fn readLine(self: *Self, socket: posix.socket_t) !usize {
        var line_len: usize = 0;
        while (true) {
            if (self.pos >= self.len) { // Check if we need to refill the buffer
                self.pos = 0;
                self.len = try posix.read(socket, self.buffer);
                if (self.len == 0) return line_len;
            }
            while (self.pos < self.len) { // Process buffered data
                const byte = self.buffer[self.pos];
                self.pos += 1;
                line_len += 1;
                if (byte == '\n') {
                    self.buffer[line_len] = 0;
                    return line_len;
                }
            }
            if (line_len >= self.buffer.len - 1) { // Check buffer overflow
                return error.LineTooLong;
            }
        }
    }

    fn compact(self: *Self) void {
        if (self.start == 0) return;
        const unprocessed = self.buffer[self.start..self.pos];
        std.mem.copyForwards(u8, self.buffer[0..unprocessed.len], unprocessed);
        self.pos = unprocessed.len;
        self.start = 0;
    }
};

fn parseMethodAndPath(buffer: []const u8) !struct { method: Method, path: []const u8 } {
    // Find first space
    const method_end = std.mem.indexOfScalar(u8, buffer, ' ') orelse return error.InvalidRequest;
    if (method_end > 7) return error.InvalidRequest;

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
