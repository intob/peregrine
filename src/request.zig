const std = @import("std");
const posix = std.posix;

pub const Method = enum(u2) {
    GET,
    POST,
    OPTIONS,

    fn parse(bytes: []const u8) !Method {
        if (bytes.len == 3 and bytes[0] == 'G') {
            return Method.GET;
        }
        if (std.mem.eql(u8, bytes, "POST")) {
            return Method.POST;
        }
        if (std.mem.eql(u8, bytes, "OPTIONS")) {
            return Method.OPTIONS;
        }
        return error.MethodUnsupported;
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
        if (n == 0) {
            return error.EOF;
        }
        const mp = try parseMethodAndPath(self.buffer[0..n]);
        return Request{
            .method = try Method.parse(mp[0]),
            .path = mp[1],
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

fn parseMethodAndPath(line: []const u8) ![2][]const u8 {
    var result: [2][]const u8 = undefined;
    var start: usize = 0;
    var part: usize = 0;

    var i: usize = 0;
    while (i < line.len and part < 2) : (i += 1) {
        if (line[i] == ' ') {
            result[part] = line[start..i];
            start = i + 1;
            part += 1;
        }
    }

    // Handle the last part if we haven't found enough spaces
    if (part < 2 and start < line.len) {
        result[part] = line[start..line.len];
        part += 1;
    }

    return if (part < 2) error.InvalidRequest else result;
}
