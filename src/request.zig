const std = @import("std");
const posix = std.posix;
const Method = @import("./method.zig").Method;
const Header = @import("./header.zig").Header;
const Version = @import("./version.zig").Version;

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
    version: Version,
    query: std.StringHashMap([]const u8),

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
            .version = Version.@"HTTP/1.1",
            .query = std.StringHashMap([]const u8).init(allocator),
        };
        return r;
    }

    pub fn deinit(self: *Self) void {
        self.query.deinit();
        self.allocator.destroy(self);
    }

    pub fn getHeaders(self: *Self) []Header {
        return self.headers[0..self.headers_len];
    }

    pub fn getHeader(self: *Self, key: []const u8) ?[]const u8 {
        for (self.headers[0..self.headers_len]) |h| {
            if (std.mem.eql(u8, key, h.key())) {
                return h.value();
            }
        }
        return null;
    }

    pub inline fn getPath(self: *Self) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    // Call this BEFORE accessing the query map.
    // The query map is NOT reset for each request, because clearing the map
    // involves aquiring a mutex. Therefore, we can save some nanoseconds by
    // clearing it here; only when the query is to be used.
    pub fn parseQuery(self: *Self) !?std.StringHashMap([]const u8) {
        self.query.clearRetainingCapacity();
        const query_start = std.mem.indexOfScalar(u8, self.path_buf[0..self.path_len], '?') orelse
            return null; // Path has no query
        var current_pos = query_start + 1;
        while (current_pos < self.path_len) {
            // Find the key-value separator
            const equals_pos = std.mem.indexOfScalar(u8, self.path_buf[current_pos..], '=') orelse
                return null; // MalformedQuery
            const key = self.path_buf[current_pos .. current_pos + equals_pos];
            const value_start = current_pos + equals_pos + 1;
            // Find the end of this value (either & or end of string)
            if (std.mem.indexOfScalar(u8, self.path_buf[value_start..], '&')) |amp_pos| {
                try self.query.put(key, self.path_buf[value_start .. value_start + amp_pos]);
                current_pos = value_start + amp_pos + 1;
            } else {
                try self.query.put(key, self.path_buf[value_start..self.path_len]);
                break;
            }
        }
        return self.query;
    }

    // Socket, method, path_buf and path_len will always be overwritten by the
    // request reader. No need to reset them here also.
    // This method should be called BEFORE the call to RequestReader.readRequest.
    // The query map is reset in the parseQuery method, because we don't need to clear
    // the map unless we want to use it.
    pub fn reset(self: *Self) void {
        self.headers_len = 0;
    }
};

test "parse query" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var req = try Request.init(allocator);
    defer req.deinit();
    const path = "/some-random-path?key1=value1&key2=value2";
    @memcpy(req.path_buf[0..path.len], path[0..]);
    req.path_len = path.len;
    try req.parseQuery();
    try std.testing.expectEqual(2, req.query.count());
    if (req.query.get("key1")) |value1| {
        try std.testing.expectEqualStrings("value1", value1);
    } else return error.KeyNotFound;
    if (req.query.get("key2")) |value2| {
        try std.testing.expectEqualStrings("value2", value2);
    } else return error.KeyNotFound;
}
