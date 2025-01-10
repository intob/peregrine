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
    const Self = @This();

    allocator: std.mem.Allocator,
    method: Method = .GET,
    path_and_query: [256]u8 = undefined,
    path_and_query_len: usize = 0,
    // Benchmarks show this array to be significantly faster than
    // std.ArrayList. Not sure why. Benchmark used was "benchmark
    // read and parse headers" in reader.zig.
    headers: [32]Header = undefined,
    headers_len: usize = 0,
    keep_alive: bool = true,
    version: Version = .@"HTTP/1.1",
    /// Before accessing this directly, call parseQuery()
    query: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const r = try allocator.create(Self);
        r.* = .{
            .allocator = allocator,
            .query = std.StringHashMap([]const u8).init(allocator),
        };
        return r;
    }

    pub fn deinit(self: *Self) void {
        self.query.deinit();
        self.allocator.destroy(self);
    }

    /// SIMD-optimised case-insensitive search. RFC 9110 Section 5.1
    /// "Field Names" explicitly states that "Field names are case-insensitive"
    pub fn findHeader(self: *Self, key: []const u8) ?[]const u8 {
        for (self.headers[0..self.headers_len]) |h| {
            if (std.ascii.eqlIgnoreCase(h.key(), key)) {
                return h.value();
            }
        }
        return null;
    }

    /// This is faster than getPath, and you can use this if you don't expect
    /// a query. The reason that this is faster is that there is no scalar search
    /// for '?' to find the query start.
    pub inline fn getPathAndQueryRaw(self: *Self) []const u8 {
        return self.path_and_query[0..self.path_and_query_len];
    }

    /// For best performance, use getPathAndQueryRaw unless you're expecting a
    /// query. This method will search for '?', returning everything before it.
    pub inline fn getPath(self: *Self) []const u8 {
        const query_start = std.mem.indexOfScalar(u8, self.getPathAndQueryRaw(), '?') orelse
            return self.getPathAndQueryRaw();
        return self.path_and_query[0..query_start];
    }

    /// Call this BEFORE accessing the query map.
    /// The query map is NOT reset for each request, because clearing the map
    /// involves aquiring a mutex. Therefore, we can save some nanoseconds by
    /// clearing it here; only when the query is to be used.
    pub fn parseQuery(self: *Self) !?std.StringHashMap([]const u8) {
        const query_start = std.mem.indexOfScalar(u8, self.path_and_query[0..self.path_and_query_len], '?') orelse
            return null;
        self.query.clearRetainingCapacity();
        const raw = self.path_and_query[query_start + 1 .. self.path_and_query_len];
        var current_pos: usize = 0;
        while (current_pos < raw.len) {
            // Find the key-value separator
            const equals_pos = std.mem.indexOfScalar(u8, raw[current_pos..], '=') orelse
                return null; // MalformedQuery
            const key = raw[current_pos .. current_pos + equals_pos];
            const value_start = current_pos + equals_pos + 1;
            // Find the end of this value (either & or end of string)
            const value_slice = raw[value_start..];
            const amp_pos = std.mem.indexOfScalar(u8, value_slice, '&');
            if (amp_pos) |pos| {
                try self.query.put(key, value_slice[0..pos]);
                current_pos = value_start + pos + 1;
            } else {
                // Handle the last key-value pair
                try self.query.put(key, value_slice);
                break;
            }
        }
        return self.query;
    }

    // Method, path_buf and path_len will always be overwritten by the
    // request reader. No need to reset them here also.
    // This method should be called BEFORE the call to RequestReader.readRequest.
    // The query map is reset in the parseQuery method, because we don't need to clear
    // the map unless we want to use it.
    pub inline fn reset(self: *Self) void {
        self.headers_len = 0;
        self.keep_alive = true;
    }
};

test "parse query" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    const raw = "/path?key1=value1&key2=value2";
    @memcpy(req.path_and_query[0..raw.len], raw[0..]);
    req.path_and_query_len = raw.len;
    _ = try req.parseQuery();
    try std.testing.expectEqual(2, req.query.count());
    if (req.query.get("key1")) |value1| {
        try std.testing.expectEqualStrings("value1", value1);
    } else return error.KeyNotFound;
    if (req.query.get("key2")) |value2| {
        try std.testing.expectEqualStrings("value2", value2);
    } else return error.KeyNotFound;
}

test "get path" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    const raw = "/path?key1=value1&key2=value2";
    @memcpy(req.path_and_query[0..raw.len], raw[0..]);
    req.path_and_query_len = raw.len;
    try std.testing.expectEqualSlices("/path", req.getPath());
}
