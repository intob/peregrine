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

    method: Method align(64) = .GET,
    path_and_query: []u8 align(64) = undefined,
    // Benchmarks show this array to be significantly faster than
    // std.ArrayList. Not sure why. Benchmark used was "benchmark
    // read and parse headers" in reader.zig.
    headers: [32]Header align(64) = undefined,
    headers_len: usize align(64) = 0,
    // TODO: make this an optional, for when unspecified.
    keep_alive: bool align(64) = false,
    version: Version align(64) = .@"HTTP/1.1",
    /// Before accessing this directly, call parseQuery()
    query: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

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

    /// For best performance access path_and_query directly, unless you're expecting a
    /// query. This method will search for '?', returning everything before it.
    pub inline fn getPath(self: *Self) []const u8 {
        const query_start = std.mem.indexOfScalar(u8, self.path_and_query, '?') orelse
            return self.path_and_query;
        return self.path_and_query[0..query_start];
    }

    /// Call this BEFORE accessing the query map.
    /// The query map is NOT reset for each request, because clearing the map
    /// involves aquiring a mutex. Therefore, we can save some nanoseconds by
    /// clearing it here; only when the query is to be used.
    pub fn parseQuery(self: *Self) !?std.StringHashMap([]const u8) {
        const query_start = std.mem.indexOfScalar(u8, self.path_and_query, '?') orelse
            return null;
        self.query.clearRetainingCapacity();
        const raw = self.path_and_query[query_start + 1 ..];
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
        self.keep_alive = false;
    }
};

test "parse query" {
    var req = try Request.init(std.testing.allocator);
    defer req.deinit();
    const raw = try std.testing.allocator.dupe(u8, "/path?key1=value1&key2=value2");
    defer std.testing.allocator.free(raw);
    req.path_and_query = raw;
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
    const raw = try std.testing.allocator.dupe(u8, "/path?key1=value1&key2=value2");
    defer std.testing.allocator.free(raw);
    req.path_and_query = raw;
    try std.testing.expectEqualSlices(u8, "/path", req.getPath());
}
