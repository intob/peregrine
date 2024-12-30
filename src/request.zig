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
    method: Method,
    path: [256]u8,
    path_len: usize,
    // Benchmarks show this array to be significantly faster than
    // std.ArrayList. Not sure why. A few headers parse in 361ns,
    // vs 426ns using ArrayList. Benchmark used was "benchmark read
    // and parse headers" in reader.zig.
    headers: [32]Header,
    headers_len: usize,
    version: Version,
    query_raw: [256]u8,
    query_raw_len: usize,
    query: std.StringHashMap([]const u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const r = try allocator.create(Self);
        r.* = .{
            .allocator = allocator,
            .method = Method.GET,
            .path = undefined,
            .path_len = 0,
            .headers = undefined,
            .headers_len = 0,
            .version = Version.@"HTTP/1.1",
            .query_raw = undefined,
            .query_raw_len = 0,
            .query = std.StringHashMap([]const u8).init(allocator),
        };
        return r;
    }

    pub fn deinit(self: *Self) void {
        self.query.deinit();
        self.allocator.destroy(self);
    }

    pub fn allHeaders(self: *Self) []Header {
        return self.headers[0..self.headers_len];
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

    pub inline fn getPath(self: *Self) []const u8 {
        return self.path[0..self.path_len];
    }

    // Call this BEFORE accessing the query map.
    // The query map is NOT reset for each request, because clearing the map
    // involves aquiring a mutex. Therefore, we can save some nanoseconds by
    // clearing it here; only when the query is to be used.
    pub fn parseQuery(self: *Self) !?std.StringHashMap([]const u8) {
        self.query.clearRetainingCapacity();
        var current_pos: usize = 0;
        while (current_pos < self.query_raw_len) {
            // Find the key-value separator
            const equals_pos = std.mem.indexOfScalar(u8, self.query_raw[current_pos..], '=') orelse
                return null; // MalformedQuery
            const key = self.query_raw[current_pos .. current_pos + equals_pos];
            const value_start = current_pos + equals_pos + 1;
            // Find the end of this value (either & or end of string)
            const value_slice = self.query_raw[value_start..self.query_raw_len];
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
    pub fn reset(self: *Self) void {
        self.headers_len = 0;
    }
};

test "parse query" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var req = try Request.init(allocator);
    defer req.deinit();
    const query = "key1=value1&key2=value2";
    @memcpy(req.query_raw[0..query.len], query[0..]);
    req.query_raw_len = query.len;
    _ = try req.parseQuery();
    try std.testing.expectEqual(2, req.query.count());
    if (req.query.get("key1")) |value1| {
        try std.testing.expectEqualStrings("value1", value1);
    } else return error.KeyNotFound;
    if (req.query.get("key2")) |value2| {
        try std.testing.expectEqualStrings("value2", value2);
    } else return error.KeyNotFound;
}
