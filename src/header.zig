const std = @import("std");

/// A header as slices. In a Request, both point into the connection's read
/// buffer (zero-copy) and are only valid during handleRequest.
pub const Header = struct {
    key: []const u8,
    value: []const u8,

    /// Response headers managed by the server. Setting them from a handler
    /// would produce duplicate or conflicting framing.
    pub const reserved = [_][]const u8{ "content-length", "transfer-encoding", "connection", "date" };

    pub inline fn init(comptime k: []const u8, v: []const u8) Header {
        comptime checkKey(k);
        return .{ .key = k, .value = v };
    }

    pub fn checkKey(comptime k: []const u8) void {
        inline for (reserved) |r| {
            if (comptime std.ascii.eqlIgnoreCase(k, r)) {
                @compileError("the '" ++ r ++ "' header is set by the server");
            }
        }
    }
};
