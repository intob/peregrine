const std = @import("std");
const testing = std.testing;

pub const Method = enum(u4) {
    GET,
    PUT,
    HEAD,
    POST,
    PATCH,
    TRACE,
    DELETE,
    CONNECT,
    OPTIONS,

    /// Parses a complete method token (the bytes before the first SP).
    /// Unknown methods return `error.UnknownMethod` (501 Not Implemented).
    pub fn parse(token: []const u8) error{UnknownMethod}!Method {
        // Compare whole tokens as integers: one load + compare per candidate.
        return switch (token.len) {
            3 => switch (asInt(u24, token)) {
                asInt(u24, "GET") => .GET,
                asInt(u24, "PUT") => .PUT,
                else => error.UnknownMethod,
            },
            4 => switch (asInt(u32, token)) {
                asInt(u32, "HEAD") => .HEAD,
                asInt(u32, "POST") => .POST,
                else => error.UnknownMethod,
            },
            5 => switch (asInt(u40, token)) {
                asInt(u40, "PATCH") => .PATCH,
                asInt(u40, "TRACE") => .TRACE,
                else => error.UnknownMethod,
            },
            6 => if (asInt(u48, token) == asInt(u48, "DELETE")) .DELETE else error.UnknownMethod,
            7 => switch (asInt(u56, token)) {
                asInt(u56, "CONNECT") => .CONNECT,
                asInt(u56, "OPTIONS") => .OPTIONS,
                else => error.UnknownMethod,
            },
            else => error.UnknownMethod,
        };
    }

    /// RFC 9110 §9.2.1: methods that don't ask for a change on the
    /// server, so a replay (of TLS early data, say) is harmless.
    pub fn isSafe(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .OPTIONS, .TRACE => true,
            else => false,
        };
    }

    pub fn toString(self: Method) []const u8 {
        return @tagName(self);
    }

    pub fn toLength(self: Method) usize {
        return @tagName(self).len;
    }

    inline fn asInt(comptime T: type, bytes: []const u8) T {
        return std.mem.readInt(T, bytes[0 .. @bitSizeOf(T) / 8], .little);
    }
};

test "parse valid HTTP methods" {
    inline for (comptime std.meta.fieldNames(Method)) |name| {
        try testing.expectEqual(@field(Method, name), try Method.parse(name));
    }
}

test "parse rejects unknown and partial methods" {
    try testing.expectError(error.UnknownMethod, Method.parse("GARBAGE"));
    try testing.expectError(error.UnknownMethod, Method.parse("GE"));
    try testing.expectError(error.UnknownMethod, Method.parse("get"));
    try testing.expectError(error.UnknownMethod, Method.parse("GETS"));
    try testing.expectError(error.UnknownMethod, Method.parse("PUTX"));
    try testing.expectError(error.UnknownMethod, Method.parse(""));
}
