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

    pub fn parse(bytes: []const u8) !Method {
        return switch (bytes.len) {
            3 => switch (bytes[0]) {
                'G' => if (bytes[1] == 'E' and bytes[2] == 'T')
                    Method.GET
                else
                    error.UnsupportedMethod,
                'P' => if (bytes[1] == 'U' and bytes[2] == 'T')
                    Method.PUT
                else
                    error.UnsupportedMethod,
                else => error.UnsupportedMethod,
            },
            4 => switch (bytes[0]) {
                'H' => if (std.mem.eql(u8, bytes, "HEAD"))
                    Method.HEAD
                else
                    error.UnsupportedMethod,
                'P' => if (std.mem.eql(u8, bytes, "POST"))
                    Method.POST
                else
                    error.UnsupportedMethod,
                else => error.UnsupportedMethod,
            },
            5 => switch (bytes[0]) {
                'P' => if (std.mem.eql(u8, bytes, "PATCH"))
                    Method.PATCH
                else
                    error.UnsupportedMethod,
                'T' => if (std.mem.eql(u8, bytes, "TRACE"))
                    Method.TRACE
                else
                    error.UnsupportedMethod,
                else => error.UnsupportedMethod,
            },
            6 => if (std.mem.eql(u8, bytes, "DELETE"))
                Method.DELETE
            else
                error.UnsupportedMethod,
            7 => switch (bytes[0]) {
                'C' => if (std.mem.eql(u8, bytes, "CONNECT"))
                    Method.CONNECT
                else
                    error.UnsupportedMethod,
                'O' => if (std.mem.eql(u8, bytes, "OPTIONS"))
                    Method.OPTIONS
                else
                    error.UnsupportedMethod,
                else => error.UnsupportedMethod,
            },
            else => error.UnsupportedMethod,
        };
    }
};

test "parse valid HTTP methods" {
    try testing.expectEqual(Method.GET, try Method.parse("GET"));
    try testing.expectEqual(Method.PUT, try Method.parse("PUT"));
    try testing.expectEqual(Method.HEAD, try Method.parse("HEAD"));
    try testing.expectEqual(Method.POST, try Method.parse("POST"));
    try testing.expectEqual(Method.PATCH, try Method.parse("PATCH"));
    try testing.expectEqual(Method.TRACE, try Method.parse("TRACE"));
    try testing.expectEqual(Method.DELETE, try Method.parse("DELETE"));
    try testing.expectEqual(Method.CONNECT, try Method.parse("CONNECT"));
    try testing.expectEqual(Method.OPTIONS, try Method.parse("OPTIONS"));
}

test "parse invalid HTTP methods" {
    try testing.expectError(error.UnsupportedMethod, Method.parse(""));
    try testing.expectError(error.UnsupportedMethod, Method.parse("INVALID"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("GET "));
    try testing.expectError(error.UnsupportedMethod, Method.parse("POSTING"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("get"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("Get"));
}

test "parse methods with matching length but invalid content" {
    try testing.expectError(error.UnsupportedMethod, Method.parse("GXT"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("PXT"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("HXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("PXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("PXXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("TXXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("DXXXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("CXXXXXX"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("OXXXXXX"));
}

test "parse methods with special characters" {
    try testing.expectError(error.UnsupportedMethod, Method.parse("GET\t"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("GET\n"));
    try testing.expectError(error.UnsupportedMethod, Method.parse("GET\r"));
}
