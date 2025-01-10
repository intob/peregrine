const testing = @import("std").testing;

pub const Version = enum(u1) {
    @"HTTP/1.0",
    @"HTTP/1.1",

    pub fn parse(version: []const u8) !Version {
        // Length check omitted because it is already done in the reader
        // method parseRequestLine.
        return switch (version[7]) {
            '0' => .@"HTTP/1.0",
            '1' => .@"HTTP/1.1",
            else => error.UnsupportedVersion,
        };
    }
};

test "parse version" {
    try testing.expectEqual(Version.@"HTTP/1.0", try Version.parse("HTTP/1.0"));
    try testing.expectEqual(Version.@"HTTP/1.1", try Version.parse("HTTP/1.1"));
    try testing.expectError(error.UnsupportedVersion, Version.parse("HTTP/1.2"));
}
