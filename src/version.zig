const testing = @import("std").testing;

pub const Version = enum(u1) {
    @"HTTP/1.0",
    @"HTTP/1.1",

    pub fn parse(version: []const u8) !Version {
        if (version.len != 8) return error.InvalidVersion;
        if (version[5] != '1') return error.UnsupportedVersion;
        if (version[6] != '.') return error.InvalidVersion;
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
    try testing.expectError(error.InvalidVersion, Version.parse("HTTP/1."));
    try testing.expectError(error.InvalidVersion, Version.parse("HTTP/1.12"));
    try testing.expectError(error.UnsupportedVersion, Version.parse("HTTP/1.2"));
    try testing.expectError(error.UnsupportedVersion, Version.parse("HTTP/2.1"));
}
