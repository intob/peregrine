const testing = @import("std").testing;

pub const Version = enum {
    @"HTTP/1.0",
    @"HTTP/1.1",

    pub fn parse(version: []const u8) !Version {
        // Verify minimum length for "HTTP/1.x"
        if (version.len < 8) return error.InvalidVersion;
        // Skip checking "HTTP/" prefix, check only the version number
        return switch (version[7]) {
            '0' => if (version[5] == '1' and version[6] == '.') .@"HTTP/1.0" else error.UnsupportedVersion,
            '1' => if (version[5] == '1' and version[6] == '.') .@"HTTP/1.1" else error.UnsupportedVersion,
            else => error.UnsupportedVersion,
        };
    }
};

test "parse version" {
    try testing.expectEqual(Version.@"HTTP/1.0", try Version.parse("HTTP/1.0"));
    try testing.expectEqual(Version.@"HTTP/1.1", try Version.parse("HTTP/1.1"));
    try testing.expectError(error.InvalidVersion, Version.parse("HTTP/1."));
    try testing.expectError(error.UnsupportedVersion, Version.parse("HTTP/1.2"));
    try testing.expectError(error.UnsupportedVersion, Version.parse("HTTP/2.1"));
}
