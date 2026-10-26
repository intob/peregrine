const testing = @import("std").testing;

pub const Version = enum(u1) {
    @"HTTP/1.0",
    @"HTTP/1.1",

    /// `version` must be exactly the 8 bytes after the request target.
    pub fn parse(version: []const u8) error{ InvalidVersion, UnsupportedVersion }!Version {
        if (version.len != 8 or !@import("std").mem.eql(u8, version[0..5], "HTTP/") or
            version[6] != '.' or !isDigit(version[5]) or !isDigit(version[7]))
        {
            return error.InvalidVersion;
        }
        if (version[5] != '1') return error.UnsupportedVersion;
        return switch (version[7]) {
            '0' => .@"HTTP/1.0",
            '1' => .@"HTTP/1.1",
            else => error.UnsupportedVersion,
        };
    }

    inline fn isDigit(c: u8) bool {
        return c >= '0' and c <= '9';
    }
};

test "parse version" {
    try testing.expectEqual(Version.@"HTTP/1.0", try Version.parse("HTTP/1.0"));
    try testing.expectEqual(Version.@"HTTP/1.1", try Version.parse("HTTP/1.1"));
    try testing.expectError(error.UnsupportedVersion, Version.parse("HTTP/1.2"));
    try testing.expectError(error.UnsupportedVersion, Version.parse("HTTP/2.0"));
    try testing.expectError(error.InvalidVersion, Version.parse("HTTX/1.1"));
    try testing.expectError(error.InvalidVersion, Version.parse("HTTP/1.1 "));
    try testing.expectError(error.InvalidVersion, Version.parse("HTTP/a.1"));
}
