const std = @import("std");

pub const Method = enum(u2) {
    GET,
    POST,
    OPTIONS,

    // TODO: benchmark different ways to match the method,
    // for example, by direct slice access.
    fn parseSlow(bytes: []const u8) !Method {
        if (bytes.len > 7) return error.MethodUnsupported;
        const first = bytes[0];
        switch (first) {
            'P' => return if (std.mem.eql(u8, bytes, "POST")) Method.POST else error.MethodUnsupported,
            'O' => return if (std.mem.eql(u8, bytes, "OPTIONS")) Method.OPTIONS else error.MethodUnsupported,
            'G' => return if (bytes.len == 3) Method.GET else error.MethodUnsupported,
            else => return error.MethodUnsupported,
        }
    }

    // Fast path
    pub fn parse(bytes: []const u8) !Method {
        if (bytes.len == 3 and bytes[0] == 'G') {
            return Method.GET;
        }
        return Method.parseSlow(bytes); // fallback to normal parsing
    }
};
