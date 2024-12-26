const std = @import("std");

pub const Header = struct {
    key_buf: [64]u8 = undefined,
    key_len: usize = 0,
    value_buf: [256]u8 = undefined,
    value_len: usize = 0,

    pub fn init(c: struct { key: []const u8, value: []const u8 }) !Header {
        if (c.key.len > 64) return error.KeyTooLarge;
        if (c.value.len > 256) return error.ValueTooLarge;
        var h = Header{};
        @memcpy(h.key_buf[0..c.key.len], c.key);
        h.key_len = c.key.len;
        @memcpy(h.value_buf[0..c.value.len], c.value);
        h.value_len = c.value.len;
        return h;
    }

    pub inline fn key(self: *const Header) []const u8 {
        return self.key_buf[0..self.key_len];
    }

    pub inline fn value(self: *const Header) []const u8 {
        return self.value_buf[0..self.value_len];
    }

    // This implementation is around 23% faster than the old one.
    // On my machine, this takes 55ns versus the old one taking 71ns.
    // The improvement is due to the use of std.mem.indexOfScalar,
    // taking advantage of SIMD/NEON.
    pub fn parse(raw: []const u8) !Header {
        var h = Header{};
        const colon_pos = std.mem.indexOfScalar(u8, raw, ':') orelse return error.InvalidHeader;
        if (colon_pos >= h.key_buf.len) return error.KeyTooLong;
        @memcpy(h.key_buf[0..colon_pos], raw[0..colon_pos]);
        h.key_len = colon_pos;
        // Skip colon and space
        const val = raw[colon_pos + 2 .. raw.len];
        if (val.len >= h.value_buf.len) return error.ValueTooLong;
        @memcpy(h.value_buf[0..val.len], val);
        h.value_len = val.len;
        return h;
    }
};

test "parse header" {
    const raw: []const u8 = "Content-Type: text/html";
    const parsed = try Header.parse(raw);
    try std.testing.expectEqualStrings("Content-Type", parsed.key());
    try std.testing.expectEqualStrings("text/html", parsed.value());
}

test "benchmark parse" {
    const iterations: usize = 100_000_000;
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        const h = try Header.parse("Content-Type: text/plain");
        std.mem.doNotOptimizeAway(h);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}
