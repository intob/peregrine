const std = @import("std");

pub const Header = struct {
    key_len: usize = 0,
    value_len: usize = 0,
    key_buf: [64]u8 = undefined,
    value_buf: [256]u8 = undefined,

    // Inlining this yeilds a 50% improvement in "benchmark init" below,
    // and 20% improvement in "benchmark serialise" in response.zig.
    pub inline fn init(comptime k: []const u8, v: []const u8) !Header {
        if (comptime k.len > 64) return error.KeyTooLarge;
        if (v.len > 256) return error.ValueTooLarge;
        var h = Header{ .key_len = k.len, .value_len = v.len };
        @memcpy(h.key_buf[0..k.len], k);
        @memcpy(h.value_buf[0..v.len], v);
        return h;
    }

    pub inline fn key(self: *const Header) []const u8 {
        return self.key_buf[0..self.key_len];
    }

    pub inline fn value(self: *const Header) []const u8 {
        return self.value_buf[0..self.value_len];
    }

    // Inlining this yeilds a small improvement in "benchmark parse" below,
    // and "benchmark read and parse headers" in reader.zig.
    pub inline fn parse(raw: []const u8) !Header {
        var h = Header{};
        const colon_pos = std.mem.indexOfScalar(u8, raw, ':') orelse return error.InvalidHeader;
        if (colon_pos >= h.key_buf.len or raw.len - (colon_pos + 2) >= h.value_buf.len) {
            return if (colon_pos >= h.key_buf.len)
                error.KeyTooLong
            else
                error.ValueTooLong;
        }
        @memcpy(h.key_buf[0..colon_pos], raw[0..colon_pos]);
        const val = raw[colon_pos + 2 ..];
        @memcpy(h.value_buf[0..val.len], val);
        h.key_len = colon_pos;
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

test "benchmark init" {
    const iterations: usize = 100_000_000;
    var i: usize = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        const h = try Header.init("Content-Type", "text/plain");
        std.mem.doNotOptimizeAway(h);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
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
