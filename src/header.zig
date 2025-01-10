const std = @import("std");

pub const Header = struct {
    key_len: usize = 0,
    value_len: usize = 0,
    key_buf: [64]u8 = undefined,
    value_buf: [256]u8 = undefined,

    pub const MAX_KEY_LEN = 64;
    pub const MAX_VALUE_LEN = 256;

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

    pub inline fn parse(self: *Header, raw: []const u8) !void {
        const colon_pos = std.mem.indexOfScalar(u8, raw, ':') orelse return error.InvalidHeader;
        if (colon_pos >= self.key_buf.len or raw.len - (colon_pos + 2) >= self.value_buf.len) {
            return if (colon_pos >= self.key_buf.len)
                error.KeyTooLong
            else
                error.ValueTooLong;
        }
        @memcpy(self.key_buf[0..colon_pos], raw[0..colon_pos]);
        const val = raw[colon_pos + 2 ..];
        @memcpy(self.value_buf[0..val.len], val);
        self.key_len = colon_pos;
        self.value_len = val.len;
    }
};

test "parse header" {
    const raw: []const u8 = "Content-Type: text/html";
    var h = Header{};
    try h.parse(raw);
    try std.testing.expectEqualStrings("Content-Type", h.key());
    try std.testing.expectEqualStrings("text/html", h.value());
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
        var h = Header{};
        try h.parse("Content-Type: text/plain");
        std.mem.doNotOptimizeAway(h);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

// This is maybe 2ns faster (53ns rather than 55ns).
// It's also more complicated. Also, indexOfScalar does basically
// the same thing under the hood. I prefer the implementation above.
pub fn moreComplicatedParser(raw: []const u8) !Header {
    if (raw.len < 3) return error.InvalidHeader; // Minimum valid length: "a:b"
    // Use SIMD to find colon
    const colon_pos = blk: {
        const chunk_size = 16;
        const colon_vec: @Vector(chunk_size, u8) = @splat(':');
        var i: usize = 0;
        while (i + chunk_size <= raw.len) : (i += chunk_size) {
            const chunk: @Vector(chunk_size, u8) = raw[i..][0..chunk_size].*;
            const mask = chunk == colon_vec;
            if (@reduce(.Or, mask)) {
                break :blk i + @ctz(@as(u16, @bitCast(mask)));
            }
        }
        // Fallback to scalar search for remaining bytes
        break :blk std.mem.indexOfScalarPos(u8, raw, i, ':') orelse return error.InvalidHeader;
    };
    // Early bounds check
    if (colon_pos >= Header.MAX_KEY_LEN) return error.KeyTooLong;
    const value_length = raw.len - (colon_pos + 2); // +2 for ": "
    if (value_length >= Header.MAX_VALUE_LEN) return error.ValueTooLong;
    var h = Header{
        .key_len = colon_pos,
        .value_len = value_length,
    };
    // Single bounds check for key copy
    @memcpy(h.key_buf[0..colon_pos], raw[0..colon_pos]);
    // Skip colon and space, copy value
    if (colon_pos + 2 < raw.len) {
        const val = raw[colon_pos + 2 ..];
        @memcpy(h.value_buf[0..val.len], val);
    }

    return h;
}
