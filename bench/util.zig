//! Helpers shared by the benchmark programs.
const std = @import("std");
const linux = std.os.linux;

/// Builds big-endian TLS structures in a fixed buffer.
pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn bytes(w: *Writer, b: []const u8) void {
        @memcpy(w.buf[w.pos..][0..b.len], b);
        w.pos += b.len;
    }

    pub fn fill(w: *Writer, n: usize, v: u8) void {
        @memset(w.buf[w.pos..][0..n], v);
        w.pos += n;
    }

    pub fn int(w: *Writer, comptime T: type, v: T) void {
        std.mem.writeInt(T, w.buf[w.pos..][0..@divExact(@bitSizeOf(T), 8)], v, .big);
        w.pos += @divExact(@bitSizeOf(T), 8);
    }

    /// Room for a length of type T, filled in by `end`.
    pub fn begin(w: *Writer, comptime T: type) usize {
        const at = w.pos;
        w.pos += @divExact(@bitSizeOf(T), 8);
        return at;
    }

    pub fn end(w: *Writer, comptime T: type, at: usize) void {
        std.mem.writeInt(T, w.buf[at..][0..@divExact(@bitSizeOf(T), 8)], @intCast(w.pos - at - @divExact(@bitSizeOf(T), 8)), .big);
    }
};

pub fn parseIp(s: []const u8) ![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    for (&out) |*b| b.* = try std.fmt.parseInt(u8, it.next() orelse return error.BadIp, 10);
    if (it.next() != null) return error.BadIp;
    return out;
}

/// Linux only.
pub fn sleepMs(ms: u64) void {
    var ts: linux.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = linux.nanosleep(&ts, &ts);
}
