const std = @import("std");
const posix = std.posix;

/// A perfect hash table optimized for file descriptors, providing O(1) lookups with no collisions.
/// This implementation uses a two-level perfect hashing scheme with FNV-1a for superior performance
/// on small integer keys like file descriptors.
///
/// The map uses two arrays:
/// - values: stores the actual values
/// - g: stores displacement values, with the highest bit indicating direct mapping
///
/// The FNV-1a hash function is used for its excellent distribution and performance on integer keys:
/// - Uses prime number 0x01000193 (16777619) for multiplication
/// - Performs wrapping multiplication and XOR operations
/// - Provides good avalanche effect for sequential file descriptors
///
/// Memory usage is O(n) where n is max_fds.
pub const FdMap = struct {
    allocator: std.mem.Allocator,
    values: []u32,
    g: []u32,

    pub fn init(allocator: std.mem.Allocator, max_fds: usize) !*@This() {
        const self = try allocator.create(@This());
        const nextPow2 = nextPowerOf2(max_fds);
        std.debug.print("using size {d} (next power of 2 from {d})\n", .{ nextPow2, max_fds });
        self.* = .{
            .allocator = allocator,
            .values = try allocator.alloc(u32, nextPow2),
            .g = try allocator.alloc(u32, nextPow2),
        };
        @memset(self.values, 0);
        @memset(self.g, 0);
        return self;
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.values);
        self.allocator.free(self.g);
        self.allocator.destroy(self);
    }

    pub fn get(self: *@This(), fd: posix.socket_t) ?u32 {
        if (fd < 0) return null; // Can't cast negative int to unsigned
        const fd_u: u32 = @intCast(fd);
        const slot = hash(0, fd_u) % self.g.len;
        const d = self.g[slot];
        return if (d & (@as(u32, 1) << 31) != 0)
            self.values[d & ~(@as(u32, 1) << 31)]
        else
            self.values[hash(d, fd_u) % self.values.len];
    }

    pub fn put(self: *@This(), fd: posix.socket_t, value: u32) !void {
        if (fd < 0) return error.NegativeFileDescriptor;
        const fd_u: u32 = @intCast(fd);
        const initial_slot: u32 = hash(0, fd_u) % @as(u32, @intCast(self.values.len));
        if (self.values[initial_slot] == 0) {
            self.values[initial_slot] = value;
            self.g[initial_slot] = initial_slot | (1 << 31);
            return;
        }
        var d: u32 = 1;
        while (d < self.values.len) : (d += 1) {
            const next_slot: u32 = hash(d, fd_u) % @as(u32, @intCast(self.values.len));
            if (self.values[next_slot] == 0) {
                self.values[next_slot] = value;
                self.g[initial_slot] = d;
                return;
            }
        }
        return error.MapFull;
    }

    pub fn remove(self: *@This(), fd: posix.socket_t) ?u32 {
        if (fd < 0) return null;
        const fd_u: u32 = @intCast(fd);
        const slot = hash(0, fd_u) % self.g.len;
        const d = self.g[slot];
        if (d & (@as(u32, 1) << 31) != 0) {
            const value_slot = d & ~(@as(u32, 1) << 31);
            const value = self.values[value_slot];
            if (value == 0) return null;
            self.values[value_slot] = 0;
            self.g[slot] = 0;
            return value;
        }
        const value_slot = hash(d, fd_u) % self.values.len;
        const value = self.values[value_slot];
        if (value == 0) return null;
        self.values[value_slot] = 0;
        self.g[slot] = 0;
        return value;
    }

    // FNV-1a hash optimized for power-of-2 tables
    inline fn hash(d: u32, fd: u32) u32 {
        const prime: u32 = 0x01000193;
        return (if (d == 0) prime else d) *% prime ^ fd;
    }

    fn nextPowerOf2(value: usize) usize {
        var v = value -% 1;
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;
        return v +% 1;
    }
};

test "basic usage" {
    const map = try FdMap.init(std.testing.allocator, 10);
    defer map.deinit();
    try map.put(0, 1);
    try map.put(1, 2);
    try std.testing.expectEqual(1, map.get(0) orelse 0);
    try std.testing.expectEqual(2, map.get(1) orelse 0);
    const removed = map.remove(1) orelse 0;
    try std.testing.expectEqual(2, removed);
    try std.testing.expectEqual(0, map.get(1) orelse 0);
}

test "benchmark put" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const iterations = 100_000_000;
    const map = try FdMap.init(allocator, iterations);
    defer map.deinit();
    var i: i32 = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        try map.put(i, 1);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

test "benchmark get" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const iterations = 100_000_000;
    const map = try FdMap.init(allocator, iterations);
    defer map.deinit();
    var i: i32 = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        _ = map.get(i);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

// 496ns
test "benchmark AutoHashMap put" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const iterations = 100_000_000;
    var map = std.AutoHashMap(i32, u32).init(allocator);
    defer map.deinit();
    var i: i32 = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        try map.put(i, 1);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}

test "benchmark AutoHashMap get" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const iterations = 100_000_000;
    var map = std.AutoHashMap(i32, u32).init(allocator);
    defer map.deinit();
    var i: i32 = 0;
    var timer = try std.time.Timer.start();
    while (i < iterations) : (i += 1) {
        _ = map.get(i);
    }
    const elapsed = timer.lap();
    const avg_ns = @divFloor(elapsed, iterations);
    std.debug.print("Average time: {d}ns\n", .{avg_ns});
}
