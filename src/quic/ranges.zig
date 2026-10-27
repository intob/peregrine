//! A set of disjoint half-open u64 ranges, kept sorted: received packet
//! numbers (what to acknowledge), stream bytes received out of order, and
//! stream bytes acknowledged. The number of ranges is capped; what happens
//! at the cap is the caller's choice (`insert` reports it).
const std = @import("std");

pub const Range = struct {
    start: u64,
    /// Exclusive.
    end: u64,
};

pub const RangeSet = struct {
    const Self = @This();

    items: std.ArrayList(Range) = .empty,

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.items.deinit(allocator);
    }

    pub fn clear(self: *Self) void {
        self.items.clearRetainingCapacity();
    }

    pub inline fn count(self: *const Self) usize {
        return self.items.items.len;
    }

    pub inline fn isEmpty(self: *const Self) bool {
        return self.items.items.len == 0;
    }

    pub fn first(self: *const Self) ?Range {
        return if (self.items.items.len > 0) self.items.items[0] else null;
    }

    pub fn last(self: *const Self) ?Range {
        return if (self.items.items.len > 0) self.items.items[self.items.items.len - 1] else null;
    }

    /// Adds [start, end), merging with touching or overlapping ranges.
    /// Fails without changing the set when the result would have more than
    /// `max` ranges.
    pub fn insert(self: *Self, allocator: std.mem.Allocator, start: u64, end: u64, max: usize) error{ OutOfMemory, TooManyRanges }!void {
        if (start >= end) return;
        const items = self.items.items;
        // Fast path: appending at or after the end (in-order arrival).
        if (items.len > 0 and start >= items[items.len - 1].start) {
            const l = &items[items.len - 1];
            if (start <= l.end) {
                l.end = @max(l.end, end);
                return;
            }
            if (items.len >= max) return error.TooManyRanges;
            try self.items.append(allocator, .{ .start = start, .end = end });
            return;
        }
        // First range whose end reaches start, then every range that the new
        // one touches.
        var lo: usize = 0;
        while (lo < items.len and items[lo].end < start) lo += 1;
        var hi = lo;
        while (hi < items.len and items[hi].start <= end) hi += 1;
        if (lo == hi) {
            if (items.len >= max) return error.TooManyRanges;
            try self.items.insert(allocator, lo, .{ .start = start, .end = end });
            return;
        }
        const merged: Range = .{ .start = @min(start, items[lo].start), .end = @max(end, items[hi - 1].end) };
        self.items.replaceRangeAssumeCapacity(lo, hi - lo, &.{merged});
    }

    pub fn contains(self: *const Self, v: u64) bool {
        for (self.items.items) |r| {
            if (v < r.start) return false;
            if (v < r.end) return true;
        }
        return false;
    }

    /// Removes everything below `v`.
    pub fn removeBelow(self: *Self, v: u64) void {
        var n: usize = 0;
        for (self.items.items) |*r| {
            if (r.end <= v) {
                n += 1;
                continue;
            }
            if (r.start < v) r.start = v;
            break;
        }
        if (n > 0) self.items.replaceRangeAssumeCapacity(0, n, &.{});
    }

    /// Removes [start, end) (used for data being resent: no longer "lost").
    pub fn remove(self: *Self, allocator: std.mem.Allocator, start: u64, end: u64) error{OutOfMemory}!void {
        if (start >= end) return;
        var i: usize = 0;
        while (i < self.items.items.len) {
            const r = self.items.items[i];
            if (r.end <= start) {
                i += 1;
                continue;
            }
            if (r.start >= end) break;
            if (r.start < start and r.end > end) {
                // Split.
                self.items.items[i].end = start;
                try self.items.insert(allocator, i + 1, .{ .start = end, .end = r.end });
                return;
            }
            if (r.start < start) {
                self.items.items[i].end = start;
                i += 1;
            } else if (r.end > end) {
                self.items.items[i].start = end;
                i += 1;
            } else {
                _ = self.items.orderedRemove(i);
            }
        }
    }

    /// Drops the lowest range (to bound ACK frames).
    pub fn dropFirst(self: *Self) void {
        if (self.items.items.len > 0) _ = self.items.orderedRemove(0);
    }
};

const testing = std.testing;

test "insert merges and orders; caps are enforced" {
    const a = testing.allocator;
    var s: RangeSet = .{};
    defer s.deinit(a);
    try s.insert(a, 10, 20, 8);
    try s.insert(a, 30, 40, 8);
    try s.insert(a, 0, 5, 8);
    try s.insert(a, 20, 25, 8); // touches [10,20)
    try testing.expectEqualSlices(Range, &.{ .{ .start = 0, .end = 5 }, .{ .start = 10, .end = 25 }, .{ .start = 30, .end = 40 } }, s.items.items);
    try s.insert(a, 4, 31, 8); // bridges everything
    try testing.expectEqualSlices(Range, &.{.{ .start = 0, .end = 40 }}, s.items.items);
    try s.insert(a, 50, 51, 2);
    try testing.expectError(error.TooManyRanges, s.insert(a, 60, 61, 2));
    try testing.expectError(error.TooManyRanges, s.insert(a, 45, 46, 2));
    try s.insert(a, 40, 50, 2); // merging is always allowed
    try testing.expectEqualSlices(Range, &.{.{ .start = 0, .end = 51 }}, s.items.items);
    try testing.expect(s.contains(50));
    try testing.expect(!s.contains(51));
}

test "remove and removeBelow" {
    const a = testing.allocator;
    var s: RangeSet = .{};
    defer s.deinit(a);
    try s.insert(a, 0, 100, 8);
    try s.remove(a, 10, 20);
    try s.remove(a, 90, 200);
    try s.remove(a, 0, 5);
    try testing.expectEqualSlices(Range, &.{ .{ .start = 5, .end = 10 }, .{ .start = 20, .end = 90 } }, s.items.items);
    s.removeBelow(30);
    try testing.expectEqualSlices(Range, &.{.{ .start = 30, .end = 90 }}, s.items.items);
}

test "random inserts agree with a bitmap" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(7);
    const random = prng.random();
    for (0..200) |_| {
        var s: RangeSet = .{};
        defer s.deinit(a);
        var bits: [256]bool = @splat(false);
        for (0..30) |_| {
            const start = random.uintLessThan(u64, 250);
            const end = start + random.uintLessThan(u64, 6);
            if (random.boolean()) {
                s.insert(a, start, end, 1000) catch unreachable;
                for (start..end) |i| bits[i] = true;
            } else {
                try s.remove(a, start, end);
                for (start..end) |i| bits[i] = false;
            }
        }
        for (bits, 0..) |b, i| try testing.expectEqual(b, s.contains(i));
        // Disjoint, sorted, non-touching.
        for (s.items.items, 0..) |r, i| {
            try testing.expect(r.start < r.end);
            if (i > 0) try testing.expect(s.items.items[i - 1].end < r.start);
        }
    }
}
