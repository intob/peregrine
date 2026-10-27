//! Stream data buffers (RFC 9000 §2-§4): reassembly and flow control on
//! the receive side, retransmission bookkeeping on the send side. CRYPTO
//! streams use the same types without flow control. Buffers keep their
//! capacity when a stream slot is reused.
const std = @import("std");
const ranges = @import("./ranges.zig");
const RangeSet = ranges.RangeSet;
const Allocator = std.mem.Allocator;

/// Out-of-order fragments a stream may hold before the connection is
/// closed (fragmentation defence).
pub const max_fragments = 64;

pub const RecvError = error{
    /// Data past the advertised limit (FLOW_CONTROL_ERROR).
    FlowControl,
    /// Data past the final size, or a changed final size (FINAL_SIZE_ERROR).
    FinalSize,
    /// Too many out-of-order fragments (PROTOCOL_VIOLATION).
    Fragmented,
    OutOfMemory,
};

pub const RecvStream = struct {
    const Self = @This();

    /// Bytes from `read_off` on; out-of-order data sits at its offset.
    buf: std.ArrayList(u8) = .empty,
    /// Where `buf` starts in the stream (the application consumed below).
    read_off: u64 = 0,
    /// Received ranges above `read_off`.
    received: RangeSet = .{},
    final_size: ?u64 = null,
    /// Highest offset received (for connection flow control).
    highest: u64 = 0,
    /// The limit we advertised (MAX_STREAM_DATA); 0 for no limit.
    max_data: u64 = 0,

    pub fn reset(self: *Self, max_data: u64) void {
        self.buf.clearRetainingCapacity();
        self.received.clear();
        self.* = .{ .buf = self.buf, .received = self.received, .max_data = max_data };
    }

    pub fn deinit(self: *Self, a: Allocator) void {
        self.buf.deinit(a);
        self.received.deinit(a);
    }

    /// Stores a frame's data. Returns how far it raised `highest` (new
    /// bytes counted against the connection's limit).
    pub fn recv(self: *Self, a: Allocator, offset: u64, data: []const u8, fin: bool) RecvError!u64 {
        const end = offset + data.len;
        if (self.max_data != 0 and end > self.max_data) return error.FlowControl;
        if (self.final_size) |fs| {
            if (end > fs or (fin and end != fs)) return error.FinalSize;
        } else if (fin) {
            if (end < self.highest) return error.FinalSize;
            self.final_size = end;
        }
        const raised = end -| self.highest;
        self.highest = @max(self.highest, end);
        if (end <= self.read_off) return raised;
        // Drop what was already consumed.
        const skip: usize = @intCast(self.read_off -| offset);
        const start = offset + skip;
        const bytes = data[skip..];
        if (bytes.len == 0) return raised;
        const rel: usize = @intCast(start - self.read_off);
        if (self.buf.items.len < rel + bytes.len) {
            const old = self.buf.items.len;
            try self.buf.resize(a, rel + bytes.len);
            // Gaps are filled later; zero them so nothing stale is read.
            if (rel > old) @memset(self.buf.items[old..rel], 0);
        }
        @memcpy(self.buf.items[rel..][0..bytes.len], bytes);
        self.received.insert(a, start, start + bytes.len, max_fragments) catch |err| switch (err) {
            error.TooManyRanges => return error.Fragmented,
            error.OutOfMemory => return error.OutOfMemory,
        };
        return raised;
    }

    /// Contiguous bytes ready to read.
    pub fn readable(self: *const Self) []u8 {
        const first = self.received.first() orelse return self.buf.items[0..0];
        if (first.start != self.read_off) return self.buf.items[0..0];
        return self.buf.items[0..@intCast(first.end - first.start)];
    }

    pub fn consume(self: *Self, n: usize) void {
        if (n == 0) return;
        self.read_off += n;
        self.received.removeBelow(self.read_off);
        const left = self.buf.items.len - n;
        std.mem.copyForwards(u8, self.buf.items[0..left], self.buf.items[n..]);
        self.buf.shrinkRetainingCapacity(left);
    }

    /// Everything up to the final size has been read.
    pub fn finished(self: *const Self) bool {
        return if (self.final_size) |fs| self.read_off == fs else false;
    }

    /// All data has arrived (it may not all be read yet).
    pub fn complete(self: *const Self) bool {
        const fs = self.final_size orelse return false;
        if (self.read_off == fs) return true;
        const first = self.received.first() orelse return false;
        return first.start == self.read_off and first.end == fs;
    }
};

pub const SendStream = struct {
    const Self = @This();

    /// Unacknowledged data, from offset `base`.
    buf: std.ArrayList(u8) = .empty,
    base: u64 = 0,
    /// The next new byte to send.
    sent_off: u64 = 0,
    acked: RangeSet = .{},
    lost: RangeSet = .{},
    fin: bool = false,
    fin_sent: bool = false,
    fin_acked: bool = false,
    /// A FIN whose packet was lost.
    fin_lost: bool = false,
    /// The peer's limit (MAX_STREAM_DATA); maxInt for none.
    max_data: u64 = std.math.maxInt(u64),

    pub fn reset(self: *Self, max_data: u64) void {
        self.buf.clearRetainingCapacity();
        self.acked.clear();
        self.lost.clear();
        self.* = .{ .buf = self.buf, .acked = self.acked, .lost = self.lost, .max_data = max_data };
    }

    pub fn deinit(self: *Self, a: Allocator) void {
        self.buf.deinit(a);
        self.acked.deinit(a);
        self.lost.deinit(a);
    }

    /// Total bytes written.
    pub inline fn writeOff(self: *const Self) u64 {
        return self.base + self.buf.items.len;
    }

    pub fn write(self: *Self, a: Allocator, data: []const u8) Allocator.Error!void {
        std.debug.assert(!self.fin);
        try self.buf.appendSlice(a, data);
    }

    /// Room for `n` more bytes, to be filled and committed with `commit`.
    pub fn reserve(self: *Self, a: Allocator, n: usize) Allocator.Error![]u8 {
        try self.buf.ensureUnusedCapacity(a, n);
        return self.buf.unusedCapacitySlice()[0..n];
    }

    pub fn commit(self: *Self, n: usize) void {
        self.buf.items.len += n;
    }

    pub fn finish(self: *Self) void {
        self.fin = true;
    }

    /// Unsent or lost data (or FIN) waiting, flow control permitting for new
    /// data.
    pub fn hasPending(self: *const Self) bool {
        if (!self.lost.isEmpty() or self.fin_lost) return true;
        if (self.sent_off < self.writeOff() and self.sent_off < self.max_data) return true;
        return self.fin and !self.fin_sent and self.sent_off == self.writeOff();
    }

    /// New data is blocked by the peer's limit.
    pub fn blocked(self: *const Self) bool {
        return self.sent_off < self.writeOff() and self.sent_off >= self.max_data;
    }

    pub const Chunk = struct {
        offset: u64,
        data: []const u8,
        fin: bool,
        /// Retransmission: doesn't count against flow control again.
        retransmit: bool,
    };

    /// The next chunk to send, at most `max` bytes, and at most `credit`
    /// bytes of new data (connection flow control). Doesn't mark it sent.
    pub fn next(self: *const Self, max: usize, credit: u64) ?Chunk {
        if (self.lost.first()) |r| {
            const len: usize = @intCast(@min(r.end - r.start, max));
            if (len == 0) return null;
            const rel: usize = @intCast(r.start - self.base);
            const fin = self.fin_lost and r.start + len == self.writeOff();
            return .{ .offset = r.start, .data = self.buf.items[rel..][0..len], .fin = fin, .retransmit = true };
        }
        if (self.fin_lost and self.sent_off == self.writeOff()) {
            return .{ .offset = self.writeOff(), .data = &.{}, .fin = true, .retransmit = true };
        }
        const limit = @min(self.writeOff(), self.max_data, self.sent_off +| credit);
        const len: usize = @intCast(@min(limit -| self.sent_off, max));
        const fin = self.fin and self.sent_off + len == self.writeOff();
        if (len == 0 and !(fin and !self.fin_sent)) return null;
        const rel: usize = @intCast(self.sent_off - self.base);
        return .{ .offset = self.sent_off, .data = self.buf.items[rel..][0..len], .fin = fin, .retransmit = false };
    }

    pub fn onSent(self: *Self, a: Allocator, c: Chunk) Allocator.Error!void {
        if (c.retransmit) {
            try self.lost.remove(a, c.offset, c.offset + c.data.len);
            if (c.fin) self.fin_lost = false;
        } else {
            self.sent_off = c.offset + c.data.len;
        }
        if (c.fin) self.fin_sent = true;
    }

    pub fn onAcked(self: *Self, a: Allocator, offset: u64, len: u64, fin: bool) Allocator.Error!void {
        if (fin) {
            self.fin_acked = true;
            self.fin_lost = false;
        }
        const start = @max(offset, self.base);
        const end = offset + len;
        if (end <= start) return;
        // Ranges are capped generously: acks merge into few ranges.
        self.acked.insert(a, start, end, 1 << 20) catch |err| switch (err) {
            error.TooManyRanges => unreachable,
            error.OutOfMemory => return error.OutOfMemory,
        };
        try self.lost.remove(a, start, end);
        // Drop the acknowledged prefix.
        const first = self.acked.first().?;
        if (first.start == self.base) {
            const n: usize = @intCast(first.end - self.base);
            const left = self.buf.items.len - n;
            std.mem.copyForwards(u8, self.buf.items[0..left], self.buf.items[n..]);
            self.buf.shrinkRetainingCapacity(left);
            self.base = first.end;
            self.acked.removeBelow(self.base);
        }
    }

    pub fn onLost(self: *Self, a: Allocator, offset: u64, len: u64, fin: bool) Allocator.Error!void {
        if (fin and !self.fin_acked) self.fin_lost = true;
        var start = @max(offset, self.base);
        const end = offset + len;
        // Resend only what isn't acknowledged since.
        for (self.acked.items.items) |r| {
            if (r.end <= start) continue;
            if (r.start >= end) break;
            if (r.start > start) {
                self.lost.insert(a, start, r.start, 1 << 20) catch |err| switch (err) {
                    error.TooManyRanges => unreachable,
                    error.OutOfMemory => return error.OutOfMemory,
                };
            }
            start = @max(start, r.end);
        }
        if (start < end) {
            self.lost.insert(a, start, end, 1 << 20) catch |err| switch (err) {
                error.TooManyRanges => unreachable,
                error.OutOfMemory => return error.OutOfMemory,
            };
        }
    }

    /// Everything, FIN included, has been acknowledged.
    pub fn allAcked(self: *const Self) bool {
        return self.fin and self.fin_acked and self.buf.items.len == 0;
    }
};

const testing = std.testing;

test "receive: reordering, duplicates, flow control and final size" {
    const a = testing.allocator;
    var s: RecvStream = .{};
    defer s.deinit(a);
    s.reset(100);
    try testing.expectEqual(@as(u64, 10), try s.recv(a, 5, "world", false));
    try testing.expectEqual(@as(usize, 0), s.readable().len);
    try testing.expectEqual(@as(u64, 0), try s.recv(a, 0, "hello", false));
    try testing.expectEqualSlices(u8, "helloworld", s.readable());
    s.consume(3);
    try testing.expectEqualSlices(u8, "loworld", s.readable());
    // A retransmission of consumed and buffered bytes changes nothing.
    _ = try s.recv(a, 0, "hellowo", false);
    try testing.expectEqualSlices(u8, "loworld", s.readable());
    try testing.expectError(error.FlowControl, s.recv(a, 95, "123456", false));
    _ = try s.recv(a, 10, "!", true);
    try testing.expect(s.complete());
    try testing.expectError(error.FinalSize, s.recv(a, 10, "!!", false));
    try testing.expectError(error.FinalSize, s.recv(a, 5, "w", true));
    s.consume(s.readable().len);
    try testing.expect(s.finished());

    // A FIN below data already received.
    s.reset(0);
    _ = try s.recv(a, 0, "abcdef", false);
    try testing.expectError(error.FinalSize, s.recv(a, 0, "abc", true));

    // Fragmentation is bounded.
    s.reset(0);
    var i: u64 = 0;
    const err: ?RecvError = while (i < 1000) : (i += 1) {
        _ = s.recv(a, 1 + i * 2, "x", false) catch |e| break e;
    } else null;
    try testing.expectEqual(@as(?RecvError, error.Fragmented), err);
}

test "send: chunks, loss, retransmission, acks, flow control" {
    const a = testing.allocator;
    var s: SendStream = .{};
    defer s.deinit(a);
    s.reset(8);
    try s.write(a, "0123456789");
    s.finish();
    // Limited by MAX_STREAM_DATA (8) and by the frame room (5).
    var c = s.next(5, 100).?;
    try testing.expectEqualSlices(u8, "01234", c.data);
    try s.onSent(a, c);
    c = s.next(5, 100).?;
    try testing.expectEqualSlices(u8, "567", c.data);
    try testing.expect(!c.fin);
    try s.onSent(a, c);
    try testing.expect(s.blocked());
    try testing.expectEqual(@as(?SendStream.Chunk, null), s.next(5, 100));
    s.max_data = 100;
    // Connection credit limits new data too.
    c = s.next(5, 1).?;
    try testing.expectEqualSlices(u8, "8", c.data);
    c = s.next(5, 100).?;
    try testing.expectEqualSlices(u8, "89", c.data);
    try testing.expect(c.fin);
    try s.onSent(a, c);
    try testing.expect(!s.hasPending());
    // "567" is lost, "01234" acked: only the lost bytes come back.
    try s.onAcked(a, 0, 5, false);
    try testing.expectEqual(@as(u64, 5), s.base);
    try s.onLost(a, 5, 3, false);
    c = s.next(100, 0).?;
    try testing.expect(c.retransmit);
    try testing.expectEqual(@as(u64, 5), c.offset);
    try testing.expectEqualSlices(u8, "567", c.data);
    try s.onSent(a, c);
    // The FIN's packet is lost after its data was acked.
    try s.onAcked(a, 5, 3, false);
    try s.onAcked(a, 8, 2, false);
    try s.onLost(a, 8, 2, true);
    c = s.next(100, 0).?;
    try testing.expect(c.fin and c.data.len == 0);
    try s.onSent(a, c);
    try s.onAcked(a, 10, 0, true);
    try testing.expect(s.allAcked());
}

test "send: random loss and acknowledgement deliver every byte" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(3);
    const random = prng.random();
    for (0..50) |_| {
        var s: SendStream = .{};
        defer s.deinit(a);
        s.reset(std.math.maxInt(u64));
        var data: [3000]u8 = undefined;
        random.bytes(&data);
        try s.write(a, &data);
        s.finish();
        var r: RecvStream = .{};
        defer r.deinit(a);
        r.reset(0);
        var inflight: std.ArrayList(SendStream.Chunk) = .empty;
        defer inflight.deinit(a);
        var rounds: usize = 0;
        while (!s.allAcked()) : (rounds += 1) {
            try testing.expect(rounds < 10_000);
            while (s.next(random.intRangeAtMost(usize, 1, 400), 1 << 20)) |c| {
                try s.onSent(a, c);
                try inflight.append(a, c);
            }
            // Resolve a random in-flight chunk.
            if (inflight.items.len == 0) continue;
            const i = random.uintLessThan(usize, inflight.items.len);
            const c = inflight.swapRemove(i);
            if (random.uintLessThan(u8, 4) == 0) {
                try s.onLost(a, c.offset, c.data.len, c.fin);
            } else {
                // c.data may have moved since (acks compact the buffer).
                _ = try r.recv(a, c.offset, data[@intCast(c.offset)..][0..c.data.len], c.fin);
                try s.onAcked(a, c.offset, c.data.len, c.fin);
            }
        }
        try testing.expect(r.complete());
        try testing.expectEqualSlices(u8, &data, r.readable());
    }
}
