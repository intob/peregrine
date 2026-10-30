//! Packets sent in one packet number space and not yet acknowledged or
//! declared lost (RFC 9002 §A.1.1), with a record of each packet's frames
//! so lost data can be sent again. Packet numbers are consecutive, so a
//! packet is found by subtraction; records are kept in one array, and both
//! arrays drop their dead prefix as the oldest packets are resolved.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn SentPackets(comptime Record: type) type {
    return struct {
        const Self = @This();

        pub const Packet = struct {
            time_sent: u64,
            size: u32,
            ack_eliciting: bool,
            /// Counts towards bytes in flight (ACK-only packets don't).
            in_flight: bool,
            /// Sent with the ECT(0) codepoint.
            ecn: bool = false,
            /// A PMTU probe (pmtud.zig): its loss is a failed probe, not
            /// congestion (RFC 9000 §14.4).
            pmtu_probe: bool = false,
            live: bool = true,
            rec_start: u32,
            rec_count: u32,
        };

        packets: std.ArrayList(Packet) = .empty,
        /// Packet number of packets.items[0].
        base_pn: u64 = 0,
        records: std.ArrayList(Record) = .empty,
        /// Absolute index of records.items[0].
        rec_base: u64 = 0,
        /// Absolute index of the next record.
        rec_next: u64 = 0,
        live_count: u32 = 0,
        ack_eliciting_in_flight: u32 = 0,
        /// Index in `packets` of the oldest live packet (or its length).
        head: usize = 0,

        pub fn deinit(self: *Self, a: Allocator) void {
            self.packets.deinit(a);
            self.records.deinit(a);
        }

        pub fn nextPn(self: *const Self) u64 {
            return self.base_pn + self.packets.items.len;
        }

        /// Records for the packet being built; `add` takes them.
        pub fn addRecord(self: *Self, a: Allocator, r: Record) Allocator.Error!void {
            try self.records.append(a, r);
            self.rec_next += 1;
        }

        /// Drops records added since `mark` (a packet that wasn't sent).
        pub fn discardRecordsSince(self: *Self, mark: u64) void {
            const n: usize = @intCast(self.rec_next - mark);
            self.records.shrinkRetainingCapacity(self.records.items.len - n);
            self.rec_next = mark;
        }

        pub fn recordMark(self: *const Self) u64 {
            return self.rec_next;
        }

        pub const Flags = struct {
            ack_eliciting: bool = false,
            in_flight: bool = false,
            ecn: bool = false,
            pmtu_probe: bool = false,
        };

        /// Records the next packet, with the records added since `mark`.
        pub fn add(self: *Self, a: Allocator, mark: u64, time_sent: u64, size: u32, flags: Flags) Allocator.Error!void {
            if (self.live_count == 0) {
                // Nothing outstanding: start both arrays afresh.
                const pn = self.nextPn();
                self.packets.clearRetainingCapacity();
                self.base_pn = pn;
                self.head = 0;
                const keep: usize = @intCast(self.rec_next - mark);
                const from = self.records.items.len - keep;
                std.mem.copyForwards(Record, self.records.items[0..keep], self.records.items[from..]);
                self.records.shrinkRetainingCapacity(keep);
                self.rec_base = mark;
            }
            try self.packets.append(a, .{
                .time_sent = time_sent,
                .size = size,
                .ack_eliciting = flags.ack_eliciting,
                .in_flight = flags.in_flight,
                .ecn = flags.ecn,
                .pmtu_probe = flags.pmtu_probe,
                .rec_start = @intCast(mark - self.rec_base),
                .rec_count = @intCast(self.rec_next - mark),
            });
            self.live_count += 1;
            if (flags.ack_eliciting and flags.in_flight) self.ack_eliciting_in_flight += 1;
        }

        pub fn get(self: *Self, pn: u64) ?*Packet {
            if (pn < self.base_pn or pn >= self.nextPn()) return null;
            const p = &self.packets.items[@intCast(pn - self.base_pn)];
            return if (p.live) p else null;
        }

        pub fn recordsOf(self: *Self, p: *const Packet) []Record {
            return self.records.items[p.rec_start..][0..p.rec_count];
        }

        /// Marks a packet resolved (acknowledged or lost).
        pub fn remove(self: *Self, p: *Packet) void {
            std.debug.assert(p.live);
            p.live = false;
            self.live_count -= 1;
            if (p.ack_eliciting and p.in_flight) self.ack_eliciting_in_flight -= 1;
            while (self.head < self.packets.items.len and !self.packets.items[self.head].live) self.head += 1;
        }

        /// The oldest live packet's number, if any.
        pub fn oldest(self: *const Self) ?u64 {
            return if (self.head < self.packets.items.len) self.base_pn + self.head else null;
        }

        /// Drops the resolved prefix once it is a good part of the arrays.
        pub fn compact(self: *Self) void {
            const dead = self.head;
            if (dead == 0 or dead * 2 < self.packets.items.len) return;
            const rec_cut: u32 = if (dead < self.packets.items.len)
                self.packets.items[dead].rec_start
            else
                @intCast(self.records.items.len);
            const left = self.packets.items.len - dead;
            std.mem.copyForwards(Packet, self.packets.items[0..left], self.packets.items[dead..]);
            self.packets.shrinkRetainingCapacity(left);
            self.base_pn += dead;
            self.head = 0;
            for (self.packets.items) |*p| p.rec_start -= rec_cut;
            const rec_left = self.records.items.len - rec_cut;
            std.mem.copyForwards(Record, self.records.items[0..rec_left], self.records.items[rec_cut..]);
            self.records.shrinkRetainingCapacity(rec_left);
            self.rec_base += rec_cut;
        }

        /// Iterates live packets from the oldest.
        pub fn iterator(self: *Self) Iterator {
            return .{ .set = self, .i = self.head };
        }

        pub const Iterator = struct {
            set: *Self,
            i: usize,

            pub fn next(it: *Iterator) ?struct { pn: u64, packet: *Packet } {
                while (it.i < it.set.packets.items.len) {
                    const i = it.i;
                    it.i += 1;
                    const p = &it.set.packets.items[i];
                    if (p.live) return .{ .pn = it.set.base_pn + i, .packet = p };
                }
                return null;
            }
        };
    };
}

const testing = std.testing;

test "packets, records, removal and compaction" {
    const a = testing.allocator;
    var s: SentPackets(u32) = .{};
    defer s.deinit(a);
    var expected_records: [100][]const u32 = undefined;
    var rec_store: [100][3]u32 = undefined;
    for (0..100) |i| {
        const mark = s.recordMark();
        const n = i % 4;
        for (0..n) |j| {
            rec_store[i][j] = @intCast(i * 10 + j);
            try s.addRecord(a, rec_store[i][j]);
        }
        expected_records[i] = rec_store[i][0..n];
        // An abandoned packet's records go away.
        if (i % 7 == 0) {
            const m2 = s.recordMark();
            try s.addRecord(a, 999);
            s.discardRecordsSince(m2);
        }
        try s.add(a, mark, i, 1200, .{ .ack_eliciting = n > 0, .in_flight = true, .ecn = i % 3 == 0, .pmtu_probe = i % 5 == 0 });
    }
    try testing.expectEqual(@as(u64, 100), s.nextPn());
    // Resolve in a scattered order, checking records each time.
    var prng = std.Random.DefaultPrng.init(5);
    var order: [100]u64 = undefined;
    for (&order, 0..) |*o, i| o.* = i;
    prng.random().shuffle(u64, &order);
    for (order, 0..) |pn, k| {
        const p = s.get(pn).?;
        try testing.expectEqualSlices(u32, expected_records[pn], s.recordsOf(p));
        try testing.expectEqual(pn % 3 == 0, p.ecn);
        try testing.expectEqual(pn % 5 == 0, p.pmtu_probe);
        s.remove(p);
        try testing.expectEqual(@as(?*SentPackets(u32).Packet, null), s.get(pn));
        if (k % 10 == 0) s.compact();
        // Everything still live keeps its records.
        var it = s.iterator();
        while (it.next()) |e| try testing.expectEqualSlices(u32, expected_records[e.pn], s.recordsOf(e.packet));
    }
    try testing.expectEqual(@as(u32, 0), s.live_count);
    // After everything resolved, a new packet restarts the arrays.
    const mark = s.recordMark();
    try s.addRecord(a, 7);
    try s.add(a, mark, 0, 100, .{ .ack_eliciting = true, .in_flight = true });
    try testing.expectEqual(@as(u64, 100), s.oldest().?);
    try testing.expectEqualSlices(u32, &.{7}, s.recordsOf(s.get(100).?));
    try testing.expectEqual(@as(usize, 1), s.packets.items.len);
}
