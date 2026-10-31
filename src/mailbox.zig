//! How other threads tell a worker that something of its own has new
//! output: a WebSocket connection, or an exchange. Each worker owns one
//! mailbox; posts name a slot in the worker's slab and the generation the
//! poster saw, so a stale post for a reused slot is ignored.
const std = @import("std");
const sys = @import("./sys.zig");

/// `ws`: an HTTP/1.1 connection carrying a WebSocket. `exchange`: an
/// exchange slot, which for a WebSocket over HTTP/2 or HTTP/3 is the
/// tunnel slot routing to its stream.
pub const Kind = enum(u1) { ws, exchange };

pub const Entry = packed struct(u64) {
    slot: u32,
    gen: u31,
    kind: Kind,
};

pub const Mailbox = struct {
    const Self = @This();

    mutex: sys.Mutex = .{},
    /// Entries with new output, a ring taken in the order posted (`head`
    /// the oldest), so that one posting again is served after the others.
    /// Deduplicated by the poster (`posted` flags), so normally at most one
    /// entry per connection or exchange and no allocation on post.
    entries: []Entry,
    head: usize = 0,
    len: usize = 0,
    /// Set if the list filled up (only possible with stale entries pending
    /// for reused slots); the worker then flushes everything instead.
    overflowed: bool = false,
    allocator: std.mem.Allocator,
    waker: sys.Waker,

    /// The mailbox of the worker running on this thread, so posts from the
    /// owning worker skip the wake-up syscall (it drains after each batch).
    threadlocal var current: ?*Self = null;

    pub fn init(allocator: std.mem.Allocator, capacity: usize, waker: sys.Waker) !Self {
        return .{
            .entries = try allocator.alloc(Entry, capacity),
            .allocator = allocator,
            .waker = waker,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.entries);
    }

    /// Called by the owning worker thread once it starts.
    pub fn bind(self: *Self) void {
        current = self;
    }

    /// Whether the calling thread is the owning worker.
    pub fn onWorkerThread(self: *const Self) bool {
        return current == self;
    }

    pub fn post(self: *Self, entry: Entry) void {
        self.mutex.lock();
        if (self.len < self.entries.len) {
            self.entries[(self.head + self.len) % self.entries.len] = entry;
            self.len += 1;
        } else {
            self.overflowed = true;
        }
        self.mutex.unlock();
        if (current != self) self.waker.wake();
    }

    /// Moves the oldest posted entries into `out`, returning how many.
    pub fn drain(self: *Self, out: []Entry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const n = @min(out.len, self.len);
        if (n == 0) return 0;
        const first = @min(n, self.entries.len - self.head);
        @memcpy(out[0..first], self.entries[self.head..][0..first]);
        @memcpy(out[first..n], self.entries[0 .. n - first]);
        self.head = (self.head + n) % self.entries.len;
        self.len -= n;
        return n;
    }

    /// How many entries are posted.
    pub fn pending(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.len;
    }

    /// Whether posts were dropped since the last call.
    pub fn takeOverflow(self: *Self) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const o = self.overflowed;
        self.overflowed = false;
        return o;
    }
};

test "mailbox: entries come out in the order posted, across the ring's end" {
    const testing = std.testing;
    var waker = try sys.Waker.init();
    defer waker.deinit();
    var m = try Mailbox.init(testing.allocator, 4, waker);
    defer m.deinit();
    m.bind();
    defer Mailbox.current = null;
    var out: [3]Entry = undefined;
    for (0..3) |i| m.post(.{ .slot = @intCast(i), .gen = 0, .kind = .ws });
    try testing.expectEqual(@as(usize, 2), m.drain(out[0..2]));
    try testing.expectEqual(@as(u32, 0), out[0].slot);
    try testing.expectEqual(@as(u32, 1), out[1].slot);
    // 2 is left; 3, 4 and 5 wrap past the end; a fifth entry overflows.
    for (3..6) |i| m.post(.{ .slot = @intCast(i), .gen = 0, .kind = .ws });
    try testing.expectEqual(@as(usize, 4), m.pending());
    m.post(.{ .slot = 6, .gen = 0, .kind = .ws });
    try testing.expect(m.takeOverflow());
    try testing.expectEqual(@as(usize, 3), m.drain(&out));
    for (out, 2..) |e, want| try testing.expectEqual(@as(u32, @intCast(want)), e.slot);
    try testing.expectEqual(@as(usize, 1), m.drain(&out));
    try testing.expectEqual(@as(u32, 5), out[0].slot);
    try testing.expectEqual(@as(usize, 0), m.drain(&out));
}

test "mailbox: threads posting while the owner drains in passes: every entry once, each thread's in order" {
    // Posts race the drains across the ring's end; at most 12 entries
    // per thread are outstanding (8 x 12 < 97, the ring's size), as the
    // worker's posted flags bound them.
    const testing = std.testing;
    const n_threads = 8;
    const per_thread = 20_000;
    var waker = try sys.Waker.init();
    defer waker.deinit();
    var m = try Mailbox.init(testing.allocator, 97, waker);
    defer m.deinit();
    m.bind();
    defer Mailbox.current = null;
    const Poster = struct {
        fn run(mb: *Mailbox, t: u32, room: *std.atomic.Value(u32)) void {
            var i: u32 = 0;
            while (i < per_thread) {
                if (room.load(.acquire) == 0) {
                    std.Thread.yield() catch {};
                    continue;
                }
                _ = room.fetchSub(1, .acq_rel);
                mb.post(.{ .slot = t, .gen = @intCast(i), .kind = .ws });
                i += 1;
            }
        }
    };
    var room: [n_threads]std.atomic.Value(u32) = @splat(.init(12));
    var threads: [n_threads]std.Thread = undefined;
    for (&threads, 0..) |*th, t| th.* = try std.Thread.spawn(.{}, Poster.run, .{ &m, @as(u32, @intCast(t)), &room[t] });
    var next: [n_threads]u32 = @splat(0);
    var total: usize = 0;
    var out: [64]Entry = undefined;
    while (total < n_threads * per_thread) {
        // One pass: what was posted when it began, in batches.
        var left = m.pending();
        if (left == 0) std.Thread.yield() catch {};
        while (left > 0) {
            const n = m.drain(out[0..@min(left, out.len)]);
            try testing.expect(n > 0);
            left -= n;
            for (out[0..n]) |e| {
                try testing.expectEqual(next[e.slot], @as(u32, e.gen));
                next[e.slot] += 1;
                _ = room[e.slot].fetchAdd(1, .acq_rel);
            }
            total += n;
        }
    }
    for (threads) |th| th.join();
    try testing.expect(!m.takeOverflow());
    try testing.expectEqual(@as(usize, 0), m.pending());
    for (next) |n| try testing.expectEqual(@as(u32, per_thread), n);
}
