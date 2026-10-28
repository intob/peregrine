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
    /// Entries with new output. Deduplicated by the poster (`posted`
    /// flags), so normally at most one entry per connection or exchange
    /// and no allocation on post.
    entries: []Entry,
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
            self.entries[self.len] = entry;
            self.len += 1;
        } else {
            self.overflowed = true;
        }
        self.mutex.unlock();
        if (current != self) self.waker.wake();
    }

    /// Moves posted entries into `out`, returning how many. Call until 0.
    pub fn drain(self: *Self, out: []Entry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const n = @min(out.len, self.len);
        @memcpy(out[0..n], self.entries[self.len - n ..][0..n]);
        self.len -= n;
        return n;
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
