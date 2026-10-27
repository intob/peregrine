//! A request that outlives `handleRequest`: `resp.later()` answers it
//! later from any thread, `resp.stream()` streams its body. Exchange state
//! lives in a per-worker slab (no allocation per request) and handlers
//! hold a value handle `{ slab, slot, generation }`; every call checks the
//! generation, so a handle kept after the exchange ended returns
//! `error.Closed` instead of touching reused memory.
//!
//! Threading: handle methods may be called from any thread. They take the
//! entry's mutex, queue, and post the entry to the owning worker's mailbox
//! (deduplicated; a wake-up syscall only from another thread). The worker
//! drains the queue into the connection's output with HTTP/1.1 framing
//! (`fill`), on its own thread.
const std = @import("std");
const sys = @import("../sys.zig");
const date = @import("./date.zig");
const Out = @import("./session.zig").Out;
const Header = @import("../header.zig").Header;
const Status = @import("../status.zig").Status;
const Mailbox = @import("../mailbox.zig").Mailbox;

pub const Options = struct {
    /// Unsent bytes per exchange before `write` fails with WouldBlock.
    max_queue_bytes: usize = 4 * 1024 * 1024,
    /// Seconds a `later()` exchange may wait for its response.
    response_timeout_s: u32 = 30,
    /// Seconds a streaming exchange may go without progress.
    request_timeout_s: u32 = 10,
    /// Serialised response trailers per exchange are limited to this.
    max_trailer_bytes: usize = 2048,
};

pub const Error = error{
    /// The exchange ended: the client went away, it was finished or
    /// aborted, or it timed out.
    Closed,
    /// `respond`/`startStream` after a response was already given, or
    /// `write`/`finish` before `startStream` on a `later()` exchange.
    WrongState,
    /// The queue is full; `handleWritable` is called once it drains.
    WouldBlock,
    /// More body than the declared Content-Length, or less at `finish`.
    ContentLengthMismatch,
    InvalidHeader,
    TrailersTooLarge,
    OutOfMemory,
};

/// Called on the worker thread once borrowed bytes have been written (or
/// the exchange ended with them unsent).
pub const Release = struct {
    ctx: ?*anyopaque,
    func: *const fn (ctx: ?*anyopaque) void,

    pub fn call(self: Release) void {
        self.func(self.ctx);
    }
};

/// The status line and headers of a response given through a handle.
pub const Head = struct {
    status: Status = .ok,
    headers: []const Header = &.{},
    /// Set to send a Content-Length body instead of chunked framing.
    content_length: ?usize = null,
};

/// How the body goes on the wire.
pub const Framing = enum(u8) {
    chunked,
    /// A Content-Length body.
    length,
    /// An HTTP/1.0 client: no framing, the connection closes after.
    close_delimited,
    /// A HEAD request: the body is dropped.
    none,
};

const State = enum(u8) {
    /// `later()`: nothing sent, waiting for `respond` or `startStream`.
    later,
    /// Head known (sent by the session, or queued here), body flowing.
    streaming,
    /// `finish` was called; the queue ends with the last chunk.
    finished,
    /// `abort`, a timeout, or an error: close the connection.
    aborted,
};

const Segment = union(enum) {
    copied: usize,
    borrowed: struct { bytes: []const u8, release: ?Release },
};

pub const Entry = struct {
    const Self = @This();

    // -- Owned by the worker --
    gen: u32 = 0,
    active: bool = false,
    conn_slot: u32 = 0,
    conn_gen: u32 = 0,
    /// The worker bound the entry to its connection (posts before that
    /// are ignored; the bind flushes).
    bound: bool = false,
    framing: Framing = .chunked,
    keep_alive: bool = true,
    is_head: bool = false,
    http10: bool = false,
    /// HTTP/2: the stream this exchange answers (0 on HTTP/1.1).
    stream_id: u32 = 0,
    /// Head to write before the body (`later()` exchanges): the session
    /// already wrote it for `stream()`.
    head_pending: bool = false,
    /// Monotonic seconds; checked once a second by the worker.
    deadline: u32 = 0,

    // -- Guarded by `mutex` --
    mutex: sys.Mutex = .{},
    state: State = .later,
    posted: bool = false,
    /// Copied bytes, in order; `segments` says how they interleave with
    /// borrowed bytes.
    bytes: std.ArrayList(u8) = .empty,
    bytes_pos: usize = 0,
    segments: std.ArrayList(Segment) = .empty,
    /// Bytes queued and not yet taken by the worker.
    queued: usize = 0,
    /// `write` failed with WouldBlock: call handleWritable when it drains.
    wants_writable: bool = false,
    /// Serialised "name: value\r\n" lines of a `respond`/`startStream`
    /// head, then (after `finish`) the trailers.
    head: std.ArrayList(u8) = .empty,
    head_status: Status = .ok,
    head_length: ?usize = null,
    trailers: std.ArrayList(u8) = .empty,
    /// Bytes written so far of a Content-Length body (any thread).
    written: usize = 0,
    /// The deadline the handler asked for, taken by the worker.
    new_deadline: ?u32 = null,

    fn clear(self: *Self, allocator: std.mem.Allocator) void {
        for (self.segments.items) |seg| {
            if (seg == .borrowed) {
                if (seg.borrowed.release) |r| r.call();
            }
        }
        self.segments.clearRetainingCapacity();
        self.bytes.clearRetainingCapacity();
        self.bytes_pos = 0;
        self.head.clearRetainingCapacity();
        self.trailers.clearRetainingCapacity();
        self.queued = 0;
        self.wants_writable = false;
        self.posted = false;
        self.written = 0;
        self.head_length = null;
        self.new_deadline = null;
        _ = allocator;
    }

    fn free(self: *Self, allocator: std.mem.Allocator) void {
        self.clear(allocator);
        self.segments.deinit(allocator);
        self.bytes.deinit(allocator);
        self.head.deinit(allocator);
        self.trailers.deinit(allocator);
    }
};

/// Per-worker storage for exchanges.
pub const Slab = struct {
    const Self = @This();

    entries: []Entry,
    free_slots: []u32,
    free_len: usize,
    allocator: std.mem.Allocator,
    mailbox: *Mailbox,
    opts: Options,
    /// Exchanges in use (for the worker's timeout scan).
    active_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: u32, mailbox: *Mailbox, opts: Options) !Self {
        const entries = try allocator.alloc(Entry, capacity);
        errdefer allocator.free(entries);
        @memset(entries, .{});
        const free_slots = try allocator.alloc(u32, capacity);
        for (free_slots, 0..) |*s, i| s.* = @intCast(capacity - 1 - i);
        return .{
            .entries = entries,
            .free_slots = free_slots,
            .free_len = capacity,
            .allocator = allocator,
            .mailbox = mailbox,
            .opts = opts,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.entries) |*e| e.free(self.allocator);
        self.allocator.free(self.entries);
        self.allocator.free(self.free_slots);
    }

    /// Worker thread: takes a free entry. The connection is bound by the
    /// worker once the session returns `.wait`.
    pub fn create(self: *Self, now: u32) error{TooManyExchanges}!Exchange {
        if (self.free_len == 0) return error.TooManyExchanges;
        self.free_len -= 1;
        const slot = self.free_slots[self.free_len];
        const e = &self.entries[slot];
        e.mutex.lock();
        e.gen +%= 1;
        if (e.gen == 0) e.gen = 1;
        e.active = true;
        e.bound = false;
        e.state = .later;
        e.head_pending = false;
        e.framing = .chunked;
        e.keep_alive = true;
        e.stream_id = 0;
        // Deadlines are whole seconds: +1 so at least the timeout passes.
        e.deadline = now +% self.opts.response_timeout_s +% 1;
        e.mutex.unlock();
        self.active_count += 1;
        return .{ .slab = self, .slot = slot, .gen = e.gen };
    }

    /// Worker thread: ends an exchange. Later calls on handles return
    /// Closed; queued borrowed bytes are released.
    pub fn release(self: *Self, slot: u32) void {
        const e = &self.entries[slot];
        e.mutex.lock();
        e.active = false;
        e.clear(self.allocator);
        e.mutex.unlock();
        self.free_slots[self.free_len] = slot;
        self.free_len += 1;
        self.active_count -= 1;
    }

    pub fn entry(self: *Self, slot: u32) *Entry {
        return &self.entries[slot];
    }

    /// Worker thread, for `resp.stream()`: the head goes out with the
    /// session's response, so the body may be written at once.
    pub fn beginStream(self: *Self, slot: u32, content_length: ?usize) void {
        const e = &self.entries[slot];
        e.mutex.lock();
        e.state = .streaming;
        e.head_length = content_length;
        e.mutex.unlock();
    }

    /// Worker thread: the handle for an active slot.
    pub fn handle(self: *Self, slot: u32) Exchange {
        return .{ .slab = self, .slot = slot, .gen = self.entries[slot].gen };
    }
};

/// What `fill` moved into the output.
pub const Filled = struct {
    /// Bytes were added to `out`.
    progressed: bool = false,
    /// Borrowed bytes now in `out.body`; release once written.
    release: ?Release = null,
    /// Everything is in `out`: the exchange is over once it is written.
    done: bool = false,
    /// Call `handleWritable` (after writing).
    notify: bool = false,
    /// `abort` was called, or the body didn't match its Content-Length.
    aborted: bool = false,
};

/// The handle a handler holds. A value; copy it freely.
pub const Exchange = struct {
    const Self = @This();

    slab: *Slab,
    slot: u32,
    gen: u32,

    /// Locks the entry if the handle is still current.
    fn lock(self: Self) Error!*Entry {
        const e = &self.slab.entries[self.slot];
        e.mutex.lock();
        if (!e.active or e.gen != self.gen) {
            e.mutex.unlock();
            return error.Closed;
        }
        return e;
    }

    fn post(self: Self, e: *Entry) void {
        const do_post = !e.posted;
        e.posted = true;
        e.mutex.unlock();
        if (do_post) self.slab.mailbox.post(.{ .kind = .exchange, .slot = self.slot, .gen = @intCast(self.gen & 0x7fffffff) });
    }

    /// Answers a `later()` exchange with a complete response. The body is
    /// copied.
    pub fn respond(self: Self, head: Head, body: []const u8) Error!void {
        const e = try self.lock();
        errdefer e.mutex.unlock();
        if (e.state != .later) return error.WrongState;
        try setHead(e, self.slab.allocator, head);
        e.head_length = body.len;
        try e.bytes.appendSlice(self.slab.allocator, body);
        if (body.len > 0) try e.segments.append(self.slab.allocator, .{ .copied = body.len });
        e.queued += body.len;
        e.state = .finished;
        self.post(e);
    }

    /// Turns a `later()` exchange into a stream: the head is sent, then
    /// `write` and `finish`.
    pub fn startStream(self: Self, head: Head) Error!void {
        const e = try self.lock();
        errdefer e.mutex.unlock();
        if (e.state != .later) return error.WrongState;
        try setHead(e, self.slab.allocator, head);
        e.head_length = head.content_length;
        e.state = .streaming;
        self.post(e);
    }

    fn setHead(e: *Entry, allocator: std.mem.Allocator, head: Head) Error!void {
        e.head.clearRetainingCapacity();
        for (head.headers) |h| try appendHeaderLine(&e.head, allocator, h);
        e.head_status = head.status;
    }

    /// Queues body bytes (copied). Empty writes are ignored.
    pub fn write(self: Self, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        const e = try self.lock();
        errdefer e.mutex.unlock();
        try checkWrite(e, self.slab.opts, bytes.len);
        try e.bytes.appendSlice(self.slab.allocator, bytes);
        // Merge with a trailing copied segment.
        if (e.segments.items.len > 0 and e.segments.items[e.segments.items.len - 1] == .copied) {
            e.segments.items[e.segments.items.len - 1].copied += bytes.len;
        } else {
            try e.segments.append(self.slab.allocator, .{ .copied = bytes.len });
        }
        e.queued += bytes.len;
        e.written += bytes.len;
        self.post(e);
    }

    /// Queues bytes without copying them. They must stay valid and
    /// unchanged until `release` is called on the worker thread, which
    /// also happens if the exchange ends with them unsent.
    pub fn writeBorrowed(self: Self, bytes: []const u8, release: ?Release) Error!void {
        if (bytes.len == 0) {
            if (release) |r| r.call();
            return;
        }
        const e = try self.lock();
        errdefer e.mutex.unlock();
        try checkWrite(e, self.slab.opts, bytes.len);
        try e.segments.append(self.slab.allocator, .{ .borrowed = .{ .bytes = bytes, .release = release } });
        e.queued += bytes.len;
        e.written += bytes.len;
        self.post(e);
    }

    fn checkWrite(e: *Entry, opts: Options, len: usize) Error!void {
        if (e.state != .streaming) return error.WrongState;
        if (e.head_length) |n| {
            if (e.written + len > n) return error.ContentLengthMismatch;
        }
        if (e.queued + len > opts.max_queue_bytes) {
            e.wants_writable = true;
            return error.WouldBlock;
        }
    }

    /// Ends the body. With chunked framing the trailers go in the last
    /// chunk; otherwise they are dropped (RFC 9110 §6.5).
    pub fn finish(self: Self, trailers: []const Header) Error!void {
        const e = try self.lock();
        errdefer e.mutex.unlock();
        if (e.state != .streaming) return error.WrongState;
        if (e.head_length) |n| {
            if (e.written != n) {
                e.state = .aborted;
                self.post(e);
                return error.ContentLengthMismatch;
            }
        }
        e.trailers.clearRetainingCapacity();
        for (trailers) |h| {
            try appendHeaderLine(&e.trailers, self.slab.allocator, h);
            if (e.trailers.items.len > self.slab.opts.max_trailer_bytes) {
                e.trailers.clearRetainingCapacity();
                return error.TrailersTooLarge;
            }
        }
        e.state = .finished;
        self.post(e);
    }

    /// Gives up: the connection is closed, so the client sees a truncated
    /// response (or none, for a `later()` exchange). Queued bytes are
    /// dropped.
    pub fn abort(self: Self) Error!void {
        const e = try self.lock();
        e.state = .aborted;
        self.post(e);
    }

    /// Sets the time the exchange may take from now, in seconds (a
    /// `later()` exchange's response, or a stream's next progress).
    pub fn setTimeout(self: Self, seconds: u32) Error!void {
        const e = try self.lock();
        e.new_deadline = sys.monotonicSeconds() +% seconds +% 1;
        self.post(e);
    }

    /// Whether the handle still refers to a live exchange.
    pub fn isOpen(self: Self) bool {
        const e = self.lock() catch return false;
        e.mutex.unlock();
        return true;
    }

    // -- Worker side -------------------------------------------------------

    /// Worker thread: moves queued output into `out` with the exchange's
    /// framing. `out` must be empty. Returns what happened; after writing
    /// `out`, call `release` if set, and `handleWritable` if `notify`.
    pub fn fill(self: Self, out: *Out, date_line: *const [date.header_len]u8, now: u32) Filled {
        const e = &self.slab.entries[self.slot];
        std.debug.assert(e.active and e.gen == self.gen);
        var r: Filled = .{};
        e.mutex.lock();
        defer e.mutex.unlock();
        e.posted = false;
        if (e.new_deadline) |d| {
            e.deadline = d;
            e.new_deadline = null;
        }
        if (e.state == .aborted) {
            r.aborted = true;
            return r;
        }
        if (e.state == .later) return r;
        if (e.head_pending) {
            // A later() exchange answered: the framing follows from the
            // request and the head.
            e.framing = streamFraming(e.head_status, e.is_head, e.http10, e.head_length);
            if (e.framing == .close_delimited) e.keep_alive = false;
            writeHead(e, out, date_line);
            e.head_pending = false;
            r.progressed = true;
        }
        // One borrowed body per fill: it goes in `out.body` by reference.
        while (e.segments.items.len > 0 and out.body.len == 0) {
            const seg = &e.segments.items[0];
            switch (seg.*) {
                .copied => |*len| {
                    const n = takeCopied(e, out, len.*);
                    if (n == 0) break;
                    len.* -= n;
                    e.bytes_pos += n;
                    e.queued -= n;
                    r.progressed = true;
                    if (len.* == 0) {
                        _ = e.segments.orderedRemove(0);
                        if (e.segments.items.len == 0) {
                            e.bytes.clearRetainingCapacity();
                            e.bytes_pos = 0;
                        }
                    }
                },
                .borrowed => |b| {
                    if (e.framing == .none) {
                        if (b.release) |rel| rel.call();
                    } else if (e.framing == .chunked) {
                        if (out.free() < 24) break;
                        out.len += std.fmt.printInt(out.buf[out.len..], b.bytes.len, 16, .lower, .{});
                        out.append("\r\n");
                        out.body = b.bytes;
                        out.tail = "\r\n";
                        r.release = b.release;
                    } else {
                        out.body = b.bytes;
                        r.release = b.release;
                    }
                    e.queued -= b.bytes.len;
                    r.progressed = true;
                    _ = e.segments.orderedRemove(0);
                },
            }
        }
        if (e.segments.items.len == 0 and e.state == .finished) {
            if (e.framing == .chunked) {
                const need = 3 + e.trailers.items.len + 2;
                if (out.free() >= need and out.body.len == 0) {
                    out.append("0\r\n");
                    out.append(e.trailers.items);
                    out.append("\r\n");
                    r.done = true;
                    r.progressed = true;
                }
            } else {
                r.done = true;
            }
        }
        if (r.progressed) e.deadline = now +% self.slab.opts.request_timeout_s +% 1;
        if (e.wants_writable and e.queued <= self.slab.opts.max_queue_bytes / 2) {
            e.wants_writable = false;
            r.notify = true;
        }
        return r;
    }

    /// Copies up to `len` queued bytes into `out`, framed. Returns how
    /// many were taken (0 if nothing fits).
    fn takeCopied(e: *Entry, out: *Out, len: usize) usize {
        const src = e.bytes.items[e.bytes_pos..][0..len];
        switch (e.framing) {
            .none => return len,
            .chunked => {
                // "{x}\r\n" + data + "\r\n": up to 16 + 2 + 2 of framing.
                if (out.free() < 24) return 0;
                const n = @min(len, out.free() - 20);
                out.len += std.fmt.printInt(out.buf[out.len..], n, 16, .lower, .{});
                out.append("\r\n");
                out.append(src[0..n]);
                out.append("\r\n");
                return n;
            },
            .length, .close_delimited => {
                const n = @min(len, out.free());
                out.append(src[0..n]);
                return n;
            },
        }
    }

    /// The head of a `later()` response, with the server's headers.
    fn writeHead(e: *Entry, out: *Out, date_line: *const [date.header_len]u8) void {
        out.append("HTTP/1.1 ");
        out.append(e.head_status.toString());
        out.append("\r\n");
        out.append(e.head.items);
        switch (e.framing) {
            .length => {
                out.append("content-length: ");
                out.len += std.fmt.printInt(out.buf[out.len..], e.head_length.?, 10, .lower, .{});
                out.append("\r\n");
            },
            .chunked => out.append("transfer-encoding: chunked\r\n"),
            .close_delimited => {},
            .none => if (e.head_status.allowsContentLength()) {
                if (e.head_length) |n| {
                    out.append("content-length: ");
                    out.len += std.fmt.printInt(out.buf[out.len..], n, 10, .lower, .{});
                    out.append("\r\n");
                }
            },
        }
        out.append(date_line);
        if (!e.keep_alive) out.append("connection: close\r\n");
        out.append("\r\n");
    }
};

/// What `h2Poll` found.
pub const H2Poll = struct {
    /// A response head to send before any data: the status and the
    /// serialised "name: value\r\n" lines (valid until the exchange ends).
    head: ?struct { status: Status, headers: []const u8, content_length: ?usize } = null,
    /// Body bytes copied into `dest`.
    n: usize = 0,
    /// Every queued byte has been taken and `finish` was called;
    /// `trailers` are the serialised trailer lines, possibly empty.
    end: bool = false,
    trailers: []const u8 = "",
    /// Data remains queued (dest was too small).
    more: bool = false,
    notify: bool = false,
    aborted: bool = false,
    progressed: bool = false,
};

/// Worker thread, for HTTP/2: moves queued output into `dest` (a DATA
/// frame's payload), copying borrowed bytes too (releasing them once
/// fully taken). The caller frames it.
pub fn h2Poll(ex: Exchange, dest: []u8, now: u32) H2Poll {
    const e = &ex.slab.entries[ex.slot];
    std.debug.assert(e.active and e.gen == ex.gen);
    var r: H2Poll = .{};
    e.mutex.lock();
    defer e.mutex.unlock();
    e.posted = false;
    if (e.new_deadline) |d| {
        e.deadline = d;
        e.new_deadline = null;
    }
    if (e.state == .aborted) {
        r.aborted = true;
        return r;
    }
    if (e.state == .later) return r;
    if (e.head_pending) {
        r.head = .{ .status = e.head_status, .headers = e.head.items, .content_length = e.head_length };
        e.head_pending = false;
        r.progressed = true;
    }
    while (e.segments.items.len > 0 and r.n < dest.len) {
        const room = dest.len - r.n;
        const seg = &e.segments.items[0];
        switch (seg.*) {
            .copied => |*len| {
                const n = @min(len.*, room);
                @memcpy(dest[r.n..][0..n], e.bytes.items[e.bytes_pos..][0..n]);
                len.* -= n;
                e.bytes_pos += n;
                r.n += n;
                e.queued -= n;
                if (len.* == 0) {
                    _ = e.segments.orderedRemove(0);
                    if (e.segments.items.len == 0) {
                        e.bytes.clearRetainingCapacity();
                        e.bytes_pos = 0;
                    }
                }
            },
            .borrowed => |*b| {
                const n = @min(b.bytes.len, room);
                @memcpy(dest[r.n..][0..n], b.bytes[0..n]);
                b.bytes = b.bytes[n..];
                r.n += n;
                e.queued -= n;
                if (b.bytes.len == 0) {
                    if (b.release) |rel| rel.call();
                    _ = e.segments.orderedRemove(0);
                }
            },
        }
    }
    if (r.n > 0) r.progressed = true;
    r.more = e.segments.items.len > 0;
    if (!r.more and e.state == .finished) {
        r.end = true;
        r.trailers = e.trailers.items;
    }
    if (r.progressed) e.deadline = now +% ex.slab.opts.request_timeout_s +% 1;
    if (e.wants_writable and e.queued <= ex.slab.opts.max_queue_bytes / 2) {
        e.wants_writable = false;
        r.notify = true;
    }
    return r;
}

/// How a response body goes on the wire, from the request and the head.
pub fn streamFraming(status: Status, is_head: bool, http10: bool, content_length: ?usize) Framing {
    if (is_head or !status.allowsContentLength()) return .none;
    if (content_length != null) return .length;
    if (http10) return .close_delimited;
    return .chunked;
}

pub fn appendHeaderLine(list: *std.ArrayList(u8), allocator: std.mem.Allocator, h: Header) Error!void {
    if (h.key.len == 0 or std.mem.indexOfAny(u8, h.key, "\r\n:") != null) return error.InvalidHeader;
    if (std.mem.indexOfAny(u8, h.value, "\r\n") != null) return error.InvalidHeader;
    for (Header.reserved) |r| {
        if (std.ascii.eqlIgnoreCase(h.key, r)) return error.InvalidHeader;
    }
    try list.ensureUnusedCapacity(allocator, h.key.len + 2 + h.value.len + 2);
    list.appendSliceAssumeCapacity(h.key);
    list.appendSliceAssumeCapacity(": ");
    list.appendSliceAssumeCapacity(h.value);
    list.appendSliceAssumeCapacity("\r\n");
}

// ---------------------------------------------------------------------------
// Tests: the slab and framing without a worker.

const testing = std.testing;

const Fixture = struct {
    mailbox: Mailbox,
    slab: Slab,
    out_buf: [256]u8 = undefined,
    out: Out = undefined,
    date_line: [date.header_len]u8 = undefined,
    released: usize = 0,

    fn init(opts: Options) !*Fixture {
        const f = try testing.allocator.create(Fixture);
        f.* = .{ .mailbox = try Mailbox.init(testing.allocator, 8, try sys.Waker.init()), .slab = undefined };
        f.mailbox.bind();
        f.slab = try Slab.init(testing.allocator, 2, &f.mailbox, opts);
        f.out = .{ .buf = &f.out_buf };
        date.formatHeader(&f.date_line, 784111777);
        return f;
    }

    fn deinit(f: *Fixture) void {
        f.slab.deinit();
        f.mailbox.waker.deinit();
        f.mailbox.deinit();
        testing.allocator.destroy(f);
    }

    fn release(ctx: ?*anyopaque) void {
        const f: *Fixture = @ptrCast(@alignCast(ctx.?));
        f.released += 1;
    }

    /// Binds like the worker does for a later() exchange.
    fn bind(f: *Fixture, ex: Exchange, is_head: bool, http10: bool) void {
        const e = f.slab.entry(ex.slot);
        e.bound = true;
        e.is_head = is_head;
        e.http10 = http10;
        e.head_pending = true;
    }

    /// Drains everything into `collected`, 256 bytes of output at a time.
    /// The flags are accumulated over the rounds.
    fn drain(f: *Fixture, ex: Exchange, collected: *std.ArrayList(u8)) !Filled {
        var acc: Filled = .{};
        while (true) {
            f.out.clear();
            const r = ex.fill(&f.out, &f.date_line, 100);
            try collected.appendSlice(testing.allocator, f.out.buf[0..f.out.len]);
            try collected.appendSlice(testing.allocator, f.out.body);
            try collected.appendSlice(testing.allocator, f.out.tail);
            if (r.release) |rel| rel.call();
            acc.progressed = acc.progressed or r.progressed;
            acc.notify = acc.notify or r.notify;
            acc.done = r.done;
            acc.aborted = r.aborted;
            if (r.done or r.aborted or !r.progressed) return acc;
        }
    }
};

const DATE = "date: Sun, 06 Nov 1994 08:49:37 GMT\r\n";

test "stale handles and wrong states" {
    const f = try Fixture.init(.{});
    defer f.deinit();
    const ex = try f.slab.create(100);
    try testing.expectError(error.WrongState, ex.write("x"));
    try testing.expectError(error.WrongState, ex.finish(&.{}));
    const ex2 = try f.slab.create(100);
    try testing.expectError(error.TooManyExchanges, f.slab.create(100));
    f.slab.release(ex.slot);
    try testing.expectError(error.Closed, ex.respond(.{}, "late"));
    try testing.expect(!ex.isOpen());
    try testing.expect(ex2.isOpen());
    // The slot is reused with a new generation; the old handle stays dead.
    const ex3 = try f.slab.create(100);
    try testing.expectEqual(ex.slot, ex3.slot);
    try testing.expect(ex.gen != ex3.gen);
    try testing.expectError(error.Closed, ex.write("x"));
    try ex3.respond(.{}, "");
    try testing.expectError(error.WrongState, ex3.respond(.{}, ""));
    try testing.expectError(error.WrongState, ex3.startStream(.{}));
}

test "respond: a complete response with the server's headers" {
    const f = try Fixture.init(.{});
    defer f.deinit();
    const ex = try f.slab.create(100);
    f.bind(ex, false, false);
    // Nothing comes out before the handler answers.
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var r = try f.drain(ex, &got);
    try testing.expect(!r.done and !r.progressed);
    try ex.respond(.{ .status = .created, .headers = &.{.{ .key = "x-a", .value = "1" }} }, "hello");
    var entries: [4]@import("../mailbox.zig").Entry = undefined;
    try testing.expectEqual(@as(usize, 1), f.mailbox.drain(&entries));
    try testing.expectEqual(ex.slot, entries[0].slot);
    r = try f.drain(ex, &got);
    try testing.expect(r.done);
    try testing.expectEqualStrings("HTTP/1.1 201 Created\r\nx-a: 1\r\ncontent-length: 5\r\n" ++ DATE ++ "\r\nhello", got.items);
    // Reserved and malformed headers are rejected.
    const ex2 = try f.slab.create(100);
    try testing.expectError(error.InvalidHeader, ex2.respond(.{ .headers = &.{.{ .key = "Content-Length", .value = "1" }} }, ""));
    try testing.expectError(error.InvalidHeader, ex2.respond(.{ .headers = &.{.{ .key = "x", .value = "a\r\nb" }} }, ""));
}

test "streamed body: chunked framing, borrowed bytes, trailers, partial chunks" {
    const f = try Fixture.init(.{});
    defer f.deinit();
    const ex = try f.slab.create(100);
    f.bind(ex, false, false);
    try ex.startStream(.{ .status = .ok });
    try ex.write("hello ");
    try ex.write("world");
    const borrowed: [300]u8 = @splat('b');
    try ex.writeBorrowed(&borrowed, .{ .ctx = f, .func = Fixture.release });
    try ex.writeBorrowed("", .{ .ctx = f, .func = Fixture.release }); // released at once
    try testing.expectEqual(@as(usize, 1), f.released);
    const long: [500]u8 = @splat('l');
    try ex.write(&long);
    try ex.finish(&.{.{ .key = "x-trailer", .value = "t" }});
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    const r = try f.drain(ex, &got);
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 2), f.released);
    // Two copied writes merge into one chunk; the borrowed bytes are one
    // chunk by reference; 500 bytes split over 256-byte outputs.
    const expected = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n" ++ DATE ++ "\r\n" ++
        "b\r\nhello world\r\n" ++ "12c\r\n" ++ borrowed ++ "\r\n" ++
        "ec\r\n" ++ long[0..236] ++ "\r\n" ++ "ec\r\n" ++ long[0..236] ++ "\r\n" ++ "1c\r\n" ++ long[0..28] ++ "\r\n" ++
        "0\r\nx-trailer: t\r\n\r\n";
    try testing.expectEqualStrings(expected, got.items);
}

test "content-length streams and HEAD" {
    const f = try Fixture.init(.{});
    defer f.deinit();
    const ex = try f.slab.create(100);
    f.bind(ex, false, false);
    try ex.startStream(.{ .content_length = 11 });
    try ex.write("hello ");
    try testing.expectError(error.ContentLengthMismatch, ex.write("world!"));
    try ex.write("world");
    try ex.finish(&.{.{ .key = "dropped", .value = "x" }});
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var r = try f.drain(ex, &got);
    try testing.expect(r.done);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-length: 11\r\n" ++ DATE ++ "\r\nhello world", got.items);
    f.slab.release(ex.slot);
    // Short at finish: aborted.
    const ex2 = try f.slab.create(100);
    f.bind(ex2, false, false);
    try ex2.startStream(.{ .content_length = 5 });
    try ex2.write("abc");
    try testing.expectError(error.ContentLengthMismatch, ex2.finish(&.{}));
    got.clearRetainingCapacity();
    r = try f.drain(ex2, &got);
    try testing.expect(r.aborted);
    f.slab.release(ex2.slot);
    // HEAD: the head with its length, no body, borrowed bytes released.
    const ex3 = try f.slab.create(100);
    f.bind(ex3, true, false);
    try ex3.startStream(.{ .content_length = 300 });
    const borrowed: [300]u8 = @splat('b');
    try ex3.writeBorrowed(&borrowed, .{ .ctx = f, .func = Fixture.release });
    try ex3.finish(&.{});
    got.clearRetainingCapacity();
    r = try f.drain(ex3, &got);
    try testing.expect(r.done);
    try testing.expectEqual(@as(usize, 1), f.released);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-length: 300\r\n" ++ DATE ++ "\r\n", got.items);
    f.slab.release(ex3.slot);
    // HTTP/1.0 without a length: no framing, connection closes after.
    const ex4 = try f.slab.create(100);
    f.bind(ex4, false, true);
    try ex4.startStream(.{});
    try ex4.write("raw");
    try ex4.finish(&.{});
    got.clearRetainingCapacity();
    r = try f.drain(ex4, &got);
    try testing.expect(r.done);
    try testing.expect(!f.slab.entry(ex4.slot).keep_alive);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n" ++ DATE ++ "connection: close\r\n\r\nraw", got.items);
}

test "backpressure: WouldBlock, then notify once the queue drains" {
    const f = try Fixture.init(.{ .max_queue_bytes = 100 });
    defer f.deinit();
    const ex = try f.slab.create(100);
    f.bind(ex, false, false);
    try ex.startStream(.{});
    const chunk: [60]u8 = @splat('c');
    try ex.write(&chunk);
    try testing.expectError(error.WouldBlock, ex.write(&chunk));
    try testing.expectError(error.WouldBlock, ex.writeBorrowed(&chunk, null));
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    const r = try f.drain(ex, &got);
    try testing.expect(r.notify);
    try ex.write(&chunk);
    // abort drops what is queued.
    try ex.abort();
    got.clearRetainingCapacity();
    try testing.expect((try f.drain(ex, &got)).aborted);
    try testing.expectEqual(@as(usize, 0), got.items.len);
}

test "timeouts: the deadline moves with progress and with setTimeout" {
    const f = try Fixture.init(.{ .response_timeout_s = 30, .request_timeout_s = 10 });
    defer f.deinit();
    const ex = try f.slab.create(100);
    f.bind(ex, false, false);
    try testing.expectEqual(@as(u32, 131), f.slab.entry(ex.slot).deadline);
    try ex.startStream(.{});
    try ex.write("x");
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    _ = try f.drain(ex, &got); // now = 100 in drain
    try testing.expectEqual(@as(u32, 111), f.slab.entry(ex.slot).deadline);
    try ex.setTimeout(1000);
    _ = try f.drain(ex, &got);
    try testing.expect(f.slab.entry(ex.slot).deadline >= sys.monotonicSeconds() +% 999);
}
