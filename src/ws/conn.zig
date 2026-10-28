//! A WebSocket connection after the upgrade: the frame decoder, a
//! per-connection send queue, and the close handshake. Like the HTTP
//! session, this does no I/O; the worker that owns the connection feeds it
//! bytes, runs `process`, and writes whatever `wireBytes` returns.
//!
//! Threading: `process` and the wire functions are only called by the
//! owning worker. `send`, `ping`, `pong` and `close` may be called from any
//! thread (they take the connection's mutex and wake the owning worker
//! through its mailbox). A `*Conn` is valid from `handleWSConn` until
//! `handleWSDisconn` returns; a handler that sends from other threads must
//! stop them using the handle before that (for example by removing it from
//! its own table inside `handleWSDisconn`, under its own lock).
const std = @import("std");
const sys = @import("../sys.zig");
const protocol = @import("./protocol.zig");
const BufferPool = @import("../http/session.zig").BufferPool;

pub const Frame = protocol.Frame;
pub const Opcode = protocol.Opcode;
pub const close_code = protocol.close_code;

pub const Options = struct {
    /// Messages larger than this fail the connection with 1009.
    max_message_size: usize = 16 * 1024 * 1024,
    /// Unsent output per connection before `send` fails with SendQueueFull.
    max_send_queue_bytes: usize = 4 * 1024 * 1024,
};

pub const SendError = error{
    /// A close frame has already been queued, by either side.
    Closed,
    /// The peer isn't reading fast enough; try again later or close.
    SendQueueFull,
    /// Control frame payloads are at most 125 bytes.
    ControlFrameTooLarge,
    OutOfMemory,
};

pub const Mailbox = @import("../mailbox.zig").Mailbox;
const MailboxEntry = @import("../mailbox.zig").Entry;

pub const Conn = struct {
    const Self = @This();

    /// The socket. Only for identification (logging); never read or write
    /// it directly. Every WebSocket on one HTTP/2 connection shares its
    /// socket, and over HTTP/3 this is the worker's UDP socket.
    fd: sys.fd_t,
    /// For the handler's own per-connection state.
    user: ?*anyopaque = null,

    allocator: std.mem.Allocator,
    opts: Options,
    decoder: protocol.Decoder,
    mailbox: *Mailbox,
    /// What `send` posts to the mailbox: the worker's connection slot
    /// (HTTP/1.1), or the exchange slot routing to an HTTP/2 or HTTP/3
    /// stream.
    post_entry: MailboxEntry,

    mutex: sys.Mutex = .{},
    /// Frames queued by send() from any thread. Guarded by `mutex`.
    shared: std.ArrayList(u8) = .empty,
    /// Guarded by `mutex`: true while `slot` sits in the mailbox.
    posted: bool = false,
    /// Guarded by `mutex`: a close frame has been queued; nothing more may
    /// be sent after it.
    close_sent: bool = false,
    /// Guarded by `mutex`: bytes in `shared` plus unsent bytes on the wire.
    queued: usize = 0,

    /// Bytes being written. Owned by the worker.
    wire: std.ArrayList(u8) = .empty,
    wire_pos: usize = 0,
    /// Worker only: the peer sent a close frame.
    close_received: bool = false,
    /// Worker only: the connection was failed (protocol error, limit).
    failed: bool = false,

    pub fn create(allocator: std.mem.Allocator, fd: sys.fd_t, opts: Options, mailbox: *Mailbox, post_entry: MailboxEntry) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .fd = fd,
            .allocator = allocator,
            .opts = opts,
            .decoder = protocol.Decoder.init(allocator, opts.max_message_size),
            .mailbox = mailbox,
            .post_entry = post_entry,
        };
        return self;
    }

    pub fn destroy(self: *Self, pool: *BufferPool) void {
        self.decoder.deinit(pool);
        self.shared.deinit(self.allocator);
        self.wire.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    // -- Sending (any thread) -------------------------------------------

    /// Queues a text (UTF-8) or binary message. The data is copied.
    pub fn send(self: *Self, data: []const u8, is_binary: bool) SendError!void {
        return self.queueFrame(if (is_binary) .binary else .text, data);
    }

    pub fn sendText(self: *Self, data: []const u8) SendError!void {
        return self.queueFrame(.text, data);
    }

    pub fn sendBinary(self: *Self, data: []const u8) SendError!void {
        return self.queueFrame(.binary, data);
    }

    pub fn ping(self: *Self, data: []const u8) SendError!void {
        if (data.len > protocol.max_control_payload) return error.ControlFrameTooLarge;
        return self.queueFrame(.ping, data);
    }

    pub fn pong(self: *Self, data: []const u8) SendError!void {
        if (data.len > protocol.max_control_payload) return error.ControlFrameTooLarge;
        return self.queueFrame(.pong, data);
    }

    /// Starts the closing handshake: sends a close frame, then waits for
    /// the peer's close frame (bounded by the request timeout) before the
    /// socket is closed and `handleWSDisconn` is called. Nothing can be
    /// sent after this. The reason is truncated to 123 bytes.
    pub fn close(self: *Self, code: u16, reason: []const u8) SendError!void {
        var payload: [protocol.max_control_payload]u8 = undefined;
        std.mem.writeInt(u16, payload[0..2], code, .big);
        const n = @min(reason.len, payload.len - 2);
        @memcpy(payload[2..][0..n], reason[0..n]);
        return self.queueFrame(.close, payload[0 .. 2 + n]);
    }

    fn queueFrame(self: *Self, opcode: Opcode, payload: []const u8) SendError!void {
        var hdr: [10]u8 = undefined;
        const h = protocol.encodeHeader(&hdr, true, opcode, payload.len);
        const total = h.len + payload.len;
        const post = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.close_sent) return error.Closed;
            // A close frame always fits: it ends the connection.
            if (opcode != .close and self.queued + total > self.opts.max_send_queue_bytes) {
                return error.SendQueueFull;
            }
            try self.shared.ensureUnusedCapacity(self.allocator, total);
            self.shared.appendSliceAssumeCapacity(h);
            self.shared.appendSliceAssumeCapacity(payload);
            self.queued += total;
            if (opcode == .close) self.close_sent = true;
            const post = !self.posted;
            self.posted = true;
            break :blk post;
        };
        if (post) self.mailbox.post(self.post_entry);
    }

    // -- Worker side -------------------------------------------------------

    pub const Action = enum {
        /// Keep going: write `wireBytes`, read more.
        ok,
        /// Write `wireBytes`, then close the socket.
        close,
    };

    /// Runs the protocol over the buffered input, calling the handler for
    /// each complete message. Pings are answered, close frames are echoed.
    pub fn process(self: *Self, comptime Handler: type, handler: *Handler) Action {
        if (self.wantsClose()) return .close;
        while (true) {
            var frame = self.decoder.next() catch |err| {
                self.fail(protocol.closeCodeFor(err));
                return .close;
            } orelse return .ok;
            const sent_close = self.closeSent();
            switch (frame.opcode) {
                .ping => if (!sent_close) {
                    self.queueFrame(.pong, frame.payload) catch {};
                },
                .close => {
                    self.close_received = true;
                    // Echo the status code (§5.5.1), then close the TCP
                    // connection ourselves (§7.1.1).
                    if (!sent_close) self.queueFrame(.close, frame.payload[0..@min(2, frame.payload.len)]) catch {};
                    self.deliver(Handler, handler, &frame);
                    return .close;
                },
                else => {},
            }
            // After we start closing, only the peer's close matters.
            if (sent_close) continue;
            self.deliver(Handler, handler, &frame);
        }
    }

    inline fn deliver(self: *Self, comptime Handler: type, handler: *Handler, frame: *Frame) void {
        if (@hasDecl(Handler, "handleWSFrame")) handler.handleWSFrame(self, frame);
    }

    /// Fails the connection (§7.1.7): queue a close frame with `code`; the
    /// worker closes the socket once it is written, without waiting for
    /// the peer's reply.
    pub fn fail(self: *Self, code: u16) void {
        self.failed = true;
        var payload: [2]u8 = undefined;
        std.mem.writeInt(u16, &payload, code, .big);
        self.queueFrame(.close, &payload) catch {};
    }

    /// Bytes to write next, refilled from the shared queue when the wire
    /// is empty. Empty means nothing is pending.
    pub fn wireBytes(self: *Self) []const u8 {
        if (self.wire_pos == self.wire.items.len) {
            self.wire.clearRetainingCapacity();
            self.wire_pos = 0;
            self.mutex.lock();
            std.mem.swap(std.ArrayList(u8), &self.shared, &self.wire);
            self.mutex.unlock();
        }
        return self.wire.items[self.wire_pos..];
    }

    pub fn advance(self: *Self, n: usize) void {
        self.wire_pos += n;
        self.mutex.lock();
        self.queued -= n;
        self.mutex.unlock();
    }

    /// Unsent bytes already taken onto the wire (a stalled write).
    pub inline fn hasWire(self: *const Self) bool {
        return self.wire_pos < self.wire.items.len;
    }

    /// Whether anything is queued, on the wire or in the shared queue.
    pub fn hasOutput(self: *Self) bool {
        if (self.hasWire()) return true;
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.shared.items.len > 0;
    }

    /// Called by the worker when it drains its mailbox.
    pub fn clearPosted(self: *Self) void {
        self.mutex.lock();
        self.posted = false;
        self.mutex.unlock();
    }

    /// The socket should be closed once the output is written.
    pub inline fn wantsClose(self: *const Self) bool {
        return self.close_received or self.failed;
    }

    /// We sent a close frame and are waiting for the peer's.
    pub fn closeSent(self: *Self) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.close_sent;
    }
};

// ---------------------------------------------------------------------------
// Tests: the connection without sockets.

const testing = std.testing;

const LogHandler = struct {
    log: std.ArrayList(u8) = .empty,
    /// What to send back on a text message, if anything.
    reply: ?[]const u8 = null,
    close_on_text: bool = false,

    pub fn handleWSFrame(self: *LogHandler, conn: *Conn, frame: *Frame) void {
        self.log.appendSlice(testing.allocator, frame.opcode.toString()) catch unreachable;
        self.log.append(testing.allocator, ':') catch unreachable;
        self.log.appendSlice(testing.allocator, frame.payload) catch unreachable;
        self.log.append(testing.allocator, ';') catch unreachable;
        if (frame.opcode == .text) {
            if (self.reply) |r| conn.send(r, false) catch unreachable;
            if (self.close_on_text) conn.close(1001, "bye") catch unreachable;
        }
    }
};

const Harness = struct {
    pool: BufferPool,
    mailbox: Mailbox,
    conn: *Conn,
    handler: LogHandler = .{},
    /// Everything "written to the socket".
    out: std.ArrayList(u8) = .empty,
    action: Conn.Action = .ok,

    fn init(opts: Options) !*Harness {
        const h = try testing.allocator.create(Harness);
        h.* = .{
            .pool = try BufferPool.init(testing.allocator, 1024, 2),
            .mailbox = try Mailbox.init(testing.allocator, 4, try sys.Waker.init()),
            .conn = undefined,
        };
        h.mailbox.bind();
        h.conn = try Conn.create(testing.allocator, 7, opts, &h.mailbox, .{ .kind = .ws, .slot = 0, .gen = 1 });
        return h;
    }

    fn deinit(h: *Harness) void {
        h.conn.destroy(&h.pool);
        h.mailbox.waker.deinit();
        h.mailbox.deinit();
        h.pool.deinit();
        h.handler.log.deinit(testing.allocator);
        h.out.deinit(testing.allocator);
        testing.allocator.destroy(h);
    }

    fn feed(h: *Harness, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0 and h.action == .ok) {
            const space = try h.conn.decoder.readSpace(&h.pool);
            const n = @min(space.len, rest.len);
            @memcpy(space[0..n], rest[0..n]);
            h.conn.decoder.commitRead(n);
            rest = rest[n..];
            h.action = h.conn.process(LogHandler, &h.handler);
            try h.flush();
        }
    }

    fn flush(h: *Harness) !void {
        while (true) {
            const bytes = h.conn.wireBytes();
            if (bytes.len == 0) break;
            try h.out.appendSlice(testing.allocator, bytes);
            h.conn.advance(bytes.len);
        }
    }

    fn drainMailbox(h: *Harness) usize {
        var entries: [4]@import("../mailbox.zig").Entry = undefined;
        return h.mailbox.drain(&entries);
    }
};

const key = [4]u8{ 9, 8, 7, 6 };

fn masked(out: []u8, op: Opcode, payload: []const u8) []u8 {
    return protocol.encodeFrame(out, true, op, payload, key);
}

test "ping is answered with a pong and delivered" {
    const h = try Harness.init(.{});
    defer h.deinit();
    var buf: [64]u8 = undefined;
    try h.feed(masked(&buf, .ping, "hi"));
    try testing.expectEqualStrings("ping:hi;", h.handler.log.items);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x8A, 2, 'h', 'i' }, h.out.items);
    try testing.expectEqual(Conn.Action.ok, h.action);
    // The pong was posted to the mailbox once, without a wake (same thread).
    try testing.expectEqual(@as(usize, 1), h.drainMailbox());
}

test "handler replies are framed and queued" {
    const h = try Harness.init(.{});
    defer h.deinit();
    h.handler.reply = "Hello client!";
    var buf: [64]u8 = undefined;
    try h.feed(masked(&buf, .text, "Hello server!"));
    try testing.expectEqualStrings("text:Hello server!;", h.handler.log.items);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x81, 13 } ++ "Hello client!".*, h.out.items);
}

test "peer close is echoed with its code, then the socket closes" {
    const h = try Harness.init(.{});
    defer h.deinit();
    var buf: [64]u8 = undefined;
    try h.feed(masked(&buf, .close, "\x03\xe9going away"));
    try testing.expectEqualStrings("close:\x03\xe9going away;", h.handler.log.items);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x88, 2, 0x03, 0xe9 }, h.out.items);
    try testing.expectEqual(Conn.Action.close, h.action);
    try testing.expectError(error.Closed, h.conn.send("late", false));
    // Input after the close frame is ignored.
    h.action = .ok;
    h.handler.log.clearRetainingCapacity();
    try h.feed(masked(&buf, .text, "ignored"));
    try testing.expectEqual(Conn.Action.close, h.action);
    try testing.expectEqualStrings("", h.handler.log.items);
}

test "handler-initiated close waits for the peer's close frame" {
    const h = try Harness.init(.{});
    defer h.deinit();
    h.handler.close_on_text = true;
    var buf: [64]u8 = undefined;
    try h.feed(masked(&buf, .text, "x"));
    try testing.expectEqual(Conn.Action.ok, h.action);
    try testing.expect(h.conn.closeSent());
    try testing.expect(!h.conn.wantsClose());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x88, 5, 0x03, 0xe9 } ++ "bye".*, h.out.items);
    try testing.expectError(error.Closed, h.conn.send("late", false));
    // Data frames in the meantime are dropped, pings are not answered.
    h.handler.log.clearRetainingCapacity();
    try h.feed(masked(&buf, .text, "more"));
    try h.feed(masked(&buf, .ping, ""));
    try testing.expectEqualStrings("", h.handler.log.items);
    try testing.expectEqual(@as(usize, 7), h.out.items.len);
    // The peer's close is not echoed again, and ends the connection.
    try h.feed(masked(&buf, .close, "\x03\xe9"));
    try testing.expectEqual(Conn.Action.close, h.action);
    try testing.expectEqual(@as(usize, 7), h.out.items.len);
    try testing.expectEqualStrings("close:\x03\xe9;", h.handler.log.items);
}

test "protocol errors fail the connection with the right close code" {
    const cases = [_]struct { bytes: []const u8, code: u16 }{
        .{ .bytes = &[_]u8{ 0x81, 0x01, 'x' }, .code = 1002 }, // unmasked
        .{ .bytes = &[_]u8{ 0x81, 0x82, 9, 8, 7, 6, 0xff ^ 9, 0xff ^ 8 }, .code = 1007 }, // bad UTF-8
        .{ .bytes = &[_]u8{ 0x82, 0xFE, 0x10, 0x00, 9, 8, 7, 6 }, .code = 1009 }, // 4096 > limit
    };
    for (cases) |case| {
        const h = try Harness.init(.{ .max_message_size = 1024 });
        defer h.deinit();
        try h.feed(case.bytes);
        try testing.expectEqual(Conn.Action.close, h.action);
        try testing.expect(h.conn.wantsClose());
        var expected: [4]u8 = .{ 0x88, 2, 0, 0 };
        std.mem.writeInt(u16, expected[2..4], case.code, .big);
        try testing.expectEqualSlices(u8, &expected, h.out.items);
        try testing.expectEqualStrings("", h.handler.log.items);
    }
}

test "send queue limit and control frame size" {
    const h = try Harness.init(.{ .max_send_queue_bytes = 100 });
    defer h.deinit();
    const big: [90]u8 = @splat('b');
    try h.conn.send(&big, true);
    try testing.expectError(error.SendQueueFull, h.conn.send(&big, true));
    try testing.expectError(error.ControlFrameTooLarge, h.conn.ping(&(@as([126]u8, @splat('p')))));
    try h.conn.ping("p");
    // Writing makes room again.
    try h.flush();
    try h.conn.send(&big, true);
    // A close frame is accepted even when the queue is full.
    try h.conn.close(1000, "");
    try testing.expectEqual(@as(usize, 1), h.drainMailbox());
}

test "partial writes resume where they stopped" {
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.conn.send("abcdef", false);
    const first = h.conn.wireBytes();
    try testing.expectEqual(@as(usize, 8), first.len);
    h.conn.advance(3);
    try testing.expect(h.conn.hasWire());
    // More output queued meanwhile goes after the rest of the wire.
    try h.conn.send("g", false);
    try testing.expectEqualSlices(u8, "bcdef", h.conn.wireBytes());
    h.conn.advance(5);
    try testing.expect(!h.conn.hasWire());
    try testing.expect(h.conn.hasOutput());
    try testing.expectEqualSlices(u8, &[_]u8{ 0x81, 1, 'g' }, h.conn.wireBytes());
    h.conn.advance(3);
    try testing.expect(!h.conn.hasOutput());
}

test "a send from another thread wakes the owning worker" {
    const h = try Harness.init(.{});
    defer h.deinit();
    const t = try std.Thread.spawn(.{}, struct {
        fn run(c: *Conn) void {
            c.send("from elsewhere", false) catch unreachable;
        }
    }.run, .{h.conn});
    t.join();
    var byte: [8]u8 = undefined;
    try testing.expect((try sys.read(h.mailbox.waker.read_fd, &byte)) > 0);
    try testing.expectEqual(@as(usize, 1), h.drainMailbox());
    try h.flush();
    try testing.expectEqualSlices(u8, &[_]u8{ 0x81, 14 } ++ "from elsewhere".*, h.out.items);
}
