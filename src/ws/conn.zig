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
const deflate = @import("./deflate.zig");
const inflate = @import("./inflate.zig");
const BufferPool = @import("../http/session.zig").BufferPool;
const WsQueues = @import("../http/session.zig").WsQueues;

pub const Frame = protocol.Frame;
pub const Opcode = protocol.Opcode;
pub const close_code = protocol.close_code;

pub const Options = struct {
    /// Messages larger than this fail the connection with 1009.
    max_message_size: usize = 16 * 1024 * 1024,
    /// Unsent output per connection before `send` fails with SendQueueFull.
    /// An empty queue takes one frame of any size, so the queue holds at
    /// most this or one frame, whichever is larger.
    max_send_queue_bytes: usize = 4 * 1024 * 1024,
    /// permessage-deflate (RFC 7692), negotiated with clients that offer
    /// it. Null: not offered.
    deflate: ?deflate.Options = null,
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

/// Queued frames in a buffer from the worker's pool (`BufferPool.wsAcquire`),
/// held only while there are some: `buf` is empty when `len` is 0.
const Queue = struct {
    buf: []u8 = &.{},
    len: usize = 0,

    fn bytes(q: Queue) []u8 {
        return q.buf[0..q.len];
    }
};

pub const Conn = struct {
    const Self = @This();

    /// A queue's buffer has room for one more frame up to this size.
    const room_for_another = 64 * 1024;
    /// The last batch sizes the next one's buffer up to this many times
    /// the frame that starts it.
    const hint_frames = 16;
    /// Messages compressed at a time (bytes of them, at least one whole
    /// message): the rest of a queue taken to compress waits for the
    /// wire to be written, so that compressing doesn't take the worker
    /// for as long as a queue full of messages that shrink a thousandfold
    /// takes.
    const compress_chunk = 64 * 1024;

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
    shared: Queue = .{},
    /// Guarded by `mutex`: true while `slot` sits in the mailbox.
    posted: bool = false,
    /// Guarded by `mutex`: a close frame has been queued; nothing more may
    /// be sent after it.
    close_sent: bool = false,
    /// Guarded by `mutex`: bytes in `shared` plus unsent bytes on the wire.
    queued: usize = 0,
    /// Guarded by `mutex`: how many bytes `shared` held when the wire last
    /// took it, so that the next batch's buffer is taken large enough at
    /// once instead of growing (and copying) through the sizes, which a
    /// buffer kept for the connection's life did once. Followed only up
    /// to `hint_frames` times the frame that starts the batch, so a small
    /// message after a large one takes a small buffer.
    batch_hint: usize = 0,

    /// Bytes being written. Owned by the worker.
    wire: Queue = .{},
    wire_pos: usize = 0,
    /// Worker only: a queue taken from `shared` to compress, the messages
    /// from `raw_pos` on still to be compressed onto the wire (in order:
    /// `shared` is taken again only once they are).
    raw: Queue = .{},
    raw_pos: usize = 0,
    /// Worker only: bytes of messages compressed, for the worker's turns
    /// (`takeCompressed`).
    compressed: usize = 0,
    /// permessage-deflate, as negotiated. Set before the handler sees the
    /// connection, then only read.
    deflate: deflate.Agreement = .{},
    /// Guarded by `mutex`: `shared` holds messages to compress (marked
    /// with RSV1 and still uncompressed).
    to_compress: bool = false,
    /// Worker only: the peer sent a close frame.
    close_received: bool = false,
    /// Worker only: the answer to the latest ping, when the send queue had
    /// no room for it (it is full of the handler's messages). It joins the
    /// queue as the worker takes the queue, past the size limit: a ping
    /// must be answered (RFC 6455 §5.5.2), and one pong waiting for the
    /// latest of the pings is enough (§5.5.3).
    waiting_pong: [protocol.max_control_payload]u8 = undefined,
    pong_len: ?u8 = null,
    /// Worker only: the connection was failed (protocol error, limit).
    failed: bool = false,

    pub fn create(allocator: std.mem.Allocator, pool: *BufferPool, fd: sys.fd_t, opts: Options, mailbox: *Mailbox, post_entry: MailboxEntry) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .fd = fd,
            .allocator = allocator,
            .opts = opts,
            .decoder = protocol.Decoder.init(pool, opts.max_message_size),
            .mailbox = mailbox,
            .post_entry = post_entry,
        };
        return self;
    }

    pub fn destroy(self: *Self) void {
        self.decoder.deinit();
        if (self.shared.buf.len > 0) self.bufferPool().wsRelease(self.shared.buf);
        if (self.wire.buf.len > 0) self.bufferPool().wsRelease(self.wire.buf);
        if (self.raw.buf.len > 0) self.bufferPool().wsRelease(self.raw.buf);
        self.allocator.destroy(self);
    }

    /// The owning worker's: input buffers, and the send queues (the part
    /// any thread may use, `wsAcquire`).
    inline fn bufferPool(self: *const Self) *BufferPool {
        return self.decoder.pool;
    }

    /// Applies what the upgrade negotiated, before the handler sees the
    /// connection.
    pub fn enableDeflate(self: *Self, agreement: deflate.Agreement) void {
        if (!agreement.enabled or self.opts.deflate == null) return;
        self.deflate = agreement;
        self.decoder.deflate = true;
        self.decoder.deflate_no_takeover = agreement.client_no_context_takeover;
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
        // Messages to compress are queued as they are, marked with RSV1;
        // the worker compresses them on their way to the wire (it has the
        // compressor, and `send` may run on any thread).
        const compress = self.deflate.enabled and !opcode.isControl() and payload.len >= self.opts.deflate.?.min_size;
        if (compress) hdr[0] |= 0x40;
        const post = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.close_sent) return error.Closed;
            // A close frame always fits: it ends the connection. So does
            // any frame when nothing is queued, or a message larger than
            // the limit could never be sent.
            if (opcode != .close and self.queued > 0 and self.queued + total > self.opts.max_send_queue_bytes) {
                return error.SendQueueFull;
            }
            try self.appendLocked(h, payload);
            if (compress) self.to_compress = true;
            if (opcode == .close) self.close_sent = true;
            const post = !self.posted;
            self.posted = true;
            break :blk post;
        };
        if (post) self.mailbox.post(self.post_entry);
    }

    /// Appends a frame to the shared queue. Hold `mutex`.
    fn appendLocked(self: *Self, h: []const u8, payload: []const u8) error{OutOfMemory}!void {
        const total = h.len + payload.len;
        const q = &self.shared;
        if (q.buf.len - q.len < total) {
            // A larger buffer (the first: an empty queue holds none),
            // for what the last batch held if that is more, half as
            // large again as the one it replaces (past the largest
            // pooled size, growing a frame at a time would copy the
            // queue on every send), and a small frame's room for
            // another like it (two of 2^k bytes and their headers
            // don't fit in 2^(k+1)). If that much can't be had, just
            // what it must hold: a pong or a close echo isn't lost for
            // a hint.
            const want = q.len + total;
            const hint = @min(self.batch_hint, hint_frames * total);
            const room = @max(want, hint, q.buf.len + q.buf.len / 2) + if (total <= room_for_another) total else 0;
            const buf = self.bufferPool().wsAcquire(room) catch try self.bufferPool().wsAcquire(want);
            @memcpy(buf[0..q.len], q.bytes());
            if (q.buf.len > 0) self.bufferPool().wsRelease(q.buf);
            q.buf = buf;
        }
        @memcpy(q.buf[q.len..][0..h.len], h);
        @memcpy(q.buf[q.len + h.len ..][0..payload.len], payload);
        q.len += total;
        self.queued += total;
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
                .ping => if (!sent_close) self.answerPing(frame.payload),
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

    fn answerPing(self: *Self, payload: []const u8) void {
        // A pong waiting already answers an earlier ping: this one takes
        // its place, so that pongs don't go out of order.
        if (self.pong_len == null) {
            if (self.queueFrame(.pong, payload)) |_| return else |err| if (err == error.Closed) return;
        }
        @memcpy(self.waiting_pong[0..payload.len], payload);
        self.pong_len = @intCast(payload.len);
    }

    /// The waiting pong joins the shared queue, unless a close frame ended
    /// it (nothing goes after one). Hold `mutex`.
    fn queuePongLocked(self: *Self) void {
        const len = self.pong_len orelse return;
        if (!self.close_sent) {
            var hdr: [10]u8 = undefined;
            const h = protocol.encodeHeader(&hdr, true, .pong, len);
            // Without a buffer it waits for the next time.
            self.appendLocked(h, self.waiting_pong[0..len]) catch return;
        }
        self.pong_len = null;
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

    /// Bytes to write next, taken from the shared queue when the wire is
    /// empty (its buffer and all; or, with messages to compress, a chunk
    /// of them compressed). Empty means nothing is pending.
    pub fn wireBytes(self: *Self) []const u8 {
        if (self.wire_pos == self.wire.len) {
            self.releaseWire();
            if (self.raw.len == 0) {
                self.mutex.lock();
                self.queuePongLocked();
                if (self.shared.len > 0) self.batch_hint = self.shared.len;
                const taken = self.shared;
                self.shared = .{};
                const compress = self.to_compress;
                self.to_compress = false;
                self.mutex.unlock();
                if (compress) self.raw = taken else self.wire = taken;
            }
            if (self.raw.len > 0) self.compressSome();
        }
        return self.wire.bytes()[self.wire_pos..];
    }

    /// Bytes of messages compressed since the last call (the worker's
    /// turns count them with the bytes it writes).
    pub fn takeCompressed(self: *Self) usize {
        defer self.compressed = 0;
        return self.compressed;
    }

    /// The wire is written: its buffer goes back to the pool.
    fn releaseWire(self: *Self) void {
        if (self.wire.buf.len > 0) self.bufferPool().wsRelease(self.wire.buf);
        self.wire = .{};
        self.wire_pos = 0;
    }

    /// The frame at the start of `src`: its header's and its payload's
    /// lengths.
    fn frameAt(src: []const u8) struct { hl: usize, n: usize } {
        const b1 = src[1] & 0x7f;
        return switch (b1) {
            126 => .{ .hl = 4, .n = std.mem.readInt(u16, src[2..4], .big) },
            127 => .{ .hl = 10, .n = @intCast(std.mem.readInt(u64, src[2..10], .big)) },
            else => .{ .hl = 2, .n = b1 },
        };
    }

    /// Compresses the next chunk of `raw`'s messages, those marked, into
    /// a buffer that becomes the wire. One that doesn't shrink, or meets a
    /// failure, goes out as it is (RSV1 cleared). Every frame is a whole
    /// message, and the server takes no context over (RFC 7692 §7.1.1):
    /// any frame boundary can end a chunk.
    fn compressSome(self: *Self) void {
        const src = self.raw.bytes()[self.raw_pos..];
        var end: usize = 0;
        while (end < src.len and (end == 0 or end < compress_chunk)) {
            const f = frameAt(src[end..]);
            end += f.hl + f.n;
        }
        // Frames only shrink, and a frame is compressed after a gap the size
        // of the longest header.
        var out: Queue = .{ .buf = self.bufferPool().wsAcquire(end + 10) catch return self.uncompressRaw() };
        const d = self.bufferPool().wsDeflater() catch null;
        var i: usize = 0;
        while (i < end) {
            const f = frameAt(src[i..]);
            const hl = f.hl;
            const n = f.n;
            const frame = src[i..][0 .. hl + n];
            i += frame.len;
            if (frame[0] & 0x40 != 0) {
                if (d) |deflater| {
                    const room = out.buf[out.len..];
                    // Only output smaller than the payload is kept.
                    if (deflater.compress(frame[hl..], room[10..][0 .. n - 1], self.deflate.server_window_bits)) |c| {
                        var hdr: [10]u8 = undefined;
                        const h = protocol.encodeHeader(&hdr, true, @fromBackingInt(@as(u4, @truncate(frame[0]))), c);
                        @memcpy(room[0..h.len], h);
                        room[0] |= 0x40;
                        std.mem.copyForwards(u8, room[h.len..][0..c], room[10..][0..c]);
                        out.len += h.len + c;
                        continue;
                    }
                }
            }
            @memcpy(out.buf[out.len..][0..frame.len], frame);
            out.buf[out.len] &= ~@as(u8, 0x40);
            out.len += frame.len;
        }
        self.mutex.lock();
        self.queued = self.queued - end + out.len;
        self.mutex.unlock();
        self.compressed += end;
        self.raw_pos += end;
        if (self.raw_pos == self.raw.len) self.releaseRaw();
        self.wire = out;
    }

    /// No buffer to compress into: the rest of `raw` goes out as it is,
    /// as the wire.
    fn uncompressRaw(self: *Self) void {
        const w = self.raw.bytes();
        var i: usize = self.raw_pos;
        while (i < w.len) {
            w[i] &= ~@as(u8, 0x40);
            const f = frameAt(w[i..]);
            i += f.hl + f.n;
        }
        self.wire = self.raw;
        self.wire_pos = self.raw_pos;
        self.raw = .{};
        self.raw_pos = 0;
    }

    fn releaseRaw(self: *Self) void {
        if (self.raw.buf.len > 0) self.bufferPool().wsRelease(self.raw.buf);
        self.raw = .{};
        self.raw_pos = 0;
    }

    /// `n` bytes of `wireBytes` are written (and no longer read: an
    /// asynchronous write has completed). A wire written to the end gives
    /// its buffer back at once.
    pub fn advance(self: *Self, n: usize) void {
        self.wire_pos += n;
        self.mutex.lock();
        self.queued -= n;
        self.mutex.unlock();
        if (self.wire_pos == self.wire.len) self.releaseWire();
    }

    /// Unsent bytes already taken onto the wire (a stalled write).
    pub inline fn hasWire(self: *const Self) bool {
        return self.wire_pos < self.wire.len;
    }

    /// Whether anything is queued, on the wire or in the shared queue.
    pub fn hasOutput(self: *Self) bool {
        if (self.hasWire() or self.raw.len > 0 or self.pong_len != null) return true;
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.shared.len > 0;
    }

    /// The worker stopped writing with output left (its turn was over):
    /// an entry in the mailbox brings it back, unless one is there already.
    /// The worker wakes itself (a post from its own thread doesn't).
    pub fn repost(self: *Self) void {
        self.mutex.lock();
        const post = !self.posted;
        self.posted = true;
        self.mutex.unlock();
        if (post) self.mailbox.post(self.post_entry);
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
        return initWith(opts, testing.allocator);
    }

    /// With the pool's (and so the send queues') memory from `pool_allocator`.
    fn initWith(opts: Options, pool_allocator: std.mem.Allocator) !*Harness {
        const h = try testing.allocator.create(Harness);
        h.* = .{
            .pool = try BufferPool.init(pool_allocator, 1024, 2),
            .mailbox = try Mailbox.init(testing.allocator, 4, try sys.Waker.init()),
            .conn = undefined,
        };
        h.mailbox.bind();
        h.conn = try Conn.create(testing.allocator, &h.pool, 7, opts, &h.mailbox, .{ .kind = .ws, .slot = 0, .gen = 1 });
        return h;
    }

    fn deinit(h: *Harness) void {
        h.conn.destroy();
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
            const space = try h.conn.decoder.readSpace();
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
    // An empty queue takes a frame larger than the limit, but nothing more.
    try h.flush();
    const huge: [300]u8 = @splat('h');
    try h.conn.send(&huge, true);
    try testing.expectError(error.SendQueueFull, h.conn.send("x", true));
    // A close frame is accepted even when the queue is full.
    try h.conn.close(1000, "");
    try testing.expectEqual(@as(usize, 1), h.drainMailbox());
}

test "a ping is answered while the send queue is full: the latest ping's pong joins the queue as the wire takes it, past the limit" {
    const h = try Harness.init(.{ .max_send_queue_bytes = 100 });
    defer h.deinit();
    var buf: [64]u8 = undefined;
    const big: [90]u8 = @splat('b');
    try h.conn.send(&big, true);
    // Room for one pong (92 + 7 bytes), not for the next.
    try feedOnly(h, masked(&buf, .ping, "aaaaa"));
    try testing.expectError(error.SendQueueFull, h.conn.send("x", true));
    try feedOnly(h, masked(&buf, .ping, "bbbbb"));
    try feedOnly(h, masked(&buf, .ping, "ccccc"));
    try testing.expect(h.conn.hasOutput());
    try h.flush();
    var rest: []const u8 = h.out.items;
    try testing.expectEqual(@as(u4, @backingInt(Opcode.binary)), (try takeFrame(&rest)).op);
    try testing.expectEqualStrings("aaaaa", (try takeFrame(&rest)).payload);
    const pong = try takeFrame(&rest);
    try testing.expectEqual(@as(u4, @backingInt(Opcode.pong)), pong.op);
    try testing.expectEqualStrings("ccccc", pong.payload);
    try testing.expectEqualSlices(u8, "", rest);
    try testing.expect(!h.conn.hasOutput());
    try testing.expectEqual(@as(usize, 0), h.conn.queued);
    // While the wire is being written the pong waits for it; then it goes
    // out on its own.
    try h.conn.send(&big, true);
    const wire = h.conn.wireBytes();
    try testing.expectEqual(@as(usize, 92), wire.len);
    try h.conn.send("0123", true);
    try feedOnly(h, masked(&buf, .ping, "ddddd"));
    h.conn.advance(wire.len);
    h.out.clearRetainingCapacity();
    try h.flush();
    rest = h.out.items;
    try testing.expectEqualStrings("0123", (try takeFrame(&rest)).payload);
    try testing.expectEqualStrings("ddddd", (try takeFrame(&rest)).payload);
    try testing.expectEqualSlices(u8, "", rest);
    // A waiting pong goes nowhere once a close frame is queued.
    try h.conn.send(&big, true);
    try feedOnly(h, masked(&buf, .ping, "aaaaa"));
    try feedOnly(h, masked(&buf, .ping, "eeeee"));
    try h.conn.close(1000, "");
    h.out.clearRetainingCapacity();
    try h.flush();
    rest = h.out.items;
    _ = try takeFrame(&rest);
    try testing.expectEqualStrings("aaaaa", (try takeFrame(&rest)).payload);
    try testing.expectEqual(@as(u4, @backingInt(Opcode.close)), (try takeFrame(&rest)).op);
    try testing.expectEqualSlices(u8, "", rest);
    try testing.expect(!h.conn.hasOutput());
}

test "permessage-deflate: sends are compressed on the way to the wire" {
    for ([_]u4{ 15, 9 }) |window_bits| {
        const h = try Harness.init(.{ .deflate = .{ .min_size = 32 } });
        defer h.deinit();
        h.conn.enableDeflate(.{ .enabled = true, .server_window_bits = window_bits });
        var big: [3000]u8 = undefined;
        for (&big, 0..) |*b, i| b.* = "compress me please "[i % 19];
        var noise: [200]u8 = undefined;
        var prng = std.Random.DefaultPrng.init(7);
        prng.random().bytes(&noise);
        try h.conn.send(&big, false);
        try h.conn.send("short", false);
        try h.conn.ping("p");
        try h.conn.send(&noise, true);
        try h.conn.send(&big, true);
        try h.flush();
        // Every byte queued has been written.
        try testing.expectEqual(@as(usize, 0), h.conn.queued);

        const tables = try h.pool.wsInflateTables();
        const want = [_]struct { op: u8, compressed: bool, payload: []const u8 }{
            .{ .op = 1, .compressed = true, .payload = &big },
            .{ .op = 1, .compressed = false, .payload = "short" },
            .{ .op = 9, .compressed = false, .payload = "p" },
            .{ .op = 2, .compressed = false, .payload = &noise },
            .{ .op = 2, .compressed = true, .payload = &big },
        };
        var rest = h.out.items;
        for (want) |w| {
            try testing.expectEqual(w.op, rest[0] & 0x0f);
            try testing.expectEqual(w.compressed, rest[0] & 0x40 != 0);
            const b1 = rest[1];
            const hl: usize = if (b1 == 126) 4 else 2;
            const n: usize = if (b1 == 126) std.mem.readInt(u16, rest[2..4], .big) else b1;
            const payload = rest[hl..][0..n];
            rest = rest[hl + n ..];
            if (!w.compressed) {
                try testing.expectEqualSlices(u8, w.payload, payload);
                continue;
            }
            try testing.expect(n < w.payload.len / 2);
            // Each stands alone (server_no_context_takeover): it inflates
            // with no window.
            const with_trailer = try std.mem.concat(testing.allocator, u8, &.{ payload, &deflate.trailer });
            defer testing.allocator.free(with_trailer);
            var got: inflate.Out = .{ .buf = &.{}, .max = 1 << 20, .pool = &h.pool };
            defer if (got.buf.len > 0) h.pool.releaseLarge(got.buf);
            _ = try inflate.inflate(tables, null, with_trailer, &got);
            try testing.expectEqualSlices(u8, w.payload, got.buf[0..got.len]);
        }
        try testing.expectEqual(@as(usize, 0), rest.len);
    }
}

test "permessage-deflate: a long queue is compressed a chunk at a time, as the wire is written, its messages whole and in order" {
    const h = try Harness.init(.{ .max_send_queue_bytes = 64 << 20, .deflate = .{ .min_size = 32 } });
    defer h.deinit();
    h.conn.enableDeflate(.{ .enabled = true });
    const big = try testing.allocator.alloc(u8, 200 * 1024);
    defer testing.allocator.free(big);
    // 64 messages of 40 KiB, one of 200 KiB (larger than a chunk), a ping
    // and a short one in between: each compresses a thousandfold.
    for (0..64) |i| {
        @memset(big[0 .. 40 * 1024], letter(i));
        try h.conn.send(big[0 .. 40 * 1024], true);
        if (i == 10) {
            @memset(big, 'Z');
            try h.conn.send(big, true);
            try h.conn.ping("p");
            try h.conn.send("short", false);
        }
    }
    var got: inflate.Out = .{ .buf = &.{}, .max = 1 << 20, .pool = &h.pool };
    defer if (got.buf.len > 0) h.pool.releaseLarge(got.buf);
    var chunks: usize = 0;
    var seen: usize = 0;
    while (true) {
        const bytes = h.conn.wireBytes();
        const taken = h.conn.takeCompressed();
        if (bytes.len == 0) break;
        chunks += 1;
        // Under a chunk's worth, but for the message that crosses the line.
        try testing.expect(taken < Conn.compress_chunk + big.len + 10);
        var rest = bytes;
        while (rest.len > 0) {
            const f = try takeFrame(&rest);
            const i = seen;
            seen += 1;
            if (i == 11) {
                try testing.expect(f.rsv1);
                const m = try messageOf(&h.pool, f, &got);
                try testing.expectEqual(big.len, m.len);
                try testing.expect(std.mem.allEqual(u8, m, 'Z'));
            } else if (i == 12) {
                try testing.expectEqual(@as(u4, @backingInt(Opcode.ping)), f.op);
            } else if (i == 13) {
                try testing.expectEqualStrings("short", f.payload);
            } else {
                const k = if (i < 11) i else i - 3;
                try testing.expect(f.rsv1);
                const m = try messageOf(&h.pool, f, &got);
                try testing.expectEqual(@as(usize, 40 * 1024), m.len);
                try testing.expect(std.mem.allEqual(u8, m, letter(k)));
            }
        }
        h.conn.advance(bytes.len);
    }
    try testing.expectEqual(@as(usize, 67), seen);
    try testing.expect(chunks >= 30);
    try testing.expectEqual(@as(usize, 0), h.conn.queued);
    try testing.expect(!h.conn.hasOutput());
}

fn letter(i: usize) u8 {
    return @as(u8, 'a') + @as(u8, @intCast(i % 26));
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

// -- Send queues: from the worker's pool, held only while they hold bytes ---

/// One frame the server wrote, taken from the front of `rest`.
/// A server frame (tests here and in HTTP/2 and HTTP/3).
pub const OutFrame = struct { op: u4, rsv1: bool, payload: []const u8 };

pub fn takeFrame(rest: *[]const u8) !OutFrame {
    const r = rest.*;
    if (r.len < 2) return error.Truncated;
    if (r[0] & 0x80 == 0 or r[1] & 0x80 != 0) return error.BadFrame;
    const b1 = r[1] & 0x7f;
    const hl: usize = switch (b1) {
        126 => 4,
        127 => 10,
        else => 2,
    };
    if (r.len < hl) return error.Truncated;
    const n: usize = switch (b1) {
        126 => std.mem.readInt(u16, r[2..4], .big),
        127 => @intCast(std.mem.readInt(u64, r[2..10], .big)),
        else => b1,
    };
    if (r.len < hl + n) return error.Truncated;
    rest.* = r[hl + n ..];
    return .{ .op = @truncate(r[0]), .rsv1 = r[0] & 0x40 != 0, .payload = r[hl..][0..n] };
}

/// The message a data frame carries, inflated into `got` if compressed.
fn messageOf(pool: *BufferPool, f: OutFrame, got: *inflate.Out) ![]const u8 {
    if (!f.rsv1) return f.payload;
    const with_trailer = try std.mem.concat(testing.allocator, u8, &.{ f.payload, &deflate.trailer });
    defer testing.allocator.free(with_trailer);
    got.len = 0;
    _ = try inflate.inflate(try pool.wsInflateTables(), null, with_trailer, got);
    return got.buf[0..got.len];
}

/// Message `seq` of sender `t`, made from the two alone: mostly small, now
/// and then a few KiB, one in 64 larger than 64 KiB (the queue's buffer
/// grows under the others' appends); compressible.
fn testMsgLen(t: usize, seq: usize) usize {
    var x: u64 = @as(u64, t) << 32 | seq;
    x = (x +% 0x9E3779B97F4A7C15) *% 0xBF58476D1CE4E5B9;
    x ^= x >> 31;
    return 5 + switch (x % 64) {
        0 => 70_000 + x % 1000,
        1...8 => 1000 + x % 4000,
        else => x % 300,
    };
}

fn testMsgFill(buf: []u8, t: usize, seq: usize) void {
    buf[0] = @intCast(t);
    std.mem.writeInt(u32, buf[1..5], @intCast(seq), .little);
    for (buf[5..], 0..) |*b, i| b.* = 'a' + @as(u8, @intCast((i + seq + t) % 16));
}

/// Threads sending numbered messages until `count` or until the
/// connection is closed, retrying while the queue is full.
const Senders = struct {
    conn: *Conn,
    count: usize,
    done: std.atomic.Value(usize) = .init(0),
    /// How many each had accepted.
    sent: [8]usize = @splat(0),

    fn run(self: *Senders, t: usize) void {
        const buf = std.heap.page_allocator.alloc(u8, 72 * 1024) catch unreachable;
        defer std.heap.page_allocator.free(buf);
        var seq: usize = 0;
        while (seq < self.count) {
            const msg = buf[0..testMsgLen(t, seq)];
            testMsgFill(msg, t, seq);
            self.conn.send(msg, true) catch |err| switch (err) {
                error.SendQueueFull => {
                    std.Thread.yield() catch {};
                    continue;
                },
                error.Closed => break,
                else => unreachable,
            };
            seq += 1;
        }
        self.sent[t] = seq;
        _ = self.done.fetchAdd(1, .release);
    }
};

/// The worker's side while `threads` senders run: drains the mailbox and
/// writes what is queued in pieces of random size until every sender is
/// done and nothing is left; closes once `close_after` bytes are out.
fn workUntilDone(h: *Harness, s: *Senders, threads: usize, rand: std.Random, close_after: ?usize) !void {
    while (true) {
        const finished = s.done.load(.acquire) == threads;
        _ = h.drainMailbox();
        h.conn.clearPosted();
        if (close_after) |n| {
            if (h.out.items.len >= n and !h.conn.closeSent()) try h.conn.close(1000, "bye");
        }
        const bytes = h.conn.wireBytes();
        if (bytes.len == 0) {
            if (finished) return;
            std.Thread.yield() catch {};
            continue;
        }
        const k = 1 + rand.uintLessThan(usize, @min(bytes.len, 20_000));
        try h.out.appendSlice(testing.allocator, bytes[0..k]);
        h.conn.advance(k);
    }
}

/// Every message accepted went out once, whole, in each sender's order;
/// then the close frame if one was sent, and nothing after it.
fn expectSent(h: *Harness, threads: usize, sent: []const usize, close: bool) !void {
    var next: [8]usize = @splat(0);
    const want = try testing.allocator.alloc(u8, 72 * 1024);
    defer testing.allocator.free(want);
    var got: inflate.Out = .{ .buf = &.{}, .max = 1 << 20, .pool = &h.pool };
    defer if (got.buf.len > 0) h.pool.releaseLarge(got.buf);
    var rest: []const u8 = h.out.items;
    var closed = false;
    var compressed: usize = 0;
    while (rest.len > 0) {
        const f = try takeFrame(&rest);
        try testing.expect(!closed);
        if (f.op == 8) {
            try testing.expectEqualSlices(u8, "\x03\xe8bye", f.payload);
            closed = true;
            continue;
        }
        try testing.expectEqual(@as(u4, 2), f.op);
        if (f.rsv1) compressed += 1;
        const m = try messageOf(&h.pool, f, &got);
        try testing.expect(m.len >= 5 and m[0] < threads);
        const t = m[0];
        const seq = std.mem.readInt(u32, m[1..5], .little);
        try testing.expectEqual(next[t], seq);
        const w = want[0..testMsgLen(t, seq)];
        testMsgFill(w, t, seq);
        try testing.expectEqualSlices(u8, w, m);
        next[t] += 1;
    }
    try testing.expectEqualSlices(usize, sent[0..threads], next[0..threads]);
    try testing.expectEqual(close, closed);
    try testing.expectEqual(h.conn.deflate.enabled, compressed > 0);
    try testing.expectEqual(@as(usize, 0), h.conn.queued);
}

/// The connection holds no queue buffer; two quiet ticks later the pool
/// keeps none either.
fn expectHoldsNothing(h: *Harness) !void {
    try testing.expectEqual(@as(usize, 0), h.conn.shared.buf.len + h.conn.wire.buf.len);
    for (h.pool.ws_queues.sizes) |r| try testing.expectEqual(@as(usize, 0), r.in_use);
    h.pool.trim();
    h.pool.trim();
    try testing.expectEqual(@as(usize, 0), h.pool.ws_queues.held.load(.monotonic));
}

test "send queues: many threads at once while the worker writes in pieces: every message once, in order" {
    for ([_]bool{ false, true }) |compress| {
        const h = try Harness.init(.{ .max_send_queue_bytes = 32 * 1024, .deflate = .{ .min_size = 32 } });
        defer h.deinit();
        if (compress) h.conn.enableDeflate(.{ .enabled = true });
        const threads = 6;
        var s: Senders = .{ .conn = h.conn, .count = 1500 };
        var ts: [threads]std.Thread = undefined;
        for (&ts, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Senders.run, .{ &s, i });
        var prng = std.Random.DefaultPrng.init(@intFromBool(compress));
        const res = workUntilDone(h, &s, threads, prng.random(), null);
        for (ts) |t| t.join();
        try res;
        try expectSent(h, threads, &s.sent, false);
        try testing.expectEqual(@as(usize, 1500), s.sent[threads - 1]);
        try expectHoldsNothing(h);
    }
}

test "send queues: closing while other threads send: what was accepted goes out whole, then the close frame, then nothing" {
    for ([_]bool{ false, true }) |compress| {
        const h = try Harness.init(.{ .max_send_queue_bytes = 32 * 1024, .deflate = .{ .min_size = 32 } });
        defer h.deinit();
        if (compress) h.conn.enableDeflate(.{ .enabled = true });
        const threads = 4;
        var s: Senders = .{ .conn = h.conn, .count = std.math.maxInt(usize) };
        var ts: [threads]std.Thread = undefined;
        for (&ts, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Senders.run, .{ &s, i });
        var prng = std.Random.DefaultPrng.init(3);
        const res = workUntilDone(h, &s, threads, prng.random(), 300 * 1024);
        for (ts) |t| t.join();
        try res;
        try expectSent(h, threads, &s.sent, true);
        try testing.expectError(error.Closed, h.conn.send("late", false));
        try expectHoldsNothing(h);
    }
}

/// Bytes `counting` has handed out and not had back.
fn heldBy(counting: *const std.testing.FailingAllocator) usize {
    return counting.allocated_bytes - counting.freed_bytes;
}

test "send queues: an idle connection holds no queue buffer whatever it sent; once warm nothing is allocated" {
    // `shared` and `wire` kept their capacity for the connection's life
    // (one that once sent 1 MiB twice held 2 MiB), `deflated` too.
    const big = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 7 % 251);
    for ([_]bool{ false, true }) |compress| {
        var counting = std.testing.FailingAllocator.init(testing.allocator, .{});
        const h = try Harness.initWith(.{ .deflate = .{} }, counting.allocator());
        defer h.deinit();
        if (compress) {
            h.conn.enableDeflate(.{ .enabled = true });
            _ = try h.pool.wsDeflater();
        }
        const base = heldBy(&counting);
        var warm: usize = 0;
        for (0..6) |round| {
            if (round == 1) warm = counting.allocations;
            try h.conn.send(big, true);
            for (0..10) |_| try h.conn.send("small", false);
            try h.flush();
            // Written: no buffer held.
            try testing.expectEqual(@as(usize, 0), h.conn.shared.buf.len + h.conn.wire.buf.len);
            // The wire partly written while more is queued behind it.
            try h.conn.send(big, true);
            const w = h.conn.wireBytes();
            try h.out.appendSlice(testing.allocator, w[0 .. w.len - 1]);
            h.conn.advance(w.len - 1);
            try testing.expect(h.conn.wire.buf.len > 0);
            try h.conn.send(big, true);
            try h.flush();
            try testing.expectEqual(@as(usize, 0), h.conn.shared.buf.len + h.conn.wire.buf.len);
            try testing.expectEqual(@as(usize, 0), h.conn.queued);
            var rest: []const u8 = h.out.items;
            var frames: usize = 0;
            while (rest.len > 0) : (frames += 1) {
                const f = try takeFrame(&rest);
                try testing.expectEqual(compress and f.op == 2, f.rsv1);
            }
            try testing.expectEqual(@as(usize, 13), frames);
            h.out.clearRetainingCapacity();
        }
        // Bursts after the first allocate nothing: the pool kept what they use.
        try testing.expectEqual(warm, counting.allocations);
        try testing.expect(h.pool.ws_queues.held.load(.monotonic) > 0);
        // Two ticks without sends: the pool gives it all back.
        h.pool.trim();
        h.pool.trim();
        try testing.expectEqual(@as(usize, 0), h.pool.ws_queues.held.load(.monotonic));
        try testing.expectEqual(base, heldBy(&counting));
    }
}

test "send queues: after the first batch, a batch like it fits the buffer its first message takes" {
    // Growing through the sizes copies what is queued each time: four
    // 16 KiB messages and their headers overflowed a 64 KiB buffer.
    const msg = try testing.allocator.alloc(u8, 300 * 1024);
    defer testing.allocator.free(msg);
    @memset(msg, 'q');
    for ([_]usize{ 20, 1000, 16 * 1024, 64 * 1024, 300 * 1024 }) |size| {
        for ([_]usize{ 1, 2, 4, 7 }) |batch| {
            const h = try Harness.init(.{ .max_send_queue_bytes = 16 << 20 });
            defer h.deinit();
            for (0..3) |round| {
                var first: []u8 = &.{};
                for (0..batch) |k| {
                    try h.conn.send(msg[0..size], true);
                    if (k == 0) first = h.conn.shared.buf;
                    if (round > 0) try testing.expectEqual(first.ptr, h.conn.shared.buf.ptr);
                }
                try h.flush();
            }
        }
    }
}

test "send queues: past the largest pooled size a queue grows geometrically, not a frame at a time" {
    // Sized for exactly what it held plus one frame, a 33 MiB queue was
    // copied whole about every second send.
    const big = try testing.allocator.alloc(u8, WsQueues.max_size + (1 << 20));
    defer testing.allocator.free(big);
    @memset(big, 'b');
    const h = try Harness.init(.{ .max_send_queue_bytes = 64 << 20 });
    defer h.deinit();
    try h.conn.send(big, true);
    var moves: usize = 0;
    var last = h.conn.shared.buf.ptr;
    for (0..400) |_| {
        try h.conn.send(big[0..100], true);
        if (h.conn.shared.buf.ptr != last) moves += 1;
        last = h.conn.shared.buf.ptr;
    }
    try testing.expect(moves <= 2);
    try h.flush();
    var rest: []const u8 = h.out.items;
    try testing.expectEqual(big.len, (try takeFrame(&rest)).payload.len);
    for (0..400) |_| try testing.expectEqualSlices(u8, big[0..100], (try takeFrame(&rest)).payload);
    try testing.expectEqual(@as(usize, 0), rest.len);
}

test "send queues: a small message after a large batch takes a small buffer" {
    // The last batch's size was followed whatever came next: after one
    // 16 MiB message, sending "hi" took a 32 MiB buffer.
    const big = try testing.allocator.alloc(u8, 16 << 20);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.conn.send(big, true);
    try h.flush();
    h.pool.trim();
    h.pool.trim();
    try h.conn.send("hi", false);
    try testing.expectEqual(@as(usize, WsQueues.min_size), h.conn.shared.buf.len);
    for (0..20) |_| try h.conn.send("hi", false);
    try testing.expectEqual(@as(usize, WsQueues.min_size), h.conn.shared.buf.len);
}

/// testing.allocator, failing anything larger than `limit`.
const LimitAllocator = struct {
    limit: usize,

    fn allocator(self: *LimitAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *LimitAllocator = @ptrCast(@alignCast(ctx));
        if (len > self.limit) return null;
        return testing.allocator.rawAlloc(len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *LimitAllocator = @ptrCast(@alignCast(ctx));
        return new_len <= self.limit and testing.allocator.rawResize(memory, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *LimitAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > self.limit) return null;
        return testing.allocator.rawRemap(memory, alignment, new_len, ra);
    }

    fn free(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        testing.allocator.rawFree(memory, alignment, ra);
    }
};

test "send queues: when the room asked for can't be had, a frame takes just what it needs" {
    // A full 40 MiB queue asks for half as much again; with only 50 MiB
    // to be had the pong, the close echo and the next message still go
    // (dropped as OutOfMemory, a pong or close echo was lost for good).
    const big = try testing.allocator.alloc(u8, 40 << 20);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    var limited: LimitAllocator = .{ .limit = 50 << 20 };
    const h = try Harness.initWith(.{ .max_send_queue_bytes = 64 << 20 }, limited.allocator());
    defer h.deinit();
    // Input processed while the queue is still full (nothing written).
    const Feed = struct {
        fn only(hh: *Harness, bytes: []const u8) !Conn.Action {
            const space = try hh.conn.decoder.readSpace();
            @memcpy(space[0..bytes.len], bytes);
            hh.conn.decoder.commitRead(bytes.len);
            return hh.conn.process(LogHandler, &hh.handler);
        }
    };
    try h.conn.send(big, true);
    try testing.expectEqual(Conn.Action.ok, try Feed.only(h, &[_]u8{ 0x89, 0x81, 1, 2, 3, 4, 'p' ^ 1 }));
    try h.conn.send(big[0..10], true);
    try testing.expectEqual(Conn.Action.close, try Feed.only(h, &[_]u8{ 0x88, 0x82, 1, 2, 3, 4, 0x03 ^ 1, 0xe8 ^ 2 }));
    try h.flush();
    var rest: []const u8 = h.out.items;
    try testing.expectEqual(big.len, (try takeFrame(&rest)).payload.len);
    const pong = try takeFrame(&rest);
    try testing.expectEqual(@as(u4, 0xa), pong.op);
    try testing.expectEqualStrings("p", pong.payload);
    try testing.expectEqualSlices(u8, big[0..10], (try takeFrame(&rest)).payload);
    const close = try takeFrame(&rest);
    try testing.expectEqual(@as(u4, 8), close.op);
    try testing.expectEqualStrings("\x03\xe8", close.payload);
    try testing.expectEqual(@as(usize, 0), rest.len);
}

test "send queues: a connection destroyed with output queued and half written gives its buffers back" {
    var counting = std.testing.FailingAllocator.init(testing.allocator, .{});
    const h = try Harness.initWith(.{}, counting.allocator());
    defer h.deinit();
    const base = heldBy(&counting);
    const big: [100_000]u8 = @splat('b');
    try h.conn.send(&big, true);
    h.conn.advance(h.conn.wireBytes().len / 2);
    try h.conn.send(&big, true);
    try testing.expect(h.conn.shared.buf.len > 0 and h.conn.wire.buf.len > 0);
    h.conn.destroy();
    for (h.pool.ws_queues.sizes) |r| try testing.expectEqual(@as(usize, 0), r.in_use);
    h.pool.trim();
    h.pool.trim();
    try testing.expectEqual(base, heldBy(&counting));
    h.conn = try Conn.create(testing.allocator, &h.pool, 7, .{}, &h.mailbox, .{ .kind = .ws, .slot = 0, .gen = 1 });
}

test "send queues: an allocation failing at any point fails one send whole; what was queued goes out intact" {
    // Messages of every header length, compressed or not, sent while the
    // wire is half written (the queue grows, from small to beyond 64 KiB).
    const lens = [_]usize{ 100, 3000, 5, 70_000, 200, 300_000, 40, 20 };
    var msgs: [lens.len][]u8 = undefined;
    for (&msgs, lens, 0..) |*m, n, k| {
        m.* = try testing.allocator.alloc(u8, n);
        for (m.*, 0..) |*b, i| b.* = @truncate((i + k) % 13 + 'a');
    }
    defer for (msgs) |m| testing.allocator.free(m);
    var fail_at: usize = 0;
    while (true) : (fail_at += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
        const h = try Harness.initWith(.{ .deflate = .{ .min_size = 32 } }, failing.allocator());
        defer h.deinit();
        h.conn.enableDeflate(.{ .enabled = true });
        failing.fail_index = failing.alloc_index + fail_at;
        var accepted: [lens.len]bool = @splat(false);
        for (msgs, 0..) |m, k| {
            if (h.conn.send(m, true)) {
                accepted[k] = true;
            } else |err| try testing.expectEqual(error.OutOfMemory, err);
            switch (k) {
                // The wire taken (compressed, unless that fails) and
                // half written; the queue fills behind it.
                2 => {
                    const w = h.conn.wireBytes();
                    try h.out.appendSlice(testing.allocator, w[0 .. w.len / 2]);
                    h.conn.advance(w.len / 2);
                },
                5 => try h.flush(),
                else => {},
            }
        }
        try h.flush();
        const induced = failing.has_induced_failure;
        failing.fail_index = std.math.maxInt(usize);
        try testing.expectEqual(@as(usize, 0), h.conn.queued);
        var got: inflate.Out = .{ .buf = &.{}, .max = 1 << 20, .pool = &h.pool };
        defer if (got.buf.len > 0) h.pool.releaseLarge(got.buf);
        var rest: []const u8 = h.out.items;
        for (msgs, accepted) |m, ok| {
            if (!ok) continue;
            const f = try takeFrame(&rest);
            try testing.expectEqualSlices(u8, m, try messageOf(&h.pool, f, &got));
        }
        try testing.expectEqual(@as(usize, 0), rest.len);
        try expectHoldsNothing(h);
        if (!induced) break;
    }
    try testing.expect(fail_at > 5);
}

// -- Send queues, adversarial (verification) -------------------------------

/// Every message accepted went out once, whole, in each sender's order;
/// pongs answer the peer's pings in order (the n-th carries n); a close
/// frame with `close_payload` ends it if one went out. Returns the pongs.
fn expectSentWithControl(h: *Harness, threads: usize, sent: []const usize, close_payload: ?[]const u8) !usize {
    var next: [8]usize = @splat(0);
    const want = try testing.allocator.alloc(u8, 72 * 1024);
    defer testing.allocator.free(want);
    var got: inflate.Out = .{ .buf = &.{}, .max = 1 << 20, .pool = &h.pool };
    defer if (got.buf.len > 0) h.pool.releaseLarge(got.buf);
    var rest: []const u8 = h.out.items;
    var closed = false;
    var pongs: u32 = 0;
    while (rest.len > 0) {
        const f = try takeFrame(&rest);
        try testing.expect(!closed);
        switch (f.op) {
            8 => {
                try testing.expectEqualSlices(u8, close_payload.?, f.payload);
                closed = true;
                continue;
            },
            10 => {
                try testing.expect(!f.rsv1);
                try testing.expectEqual(@as(usize, 4), f.payload.len);
                // A ping that finds the queue full goes unanswered
                // (RFC 6455 §5.5.3 lets a later pong answer it): the
                // pongs that go out answer pings in order.
                const n = std.mem.readInt(u32, f.payload[0..4], .little);
                try testing.expect(n >= pongs);
                pongs = n + 1;
                continue;
            },
            else => {},
        }
        try testing.expectEqual(@as(u4, 2), f.op);
        const m = try messageOf(&h.pool, f, &got);
        try testing.expect(m.len >= 5 and m[0] < threads);
        const t = m[0];
        const seq = std.mem.readInt(u32, m[1..5], .little);
        try testing.expectEqual(next[t], seq);
        const w = want[0..testMsgLen(t, seq)];
        testMsgFill(w, t, seq);
        try testing.expectEqualSlices(u8, w, m);
        next[t] += 1;
    }
    try testing.expectEqualSlices(usize, sent[0..threads], next[0..threads]);
    try testing.expectEqual(close_payload != null, closed);
    try testing.expectEqual(@as(usize, 0), h.conn.queued);
    return pongs;
}

/// Feeds the peer's bytes and runs the protocol, without writing.
fn feedOnly(h: *Harness, bytes: []const u8) !void {
    var rest = bytes;
    while (rest.len > 0 and h.action == .ok) {
        const space = try h.conn.decoder.readSpace();
        const n = @min(space.len, rest.len);
        @memcpy(space[0..n], rest[0..n]);
        h.conn.decoder.commitRead(n);
        rest = rest[n..];
        h.action = h.conn.process(LogHandler, &h.handler);
    }
}

/// The worker's side: writes in random pieces, trims the pool now and
/// then (as its tick does), feeds the peer's pings, and the peer's close
/// after `peer_close_after` bytes are out.
fn workTrimPing(h: *Harness, s: *Senders, threads: usize, rand: std.Random, peer_close_after: ?usize, pings: *u32) !void {
    var buf: [32]u8 = undefined;
    var peer_closed = false;
    while (true) {
        const finished = s.done.load(.acquire) == threads;
        _ = h.drainMailbox();
        h.conn.clearPosted();
        if (rand.uintLessThan(u8, 16) == 0) h.pool.trim();
        if (!peer_closed and rand.uintLessThan(u8, 8) == 0) {
            var p: [4]u8 = undefined;
            std.mem.writeInt(u32, &p, pings.*, .little);
            try feedOnly(h, masked(&buf, .ping, &p));
            if (h.action == .ok) pings.* += 1;
            h.handler.log.clearRetainingCapacity();
        }
        if (peer_close_after) |n| {
            if (!peer_closed and h.out.items.len >= n) {
                try feedOnly(h, masked(&buf, .close, "\x03\xe9gone"));
                peer_closed = true;
            }
        }
        const bytes = h.conn.wireBytes();
        if (bytes.len == 0) {
            if (finished) return;
            std.Thread.yield() catch {};
            continue;
        }
        const k = 1 + rand.uintLessThan(usize, @min(bytes.len, 20_000));
        try h.out.appendSlice(testing.allocator, bytes[0..k]);
        h.conn.advance(k);
    }
}

test "verify send queues: senders racing trims, pings answered in between, every message once in order" {
    for ([_]bool{ false, true }) |compress| {
        for (0..3) |seed| {
            const h = try Harness.init(.{ .max_send_queue_bytes = 32 * 1024, .deflate = .{ .min_size = 32 } });
            defer h.deinit();
            if (compress) h.conn.enableDeflate(.{ .enabled = true });
            const threads = 6;
            var s: Senders = .{ .conn = h.conn, .count = 800 };
            var ts: [threads]std.Thread = undefined;
            for (&ts, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Senders.run, .{ &s, i });
            var prng = std.Random.DefaultPrng.init(100 + seed);
            var pings: u32 = 0;
            const res = workTrimPing(h, &s, threads, prng.random(), null, &pings);
            for (ts) |t| t.join();
            try res;
            const pongs = try expectSentWithControl(h, threads, &s.sent, null);
            try testing.expect(pongs <= pings and pongs + 64 > pings);
            try testing.expect(pongs > 0);
            try expectHoldsNothing(h);
        }
    }
}

test "verify send queues: the peer closes while senders race: accepted messages whole, the close echo last" {
    for ([_]bool{ false, true }) |compress| {
        for (0..3) |seed| {
            const h = try Harness.init(.{ .max_send_queue_bytes = 32 * 1024, .deflate = .{ .min_size = 32 } });
            defer h.deinit();
            if (compress) h.conn.enableDeflate(.{ .enabled = true });
            const threads = 5;
            var s: Senders = .{ .conn = h.conn, .count = std.math.maxInt(usize) };
            var ts: [threads]std.Thread = undefined;
            for (&ts, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Senders.run, .{ &s, i });
            var prng = std.Random.DefaultPrng.init(200 + seed);
            var pings: u32 = 0;
            const res = workTrimPing(h, &s, threads, prng.random(), 200 * 1024 + seed * 77_777, &pings);
            for (ts) |t| t.join();
            try res;
            try testing.expectEqual(Conn.Action.close, h.action);
            const pongs = try expectSentWithControl(h, threads, &s.sent, "\x03\xe9");
            try testing.expect(pongs <= pings and pongs + 64 > pings);
            try testing.expectError(error.Closed, h.conn.send("late", false));
            try expectHoldsNothing(h);
        }
    }
}

// Messages straddling every size class boundary: alone, in batches, with
// the wire half written, compressed or not; whole and in order, and the
// pool's books balance.
test "verify send queues: messages at the size class boundaries" {
    const max = WsQueues.max_size;
    const sizes = [_]usize{
        0,            1,              125,     126,     127,      244,
        246,          250,            252,     253,     254,      255,
        256,          257,            508,     65_525,  65_527,   65_535,
        65_536,       65_537,         131_062, 131_072, 16 << 20, (16 << 20) + 1,
        max - 14,     max - 10,       max - 9, max - 1, max,      max + 1,
        max + 65_536, (40 << 20) + 3,
    };
    const big = try testing.allocator.alloc(u8, (40 << 20) + 3 + 64);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate((i >> 3) *% 31 +% (i & 7));
    for ([_]bool{ false, true }) |compress| {
        var counting = std.testing.FailingAllocator.init(testing.allocator, .{});
        const h = try Harness.initWith(.{ .max_send_queue_bytes = 128 << 20, .deflate = .{ .min_size = 32 } }, counting.allocator());
        defer h.deinit();
        if (compress) {
            h.conn.enableDeflate(.{ .enabled = true });
            _ = try h.pool.wsDeflater();
        }
        _ = try h.pool.wsInflateTables();
        const base = heldBy(&counting);
        var got: inflate.Out = .{ .buf = &.{}, .max = 64 << 20, .pool = &h.pool };
        var prng = std.Random.DefaultPrng.init(7);
        const rand = prng.random();
        // Each size, then small ones and a ping while it is half written,
        // then it again.
        for (sizes, 0..) |n, k| {
            const off = k * 13 % 64;
            const m = big[off..][0..n];
            h.out.clearRetainingCapacity();
            try h.conn.send(m, true);
            const w = h.conn.wireBytes();
            const half = w.len / 2;
            try h.out.appendSlice(testing.allocator, w[0..half]);
            h.conn.advance(half);
            try h.conn.send(big[0..20], true);
            try h.conn.send(m, true);
            try h.conn.ping("p");
            try h.conn.send(big[1..300], true);
            while (true) {
                const b = h.conn.wireBytes();
                if (b.len == 0) break;
                const step = 1 + rand.uintLessThan(usize, @min(b.len, 3 << 20));
                try h.out.appendSlice(testing.allocator, b[0..step]);
                h.conn.advance(step);
                if (rand.boolean()) h.pool.trim();
            }
            var rest: []const u8 = h.out.items;
            const expect = [_][]const u8{ m, big[0..20], m, "p", big[1..300] };
            for (expect, 0..) |e, i| {
                const f = try takeFrame(&rest);
                if (i == 3) {
                    try testing.expectEqual(@as(u4, 9), f.op);
                    try testing.expectEqualSlices(u8, e, f.payload);
                    continue;
                }
                try testing.expectEqual(@as(u4, 2), f.op);
                const msg = try messageOf(&h.pool, f, &got);
                if (!std.mem.eql(u8, e, msg)) {
                    std.debug.print("size {d} compress {} message {d} differs ({d} vs {d} bytes)\n", .{ n, compress, i, msg.len, e.len });
                    return error.TestUnexpectedResult;
                }
            }
            try testing.expectEqual(@as(usize, 0), rest.len);
            try testing.expectEqual(@as(usize, 0), h.conn.queued);
            try testing.expectEqual(@as(usize, 0), h.conn.shared.buf.len + h.conn.wire.buf.len);
            for (h.pool.ws_queues.sizes) |r| try testing.expectEqual(@as(usize, 0), r.in_use);
            try testing.expectEqual(@as(usize, 0), h.pool.ws_queues.oversized);
        }
        if (got.buf.len > 0) h.pool.releaseLarge(got.buf);
        h.pool.trim();
        h.pool.trim();
        try testing.expectEqual(@as(usize, 0), h.pool.ws_queues.held.load(.monotonic));
        // Only the large-message cache (inflating the output) stays.
        try testing.expectEqual(base + h.pool.large_bytes, heldBy(&counting));
    }
}

// A backlog of multi-MiB messages, then small ones: what buffer does a
// small message take after it?
test "verify send queues: a backlog of large messages, then small batches" {
    const big = try testing.allocator.alloc(u8, 5 << 20);
    defer testing.allocator.free(big);
    @memset(big, 'z');
    const h = try Harness.init(.{ .max_send_queue_bytes = 64 << 20 });
    defer h.deinit();
    for (0..6) |_| try h.conn.send(big, true);
    try h.flush();
    var sizes: [4]usize = undefined;
    for (&sizes) |*s| {
        try h.conn.send("small", false);
        s.* = h.conn.shared.buf.len;
        try h.flush();
    }
    std.debug.print("buffers for a small message after a 30 MiB backlog: {any}\n", .{sizes});
    try testing.expect(sizes[1] <= 4096);
}

// Fuzz target: sends of every size around the queue's size classes (with
// and without compression), pings, a close, partial writes, the pool's
// trims and whole flushes in any order. Every frame accepted goes out once,
// whole and in order, nothing after the close, and the pool's books
// balance: nothing held once written and two ticks pass.
fn fuzzSendQueues(_: void, smith: *std.testing.Smith) anyerror!void {
    const S = struct {
        var src: [300 * 1024]u8 = undefined;
        var ready = false;
    };
    if (!S.ready) {
        for (&S.src, 0..) |*b, i| b.* = @truncate((i >> 2) *% 13 +% (i & 3));
        S.ready = true;
    }
    const sizes = [_]usize{ 0, 1, 5, 125, 126, 127, 244, 246, 250, 252, 253, 254, 255, 256, 257, 500, 508, 509, 1000, 4096, 65_525, 65_527, 65_535, 65_536, 65_537, 131_062, 131_072, 131_073, 262_134, 262_144 };
    const compress = smith.value(u8) & 1 == 1;
    const limit = 1 + @as(usize, smith.value(u16)) * 8;
    const h = try Harness.init(.{ .max_send_queue_bytes = limit, .deflate = .{ .min_size = 32 } });
    defer h.deinit();
    if (compress) h.conn.enableDeflate(.{ .enabled = true });
    const Sent = struct { op: u4, off: usize, len: usize };
    var sent: std.ArrayList(Sent) = .empty;
    defer sent.deinit(testing.allocator);
    var steps: usize = 0;
    while (!smith.eos() and steps < 300) : (steps += 1) {
        switch (smith.value(u8) % 9) {
            0...2 => {
                const k = smith.value(u16);
                const n = if (k & 1 == 0) sizes[(k >> 1) % sizes.len] else @as(usize, k >> 1) * 7 % S.src.len;
                const off = smith.value(u8) % 64;
                const m = S.src[off..][0..@min(n, S.src.len - off)];
                if (h.conn.send(m, true)) {
                    try sent.append(testing.allocator, .{ .op = 2, .off = off, .len = m.len });
                } else |err| switch (err) {
                    error.SendQueueFull, error.Closed => {},
                    else => return err,
                }
            },
            3 => {
                const n = smith.value(u8) % 126;
                if (h.conn.ping(S.src[0..n])) {
                    try sent.append(testing.allocator, .{ .op = 9, .off = 0, .len = n });
                } else |err| switch (err) {
                    error.SendQueueFull, error.Closed => {},
                    else => return err,
                }
            },
            4 => if (smith.value(u8) % 8 == 0) {
                if (h.conn.close(1000, "fz")) {
                    try sent.append(testing.allocator, .{ .op = 8, .off = 0, .len = 0 });
                } else |err| switch (err) {
                    error.Closed => {},
                    else => return err,
                }
            },
            5, 6 => {
                const w = h.conn.wireBytes();
                if (w.len > 0) {
                    const k = 1 + @as(usize, smith.value(u32)) % w.len;
                    try h.out.appendSlice(testing.allocator, w[0..k]);
                    h.conn.advance(k);
                }
            },
            7 => h.pool.trim(),
            else => try h.flush(),
        }
    }
    try h.flush();
    try testing.expectEqual(@as(usize, 0), h.conn.queued);
    var got: inflate.Out = .{ .buf = &.{}, .max = 1 << 20, .pool = &h.pool };
    defer if (got.buf.len > 0) h.pool.releaseLarge(got.buf);
    var rest: []const u8 = h.out.items;
    for (sent.items) |s| {
        const f = try takeFrame(&rest);
        try testing.expectEqual(s.op, f.op);
        switch (s.op) {
            2 => try testing.expectEqualSlices(u8, S.src[s.off..][0..s.len], try messageOf(&h.pool, f, &got)),
            9 => try testing.expectEqualSlices(u8, S.src[0..s.len], f.payload),
            else => try testing.expectEqualSlices(u8, "\x03\xe8fz", f.payload),
        }
    }
    try testing.expectEqual(@as(usize, 0), rest.len);
    try expectHoldsNothing(h);
}

// Six connections sharing one worker's pool, six threads each sending to
// all of them in turn while the worker writes pieces of random ones and
// trims: buffers move between connections through the free lists.
const ManySenders = struct {
    conns: []const *Conn,
    count: usize,
    done: std.atomic.Value(usize) = .init(0),
    sent: [6][6]u32 = @splat(@splat(0)),

    fn run(self: *ManySenders, t: usize) void {
        var buf: [72 * 1024]u8 = undefined;
        var seq: [6]u32 = @splat(0);
        var k: usize = t;
        var tries: usize = 0;
        while (tries < self.count * self.conns.len) : (tries += 1) {
            k = (k + 1) % self.conns.len;
            const c = self.conns[k];
            const m = buf[0..testMsgLen(t, seq[k])];
            testMsgFill(m, t, seq[k]);
            m[0] = @intCast(t << 4 | k);
            c.send(m, true) catch |err| switch (err) {
                error.SendQueueFull => {
                    std.Thread.yield() catch {};
                    continue;
                },
                else => unreachable,
            };
            seq[k] += 1;
        }
        for (seq, 0..) |n, i| self.sent[t][i] = n;
        _ = self.done.fetchAdd(1, .release);
    }
};

test "verify send queues: connections sharing a pool, threads sending to all of them, the worker writing and trimming" {
    for ([_]bool{ false, true }) |compress| {
        const h = try Harness.init(.{ .max_send_queue_bytes = 48 * 1024, .deflate = .{ .min_size = 32 } });
        defer h.deinit();
        var conns: [6]*Conn = undefined;
        var outs: [6]std.ArrayList(u8) = @splat(.empty);
        defer for (&outs) |*o| o.deinit(testing.allocator);
        conns[0] = h.conn;
        for (conns[1..], 1..) |*c, i| c.* = try Conn.create(testing.allocator, &h.pool, @intCast(10 + i), .{ .max_send_queue_bytes = 48 * 1024, .deflate = .{ .min_size = 32 } }, &h.mailbox, .{ .kind = .ws, .slot = @intCast(i), .gen = 1 });
        defer for (conns[1..]) |c| c.destroy();
        if (compress) for (conns) |c| c.enableDeflate(.{ .enabled = true });
        var s: ManySenders = .{ .conns = &conns, .count = 300 };
        var ts: [6]std.Thread = undefined;
        for (&ts, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, ManySenders.run, .{ &s, i });
        var prng = std.Random.DefaultPrng.init(@as(u64, @intFromBool(compress)) + 40);
        const rand = prng.random();
        while (true) {
            const finished = s.done.load(.acquire) == ts.len;
            _ = h.drainMailbox();
            for (conns) |c| c.clearPosted();
            if (rand.uintLessThan(u8, 16) == 0) h.pool.trim();
            var any = false;
            for (0..conns.len) |_| {
                const i = rand.uintLessThan(usize, conns.len);
                const bytes = conns[i].wireBytes();
                if (bytes.len == 0) continue;
                any = true;
                const k = 1 + rand.uintLessThan(usize, @min(bytes.len, 30_000));
                try outs[i].appendSlice(testing.allocator, bytes[0..k]);
                conns[i].advance(k);
            }
            if (!any) {
                var pending = false;
                for (conns) |c| pending = pending or c.hasOutput();
                if (finished and !pending) break;
                std.Thread.yield() catch {};
            }
        }
        for (&ts) |t| t.join();
        var got: inflate.Out = .{ .buf = &.{}, .max = 1 << 20, .pool = &h.pool };
        defer if (got.buf.len > 0) h.pool.releaseLarge(got.buf);
        var want: [72 * 1024]u8 = undefined;
        for (outs, 0..) |o, ci| {
            var next: [6]u32 = @splat(0);
            var rest: []const u8 = o.items;
            while (rest.len > 0) {
                const f = try takeFrame(&rest);
                try testing.expectEqual(@as(u4, 2), f.op);
                const m = try messageOf(&h.pool, f, &got);
                const t = m[0] >> 4;
                try testing.expectEqual(ci, m[0] & 15);
                const seq = std.mem.readInt(u32, m[1..5], .little);
                try testing.expectEqual(next[t], seq);
                const w = want[0..testMsgLen(t, seq)];
                testMsgFill(w, t, seq);
                w[0] = m[0];
                try testing.expectEqualSlices(u8, w, m);
                next[t] += 1;
            }
            for (0..6) |t| try testing.expectEqual(s.sent[t][ci], next[t]);
        }
        for (conns) |c| try testing.expectEqual(@as(usize, 0), c.shared.buf.len + c.wire.buf.len);
        h.pool.trim();
        h.pool.trim();
        try testing.expectEqual(@as(usize, 0), h.pool.ws_queues.held.load(.monotonic));
    }
}

test "fuzz: ws send queues" {
    try std.testing.fuzz({}, fuzzSendQueues, .{ .corpus = &.{
        &[_]u8{ 0x01, 0x00, 0x10, 0x00, 0x2a, 0x00, 0x03, 0x00, 0x30, 0x05, 0x10, 0x00, 0x00, 0x00, 0x01, 0x2b, 0x01, 0x07, 0x00, 0x46, 0x00, 0x08 },
        &[_]u8{ 0x00, 0xff, 0xff, 0x02, 0x37, 0x00, 0x05, 0x05, 0x00, 0x10, 0x00, 0x00, 0x02, 0x33, 0x00, 0x09, 0x04, 0x00, 0x08 },
    } });
}
