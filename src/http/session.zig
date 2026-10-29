//! The HTTP/1.1 connection state machine, independent of the I/O model.
//! The event loop reads into a Session's buffer, calls `process`, and writes
//! whatever ends up in the Out buffer. No syscalls happen here, which keeps
//! it testable byte-by-byte and reusable by different backends.
const std = @import("std");
const parser = @import("./parser.zig");
const date = @import("./date.zig");
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const File = @import("../response.zig").File;
const Status = @import("../status.zig").Status;
const Header = @import("../header.zig").Header;
const exchange = @import("./exchange.zig");
const ws_deflate = @import("../ws/deflate.zig");
const ws_inflate = @import("../ws/inflate.zig");
const iovec_const = std.posix.iovec_const;

/// A bounded stack of things waiting for reuse: BufferPool's buffers, and
/// tls/conn.zig's connection and handshake states.
pub fn FreeList(comptime T: type) type {
    return struct {
        items: []T,
        len: usize = 0,

        pub fn pop(self: *@This()) ?T {
            if (self.len == 0) return null;
            self.len -= 1;
            return self.items[self.len];
        }

        /// False if the list is full.
        pub fn push(self: *@This(), x: T) bool {
            if (self.len == self.items.len) return false;
            self.items[self.len] = x;
            self.len += 1;
            return true;
        }

        pub fn slice(self: *const @This()) []T {
            return self.items[0..self.len];
        }
    };
}

/// Buffers of one size kept for reuse, as many as were in use at once
/// recently: `trim` (the worker's tick, once a second) frees the ones
/// beyond the most in use since the trim before, so steady traffic, bursts
/// included, allocates nothing, and an idle worker gives them all back
/// within two ticks. Releasing never frees (a send in flight may still be
/// reading a buffer until the worker has drained its ring) and never
/// allocates (acquiring made room for it).
pub const Recycler = struct {
    /// Bytes per buffer; 0 until the first user sets it.
    size: usize = 0,
    free: FreeList([]u8) = .{ .items = &.{} },
    in_use: usize = 0,
    /// The most in use at once since the last trim.
    peak: usize = 0,

    pub fn acquire(self: *Recycler, allocator: std.mem.Allocator) ![]u8 {
        if (self.free.pop()) |b| {
            self.take();
            return b;
        }
        // Room for every buffer to come back.
        if (self.free.items.len < self.in_use + 1) {
            const items = try allocator.alloc([]u8, @max(8, 2 * (self.in_use + 1)));
            @memcpy(items[0..self.free.len], self.free.slice());
            allocator.free(self.free.items);
            self.free.items = items;
        }
        const b = try allocator.alloc(u8, self.size);
        self.take();
        return b;
    }

    fn take(self: *Recycler) void {
        self.in_use += 1;
        self.peak = @max(self.peak, self.in_use);
    }

    pub fn release(self: *Recycler, buf: []u8) void {
        self.in_use -= 1;
        const kept = self.free.push(buf);
        std.debug.assert(kept);
    }

    pub fn trim(self: *Recycler, allocator: std.mem.Allocator) void {
        while (self.free.len > self.peak -| self.in_use) allocator.free(self.free.pop().?);
        self.peak = self.in_use;
        // The list shrinks with them: room for twice what is out now.
        const count = self.in_use + self.free.len;
        if (count == 0) {
            allocator.free(self.free.items);
            self.free.items = &.{};
        } else if (self.free.items.len > 8 and self.free.items.len > 4 * count) {
            const items = allocator.alloc([]u8, @max(8, 2 * count)) catch return;
            @memcpy(items[0..self.free.len], self.free.slice());
            allocator.free(self.free.items);
            self.free.items = items;
        }
    }

    /// Buffers in use or waiting for reuse: the worker keeps ticking (to
    /// trim) while there are any, connections or not.
    pub inline fn holds(self: *const Recycler) bool {
        return self.in_use + self.free.len > 0;
    }

    pub fn deinit(self: *Recycler, allocator: std.mem.Allocator) void {
        for (self.free.slice()) |b| allocator.free(b);
        allocator.free(self.free.items);
        self.* = .{};
    }
};

/// Fixed-size read buffers shared by a worker's connections. A connection
/// only holds one while it has unprocessed bytes, so idle keep-alive
/// connections cost no buffer memory.
///
/// It also keeps a few larger buffers (WebSocket messages being
/// reassembled) for the next message instead of freeing them: allocations
/// that size are mapped from the kernel, and mapping, faulting in and
/// unmapping a fresh buffer per message cost more than the message's own
/// copies.
pub const BufferPool = struct {
    const Self = @This();

    /// At most this many large buffers, and this many bytes in all, wait
    /// for reuse.
    pub const large_cache_count = 32;
    pub const large_cache_bytes = 4 * 1024 * 1024;

    buffer_size: usize,
    free: FreeList([]u8),
    large: [large_cache_count][]u8 = undefined,
    large_len: usize = 0,
    large_bytes: usize = 0,
    /// HTTP/2 output (h2/conn.zig): buffers for one frame and some
    /// control frames, and for everything `out_limit` lets a connection
    /// queue. Sizes are set by the first connection.
    out_small: Recycler = .{},
    out_large: Recycler = .{},
    /// Output buffers held or kept, as of the last trim, for other
    /// threads (tests) to read.
    output_held: std.atomic.Value(usize) = .init(0),
    /// The worker's WebSocket compressor and inflate tables, made on
    /// first use.
    ws_deflater: ?*ws_deflate.Deflater = null,
    ws_inflate_tables: ?*ws_inflate.Tables = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize, count: usize) !Self {
        var self: Self = .{
            .allocator = allocator,
            .buffer_size = buffer_size,
            .free = .{ .items = try allocator.alloc([]u8, count) },
        };
        errdefer self.deinit();
        while (self.free.len < count) _ = self.free.push(try allocator.alloc(u8, buffer_size));
        return self;
    }

    pub fn deinit(self: *Self) void {
        for (self.free.slice()) |b| self.allocator.free(b);
        self.allocator.free(self.free.items);
        for (self.large[0..self.large_len]) |b| self.allocator.free(b);
        self.out_small.deinit(self.allocator);
        self.out_large.deinit(self.allocator);
        if (self.ws_deflater) |d| self.allocator.destroy(d);
        if (self.ws_inflate_tables) |t| self.allocator.destroy(t);
    }

    /// The worker's inflate tables (permessage-deflate), about 95 KiB.
    pub fn wsInflateTables(self: *Self) !*ws_inflate.Tables {
        if (self.ws_inflate_tables) |t| return t;
        const t = try self.allocator.create(ws_inflate.Tables);
        t.init();
        self.ws_inflate_tables = t;
        return t;
    }

    /// The worker's WebSocket compressor (permessage-deflate).
    pub fn wsDeflater(self: *Self) !*ws_deflate.Deflater {
        if (self.ws_deflater) |d| return d;
        const d = try self.allocator.create(ws_deflate.Deflater);
        d.init();
        self.ws_deflater = d;
        return d;
    }

    pub fn acquire(self: *Self) ![]u8 {
        if (self.free.pop()) |b| return b;
        // Pool exhausted: overflow to the heap.
        return self.allocator.alloc(u8, self.buffer_size);
    }

    pub fn release(self: *Self, buf: []u8) void {
        if (buf.len != self.buffer_size or !self.free.push(buf)) self.allocator.free(buf);
    }

    /// Once a second, from the worker's tick: output buffers beyond what
    /// was in use recently are freed.
    pub fn trim(self: *Self) void {
        self.out_small.trim(self.allocator);
        self.out_large.trim(self.allocator);
        const held = self.out_small.in_use + self.out_small.free.len + self.out_large.in_use + self.out_large.free.len;
        self.output_held.store(held, .release);
    }

    /// Output buffers are held or kept: the worker must keep ticking.
    pub inline fn holdsOutput(self: *const Self) bool {
        return self.out_small.holds() or self.out_large.holds();
    }

    /// A buffer of at least `min` bytes: the smallest cached one that
    /// fits (the one released last, of equals: it is the warmest), or a
    /// new one (whole pages).
    pub fn acquireLarge(self: *Self, min: usize) ![]u8 {
        var best: ?usize = null;
        for (self.large[0..self.large_len], 0..) |b, i| {
            if (b.len >= min and (best == null or b.len <= self.large[best.?].len)) best = i;
        }
        if (best) |i| {
            const b = self.large[i];
            // In order, so that the newest stays last.
            std.mem.copyForwards([]u8, self.large[i .. self.large_len - 1], self.large[i + 1 .. self.large_len]);
            self.large_len -= 1;
            self.large_bytes -= b.len;
            return b;
        }
        return self.allocator.alloc(u8, std.mem.alignForward(usize, min, 4096));
    }

    /// Gives back a buffer from `acquireLarge`. Smaller cached buffers
    /// are dropped to make room for it (a larger one serves any request
    /// they would), so the cache follows the sizes in use; it is freed if
    /// everything cached is at least as large.
    pub fn releaseLarge(self: *Self, buf: []u8) void {
        if (buf.len > large_cache_bytes) return self.allocator.free(buf);
        while (self.large_len == self.large.len or self.large_bytes + buf.len > large_cache_bytes) {
            var smallest: usize = 0;
            for (self.large[1..self.large_len], 1..) |b, i| {
                if (b.len < self.large[smallest].len) smallest = i;
            }
            const victim = self.large[smallest];
            if (victim.len >= buf.len) return self.allocator.free(buf);
            self.allocator.free(victim);
            self.large_len -= 1;
            self.large[smallest] = self.large[self.large_len];
            self.large_bytes -= victim.len;
        }
        self.large[self.large_len] = buf;
        self.large_len += 1;
        self.large_bytes += buf.len;
    }
};

/// Serialised output waiting to be written: `buf[0..len]`, then `body`,
/// then `tail`.
/// Bodies up to this size are copied after the head instead of written
/// from where they are.
const copy_body_max = 1024;

pub const Out = struct {
    buf: []u8,
    len: usize = 0,
    /// An uncopied response body sent after buf[0..len].
    body: []const u8 = "",
    /// Sent after the body: the CRLF that ends a chunk of a streamed
    /// response whose bytes are borrowed.
    tail: []const u8 = "",
    /// A file body, sent after the head (with nothing in `body`). Whoever
    /// writes it closes it (`File.release`).
    file: ?File = null,

    pub inline fn isEmpty(self: *const Out) bool {
        return self.len == 0 and self.body.len == 0 and self.file == null;
    }

    /// The file, if any, has been taken by the writer.
    pub inline fn clear(self: *Out) void {
        self.len = 0;
        self.body = "";
        self.tail = "";
        self.file = null;
    }

    pub inline fn totalLen(self: *const Out) usize {
        return self.len + self.body.len + self.tail.len;
    }

    pub fn iovecs(self: *const Out, iov: *[3]iovec_const) []iovec_const {
        var n: usize = 0;
        if (self.len > 0) {
            iov[n] = .{ .base = self.buf.ptr, .len = self.len };
            n += 1;
        }
        if (self.body.len > 0) {
            iov[n] = .{ .base = self.body.ptr, .len = self.body.len };
            n += 1;
        }
        if (self.tail.len > 0) {
            iov[n] = .{ .base = self.tail.ptr, .len = self.tail.len };
            n += 1;
        }
        return iov[0..n];
    }

    pub inline fn free(self: *const Out) usize {
        return self.buf.len - self.len;
    }

    pub inline fn append(self: *Out, bytes: []const u8) void {
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }
};

pub const Action = enum {
    /// Every complete request was handled. Flush Out, then read more.
    need_more,
    /// Flush Out completely, then call process again.
    flush,
    /// Flush Out, then close the connection.
    close,
    /// Flush Out, then hand the connection and any remaining buffered
    /// bytes to the WebSocket side.
    upgrade,
    /// Flush Out; the response (or the rest of it) comes through the
    /// exchange the handler took (`resp.exchange`). Don't call process
    /// again until it ends (responses go out in request order), except
    /// to deliver a streamed request body while `wantsBody()`.
    wait,
};

pub const Options = struct {
    limits: parser.Limits = .{},
    /// 0 means unlimited.
    max_requests_per_connection: u32 = 0,
};

pub const Session = struct {
    const Self = @This();

    buf: []u8 = &.{},
    start: usize = 0,
    end: usize = 0,
    /// Resume offset for findHeadEnd, relative to start.
    head_scan: usize = 0,
    chunked: parser.ChunkedScanner = .{},
    /// Total bytes the current request needs in the buffer, if known.
    need: usize = 0,
    sent_continue: bool = false,
    requests: u32 = 0,
    /// Closing after an error, possibly with request bytes still arriving.
    /// The event loop should drain input before closing (lingering close),
    /// or the kernel may reset the connection and destroy the response.
    linger: bool = false,
    /// An exchange is pending on this connection: parsing is paused.
    waiting: bool = false,
    /// What the pending exchange's response needs to know about its
    /// request, for the worker to bind.
    wait_keep_alive: bool = true,
    wait_is_head: bool = false,
    wait_http10: bool = false,
    /// handleHead chose `.buffer` for the request being received (it is
    /// parsed again as more of its body arrives).
    head_checked: bool = false,
    /// A request body streamed to the handler (`handleHead` returned
    /// `.stream`): what is left of it, and the exchange it goes to.
    body: Body = .none,
    body_left: u64 = 0,
    body_paused: bool = false,
    body_ex: exchange.Exchange = undefined,
    /// For `.upgrade`: the permessage-deflate agreement of the WebSocket.
    ws_deflate: ws_deflate.Agreement = .{},

    pub const Body = enum(u8) {
        none,
        /// No body: only the end is still to be delivered.
        end,
        length,
        chunked,
    };

    /// Whether the event loop should read: a streamed body is arriving
    /// and the handler has not paused it.
    pub inline fn wantsBody(self: *const Self) bool {
        return self.body != .none and !self.body_paused;
    }

    /// The exchange ended: any body still arriving is not for anyone, and
    /// the connection can't be reused.
    pub fn endWait(self: *Self) bool {
        const unread = self.body != .none;
        self.waiting = false;
        self.body = .none;
        self.body_paused = false;
        return unread;
    }

    pub inline fn buffered(self: *const Self) usize {
        return self.end - self.start;
    }

    /// Whether a request is partially received.
    pub inline fn inRequest(self: *const Self) bool {
        return self.end > self.start;
    }

    /// Returns space to read into, acquiring, compacting or growing the
    /// buffer as needed.
    pub fn readSpace(self: *Self, pool: *BufferPool, opts: Options) ![]u8 {
        if (self.buf.len == 0) {
            self.buf = try pool.acquire();
            self.start = 0;
            self.end = 0;
        }
        if (self.end == self.buf.len) {
            if (self.start > 0) {
                self.compact();
            } else {
                // A full buffer with a request at its start: only a body can
                // need more room (findHeadEnd limits the head).
                const max = opts.limits.max_header_bytes + opts.limits.max_body_size * 2 + 4096;
                const wanted = if (self.need > self.buf.len) self.need else self.buf.len * 2;
                const new_len = @min(wanted, max);
                if (new_len <= self.buf.len) return error.BufferFull;
                const new_buf = try pool.allocator.alloc(u8, new_len);
                @memcpy(new_buf[0..self.end], self.buf[0..self.end]);
                pool.release(self.buf);
                self.buf = new_buf;
            }
        }
        return self.buf[self.end..];
    }

    pub inline fn commitRead(self: *Self, n: usize) void {
        self.end += n;
    }

    fn compact(self: *Self) void {
        const len = self.end - self.start;
        std.mem.copyForwards(u8, self.buf[0..len], self.buf[self.start..self.end]);
        self.start = 0;
        self.end = len;
    }

    /// Return the buffer to the pool when nothing is buffered.
    pub fn releaseIfIdle(self: *Self, pool: *BufferPool) void {
        if (self.buf.len > 0 and self.start == self.end) {
            pool.release(self.buf);
            self.buf = &.{};
            self.start = 0;
            self.end = 0;
        }
    }

    pub fn deinit(self: *Self, pool: *BufferPool) void {
        if (self.buf.len > 0) pool.release(self.buf);
        self.* = .{};
    }

    fn resetRequestState(self: *Self) void {
        self.head_scan = 0;
        self.chunked = .{};
        self.need = 0;
        self.sent_continue = false;
        self.head_checked = false;
    }
};

/// Everything `process` needs besides the session.
pub fn Context(comptime Handler: type) type {
    return struct {
        handler: *Handler,
        req: *Request,
        resp: *Response,
        /// The current "date: ...\r\n" line, refreshed once per second.
        date: *const [date.header_len]u8,
        opts: Options,
        /// Input is TLS early data (0-RTT): requests may be replays.
        early_data: bool = false,
    };
}

const continue_line = "HTTP/1.1 100 Continue\r\n\r\n";

/// Longest status line + server-managed headers (after a 100 Continue).
const fixed_head_overhead = continue_line.len + "HTTP/1.1 ".len + 48 + "content-length: ".len + 20 + 2 +
    date.header_len + "connection: keep-alive\r\n".len + 2;

/// Out must be at least this large.
pub fn headRoom(resp: *const Response) usize {
    return fixed_head_overhead + resp.header_buf.len;
}

pub fn process(comptime Handler: type, s: *Session, ctx: *const Context(Handler), out: *Out) Action {
    const opts = ctx.opts;
    if (s.waiting) {
        if (s.body != .none) return streamBody(Handler, s, ctx);
        return .wait;
    }
    while (true) {
        // A borrowed body must be written before the response is reused,
        // and Out must have room for the largest possible response head.
        // Checked before parsing: chunked bodies are decoded in place, so a
        // request must not be parsed twice.
        if (out.body.len > 0 or out.file != null) return .flush;
        if (out.len > 0 and out.free() < headRoom(ctx.resp)) return .flush;
        var data = s.buf[s.start..s.end];
        if (s.head_scan == 0) {
            // RFC 9112 §2.2: ignore empty lines before a request line.
            while (data.len >= 2 and data[0] == '\r' and data[1] == '\n') {
                s.start += 2;
                data = data[2..];
            }
            // A lone CR may be the start of another empty line; don't let
            // findHeadEnd scan past it.
            if (data.len == 1 and data[0] == '\r') return .need_more;
        }
        if (data.len == 0) return .need_more;
        const head_len = (parser.findHeadEnd(data, &s.head_scan, opts.limits) catch |err| {
            return errorResponse(s, ctx, out, err);
        }) orelse return .need_more;
        const head = parser.parseHead(data[0..head_len], ctx.req, opts.limits) catch |err| {
            return errorResponse(s, ctx, out, err);
        };
        ctx.req.early_data = ctx.early_data;
        if (ctx.early_data and !ctx.req.method.isSafe()) {
            // A replay must not change anything (RFC 8470 §5): wait for
            // the handshake, which a replay never completes, and parse
            // the request again then.
            s.head_scan = 0;
            return .need_more;
        }
        if (@hasDecl(Handler, "handleHead") and !s.head_checked) {
            ctx.resp.reset();
            var mode = ctx.handler.handleHead(ctx.req, ctx.resp);
            if (mode == .stream and !@hasDecl(Handler, "handleBody")) mode = .buffer;
            switch (mode) {
                .buffer => s.head_checked = true,
                .reject => {
                    if (finishRequest(Handler, s, ctx, out, head_len, head.framing != .none)) |action| return action;
                    continue;
                },
                .stream => {
                    if (startBody(Handler, s, ctx, out, head)) |action| return action;
                    continue;
                },
            }
        }
        var total: usize = head_len;
        switch (head.framing) {
            .none => {},
            .length => |n| {
                if (n > opts.limits.max_body_size) return errorResponse(s, ctx, out, error.PayloadTooLarge);
                total += n;
                if (data.len < total) {
                    s.need = total;
                    return awaitBody(s, ctx, out, head);
                }
                ctx.req.body = data[head_len..total];
            },
            .chunked => {
                const complete = s.chunked.scan(data[head_len..], opts.limits.max_body_size) catch |err| {
                    return errorResponse(s, ctx, out, err);
                };
                if (!complete) return awaitBody(s, ctx, out, head);
                const raw = s.buf[s.start + head_len ..][0..s.chunked.pos];
                const section = s.chunked.trailers(raw);
                if (section.len > 0) {
                    const room = ctx.req.headers[ctx.req.headers_len..];
                    const n = parser.parseTrailers(section, room) catch |err| return errorResponse(s, ctx, out, err);
                    ctx.req.trailers = room[0..n];
                }
                ctx.req.body = raw[0..parser.decodeChunked(raw)];
                total += s.chunked.pos;
            },
        }

        ctx.resp.reset();
        ctx.handler.handleRequest(ctx.req, ctx.resp);
        if (finishRequest(Handler, s, ctx, out, total, false)) |action| return action;
    }
}

/// After the handler: accounts for the request's `consumed` bytes and
/// serialises the response, or hands over to the exchange the handler
/// took. With `unread_body` the request's body was not read (rejected, or
/// answered without streaming it): the connection closes after the
/// response, draining what the client still sends. Returns null to go on
/// with the next request.
fn finishRequest(comptime Handler: type, s: *Session, ctx: *const Context(Handler), out: *Out, consumed: usize, unread_body: bool) ?Action {
    const opts = ctx.opts;
    s.requests +|= 1;
    var keep_alive = !unread_body and ctx.req.keep_alive and !ctx.resp.close and
        (opts.max_requests_per_connection == 0 or s.requests < opts.max_requests_per_connection);
    s.start += consumed;
    s.resetRequestState();
    if (ctx.resp.mode != .sync) {
        // The response comes through the exchange. A streamed body
        // without a length to an HTTP/1.0 client is close-delimited.
        const http10 = ctx.req.version == .@"HTTP/1.0";
        if (ctx.resp.mode == .stream and http10 and ctx.resp.content_length == null) keep_alive = false;
        s.waiting = true;
        s.wait_keep_alive = keep_alive;
        s.wait_is_head = ctx.req.method == .HEAD;
        s.wait_http10 = http10;
        if (ctx.resp.mode == .stream) writeStreamHead(ctx.req, ctx.resp, ctx.date, out, keep_alive);
        return .wait;
    }
    const more = s.start < s.end;
    writeResponse(ctx.req, ctx.resp, ctx.date, out, keep_alive, more);
    if (ctx.resp.is_ws_upgrade) {
        // Anything after the request is the first WebSocket frames; the
        // event loop hands the buffer to the WebSocket side.
        s.ws_deflate = ctx.resp.ws_deflate;
        return .upgrade;
    }
    if (!keep_alive) {
        s.start = s.end;
        if (unread_body) s.linger = true;
        return .close;
    }
    return null;
}

/// handleHead chose `.stream`: handleRequest runs now with an empty body.
/// If it takes an exchange, the body follows through handleBody once the
/// worker has bound the exchange (process is called again while
/// `wantsBody()`); otherwise the body is not read.
fn startBody(comptime Handler: type, s: *Session, ctx: *const Context(Handler), out: *Out, head: parser.Head) ?Action {
    ctx.resp.reset();
    ctx.handler.handleRequest(ctx.req, ctx.resp);
    if (ctx.resp.mode == .sync) return finishRequest(Handler, s, ctx, out, head.len, head.framing != .none);
    // RFC 9110 §10.1.1: now the client may send the body.
    if (head.expect_continue) out.append(continue_line);
    s.body_ex = ctx.resp.exchange;
    s.body_paused = false;
    switch (head.framing) {
        .none => s.body = .end,
        .length => |n| {
            s.body = .length;
            s.body_left = n;
        },
        .chunked => s.body = .chunked,
    }
    return finishRequest(Handler, s, ctx, out, head.len, false);
}

/// Hands the buffered part of a streamed body to handleBody, until the
/// buffer is empty (`.need_more`), the handler pauses, or the body ends
/// (`.wait`: the exchange is still answering). A malformed chunked body
/// can no longer be answered with a 400: the connection closes, and the
/// handler hears of it through handleAbort.
fn streamBody(comptime Handler: type, s: *Session, ctx: *const Context(Handler)) Action {
    if (!@hasDecl(Handler, "handleBody")) unreachable;
    while (!s.body_paused) {
        const data = s.buf[s.start..s.end];
        var chunk: []const u8 = "";
        var end: ?[]const Header = null;
        switch (s.body) {
            .none => unreachable,
            .end => end = &.{},
            .length => {
                const n: usize = @intCast(@min(s.body_left, data.len));
                if (n == 0) return .need_more;
                chunk = data[0..n];
                s.start += n;
                s.body_left -= n;
                if (s.body_left == 0) end = &.{};
            },
            .chunked => {
                const piece = s.chunked.next(data, ctx.opts.limits.max_header_bytes) catch {
                    s.start = s.end;
                    return .close;
                };
                s.start += piece.consumed;
                if (piece.done) {
                    // The worker's Request is free while the body streams:
                    // its header slots hold the trailers for the call.
                    const n = parser.parseTrailers(piece.trailers, &ctx.req.headers) catch {
                        s.start = s.end;
                        return .close;
                    };
                    end = ctx.req.headers[0..n];
                } else if (piece.data.len == 0) {
                    return .need_more;
                }
                chunk = piece.data;
            },
        }
        if (end != null) {
            s.body = .none;
            s.chunked = .{};
        }
        const action = s.body_ex.deliverBody(ctx.handler, chunk, end, ctx.resp.now.*);
        if (end != null) return .wait;
        if (action == .pause) s.body_paused = true;
    }
    return .wait;
}

fn awaitBody(s: *Session, ctx: anytype, out: *Out, head: parser.Head) Action {
    if (head.expect_continue and !s.sent_continue) {
        // RFC 9110 §10.1.1: tell the client to send the body.
        if (out.free() < continue_line.len) return .flush;
        out.append(continue_line);
        s.sent_continue = true;
    }
    _ = ctx;
    return .need_more;
}

fn errorResponse(s: *Session, ctx: anytype, out: *Out, err: parser.ParseError) Action {
    const status = parser.statusFor(err);
    const reason = status.toString();
    const needed = 9 + reason.len + 2 + "content-length: 0\r\n".len + date.header_len +
        "connection: close\r\n\r\n".len;
    if (out.free() < needed) {
        if (out.len > 0) return .flush;
        return .close;
    }
    out.append("HTTP/1.1 ");
    out.append(reason);
    out.append("\r\ncontent-length: 0\r\n");
    out.append(ctx.date);
    out.append("connection: close\r\n\r\n");
    s.start = s.end;
    s.linger = true;
    return .close;
}

/// The head of a `resp.stream()` response: chunked unless the handler set
/// a Content-Length (or the client is HTTP/1.0, which gets no framing).
fn writeStreamHead(
    req: *const Request,
    resp: *Response,
    date_line: *const [date.header_len]u8,
    out: *Out,
    keep_alive: bool,
) void {
    out.append("HTTP/1.1 ");
    out.append(resp.status.toString());
    out.append("\r\n");
    out.append(resp.headerBytes());
    if (resp.status.allowsContentLength()) {
        if (resp.content_length) |n| {
            out.append("content-length: ");
            out.len += std.fmt.printInt(out.buf[out.len..], n, 10, .lower, .{});
            out.append("\r\n");
        } else if (req.version != .@"HTTP/1.0") {
            out.append("transfer-encoding: chunked\r\n");
        }
    }
    out.append(date_line);
    if (!keep_alive) {
        out.append("connection: close\r\n");
    } else if (req.version == .@"HTTP/1.0") {
        out.append("connection: keep-alive\r\n");
    }
    out.append("\r\n");
}

fn writeResponse(
    req: *const Request,
    resp: *Response,
    date_line: *const [date.header_len]u8,
    out: *Out,
    keep_alive: bool,
    more: bool,
) void {
    const reason = resp.status.toString();
    out.append("HTTP/1.1 ");
    out.append(reason);
    out.append("\r\n");
    out.append(resp.headerBytes());
    const code = @backingInt(resp.status);
    const send_body = req.method != .HEAD and code >= 200 and code != 204 and code != 304;
    if (resp.status.allowsContentLength() and !resp.is_ws_upgrade) {
        out.append("content-length: ");
        out.len += std.fmt.printInt(out.buf[out.len..], resp.bodyLen(), 10, .lower, .{});
        out.append("\r\n");
    }
    out.append(date_line);
    if (resp.is_ws_upgrade) {
        out.append("connection: upgrade\r\n");
    } else if (!keep_alive) {
        out.append("connection: close\r\n");
    } else if (req.version == .@"HTTP/1.0") {
        out.append("connection: keep-alive\r\n");
    }
    out.append("\r\n");
    if (resp.takeFile()) |f| {
        if (send_body and f.len > 0) out.file = f else f.release();
        return;
    }
    if (!send_body or resp.body.len == 0) return;
    if ((more or resp.body.len <= copy_body_max) and resp.body.len <= out.free()) {
        // More pipelined requests follow and the response object will be
        // reused, so copy small bodies to batch them into one write. A
        // small body is copied anyway: one buffer is cheaper to send.
        out.append(resp.body);
    } else {
        out.body = resp.body;
    }
}

// ---------------------------------------------------------------------------
// Tests: drive the state machine without sockets.

const testing = std.testing;
const sys = @import("../sys.zig");
const Mailbox = @import("../mailbox.zig").Mailbox;

const EchoHandler = struct {
    calls: usize = 0,

    pub fn handleRequest(self: *EchoHandler, req: *Request, resp: *Response) void {
        self.calls += 1;
        resp.addNewHeader("x-path", req.path_and_query) catch {};
        if (std.mem.eql(u8, req.getPath(), "/close")) resp.close = true;
        if (std.mem.eql(u8, req.getPath(), "/big")) {
            const big = resp.bodyWriteBuffer();
            @memset(big[0..3000], 'b');
            resp.commitBody(3000);
            return;
        }
        _ = resp.setBody(req.body) catch {};
    }
};

const Harness = HarnessFor(EchoHandler);

/// Drives a session the way the workers do, with an exchange slab: an
/// exchange is bound when the session waits, drained into the output, and
/// ended when done.
fn HarnessFor(comptime H: type) type {
    return struct {
        const Self = @This();

        pool: BufferPool,
        session: Session = .{},
        handler: H = .{},
        req: *Request,
        resp: *Response,
        mailbox: Mailbox,
        slab: exchange.Slab,
        now: u32 = 100,
        bound: bool = false,
        out_buf: []u8,
        out: Out,
        written: std.ArrayList(u8) = .empty,
        date_line: [date.header_len]u8 = undefined,
        opts: Options,
        closed: bool = false,
        /// Input is TLS early data, as the worker would say.
        early_data: bool = false,

        fn init(opts: Options, pool_buf: usize, out_size: usize) !*Self {
            const h = try testing.allocator.create(Self);
            const out_buf = try testing.allocator.alloc(u8, out_size);
            h.* = .{
                .pool = try BufferPool.init(testing.allocator, pool_buf, 2),
                .req = try Request.init(testing.allocator),
                .resp = try Response.init(testing.allocator, 8192, 1024),
                .mailbox = try Mailbox.init(testing.allocator, 16, try sys.Waker.init()),
                .slab = undefined,
                .out_buf = out_buf,
                .out = .{ .buf = out_buf },
                .opts = opts,
            };
            h.mailbox.bind();
            h.slab = try exchange.Slab.init(testing.allocator, 4, &h.mailbox, .{});
            h.resp.exchanges = &h.slab;
            h.resp.now = &h.now;
            date.formatHeader(&h.date_line, 784111777);
            return h;
        }

        fn deinit(h: *Self) void {
            if (h.bound) h.slab.release(h.resp.exchange.slot);
            if (@hasDecl(H, "deinit")) h.handler.deinit();
            h.session.deinit(&h.pool);
            h.pool.deinit();
            h.req.deinit();
            h.resp.deinit();
            h.slab.deinit();
            h.mailbox.waker.deinit();
            h.mailbox.deinit();
            h.written.deinit(testing.allocator);
            testing.allocator.free(h.out_buf);
            testing.allocator.destroy(h);
        }

        fn flush(h: *Self) !void {
            try h.written.appendSlice(testing.allocator, h.out.buf[0..h.out.len]);
            try h.written.appendSlice(testing.allocator, h.out.body);
            try h.written.appendSlice(testing.allocator, h.out.tail);
            if (h.out.file) |f| {
                defer f.release();
                const dst = try h.written.addManyAsSlice(testing.allocator, @intCast(f.len));
                try testing.expectEqual(dst.len, try sys.pread(f.fd, dst, f.offset));
            }
            h.out.clear();
        }

        /// Feed bytes as if they arrived in one read, then run the loop the way
        /// the worker does.
        fn feed(h: *Self, bytes: []const u8) !void {
            var rest = bytes;
            while (rest.len > 0) {
                const space = try h.session.readSpace(&h.pool, h.opts);
                const n = @min(space.len, rest.len);
                @memcpy(space[0..n], rest[0..n]);
                h.session.commitRead(n);
                rest = rest[n..];
                try h.run();
                if (h.closed) return;
            }
        }

        fn run(h: *Self) !void {
            const ctx: Context(H) = .{
                .handler = &h.handler,
                .req = h.req,
                .resp = h.resp,
                .date = &h.date_line,
                .opts = h.opts,
                .early_data = h.early_data,
            };
            while (!h.closed) {
                const action = process(H, &h.session, &ctx, &h.out);
                try h.flush();
                switch (action) {
                    .flush => continue,
                    .need_more => break,
                    .close, .upgrade => h.closed = true,
                    .wait => {
                        const ex = h.resp.exchange;
                        if (!h.bound) {
                            h.slab.bindHttp1(ex, 0, 1, &h.session, h.resp, h.now);
                            h.bound = true;
                        }
                        // A resume asked for since the last look.
                        if (ex.takeResume()) h.session.body_paused = false;
                        while (true) {
                            const r = ex.fill(&h.out, &h.date_line, h.now);
                            try h.flush();
                            if (r.release) |rel| rel.call();
                            if (r.aborted) {
                                h.closed = true;
                                break;
                            }
                            if (r.done) {
                                const keep_alive = h.slab.entry(ex.slot).keep_alive;
                                h.bound = false;
                                h.slab.release(ex.slot);
                                if (h.session.endWait() or !keep_alive) h.closed = true;
                                break;
                            }
                            if (!r.progressed) break;
                        }
                        if (h.closed or !h.bound) continue;
                        if (h.session.wantsBody()) continue;
                        break;
                    },
                }
            }
            h.session.releaseIfIdle(&h.pool);
        }
    };
}

const DATE = "date: Sun, 06 Nov 1994 08:49:37 GMT\r\n";

fn dupFd(fd: sys.fd_t) sys.fd_t {
    return @intCast(std.posix.system.dup(fd));
}

fn isOpen(fd: sys.fd_t) bool {
    return std.posix.errno(std.posix.system.fcntl(fd, std.posix.F.GETFD, @as(usize, 0))) != .BADF;
}

const FileHandler = struct {
    fd: sys.fd_t = -1,
    owned: [4]sys.fd_t = @splat(-1),
    owned_len: usize = 0,

    pub fn handleRequest(self: *FileHandler, req: *Request, resp: *Response) void {
        const path = req.getPath();
        // /file: bytes 2..12 of the file; /owned: a duplicate the server
        // closes.
        if (std.mem.eql(u8, path, "/file")) {
            resp.sendFile(.{ .fd = self.fd, .offset = 2, .len = 10 });
        } else if (std.mem.startsWith(u8, path, "/owned")) {
            const dup = dupFd(self.fd);
            self.owned[self.owned_len] = dup;
            self.owned_len += 1;
            resp.sendFile(.{ .fd = dup, .len = 4, .close = true });
            // Replaced by bytes: the file is released at once.
            if (std.mem.eql(u8, path, "/owned-replaced")) resp.sendFile(.{ .fd = dupFd(self.fd), .len = 1, .close = true });
        } else {
            resp.setBodyBorrowed("hi");
        }
    }
};

test "file bodies: a range, HEAD, pipelined, owned files closed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const file = try tmp.dir.createFile(io, "body", .{ .read = true });
    defer file.close(io);
    try file.writeStreamingAll(io, "0123456789abcdef");
    const h = try HarnessFor(FileHandler).init(.{}, 4096, 4096);
    defer h.deinit();
    h.handler.fd = file.handle;
    // Pipelined: the file body ends one write; the next response follows.
    try h.feed("GET /file HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\nHEAD /file HTTP/1.1\r\nHost: x\r\n\r\n" ++
        "GET /owned HTTP/1.1\r\nHost: x\r\n\r\nHEAD /owned HTTP/1.1\r\nHost: x\r\n\r\nGET /owned-replaced HTTP/1.1\r\nHost: x\r\n\r\n");
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n" ++ DATE ++ "\r\n23456789ab" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n" ++ DATE ++ "\r\nhi" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n" ++ DATE ++ "\r\n" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 4\r\n" ++ DATE ++ "\r\n0123" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 4\r\n" ++ DATE ++ "\r\n" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 1\r\n" ++ DATE ++ "\r\n0",
        h.written.items,
    );
    try testing.expect(h.resp.file == null);
    // Owned files are closed once sent, not sent (HEAD) or replaced.
    try testing.expectEqual(@as(usize, 3), h.handler.owned_len);
    for (h.handler.owned[0..3]) |fd| try testing.expect(!isOpen(fd));
    try testing.expect(isOpen(file.handle));
}

test "single request" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nx-path: /a\r\ncontent-length: 0\r\n" ++ DATE ++ "\r\n", h.written.items);
    // The buffer went back to the pool.
    try testing.expectEqual(@as(usize, 0), h.session.buf.len);
}

test "HTTP/1.0 and close semantics" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("GET /a HTTP/1.0\r\n\r\nGET /ignored HTTP/1.0\r\n\r\n");
    try testing.expect(h.closed);
    try testing.expectEqual(@as(usize, 1), h.handler.calls);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nx-path: /a\r\ncontent-length: 0\r\n" ++ DATE ++ "connection: close\r\n\r\n", h.written.items);
}

test "HEAD omits the body but keeps its length" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("HEAD /big HTTP/1.1\r\nHost: x\r\n\r\n");
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nx-path: /big\r\ncontent-length: 3000\r\n" ++ DATE ++ "\r\n", h.written.items);
}

test "errors get a response and close" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("GET / HTTP/1.1\r\n\r\n");
    try testing.expect(h.closed);
    try testing.expectEqualStrings("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n" ++ DATE ++ "connection: close\r\n\r\n", h.written.items);
}

test "expect 100-continue" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("POST /e HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", h.written.items);
    try h.feed("hello");
    try testing.expect(std.mem.endsWith(u8, h.written.items, "\r\n\r\nhello"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, h.written.items, "100 Continue"));
}

test "large buffers are cached for reuse, best fit first, within limits" {
    var pool = try BufferPool.init(testing.allocator, 1024, 1);
    defer pool.deinit();
    const a = try pool.acquireLarge(100 * 1024);
    const b = try pool.acquireLarge(300 * 1024);
    try testing.expectEqual(@as(usize, 100 * 1024), a.len);
    pool.releaseLarge(b);
    pool.releaseLarge(a);
    try testing.expectEqual(@as(usize, 400 * 1024), pool.large_bytes);
    // The smallest that fits.
    const c = try pool.acquireLarge(50 * 1024);
    try testing.expect(c.ptr == a.ptr);
    const d = try pool.acquireLarge(200 * 1024);
    try testing.expect(d.ptr == b.ptr);
    try testing.expectEqual(@as(usize, 0), pool.large_len);
    pool.releaseLarge(c);
    pool.releaseLarge(d);
    // Over the byte limit: the smallest is dropped for a larger buffer...
    const e = try pool.acquireLarge(BufferPool.large_cache_bytes - 300 * 1024);
    pool.releaseLarge(e);
    try testing.expectEqual(@as(usize, 2), pool.large_len);
    try testing.expectEqual(BufferPool.large_cache_bytes, pool.large_bytes);
    try testing.expect((try pool.acquireLarge(1)).ptr == d.ptr);
    pool.releaseLarge(d);
    // ...but a smaller one is freed, as is one over the limit on its own.
    pool.releaseLarge(try testing.allocator.alloc(u8, 64 * 1024));
    pool.releaseLarge(try testing.allocator.alloc(u8, BufferPool.large_cache_bytes + 1));
    try testing.expectEqual(@as(usize, 2), pool.large_len);
    try testing.expectEqual(BufferPool.large_cache_bytes, pool.large_bytes);
    // At the count limit, the same.
    var many = try BufferPool.init(testing.allocator, 1024, 1);
    defer many.deinit();
    for (0..BufferPool.large_cache_count) |_| many.releaseLarge(try testing.allocator.alloc(u8, 4096));
    many.releaseLarge(try testing.allocator.alloc(u8, 8192));
    try testing.expectEqual(@as(usize, BufferPool.large_cache_count), many.large_len);
    try testing.expectEqual(@as(usize, (BufferPool.large_cache_count - 1) * 4096 + 8192), many.large_bytes);
}

test "large buffers of equal size: the one released last comes back first" {
    var pool = try BufferPool.init(testing.allocator, 1024, 1);
    defer pool.deinit();
    const a = try pool.acquireLarge(8192);
    const b = try pool.acquireLarge(8192);
    const c = try pool.acquireLarge(8192);
    pool.releaseLarge(a);
    pool.releaseLarge(b);
    pool.releaseLarge(c);
    try testing.expect((try pool.acquireLarge(8192)).ptr == c.ptr);
    try testing.expect((try pool.acquireLarge(8192)).ptr == b.ptr);
    try testing.expect((try pool.acquireLarge(8192)).ptr == a.ptr);
    // Taking a buffer of another size out keeps the order.
    const x = try pool.acquireLarge(16384);
    pool.releaseLarge(a);
    pool.releaseLarge(x);
    pool.releaseLarge(b);
    pool.releaseLarge(c);
    try testing.expect((try pool.acquireLarge(16384)).ptr == x.ptr);
    try testing.expect((try pool.acquireLarge(8192)).ptr == c.ptr);
    pool.releaseLarge(c);
    pool.releaseLarge(x);
}

test "recycler: random acquires, releases, trims and failing allocations keep the books" {
    // Every buffer handed out is distinct and stays allocated until it
    // comes back (a send may be reading it); free + held never exceeds
    // the most held at once since the trim before last; nothing leaks.
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const rand = prng.random();
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
    const a = failing.allocator();
    var r: Recycler = .{ .size = 64 };
    defer r.deinit(a);
    var held: std.ArrayList([]u8) = .empty;
    defer held.deinit(testing.allocator);
    var peak_prev: usize = 0;
    var peak_now: usize = 0;
    for (0..20000) |_| {
        switch (rand.uintLessThan(u8, 10)) {
            0...4 => {
                // Now and then an allocation fails: nothing changes.
                failing.fail_index = if (rand.uintLessThan(u8, 8) == 0) failing.alloc_index else std.math.maxInt(usize);
                const in_use = r.in_use;
                const b = r.acquire(a) catch {
                    try testing.expectEqual(in_use, r.in_use);
                    continue;
                };
                failing.fail_index = std.math.maxInt(usize);
                for (held.items) |h| try testing.expect(h.ptr != b.ptr);
                @memset(b, 0xAB);
                try held.append(testing.allocator, b);
                peak_now = @max(peak_now, held.items.len);
            },
            5...8 => if (held.items.len > 0) {
                const b = held.swapRemove(rand.uintLessThan(usize, held.items.len));
                for (b) |x| try testing.expectEqual(@as(u8, 0xAB), x);
                r.release(b);
            },
            else => {
                r.trim(a);
                peak_prev = peak_now;
                peak_now = held.items.len;
            },
        }
        try testing.expectEqual(held.items.len, r.in_use);
        try testing.expect(r.free.len + r.in_use <= r.free.items.len);
        try testing.expect(r.free.len + r.in_use <= @max(peak_prev, peak_now));
    }
    for (held.items) |b| r.release(b);
    r.trim(a);
    r.trim(a);
    // Two quiet trims (what an idle worker's ticks do): nothing held or
    // kept, the list itself included, every allocation freed.
    try testing.expectEqual(@as(usize, 0), r.free.len);
    try testing.expect(!r.holds());
    try testing.expectEqual(@as(usize, 0), r.free.items.len);
    try testing.expectEqual(failing.allocations, failing.deallocations);
}

test "recycler: keeps as many as were in use at once recently, frees the rest on trim" {
    var counting = std.testing.FailingAllocator.init(testing.allocator, .{});
    const a = counting.allocator();
    var r: Recycler = .{ .size = 4096 };
    defer r.deinit(a);
    var held: [40][]u8 = undefined;
    // Bursts of 40, again and again, between trims: allocated once.
    var warm: usize = 0;
    for (0..5) |round| {
        for (&held) |*b| b.* = try r.acquire(a);
        try testing.expectEqual(@as(usize, 40), r.peak);
        if (round == 0) warm = counting.allocations;
        for (held) |b| r.release(b);
        try testing.expectEqual(warm, counting.allocations);
        r.trim(a);
        try testing.expectEqual(@as(usize, 40), r.free.len);
    }
    // The newest is the warmest.
    const x = try r.acquire(a);
    try testing.expect(x.ptr == held[held.len - 1].ptr);
    r.release(x);
    // Idle: the trim after a quiet second frees everything.
    r.trim(a);
    try testing.expectEqual(@as(usize, 1), r.free.len);
    r.trim(a);
    try testing.expectEqual(@as(usize, 0), r.free.len);
    // Nothing is left, the list included.
    try testing.expectEqual(counting.allocations, counting.deallocations);
    try testing.expect(!r.holds());
}

test "body larger than the pool buffer grows the buffer" {
    const h = try Harness.init(.{}, 256, 4096);
    defer h.deinit();
    const body = parser.repeat("z", 2000);
    try h.feed(std.fmt.comptimePrint("POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{body.len}) ++ body);
    try testing.expect(std.mem.endsWith(u8, h.written.items, "\r\n\r\n" ++ body));
}

test "oversized body is rejected" {
    const h = try Harness.init(.{ .limits = .{ .max_body_size = 10 } }, 4096, 4096);
    defer h.deinit();
    try h.feed("POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n");
    try testing.expect(h.closed);
    try testing.expect(std.mem.startsWith(u8, h.written.items, "HTTP/1.1 413 "));
}

// The property from PLAN.md Phase 2: any split of the input, including
// byte-by-byte, and any amount of pipelining gives identical output.
test "random splits and pipelining produce identical output" {
    const requests = [_][]const u8{
        "GET /1 HTTP/1.1\r\nHost: x\r\n\r\n",
        "POST /2 HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world",
        "\r\nGET /3?q=1 HTTP/1.1\r\nHost: x\r\nCookie: " ++ parser.repeat("c", 600) ++ "\r\n\r\n",
        "POST /4 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;e=1\r\n world\r\n0\r\nT: v\r\n\r\n",
        "GET /big HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /6 HTTP/1.1\r\nHost: x\r\n\r\n",
    };
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    for (0..16) |i| try input.appendSlice(testing.allocator, requests[i % requests.len]);
    try input.appendSlice(testing.allocator, "GET /close HTTP/1.1\r\nHost: x\r\n\r\n");

    // Reference: everything in one read.
    const ref = try Harness.init(.{}, 512, 2048);
    defer ref.deinit();
    try ref.feed(input.items);
    try testing.expect(ref.closed);
    try testing.expectEqual(@as(usize, 17), ref.handler.calls);

    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    for (0..200) |iteration| {
        const h = try Harness.init(.{}, 512, 2048);
        defer h.deinit();
        var rest = input.items;
        while (rest.len > 0 and !h.closed) {
            const max_chunk: usize = if (iteration == 0) 1 else 1 + random.uintLessThan(usize, 300);
            const n = @min(rest.len, max_chunk);
            try h.feed(rest[0..n]);
            rest = rest[n..];
        }
        try testing.expect(h.closed);
        try testing.expectEqualStrings(ref.written.items, h.written.items);
    }
}

// Fuzz target: arbitrary bytes, split arbitrarily. The state machine must not
// crash or leak, and the split must never change the output. Without --fuzz
// this runs over the corpus as a regression test.
fn fuzzSplitInvariance(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [2048]u8 = undefined;
    const input = input_buf[0..smith.slice(&input_buf)];

    const whole = try Harness.init(.{ .limits = .{ .max_header_bytes = 1024, .max_body_size = 512 } }, 128, 2048);
    defer whole.deinit();
    try whole.feed(input);

    const split = try Harness.init(whole.opts, 128, 2048);
    defer split.deinit();
    var rest: []const u8 = input;
    while (rest.len > 0 and !split.closed) {
        const n = @min(rest.len, @as(usize, smith.value(u8)) + 1);
        try split.feed(rest[0..n]);
        rest = rest[n..];
    }
    try testing.expectEqual(whole.closed, split.closed);
    try testing.expectEqualStrings(whole.written.items, split.written.items);
}

test "fuzz: split invariance" {
    try std.testing.fuzz({}, fuzzSplitInvariance, .{ .corpus = &.{
        "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n",
        "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
        "POST /p HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3;e\r\nabc\r\n0\r\nT: v\r\n\r\n",
        "POST /p HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc",
        "\r\n\r\nGET /close HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
        "HEAD /big HTTP/1.1\r\nHost: x\r\n\r\n",
    } });
}

/// Streams bodies under /stream, rejects /reject, buffers the rest; logs
/// what it sees so runs can be compared.
const BodyHandler = struct {
    log: std.ArrayList(u8) = .empty,
    /// Pause after every chunk (the harness then resumes).
    pause: bool = false,
    received: usize = 0,

    pub fn deinit(self: *BodyHandler) void {
        self.log.deinit(testing.allocator);
    }

    pub fn handleHead(self: *BodyHandler, req: *Request, resp: *Response) exchange.BodyMode {
        _ = self;
        const path = req.getPath();
        if (std.mem.startsWith(u8, path, "/reject")) {
            resp.status = .unauthorized;
            resp.setBodyBorrowed("no");
            return .reject;
        }
        if (std.mem.startsWith(u8, path, "/stream")) return .stream;
        return .buffer;
    }

    pub fn handleRequest(self: *BodyHandler, req: *Request, resp: *Response) void {
        const a = testing.allocator;
        self.log.print(a, "{s} {s} body={d}", .{ @tagName(req.method), req.path_and_query, req.body.len }) catch unreachable;
        for (req.trailers) |t| self.log.print(a, " [{s}={s}]", .{ t.key, t.value }) catch unreachable;
        self.log.append(a, '\n') catch unreachable;
        if (std.mem.eql(u8, req.getPath(), "/stream-sync")) {
            resp.setBodyBorrowed("sync");
            return;
        }
        if (std.mem.startsWith(u8, req.getPath(), "/stream")) {
            self.received = 0;
            _ = resp.later() catch unreachable;
            return;
        }
        resp.setBodyBorrowed("buffered");
    }

    pub fn handleBody(self: *BodyHandler, ex: exchange.Exchange, chunk: []const u8, end: ?[]const Header) exchange.BodyAction {
        const a = testing.allocator;
        self.received += chunk.len;
        self.log.appendSlice(a, chunk) catch unreachable;
        if (end) |trailers| {
            self.log.appendSlice(a, "|END") catch unreachable;
            for (trailers) |t| self.log.print(a, " [{s}={s}]", .{ t.key, t.value }) catch unreachable;
            self.log.append(a, '\n') catch unreachable;
            var buf: [32]u8 = undefined;
            ex.respond(.{}, std.fmt.bufPrint(&buf, "got {d}", .{self.received}) catch unreachable) catch unreachable;
            return .more;
        }
        if (self.pause and chunk.len > 0) {
            ex.resumeBody() catch unreachable;
            return .pause;
        }
        return .more;
    }
};

const BodyHarness = HarnessFor(BodyHandler);

test "handleHead: reject answers without reading the body" {
    // No body: the connection stays open.
    var h = try BodyHarness.init(.{}, 4096, 4096);
    try h.feed("GET /reject HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    try testing.expect(!h.closed);
    try testing.expectEqualStrings("HTTP/1.1 401 Unauthorized\r\ncontent-length: 2\r\n" ++ DATE ++ "\r\nno" ++
        "HTTP/1.1 200 OK\r\ncontent-length: 8\r\n" ++ DATE ++ "\r\nbuffered", h.written.items);
    h.deinit();
    // A body: closed after the response, lingering; no 100 Continue.
    h = try BodyHarness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("PUT /reject HTTP/1.1\r\nHost: x\r\nContent-Length: 5000000\r\nExpect: 100-continue\r\n\r\nabc");
    try testing.expect(h.closed and h.session.linger);
    try testing.expectEqualStrings("HTTP/1.1 401 Unauthorized\r\ncontent-length: 2\r\n" ++ DATE ++ "connection: close\r\n\r\nno", h.written.items);
    try testing.expectEqual(@as(usize, 0), h.handler.log.items.len);
}

test "streamed bodies: any split delivers the same body, trailers and responses" {
    const big = parser.repeat("0123456789", 300);
    const input = "PUT /stream-a HTTP/1.1\r\nHost: x\r\nContent-Length: 3000\r\nExpect: 100-continue\r\n\r\n" ++ big ++
        "POST /stream-b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n1;e=1\r\n \r\n5\r\nworld\r\n0\r\nX-Sum: 11\r\nY: z\r\n\r\n" ++
        "POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nT: 1\r\n\r\n" ++
        "GET /stream-empty HTTP/1.1\r\nHost: x\r\n\r\n" ++
        "GET /reject HTTP/1.1\r\nHost: x\r\n\r\n" ++
        "POST /stream-sync HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd";
    // Bodies above max_body_size stream; buffered ones are still limited.
    const opts: Options = .{ .limits = .{ .max_body_size = 1000 } };

    const ref = try BodyHarness.init(opts, 512, 2048);
    defer ref.deinit();
    try ref.feed(input);
    try testing.expect(ref.closed and ref.session.linger);
    try testing.expectEqualStrings(
        "PUT /stream-a body=0\n" ++ big ++ "|END\n" ++
            "POST /stream-b body=0\nhello world|END [X-Sum=11] [Y=z]\n" ++
            "POST /c body=3 [T=1]\n" ++
            "GET /stream-empty body=0\n|END\n" ++
            "POST /stream-sync body=0\n",
        ref.handler.log.items,
    );
    try testing.expectEqualStrings(
        "HTTP/1.1 100 Continue\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 8\r\n" ++ DATE ++ "\r\ngot 3000" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 6\r\n" ++ DATE ++ "\r\ngot 11" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 8\r\n" ++ DATE ++ "\r\nbuffered" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n" ++ DATE ++ "\r\ngot 0" ++
            "HTTP/1.1 401 Unauthorized\r\ncontent-length: 2\r\n" ++ DATE ++ "\r\nno" ++
            "HTTP/1.1 200 OK\r\ncontent-length: 4\r\n" ++ DATE ++ "connection: close\r\n\r\nsync",
        ref.written.items,
    );

    var prng = std.Random.DefaultPrng.init(0xb0d1);
    const random = prng.random();
    for (0..200) |iteration| {
        const h = try BodyHarness.init(opts, 512, 2048);
        defer h.deinit();
        h.handler.pause = iteration % 2 == 1;
        var rest: []const u8 = input;
        while (rest.len > 0 and !h.closed) {
            const max_chunk: usize = if (iteration == 0) 1 else 1 + random.uintLessThan(usize, 700);
            const n = @min(rest.len, max_chunk);
            try h.feed(rest[0..n]);
            rest = rest[n..];
        }
        try testing.expect(h.closed);
        try testing.expectEqualStrings(ref.written.items, h.written.items);
        // Chunk boundaries differ; the bytes and events don't.
        try testing.expectEqualStrings(ref.handler.log.items, h.handler.log.items);
    }
}

test "streamed bodies: a malformed chunk closes the connection" {
    const h = try BodyHarness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("POST /stream HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n");
    try testing.expect(h.closed);
    try testing.expect(!h.session.linger);
    try testing.expectEqualStrings("POST /stream body=0\nabc", h.handler.log.items);
}

test "buffered bodies: Content-Length over max_body_size is 413 after handleHead" {
    const h = try BodyHarness.init(.{ .limits = .{ .max_body_size = 10 } }, 4096, 4096);
    defer h.deinit();
    try h.feed("POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n");
    try testing.expect(h.closed);
    try testing.expect(std.mem.startsWith(u8, h.written.items, "HTTP/1.1 413 "));
}

// Fuzz target: like "fuzz: split invariance", with a handler that streams,
// rejects and buffers bodies, pausing on alternate runs.
fn fuzzBodySplitInvariance(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [2048]u8 = undefined;
    const input = input_buf[0..smith.slice(&input_buf)];
    const opts: Options = .{ .limits = .{ .max_header_bytes = 1024, .max_body_size = 512 } };

    const whole = try BodyHarness.init(opts, 128, 2048);
    defer whole.deinit();
    try whole.feed(input);

    const split = try BodyHarness.init(opts, 128, 2048);
    defer split.deinit();
    split.handler.pause = smith.value(bool);
    var rest: []const u8 = input;
    while (rest.len > 0 and !split.closed) {
        const n = @min(rest.len, @as(usize, smith.value(u8)) + 1);
        try split.feed(rest[0..n]);
        rest = rest[n..];
    }
    try testing.expectEqual(whole.closed, split.closed);
    try testing.expectEqualStrings(whole.written.items, split.written.items);
    try testing.expectEqualStrings(whole.handler.log.items, split.handler.log.items);
}

test "fuzz: streamed body split invariance" {
    try std.testing.fuzz({}, fuzzBodySplitInvariance, .{ .corpus = &.{
        "PUT /stream HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "POST /stream HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3;e\r\nabc\r\n0\r\nT: v\r\n\r\n",
        "POST /stream HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc",
        "POST /reject HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc",
        "GET /reject HTTP/1.1\r\nHost: x\r\n\r\nGET /stream HTTP/1.1\r\nHost: x\r\n\r\n",
        "POST /stream-sync HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc",
        "POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nA: 1\r\nB: 2\r\n\r\n",
    } });
}

const EarlyHandler = struct {
    /// "M early|late" per call.
    log: [4][]const u8 = undefined,
    calls: usize = 0,

    pub fn handleRequest(self: *EarlyHandler, req: *Request, resp: *Response) void {
        self.log[self.calls] = switch (req.method) {
            .GET => if (req.early_data) "GET early" else "GET late",
            .POST => if (req.early_data) "POST early" else "POST late",
            else => "?",
        };
        self.calls += 1;
        _ = resp.setBody("ok") catch {};
    }
};

test "0-RTT: safe methods are handled in early data, others wait for the handshake" {
    const h = try HarnessFor(EarlyHandler).init(.{}, 4096, 4096);
    defer h.deinit();
    h.early_data = true;
    // A GET, then a pipelined POST with its body, both in early data.
    try h.feed("GET /a HTTP/1.1\r\nhost: x\r\n\r\nPOST /b HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\n\r\nhi");
    try testing.expectEqual(1, h.handler.calls);
    try testing.expectEqualStrings("GET early", h.handler.log[0]);
    // Again (more input arrives, still early): the POST still waits.
    try h.run();
    try testing.expectEqual(1, h.handler.calls);
    // The handshake completes: the POST is parsed again and handled.
    h.early_data = false;
    try h.run();
    try testing.expectEqual(2, h.handler.calls);
    try testing.expectEqualStrings("POST late", h.handler.log[1]);
    try testing.expectEqual(2, std.mem.count(u8, h.written.items, "HTTP/1.1 200 OK"));
    try testing.expect(!h.closed);
}
