//! One HTTP/2 connection (RFC 9113), independent of the I/O model. The
//! worker reads into the frame Reader, calls `process`, writes whatever is
//! in `out`, and calls `pump` once output has drained. Each stream carries
//! one request, answered through the same handler API as HTTP/1.1: the
//! synchronous path serialises HEADERS and DATA into `out` when
//! handleRequest returns, without allocating in steady state; `later()`
//! and `stream()` exchanges are drained per stream as the windows allow.
//!
//! Priorities (RFC 7540 and RFC 9218) are accepted and ignored. Server
//! push is never used.
const std = @import("std");
const frame = @import("./frame.zig");
const hpack = @import("./hpack.zig");
const parser = @import("../http/parser.zig");
const date = @import("../http/date.zig");
const exchange = @import("../http/exchange.zig");
const BufferPool = @import("../http/session.zig").BufferPool;
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const Status = @import("../status.zig").Status;
const Method = @import("../method.zig").Method;
const Header = @import("../header.zig").Header;
const MAX_HEADERS = @import("../request.zig").MAX_HEADERS;

pub const ErrorCode = frame.ErrorCode;
const NIL: u32 = std.math.maxInt(u32);

pub const Options = struct {
    limits: parser.Limits = .{},
    hpack: hpack.Limits = .{},
    /// Streams the client may have open at once (SETTINGS_MAX_CONCURRENT_STREAMS).
    max_concurrent_streams: u32 = 128,
    /// Per-stream receive window we advertise (SETTINGS_INITIAL_WINDOW_SIZE).
    initial_window_size: u32 = 1024 * 1024,
    /// Connection receive window (raised from the default with a WINDOW_UPDATE).
    connection_window: u32 = 4 * 1024 * 1024,
    /// Largest frame we accept (SETTINGS_MAX_FRAME_SIZE).
    max_frame_size: u32 = frame.min_max_frame_size,
    /// Unsent output above which `process` stops parsing until it is
    /// written (backpressure; one response may exceed it).
    out_limit: usize = 256 * 1024,
    /// RST_STREAM frames per second before the connection is closed with
    /// ENHANCE_YOUR_CALM (CVE-2023-44487).
    max_resets_per_second: u32 = 100,
    /// Frames per second that carry no request progress (PING, SETTINGS,
    /// PRIORITY, WINDOW_UPDATE, RST_STREAM, empty DATA and HEADERS, unknown
    /// types) before ENHANCE_YOUR_CALM.
    max_control_frames_per_second: u32 = 1000,
    /// Seconds a stream may hold unsent output against a zero window, or a
    /// header block may stay incomplete, before it is reset.
    request_timeout_s: u32 = 10,
};

pub const Action = enum {
    /// Everything buffered was processed; write `out`, then read more.
    need_more,
    /// `out` is above the limit: write it, then call process again.
    flush,
    /// Write `out`, then close the connection.
    close,
};

/// Everything `process` needs besides the connection.
pub fn Context(comptime Handler: type) type {
    return struct {
        handler: *Handler,
        req: *Request,
        resp: *Response,
        /// The current "date: ...\r\n" line.
        date: *const [date.header_len]u8,
        now: u32,
        exchanges: *exchange.Slab,
        /// The worker's slot and generation for this connection, for
        /// exchanges to find their way back.
        conn_slot: u32,
        conn_gen: u32,
    };
}

const StreamState = enum(u8) {
    /// Request head or body still arriving.
    open,
    /// The request is complete (END_STREAM received); responding.
    half_closed_remote,
};

const HeaderRef = struct { name_off: u32, name_len: u32, value_len: u32 };

const Stream = struct {
    id: u31 = 0,
    active: bool = false,
    state: StreamState = .open,
    recv_window: i64 = 0,
    send_window: i64 = 0,
    /// Decoded request: header names and values back to back, then the
    /// body.
    req: std.ArrayList(u8) = .empty,
    hdr: [MAX_HEADERS]HeaderRef = undefined,
    hdr_count: u16 = 0,
    /// Offsets of the pseudo-header values in `req`.
    method: ?HeaderRef = null,
    path: ?HeaderRef = null,
    scheme: ?HeaderRef = null,
    authority: ?HeaderRef = null,
    has_host: bool = false,
    regular_seen: bool = false,
    body_start: usize = 0,
    content_length: ?u64 = null,
    body_received: u64 = 0,
    /// A request fault found while decoding; answered after the block.
    fault: ?Fault = null,
    /// The response head was sent.
    head_sent: bool = false,
    /// Unsent response body (a synchronous response the windows didn't
    /// allow), then END_STREAM.
    pending: std.ArrayList(u8) = .empty,
    pending_pos: usize = 0,
    pending_end: bool = false,
    /// The exchange answering this stream, or NIL.
    exchange: u32 = NIL,
    /// Set while output waits for a window; cleared on progress.
    stalled_since: u32 = 0,
    stalled: bool = false,
    /// Bytes consumed since the last stream WINDOW_UPDATE.
    consumed: u32 = 0,

    fn clear(s: *Stream) void {
        s.req.clearRetainingCapacity();
        s.pending.clearRetainingCapacity();
        s.* = .{ .req = s.req, .pending = s.pending };
    }

    fn free(s: *Stream, allocator: std.mem.Allocator) void {
        s.req.deinit(allocator);
        s.pending.deinit(allocator);
    }

    inline fn hasOutput(s: *const Stream) bool {
        return s.pending_pos < s.pending.items.len or s.pending_end or s.exchange != NIL;
    }

    fn slice(s: *const Stream, ref: HeaderRef) []const u8 {
        return s.req.items[ref.name_off + ref.name_len ..][0..ref.value_len];
    }
};

const Fault = enum(u8) {
    /// Malformed request (RFC 9113 §8.1.1): RST_STREAM(PROTOCOL_ERROR).
    protocol,
    /// Too many or too large headers: 431.
    headers_too_large,
    /// Unknown method, or CONNECT: 501.
    not_implemented,
    /// Body over the limit: 413.
    body_too_large,
};

const State = enum(u8) {
    preface,
    /// The preface is in; the first frame must be SETTINGS.
    first_settings,
    open,
};

/// A recently closed stream, to tell "closed" from "idle" (§5.1).
const Closed = struct { id: u31 = 0, we_reset: bool = false };

pub const Conn = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    opts: Options,
    reader: frame.Reader = .{},
    frame_opts: frame.Options,
    decoder: hpack.Decoder,
    encoder: hpack.Encoder,
    /// Serialised output; the worker writes `out.items[out_pos..]`.
    out: std.ArrayList(u8) = .empty,
    out_pos: usize = 0,
    state: State = .preface,
    failed: bool = false,
    goaway_sent: bool = false,
    goaway_received: bool = false,
    /// Peer settings.
    peer_initial_window: i64 = frame.min_max_frame_size * 4 - 1, // 65535
    peer_max_frame_size: u32 = frame.min_max_frame_size,
    /// Connection flow control: what we may send, what the peer may send.
    send_window: i64 = 65535,
    recv_window: i64 = 65535,
    consumed: u32 = 0,
    streams: []Stream,
    stream_count: u32 = 0,
    /// Highest stream id the client opened (or that we refused).
    last_stream_id: u31 = 0,
    closed_ring: [64]Closed = @splat(.{}),
    closed_pos: usize = 0,
    /// Header block in progress.
    hb_stream: u31 = 0,
    hb_slot: u32 = NIL,
    hb_end_stream: bool = false,
    hb_trailers: bool = false,
    /// The block is decoded only to keep HPACK in sync; its stream is
    /// refused or closed with this code (stream error) afterwards.
    hb_discard: ?ErrorCode = null,
    hb_buf: std.ArrayList(u8) = .empty,
    hb_since: u32 = 0,
    /// Scratch for an encoded response field block.
    enc_buf: std.ArrayList(u8) = .empty,
    /// Flood budgets, per second.
    second: u32 = 0,
    resets: u32 = 0,
    control_frames: u32 = 0,
    /// Streams with unsent output or a live exchange (a scan hint).
    output_streams: u32 = 0,
    /// Every stream's output waits for the connection window.
    conn_stalled_since: u32 = 0,
    conn_stalled: bool = false,

    pub fn init(allocator: std.mem.Allocator, opts: Options) !Self {
        var decoder = try hpack.Decoder.init(allocator, opts.hpack);
        errdefer decoder.deinit();
        var encoder = try hpack.Encoder.init(allocator, hpack.default_table_size);
        errdefer encoder.deinit();
        const streams = try allocator.alloc(Stream, opts.max_concurrent_streams);
        errdefer allocator.free(streams);
        @memset(streams, .{});
        var self: Self = .{
            .allocator = allocator,
            .opts = opts,
            .frame_opts = .{ .max_frame_size = opts.max_frame_size },
            .decoder = decoder,
            .encoder = encoder,
            .streams = streams,
        };
        errdefer self.out.deinit(allocator);
        // Our preface: SETTINGS, then a larger connection window.
        var buf: [64]u8 = undefined;
        var n = try frame.writeSettings(&buf, &.{
            .{ .id = .max_concurrent_streams, .value = opts.max_concurrent_streams },
            .{ .id = .initial_window_size, .value = @min(opts.initial_window_size, frame.max_window_size) },
            .{ .id = .max_frame_size, .value = opts.max_frame_size },
            .{ .id = .max_header_list_size, .value = opts.hpack.max_header_list_size },
        });
        if (opts.connection_window > 65535) {
            n += try frame.writeWindowUpdate(buf[n..], 0, @intCast(@min(opts.connection_window, frame.max_window_size) - 65535));
            self.recv_window = @min(opts.connection_window, frame.max_window_size);
        }
        try self.out.appendSlice(allocator, buf[0..n]);
        try self.out.ensureTotalCapacity(allocator, opts.out_limit + 2 * opts.max_frame_size);
        try self.enc_buf.ensureTotalCapacity(allocator, 4096);
        return self;
    }

    /// `pool` is where the reader's buffer goes back. Exchanges still
    /// bound to streams are released through the slab (handleAbort is the
    /// worker's job before calling this, via `abortAll`).
    pub fn deinit(self: *Self, pool: *BufferPool) void {
        self.reader.deinit(pool);
        for (self.streams) |*s| s.free(self.allocator);
        self.allocator.free(self.streams);
        self.decoder.deinit();
        self.encoder.deinit();
        self.out.deinit(self.allocator);
        self.hb_buf.deinit(self.allocator);
        self.enc_buf.deinit(self.allocator);
    }

    // -- Input buffer -------------------------------------------------------

    pub fn readSpace(self: *Self, pool: *BufferPool) ![]u8 {
        return self.reader.readSpace(pool, self.frame_opts);
    }

    pub inline fn commitRead(self: *Self, n: usize) void {
        self.reader.commitRead(n);
    }

    pub fn releaseIfIdle(self: *Self, pool: *BufferPool) void {
        self.reader.releaseIfIdle(pool);
    }

    /// Whether a frame is partially received (for timeouts).
    pub inline fn inFrame(self: *const Self) bool {
        return self.reader.buffered() > 0 or self.hb_stream != 0;
    }

    // -- Output -----------------------------------------------------------

    pub fn wireBytes(self: *const Self) []const u8 {
        return self.out.items[self.out_pos..];
    }

    pub inline fn hasWire(self: *const Self) bool {
        return self.out_pos < self.out.items.len;
    }

    pub fn advance(self: *Self, n: usize) void {
        self.out_pos += n;
        if (self.out_pos == self.out.items.len) {
            self.out.clearRetainingCapacity();
            self.out_pos = 0;
        }
    }

    /// The connection should be closed once `out` is written.
    pub fn wantsClose(self: *const Self) bool {
        return self.failed or ((self.goaway_sent or self.goaway_received) and self.stream_count == 0);
    }

    /// Begins a graceful shutdown: GOAWAY, finish open streams, close.
    pub fn shutdown(self: *Self) void {
        if (self.goaway_sent) return;
        self.goaway_sent = true;
        self.writeGoaway(.no_error);
    }

    fn writeGoaway(self: *Self, code: ErrorCode) void {
        var buf: [frame.header_len + 8]u8 = undefined;
        const n = frame.writeGoaway(&buf, self.last_stream_id, code, "") catch unreachable;
        self.out.appendSlice(self.allocator, buf[0..n]) catch {};
    }

    /// A connection error (§5.4.1): GOAWAY with the code, then close.
    fn fail(self: *Self, code: ErrorCode) void {
        if (self.failed) return;
        self.failed = true;
        self.goaway_sent = true;
        self.writeGoaway(code);
    }

    fn writeRst(self: *Self, stream_id: u31, code: ErrorCode) void {
        var buf: [frame.header_len + 4]u8 = undefined;
        const n = frame.writeRstStream(&buf, stream_id, code) catch unreachable;
        self.out.appendSlice(self.allocator, buf[0..n]) catch {};
    }

    // -- Streams ------------------------------------------------------------

    fn findStream(self: *Self, id: u31) ?*Stream {
        for (self.streams) |*s| {
            if (s.active and s.id == id) return s;
        }
        return null;
    }

    fn openStream(self: *Self, id: u31) ?*Stream {
        for (self.streams) |*s| {
            if (s.active) continue;
            s.clear();
            s.active = true;
            s.id = id;
            s.recv_window = self.opts.initial_window_size;
            s.send_window = self.peer_initial_window;
            self.stream_count += 1;
            return s;
        }
        return null;
    }

    fn recentlyClosed(self: *const Self, id: u31) ?Closed {
        for (self.closed_ring) |c| {
            if (c.id == id) return c;
        }
        return null;
    }

    /// Ends a stream. `we_reset` means we sent RST_STREAM (frames that
    /// follow are ignored rather than errors).
    fn closeStream(self: *Self, ctx: anytype, s: *Stream, we_reset: bool, abort_exchange: bool) void {
        if (s.exchange != NIL) {
            self.output_streams -= 1;
            if (abort_exchange) self.abortExchange(ctx, s.exchange);
            ctx.exchanges.release(s.exchange);
            s.exchange = NIL;
        } else if (s.hasOutput()) {
            self.output_streams -= 1;
        }
        if (self.hb_slot != NIL and &self.streams[self.hb_slot] == s) {
            self.hb_stream = 0;
            self.hb_slot = NIL;
        }
        self.closed_ring[self.closed_pos] = .{ .id = s.id, .we_reset = we_reset };
        self.closed_pos = (self.closed_pos + 1) % self.closed_ring.len;
        s.active = false;
        s.clear();
        self.stream_count -= 1;
    }

    fn abortExchange(_: *Self, ctx: anytype, slot: u32) void {
        const Handler = @TypeOf(ctx.handler.*);
        if (!@hasDecl(Handler, "handleAbort")) return;
        const e = ctx.exchanges.entry(slot);
        e.mutex.lock();
        const in_use = e.state == .later or e.state == .streaming;
        e.mutex.unlock();
        if (in_use) ctx.handler.handleAbort(ctx.exchanges.handle(slot));
    }

    /// Resets a stream and closes it.
    fn resetStream(self: *Self, ctx: anytype, s: *Stream, code: ErrorCode) void {
        self.writeRst(s.id, code);
        self.closeStream(ctx, s, true, true);
    }

    /// The worker is closing the connection: tell handlers about live
    /// exchanges and release them.
    pub fn abortAll(self: *Self, ctx: anytype) void {
        for (self.streams) |*s| {
            if (s.active and s.exchange != NIL) {
                self.abortExchange(ctx, s.exchange);
                ctx.exchanges.release(s.exchange);
                s.exchange = NIL;
            }
        }
    }

    // -- Processing -----------------------------------------------------------

    pub fn process(self: *Self, comptime Handler: type, ctx: *const Context(Handler)) Action {
        self.refreshBudgets(ctx.now);
        while (true) {
            if (self.failed) return .close;
            if (self.out.items.len - self.out_pos > self.opts.out_limit) return .flush;
            if (self.state == .preface) {
                const data = self.reader.buf[self.reader.start..self.reader.end];
                if (data.len < frame.preface.len) {
                    if (!std.mem.startsWith(u8, frame.preface, data)) {
                        self.fail(.protocol_error);
                        return .close;
                    }
                    return .need_more;
                }
                if (!std.mem.eql(u8, data[0..frame.preface.len], frame.preface)) {
                    self.fail(.protocol_error);
                    return .close;
                }
                self.reader.start += frame.preface.len;
                self.state = .first_settings;
            }
            switch (self.reader.next(self.frame_opts)) {
                .need_more => break,
                .failure => |f| {
                    if (f.stream_id == 0) {
                        self.fail(f.code);
                        return .close;
                    }
                    self.countControl();
                    if (self.findStream(f.stream_id)) |s| self.resetStream(ctx, s, f.code) else self.writeRst(f.stream_id, f.code);
                },
                .frame => |fr| self.handleFrame(Handler, ctx, fr),
            }
        }
        self.pumpAll(Handler, ctx);
        if (self.failed or self.wantsClose()) return .close;
        return .need_more;
    }

    fn refreshBudgets(self: *Self, now: u32) void {
        if (now != self.second) {
            self.second = now;
            self.resets = 0;
            self.control_frames = 0;
        }
    }

    fn countControl(self: *Self) void {
        self.control_frames += 1;
        if (self.control_frames > self.opts.max_control_frames_per_second) self.fail(.enhance_your_calm);
    }

    fn handleFrame(self: *Self, comptime Handler: type, ctx: *const Context(Handler), fr: frame.Frame) void {
        if (self.state == .first_settings) {
            if (fr != .settings or fr.settings.ack) return self.fail(.protocol_error);
            self.state = .open;
        }
        // A field block in progress admits only its own CONTINUATIONs (§6.2).
        if (self.hb_stream != 0) {
            switch (fr) {
                .continuation => |c| if (c.stream_id != self.hb_stream) return self.fail(.protocol_error),
                else => return self.fail(.protocol_error),
            }
        }
        switch (fr) {
            .data => |d| self.onData(Handler, ctx, d),
            .headers => |h| self.onHeaders(Handler, ctx, h),
            .continuation => |c| self.onContinuation(Handler, ctx, c),
            .priority => self.countControl(),
            .rst_stream => |r| {
                self.countControl();
                self.resets += 1;
                if (self.resets > self.opts.max_resets_per_second) return self.fail(.enhance_your_calm);
                if (r.stream_id > self.last_stream_id or r.stream_id % 2 == 0) return self.fail(.protocol_error);
                if (self.findStream(r.stream_id)) |s| self.closeStream(ctx, s, false, true);
            },
            .settings => |s| self.onSettings(Handler, ctx, s),
            .ping => |p| {
                self.countControl();
                if (p.ack) return;
                var buf: [frame.header_len + 8]u8 = undefined;
                const n = frame.writePing(&buf, true, p.data) catch unreachable;
                self.out.appendSlice(self.allocator, buf[0..n]) catch {};
            },
            .goaway => |g| {
                self.countControl();
                self.goaway_received = true;
                _ = g;
            },
            .window_update => |w| self.onWindowUpdate(Handler, ctx, w),
            .unknown => self.countControl(),
        }
    }

    fn onSettings(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: frame.SettingsFrame) void {
        self.countControl();
        if (s.ack) return;
        var it = s.iterator();
        while (it.next()) |setting| {
            switch (setting.id) {
                .header_table_size => self.encoder.setPeerMaxTableSize(setting.value),
                .initial_window_size => {
                    // §6.9.2: every stream's send window moves by the delta.
                    const delta: i64 = @as(i64, setting.value) - self.peer_initial_window;
                    self.peer_initial_window = setting.value;
                    for (self.streams) |*st| {
                        if (!st.active) continue;
                        st.send_window += delta;
                        if (st.send_window > frame.max_window_size) return self.fail(.flow_control_error);
                    }
                },
                .max_frame_size => self.peer_max_frame_size = setting.value,
                else => {},
            }
        }
        var buf: [frame.header_len]u8 = undefined;
        _ = frame.writeSettingsAck(&buf) catch unreachable;
        self.out.appendSlice(self.allocator, &buf) catch {};
        self.pumpAll(Handler, ctx);
    }

    fn onWindowUpdate(self: *Self, comptime Handler: type, ctx: *const Context(Handler), w: anytype) void {
        self.countControl();
        if (w.stream_id == 0) {
            self.send_window += w.increment;
            if (self.send_window > frame.max_window_size) return self.fail(.flow_control_error);
            self.conn_stalled = false;
            return self.pumpAll(Handler, ctx);
        }
        if (self.findStream(w.stream_id)) |s| {
            s.send_window += w.increment;
            if (s.send_window > frame.max_window_size) return self.resetStream(ctx, s, .flow_control_error);
            s.stalled = false;
            self.pumpStream(Handler, ctx, s);
        } else if (w.stream_id > self.last_stream_id) {
            // Idle stream (§5.1).
            self.fail(.protocol_error);
        }
        // Closed: ignored (§5.1).
    }

    fn onData(self: *Self, comptime Handler: type, ctx: *const Context(Handler), d: anytype) void {
        if (d.data.len == 0) self.countControl();
        // Connection-level flow control applies whatever the stream state.
        if (d.flow_len > self.recv_window) return self.fail(.flow_control_error);
        self.recv_window -= d.flow_len;
        self.consumeConnection(d.flow_len);
        const s = self.findStream(d.stream_id) orelse {
            if (d.stream_id > self.last_stream_id or d.stream_id % 2 == 0) return self.fail(.protocol_error);
            if (self.recentlyClosed(d.stream_id)) |c| {
                if (c.we_reset) return; // §5.1: ignore for a while after our RST
                return self.writeRst(d.stream_id, .stream_closed);
            }
            return self.fail(.stream_closed);
        };
        if (s.state != .open) return self.resetStream(ctx, s, .stream_closed);
        if (d.flow_len > s.recv_window) return self.resetStream(ctx, s, .flow_control_error);
        s.recv_window -= d.flow_len;
        if (s.fault == null) {
            s.body_received += d.data.len;
            if (s.content_length) |cl| {
                if (s.body_received > cl) return self.resetStream(ctx, s, .protocol_error);
            }
            if (s.body_received > self.opts.limits.max_body_size) {
                s.fault = .body_too_large;
            } else {
                s.req.appendSlice(self.allocator, d.data) catch return self.fail(.internal_error);
            }
        }
        if (d.end_stream) {
            if (s.content_length) |cl| {
                if (s.body_received != cl and s.fault == null) return self.resetStream(ctx, s, .protocol_error);
            }
            s.state = .half_closed_remote;
            return self.dispatch(Handler, ctx, s);
        }
        // Replenish the stream window as the body is consumed, in batches.
        s.consumed += d.flow_len;
        if (s.consumed >= self.opts.initial_window_size / 2) {
            var buf: [frame.header_len + 4]u8 = undefined;
            const n = frame.writeWindowUpdate(&buf, s.id, @intCast(s.consumed)) catch unreachable;
            self.out.appendSlice(self.allocator, buf[0..n]) catch {};
            s.recv_window += s.consumed;
            s.consumed = 0;
        }
    }

    fn consumeConnection(self: *Self, n: u32) void {
        self.consumed += n;
        const window = @max(self.opts.connection_window, 65535);
        if (self.consumed >= window / 2) {
            var buf: [frame.header_len + 4]u8 = undefined;
            const len = frame.writeWindowUpdate(&buf, 0, @intCast(self.consumed)) catch unreachable;
            self.out.appendSlice(self.allocator, buf[0..len]) catch {};
            self.recv_window += self.consumed;
            self.consumed = 0;
        }
    }

    fn onHeaders(self: *Self, comptime Handler: type, ctx: *const Context(Handler), h: anytype) void {
        if (h.fragment.len == 0 and !h.end_headers) self.countControl();
        if (h.stream_id % 2 == 0) return self.fail(.protocol_error);
        self.hb_discard = null;
        self.hb_trailers = false;
        if (h.stream_id > self.last_stream_id) {
            self.last_stream_id = h.stream_id;
            if (self.goaway_sent or self.goaway_received) {
                // Not accepted after GOAWAY: decode to stay in sync, then refuse.
                self.hb_discard = .refused_stream;
                self.hb_slot = NIL;
            } else if (self.openStream(h.stream_id)) |s| {
                self.hb_slot = @intCast((@intFromPtr(s) - @intFromPtr(self.streams.ptr)) / @sizeOf(Stream));
            } else {
                // §5.1.2: over SETTINGS_MAX_CONCURRENT_STREAMS.
                self.hb_discard = .refused_stream;
                self.hb_slot = NIL;
            }
        } else if (self.findStream(h.stream_id)) |s| {
            if (s.state != .open) {
                self.hb_discard = .stream_closed;
                self.hb_slot = NIL;
            } else {
                // Trailers (§8.1): must end the stream.
                if (!h.end_stream) return self.fail(.protocol_error);
                self.hb_trailers = true;
                self.hb_slot = @intCast((@intFromPtr(s) - @intFromPtr(self.streams.ptr)) / @sizeOf(Stream));
            }
        } else if (self.recentlyClosed(h.stream_id) != null) {
            self.hb_discard = .stream_closed;
            self.hb_slot = NIL;
        } else {
            return self.fail(.protocol_error);
        }
        self.hb_stream = h.stream_id;
        self.hb_end_stream = h.end_stream;
        self.hb_since = ctx.now;
        self.hb_buf.clearRetainingCapacity();
        self.appendFragment(Handler, ctx, h.fragment, h.end_headers);
    }

    fn onContinuation(self: *Self, comptime Handler: type, ctx: *const Context(Handler), c: anytype) void {
        if (self.hb_stream == 0) return self.fail(.protocol_error);
        if (c.fragment.len == 0) self.countControl();
        self.appendFragment(Handler, ctx, c.fragment, c.end_headers);
    }

    fn appendFragment(self: *Self, comptime Handler: type, ctx: *const Context(Handler), fragment: []const u8, end: bool) void {
        // A CONTINUATION flood: the block is bounded like an HTTP/1.1 head.
        if (self.hb_buf.items.len + fragment.len > self.opts.limits.max_header_bytes) return self.fail(.enhance_your_calm);
        self.hb_buf.appendSlice(self.allocator, fragment) catch return self.fail(.internal_error);
        if (!end) return;
        const block = self.hb_buf.items;
        const stream_id = self.hb_stream;
        const slot = self.hb_slot;
        const end_stream = self.hb_end_stream;
        const trailers = self.hb_trailers;
        const discard = self.hb_discard;
        self.hb_stream = 0;
        self.hb_slot = NIL;
        if (discard) |code| {
            var sink: DiscardSink = .{};
            self.decoder.decode(block, &sink) catch |err| switch (err) {
                error.HeaderListTooLarge => {},
                else => return self.fail(.compression_error),
            };
            if (code == .refused_stream and self.recentlyClosed(stream_id) == null and self.findStream(stream_id) == null) {
                self.closed_ring[self.closed_pos] = .{ .id = stream_id, .we_reset = true };
                self.closed_pos = (self.closed_pos + 1) % self.closed_ring.len;
            }
            return self.writeRst(stream_id, code);
        }
        const s = &self.streams[slot];
        if (trailers) {
            var sink: TrailerSink = .{};
            self.decoder.decode(block, &sink) catch |err| switch (err) {
                error.HeaderListTooLarge => {},
                else => return self.fail(.compression_error),
            };
            if (sink.fault) return self.resetStream(ctx, s, .protocol_error);
            if (s.content_length) |cl| {
                if (s.body_received != cl and s.fault == null) return self.resetStream(ctx, s, .protocol_error);
            }
            s.state = .half_closed_remote;
            return self.dispatch(Handler, ctx, s);
        }
        var sink: RequestSink = .{ .stream = s, .allocator = self.allocator };
        self.decoder.decode(block, &sink) catch |err| switch (err) {
            error.HeaderListTooLarge => s.fault = s.fault orelse .headers_too_large,
            error.OutOfMemory => return self.fail(.internal_error),
            else => return self.fail(.compression_error),
        };
        if (s.fault == null and !s.has_host and s.authority != null and s.hdr_count < MAX_HEADERS) {
            // Handlers written for HTTP/1.1 look for Host.
            const auth = s.slice(s.authority.?);
            const off = s.req.items.len;
            s.req.ensureUnusedCapacity(self.allocator, 4 + auth.len) catch return self.fail(.internal_error);
            s.req.appendSliceAssumeCapacity("host");
            s.req.appendSliceAssumeCapacity(s.slice(s.authority.?));
            s.hdr[s.hdr_count] = .{ .name_off = @intCast(off), .name_len = 4, .value_len = @intCast(auth.len) };
            s.hdr_count += 1;
        }
        s.body_start = s.req.items.len;
        if (s.fault == null) self.validateRequest(s);
        if (s.fault == null) {
            if (s.content_length) |cl| {
                if (cl > self.opts.limits.max_body_size) s.fault = .body_too_large;
            }
        }
        if (end_stream) {
            if (s.content_length) |cl| {
                if (cl != 0 and s.fault == null) return self.resetStream(ctx, s, .protocol_error);
            }
            s.state = .half_closed_remote;
            return self.dispatch(Handler, ctx, s);
        }
        // A fault with a body still to come: answer now, reset the rest.
        if (s.fault) |f| {
            if (f == .protocol) return self.resetStream(ctx, s, .protocol_error);
            self.dispatch(Handler, ctx, s);
        }
    }

    /// RFC 9113 §8.3.1: the required pseudo-header fields.
    fn validateRequest(self: *Self, s: *Stream) void {
        _ = self;
        const method = s.method orelse {
            s.fault = .protocol;
            return;
        };
        if (std.mem.eql(u8, s.slice(method), "CONNECT")) {
            // RFC 9113 §8.5: no :scheme or :path. Not supported (RFC 8441 later).
            if (s.scheme != null or s.path != null) s.fault = .protocol else s.fault = .not_implemented;
            return;
        }
        const path = s.path orelse {
            s.fault = .protocol;
            return;
        };
        if (s.scheme == null or path.value_len == 0) {
            s.fault = .protocol;
            return;
        }
    }

    // -- Dispatch: the handler, and the synchronous response -------------------

    /// The request is complete (or faulted): run the handler and start the
    /// response.
    fn dispatch(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream) void {
        const req = ctx.req;
        const resp = ctx.resp;
        resp.reset();
        var is_head = false;
        if (s.fault) |f| {
            resp.status = switch (f) {
                .protocol => return self.resetStream(ctx, s, .protocol_error),
                .headers_too_large => .request_header_fields_too_large,
                .not_implemented => .not_implemented,
                .body_too_large => .payload_too_large,
            };
            resp.body = "";
        } else {
            req.reset();
            req.version = .@"HTTP/1.1";
            req.method = Method.parse(s.slice(s.method.?)) catch {
                resp.status = .not_implemented;
                return self.respondSync(Handler, ctx, s, false);
            };
            is_head = req.method == .HEAD;
            req.path_and_query = s.slice(s.path.?);
            for (s.hdr[0..s.hdr_count], 0..) |h, i| {
                req.headers[i] = .{
                    .key = s.req.items[h.name_off..][0..h.name_len],
                    .value = s.req.items[h.name_off + h.name_len ..][0..h.value_len],
                };
            }
            req.headers_len = s.hdr_count;
            req.body = s.req.items[s.body_start..];
            ctx.handler.handleRequest(req, resp);
            if (resp.mode != .sync) return self.bindExchange(Handler, ctx, s, is_head);
        }
        self.respondSync(Handler, ctx, s, is_head);
    }

    /// Serialises a complete response: HEADERS, then DATA as the windows
    /// allow (the rest is copied to the stream's pending buffer).
    fn respondSync(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream, is_head: bool) void {
        const resp = ctx.resp;
        const code = @backingInt(resp.status);
        const has_body = !is_head and code >= 200 and code != 204 and code != 304 and resp.body.len > 0;
        const content_length: ?usize = if (resp.status.allowsContentLength() and !resp.is_ws_upgrade) resp.body.len else null;
        self.writeHead(ctx, s, resp.status, resp.headerBytes(), content_length, !has_body);
        s.head_sent = true;
        if (!has_body) return self.finishStream(ctx, s);
        const sent = self.writeData(s, resp.body, true);
        if (sent < resp.body.len) {
            s.pending.appendSlice(self.allocator, resp.body[sent..]) catch return self.fail(.internal_error);
            s.pending_end = true;
            self.output_streams += 1;
            return;
        }
        self.finishStream(ctx, s);
    }

    /// Our side of the stream is done: close it, resetting the request if
    /// the client is still sending (§8.1).
    fn finishStream(self: *Self, ctx: anytype, s: *Stream) void {
        if (s.state == .open) return self.resetStream(ctx, s, .no_error);
        self.closeStream(ctx, s, false, false);
    }

    /// Writes a HEADERS frame (with CONTINUATIONs if the block is larger
    /// than the peer's maximum frame size). `lines` are "name: value\r\n".
    fn writeHead(self: *Self, ctx: anytype, s: *Stream, status: Status, lines: []const u8, content_length: ?usize, end_stream: bool) void {
        const a = self.allocator;
        self.enc_buf.clearRetainingCapacity();
        self.encodeField(":status", statusText(status)) catch return self.fail(.internal_error);
        var rest = lines;
        while (rest.len > 0) {
            const eol = std.mem.indexOf(u8, rest, "\r\n") orelse break;
            const line = rest[0..eol];
            rest = rest[eol + 2 ..];
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            // HPACK field names are lowercase (§8.2.1).
            const name = @constCast(line[0..colon]);
            for (name) |*c| c.* = std.ascii.toLower(c.*);
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            self.encodeField(name, value) catch return self.fail(.internal_error);
        }
        if (content_length) |n| {
            var num: [20]u8 = undefined;
            const len = std.fmt.printInt(&num, n, 10, .lower, .{});
            self.encodeField("content-length", num[0..len]) catch return self.fail(.internal_error);
        }
        const date_line: []const u8 = ctx.date;
        self.encodeField("date", date_line[6 .. date_line.len - 2]) catch return self.fail(.internal_error);
        // Frame it.
        var block: []const u8 = self.enc_buf.items;
        var first = true;
        while (true) {
            const n = @min(block.len, self.peer_max_frame_size);
            const last = n == block.len;
            var flags: u8 = 0;
            if (first and end_stream) flags |= frame.flag.end_stream;
            if (last) flags |= frame.flag.end_headers;
            var hdr: [frame.header_len]u8 = undefined;
            frame.writeHeader(&hdr, @intCast(n), if (first) .headers else .continuation, flags, s.id);
            self.out.appendSlice(a, &hdr) catch return self.fail(.internal_error);
            self.out.appendSlice(a, block[0..n]) catch return self.fail(.internal_error);
            block = block[n..];
            first = false;
            if (last) break;
        }
    }

    fn encodeField(self: *Self, name: []const u8, value: []const u8) !void {
        while (true) {
            const space = self.enc_buf.unusedCapacitySlice();
            const n = self.encoder.encode(space, name, value, .{}) catch |err| switch (err) {
                error.NoSpace => {
                    try self.enc_buf.ensureUnusedCapacity(self.allocator, @max(space.len * 2, 256));
                    continue;
                },
            };
            self.enc_buf.items.len += n;
            return;
        }
    }

    /// Writes as much of `data` as the windows, the peer's frame size and
    /// the output limit allow, in DATA frames. END_STREAM goes on the last
    /// frame if everything fits and `end` is set. Returns bytes sent.
    fn writeData(self: *Self, s: *Stream, data: []const u8, end: bool) usize {
        var sent: usize = 0;
        while (true) {
            const window = @min(s.send_window, self.send_window);
            const room = self.opts.out_limit + 2 * self.opts.max_frame_size -| self.out.items.len;
            const max = @min(@as(usize, if (window > 0) @intCast(window) else 0), self.peer_max_frame_size, room -| frame.header_len);
            const n = @min(max, data.len - sent);
            const last = sent + n == data.len;
            if (n == 0 and !(last and end)) break;
            var hdr: [frame.header_len]u8 = undefined;
            frame.writeHeader(&hdr, @intCast(n), .data, if (last and end) frame.flag.end_stream else 0, s.id);
            self.out.appendSlice(self.allocator, &hdr) catch return sent;
            self.out.appendSlice(self.allocator, data[sent..][0..n]) catch return sent;
            sent += n;
            s.send_window -= @intCast(n);
            self.send_window -= @intCast(n);
            if (last) break;
        }
        return sent;
    }

    // -- Exchanges ------------------------------------------------------------

    fn bindExchange(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream, is_head: bool) void {
        const resp = ctx.resp;
        const ex = resp.exchange;
        const e = ctx.exchanges.entry(ex.slot);
        e.mutex.lock();
        e.conn_slot = ctx.conn_slot;
        e.conn_gen = ctx.conn_gen;
        e.stream_id = s.id;
        e.is_head = is_head;
        e.bound = true;
        if (resp.mode == .stream) {
            e.head_pending = false;
        } else {
            e.head_pending = true;
        }
        e.mutex.unlock();
        s.exchange = ex.slot;
        self.output_streams += 1;
        if (resp.mode == .stream) {
            const content_length: ?usize = if (resp.status.allowsContentLength()) resp.content_length else null;
            self.writeHead(ctx, s, resp.status, resp.headerBytes(), content_length, false);
            s.head_sent = true;
        }
        self.pumpStream(Handler, ctx, s);
    }

    /// Called by the worker for a mailbox post naming this exchange.
    pub fn onExchangePosted(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        for (self.streams) |*s| {
            if (s.active and s.exchange == slot) return self.pumpStream(Handler, ctx, s);
        }
    }

    /// The worker's exchange deadline scan found this exchange expired.
    pub fn onExchangeTimeout(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        for (self.streams) |*s| {
            if (s.active and s.exchange == slot) return self.resetStream(ctx, s, .internal_error);
        }
    }

    /// Called by the worker after output drained: continue sending.
    pub fn pump(self: *Self, comptime Handler: type, ctx: *const Context(Handler)) void {
        self.pumpAll(Handler, ctx);
    }

    fn pumpAll(self: *Self, comptime Handler: type, ctx: *const Context(Handler)) void {
        if (self.output_streams == 0 or self.failed) return;
        for (self.streams) |*s| {
            if (!s.active or !s.hasOutput()) continue;
            if (self.out.items.len - self.out_pos > self.opts.out_limit) return;
            self.pumpStream(Handler, ctx, s);
            if (self.failed) return;
        }
    }

    /// Sends what a stream has queued (its pending buffer or exchange).
    fn pumpStream(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream) void {
        if (self.failed) return;
        if (s.pending_end or s.pending_pos < s.pending.items.len) {
            const rest = s.pending.items[s.pending_pos..];
            const n = self.writeData(s, rest, true);
            s.pending_pos += n;
            if (s.pending_pos == s.pending.items.len) {
                self.output_streams -= 1;
                s.pending_end = false;
                s.pending.clearRetainingCapacity();
                s.pending_pos = 0;
                return self.finishStream(ctx, s);
            }
            self.noteStall(ctx, s, n > 0);
            return;
        }
        if (s.exchange == NIL) return;
        const ex = ctx.exchanges.handle(s.exchange);
        const e = ctx.exchanges.entry(s.exchange);
        const is_head = e.is_head;
        while (true) {
            if (self.out.items.len - self.out_pos > self.opts.out_limit) return;
            // The head, if any, must precede the data: fetch it first.
            var r = exchange.h2Poll(ex, &.{}, ctx.now);
            if (r.aborted) return self.resetStream(ctx, s, .internal_error);
            if (r.head) |h| {
                self.writeHead(ctx, s, h.status, h.headers, h.content_length, false);
                s.head_sent = true;
            }
            if (!s.head_sent) {
                if (r.notify) self.notifyWritable(Handler, ctx, ex);
                return; // later(): nothing yet
            }
            const window = @min(s.send_window, self.send_window);
            const room = self.opts.out_limit + 2 * self.opts.max_frame_size -| self.out.items.len;
            var max = @min(@as(usize, if (window > 0) @intCast(window) else 0), self.peer_max_frame_size, room -| frame.header_len);
            if (is_head) max = self.peer_max_frame_size;
            if (max == 0) {
                self.noteStall(ctx, s, false);
                if (r.notify) self.notifyWritable(Handler, ctx, ex);
                return;
            }
            // Reserve a DATA frame and poll straight into it.
            const start = self.out.items.len;
            self.out.ensureUnusedCapacity(self.allocator, frame.header_len + max) catch return self.fail(.internal_error);
            self.out.items.len = start + frame.header_len + max;
            r = exchange.h2Poll(ex, self.out.items[start + frame.header_len ..][0..max], ctx.now);
            if (r.aborted) {
                self.out.items.len = start;
                return self.resetStream(ctx, s, .internal_error);
            }
            if (is_head) {
                // No body for HEAD: the data is dropped.
                self.out.items.len = start;
            } else if (r.n == 0) {
                self.out.items.len = start;
            } else {
                const end_on_data = r.end and r.trailers.len == 0;
                frame.writeHeader(self.out.items[start..][0..frame.header_len], @intCast(r.n), .data, if (end_on_data) frame.flag.end_stream else 0, s.id);
                self.out.items.len = start + frame.header_len + r.n;
                s.send_window -= @intCast(r.n);
                self.send_window -= @intCast(r.n);
            }
            self.noteStall(ctx, s, r.n > 0);
            if (r.notify) self.notifyWritable(Handler, ctx, ex);
            if (r.end) {
                if (r.trailers.len > 0) {
                    self.writeTrailers(s, r.trailers);
                } else if (r.n == 0 or is_head) {
                    // An empty DATA frame carries the END_STREAM.
                    var hdr: [frame.header_len]u8 = undefined;
                    frame.writeHeader(&hdr, 0, .data, frame.flag.end_stream, s.id);
                    self.out.appendSlice(self.allocator, &hdr) catch return self.fail(.internal_error);
                }
                self.output_streams -= 1;
                ctx.exchanges.release(s.exchange);
                s.exchange = NIL;
                return self.finishStream(ctx, s);
            }
            if (!r.more) return;
        }
    }

    fn writeTrailers(self: *Self, s: *Stream, lines: []const u8) void {
        self.enc_buf.clearRetainingCapacity();
        var rest = lines;
        while (rest.len > 0) {
            const eol = std.mem.indexOf(u8, rest, "\r\n") orelse break;
            const line = rest[0..eol];
            rest = rest[eol + 2 ..];
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            var lower: [256]u8 = undefined;
            const name = std.ascii.lowerString(lower[0..@min(colon, 256)], line[0..@min(colon, 256)]);
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            self.encodeField(name, value) catch return self.fail(.internal_error);
        }
        var block: []const u8 = self.enc_buf.items;
        var first = true;
        while (true) {
            const n = @min(block.len, self.peer_max_frame_size);
            const last = n == block.len;
            var flags: u8 = if (first) frame.flag.end_stream else 0;
            if (last) flags |= frame.flag.end_headers;
            var hdr: [frame.header_len]u8 = undefined;
            frame.writeHeader(&hdr, @intCast(n), if (first) .headers else .continuation, flags, s.id);
            self.out.appendSlice(self.allocator, &hdr) catch return self.fail(.internal_error);
            self.out.appendSlice(self.allocator, block[0..n]) catch return self.fail(.internal_error);
            block = block[n..];
            first = false;
            if (last) break;
        }
    }

    fn notifyWritable(_: *Self, comptime Handler: type, ctx: *const Context(Handler), ex: exchange.Exchange) void {
        if (@hasDecl(Handler, "handleWritable")) ctx.handler.handleWritable(ex);
    }

    /// Tracks a stream waiting for a window (zero-window stall defence).
    fn noteStall(self: *Self, ctx: anytype, s: *Stream, progressed: bool) void {
        if (progressed) {
            s.stalled = false;
            self.conn_stalled = false;
            return;
        }
        if (!s.stalled) {
            s.stalled = true;
            s.stalled_since = ctx.now;
        }
        if (self.send_window <= 0 and !self.conn_stalled) {
            self.conn_stalled = true;
            self.conn_stalled_since = ctx.now;
        }
    }

    /// Once a second: resets streams stalled on a zero window, and the
    /// connection when its window is the cause; fails a connection whose
    /// field block never completes.
    pub fn tick(self: *Self, comptime Handler: type, ctx: *const Context(Handler)) void {
        const timeout = self.opts.request_timeout_s;
        if (self.conn_stalled and ctx.now -% self.conn_stalled_since > timeout) return self.fail(.enhance_your_calm);
        if (self.hb_stream != 0 and ctx.now -% self.hb_since > timeout) return self.fail(.enhance_your_calm);
        for (self.streams) |*s| {
            if (!s.active or !s.stalled) continue;
            if (ctx.now -% s.stalled_since > timeout) self.resetStream(ctx, s, .cancel);
        }
    }

    pub fn activeStreams(self: *const Self) u32 {
        return self.stream_count;
    }
};

fn statusText(status: Status) []const u8 {
    return status.toString()[0..3];
}

/// Decodes a request's fields into the stream (RFC 9113 §8.2, §8.3).
const RequestSink = struct {
    stream: *Stream,
    allocator: std.mem.Allocator,

    pub fn header(self: *RequestSink, name: []const u8, value: []const u8) !void {
        const s = self.stream;
        if (s.fault != null) return;
        if (name.len == 0) {
            s.fault = .protocol;
            return;
        }
        // §8.2.1: field values must not contain NUL, CR or LF, nor start
        // or end with whitespace.
        for (value) |c| {
            if (c == 0 or c == '\r' or c == '\n') {
                s.fault = .protocol;
                return;
            }
        }
        if (value.len > 0 and (value[0] == ' ' or value[0] == '\t' or value[value.len - 1] == ' ' or value[value.len - 1] == '\t')) {
            s.fault = .protocol;
            return;
        }
        if (name[0] == ':') {
            // §8.3: pseudo-headers come first, each at most once, only
            // the request ones.
            if (s.regular_seen) {
                s.fault = .protocol;
                return;
            }
            const ref = try self.store(name, value);
            const target: *?HeaderRef = if (std.mem.eql(u8, name, ":method"))
                &s.method
            else if (std.mem.eql(u8, name, ":path"))
                &s.path
            else if (std.mem.eql(u8, name, ":scheme"))
                &s.scheme
            else if (std.mem.eql(u8, name, ":authority"))
                &s.authority
            else {
                s.fault = .protocol;
                return;
            };
            if (target.* != null) {
                s.fault = .protocol;
                return;
            }
            target.* = ref;
            return;
        }
        s.regular_seen = true;
        for (name) |c| {
            // §8.2.1: lowercase token characters only.
            if (c >= 'A' and c <= 'Z' or !isTokenChar(c)) {
                s.fault = .protocol;
                return;
            }
        }
        // §8.2.2: connection-specific fields are forbidden; TE only "trailers".
        if (std.mem.eql(u8, name, "connection") or std.mem.eql(u8, name, "keep-alive") or
            std.mem.eql(u8, name, "proxy-connection") or std.mem.eql(u8, name, "transfer-encoding") or
            std.mem.eql(u8, name, "upgrade"))
        {
            s.fault = .protocol;
            return;
        }
        if (std.mem.eql(u8, name, "te") and !std.mem.eql(u8, value, "trailers")) {
            s.fault = .protocol;
            return;
        }
        if (std.mem.eql(u8, name, "content-length")) {
            const n = std.fmt.parseInt(u64, value, 10) catch {
                s.fault = .protocol;
                return;
            };
            if (value.len == 0 or value[0] == '+' or value[0] == '-' or (s.content_length != null and s.content_length.? != n)) {
                s.fault = .protocol;
                return;
            }
            s.content_length = n;
        }
        if (std.mem.eql(u8, name, "host")) s.has_host = true;
        if (s.hdr_count >= MAX_HEADERS) {
            s.fault = .headers_too_large;
            return;
        }
        s.hdr[s.hdr_count] = try self.store(name, value);
        s.hdr_count += 1;
    }

    fn store(self: *RequestSink, name: []const u8, value: []const u8) !HeaderRef {
        const s = self.stream;
        const off = s.req.items.len;
        try s.req.ensureUnusedCapacity(self.allocator, name.len + value.len);
        s.req.appendSliceAssumeCapacity(name);
        s.req.appendSliceAssumeCapacity(value);
        return .{ .name_off = @intCast(off), .name_len = @intCast(name.len), .value_len = @intCast(value.len) };
    }
};

/// Trailers are validated and dropped (no API for them yet).
const TrailerSink = struct {
    fault: bool = false,

    pub fn header(self: *TrailerSink, name: []const u8, _: []const u8) !void {
        if (name.len == 0 or name[0] == ':') self.fault = true;
        for (name) |c| {
            if (c >= 'A' and c <= 'Z' or !isTokenChar(c)) self.fault = true;
        }
    }
};

const DiscardSink = struct {
    pub fn header(_: *DiscardSink, _: []const u8, _: []const u8) !void {}
};

fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Tests: a scripted client against the connection, without sockets.

const testing = std.testing;
const Mailbox = @import("../mailbox.zig").Mailbox;
const sys = @import("../sys.zig");

const TestHandler = struct {
    /// "METHOD path\n" plus selected headers and the body, per request.
    log: std.ArrayList(u8) = .empty,
    /// Exchanges taken by /later and /stream paths, in order.
    exchanges: std.ArrayList(exchange.Exchange) = .empty,
    aborts: usize = 0,
    writable: usize = 0,
    big: []const u8 = "",

    pub fn handleRequest(self: *TestHandler, req: *Request, resp: *Response) void {
        const a = testing.allocator;
        self.log.print(a, "{s} {s}", .{ @tagName(req.method), req.path_and_query }) catch unreachable;
        for (req.getHeaders()) |h| {
            if (std.mem.startsWith(u8, h.key, "x-") or std.mem.eql(u8, h.key, "host") or std.mem.eql(u8, h.key, "cookie")) {
                self.log.print(a, " [{s}={s}]", .{ h.key, h.value }) catch unreachable;
            }
        }
        if (req.body.len > 0) self.log.print(a, " body={d}:{s}", .{ req.body.len, req.body[0..@min(req.body.len, 12)] }) catch unreachable;
        self.log.append(a, '\n') catch unreachable;
        const path = req.getPath();
        resp.addNewHeader("Content-Type", "text/plain") catch {};
        if (std.mem.eql(u8, path, "/later") or std.mem.eql(u8, path, "/stream")) {
            const ex = if (path[1] == 'l') resp.later() catch unreachable else resp.stream() catch unreachable;
            self.exchanges.append(a, ex) catch unreachable;
            return;
        }
        if (std.mem.eql(u8, path, "/big")) {
            resp.setBodyBorrowed(self.big);
            return;
        }
        if (std.mem.eql(u8, path, "/empty")) {
            resp.status = .no_content;
            return;
        }
        if (std.mem.eql(u8, path, "/echo")) {
            _ = resp.setBody(req.body) catch {};
            return;
        }
        resp.setBodyBorrowed("Hello, World!");
    }

    pub fn handleAbort(self: *TestHandler, _: exchange.Exchange) void {
        self.aborts += 1;
    }

    pub fn handleWritable(self: *TestHandler, _: exchange.Exchange) void {
        self.writable += 1;
    }
};

const Harness = struct {
    pool: BufferPool,
    conn: Conn,
    handler: TestHandler = .{},
    req: *Request,
    resp: *Response,
    mailbox: Mailbox,
    slab: exchange.Slab,
    date_line: [date.header_len]u8 = undefined,
    now: u32 = 1000,
    /// Everything the server "wrote".
    out: std.ArrayList(u8) = .empty,
    last: Action = .need_more,
    // The client side.
    enc: hpack.Encoder,
    dec: hpack.Decoder,
    cpool: BufferPool,
    creader: frame.Reader = .{},
    /// Server frames, one per line.
    events: std.ArrayList(u8) = .empty,
    /// Server frames per stream (ordered within a stream), for comparing
    /// runs that may interleave streams differently.
    per_stream: std.AutoHashMap(u32, std.ArrayList(u8)),

    fn init(opts: Options) !*Harness {
        const a = testing.allocator;
        const h = try a.create(Harness);
        errdefer a.destroy(h);
        h.* = .{
            .pool = try BufferPool.init(a, 1024, 2),
            .conn = undefined,
            .req = try Request.init(a),
            .resp = try Response.init(a, 64 * 1024, 2048),
            .mailbox = try Mailbox.init(a, 16, try sys.Waker.init()),
            .slab = undefined,
            .enc = try hpack.Encoder.init(a, 4096),
            .dec = try hpack.Decoder.init(a, .{}),
            .cpool = try BufferPool.init(a, 1024, 2),
            .per_stream = std.AutoHashMap(u32, std.ArrayList(u8)).init(a),
        };
        h.mailbox.bind();
        h.slab = try exchange.Slab.init(a, 8, &h.mailbox, .{});
        h.resp.exchanges = &h.slab;
        h.resp.now = &h.now;
        h.conn = try Conn.init(a, opts);
        date.formatHeader(&h.date_line, 784111777);
        try h.collect();
        return h;
    }

    fn deinit(h: *Harness) void {
        const a = testing.allocator;
        h.conn.abortAll(&h.ctx());
        h.conn.deinit(&h.pool);
        h.slab.deinit();
        h.mailbox.waker.deinit();
        h.mailbox.deinit();
        h.req.deinit();
        h.resp.deinit();
        h.pool.deinit();
        h.handler.log.deinit(a);
        h.handler.exchanges.deinit(a);
        h.out.deinit(a);
        h.enc.deinit();
        h.dec.deinit();
        h.creader.deinit(&h.cpool);
        h.cpool.deinit();
        h.events.deinit(a);
        var it = h.per_stream.valueIterator();
        while (it.next()) |l| l.deinit(a);
        h.per_stream.deinit();
        a.destroy(h);
    }

    fn ctx(h: *Harness) Context(TestHandler) {
        return .{
            .handler = &h.handler,
            .req = h.req,
            .resp = h.resp,
            .date = &h.date_line,
            .now = h.now,
            .exchanges = &h.slab,
            .conn_slot = 3,
            .conn_gen = 7,
        };
    }

    /// Takes what the server wrote and parses it into events.
    fn collect(h: *Harness) !void {
        const a = testing.allocator;
        const bytes = h.conn.wireBytes();
        try h.out.appendSlice(a, bytes);
        var rest = bytes;
        while (rest.len > 0) {
            const space = try h.creader.readSpace(&h.cpool, .{ .max_frame_size = frame.max_max_frame_size });
            const n = @min(space.len, rest.len);
            @memcpy(space[0..n], rest[0..n]);
            h.creader.commitRead(n);
            rest = rest[n..];
            try h.parseServerFrames();
        }
        h.conn.advance(bytes.len);
    }

    fn parseServerFrames(h: *Harness) !void {
        const a = testing.allocator;
        while (true) {
            var line: std.ArrayList(u8) = .empty;
            defer line.deinit(a);
            var stream: u32 = 0;
            switch (h.creader.next(.{ .max_frame_size = frame.max_max_frame_size })) {
                .need_more => return,
                .failure => |f| try line.print(a, "BAD {s} on {d}", .{ @tagName(f.code), f.stream_id }),
                .frame => |fr| switch (fr) {
                    .data => |d| {
                        stream = d.stream_id;
                        try line.print(a, "data {d} len={d} end={}", .{ d.stream_id, d.data.len, d.end_stream });
                    },
                    .headers => |x| {
                        stream = x.stream_id;
                        try line.print(a, "headers {d} end={}", .{ x.stream_id, x.end_stream });
                        try testing.expect(x.end_headers); // the tests send small heads
                        const Sink = struct {
                            l: *std.ArrayList(u8),
                            pub fn header(self: *@This(), name: []const u8, value: []const u8) !void {
                                if (std.mem.eql(u8, name, "date")) {
                                    try self.l.print(testing.allocator, " [date]", .{});
                                } else {
                                    try self.l.print(testing.allocator, " [{s}={s}]", .{ name, value });
                                }
                            }
                        };
                        var sink: Sink = .{ .l = &line };
                        try h.dec.decode(x.fragment, &sink);
                    },
                    .continuation => |c| {
                        stream = c.stream_id;
                        try line.print(a, "continuation {d} len={d}", .{ c.stream_id, c.fragment.len });
                    },
                    .rst_stream => |r| {
                        stream = r.stream_id;
                        try line.print(a, "rst {d} {s}", .{ r.stream_id, @tagName(r.code) });
                    },
                    .settings => |s| {
                        try line.print(a, "settings ack={}", .{s.ack});
                        var it = s.iterator();
                        while (it.next()) |st| try line.print(a, " {s}={d}", .{ @tagName(st.id), st.value });
                    },
                    .ping => |p| try line.print(a, "ping ack={} {s}", .{ p.ack, p.data }),
                    .goaway => |g| try line.print(a, "goaway last={d} {s}", .{ g.last_stream_id, @tagName(g.code) }),
                    .window_update => |w| {
                        stream = w.stream_id;
                        try line.print(a, "window {d} +{d}", .{ w.stream_id, w.increment });
                    },
                    .priority, .unknown => try line.print(a, "?", .{}),
                },
            }
            try h.events.appendSlice(a, line.items);
            try h.events.append(a, '\n');
            const gop = try h.per_stream.getOrPut(stream);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.appendSlice(a, line.items);
            try gop.value_ptr.append(a, '\n');
        }
    }

    /// Feeds client bytes as one read and runs the loop the worker runs.
    fn feed(h: *Harness, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0) {
            const space = try h.conn.readSpace(&h.pool);
            const n = @min(space.len, rest.len);
            @memcpy(space[0..n], rest[0..n]);
            h.conn.commitRead(n);
            rest = rest[n..];
            try h.run();
            if (h.last == .close) return;
        }
    }

    fn run(h: *Harness) !void {
        while (true) {
            const c = h.ctx();
            h.last = h.conn.process(TestHandler, &c);
            try h.collect();
            try h.drainMailbox();
            try h.collect();
            if (h.last != .flush) break;
        }
        h.conn.releaseIfIdle(&h.pool);
    }

    fn drainMailbox(h: *Harness) !void {
        var entries: [16]@import("../mailbox.zig").Entry = undefined;
        while (true) {
            const n = h.mailbox.drain(&entries);
            if (n == 0) break;
            for (entries[0..n]) |e| {
                const c = h.ctx();
                if (e.kind == .exchange) h.conn.onExchangePosted(TestHandler, &c, e.slot);
            }
        }
    }

    fn tick(h: *Harness, seconds: u32) !void {
        h.now += seconds;
        const c = h.ctx();
        h.conn.tick(TestHandler, &c);
        if (h.conn.wantsClose()) h.last = .close;
        try h.collect();
    }

    // -- Client frames --

    fn preface(h: *Harness) !void {
        try h.feed(frame.preface);
        var buf: [64]u8 = undefined;
        const n = try frame.writeSettings(&buf, &.{});
        try h.feed(buf[0..n]);
    }

    const Head = struct { stream: u31, fields: []const hpack.Field, end_stream: bool = true, flags: u8 = 0 };

    fn encodeFields(h: *Harness, fields: []const hpack.Field) ![]u8 {
        var block: [8192]u8 = undefined;
        var n: usize = 0;
        for (fields) |f| n += try h.enc.encode(block[n..], f.name, f.value, .{});
        return try testing.allocator.dupe(u8, block[0..n]);
    }

    fn headers(h: *Harness, head: Head) !void {
        const block = try h.encodeFields(head.fields);
        defer testing.allocator.free(block);
        var out = try testing.allocator.alloc(u8, block.len + frame.header_len);
        defer testing.allocator.free(out);
        var flags = head.flags | frame.flag.end_headers;
        if (head.end_stream) flags |= frame.flag.end_stream;
        const n = try frame.writeHeaders(out, head.stream, flags, block);
        try h.feed(out[0..n]);
    }

    fn get(h: *Harness, stream: u31, path: []const u8) !void {
        try h.headers(.{ .stream = stream, .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = path },
            .{ .name = ":authority", .value = "example.com" },
        } });
    }

    fn data(h: *Harness, stream: u31, bytes: []const u8, end: bool) !void {
        const out = try testing.allocator.alloc(u8, bytes.len + frame.header_len);
        defer testing.allocator.free(out);
        const n = try frame.writeData(out, stream, end, bytes);
        try h.feed(out[0..n]);
    }

    fn window(h: *Harness, stream: u31, inc: u31) !void {
        var buf: [frame.header_len + 4]u8 = undefined;
        const n = try frame.writeWindowUpdate(&buf, stream, inc);
        try h.feed(buf[0..n]);
    }

    fn rst(h: *Harness, stream: u31, code: ErrorCode) !void {
        var buf: [frame.header_len + 4]u8 = undefined;
        const n = try frame.writeRstStream(&buf, stream, code);
        try h.feed(buf[0..n]);
    }

    fn settings(h: *Harness, list: []const frame.Setting) !void {
        var buf: [128]u8 = undefined;
        const n = try frame.writeSettings(&buf, list);
        try h.feed(buf[0..n]);
    }

    fn expectEvents(h: *Harness, expected: []const u8) !void {
        try testing.expectEqualStrings(expected, h.events.items);
        h.events.clearRetainingCapacity();
    }

    fn expectLog(h: *Harness, expected: []const u8) !void {
        try testing.expectEqualStrings(expected, h.handler.log.items);
        h.handler.log.clearRetainingCapacity();
    }
};

const server_preface = "settings ack=false max_concurrent_streams=128 initial_window_size=1048576 max_frame_size=16384 max_header_list_size=16384\nwindow 0 +4128769\n";

test "preface and settings exchange" {
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.expectEvents(server_preface);
    try h.feed(frame.preface[0..10]);
    try h.expectEvents("");
    try h.feed(frame.preface[10..]);
    try h.settings(&.{.{ .id = .header_table_size, .value = 0 }});
    try h.expectEvents("settings ack=true\n");
    try testing.expectEqual(Action.need_more, h.last);
    // Our encoder now signals the table size at the start of the next block.
    try h.get(1, "/");
    try h.expectEvents("headers 1 end=false [:status=200] [content-type=text/plain] [content-length=13] [date]\ndata 1 len=13 end=true\n");
    try h.expectLog("GET / [host=example.com]\n");
}

test "a bad preface, or a first frame that isn't SETTINGS, fails the connection" {
    {
        const h = try Harness.init(.{});
        defer h.deinit();
        h.events.clearRetainingCapacity();
        try h.feed("GET / HTTP/1.1\r\n");
        try testing.expectEqual(Action.close, h.last);
        try h.expectEvents("goaway last=0 protocol_error\n");
    }
    {
        const h = try Harness.init(.{});
        defer h.deinit();
        h.events.clearRetainingCapacity();
        try h.feed(frame.preface);
        var buf: [frame.header_len + 8]u8 = undefined;
        const n = try frame.writePing(&buf, false, "12345678");
        try h.feed(buf[0..n]);
        try testing.expectEqual(Action.close, h.last);
        try h.expectEvents("goaway last=0 protocol_error\n");
    }
}

test "requests: fast path, bodies, trailers, multiplexing, HEAD, 204" {
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    // Three streams, a POST interleaved with GETs, each answered in order.
    try h.headers(.{ .stream = 1, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo?q=1" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "11" },
        .{ .name = "x-custom", .value = "v" },
    } });
    try h.get(3, "/a");
    try h.data(1, "hello ", false);
    try h.get(5, "/b");
    try h.data(1, "world", true);
    try h.expectEvents(
        \\headers 3 end=false [:status=200] [content-type=text/plain] [content-length=13] [date]
        \\data 3 len=13 end=true
        \\headers 5 end=false [:status=200] [content-type=text/plain] [content-length=13] [date]
        \\data 5 len=13 end=true
        \\headers 1 end=false [:status=200] [content-type=text/plain] [content-length=11] [date]
        \\data 1 len=11 end=true
        \\
    );
    try h.expectLog("GET /a [host=example.com]\nGET /b [host=example.com]\nPOST /echo?q=1 [x-custom=v] [host=example.com] body=11:hello world\n");
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    // Trailers end a request; a HEAD gets the length but no body; 204 has neither.
    try h.headers(.{ .stream = 7, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = ":authority", .value = "example.com" },
    } });
    try h.data(7, "abc", false);
    try h.headers(.{ .stream = 7, .end_stream = true, .fields = &.{.{ .name = "x-trailer", .value = "t" }} });
    try h.headers(.{ .stream = 9, .fields = &.{
        .{ .name = ":method", .value = "HEAD" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "h" },
    } });
    try h.get(11, "/empty");
    try h.expectEvents(
        \\headers 7 end=false [:status=200] [content-type=text/plain] [content-length=3] [date]
        \\data 7 len=3 end=true
        \\headers 9 end=true [:status=200] [content-type=text/plain] [content-length=13] [date]
        \\headers 11 end=true [:status=204] [content-type=text/plain] [date]
        \\
    );
    try h.expectLog("POST /echo [host=example.com] body=3:abc\nHEAD / [host=h]\nGET /empty [host=example.com]\n");
}

test "request validation (RFC 9113 §8): each rule, and the status codes" {
    const h = try Harness.init(.{ .limits = .{ .max_body_size = 10 } });
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    const ok = [_]hpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    const cases = [_]struct { fields: []const hpack.Field, expect: []const u8 }{
        // Missing :method, :scheme, :path; empty :path.
        .{ .fields = ok[1..], .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[2] }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = ok[0..2], .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], .{ .name = ":path", .value = "" } }, .expect = "rst {d} protocol_error\n" },
        // Duplicate and unknown pseudo-headers, a response pseudo-header,
        // a pseudo-header after a regular one.
        .{ .fields = &.{ ok[0], ok[1], ok[2], ok[0] }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = ":foo", .value = "bar" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = ":status", .value = "200" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], .{ .name = "x", .value = "y" }, ok[2] }, .expect = "rst {d} protocol_error\n" },
        // Uppercase names, connection-specific fields, TE other than trailers.
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "X-Up", .value = "y" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "connection", .value = "close" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "transfer-encoding", .value = "chunked" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "keep-alive", .value = "x" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "te", .value = "gzip" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "te", .value = "trailers" } }, .expect = "headers {d} end=false [:status=200] [content-type=text/plain] [content-length=13] [date]\ndata {d} len=13 end=true\n" },
        // Field values with CR, LF, NUL, or surrounding whitespace.
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "x", .value = "a\nb" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "x", .value = " a" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "x", .value = "a\x00" } }, .expect = "rst {d} protocol_error\n" },
        // Bad content-length values.
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "content-length", .value = "x" } }, .expect = "rst {d} protocol_error\n" },
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "content-length", .value = "1" }, .{ .name = "content-length", .value = "2" } }, .expect = "rst {d} protocol_error\n" },
        // content-length with END_STREAM and no body.
        .{ .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "content-length", .value = "5" } }, .expect = "rst {d} protocol_error\n" },
        // A method we don't know, and CONNECT: 501. A body over the limit: 413.
        .{ .fields = &.{ .{ .name = ":method", .value = "BREW" }, ok[1], ok[2] }, .expect = "headers {d} end=true [:status=501] [content-length=0] [date]\n" },
        .{ .fields = &.{.{ .name = ":method", .value = "CONNECT" }}, .expect = "headers {d} end=true [:status=501] [content-length=0] [date]\n" },
        .{ .fields = &.{ .{ .name = ":method", .value = "CONNECT" }, ok[2] }, .expect = "rst {d} protocol_error\n" },
    };
    var stream: u31 = 1;
    for (cases) |case| {
        try h.headers(.{ .stream = stream, .fields = case.fields });
        var expected: [256]u8 = undefined;
        var n: usize = 0;
        var it = std.mem.splitSequence(u8, case.expect, "{d}");
        var first = true;
        while (it.next()) |part| {
            if (!first) n += std.fmt.printInt(expected[n..], stream, 10, .lower, .{});
            first = false;
            @memcpy(expected[n..][0..part.len], part);
            n += part.len;
        }
        try h.expectEvents(expected[0..n]);
        stream += 2;
    }
    // Too many headers: 431, with the table still in sync afterwards.
    {
        var many: [MAX_HEADERS + 4]hpack.Field = undefined;
        many[0] = ok[0];
        many[1] = ok[1];
        many[2] = ok[2];
        for (many[3..]) |*f| f.* = .{ .name = "x-h", .value = "v" };
        try h.headers(.{ .stream = stream, .fields = &many });
        try testing.expect(std.mem.indexOf(u8, h.events.items, "[:status=431]") != null);
        h.events.clearRetainingCapacity();
        stream += 2;
        try h.get(stream, "/");
        try testing.expect(std.mem.indexOf(u8, h.events.items, "[:status=200]") != null);
        h.events.clearRetainingCapacity();
        stream += 2;
    }
    // Content-Length over max_body_size (10): 413 at once, the rest reset.
    try h.headers(.{ .stream = stream, .end_stream = false, .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "content-length", .value = "11" } } });
    try testing.expect(std.mem.indexOf(u8, h.events.items, "[:status=413]") != null);
    try testing.expect(std.mem.endsWith(u8, h.events.items, "no_error\n"));
    h.events.clearRetainingCapacity();
    stream += 2;
    // Body longer than content-length, and shorter at END_STREAM.
    try h.headers(.{ .stream = stream, .end_stream = false, .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "content-length", .value = "2" } } });
    try h.data(stream, "abc", true);
    var buf: [64]u8 = undefined;
    try h.expectEvents(try std.fmt.bufPrint(&buf, "rst {d} protocol_error\n", .{stream}));
    stream += 2;
    try h.headers(.{ .stream = stream, .end_stream = false, .fields = &.{ ok[0], ok[1], ok[2], .{ .name = "content-length", .value = "4" } } });
    try h.data(stream, "abc", true);
    try h.expectEvents(try std.fmt.bufPrint(&buf, "rst {d} protocol_error\n", .{stream}));
    stream += 2;
    // A body without content-length that grows past the limit: 413.
    try h.headers(.{ .stream = stream, .end_stream = false, .fields = &ok });
    try h.data(stream, "123456", false);
    try h.data(stream, "7890123", true);
    try testing.expect(std.mem.indexOf(u8, h.events.items, "[:status=413]") != null);
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    try testing.expectEqual(Action.need_more, h.last);
}

test "stream states: idle, closed, decreasing ids, even ids, concurrency limit" {
    const h = try Harness.init(.{ .max_concurrent_streams = 2 });
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    // Over the limit: REFUSED_STREAM, and the block was decoded (the
    // dynamic table stays in sync for the next request).
    const post = [_]hpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = "x-indexed", .value = "value that goes into the dynamic table" },
    };
    try h.headers(.{ .stream = 1, .end_stream = false, .fields = &post });
    try h.headers(.{ .stream = 3, .end_stream = false, .fields = &post });
    try h.headers(.{ .stream = 5, .end_stream = false, .fields = &post });
    try h.expectEvents("rst 5 refused_stream\n");
    try h.data(1, "", true);
    try h.data(3, "", true);
    try h.expectEvents("headers 1 end=true [:status=200] [content-type=text/plain] [content-length=0] [date]\nheaders 3 end=true [:status=200] [content-type=text/plain] [content-length=0] [date]\n");
    try h.headers(.{ .stream = 7, .fields = &post });
    try h.expectEvents("headers 7 end=true [:status=200] [content-type=text/plain] [content-length=0] [date]\n");
    try h.expectLog("POST /echo [x-indexed=value that goes into the dynamic table]\nPOST /echo [x-indexed=value that goes into the dynamic table]\nPOST /echo [x-indexed=value that goes into the dynamic table]\n");
    // DATA and HEADERS on closed streams (we finished them): STREAM_CLOSED.
    try h.data(1, "x", false);
    try h.expectEvents("rst 1 stream_closed\n");
    try h.get(3, "/");
    try h.expectEvents("rst 3 stream_closed\n");
    // After our RST (refused stream 5), its DATA is ignored.
    try h.data(5, "x", false);
    try h.expectEvents("");
    // A stream id below the highest, never seen: a connection error.
    try h.get(9, "/");
    h.events.clearRetainingCapacity();
    try h.get(7, "/again"); // 7 is in the closed ring: stream error
    try h.expectEvents("rst 7 stream_closed\n");
    try h.feed(&[_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 13, 'x' }); // DATA on an idle stream 13
    try h.expectEvents("goaway last=9 protocol_error\n");
    try testing.expectEqual(Action.close, h.last);
    // Even stream id, in a fresh connection.
    const h2 = try Harness.init(.{});
    defer h2.deinit();
    try h2.preface();
    h2.events.clearRetainingCapacity();
    try h2.get(2, "/");
    try h2.expectEvents("goaway last=0 protocol_error\n");
    // WINDOW_UPDATE on an idle stream.
    const h3 = try Harness.init(.{});
    defer h3.deinit();
    try h3.preface();
    h3.events.clearRetainingCapacity();
    try h3.window(1, 10);
    try h3.expectEvents("goaway last=0 protocol_error\n");
}

test "CONTINUATION rules and interleaving" {
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    const block = try h.encodeFields(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/split" },
        .{ .name = "x-a", .value = "1" },
    });
    defer testing.allocator.free(block);
    // A head split over HEADERS and two CONTINUATIONs.
    var buf: [256]u8 = undefined;
    var n = try frame.writeHeaders(&buf, 1, frame.flag.end_stream, block[0..3]);
    try h.feed(buf[0..n]);
    n = frame.header_len + 2;
    frame.writeHeader(buf[0..frame.header_len], 2, .continuation, 0, 1);
    @memcpy(buf[frame.header_len..][0..2], block[3..5]);
    try h.feed(buf[0..n]);
    frame.writeHeader(buf[0..frame.header_len], @intCast(block.len - 5), .continuation, frame.flag.end_headers, 1);
    @memcpy(buf[frame.header_len..][0 .. block.len - 5], block[5..]);
    try h.feed(buf[0 .. frame.header_len + block.len - 5]);
    try h.expectEvents("headers 1 end=false [:status=200] [content-type=text/plain] [content-length=13] [date]\ndata 1 len=13 end=true\n");
    try h.expectLog("GET /split [x-a=1]\n");
    // Another frame in the middle of a block: connection error.
    n = try frame.writeHeaders(&buf, 3, frame.flag.end_stream, block[0..3]);
    try h.feed(buf[0..n]);
    n = try frame.writePing(&buf, false, "12345678");
    try h.feed(buf[0..n]);
    try h.expectEvents("goaway last=3 protocol_error\n");
    // A CONTINUATION for another stream, and one with no block in progress.
    const h2 = try Harness.init(.{});
    defer h2.deinit();
    try h2.preface();
    h2.events.clearRetainingCapacity();
    n = try frame.writeHeaders(&buf, 1, frame.flag.end_stream, block[0..3]);
    try h2.feed(buf[0..n]);
    frame.writeHeader(buf[0..frame.header_len], 1, .continuation, frame.flag.end_headers, 3);
    buf[frame.header_len] = block[3];
    try h2.feed(buf[0 .. frame.header_len + 1]);
    try h2.expectEvents("goaway last=1 protocol_error\n");
    const h3 = try Harness.init(.{});
    defer h3.deinit();
    try h3.preface();
    h3.events.clearRetainingCapacity();
    frame.writeHeader(buf[0..frame.header_len], 1, .continuation, frame.flag.end_headers, 1);
    buf[frame.header_len] = block[0];
    try h3.feed(buf[0 .. frame.header_len + 1]);
    try h3.expectEvents("goaway last=0 protocol_error\n");
}

test "flow control: windows limit DATA, WINDOW_UPDATE resumes, uploads replenish" {
    const h = try Harness.init(.{ .initial_window_size = 65535, .connection_window = 65535 });
    defer h.deinit();
    const big = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    h.handler.big = big;
    try h.preface();
    // The client's initial window is 65535 per stream and per connection:
    // a 100 KB body goes out as 16384 + 16384 + 16384 + 16383 and waits.
    try h.get(1, "/big");
    try h.expectEvents(
        \\settings ack=false max_concurrent_streams=128 initial_window_size=65535 max_frame_size=16384 max_header_list_size=16384
        \\settings ack=true
        \\headers 1 end=false [:status=200] [content-type=text/plain] [content-length=100000] [date]
        \\data 1 len=16384 end=false
        \\data 1 len=16384 end=false
        \\data 1 len=16384 end=false
        \\data 1 len=16383 end=false
        \\
    );
    try testing.expectEqual(@as(u32, 1), h.conn.activeStreams());
    // A stream window update alone does nothing: the connection is at 0.
    try h.window(1, 100_000);
    try h.expectEvents("");
    try h.window(0, 20_000);
    try h.expectEvents("data 1 len=16384 end=false\ndata 1 len=3616 end=false\n");
    try h.window(0, 100_000);
    try h.expectEvents("data 1 len=14465 end=true\n");
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    // SETTINGS_INITIAL_WINDOW_SIZE changes apply to open streams (§6.9.2),
    // and a larger peer frame size is used.
    try h.settings(&.{ .{ .id = .initial_window_size, .value = 1000 }, .{ .id = .max_frame_size, .value = 1 << 20 } });
    try h.expectEvents("settings ack=true\n");
    try h.get(3, "/big");
    try h.expectEvents("headers 3 end=false [:status=200] [content-type=text/plain] [content-length=100000] [date]\ndata 3 len=1000 end=false\n");
    try h.settings(&.{.{ .id = .initial_window_size, .value = 200_000 }});
    // The connection window is what's left: 65535 + 20000 + 100000 - 100000 - 1000.
    try h.expectEvents("settings ack=true\ndata 3 len=84535 end=false\n");
    try h.window(0, 100_000);
    try h.expectEvents("data 3 len=14465 end=true\n");
    // Uploads: our windows are replenished in batches, not per frame.
    try h.headers(.{ .stream = 5, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
    } });
    const chunk: [16384]u8 = @splat('u');
    try h.data(5, &chunk, false);
    try h.expectEvents("");
    try h.data(5, &chunk, false);
    try h.expectEvents("window 0 +32768\nwindow 5 +32768\n");
    try h.data(5, chunk[0..1000], true);
    try h.expectEvents("headers 5 end=false [:status=200] [content-type=text/plain] [content-length=33768] [date]\ndata 5 len=33768 end=true\n"); // the peer allows 1 MiB frames now
    // Sending past our window is a flow control error (a stream window
    // here: the connection window is replenished before it can run out).
    const h2 = try Harness.init(.{ .initial_window_size = 1000 });
    defer h2.deinit();
    try h2.preface();
    h2.events.clearRetainingCapacity();
    try h2.headers(.{ .stream = 1, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
    } });
    try h2.data(1, chunk[0..1001], false);
    try h2.expectEvents("rst 1 flow_control_error\n");
    try testing.expectEqual(Action.need_more, h2.last);
}

test "PING, SETTINGS table size, GOAWAY in both directions" {
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    var buf: [frame.header_len + 8]u8 = undefined;
    var n = try frame.writePing(&buf, false, "pingpong");
    try h.feed(buf[0..n]);
    n = try frame.writePing(&buf, true, "pingpong");
    try h.feed(buf[0..n]);
    try h.expectEvents("ping ack=true pingpong\n");
    // Graceful shutdown: GOAWAY, open streams finish, then close.
    try h.headers(.{ .stream = 1, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
    } });
    h.conn.shutdown();
    try h.collect();
    try h.expectEvents("goaway last=1 no_error\n");
    try testing.expect(!h.conn.wantsClose());
    try h.get(3, "/new"); // refused after GOAWAY
    try h.expectEvents("rst 3 refused_stream\n");
    try h.data(1, "done", true);
    try h.expectEvents("headers 1 end=false [:status=200] [content-type=text/plain] [content-length=4] [date]\ndata 1 len=4 end=true\n");
    try testing.expect(h.conn.wantsClose());
    try testing.expectEqual(Action.close, h.last);
    // The client's GOAWAY: finish what is open, then close.
    const h2 = try Harness.init(.{});
    defer h2.deinit();
    try h2.preface();
    h2.events.clearRetainingCapacity();
    try h2.headers(.{ .stream = 1, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
    } });
    var gbuf: [frame.header_len + 8]u8 = undefined;
    n = try frame.writeGoaway(&gbuf, 1, .no_error, "");
    try h2.feed(gbuf[0..n]);
    try testing.expectEqual(Action.need_more, h2.last);
    try h2.data(1, "", true);
    try testing.expectEqual(Action.close, h2.last);
}

test "exchanges per stream: later(), stream() with trailers, abort, client reset" {
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    try h.get(1, "/later");
    try h.get(3, "/stream");
    try h.get(5, "/sync");
    // The stream() head went out at once; later() sent nothing; the sync
    // request was answered in between.
    try h.expectEvents("headers 3 end=false [:status=200] [content-type=text/plain] [date]\nheaders 5 end=false [:status=200] [content-type=text/plain] [content-length=13] [date]\ndata 5 len=13 end=true\n");
    const later = h.handler.exchanges.items[0];
    const stream = h.handler.exchanges.items[1];
    try stream.write("part1");
    try h.drainMailbox();
    try h.collect();
    try h.expectEvents("data 3 len=5 end=false\n");
    try later.respond(.{ .status = .created, .headers = &.{.{ .key = "X-Later", .value = "yes" }} }, "created!");
    try h.drainMailbox();
    try h.collect();
    try h.expectEvents("headers 1 end=false [:status=201] [x-later=yes] [content-length=8] [date]\ndata 1 len=8 end=true\n");
    try testing.expect(!later.isOpen());
    try stream.writeBorrowed("part2", null);
    try stream.finish(&.{.{ .key = "X-Trailer", .value = "end" }});
    try h.drainMailbox();
    try h.collect();
    try h.expectEvents("data 3 len=5 end=false\nheaders 3 end=true [x-trailer=end]\n");
    try testing.expect(!stream.isOpen());
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    // abort resets the stream; a client RST_STREAM aborts the exchange.
    try h.get(7, "/stream");
    try h.get(9, "/later");
    h.events.clearRetainingCapacity();
    try h.handler.exchanges.items[2].abort();
    try h.drainMailbox();
    try h.collect();
    try h.expectEvents("rst 7 internal_error\n");
    try h.rst(9, .cancel);
    try testing.expectEqual(@as(usize, 1), h.handler.aborts);
    try testing.expect(!h.handler.exchanges.items[3].isOpen());
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    // A later() stream for a HEAD request: head only.
    try h.headers(.{ .stream = 11, .fields = &.{
        .{ .name = ":method", .value = "HEAD" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/later" },
    } });
    try h.handler.exchanges.items[4].respond(.{}, "dropped");
    try h.drainMailbox();
    try h.collect();
    try h.expectEvents("headers 11 end=false [:status=200] [content-length=7] [date]\ndata 11 len=0 end=true\n");
    // A stream() response that finishes with no data at all.
    try h.get(13, "/stream");
    h.events.clearRetainingCapacity();
    try h.handler.exchanges.items[5].finish(&.{});
    try h.drainMailbox();
    try h.collect();
    try h.expectEvents("data 13 len=0 end=true\n");
    // The exchange deadline: the worker reports it, the stream is reset.
    try h.get(15, "/later");
    const c = h.ctx();
    h.conn.onExchangeTimeout(TestHandler, &c, h.handler.exchanges.items[6].slot);
    try h.collect();
    try h.expectEvents("rst 15 internal_error\n");
    try testing.expectEqual(@as(usize, 2), h.handler.aborts);
}

test "defence: rapid reset" {
    const h = try Harness.init(.{ .max_resets_per_second = 5 });
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    var stream: u31 = 1;
    while (stream <= 11) : (stream += 2) {
        try h.get(stream, "/later");
        try h.rst(stream, .cancel);
    }
    try testing.expectEqual(Action.close, h.last);
    try testing.expect(std.mem.endsWith(u8, h.events.items, "goaway last=11 enhance_your_calm\n"));
    try testing.expectEqual(@as(usize, 5), h.handler.aborts);
    // Within the budget, resets are fine, and the budget refills each second.
    const h2 = try Harness.init(.{ .max_resets_per_second = 5 });
    defer h2.deinit();
    try h2.preface();
    h2.events.clearRetainingCapacity();
    stream = 1;
    while (stream <= 9) : (stream += 2) {
        try h2.get(stream, "/later");
        try h2.rst(stream, .cancel);
    }
    try testing.expectEqual(Action.need_more, h2.last);
    h2.now += 1;
    while (stream <= 19) : (stream += 2) {
        try h2.get(stream, "/later");
        try h2.rst(stream, .cancel);
    }
    try testing.expectEqual(Action.need_more, h2.last);
}

test "defence: CONTINUATION flood" {
    const h = try Harness.init(.{ .limits = .{ .max_header_bytes = 1000 } });
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    var buf: [frame.header_len + 100]u8 = undefined;
    var n = try frame.writeHeaders(&buf, 1, 0, &(@as([100]u8, @splat(0x80 | 2)))); // ":method GET" indexed, forever
    try h.feed(buf[0..n]);
    var i: usize = 0;
    while (h.last != .close) : (i += 1) {
        frame.writeHeader(buf[0..frame.header_len], 100, .continuation, 0, 1);
        n = frame.header_len + 100;
        try h.feed(buf[0..n]);
        try testing.expect(i < 20);
    }
    try h.expectEvents("goaway last=1 enhance_your_calm\n");
    // A block that never completes times out.
    const h2 = try Harness.init(.{ .request_timeout_s = 2 });
    defer h2.deinit();
    try h2.preface();
    h2.events.clearRetainingCapacity();
    n = try frame.writeHeaders(&buf, 1, 0, &[_]u8{0x82});
    try h2.feed(buf[0..n]);
    try h2.tick(2);
    try testing.expectEqual(Action.need_more, h2.last);
    try h2.tick(1);
    try testing.expectEqual(Action.close, h2.last);
    try h2.expectEvents("goaway last=1 enhance_your_calm\n");
}

test "defence: HPACK bomb" {
    // A 4 KB dynamic table entry referenced over and over decompresses to
    // megabytes; the header list limit stops it at 431 and the table
    // stays in sync.
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    const big_value: [4000]u8 = @splat('x');
    const block = try h.encodeFields(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "x-bomb", .value = &big_value },
    });
    defer testing.allocator.free(block);
    var bomb: std.ArrayList(u8) = .empty;
    defer bomb.deinit(testing.allocator);
    try bomb.appendSlice(testing.allocator, block);
    // 1000 references to the entry just added (index 62): 4 MB decoded.
    for (0..1000) |_| try bomb.appendSlice(testing.allocator, &.{0xbe});
    var out = try testing.allocator.alloc(u8, bomb.items.len + frame.header_len);
    defer testing.allocator.free(out);
    const n = try frame.writeHeaders(out, 1, frame.flag.end_stream | frame.flag.end_headers, bomb.items);
    try h.feed(out[0..n]);
    try h.expectEvents("headers 1 end=true [:status=431] [content-length=0] [date]\n");
    try testing.expectEqual(Action.need_more, h.last);
    // The table is in sync: the entry is still usable.
    var out2: [64]u8 = undefined;
    const n2 = try frame.writeHeaders(&out2, 3, frame.flag.end_stream | frame.flag.end_headers, &.{ 0x82, 0x87, 0x84, 0xbe });
    try h.feed(out2[0..n2]);
    try h.expectEvents("headers 3 end=false [:status=200] [content-type=text/plain] [content-length=13] [date]\ndata 3 len=13 end=true\n");
    try testing.expect(std.mem.startsWith(u8, h.handler.log.items, "GET / [x-bomb=xxxx"));
}

test "defence: SETTINGS, PING and empty frame floods" {
    const h = try Harness.init(.{ .max_control_frames_per_second = 20 });
    defer h.deinit();
    try h.preface();
    // An open stream for the empty DATA frames.
    try h.headers(.{ .stream = 1, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
    } });
    h.events.clearRetainingCapacity();
    var buf: [frame.header_len + 8]u8 = undefined;
    var i: usize = 0;
    while (h.last != .close) : (i += 1) {
        const n = switch (i % 4) {
            0 => try frame.writePing(&buf, false, "pingping"),
            1 => try frame.writeSettings(&buf, &.{}),
            2 => try frame.writeData(&buf, 1, false, ""),
            else => try frame.writeWindowUpdate(&buf, 0, 1),
        };
        try h.feed(buf[0..n]);
        try testing.expect(i < 40);
    }
    try testing.expect(std.mem.endsWith(u8, h.events.items, "goaway last=1 enhance_your_calm\n"));
    // Real requests are not counted: 100 in a row are fine.
    const h2 = try Harness.init(.{ .max_control_frames_per_second = 20 });
    defer h2.deinit();
    try h2.preface();
    var stream: u31 = 1;
    while (stream < 200) : (stream += 2) try h2.get(stream, "/");
    try testing.expectEqual(Action.need_more, h2.last);
}

test "defence: zero-window stalls" {
    const h = try Harness.init(.{ .request_timeout_s = 3 });
    defer h.deinit();
    const big = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    h.handler.big = big;
    try h.preface();
    // A stream window of 0: the response waits, then the stream is reset.
    try h.settings(&.{.{ .id = .initial_window_size, .value = 0 }});
    h.events.clearRetainingCapacity();
    try h.get(1, "/big");
    try h.expectEvents("headers 1 end=false [:status=200] [content-type=text/plain] [content-length=100000] [date]\n");
    try h.tick(3);
    try h.expectEvents("");
    try h.tick(1);
    try h.expectEvents("rst 1 cancel\n");
    try testing.expectEqual(Action.need_more, h.last);
    // The connection window at 0 with a stream waiting: the connection
    // is closed instead.
    try h.settings(&.{.{ .id = .initial_window_size, .value = 1 << 20 }});
    h.events.clearRetainingCapacity();
    try h.get(3, "/big");
    try testing.expect(std.mem.endsWith(u8, h.events.items, "data 3 len=16383 end=false\n")); // 65535 sent, conn window 0
    h.events.clearRetainingCapacity();
    try h.tick(4);
    try h.expectEvents("goaway last=3 enhance_your_calm\n");
    try testing.expectEqual(Action.close, h.last);
}

test "output backpressure: process stops parsing above out_limit" {
    const h = try Harness.init(.{ .out_limit = 1024 });
    defer h.deinit();
    const big = try testing.allocator.alloc(u8, 3000);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    h.handler.big = big;
    try h.preface();
    h.events.clearRetainingCapacity();
    // Several responses at once; each process round stops once the
    // limit is reached and the harness "writes" before the next.
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    var stream: u31 = 1;
    while (stream <= 9) : (stream += 2) {
        const block = try h.encodeFields(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/big" },
        });
        defer testing.allocator.free(block);
        var buf: [64]u8 = undefined;
        const n = try frame.writeHeaders(&buf, stream, frame.flag.end_stream | frame.flag.end_headers, block);
        try frames.appendSlice(testing.allocator, buf[0..n]);
    }
    try h.feed(frames.items);
    try testing.expectEqual(@as(usize, 5), std.mem.count(u8, h.events.items, "end=true"));
    try testing.expectEqual(@as(usize, 5 * 3000), 5 * 3000);
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
}

// Any split of the same client bytes gives the same frames per stream.
test "split invariance" {
    const script = try buildScript();
    defer testing.allocator.free(script);
    const ref = try Harness.init(.{});
    defer ref.deinit();
    try ref.feed(script);
    try testing.expect(ref.per_stream.count() > 3);
    var prng = std.Random.DefaultPrng.init(11);
    const random = prng.random();
    for (0..40) |iteration| {
        const h = try Harness.init(.{});
        defer h.deinit();
        var rest: []const u8 = script;
        while (rest.len > 0 and h.last != .close) {
            const max_chunk: usize = if (iteration == 0) 1 else 1 + random.uintLessThan(usize, 700);
            const n = @min(rest.len, max_chunk);
            try h.feed(rest[0..n]);
            rest = rest[n..];
        }
        try expectSameStreams(ref, h);
    }
}

fn expectSameStreams(a: *Harness, b: *Harness) !void {
    try testing.expectEqual(a.last, b.last);
    try testing.expectEqual(a.per_stream.count(), b.per_stream.count());
    var it = a.per_stream.iterator();
    while (it.next()) |entry| {
        const other = b.per_stream.get(entry.key_ptr.*) orelse return error.MissingStream;
        try testing.expectEqualStrings(entry.value_ptr.items, other.items);
    }
    try testing.expectEqualStrings(a.handler.log.items, b.handler.log.items);
}

/// A conversation with requests, bodies, trailers, window updates, pings,
/// settings, a refused stream and finally a connection error.
fn buildScript() ![]u8 {
    const a = testing.allocator;
    var enc = try hpack.Encoder.init(a, 4096);
    defer enc.deinit();
    var s: std.ArrayList(u8) = .empty;
    errdefer s.deinit(a);
    try s.appendSlice(a, frame.preface);
    var buf: [2048]u8 = undefined;
    var n = try frame.writeSettings(&buf, &.{.{ .id = .initial_window_size, .value = 30000 }});
    try s.appendSlice(a, buf[0..n]);
    var block: [1024]u8 = undefined;
    var stream: u31 = 1;
    for (0..12) |i| {
        var bn: usize = 0;
        bn += try enc.encode(block[bn..], ":method", if (i % 3 == 0) "POST" else "GET", .{});
        bn += try enc.encode(block[bn..], ":scheme", "https", .{});
        bn += try enc.encode(block[bn..], ":path", if (i % 3 == 0) "/echo" else if (i % 3 == 1) "/" else "/big", .{});
        bn += try enc.encode(block[bn..], "x-req", &(@as([3]u8, @splat('a' + @as(u8, @intCast(i))))), .{});
        if (i % 3 == 0) {
            n = try frame.writeHeaders(&buf, stream, frame.flag.end_headers, block[0..bn]);
            try s.appendSlice(a, buf[0..n]);
            n = try frame.writeData(&buf, stream, false, "body-");
            try s.appendSlice(a, buf[0..n]);
            n = try frame.writePing(&buf, false, "pingpong");
            try s.appendSlice(a, buf[0..n]);
            n = try frame.writeData(&buf, stream, i % 2 == 0, "part");
            try s.appendSlice(a, buf[0..n]);
            if (i % 2 != 0) {
                bn = try enc.encode(&block, "x-trailer", "t", .{});
                n = try frame.writeHeaders(&buf, stream, frame.flag.end_headers | frame.flag.end_stream, block[0..bn]);
                try s.appendSlice(a, buf[0..n]);
            }
        } else {
            n = try frame.writeHeaders(&buf, stream, frame.flag.end_headers | frame.flag.end_stream, block[0..bn]);
            try s.appendSlice(a, buf[0..n]);
        }
        if (i % 4 == 2) {
            n = try frame.writeWindowUpdate(&buf, stream, 50000);
            try s.appendSlice(a, buf[0..n]);
            n = try frame.writeWindowUpdate(&buf, 0, 50000);
            try s.appendSlice(a, buf[0..n]);
        }
        stream += 2;
    }
    n = try frame.writeRstStream(&buf, 1, .cancel);
    try s.appendSlice(a, buf[0..n]);
    n = try frame.writeData(&buf, 99, false, "idle"); // connection error at the end
    try s.appendSlice(a, buf[0..n]);
    return s.toOwnedSlice(a);
}

fn fuzzConn(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [4096]u8 = undefined;
    const tail = input_buf[0..smith.slice(&input_buf)];
    // Start from a valid preface so the fuzzer reaches the frame logic.
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try script.appendSlice(testing.allocator, frame.preface);
    var buf: [64]u8 = undefined;
    const n = try frame.writeSettings(&buf, &.{});
    try script.appendSlice(testing.allocator, buf[0..n]);
    try script.appendSlice(testing.allocator, tail);
    const opts: Options = .{ .limits = .{ .max_header_bytes = 2048, .max_body_size = 1024 }, .out_limit = 4096, .max_concurrent_streams = 8 };
    const whole = try Harness.init(opts);
    defer whole.deinit();
    whole.handler.big = "big body for the fuzzer, not very big";
    try whole.feed(script.items);
    const split = try Harness.init(opts);
    defer split.deinit();
    split.handler.big = whole.handler.big;
    var rest: []const u8 = script.items;
    while (rest.len > 0 and split.last != .close) {
        const k = @min(rest.len, @as(usize, smith.value(u8)) + 1);
        try split.feed(rest[0..k]);
        rest = rest[k..];
    }
    try expectSameStreams(whole, split);
}

test "fuzz: h2 connection" {
    const script = try buildScript();
    defer testing.allocator.free(script);
    try std.testing.fuzz({}, fuzzConn, .{ .corpus = &.{
        script[frame.preface.len + frame.header_len ..],
        &[_]u8{ 0, 0, 5, 1, 5, 0, 0, 0, 1, 0x82, 0x87, 0x84, 0x41, 0x00 },
        &[_]u8{ 0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 },
    } });
}
