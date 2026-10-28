//! One HTTP/2 connection (RFC 9113), independent of the I/O model. The
//! worker reads into the frame Reader, calls `process`, writes whatever is
//! in `out`, and calls `pump` once output has drained. Each stream carries
//! one request, answered through the same handler API as HTTP/1.1: the
//! synchronous path serialises HEADERS and DATA into `out` when
//! handleRequest returns, without allocating in steady state; `later()`
//! and `stream()` exchanges are drained per stream as the windows allow.
//!
//! WebSockets (RFC 8441): with `enable_connect_protocol`, an extended
//! CONNECT whose handler accepts it (`ws.upgrader.handleUpgrade`) gets a
//! 200 without END_STREAM, and the stream's DATA then carries the
//! WebSocket both ways through a `ws.Conn`, flow-controlled like any body.
//!
//! Priorities (RFC 7540 and RFC 9218) are accepted and ignored. Server
//! push is never used.
const std = @import("std");
const frame = @import("./frame.zig");
const hpack = @import("./hpack.zig");
const parser = @import("../http/parser.zig");
const date = @import("../http/date.zig");
const exchange = @import("../http/exchange.zig");
const fields_mod = @import("../http/fields.zig");
const Priority = @import("../http/priority.zig").Priority;
const BufferPool = @import("../http/session.zig").BufferPool;
const ws = @import("../ws/conn.zig");
const sys = @import("../sys.zig");
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const File = @import("../response.zig").File;
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
    /// PRIORITY, empty DATA and HEADERS, unknown types) before
    /// ENHANCE_YOUR_CALM. WINDOW_UPDATE carries flow-control credit and is
    /// not counted; RST_STREAM has its own budget.
    max_control_frames_per_second: u32 = 1000,
    /// Seconds a stream may hold unsent output against a zero window, or a
    /// header block may stay incomplete, before it is reset.
    request_timeout_s: u32 = 10,
    /// Advertise SETTINGS_ENABLE_CONNECT_PROTOCOL and accept extended
    /// CONNECT (RFC 8441), for WebSockets. Set by the server when the
    /// handler has WebSocket hooks.
    enable_connect_protocol: bool = false,
    /// Limits for WebSockets over this connection.
    websocket: ws.Options = .{},
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
        /// The worker's read buffers, for WebSocket decoders.
        pool: *BufferPool,
        /// The socket, for `ws.Conn.fd` (identification only).
        fd: sys.fd_t = -1,
        /// Input is TLS early data (0-RTT): requests may be replays.
        early_data: bool = false,
    };
}

/// Output capacity kept per idle connection.
const idle_capacity = 16 * 1024;

const StreamState = enum(u8) {
    /// Request head or body still arriving.
    open,
    /// The request is complete (END_STREAM received); responding.
    half_closed_remote,
};

const HeaderRef = fields_mod.HeaderRef;

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
    /// Extended CONNECT (RFC 8441): `:protocol`.
    protocol: ?HeaderRef = null,
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
    /// A file body still to send (Response.sendFile), read as the windows
    /// allow; closed by whoever clears it.
    file: ?File = null,
    /// The exchange answering this stream, or NIL.
    exchange: u32 = NIL,
    /// Set while output waits for a window; cleared on progress.
    stalled_since: u32 = 0,
    stalled: bool = false,
    /// Bytes consumed since the last stream WINDOW_UPDATE.
    consumed: u32 = 0,
    /// Trailers: names and values from `trl_off` in `req`, references
    /// after the headers' in `hdr`.
    trl_off: usize = 0,
    trl_count: u16 = 0,
    /// The body goes to the exchange through handleBody as it arrives
    /// (handleHead chose `.stream`). While the handler has paused it,
    /// DATA is kept in `req` from `body_start`, the window held back:
    /// `body_pos` bytes of that were delivered, `body_end` says the rest
    /// of the request (END_STREAM, trailers) is in too.
    body_stream: bool = false,
    body_paused: bool = false,
    body_end: bool = false,
    body_pos: usize = 0,
    /// An extended CONNECT: DATA is never buffered as a body. It goes to
    /// `ws` once the handler accepted a WebSocket, and is dropped
    /// otherwise.
    tunnel: bool = false,
    ws: ?*ws.Conn = null,
    /// The WebSocket has output the windows (or `out_limit`) held back.
    ws_pending: bool = false,
    /// RFC 9218: from the `priority` header, or PRIORITY_UPDATE.
    prio: Priority = .{},
    /// A PRIORITY_UPDATE set `prio`: it overrides the header.
    prio_frame: bool = false,
    /// Has output that waits for room in `out` or for the connection
    /// window (not for its own window), or behind more urgent streams.
    /// Less urgent streams wait for it (see `pumpStream`).
    blocked: bool = false,

    fn clear(s: *Stream) void {
        s.req.clearRetainingCapacity();
        s.pending.clearRetainingCapacity();
        s.* = .{ .req = s.req, .pending = s.pending };
    }

    fn free(s: *Stream, allocator: std.mem.Allocator) void {
        s.req.deinit(allocator);
        s.pending.deinit(allocator);
        if (s.file) |f| f.release();
        s.file = null;
    }

    inline fn hasOutput(s: *const Stream) bool {
        return s.pending_pos < s.pending.items.len or s.pending_end or s.exchange != NIL or s.file != null;
    }

    /// The priority output is scheduled by. A tunnel never ends, so it
    /// shares rather than holding back later streams (RFC 9218 §10.1).
    fn schedPriority(s: *const Stream) Priority {
        var p = s.prio;
        if (s.tunnel) p.incremental = true;
        return p;
    }

    /// Sending order (RFC 9218 §10): more urgent first; at one urgency,
    /// non-incremental streams in stream order, then incremental ones.
    fn sendsBefore(a: *const Stream, b: *const Stream) bool {
        const pa = a.schedPriority();
        const pb = b.schedPriority();
        if (pa.before(pb) or pb.before(pa)) return pa.before(pb);
        return a.id < b.id;
    }

    /// The `priority` header lines (names are lowercase by now).
    fn headerPriority(s: *const Stream) Priority {
        const Lines = struct {
            s: *const Stream,
            i: usize = 0,
            pub fn next(it: *@This()) ?[]const u8 {
                while (it.i < it.s.hdr_count) {
                    const h = it.s.hdr[it.i];
                    it.i += 1;
                    if (std.mem.eql(u8, it.s.req.items[h.name_off..][0..h.name_len], "priority")) return it.s.slice(h);
                }
                return null;
            }
        };
        return Priority.fromLines(Lines{ .s = s });
    }

    fn slice(s: *const Stream, ref: HeaderRef) []const u8 {
        return s.req.items[ref.name_off + ref.name_len ..][0..ref.value_len];
    }

    /// The end of the body bytes in `req` (trailers follow).
    fn bodyEnd(s: *const Stream) usize {
        return if (s.trl_count > 0) s.trl_off else s.req.items.len;
    }

    fn trailers(s: *const Stream, out: []Header) []const Header {
        return fields_mod.resolve(s.req.items, s.hdr[s.hdr_count..][0..s.trl_count], out);
    }
};

const Fault = enum(u8) {
    /// Malformed request (RFC 9113 §8.1.1): RST_STREAM(PROTOCOL_ERROR).
    protocol,
    /// Too many or too large headers: 431.
    headers_too_large,
    /// Unknown method, or a CONNECT that isn't extended: 501.
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

/// A recently closed stream, to tell "closed" from "idle" (§5.1), and
/// how it closed: frames after END_STREAM are a connection error, after
/// the peer's RST_STREAM a stream error, after our RST_STREAM ignored.
const Closed = struct { id: u31 = 0, how: How = .ended };
const IdlePriority = struct { id: u31, prio: Priority };

/// DATA bytes an incremental stream sends before the next one of its
/// urgency takes a turn.
const share_quantum = 16 * 1024;
const How = enum(u8) { ended, peer_reset, we_reset };

pub const Conn = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    opts: Options,
    reader: frame.Reader = .{},
    frame_opts: frame.Options,
    decoder: hpack.Decoder,
    encoder: hpack.Encoder,
    /// Serialised output being appended. `wireBytes` swaps it into `wire`
    /// once the wire is drained, so frames can be queued while a write of
    /// the wire is in flight (as ws.Conn does).
    out: std.ArrayList(u8) = .empty,
    wire: std.ArrayList(u8) = .empty,
    wire_pos: usize = 0,
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

    /// Streams with `blocked` set.
    blocked_count: u32 = 0,
    /// Scratch for `pumpAll`: stream slots in sending order.
    order: []u32,
    /// Per urgency: the incremental stream served last, so the next pass
    /// starts after it.
    rr_last: [8]u31 = @splat(0),
    /// PRIORITY_UPDATEs for streams not yet opened (RFC 9218 §7).
    idle_prio: []IdlePriority,
    idle_prio_len: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, opts: Options) !Self {
        var decoder = try hpack.Decoder.init(allocator, opts.hpack);
        errdefer decoder.deinit();
        var encoder = try hpack.Encoder.init(allocator, hpack.default_table_size);
        errdefer encoder.deinit();
        const streams = try allocator.alloc(Stream, opts.max_concurrent_streams);
        errdefer allocator.free(streams);
        @memset(streams, .{});
        const order = try allocator.alloc(u32, opts.max_concurrent_streams);
        errdefer allocator.free(order);
        const idle_prio = try allocator.alloc(IdlePriority, opts.max_concurrent_streams);
        errdefer allocator.free(idle_prio);
        var self: Self = .{
            .allocator = allocator,
            .opts = opts,
            .frame_opts = .{ .max_frame_size = opts.max_frame_size },
            .decoder = decoder,
            .encoder = encoder,
            .streams = streams,
            .order = order,
            .idle_prio = idle_prio,
        };
        errdefer self.out.deinit(allocator);
        // Our preface: SETTINGS, then a larger connection window.
        var buf: [64]u8 = undefined;
        const settings = [_]frame.Setting{
            .{ .id = .max_concurrent_streams, .value = opts.max_concurrent_streams },
            .{ .id = .initial_window_size, .value = @min(opts.initial_window_size, frame.max_window_size) },
            .{ .id = .max_frame_size, .value = opts.max_frame_size },
            .{ .id = .max_header_list_size, .value = opts.hpack.max_header_list_size },
            // RFC 9218 replaces RFC 7540's priority tree.
            .{ .id = .no_rfc7540_priorities, .value = 1 },
            .{ .id = .enable_connect_protocol, .value = 1 },
        };
        var n = try frame.writeSettings(&buf, settings[0 .. settings.len - @intFromBool(!opts.enable_connect_protocol)]);
        if (opts.connection_window > 65535) {
            n += try frame.writeWindowUpdate(buf[n..], 0, @intCast(@min(opts.connection_window, frame.max_window_size) - 65535));
            self.recv_window = @min(opts.connection_window, frame.max_window_size);
        }
        try self.out.appendSlice(allocator, buf[0..n]);
        try self.out.ensureTotalCapacity(allocator, idle_capacity);
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
        self.allocator.free(self.order);
        self.allocator.free(self.idle_prio);
        self.decoder.deinit();
        self.encoder.deinit();
        self.out.deinit(self.allocator);
        self.wire.deinit(self.allocator);
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

    /// Returns the input buffer when nothing is buffered, and trims
    /// output buffers that grew for a large response once the connection
    /// is idle.
    pub fn releaseIfIdle(self: *Self, pool: *BufferPool) void {
        self.reader.releaseIfIdle(pool);
        if (self.stream_count == 0 and !self.hasWire()) {
            if (self.out.capacity > 2 * idle_capacity) {
                self.out.clearAndFree(self.allocator);
                self.out.ensureTotalCapacity(self.allocator, idle_capacity) catch {};
            }
            if (self.wire.capacity > 2 * idle_capacity) self.wire.clearAndFree(self.allocator);
        }
    }

    /// Whether a frame is partially received (for timeouts).
    pub inline fn inFrame(self: *const Self) bool {
        return self.reader.buffered() > 0 or self.hb_stream != 0;
    }

    // -- Output -----------------------------------------------------------

    /// Bytes to write next, refilled from `out` when the wire is empty.
    /// Not to be called while a write of the previous bytes is in flight.
    pub fn wireBytes(self: *Self) []const u8 {
        if (self.wire_pos == self.wire.items.len) {
            self.wire.clearRetainingCapacity();
            self.wire_pos = 0;
            std.mem.swap(std.ArrayList(u8), &self.out, &self.wire);
        }
        return self.wire.items[self.wire_pos..];
    }

    /// Unsent bytes, on the wire or queued.
    pub inline fn hasWire(self: *const Self) bool {
        return self.wire_pos < self.wire.items.len or self.out.items.len > 0;
    }

    pub fn advance(self: *Self, n: usize) void {
        self.wire_pos += n;
    }

    fn unsent(self: *const Self) usize {
        return self.out.items.len + (self.wire.items.len - self.wire_pos);
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

    /// Ends a stream, remembering how (see Closed).
    fn closeStream(self: *Self, ctx: anytype, s: *Stream, how: How, abort_exchange: bool) void {
        dropWebSocket(ctx, s);
        if (s.exchange != NIL) {
            self.output_streams -= 1;
            if (abort_exchange) self.abortExchange(ctx, s.exchange);
            ctx.exchanges.release(s.exchange);
            s.exchange = NIL;
        } else if (s.hasOutput()) {
            self.output_streams -= 1;
        }
        if (s.file) |f| f.release();
        s.file = null;
        if (self.hb_slot != NIL and &self.streams[self.hb_slot] == s) {
            self.hb_stream = 0;
            self.hb_slot = NIL;
        }
        self.setBlocked(s, false);
        self.closed_ring[self.closed_pos] = .{ .id = s.id, .how = how };
        self.closed_pos = (self.closed_pos + 1) % self.closed_ring.len;
        s.active = false;
        s.clear();
        self.stream_count -= 1;
    }

    /// The stream is ending: handleWSDisconn, then the WebSocket is freed
    /// (its tunnel slot goes with the stream's exchange).
    fn dropWebSocket(ctx: anytype, s: *Stream) void {
        const w = s.ws orelse return;
        s.ws = null;
        const Handler = @TypeOf(ctx.handler.*);
        if (@hasDecl(Handler, "handleWSDisconn")) ctx.handler.handleWSDisconn(w);
        w.destroy(ctx.pool);
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
        self.closeStream(ctx, s, .we_reset, true);
    }

    /// The worker is closing the connection: tell handlers about live
    /// exchanges and release them.
    pub fn abortAll(self: *Self, ctx: anytype) void {
        for (self.streams) |*s| {
            if (s.active) dropWebSocket(ctx, s);
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
            // After a GOAWAY with no streams left, the rest of the input is
            // not read, however it was split.
            if (self.wantsClose()) return .close;
            if (self.unsent() > self.opts.out_limit) return .flush;
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
                self.resets += 1;
                if (self.resets > self.opts.max_resets_per_second) return self.fail(.enhance_your_calm);
                if (r.stream_id > self.last_stream_id or r.stream_id % 2 == 0) return self.fail(.protocol_error);
                if (self.findStream(r.stream_id)) |s| self.closeStream(ctx, s, .peer_reset, true);
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
            .priority_update => |u| self.onPriorityUpdate(u),
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

    /// RFC 9218 §7.1. A value that doesn't parse is ignored.
    fn onPriorityUpdate(self: *Self, u: anytype) void {
        self.countControl();
        // We never push: an even ID names a push stream that is idle.
        if (u.prioritized_id % 2 == 0) return self.fail(.protocol_error);
        var p: Priority = .{};
        if (!p.apply(u.value)) return;
        if (u.prioritized_id > self.last_stream_id) {
            // Kept until the stream opens.
            for (self.idle_prio[0..self.idle_prio_len]) |*e| {
                if (e.id == u.prioritized_id) {
                    e.prio = p;
                    return;
                }
            }
            // Idle prioritised streams and open ones together stay within
            // SETTINGS_MAX_CONCURRENT_STREAMS.
            if (self.idle_prio_len + self.stream_count >= self.opts.max_concurrent_streams) return self.fail(.protocol_error);
            self.idle_prio[self.idle_prio_len] = .{ .id = u.prioritized_id, .prio = p };
            self.idle_prio_len += 1;
            return;
        }
        // Applies from the next pass of `pumpAll`. Closed: ignored.
        if (self.findStream(u.prioritized_id)) |s| {
            s.prio = p;
            s.prio_frame = true;
        }
    }

    /// A stream with this ID is opening: the update kept for it, if any.
    /// Updates for lower IDs are dropped, those streams can't open now.
    fn takeIdlePriority(self: *Self, id: u31) ?Priority {
        var found: ?Priority = null;
        var kept: u32 = 0;
        for (self.idle_prio[0..self.idle_prio_len]) |e| {
            if (e.id == id) found = e.prio;
            if (e.id <= id) continue;
            self.idle_prio[kept] = e;
            kept += 1;
        }
        self.idle_prio_len = kept;
        return found;
    }

    fn onWindowUpdate(self: *Self, comptime Handler: type, ctx: *const Context(Handler), w: anytype) void {
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
            if (self.recentlyClosed(d.stream_id)) |c| switch (c.how) {
                .we_reset => return, // §5.1: ignored for a while after our RST
                .peer_reset => return self.writeRst(d.stream_id, .stream_closed),
                .ended => return self.fail(.stream_closed),
            };
            return self.fail(.stream_closed);
        };
        if (s.state != .open) return self.resetStream(ctx, s, .stream_closed);
        if (d.flow_len > s.recv_window) return self.resetStream(ctx, s, .flow_control_error);
        s.recv_window -= d.flow_len;
        if (s.tunnel) return self.tunnelData(Handler, ctx, s, d);
        if (s.body_stream) return self.streamData(Handler, ctx, s, d);
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
        self.creditStream(s, d.flow_len);
    }

    /// Returns `n` bytes of the stream's window once half the window has
    /// been consumed (only while the request is still arriving).
    fn creditStream(self: *Self, s: *Stream, n: u32) void {
        s.consumed += n;
        if (s.state != .open or s.consumed < self.opts.initial_window_size / 2) return;
        var buf: [frame.header_len + 4]u8 = undefined;
        const len = frame.writeWindowUpdate(&buf, s.id, @intCast(s.consumed)) catch unreachable;
        self.out.appendSlice(self.allocator, buf[0..len]) catch {};
        s.recv_window += s.consumed;
        s.consumed = 0;
    }

    /// DATA on an extended CONNECT stream: WebSocket bytes, run through
    /// the stream's ws.Conn at once, or dropped if the handler didn't take
    /// the tunnel. The window comes back once the WebSocket's output has
    /// been written (backpressure, as HTTP/1.1 stops reading the socket
    /// while output is stalled).
    fn tunnelData(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream, d: anytype) void {
        if (d.end_stream) s.state = .half_closed_remote;
        const w = s.ws orelse return self.creditStream(s, d.flow_len);
        var rest = d.data;
        while (rest.len > 0 and !w.wantsClose()) {
            const space = w.decoder.readSpace(ctx.pool) catch return self.resetStream(ctx, s, .internal_error);
            const n = @min(space.len, rest.len);
            @memcpy(space[0..n], rest[0..n]);
            w.decoder.commitRead(n);
            rest = rest[n..];
            _ = w.process(Handler, ctx.handler);
        }
        w.decoder.releaseIfIdle(ctx.pool);
        s.consumed += d.flow_len;
        self.pumpStream(Handler, ctx, s);
    }

    /// DATA for a streamed body: handed to the handler at once, or kept
    /// while it has paused (or earlier DATA is still kept). The window is
    /// returned only for delivered bytes, so a paused stream holds at most
    /// a window's worth.
    fn streamData(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream, d: anytype) void {
        s.body_received += d.data.len;
        if (s.content_length) |cl| {
            if (s.body_received > cl or (d.end_stream and s.body_received != cl)) return self.resetStream(ctx, s, .protocol_error);
        }
        // Padding is never delivered.
        self.creditStream(s, d.flow_len - @as(u32, @intCast(d.data.len)));
        if (d.end_stream) s.state = .half_closed_remote;
        if (s.body_paused or s.req.items.len > s.body_start) {
            s.req.appendSlice(self.allocator, d.data) catch return self.fail(.internal_error);
            if (d.end_stream) s.body_end = true;
            return;
        }
        if (d.data.len == 0 and !d.end_stream) return;
        self.deliver(Handler, ctx, s, d.data, if (d.end_stream) &.{} else null);
    }

    /// Calls handleBody, returns the window for the bytes, and sends what
    /// the handler queued in the call (a response given there goes out in
    /// this pass, not after the next mailbox drain). The stream may be
    /// closed when this returns.
    fn deliver(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream, chunk: []const u8, end: ?[]const Header) void {
        if (!@hasDecl(Handler, "handleBody")) unreachable;
        if (end != null) s.body_stream = false;
        const action = ctx.exchanges.handle(s.exchange).deliverBody(ctx.handler, chunk, end, ctx.now);
        if (end == null and action == .pause) s.body_paused = true;
        self.creditStream(s, @intCast(chunk.len));
        self.pumpStream(Handler, ctx, s);
    }

    /// Delivers what was kept while the body was paused, and the end once
    /// it is in.
    fn drainBody(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream) void {
        while (s.active and s.body_stream and !s.body_paused) {
            const rest = s.req.items[s.body_start + s.body_pos .. s.bodyEnd()];
            if (rest.len == 0 and !s.body_end) {
                // All delivered: later DATA goes straight through.
                s.req.items.len = s.body_start;
                s.body_pos = 0;
                return;
            }
            s.body_pos += rest.len;
            self.deliver(Handler, ctx, s, rest, if (s.body_end) s.trailers(&ctx.req.headers) else null);
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
            const prio = if (self.idle_prio_len > 0) self.takeIdlePriority(h.stream_id) else null;
            if (self.goaway_sent or self.goaway_received) {
                // Not accepted after GOAWAY: decode to stay in sync, then refuse.
                self.hb_discard = .refused_stream;
                self.hb_slot = NIL;
            } else if (self.openStream(h.stream_id)) |s| {
                if (prio) |p| {
                    s.prio = p;
                    s.prio_frame = true;
                }
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
        } else if (self.recentlyClosed(h.stream_id)) |c| {
            // After END_STREAM both ways the client knows the stream is
            // closed: a connection error (§5.1). After a reset, a stream
            // error (the block is still decoded, to keep HPACK in sync).
            if (c.how == .ended) return self.fail(.stream_closed);
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
                self.closed_ring[self.closed_pos] = .{ .id = stream_id, .how = .we_reset };
                self.closed_pos = (self.closed_pos + 1) % self.closed_ring.len;
            }
            return self.writeRst(stream_id, code);
        }
        const s = &self.streams[slot];
        if (trailers) {
            // Kept after the body (and after a paused body's kept DATA).
            s.trl_off = s.req.items.len;
            var sink: fields_mod.TrailerStore = .{ .buf = &s.req, .allocator = self.allocator, .refs = s.hdr[s.hdr_count..], .count = &s.trl_count };
            self.decoder.decode(block, &sink) catch |err| switch (err) {
                error.HeaderListTooLarge => {},
                error.OutOfMemory => return self.fail(.internal_error),
                else => return self.fail(.compression_error),
            };
            if (sink.fault) return self.resetStream(ctx, s, .protocol_error);
            if (s.content_length) |cl| {
                if (s.body_received != cl and s.fault == null) return self.resetStream(ctx, s, .protocol_error);
            }
            s.state = .half_closed_remote;
            // A tunnel's trailers end it like END_STREAM on DATA.
            if (s.tunnel) return self.pumpStream(Handler, ctx, s);
            if (s.body_stream) {
                s.body_end = true;
                return self.drainBody(Handler, ctx, s);
            }
            return self.dispatch(Handler, ctx, s);
        }
        var sink: RequestSink = .{ .stream = s, .allocator = self.allocator, .allow_protocol = self.opts.enable_connect_protocol };
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
        // A PRIORITY_UPDATE sent before the request is the newer signal.
        if (!s.prio_frame) s.prio = s.headerPriority();
        if (s.protocol != null and s.fault == null) {
            // Extended CONNECT: answered now, DATA is the tunnel's.
            s.tunnel = true;
            if (end_stream) s.state = .half_closed_remote;
            if (@hasDecl(Handler, "handleHead") and self.checkHead(Handler, ctx, s) == .reject)
                return self.respondSync(Handler, ctx, s, false);
            return self.dispatch(Handler, ctx, s);
        }
        if (end_stream) {
            if (s.content_length) |cl| {
                if (cl != 0 and s.fault == null) return self.resetStream(ctx, s, .protocol_error);
            }
            s.state = .half_closed_remote;
        }
        if (@hasDecl(Handler, "handleHead") and s.fault == null) {
            switch (self.checkHead(Handler, ctx, s)) {
                .buffer => {},
                // The response, then RST_STREAM(NO_ERROR) if the body is
                // still to come (§8.1).
                .reject => return self.respondSync(Handler, ctx, s, ctx.req.method == .HEAD),
                .stream => return self.startBody(Handler, ctx, s),
            }
        }
        if (s.fault == null) {
            if (s.content_length) |cl| {
                if (cl > self.opts.limits.max_body_size) s.fault = .body_too_large;
            }
        }
        if (end_stream) return self.dispatch(Handler, ctx, s);
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
        const connect = std.mem.eql(u8, s.slice(method), "CONNECT");
        if (s.protocol != null) {
            // RFC 8441 §4: :protocol only on CONNECT, which then has
            // :scheme and :path like any request.
            if (!connect) {
                s.fault = .protocol;
                return;
            }
        } else if (connect) {
            // RFC 9113 §8.5: no :scheme or :path. A proxy's CONNECT: not
            // supported.
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
            if (!fillRequest(ctx, s)) {
                resp.status = .not_implemented;
                return self.respondSync(Handler, ctx, s, false);
            }
            is_head = req.method == .HEAD;
            if (tooEarly(ctx)) return self.respondSync(Handler, ctx, s, is_head);
            ctx.handler.handleRequest(req, resp);
            if (s.tunnel and resp.is_ws_upgrade) return self.startWebSocket(Handler, ctx, s);
            if (resp.mode != .sync) return self.bindExchange(Handler, ctx, s, is_head);
        }
        self.respondSync(Handler, ctx, s, is_head);
    }

    /// Fills the worker's Request from the stream. False for an unknown
    /// method.
    fn fillRequest(ctx: anytype, s: *Stream) bool {
        const req = ctx.req;
        req.reset();
        req.version = .@"HTTP/1.1";
        req.method = Method.parse(s.slice(s.method.?)) catch return false;
        req.path_and_query = s.slice(s.path.?);
        req.protocol = if (s.protocol) |p| s.slice(p) else null;
        for (s.hdr[0..s.hdr_count], 0..) |h, i| {
            req.headers[i] = .{
                .key = s.req.items[h.name_off..][0..h.name_len],
                .value = s.req.items[h.name_off + h.name_len ..][0..h.value_len],
            };
        }
        req.headers_len = s.hdr_count;
        req.body = s.req.items[s.body_start..s.bodyEnd()];
        req.trailers = s.trailers(req.headers[s.hdr_count..]);
        req.early_data = ctx.early_data;
        return true;
    }

    /// RFC 8470 §5.2: a request in early data whose method isn't safe is
    /// answered 425 Too Early (the client retries once the handshake is
    /// done). Sets the response if so.
    fn tooEarly(ctx: anytype) bool {
        if (!ctx.early_data or ctx.req.method.isSafe()) return false;
        ctx.resp.reset();
        ctx.resp.status = .too_early;
        ctx.resp.body = "";
        return true;
    }

    /// handleHead on a complete field block. An unknown method is left
    /// to dispatch (501).
    fn checkHead(_: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream) exchange.BodyMode {
        if (!fillRequest(ctx, s)) return .buffer;
        if (tooEarly(ctx)) return .reject;
        ctx.resp.reset();
        const mode = ctx.handler.handleHead(ctx.req, ctx.resp);
        if (mode == .stream and !@hasDecl(Handler, "handleBody")) return .buffer;
        return mode;
    }

    /// handleHead chose `.stream`: handleRequest runs now with an empty
    /// body. If it takes an exchange, DATA goes to handleBody from here
    /// on; if it answers at once, the body is not read (RST_STREAM with
    /// NO_ERROR after the response).
    fn startBody(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream) void {
        const resp = ctx.resp;
        resp.reset();
        _ = fillRequest(ctx, s);
        const is_head = ctx.req.method == .HEAD;
        ctx.handler.handleRequest(ctx.req, resp);
        if (resp.mode == .sync) return self.respondSync(Handler, ctx, s, is_head);
        s.body_stream = true;
        s.body_end = s.state == .half_closed_remote;
        s.req.items.len = s.body_start;
        self.bindExchange(Handler, ctx, s, is_head);
        // The exchange may have finished (and the stream closed) already.
        if (s.active and s.exchange != NIL) self.drainBody(Handler, ctx, s);
    }

    /// The handler accepted a WebSocket (RFC 8441 §5): a 2xx HEADERS
    /// without END_STREAM, then the stream's DATA is the WebSocket's. A
    /// tunnel slot in the exchange slab routes sends from other threads
    /// back here.
    fn startWebSocket(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream) void {
        const resp = ctx.resp;
        const code = @backingInt(resp.status);
        if (!@hasDecl(Handler, "handleWSFrame") or code < 200 or code >= 300) {
            resp.is_ws_upgrade = false;
            return self.respondSync(Handler, ctx, s, false);
        }
        const ex = ctx.exchanges.createTunnel(ctx.conn_slot, ctx.conn_gen, s.id) catch {
            resp.reset();
            resp.status = .service_unavailable;
            return self.respondSync(Handler, ctx, s, false);
        };
        s.ws = ws.Conn.create(self.allocator, ctx.fd, self.opts.websocket, ctx.exchanges.mailbox, ex.mailboxEntry()) catch {
            ctx.exchanges.release(ex.slot);
            return self.resetStream(ctx, s, .internal_error);
        };
        s.exchange = ex.slot;
        self.output_streams += 1;
        self.writeHead(ctx, s, resp.status, resp.headerBytes(), null, false);
        s.head_sent = true;
        if (@hasDecl(Handler, "handleWSConn")) ctx.handler.handleWSConn(s.ws.?);
        self.pumpStream(Handler, ctx, s);
    }

    /// Serialises a complete response: HEADERS, then DATA as the windows
    /// allow (the rest is copied to the stream's pending buffer).
    fn respondSync(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream, is_head: bool) void {
        const resp = ctx.resp;
        const code = @backingInt(resp.status);
        const body_len = resp.bodyLen();
        const has_body = !is_head and code >= 200 and code != 204 and code != 304 and body_len > 0;
        const content_length: ?usize = if (resp.status.allowsContentLength() and !resp.is_ws_upgrade) @intCast(body_len) else null;
        self.writeHead(ctx, s, resp.status, resp.headerBytes(), content_length, !has_body);
        s.head_sent = true;
        if (resp.takeFile()) |f| {
            if (!has_body) {
                f.release();
                return self.finishStream(ctx, s);
            }
            // Read into DATA frames as the windows allow.
            s.file = f;
            self.output_streams += 1;
            return self.pumpStream(Handler, ctx, s);
        }
        if (!has_body) return self.finishStream(ctx, s);
        const yield = self.blocked_count > 0 and self.mustYield(s);
        const sent = if (yield) 0 else self.writeData(s, resp.body, true);
        if (sent < resp.body.len) {
            s.pending.appendSlice(self.allocator, resp.body[sent..]) catch return self.fail(.internal_error);
            s.pending_end = true;
            self.output_streams += 1;
            self.setBlocked(s, yield or s.send_window > 0);
            return;
        }
        self.finishStream(ctx, s);
    }

    /// Our side of the stream is done: close it, resetting the request if
    /// the client is still sending (§8.1).
    fn finishStream(self: *Self, ctx: anytype, s: *Stream) void {
        if (s.state == .open) return self.resetStream(ctx, s, .no_error);
        self.closeStream(ctx, s, .ended, false);
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
            const room = self.opts.out_limit + 2 * self.opts.max_frame_size -| self.unsent();
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
            if (!s.active or s.exchange != slot) continue;
            if (s.ws) |w| {
                w.clearPosted();
                return self.pumpStream(Handler, ctx, s);
            }
            if (ctx.exchanges.handle(slot).takeResume() and s.body_paused) {
                s.body_paused = false;
                self.drainBody(Handler, ctx, s);
            }
            if (s.active and s.exchange == slot) self.pumpStream(Handler, ctx, s);
            return;
        }
    }

    /// The worker's exchange deadline scan found this exchange expired.
    pub fn onExchangeTimeout(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        for (self.streams) |*s| {
            if (!s.active or s.exchange != slot) continue;
            if (s.blocked) {
                // Its output waits behind other streams (the worker times
                // out a connection whose output doesn't drain at all).
                return ctx.exchanges.postpone(slot, ctx.now);
            }
            // A WebSocket's output stalled, or the peer never answered our
            // close frame.
            return self.resetStream(ctx, s, if (s.ws != null) .cancel else .internal_error);
        }
    }

    /// Called by the worker after output drained: continue sending.
    pub fn pump(self: *Self, comptime Handler: type, ctx: *const Context(Handler)) void {
        self.pumpAll(Handler, ctx);
    }

    /// Sends for every stream with output, in priority order (RFC 9218
    /// §10), until `out` is full.
    fn pumpAll(self: *Self, comptime Handler: type, ctx: *const Context(Handler)) void {
        if (self.output_streams == 0 or self.failed) return;
        var n: usize = 0;
        for (self.streams, 0..) |*s, slot| {
            if (!self.wantsPump(s)) continue;
            self.order[n] = @intCast(slot);
            n += 1;
        }
        const order = self.order[0..n];
        std.mem.sort(u32, order, self.streams, struct {
            fn less(streams: []Stream, a: u32, b: u32) bool {
                return streams[a].sendsBefore(&streams[b]);
            }
        }.less);
        var i: usize = 0;
        while (i < order.len) {
            const p = self.streams[order[i]].schedPriority();
            if (!p.incremental) {
                if (self.unsent() > self.opts.out_limit) return self.holdBack(order[i..]);
                const s = &self.streams[order[i]];
                if (self.wantsPump(s)) self.sendStream(Handler, ctx, s, std.math.maxInt(usize));
                if (self.failed) return;
                i += 1;
                continue;
            }
            // Incremental streams of one urgency share: a quantum each in
            // turn, starting after the one served last.
            var end = i + 1;
            while (end < order.len and self.streams[order[end]].schedPriority().urgency == p.urgency) end += 1;
            const group = order[i..end];
            var first: usize = 0;
            while (first < group.len and self.streams[group[first]].id <= self.rr_last[p.urgency]) first += 1;
            while (true) {
                var progressed = false;
                for (0..group.len) |k| {
                    const s = &self.streams[group[(first + k) % group.len]];
                    if (!self.wantsPump(s)) continue;
                    if (self.unsent() > self.opts.out_limit) return self.holdBack(order[i..]);
                    const before = self.out.items.len;
                    self.sendStream(Handler, ctx, s, share_quantum);
                    if (self.failed) return;
                    if (self.out.items.len != before) {
                        progressed = true;
                        self.rr_last[p.urgency] = s.id;
                    }
                }
                if (!progressed) break;
            }
            i = end;
        }
    }

    fn wantsPump(_: *const Self, s: *const Stream) bool {
        if (!s.active or !s.hasOutput()) return false;
        // A WebSocket with nothing held back is pumped when it posts.
        return s.ws == null or s.ws_pending;
    }

    /// `out` is full: the streams not reached wait for room.
    fn holdBack(self: *Self, slots: []const u32) void {
        for (slots) |slot| {
            const s = &self.streams[slot];
            if (self.wantsPump(s)) self.setBlocked(s, s.send_window > 0);
        }
    }

    fn setBlocked(self: *Self, s: *Stream, blocked: bool) void {
        if (s.blocked == blocked) return;
        s.blocked = blocked;
        if (blocked) self.blocked_count += 1 else self.blocked_count -= 1;
    }

    /// A stream waits for room, or for the connection window, that `s`
    /// would otherwise take first.
    fn mustYield(self: *const Self, s: *const Stream) bool {
        for (self.streams) |*t| {
            if (!t.blocked or t == s) continue;
            // An incremental stream yields to its peers too: `pumpAll`
            // shares between them.
            if (t.sendsBefore(s) or (s.schedPriority().incremental and !s.schedPriority().before(t.schedPriority()))) return true;
        }
        return false;
    }

    /// Sends what a stream has queued, unless more urgent streams are
    /// waiting for room: then it waits too, for the next `pumpAll` (the
    /// worker's once `out` drains, or a WINDOW_UPDATE's).
    fn pumpStream(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream) void {
        if (self.failed) return;
        if (self.blocked_count > 0 and self.mustYield(s)) {
            if (!s.hasOutput()) return;
            if (s.ws != null) s.ws_pending = true;
            return self.setBlocked(s, true);
        }
        self.sendStream(Handler, ctx, s, std.math.maxInt(usize));
    }

    /// Sends up to `budget` DATA bytes of what a stream has queued (its
    /// pending buffer, exchange or WebSocket).
    fn sendStream(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream, budget: usize) void {
        if (self.failed) return;
        self.setBlocked(s, false);
        if (s.ws != null) return self.pumpWebSocket(Handler, ctx, s, budget);
        if (s.file != null) return self.sendFile(ctx, s, budget);
        if (s.pending_end or s.pending_pos < s.pending.items.len) {
            const rest = s.pending.items[s.pending_pos..];
            const k = @min(rest.len, budget);
            const n = self.writeData(s, rest[0..k], k == rest.len);
            s.pending_pos += n;
            if (s.pending_pos == s.pending.items.len) {
                self.output_streams -= 1;
                s.pending_end = false;
                s.pending.clearRetainingCapacity();
                s.pending_pos = 0;
                return self.finishStream(ctx, s);
            }
            if (n < k) self.setBlocked(s, s.send_window > 0);
            self.noteStall(ctx, s, n > 0);
            return;
        }
        if (s.exchange == NIL) return;
        const ex = ctx.exchanges.handle(s.exchange);
        const e = ctx.exchanges.entry(s.exchange);
        const is_head = e.is_head;
        var sent: usize = 0;
        while (true) {
            if (self.unsent() > self.opts.out_limit) return self.setBlocked(s, s.send_window > 0);
            if (sent >= budget) return;
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
            const room = self.opts.out_limit + 2 * self.opts.max_frame_size -| self.unsent();
            var max = @min(@as(usize, if (window > 0) @intCast(window) else 0), self.peer_max_frame_size, room -| frame.header_len, budget - sent);
            if (is_head) max = self.peer_max_frame_size;
            if (max == 0) {
                self.setBlocked(s, s.send_window > 0);
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
                sent += r.n;
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

    /// Reads the file body straight into DATA frames, as far as the
    /// windows, `out_limit` and `budget` allow; END_STREAM on the last.
    fn sendFile(self: *Self, ctx: anytype, s: *Stream, budget: usize) void {
        const f = &s.file.?;
        var sent: usize = 0;
        while (f.len > 0) {
            if (self.unsent() > self.opts.out_limit) return self.setBlocked(s, s.send_window > 0);
            if (sent >= budget) return;
            const window = @min(s.send_window, self.send_window);
            const room = self.opts.out_limit + 2 * self.opts.max_frame_size -| self.unsent();
            const max: usize = @intCast(@min(@as(u64, if (window > 0) @intCast(window) else 0), self.peer_max_frame_size, room -| frame.header_len, budget - sent, f.len));
            if (max == 0) {
                self.setBlocked(s, s.send_window > 0);
                return self.noteStall(ctx, s, false);
            }
            const start = self.out.items.len;
            self.out.ensureUnusedCapacity(self.allocator, frame.header_len + max) catch return self.fail(.internal_error);
            self.out.items.len = start + frame.header_len + max;
            const got = sys.pread(f.fd, self.out.items[start + frame.header_len ..][0..max], f.offset) catch 0;
            if (got < max) {
                // The file shrank: the response can't be completed.
                self.out.items.len = start;
                return self.resetStream(ctx, s, .internal_error);
            }
            f.offset += max;
            f.len -= max;
            sent += max;
            frame.writeHeader(self.out.items[start..][0..frame.header_len], @intCast(max), .data, if (f.len == 0) frame.flag.end_stream else 0, s.id);
            s.send_window -= @intCast(max);
            self.send_window -= @intCast(max);
            self.noteStall(ctx, s, true);
        }
        f.release();
        s.file = null;
        self.output_streams -= 1;
        self.finishStream(ctx, s);
    }

    /// Sends what the WebSocket has queued as the windows allow. Once
    /// everything is written and the WebSocket is over (the close
    /// handshake, a failure, or the client's END_STREAM, which is a TCP
    /// FIN to it), END_STREAM ends our side and the stream closes.
    fn pumpWebSocket(self: *Self, comptime Handler: type, ctx: *const Context(Handler), s: *Stream, budget: usize) void {
        const w = s.ws.?;
        var progressed = false;
        var sent: usize = 0;
        while (sent < budget) {
            if (self.unsent() > self.opts.out_limit) {
                self.setBlocked(s, s.send_window > 0);
                break;
            }
            const bytes = w.wireBytes();
            if (bytes.len == 0) break;
            const k = @min(bytes.len, budget - sent);
            const n = self.writeData(s, bytes[0..k], false);
            w.advance(n);
            sent += n;
            progressed = progressed or n > 0;
            if (n < k) {
                self.setBlocked(s, s.send_window > 0);
                break;
            }
        }
        s.ws_pending = w.hasOutput();
        self.noteStall(ctx, s, progressed or !s.ws_pending);
        ctx.exchanges.tunnelTimer(s.exchange, ctx.now, s.ws_pending, progressed, w.closeSent());
        if (s.ws_pending) return;
        // Written: the window for what was read comes back.
        self.creditStream(s, 0);
        if (!w.wantsClose() and s.state == .open) return;
        var hdr: [frame.header_len]u8 = undefined;
        frame.writeHeader(&hdr, 0, .data, frame.flag.end_stream, s.id);
        self.out.appendSlice(self.allocator, &hdr) catch return self.fail(.internal_error);
        self.finishStream(ctx, s);
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
        // Only a zero window is the client's doing: waiting for room in
        // `out`, or behind more urgent streams, is not.
        if (s.send_window > 0) {
            s.stalled = false;
        } else if (!s.stalled) {
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
    /// Accept :protocol (we sent SETTINGS_ENABLE_CONNECT_PROTOCOL);
    /// otherwise it is an unknown pseudo-header field.
    allow_protocol: bool = false,

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
            else if (self.allow_protocol and std.mem.eql(u8, name, ":protocol"))
                &s.protocol
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
const ws_protocol = @import("../ws/protocol.zig");
const ws_upgrader = @import("../ws/upgrader.zig");

const TestHandler = struct {
    /// "METHOD path\n" plus selected headers and the body, per request.
    log: std.ArrayList(u8) = .empty,
    /// Exchanges taken by /later and /stream paths, in order.
    exchanges: std.ArrayList(exchange.Exchange) = .empty,
    aborts: usize = 0,
    writable: usize = 0,
    big: []const u8 = "",
    /// Streamed bodies (paths under /up): what handleBody saw.
    bodies: std.ArrayList(u8) = .empty,
    received: usize = 0,
    /// handleBody pauses after each chunk.
    pause: bool = false,
    /// WebSockets: the last one opened, and what the hooks saw.
    ws_conn: ?*ws.Conn = null,
    ws_log: std.ArrayList(u8) = .empty,
    /// /file and /file-owned (a duplicate the connection closes).
    file_fd: sys.fd_t = -1,
    file_len: u64 = 0,
    owned_fd: sys.fd_t = -1,

    pub fn handleWSConn(self: *TestHandler, conn: *ws.Conn) void {
        self.ws_conn = conn;
        self.ws_log.appendSlice(testing.allocator, "open;") catch unreachable;
    }

    pub fn handleWSDisconn(self: *TestHandler, conn: *ws.Conn) void {
        if (self.ws_conn == conn) self.ws_conn = null;
        self.ws_log.appendSlice(testing.allocator, "gone;") catch unreachable;
    }

    /// Echoes text and binary; "close-me" starts the close handshake,
    /// "big" sends 1000 bytes.
    pub fn handleWSFrame(self: *TestHandler, conn: *ws.Conn, fr: *ws.Frame) void {
        const p = fr.getPayload();
        self.ws_log.print(testing.allocator, "{s}:{s};", .{ fr.opcode.toString(), p[0..@min(p.len, 16)] }) catch unreachable;
        switch (fr.opcode) {
            .text, .binary => {},
            else => return,
        }
        if (std.mem.eql(u8, p, "close-me")) {
            conn.close(1000, "bye") catch unreachable;
        } else if (std.mem.eql(u8, p, "big")) {
            conn.sendBinary(&(@as([1000]u8, @splat('B')))) catch unreachable;
        } else {
            conn.send(p, fr.opcode == .binary) catch unreachable;
        }
    }

    pub fn handleHead(_: *TestHandler, req: *Request, resp: *Response) exchange.BodyMode {
        const path = req.getPath();
        if (std.mem.eql(u8, path, "/reject")) {
            resp.status = .forbidden;
            resp.setBodyBorrowed("no");
            return .reject;
        }
        return if (std.mem.startsWith(u8, path, "/up")) .stream else .buffer;
    }

    pub fn handleBody(self: *TestHandler, ex: exchange.Exchange, chunk: []const u8, end: ?[]const Header) exchange.BodyAction {
        const a = testing.allocator;
        self.received += chunk.len;
        self.bodies.print(a, "{d}:{s};", .{ chunk.len, chunk[0..@min(chunk.len, 8)] }) catch unreachable;
        if (end) |trailers| {
            self.bodies.appendSlice(a, "END") catch unreachable;
            for (trailers) |t| self.bodies.print(a, " [{s}={s}]", .{ t.key, t.value }) catch unreachable;
            self.bodies.append(a, '\n') catch unreachable;
            var buf: [32]u8 = undefined;
            ex.respond(.{}, std.fmt.bufPrint(&buf, "got {d}", .{self.received}) catch unreachable) catch unreachable;
            self.received = 0;
            return .more;
        }
        return if (self.pause) .pause else .more;
    }

    pub fn handleRequest(self: *TestHandler, req: *Request, resp: *Response) void {
        const a = testing.allocator;
        self.log.print(a, "{s} {s}", .{ @tagName(req.method), req.path_and_query }) catch unreachable;
        for (req.getHeaders()) |h| {
            if (std.mem.startsWith(u8, h.key, "x-") or std.mem.eql(u8, h.key, "host") or std.mem.eql(u8, h.key, "cookie")) {
                self.log.print(a, " [{s}={s}]", .{ h.key, h.value }) catch unreachable;
            }
        }
        if (req.body.len > 0) self.log.print(a, " body={d}:{s}", .{ req.body.len, req.body[0..@min(req.body.len, 12)] }) catch unreachable;
        for (req.trailers) |t| self.log.print(a, " trailer[{s}={s}]", .{ t.key, t.value }) catch unreachable;
        if (req.early_data) self.log.appendSlice(a, " early") catch unreachable;
        self.log.append(a, '\n') catch unreachable;
        const path = req.getPath();
        if (std.mem.eql(u8, path, "/up-sync")) {
            resp.setBodyBorrowed("early");
            return;
        }
        if (std.mem.startsWith(u8, path, "/up")) {
            self.exchanges.append(a, resp.later() catch unreachable) catch unreachable;
            return;
        }
        if (std.mem.eql(u8, path, "/ws")) {
            ws_upgrader.handleUpgrade(undefined, req, resp) catch {
                resp.status = .bad_request;
            };
            return;
        }
        if (std.mem.eql(u8, path, "/file")) {
            resp.sendFile(.{ .fd = self.file_fd, .len = self.file_len });
            return;
        }
        if (std.mem.eql(u8, path, "/file-owned")) {
            self.owned_fd = @intCast(std.posix.system.dup(self.file_fd));
            resp.sendFile(.{ .fd = self.owned_fd, .len = self.file_len, .close = true });
            return;
        }
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
    /// Input is TLS early data, as the worker would say.
    early_data: bool = false,
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
    /// Every DATA payload the server sent, in order.
    data_out: std.ArrayList(u8) = .empty,
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
        h.handler.bodies.deinit(a);
        h.handler.exchanges.deinit(a);
        h.handler.ws_log.deinit(a);
        h.data_out.deinit(a);
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
            .pool = &h.pool,
            .early_data = h.early_data,
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
                        try h.data_out.appendSlice(a, d.data);
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
                    .priority, .priority_update, .unknown => try line.print(a, "?", .{}),
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

    /// The worker's part once output drains: pump, until nothing more
    /// goes out.
    fn flushAll(h: *Harness) !void {
        while (true) {
            const c = h.ctx();
            h.conn.pump(TestHandler, &c);
            const before = h.out.items.len;
            try h.collect();
            if (h.out.items.len == before) break;
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

const server_preface = "settings ack=false max_concurrent_streams=128 initial_window_size=1048576 max_frame_size=16384 max_header_list_size=16384 no_rfc7540_priorities=1\nwindow 0 +4128769\n";

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
    try h.expectLog("POST /echo [host=example.com] body=3:abc trailer[x-trailer=t]\nHEAD / [host=h]\nGET /empty [host=example.com]\n");
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
    // After our RST (refused stream 5), its DATA is ignored.
    try h.data(5, "x", false);
    try h.expectEvents("");
    // A stream the peer reset: DATA and HEADERS on it are stream errors.
    try h.headers(.{ .stream = 9, .end_stream = false, .fields = &post });
    try h.rst(9, .cancel);
    try h.data(9, "x", false);
    try h.expectEvents("rst 9 stream_closed\n");
    try h.get(9, "/again");
    try h.expectEvents("rst 9 stream_closed\n");
    // DATA on an idle stream: a connection error.
    try h.get(11, "/");
    h.events.clearRetainingCapacity();
    try h.feed(&[_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 13, 'x' });
    try h.expectEvents("goaway last=11 protocol_error\n");
    try testing.expectEqual(Action.close, h.last);
    // Frames on a stream that ended normally (END_STREAM both ways): a
    // connection error (§5.1), as h2spec 5.1/12 checks.
    for ([_]bool{ false, true }) |use_headers| {
        const hh = try Harness.init(.{});
        defer hh.deinit();
        try hh.preface();
        try hh.get(1, "/");
        hh.events.clearRetainingCapacity();
        if (use_headers) try hh.get(1, "/again") else try hh.data(1, "x", false);
        try hh.expectEvents("goaway last=1 stream_closed\n");
        try testing.expectEqual(Action.close, hh.last);
    }
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
        \\settings ack=false max_concurrent_streams=128 initial_window_size=65535 max_frame_size=16384 max_header_list_size=16384 no_rfc7540_priorities=1
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

fn postTo(h: *Harness, stream: u31, path: []const u8, end_stream: bool) !void {
    try h.headers(.{ .stream = stream, .end_stream = end_stream, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "example.com" },
    } });
}

test "streamed bodies: handleHead reject and stream, trailers, an early answer" {
    const h = try Harness.init(.{ .limits = .{ .max_body_size = 10 } });
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    // Rejected: without a body the stream just ends; with one, the rest is
    // refused with RST_STREAM(NO_ERROR) after the response.
    try postTo(h, 1, "/reject", true);
    try postTo(h, 3, "/reject", false);
    try h.expectEvents(
        \\headers 1 end=false [:status=403] [content-length=2] [date]
        \\data 1 len=2 end=true
        \\headers 3 end=false [:status=403] [content-length=2] [date]
        \\data 3 len=2 end=true
        \\rst 3 no_error
        \\
    );
    try h.expectLog("");
    // Streamed, beyond max_body_size, with trailers.
    try postTo(h, 5, "/up", false);
    try h.expectLog("POST /up [host=example.com]\n");
    try h.data(5, "hello ", false);
    try h.data(5, "streamed world", false);
    try h.expectEvents("");
    try h.headers(.{ .stream = 5, .fields = &.{.{ .name = "x-sum", .value = "20" }} });
    try testing.expectEqualStrings("6:hello ;14:streamed;0:;END [x-sum=20]\n", h.handler.bodies.items);
    try h.expectEvents(
        \\headers 5 end=false [:status=200] [content-length=6] [date]
        \\data 5 len=6 end=true
        \\
    );
    // No body at all: the end is delivered at once.
    h.handler.bodies.clearRetainingCapacity();
    try postTo(h, 7, "/up", true);
    try testing.expectEqualStrings("0:;END\n", h.handler.bodies.items);
    try h.expectEvents("headers 7 end=false [:status=200] [content-length=5] [date]\ndata 7 len=5 end=true\n");
    // Answered at once: the body is refused.
    try postTo(h, 9, "/up-sync", false);
    try h.expectEvents("headers 9 end=false [:status=200] [content-length=5] [date]\ndata 9 len=5 end=true\nrst 9 no_error\n");
    try h.data(9, "ignored", true);
    try h.expectEvents("");
    // A body cut short of its content-length, or past it, is malformed.
    try h.headers(.{ .stream = 11, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/up" },
        .{ .name = "content-length", .value = "3" },
    } });
    try h.data(11, "abcd", false);
    try h.expectEvents("rst 11 protocol_error\n");
    try testing.expectEqual(@as(usize, 1), h.handler.aborts);
    h.events.clearRetainingCapacity();
    try h.expectLog("POST /up [host=example.com]\nPOST /up-sync [host=example.com]\nPOST /up\n");
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
}

test "streamed bodies: a pause holds the window back, resume delivers what was kept" {
    const h = try Harness.init(.{ .initial_window_size = 65535 });
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    h.handler.pause = true;
    try postTo(h, 1, "/up", false);
    const chunk: [16384]u8 = @splat('u');
    // The first DATA is delivered, then the handler pauses: the rest of
    // the window's worth is kept, and no WINDOW_UPDATE goes out.
    try h.data(1, &chunk, false);
    try h.data(1, &chunk, false);
    try h.data(1, &chunk, false);
    try h.data(1, chunk[0..16383], false);
    try testing.expectEqualStrings("16384:uuuuuuuu;", h.handler.bodies.items);
    try h.expectEvents("");
    // Past the window: a flow control error, so the hold is real.
    const h2 = try Harness.init(.{ .initial_window_size = 65535 });
    defer h2.deinit();
    try h2.preface();
    h2.events.clearRetainingCapacity();
    h2.handler.pause = true;
    try postTo(h2, 1, "/up", false);
    for (0..4) |_| try h2.data(1, &chunk, false);
    try h2.expectEvents("rst 1 flow_control_error\n");
    try testing.expectEqual(@as(usize, 1), h2.handler.aborts);
    // Resume: what was kept is delivered in one call, and the window
    // comes back.
    h.handler.pause = false;
    try h.handler.exchanges.items[0].resumeBody();
    try h.drainMailbox();
    try h.collect();
    try testing.expectEqualStrings("16384:uuuuuuuu;49151:uuuuuuuu;", h.handler.bodies.items);
    try h.expectEvents("window 1 +65535\n");
    // Paused again with END_STREAM kept: the end waits for the resume too.
    h.handler.pause = true;
    try h.data(1, &chunk, false);
    try h.data(1, "tail", true);
    try testing.expectEqualStrings("16384:uuuuuuuu;49151:uuuuuuuu;16384:uuuuuuuu;", h.handler.bodies.items);
    try h.expectEvents("");
    try h.handler.exchanges.items[0].resumeBody();
    try h.drainMailbox();
    try h.collect();
    try testing.expectEqualStrings("16384:uuuuuuuu;49151:uuuuuuuu;16384:uuuuuuuu;4:tail;END\n", h.handler.bodies.items);
    try h.expectEvents("headers 1 end=false [:status=200] [content-length=9] [date]\ndata 1 len=9 end=true\n");
    // A client reset while paused aborts the exchange.
    try postTo(h, 3, "/up", false);
    try h.data(3, "x", false);
    try h.rst(3, .cancel);
    try testing.expectEqual(@as(usize, 1), h.handler.aborts);
}

test "streamed bodies: a response given in handleBody goes out in the same pass" {
    // Found by the fuzzer: one read with the whole request, then a
    // connection error. The response is sent before the GOAWAY, as it
    // would be if the bytes arrived one at a time.
    const h = try Harness.init(.{});
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    var block: [256]u8 = undefined;
    var bn: usize = 0;
    for ([_][2][]const u8{ .{ ":method", "POST" }, .{ ":scheme", "https" }, .{ ":path", "/up" } }) |f|
        bn += try h.enc.encode(block[bn..], f[0], f[1], .{});
    var input: [512]u8 = undefined;
    var n = try frame.writeHeaders(&input, 1, frame.flag.end_headers, block[0..bn]);
    n += try frame.writeData(input[n..], 1, true, "body");
    n += try frame.writeData(input[n..], 3, false, "idle"); // a connection error
    try h.feed(input[0..n]);
    try h.expectEvents(
        \\headers 1 end=false [:status=200] [content-length=5] [date]
        \\data 1 len=5 end=true
        \\goaway last=1 protocol_error
        \\
    );
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
            else => blk: {
                frame.writeHeader(buf[0..frame.header_len], 5, .priority, 0, 1);
                @memset(buf[frame.header_len..][0..5], 0);
                break :blk frame.header_len + 5;
            },
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

fn fdOpen(fd: sys.fd_t) bool {
    return std.posix.errno(std.posix.system.fcntl(fd, std.posix.F.GETFD, @as(usize, 0))) != .BADF;
}

test "file bodies: DATA frames through the windows, HEAD, a reset closes the owned file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const file = try tmp.dir.createFile(io, "f", .{ .read = true });
    defer file.close(io);
    var content: [100_000]u8 = undefined;
    for (&content, 0..) |*b, i| b.* = @truncate(i *% 7);
    try file.writeStreamingAll(io, &content);
    const h = try Harness.init(.{});
    defer h.deinit();
    h.handler.file_fd = file.handle;
    h.handler.file_len = content.len;
    try h.preface();
    h.events.clearRetainingCapacity();
    // The client's windows (65535) hold the rest back.
    try h.get(1, "/file");
    try testing.expect(std.mem.startsWith(u8, h.events.items, "headers 1 end=false [:status=200] [content-length=100000] [date]\n"));
    try expectData(h, "1:16384 1:16384 1:16384 1:16383");
    try h.window(1, 100_000);
    try h.window(0, 100_000);
    try expectData(h, "1:16384 1:16384 1:1697!");
    try testing.expectEqualSlices(u8, &content, h.data_out.items);
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    // HEAD: the length only, and an owned file closed at once.
    try h.headers(.{ .stream = 3, .fields = &.{
        .{ .name = ":method", .value = "HEAD" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/file-owned" },
    } });
    try h.expectEvents("headers 3 end=true [:status=200] [content-length=100000] [date]\n");
    try testing.expect(!fdOpen(h.handler.owned_fd));
    // Reset by the client mid-file: closed too.
    try h.get(5, "/file-owned");
    try testing.expect(fdOpen(h.handler.owned_fd));
    try h.rst(5, .cancel);
    try testing.expect(!fdOpen(h.handler.owned_fd));
    // Open at the end: closed with the connection.
    try h.get(7, "/file-owned");
    h.conn.abortAll(&h.ctx());
    h.conn.deinit(&h.pool);
    try testing.expect(!fdOpen(h.handler.owned_fd));
    h.conn = try Conn.init(testing.allocator, .{});
}

/// A GET with an optional `priority` header, as frame bytes.
fn appendGet(h: *Harness, out: *std.ArrayList(u8), stream: u31, path: []const u8, priority: ?[]const u8) !void {
    var fields: [5]hpack.Field = .{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "priority", .value = priority orelse "" },
    };
    const block = try h.encodeFields(fields[0..if (priority != null) 5 else 4]);
    defer testing.allocator.free(block);
    var buf: [256]u8 = undefined;
    const n = try frame.writeHeaders(&buf, stream, frame.flag.end_stream | frame.flag.end_headers, block);
    try out.appendSlice(testing.allocator, buf[0..n]);
}

fn priorityUpdate(h: *Harness, stream: u32, value: []const u8) !void {
    var buf: [frame.header_len + 4 + 64]u8 = undefined;
    try h.feed(buf[0..try frame.writePriorityUpdate(&buf, stream, value)]);
}

/// The DATA frames in `events` as "stream:len" ("!" on END_STREAM),
/// clearing them.
fn dataSequence(h: *Harness) ![]u8 {
    const a = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, h.events.items, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, it.next().?, "data")) continue;
        const id = it.next().?;
        const len = it.next().?["len=".len..];
        const end = std.mem.eql(u8, it.next().?, "end=true");
        if (out.items.len > 0) try out.append(a, ' ');
        try out.print(a, "{s}:{s}{s}", .{ id, len, if (end) "!" else "" });
    }
    h.events.clearRetainingCapacity();
    return out.toOwnedSlice(a);
}

fn expectData(h: *Harness, expected: []const u8) !void {
    const got = try dataSequence(h);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

/// The streams in the order their DATA went out, repeats collapsed.
fn expectDataRuns(h: *Harness, expected: []const u8) !void {
    const a = testing.allocator;
    var runs: std.ArrayList(u8) = .empty;
    defer runs.deinit(a);
    var lines = std.mem.tokenizeScalar(u8, h.events.items, '\n');
    var last: []const u8 = "";
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, it.next().?, "data")) continue;
        const id = it.next().?;
        if (std.mem.eql(u8, id, last)) continue;
        last = id;
        if (runs.items.len > 0) try runs.append(a, ' ');
        try runs.appendSlice(a, id);
    }
    h.events.clearRetainingCapacity();
    try testing.expectEqualStrings(expected, runs.items);
}

test "priorities (RFC 9218): urgency first, incremental streams share, PRIORITY_UPDATE reorders" {
    const h = try Harness.init(.{});
    defer h.deinit();
    const big = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    h.handler.big = big;
    try h.preface();
    // Large stream windows; the connection window stays at 65535.
    try h.settings(&.{.{ .id = .initial_window_size, .value = 1 << 20 }});
    h.events.clearRetainingCapacity();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try appendGet(h, &frames, 1, "/big", "u=5");
    try appendGet(h, &frames, 3, "/big", "u=1");
    try appendGet(h, &frames, 5, "/big", null);
    try appendGet(h, &frames, 7, "/big", "u=2, i");
    try appendGet(h, &frames, 9, "/big", "u=2;x=1, i=?1, y=(a b)");
    try h.feed(frames.items);
    // The first stream takes the connection window as it arrives.
    try expectData(h, "1:16384 1:16384 1:16384 1:16383");
    // Then the most urgent goes first: 3 (u=1), then 7 and 9 (u=2,
    // incremental) in turns, then 5 (u=3), then 1 (u=5).
    try h.window(0, 3 * 16384);
    try expectData(h, "3:16384 3:16384 3:16384");
    try h.window(0, 60_000);
    try expectData(h, "3:16384 3:16384 3:16384 3:1696! 7:9152");
    try h.window(0, 4 * 16384);
    try expectData(h, "9:16384 7:16384 9:16384 7:16384");
    // PRIORITY_UPDATE: stream 1 becomes the most urgent.
    try priorityUpdate(h, 1, "u=0");
    try h.window(0, 40_000);
    try expectData(h, "1:16384 1:16384 1:1697! 9:5535");
    try h.window(0, 1_000_000);
    try expectDataRuns(h, "7 9 7 9 7 9 7 9 5");
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    try testing.expectEqual(@as(u32, 0), h.conn.blocked_count);
}

test "priorities: urgency orders streams waiting for room in out_limit" {
    const h = try Harness.init(.{ .out_limit = 1024 });
    defer h.deinit();
    const big = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    h.handler.big = big;
    try h.preface();
    try h.settings(&.{.{ .id = .initial_window_size, .value = 1 << 20 }});
    try h.window(0, 1 << 20);
    h.events.clearRetainingCapacity();
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try appendGet(h, &frames, 1, "/big", "u=7");
    try appendGet(h, &frames, 3, "/big", "u=0");
    try appendGet(h, &frames, 5, "/big", "u=0");
    try h.feed(frames.items);
    try h.flushAll();
    // 1 starts before the others arrive; 3 overtakes it, 5 waits for 3
    // (non-incremental, in stream order), then 1 finishes.
    try expectDataRuns(h, "1 3 5 1");
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    try testing.expectEqual(@as(u32, 0), h.conn.blocked_count);
}

test "priorities: PRIORITY_UPDATE before the request, limits, errors" {
    {
        const h = try Harness.init(.{ .max_concurrent_streams = 2 });
        defer h.deinit();
        try h.preface();
        try h.get(1, "/later");
        // Kept for idle stream 3, replaced, a bad value ignored; it wins
        // over the request's header.
        try priorityUpdate(h, 3, "u=6");
        try priorityUpdate(h, 3, "u=0, i");
        try priorityUpdate(h, 3, "u=");
        try h.get(3, "/later");
        try testing.expectEqual(Priority{ .urgency = 0, .incremental = true }, h.conn.findStream(3).?.prio);
        var frames: std.ArrayList(u8) = .empty;
        defer frames.deinit(testing.allocator);
        try appendGet(h, &frames, 5, "/later", "u=4");
        try h.feed(frames.items); // refused: two streams are open
        // Updates for open and closed streams.
        try priorityUpdate(h, 1, "i");
        try testing.expectEqual(Priority{ .incremental = true }, h.conn.findStream(1).?.prio);
        try priorityUpdate(h, 5, "u=1");
        try testing.expectEqual(Action.need_more, h.last);
        // Idle prioritised streams plus open ones over the limit.
        try h.handler.exchanges.items[0].respond(.{}, "x");
        try h.drainMailbox();
        try priorityUpdate(h, 7, "u=1");
        try testing.expectEqual(Action.need_more, h.last);
        h.events.clearRetainingCapacity();
        try priorityUpdate(h, 9, "u=1");
        try h.expectEvents("goaway last=5 protocol_error\n");
        try testing.expectEqual(Action.close, h.last);
    }
    {
        // An even ID: a push stream, idle since we never push.
        const h = try Harness.init(.{});
        defer h.deinit();
        try h.preface();
        h.events.clearRetainingCapacity();
        try priorityUpdate(h, 2, "u=1");
        try h.expectEvents("goaway last=0 protocol_error\n");
    }
    {
        // The header alone.
        const h = try Harness.init(.{});
        defer h.deinit();
        try h.preface();
        var frames: std.ArrayList(u8) = .empty;
        defer frames.deinit(testing.allocator);
        try appendGet(h, &frames, 1, "/later", "u=6, i");
        try appendGet(h, &frames, 3, "/later", "u=6, i, u=");
        try h.feed(frames.items);
        try testing.expectEqual(Priority{ .urgency = 6, .incremental = true }, h.conn.findStream(1).?.prio);
        try testing.expectEqual(Priority{}, h.conn.findStream(3).?.prio);
    }
}

test "priorities: an exchange waiting behind other streams doesn't time out" {
    const h = try Harness.init(.{});
    defer h.deinit();
    const big = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    h.handler.big = big;
    try h.preface();
    try h.settings(&.{.{ .id = .initial_window_size, .value = 1 << 20 }});
    var frames: std.ArrayList(u8) = .empty;
    defer frames.deinit(testing.allocator);
    try appendGet(h, &frames, 1, "/big", "u=0");
    try appendGet(h, &frames, 3, "/stream", "u=7");
    try h.feed(frames.items);
    const ex = h.handler.exchanges.items[0];
    try ex.write("waiting");
    try h.drainMailbox();
    try h.collect();
    // The connection window is spent on stream 1: 3 waits, and its
    // deadline moves instead of resetting it.
    h.events.clearRetainingCapacity();
    h.now += 100;
    const c = h.ctx();
    h.conn.onExchangeTimeout(TestHandler, &c, ex.slot);
    try h.collect();
    try h.expectEvents("");
    try testing.expectEqual(h.now + 11, h.slab.entry(ex.slot).deadline);
    try h.window(0, 1 << 20);
    try expectDataRuns(h, "1 3");
    // Not waiting: reset as before.
    h.conn.onExchangeTimeout(TestHandler, &c, ex.slot);
    try h.collect();
    try h.expectEvents("rst 3 internal_error\n");
}

// Any split of the same client bytes gives the same frames per stream.
fn connectWs(h: *Harness, stream: u31, path: []const u8) !void {
    try h.headers(.{ .stream = stream, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = path },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "sec-websocket-version", .value = "13" },
    } });
}

/// One masked WebSocket frame in a DATA frame.
fn wsSend(h: *Harness, stream: u31, op: ws_protocol.Opcode, payload: []const u8, end: bool) !void {
    var buf: [2048]u8 = undefined;
    try h.data(stream, ws_protocol.encodeFrame(&buf, true, op, payload, .{ 1, 2, 3, 4 }), end);
}

test "WebSocket over HTTP/2 (RFC 8441): the setting, and extended CONNECT validation" {
    const off = try Harness.init(.{});
    defer off.deinit();
    try off.preface();
    off.events.clearRetainingCapacity();
    // Not advertised: :protocol is an unknown pseudo-header field.
    try connectWs(off, 1, "/ws");
    try off.expectEvents("rst 1 protocol_error\n");

    const h = try Harness.init(.{ .enable_connect_protocol = true });
    defer h.deinit();
    try h.expectEvents("settings ack=false max_concurrent_streams=128 initial_window_size=1048576 max_frame_size=16384 max_header_list_size=16384 no_rfc7540_priorities=1 enable_connect_protocol=1\nwindow 0 +4128769\n");
    try h.preface();
    try h.expectEvents("settings ack=true\n");
    // :protocol on another method, and an extended CONNECT without :path.
    try h.headers(.{ .stream = 1, .fields = &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/ws" },
        .{ .name = ":authority", .value = "example.com" },
    } });
    try h.expectEvents("rst 1 protocol_error\n");
    try h.headers(.{ .stream = 3, .end_stream = false, .fields = &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    } });
    try h.expectEvents("rst 3 protocol_error\n");
    // A proxy's CONNECT is still 501.
    try h.headers(.{ .stream = 5, .fields = &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    } });
    try h.expectEvents("headers 5 end=true [:status=501] [content-length=0] [date]\n");
    try h.expectLog("");
    // A handler that doesn't take the WebSocket answers as usual; the
    // client's side is then reset (NO_ERROR) and its DATA ignored.
    try connectWs(h, 7, "/other");
    try h.expectEvents("headers 7 end=false [:status=200] [content-type=text/plain] [content-length=13] [date]\ndata 7 len=13 end=true\nrst 7 no_error\n");
    try wsSend(h, 7, .text, "ignored", false);
    try h.expectEvents("");
    try h.expectLog("CONNECT /other [host=example.com]\n");
    try testing.expectEqualStrings("", h.handler.ws_log.items);
}

test "WebSocket over HTTP/2: echo, ping, the close handshake both ways, END_STREAM, RST_STREAM, errors" {
    const h = try Harness.init(.{ .enable_connect_protocol = true });
    defer h.deinit();
    try h.preface();
    h.events.clearRetainingCapacity();
    try connectWs(h, 1, "/ws");
    // 200 without END_STREAM or content-length.
    try h.expectEvents("headers 1 end=false [:status=200] [date]\n");
    try h.expectLog("CONNECT /ws [host=example.com]\n");
    try wsSend(h, 1, .text, "hello", false);
    try wsSend(h, 1, .ping, "p", false);
    try h.expectEvents("data 1 len=7 end=false\ndata 1 len=3 end=false\n");
    try testing.expectEqualSlices(u8, "\x81\x05hello\x8a\x01p", h.data_out.items);
    // The client's close is echoed, then END_STREAM, then RST_STREAM
    // (NO_ERROR): the client's side is still open.
    try wsSend(h, 1, .close, "\x03\xe8", false);
    try h.expectEvents("data 1 len=4 end=false\ndata 1 len=0 end=true\nrst 1 no_error\n");
    try testing.expectEqualStrings("open;text:hello;ping:p;close:\x03\xe8;gone;", h.handler.ws_log.items);
    h.handler.ws_log.clearRetainingCapacity();
    h.data_out.clearRetainingCapacity();

    // Our close waits for the client's (with a deadline), dropping data
    // meanwhile; the client's close with END_STREAM ends the stream.
    try connectWs(h, 3, "/ws");
    try wsSend(h, 3, .text, "close-me", false);
    try h.expectEvents("headers 3 end=false [:status=200] [date]\ndata 3 len=7 end=false\n");
    try testing.expectEqualSlices(u8, "\x88\x05\x03\xe8bye", h.data_out.items);
    try testing.expect(h.slab.entry(h.conn.findStream(3).?.exchange).tunnel_timed);
    try wsSend(h, 3, .text, "late", false);
    try h.expectEvents("");
    try wsSend(h, 3, .close, "\x03\xe8", true);
    try h.expectEvents("data 3 len=0 end=true\n");
    try testing.expectEqualStrings("open;text:close-me;close:\x03\xe8;gone;", h.handler.ws_log.items);
    h.handler.ws_log.clearRetainingCapacity();
    h.data_out.clearRetainingCapacity();

    // END_STREAM without a close frame is a TCP FIN: we end ours.
    try connectWs(h, 5, "/ws");
    try h.data(5, "", true);
    try h.expectEvents("headers 5 end=false [:status=200] [date]\ndata 5 len=0 end=true\n");
    // RST_STREAM is a TCP RST.
    try connectWs(h, 7, "/ws");
    try h.rst(7, .cancel);
    try h.expectEvents("headers 7 end=false [:status=200] [date]\n");
    // A protocol violation (an unmasked frame) fails the WebSocket: 1002.
    try connectWs(h, 9, "/ws");
    try h.data(9, &.{ 0x81, 0x01, 'x' }, false);
    try h.expectEvents("headers 9 end=false [:status=200] [date]\ndata 9 len=4 end=false\ndata 9 len=0 end=true\nrst 9 no_error\n");
    try testing.expectEqualSlices(u8, "\x88\x02\x03\xea", h.data_out.items);
    try testing.expectEqualStrings("open;gone;open;gone;open;gone;", h.handler.ws_log.items);
    try testing.expectEqual(@as(u32, 0), h.conn.activeStreams());
    try testing.expectEqual(@as(usize, 0), h.slab.active_count);
    // END_STREAM on the HEADERS: accepted, then ended at once.
    try h.headers(.{ .stream = 11, .fields = &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/ws" },
        .{ .name = ":authority", .value = "example.com" },
    } });
    try h.expectEvents("headers 11 end=false [:status=200] [date]\ndata 11 len=0 end=true\n");
    try testing.expectEqual(@as(usize, 0), h.slab.active_count);
    // Each WebSocket takes an exchange slot (8 here); with none left, 503.
    var id: u31 = 13;
    while (id < 13 + 2 * 8) : (id += 2) try connectWs(h, id, "/ws");
    h.events.clearRetainingCapacity();
    try connectWs(h, id, "/ws");
    try h.expectEvents("headers 29 end=true [:status=503] [content-length=0] [date]\nrst 29 no_error\n");
    try testing.expectEqual(@as(u32, 8), h.conn.activeStreams());
}

test "WebSocket over HTTP/2: windows hold output, held output holds the client's window, sends from another thread, stalls time out" {
    const h = try Harness.init(.{ .enable_connect_protocol = true, .initial_window_size = 2000 });
    defer h.deinit();
    try h.preface();
    try h.settings(&.{.{ .id = .initial_window_size, .value = 300 }});
    h.events.clearRetainingCapacity();
    try connectWs(h, 1, "/ws");
    // 1004 bytes queued, 300 allowed.
    try wsSend(h, 1, .text, "big", false);
    try h.expectEvents("headers 1 end=false [:status=200] [date]\ndata 1 len=300 end=false\n");
    // With output held back, input isn't credited: 1017 bytes are past
    // half our window, yet no WINDOW_UPDATE. The echo queues behind.
    const msg: [1000]u8 = @splat('m');
    try wsSend(h, 1, .binary, &msg, false);
    try h.expectEvents("");
    // Window: the rest, the echo, then our window comes back.
    try h.window(1, 5000);
    try h.expectEvents("data 1 len=704 end=false\ndata 1 len=1004 end=false\nwindow 1 +1017\n");
    // A send from another thread goes through the mailbox.
    const t = try std.Thread.spawn(.{}, struct {
        fn run(c: *ws.Conn) void {
            c.sendText("from elsewhere") catch unreachable;
        }
    }.run, .{h.handler.ws_conn.?});
    t.join();
    try h.drainMailbox();
    try h.collect();
    try h.expectEvents("data 1 len=16 end=false\n");
    try testing.expect(std.mem.endsWith(u8, h.data_out.items, "\x81\x0efrom elsewhere"));
    // A stream whose output waits on a zero window is reset after the
    // request timeout; the other goes on.
    try connectWs(h, 3, "/ws");
    try wsSend(h, 3, .text, "big", false);
    try h.expectEvents("headers 3 end=false [:status=200] [date]\ndata 3 len=300 end=false\n");
    try testing.expect(h.slab.entry(h.conn.findStream(3).?.exchange).tunnel_timed);
    try h.tick(11);
    try h.expectEvents("rst 3 cancel\n");
    try testing.expectEqual(@as(u32, 1), h.conn.activeStreams());
    try testing.expectEqual(@as(usize, 1), h.slab.active_count);
    try testing.expect(std.mem.endsWith(u8, h.handler.ws_log.items, "open;text:big;gone;"));
}

test "0-RTT: in early data, safe methods are handled and others get 425 Too Early" {
    const h = try Harness.init(.{});
    defer h.deinit();
    h.early_data = true;
    try h.preface();
    h.events.clearRetainingCapacity();
    try h.get(1, "/a");
    // A POST with its body to come, and one without a body.
    const post = [_]hpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/echo" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try h.headers(.{ .stream = 3, .end_stream = false, .fields = &post });
    try h.headers(.{ .stream = 5, .fields = &post });
    try h.expectEvents(
        \\headers 1 end=false [:status=200] [content-type=text/plain] [content-length=13] [date]
        \\data 1 len=13 end=true
        \\headers 3 end=true [:status=425] [content-length=0] [date]
        \\rst 3 no_error
        \\headers 5 end=true [:status=425] [content-length=0] [date]
        \\
    );
    try h.expectLog("GET /a [host=example.com] early\n");
    // After the handshake, the same POST is handled.
    h.early_data = false;
    try h.headers(.{ .stream = 7, .fields = &post });
    try h.expectLog("POST /echo [host=example.com]\n");
}

test "split invariance" {
    const script = try buildScript();
    defer testing.allocator.free(script);
    const ref = try Harness.init(.{ .enable_connect_protocol = true });
    defer ref.deinit();
    try ref.feed(script);
    try testing.expect(ref.per_stream.count() > 3);
    try testing.expect(std.mem.indexOf(u8, ref.handler.bodies.items, "END") != null);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, ref.handler.ws_log.items, "gone;"));
    try testing.expect(std.mem.indexOf(u8, ref.handler.ws_log.items, "binary:") != null);
    var prng = std.Random.DefaultPrng.init(11);
    const random = prng.random();
    for (0..40) |iteration| {
        const h = try Harness.init(.{ .enable_connect_protocol = true });
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
    try testing.expectEqualStrings(a.handler.bodies.items, b.handler.bodies.items);
    try testing.expectEqualStrings(a.handler.ws_log.items, b.handler.ws_log.items);
}

/// A conversation with requests, buffered and streamed bodies, trailers, a
/// rejected request, window updates, pings, settings, two WebSockets, a
/// refused stream and finally a connection error.
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
        const path = if (i % 6 == 0) "/up" else if (i % 3 == 0) "/echo" else if (i == 4) "/reject" else if (i % 3 == 1) "/" else "/big";
        bn += try enc.encode(block[bn..], ":path", path, .{});
        bn += try enc.encode(block[bn..], "x-req", &(@as([3]u8, @splat('a' + @as(u8, @intCast(i))))), .{});
        // Priorities: urgencies 0-7, half incremental; updates for this
        // stream (open) and the next (idle).
        const prio = [_][]const u8{ "u=0", "u=1, i", "u=2", "u=3, i", "u=4", "u=5, i", "u=6", "u=7, i" };
        if (i % 4 != 3) bn += try enc.encode(block[bn..], "priority", prio[i % 8], .{});
        if (i % 5 == 1) {
            n = try frame.writePriorityUpdate(&buf, stream + 2, prio[(i + 3) % 8]);
            try s.appendSlice(a, buf[0..n]);
        }
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
        if (i % 4 == 1) {
            n = try frame.writePriorityUpdate(&buf, stream, prio[(i + 5) % 8]);
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
    // WebSockets: frames split across DATA frames, a message larger than
    // a read buffer, fragments with a ping between; one closed by the
    // client, one by the server.
    var wsbuf: [4096]u8 = undefined;
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(a);
    const key = [4]u8{ 9, 8, 7, 6 };
    for ([_]u31{ stream, stream + 2 }) |ws_stream| {
        var bn: usize = 0;
        for ([_][2][]const u8{ .{ ":method", "CONNECT" }, .{ ":protocol", "websocket" }, .{ ":scheme", "https" }, .{ ":path", "/ws" }, .{ ":authority", "x" } }) |f|
            bn += try enc.encode(block[bn..], f[0], f[1], .{});
        n = try frame.writeHeaders(&buf, ws_stream, frame.flag.end_headers, block[0..bn]);
        try s.appendSlice(a, buf[0..n]);
    }
    wire.clearRetainingCapacity();
    try wire.appendSlice(a, ws_protocol.encodeFrame(&wsbuf, true, .text, "hello", key));
    try wire.appendSlice(a, ws_protocol.encodeFrame(&wsbuf, false, .text, "frag", key));
    try wire.appendSlice(a, ws_protocol.encodeFrame(&wsbuf, true, .ping, "pp", key));
    try wire.appendSlice(a, ws_protocol.encodeFrame(&wsbuf, true, .continuation, "mented", key));
    const big: [3000]u8 = @splat('w');
    try wire.appendSlice(a, ws_protocol.encodeFrame(&wsbuf, true, .binary, &big, key));
    for ([_][2]usize{ .{ 0, 7 }, .{ 7, 1500 }, .{ 1500, wire.items.len } }) |r| {
        n = try frame.writeData(&wsbuf, stream, false, wire.items[r[0]..r[1]]);
        try s.appendSlice(a, wsbuf[0..n]);
    }
    n = try frame.writeData(&buf, stream + 2, false, ws_protocol.encodeFrame(&wsbuf, true, .text, "close-me", key));
    try s.appendSlice(a, buf[0..n]);
    n = try frame.writeData(&buf, stream, false, ws_protocol.encodeFrame(&wsbuf, true, .close, "\x03\xe8", key));
    try s.appendSlice(a, buf[0..n]);
    n = try frame.writeData(&buf, stream + 2, true, ws_protocol.encodeFrame(&wsbuf, true, .close, "\x03\xe8", key));
    try s.appendSlice(a, buf[0..n]);
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
    const opts: Options = .{ .limits = .{ .max_header_bytes = 2048, .max_body_size = 1024 }, .out_limit = 4096, .max_concurrent_streams = 8, .enable_connect_protocol = true, .websocket = .{ .max_message_size = 4096, .max_send_queue_bytes = 8192 } };
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
    try std.testing.fuzz({}, fuzzConn, .{
        .corpus = &.{
            script[frame.preface.len + frame.header_len ..],
            &[_]u8{ 0, 0, 5, 1, 5, 0, 0, 0, 1, 0x82, 0x87, 0x84, 0x41, 0x00 },
            &[_]u8{ 0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 },
            // Found by the fuzzer.
            @embedFile("testdata/fuzz/split-1.bin"),
        },
    });
}
