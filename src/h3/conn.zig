//! One HTTP/3 connection (RFC 9114) over a QUIC connection, independent of
//! the I/O model. After the worker has fed datagrams to the QUIC
//! connection, `process` drains its stream events: the peer's control and
//! QPACK streams are checked, request streams are parsed into HEADERS and
//! DATA frames and answered through the same handler API as HTTP/1.1 and
//! HTTP/2. Synchronous responses are written into the QUIC stream's send
//! buffer when handleRequest returns; `later()` and `stream()` exchanges
//! are drained as the stream's unacknowledged data allows.
//!
//! QPACK uses the static table only (see qpack.zig). Server push is never
//! used; extended CONNECT (RFC 9220) and DATAGRAM are not yet supported.
const std = @import("std");
const quic = @import("../quic/conn.zig");
const packet = @import("../quic/packet.zig");
const frame = @import("./frame.zig");
const qpack = @import("./qpack.zig");
const fields_mod = @import("../http/fields.zig");
const parser = @import("../http/parser.zig");
const date = @import("../http/date.zig");
const exchange = @import("../http/exchange.zig");
const Request = @import("../request.zig").Request;
const Header = @import("../header.zig").Header;
const Response = @import("../response.zig").Response;
const Status = @import("../status.zig").Status;
const Fields = fields_mod.Fields;
const ErrorCode = frame.ErrorCode;
const Allocator = std.mem.Allocator;

const NIL: u32 = std.math.maxInt(u32);

/// A QPACK prefixed integer from a stream: null if it isn't all there yet,
/// an error if it overflows (where HPACK's decoder can't tell the two
/// apart).
fn qpackInt(data: []const u8, comptime prefix: u4) error{Overflow}!?@import("../h2/hpack.zig").Int {
    if (data.len == 0) return null;
    const r = @import("../h2/hpack.zig").decodeInt(data, prefix) catch {
        // Complete (a byte without the continuation bit after the first)
        // yet undecodable, or five continuation bytes and still going:
        // too large either way.
        for (data[1..@min(data.len, 6)]) |b| if (b & 0x80 == 0) return error.Overflow;
        return if (data.len >= 6) error.Overflow else null;
    };
    return r;
}

pub const Options = struct {
    limits: parser.Limits = .{},
    qpack: qpack.Limits = .{},
    /// Unacknowledged response bytes per stream before an exchange stops
    /// being drained (it resumes as acknowledgements arrive).
    stream_buffer: usize = 1024 * 1024,
    /// Largest control stream frame accepted (SETTINGS and friends).
    max_control_frame: usize = 4096,
};

/// Everything `process` needs besides the connection.
pub fn Context(comptime Handler: type) type {
    return struct {
        handler: *Handler,
        req: *Request,
        resp: *Response,
        /// The current "date: ...\r\n" line.
        date: *const [date.header_len]u8,
        /// Monotonic seconds (exchange deadlines) and microseconds (QUIC).
        now: u32,
        now_us: u64,
        exchanges: *exchange.Slab,
        /// The worker's slot and generation for this connection, for
        /// exchanges to find their way back.
        conn_slot: u32,
        conn_gen: u32,
    };
}

const UniKind = enum(u8) { unknown, control, qpack_encoder, qpack_decoder, ignored };

const Phase = enum(u8) {
    /// Waiting for the request's HEADERS.
    headers,
    /// DATA frames, or trailing HEADERS.
    body,
    /// After trailers: only unknown frame types may follow.
    trailers_done,
};

const Stream = struct {
    active: bool = false,
    request: bool = false,
    uni: UniKind = .unknown,
    phase: Phase = .headers,
    /// The frame being read, when its payload is consumed piecewise
    /// (DATA, or skipped frames).
    frame_type: frame.FrameType = .data,
    frame_left: u64 = 0,
    /// The control stream's first frame has been read.
    settings_seen: bool = false,
    fields: Fields = .{},
    dispatched: bool = false,
    /// Our response is complete (FIN written or the stream reset).
    responded: bool = false,
    is_head: bool = false,
    head_sent: bool = false,
    exchange: u32 = NIL,
    /// The body goes to the exchange through handleBody as it arrives
    /// (handleHead chose `.stream`). While the handler has paused it, DATA
    /// stays unread in the QUIC stream, so no credit is given for it.
    body_stream: bool = false,
    body_paused: bool = false,

    fn clear(s: *Stream) void {
        s.fields.clear();
        s.* = .{ .fields = s.fields };
    }
};

pub const Conn = struct {
    const Self = @This();

    allocator: Allocator,
    opts: Options,
    quic: *quic.Conn,
    streams: []Stream,
    started: bool = false,
    peer_control: u32 = NIL,
    peer_encoder: u32 = NIL,
    peer_decoder: u32 = NIL,
    control: u32 = NIL,
    peer_settings: ?frame.Settings = null,
    decoder: qpack.Decoder,
    enc_buf: std.ArrayList(u8) = .empty,
    goaway_sent: bool = false,
    /// Requests with this stream ID and above are refused after GOAWAY.
    goaway_id: u64 = 0,
    /// One past the highest request stream ID seen.
    next_request_id: u64 = 0,
    active_requests: u32 = 0,
    failed: bool = false,
    /// Request streams with an exchange (a scan hint for pumping).
    exchanges: u32 = 0,

    pub fn init(allocator: Allocator, opts: Options, q: *quic.Conn) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        const streams = try allocator.alloc(Stream, q.streams.len);
        errdefer allocator.free(streams);
        @memset(streams, .{});
        var decoder = try qpack.Decoder.init(allocator, opts.qpack);
        errdefer decoder.deinit();
        self.* = .{ .allocator = allocator, .opts = opts, .quic = q, .streams = streams, .decoder = decoder };
        try self.enc_buf.ensureTotalCapacity(allocator, 1024);
        return self;
    }

    pub fn deinit(self: *Self) void {
        for (self.streams) |*s| s.fields.deinit(self.allocator);
        self.allocator.free(self.streams);
        self.decoder.deinit();
        self.enc_buf.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// A connection error (§8): CONNECTION_CLOSE with the code.
    fn fail(self: *Self, code: ErrorCode, reason: []const u8, now_us: u64) void {
        if (self.failed) return;
        self.failed = true;
        self.quic.closeApp(@backingInt(code), reason, now_us);
    }

    /// Our control stream, SETTINGS, and the (empty) QPACK streams.
    fn start(self: *Self, now_us: u64) void {
        self.started = true;
        const q = self.quic;
        const control = q.openUni() orelse return self.fail(.stream_creation_error, "no stream credit", now_us);
        const encoder = q.openUni() orelse return self.fail(.stream_creation_error, "no stream credit", now_us);
        const decoder = q.openUni() orelse return self.fail(.stream_creation_error, "no stream credit", now_us);
        self.control = control;
        var buf: [64]u8 = undefined;
        var w: packet.Writer = .{ .buf = &buf };
        w.varint(@backingInt(frame.StreamType.control));
        // SETTINGS: our field section limit; a dynamic table capacity of 0
        // and no blocked streams are the defaults. A reserved setting
        // (0x1f * N + 0x21) keeps peers tolerant of unknown ones.
        var payload: [32]u8 = undefined;
        var pw: packet.Writer = .{ .buf = &payload };
        pw.varint(@backingInt(frame.SettingId.max_field_section_size));
        pw.varint(self.opts.qpack.max_field_section_size);
        pw.varint(0x1f * 7 + 0x21);
        pw.varint(0);
        frame.writeHeader(&w, .settings, pw.pos);
        w.bytes(pw.written());
        q.streamWrite(control, w.written()) catch return self.fail(.internal_error, "", now_us);
        q.streamWrite(encoder, &.{@backingInt(frame.StreamType.qpack_encoder)}) catch return self.fail(.internal_error, "", now_us);
        q.streamWrite(decoder, &.{@backingInt(frame.StreamType.qpack_decoder)}) catch return self.fail(.internal_error, "", now_us);
        for ([_]u32{ control, encoder, decoder }) |slot| {
            self.streams[slot].clear();
            self.streams[slot].active = true;
        }
    }

    /// Begins a graceful shutdown: GOAWAY; requests already received are
    /// answered, the connection closes once they are.
    pub fn shutdown(self: *Self, now_us: u64) void {
        if (self.goaway_sent or self.failed or !self.started) return;
        self.goaway_sent = true;
        self.goaway_id = self.next_request_id;
        var buf: [16]u8 = undefined;
        var w: packet.Writer = .{ .buf = &buf };
        frame.writeHeader(&w, .goaway, packet.varintLen(self.goaway_id));
        w.varint(self.goaway_id);
        self.quic.streamWrite(self.control, w.written()) catch {};
        self.maybeClose(now_us);
    }

    /// After GOAWAY: close once every response, and the GOAWAY itself, has
    /// been acknowledged (CONNECTION_CLOSE would discard unacknowledged
    /// data).
    fn maybeClose(self: *Self, now_us: u64) void {
        if (!self.goaway_sent or self.failed or self.active_requests > 0) return;
        if (self.quic.openRequestStreams() > 0 or self.quic.streamBuffered(self.control) > 0) return;
        self.failed = true;
        self.quic.closeApp(@backingInt(ErrorCode.no_error), "", now_us);
    }

    // -- Events -------------------------------------------------------------

    pub fn process(self: *Self, comptime Handler: type, ctx: *const Context(Handler)) void {
        const q = self.quic;
        if (self.failed) {
            // Drain the events; nothing more is answered.
            while (q.nextEvent()) |_| {}
            return;
        }
        if (!q.isEstablished()) return;
        if (!self.started) {
            self.start(ctx.now_us);
            if (self.failed) return;
        }
        defer self.maybeClose(ctx.now_us);
        while (q.nextEvent()) |e| {
            if (self.failed) continue;
            switch (e) {
                .stream_opened => |slot| self.onOpened(slot, ctx.now_us),
                .stream_readable => |slot| {
                    const s = &self.streams[slot];
                    if (!s.active) continue;
                    if (s.request) self.readRequest(Handler, ctx, slot) else self.readUni(slot, ctx.now_us);
                },
                .stop_sending => |ss| {
                    // The client no longer wants the response: QUIC reset
                    // our side already.
                    const s = &self.streams[ss.slot];
                    if (!s.active) continue;
                    if (!s.request) {
                        // Our control or QPACK streams are critical.
                        if (ss.slot == self.control) self.fail(.closed_critical_stream, "control stream stopped", ctx.now_us);
                        continue;
                    }
                    self.abandon(ctx, ss.slot, null);
                },
                .stream_writable => |slot| {
                    const s = &self.streams[slot];
                    if (s.active and s.exchange != NIL) self.pumpStream(Handler, ctx, slot);
                },
            }
        }
    }

    fn onOpened(self: *Self, slot: u32, now_us: u64) void {
        const q = self.quic;
        const s = &self.streams[slot];
        s.clear();
        s.active = true;
        const id = q.streamId(slot);
        if (q.stream(slot).kind != .client_bidi) return;
        s.request = true;
        self.next_request_id = @max(self.next_request_id, id + 4);
        if (self.goaway_sent and id >= self.goaway_id) {
            // §5.2: not processed; the client may retry it elsewhere.
            q.resetSend(slot, @backingInt(ErrorCode.request_rejected));
            q.stopSending(slot, @backingInt(ErrorCode.request_rejected));
            s.responded = true;
            self.release(slot);
            return;
        }
        self.active_requests += 1;
        _ = now_us;
    }

    /// Frees a non-request stream (the peer's unidirectional ones).
    fn release(self: *Self, slot: u32) void {
        const s = &self.streams[slot];
        if (!s.active) return;
        s.active = false;
        self.quic.releaseStream(slot);
    }

    // -- The peer's unidirectional streams -----------------------------------

    fn readUni(self: *Self, slot: u32, now_us: u64) void {
        const q = self.quic;
        const s = &self.streams[slot];
        while (true) {
            // §6.2.1, RFC 9204 §4.2: critical streams must not close, even
            // with an instruction left unfinished.
            const critical = s.uni == .control or s.uni == .qpack_encoder or s.uni == .qpack_decoder;
            if (q.streamResetCode(slot) != null or (critical and q.streamComplete(slot)))
                return if (critical) self.fail(.closed_critical_stream, "critical stream closed", now_us) else self.release(slot);
            if (q.streamFinished(slot)) return self.release(slot);
            const data = q.streamReadable(slot);
            if (data.len == 0) return;
            switch (s.uni) {
                .unknown => {
                    var r: packet.Reader = .{ .data = data };
                    const t = r.varint() catch return; // wait for the rest
                    q.streamConsume(slot, r.pos);
                    switch (@as(frame.StreamType, @fromBackingInt(t))) {
                        .control => {
                            if (self.peer_control != NIL) return self.fail(.stream_creation_error, "second control stream", now_us);
                            self.peer_control = slot;
                            s.uni = .control;
                        },
                        .qpack_encoder => {
                            if (self.peer_encoder != NIL) return self.fail(.stream_creation_error, "second encoder stream", now_us);
                            self.peer_encoder = slot;
                            s.uni = .qpack_encoder;
                        },
                        .qpack_decoder => {
                            if (self.peer_decoder != NIL) return self.fail(.stream_creation_error, "second decoder stream", now_us);
                            self.peer_decoder = slot;
                            s.uni = .qpack_decoder;
                        },
                        // Only servers push.
                        .push => return self.fail(.stream_creation_error, "push stream from a client", now_us),
                        // Unknown and reserved types (§6.2.3): stop reading.
                        _ => {
                            s.uni = .ignored;
                            q.stopSending(slot, @backingInt(ErrorCode.stream_creation_error));
                        },
                    }
                },
                .control => return self.readControl(slot, now_us),
                .qpack_encoder => {
                    // With a capacity of 0, only "Set Dynamic Table Capacity"
                    // to 0 is valid (RFC 9204 §4.3).
                    var pos: usize = 0;
                    while (pos < data.len) {
                        const b = data[pos];
                        if (b & 0xe0 != 0x20) return self.fail(.qpack_encoder_stream_error, "insert without a table", now_us);
                        const r = (qpackInt(data[pos..], 5) catch return self.fail(.qpack_encoder_stream_error, "table capacity", now_us)) orelse break;
                        if (r.value != 0) return self.fail(.qpack_encoder_stream_error, "table capacity", now_us);
                        pos += r.len;
                    }
                    q.streamConsume(slot, pos);
                    if (pos < data.len) return;
                },
                .qpack_decoder => {
                    // Only Stream Cancellation (01xxxxxx) can be valid: we
                    // never reference a dynamic table to acknowledge.
                    var pos: usize = 0;
                    while (pos < data.len) {
                        const b = data[pos];
                        if (b & 0xc0 != 0x40) return self.fail(.qpack_decoder_stream_error, "nothing to acknowledge", now_us);
                        const r = (qpackInt(data[pos..], 6) catch return self.fail(.qpack_decoder_stream_error, "stream id", now_us)) orelse break;
                        pos += r.len;
                    }
                    q.streamConsume(slot, pos);
                    if (pos < data.len) return;
                },
                .ignored => q.streamConsume(slot, data.len),
            }
        }
    }

    fn readControl(self: *Self, slot: u32, now_us: u64) void {
        const q = self.quic;
        const s = &self.streams[slot];
        while (true) {
            const data = q.streamReadable(slot);
            if (s.frame_left > 0) {
                const n: usize = @intCast(@min(s.frame_left, data.len));
                if (n == 0) break;
                q.streamConsume(slot, n);
                s.frame_left -= n;
                continue;
            }
            const h = frame.parseHeader(data) orelse break;
            const t = h.type;
            if (!s.settings_seen and t != .settings) return self.fail(.missing_settings, "", now_us);
            switch (t) {
                .settings, .goaway, .max_push_id, .cancel_push => {
                    if (h.len > self.opts.max_control_frame) return self.fail(.excessive_load, "control frame too large", now_us);
                    if (data.len < h.size + h.len) break;
                    const payload = data[h.size..][0..@intCast(h.len)];
                    switch (t) {
                        .settings => {
                            if (s.settings_seen) return self.fail(.frame_unexpected, "second SETTINGS", now_us);
                            s.settings_seen = true;
                            self.peer_settings = frame.parseSettings(payload) catch |err| return self.fail(switch (err) {
                                error.Settings => .settings_error,
                                error.Frame => .frame_error,
                            }, "", now_us);
                        },
                        else => {
                            // GOAWAY (a push ID: we never push), MAX_PUSH_ID,
                            // CANCEL_PUSH: one varint each.
                            var r: packet.Reader = .{ .data = payload };
                            _ = r.varint() catch return self.fail(.frame_error, "", now_us);
                            if (r.left() != 0) return self.fail(.frame_error, "", now_us);
                        },
                    }
                    q.streamConsume(slot, h.size + payload.len);
                },
                .data, .headers, .push_promise => return self.fail(.frame_unexpected, "on the control stream", now_us),
                _ => {
                    if (t.reservedH2()) return self.fail(.frame_unexpected, "HTTP/2 frame type", now_us);
                    q.streamConsume(slot, h.size);
                    s.frame_left = h.len;
                },
            }
        }
        if (q.streamResetCode(slot) != null or q.streamComplete(slot))
            self.fail(.closed_critical_stream, "control stream closed", now_us);
    }

    // -- Request streams ---------------------------------------------------------

    fn readRequest(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        const q = self.quic;
        const s = &self.streams[slot];
        if (q.streamResetCode(slot) != null) {
            // The client abandoned the request.
            return self.abandon(ctx, slot, ErrorCode.request_cancelled);
        }
        if (s.responded and !s.dispatched) return;
        const max_body = self.opts.limits.max_body_size;
        while (true) {
            const data = q.streamReadable(slot);
            if (s.frame_left > 0) {
                const n: usize = @intCast(@min(s.frame_left, data.len));
                if (n == 0) break;
                if (s.frame_type == .data and s.body_stream) {
                    if (s.body_paused) return;
                    s.fields.body_received += n;
                    if (s.fields.content_length) |cl| {
                        if (s.fields.body_received > cl) return self.streamError(ctx, slot, .message_error);
                    }
                    // Delivered from the stream's buffer, then consumed.
                    self.deliver(Handler, ctx, slot, data[0..n], null);
                    if (!s.active) return;
                } else if (s.frame_type == .data) {
                    s.fields.appendBody(self.allocator, data[0..n], max_body) catch return self.fail(.internal_error, "", ctx.now_us);
                    if (s.fields.fault == .body_too_large and !s.dispatched) {
                        q.streamConsume(slot, n);
                        return self.dispatch(Handler, ctx, slot);
                    }
                }
                q.streamConsume(slot, n);
                s.frame_left -= n;
                continue;
            }
            const h = frame.parseHeader(data) orelse break;
            switch (h.type) {
                .headers => {
                    if (s.phase == .trailers_done) return self.fail(.frame_unexpected, "HEADERS after trailers", ctx.now_us);
                    if (h.len > self.opts.qpack.max_field_section_size) {
                        if (s.phase == .headers) {
                            // Too large to decode: 431, reading no further.
                            s.fields.fault = .headers_too_large;
                            return self.dispatch(Handler, ctx, slot);
                        }
                        return self.streamError(ctx, slot, .excessive_load);
                    }
                    if (data.len < h.size + h.len) break;
                    const section = data[h.size..][0..@intCast(h.len)];
                    if (s.phase == .headers) {
                        var sink = s.fields.sink(self.allocator);
                        self.decoder.decode(section, &sink) catch |err| switch (err) {
                            error.FieldSectionTooLarge => s.fields.fault = s.fields.fault orelse .headers_too_large,
                            error.OutOfMemory => return self.fail(.internal_error, "", ctx.now_us),
                            else => return self.fail(.qpack_decompression_failed, "", ctx.now_us),
                        };
                        s.fields.endHead(self.allocator) catch return self.fail(.internal_error, "", ctx.now_us);
                        q.streamConsume(slot, h.size + section.len);
                        s.phase = .body;
                        if (@hasDecl(Handler, "handleHead") and s.fields.fault == null) {
                            switch (self.checkHead(Handler, ctx, slot)) {
                                .buffer => {},
                                // The response, then STOP_SENDING if the
                                // body is still to come (§4.1).
                                .reject => return self.respondSync(Handler, ctx, slot),
                                .stream => {
                                    self.startBody(Handler, ctx, slot);
                                    if (!s.active or !s.body_stream) return;
                                    continue;
                                },
                            }
                        }
                        s.fields.limitBody(max_body);
                        if (s.fields.fault) |f| {
                            if (f == .protocol) return self.streamError(ctx, slot, .message_error);
                            // Answer now; the rest of the request is unread.
                            return self.dispatch(Handler, ctx, slot);
                        }
                    } else {
                        var sink = s.fields.trailerSink(self.allocator);
                        self.decoder.decode(section, &sink) catch |err| switch (err) {
                            error.FieldSectionTooLarge => {},
                            error.OutOfMemory => return self.fail(.internal_error, "", ctx.now_us),
                            else => return self.fail(.qpack_decompression_failed, "", ctx.now_us),
                        };
                        q.streamConsume(slot, h.size + section.len);
                        if (sink.fault) return self.streamError(ctx, slot, .message_error);
                        s.phase = .trailers_done;
                    }
                },
                .data => {
                    if (s.phase != .body) return self.fail(.frame_unexpected, "DATA outside a body", ctx.now_us);
                    q.streamConsume(slot, h.size);
                    s.frame_type = .data;
                    s.frame_left = h.len;
                },
                .cancel_push, .settings, .goaway, .max_push_id, .push_promise => return self.fail(.frame_unexpected, "on a request stream", ctx.now_us),
                _ => {
                    if (h.type.reservedH2()) return self.fail(.frame_unexpected, "HTTP/2 frame type", ctx.now_us);
                    q.streamConsume(slot, h.size);
                    s.frame_type = h.type;
                    s.frame_left = h.len;
                },
            }
        }
        if (!q.streamComplete(slot) or (s.dispatched and !s.body_stream) or s.body_paused) return;
        // The request is all here.
        if (s.phase == .headers or s.frame_left > 0 or q.streamReadable(slot).len > 0)
            return self.streamError(ctx, slot, .request_incomplete);
        if (!s.fields.lengthMatches()) return self.streamError(ctx, slot, .message_error);
        if (s.body_stream) return self.deliver(Handler, ctx, slot, "", s.fields.trailers(&ctx.req.headers));
        self.dispatch(Handler, ctx, slot);
    }

    /// handleHead on a complete field section. An unknown method is left
    /// to dispatch (501).
    fn checkHead(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) exchange.BodyMode {
        const s = &self.streams[slot];
        if (!s.fields.fill(ctx.req)) return .buffer;
        s.is_head = ctx.req.method == .HEAD;
        ctx.resp.reset();
        const mode = ctx.handler.handleHead(ctx.req, ctx.resp);
        if (mode == .stream and !@hasDecl(Handler, "handleBody")) return .buffer;
        return mode;
    }

    /// handleHead chose `.stream`: handleRequest runs now with an empty
    /// body. If it takes an exchange, DATA goes to handleBody from here
    /// on; if it answers at once, the body is not read (STOP_SENDING with
    /// H3_NO_ERROR after the response).
    fn startBody(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        const s = &self.streams[slot];
        s.dispatched = true;
        ctx.resp.reset();
        _ = s.fields.fill(ctx.req);
        ctx.handler.handleRequest(ctx.req, ctx.resp);
        if (ctx.resp.mode == .sync) return self.respondSync(Handler, ctx, slot);
        s.body_stream = true;
        self.bindExchange(Handler, ctx, slot);
    }

    /// Calls handleBody; the end turns streaming off.
    fn deliver(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32, chunk: []const u8, end: ?[]const Header) void {
        if (!@hasDecl(Handler, "handleBody")) unreachable;
        const s = &self.streams[slot];
        if (end != null) s.body_stream = false;
        const action = ctx.exchanges.handle(s.exchange).deliverBody(ctx.handler, chunk, end, ctx.now);
        if (end == null and action == .pause) s.body_paused = true;
    }

    /// A stream error: reset both directions with `code`.
    fn streamError(self: *Self, ctx: anytype, slot: u32, code: ErrorCode) void {
        const q = self.quic;
        q.resetSend(slot, @backingInt(code));
        q.stopSending(slot, @backingInt(code));
        self.abandon(ctx, slot, null);
    }

    /// Ends a request without (more of) a response: aborts its exchange,
    /// resets our side with `reset` if given, frees the stream.
    fn abandon(self: *Self, ctx: anytype, slot: u32, reset: ?ErrorCode) void {
        const s = &self.streams[slot];
        if (!s.active) return;
        if (s.exchange != NIL) {
            abortExchange(ctx, s.exchange);
            ctx.exchanges.release(s.exchange);
            s.exchange = NIL;
            self.exchanges -= 1;
        }
        if (reset) |code| {
            if (!s.responded) self.quic.resetSend(slot, @backingInt(code));
        }
        self.endRequest(slot, ctx.now_us);
    }

    fn endRequest(self: *Self, slot: u32, now_us: u64) void {
        const s = &self.streams[slot];
        if (!s.active) return;
        s.responded = true;
        if (s.request) self.active_requests -= 1;
        s.active = false;
        self.quic.releaseStream(slot);
        self.maybeClose(now_us);
    }

    fn abortExchange(ctx: anytype, slot: u32) void {
        const Handler = @TypeOf(ctx.handler.*);
        if (!@hasDecl(Handler, "handleAbort")) return;
        const e = ctx.exchanges.entry(slot);
        e.mutex.lock();
        const in_use = e.state == .later or e.state == .streaming;
        e.mutex.unlock();
        if (in_use) ctx.handler.handleAbort(ctx.exchanges.handle(slot));
    }

    // -- Responses ----------------------------------------------------------------

    fn dispatch(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        const s = &self.streams[slot];
        s.dispatched = true;
        const req = ctx.req;
        const resp = ctx.resp;
        resp.reset();
        if (s.fields.fault) |f| {
            resp.status = switch (f) {
                .protocol => return self.streamError(ctx, slot, .message_error),
                .headers_too_large => .request_header_fields_too_large,
                .not_implemented => .not_implemented,
                .body_too_large => .payload_too_large,
            };
            resp.body = "";
            return self.respondSync(Handler, ctx, slot);
        }
        if (!s.fields.fill(req)) {
            resp.status = .not_implemented;
            return self.respondSync(Handler, ctx, slot);
        }
        s.is_head = req.method == .HEAD;
        ctx.handler.handleRequest(req, resp);
        if (resp.mode != .sync) return self.bindExchange(Handler, ctx, slot);
        self.respondSync(Handler, ctx, slot);
    }

    fn respondSync(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        const resp = ctx.resp;
        const s = &self.streams[slot];
        const code = @backingInt(resp.status);
        const has_body = !s.is_head and code >= 200 and code != 204 and code != 304 and resp.body.len > 0;
        const content_length: ?usize = if (resp.status.allowsContentLength()) resp.body.len else null;
        self.writeHead(ctx, slot, resp.status, resp.headerBytes(), content_length) catch return self.fail(.internal_error, "", ctx.now_us);
        if (has_body) self.writeData(slot, resp.body) catch return self.fail(.internal_error, "", ctx.now_us);
        self.finishResponse(ctx, slot);
    }

    /// FIN on our side; if the request is still arriving, ask the client to
    /// stop (§4.1: a complete response before the complete request).
    fn finishResponse(self: *Self, ctx: anytype, slot: u32) void {
        const q = self.quic;
        q.streamFinish(slot);
        if (!q.streamFinished(slot) and q.streamResetCode(slot) == null)
            q.stopSending(slot, @backingInt(ErrorCode.no_error));
        self.endRequest(slot, ctx.now_us);
    }

    fn writeHead(self: *Self, ctx: anytype, slot: u32, status: Status, lines: []const u8, content_length: ?usize) !void {
        self.enc_buf.clearRetainingCapacity();
        try self.enc_buf.appendSlice(self.allocator, &qpack.section_prefix);
        try self.encodeField(":status", status.toString()[0..3]);
        try fields_mod.forEachLine(lines, self, encodeField);
        if (content_length) |n| {
            var num: [20]u8 = undefined;
            const len = std.fmt.printInt(&num, n, 10, .lower, .{});
            try self.encodeField("content-length", num[0..len]);
        }
        const date_line: []const u8 = ctx.date;
        try self.encodeField("date", date_line[6 .. date_line.len - 2]);
        try self.writeFrame(slot, .headers, self.enc_buf.items);
        self.streams[slot].head_sent = true;
    }

    fn encodeField(self: *Self, name: []const u8, value: []const u8) !void {
        while (true) {
            const n = qpack.encodeField(self.enc_buf.unusedCapacitySlice(), name, value) catch {
                try self.enc_buf.ensureUnusedCapacity(self.allocator, @max(self.enc_buf.capacity, name.len + value.len + 16));
                continue;
            };
            self.enc_buf.items.len += n;
            return;
        }
    }

    fn writeFrame(self: *Self, slot: u32, t: frame.FrameType, payload: []const u8) !void {
        const hlen = frame.headerLen(t, payload.len);
        const buf = try self.quic.streamReserve(slot, hlen + payload.len);
        var w: packet.Writer = .{ .buf = buf };
        frame.writeHeader(&w, t, payload.len);
        w.bytes(payload);
        self.quic.streamCommit(slot, w.pos);
    }

    fn writeData(self: *Self, slot: u32, data: []const u8) !void {
        try self.writeFrame(slot, .data, data);
    }

    // -- Exchanges ------------------------------------------------------------------

    fn bindExchange(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        const resp = ctx.resp;
        const s = &self.streams[slot];
        const ex = resp.exchange;
        const e = ctx.exchanges.entry(ex.slot);
        e.mutex.lock();
        e.conn_slot = ctx.conn_slot;
        e.conn_gen = ctx.conn_gen;
        e.stream_id = slot;
        e.is_head = s.is_head;
        e.bound = true;
        e.head_pending = resp.mode != .stream;
        e.mutex.unlock();
        s.exchange = ex.slot;
        self.exchanges += 1;
        if (resp.mode == .stream) {
            const content_length: ?usize = if (resp.status.allowsContentLength()) resp.content_length else null;
            self.writeHead(ctx, slot, resp.status, resp.headerBytes(), content_length) catch return self.fail(.internal_error, "", ctx.now_us);
        }
        self.pumpStream(Handler, ctx, slot);
    }

    /// Called by the worker for a mailbox post naming this exchange.
    pub fn onExchangePosted(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        const ex_slot = slot;
        const stream_slot = ctx.exchanges.entry(ex_slot).stream_id;
        if (stream_slot >= self.streams.len) return;
        const s = &self.streams[stream_slot];
        if (!s.active or s.exchange != ex_slot) return;
        if (ctx.exchanges.handle(ex_slot).takeResume() and s.body_paused) {
            s.body_paused = false;
            self.readRequest(Handler, ctx, stream_slot);
            if (!s.active or s.exchange != ex_slot) return;
        }
        self.pumpStream(Handler, ctx, stream_slot);
    }

    /// The worker's exchange deadline scan found this exchange expired.
    pub fn onExchangeTimeout(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        const stream_slot = ctx.exchanges.entry(slot).stream_id;
        if (stream_slot >= self.streams.len) return;
        const s = &self.streams[stream_slot];
        if (s.active and s.exchange == slot) self.abandon(ctx, stream_slot, .internal_error);
    }

    /// The worker is closing the connection: tell handlers about live
    /// exchanges and release them.
    pub fn abortAll(self: *Self, ctx: anytype) void {
        for (self.streams) |*s| {
            if (s.active and s.exchange != NIL) {
                abortExchange(ctx, s.exchange);
                ctx.exchanges.release(s.exchange);
                s.exchange = NIL;
                self.exchanges -= 1;
            }
        }
    }

    /// Moves an exchange's queued output into the stream, as far as the
    /// stream's buffer allows.
    fn pumpStream(self: *Self, comptime Handler: type, ctx: *const Context(Handler), slot: u32) void {
        const q = self.quic;
        const s = &self.streams[slot];
        if (s.exchange == NIL or self.failed) return;
        const ex = ctx.exchanges.handle(s.exchange);
        const is_head = s.is_head;
        while (true) {
            const buffered = q.streamBuffered(slot);
            if (buffered >= self.opts.stream_buffer) {
                q.streamWantWritable(slot, self.opts.stream_buffer / 2);
                return;
            }
            var r = exchange.h2Poll(ex, &.{}, ctx.now);
            if (r.aborted) return self.abandon(ctx, slot, .internal_error);
            if (r.head) |h| {
                self.writeHead(ctx, slot, h.status, h.headers, h.content_length) catch return self.fail(.internal_error, "", ctx.now_us);
            }
            if (!s.head_sent) {
                if (r.notify) notifyWritable(Handler, ctx, ex);
                return; // later(): nothing yet
            }
            // Poll straight into a DATA frame reserved in the stream, with
            // a four-byte length (patched below).
            const room = @min(self.opts.stream_buffer - buffered, 64 * 1024);
            const buf = q.streamReserve(slot, 5 + room) catch return self.fail(.internal_error, "", ctx.now_us);
            r = exchange.h2Poll(ex, buf[5..][0..room], ctx.now);
            if (r.aborted) return self.abandon(ctx, slot, .internal_error);
            if (r.n > 0 and !is_head) {
                buf[0] = @backingInt(frame.FrameType.data);
                _ = packet.writeVarintLen(buf[1..], r.n, 4);
                q.streamCommit(slot, 5 + r.n);
            }
            if (r.notify) notifyWritable(Handler, ctx, ex);
            if (r.end) {
                if (r.trailers.len > 0 and !is_head) {
                    self.enc_buf.clearRetainingCapacity();
                    self.enc_buf.appendSlice(self.allocator, &qpack.section_prefix) catch return self.fail(.internal_error, "", ctx.now_us);
                    fields_mod.forEachLine(r.trailers, self, encodeField) catch return self.fail(.internal_error, "", ctx.now_us);
                    self.writeFrame(slot, .headers, self.enc_buf.items) catch return self.fail(.internal_error, "", ctx.now_us);
                }
                ctx.exchanges.release(s.exchange);
                s.exchange = NIL;
                self.exchanges -= 1;
                return self.finishResponse(ctx, slot);
            }
            if (!r.more) return;
        }
    }

    fn notifyWritable(comptime Handler: type, ctx: *const Context(Handler), ex: exchange.Exchange) void {
        if (@hasDecl(Handler, "handleWritable")) ctx.handler.handleWritable(ex);
    }

    pub fn activeRequests(self: *const Self) u32 {
        return self.active_requests;
    }
};
