//! One QUIC connection, server side (RFC 9000, RFC 9001, RFC 9002),
//! independent of the I/O model. The worker hands each datagram for this
//! connection to `recv`, calls `send` to fill datagrams until it returns 0,
//! and calls `onTimeout` at `deadline()`. The application protocol
//! (HTTP/3) reads and writes streams by slot and drains `nextEvent`.
//!
//! Streams live in a fixed array of slots: client-initiated bidirectional
//! (requests), client-initiated unidirectional, and ours (unidirectional).
//! A slot is reused once both directions are finished and the application
//! has released it; frame records name a slot and its generation, so acks
//! and losses for an old stream are ignored.
//!
//! 0-RTT (RFC 9001 §4.6): when the handshake accepts early data, 0-RTT
//! packets open with the client's early key into the application space
//! (shared with 1-RTT, §12.3 of RFC 9000), and streams are read and
//! written before the handshake completes (`inEarlyData`). The early key
//! goes once a 1-RTT packet arrives (RFC 9001 §4.9.3).
//!
//! Not yet: connection migration and NEW_CONNECTION_ID, Retry tokens
//! (the worker's job), pacing, ECN, PMTU discovery, DATAGRAM frames.
const std = @import("std");
const packet = @import("./packet.zig");
const protection = @import("./protection.zig");
const frame = @import("./frame.zig");
const tp = @import("./transport_params.zig");
const recovery = @import("./recovery.zig");
const stream_mod = @import("./stream.zig");
const sent_mod = @import("./sent.zig");
const ranges = @import("./ranges.zig");
const handshake = @import("../tls/handshake.zig");
const tls_errors = @import("../tls/errors.zig");
const Allocator = std.mem.Allocator;
const Keys = protection.Keys;
const PacketKey = protection.PacketKey;
const HeaderKey = protection.HeaderKey;
const Suite = protection.Suite;
const TransportError = frame.TransportError;
const RecvStream = stream_mod.RecvStream;
const SendStream = stream_mod.SendStream;
const Cid = tp.Cid;

pub const Config = struct {
    tls: *const handshake.Config,
    /// Milliseconds; 0 for none.
    max_idle_timeout_ms: u64 = 30_000,
    /// Connection receive window (MAX_DATA increments).
    max_data: u64 = 16 * 1024 * 1024,
    /// Per-stream receive window for request streams.
    max_stream_data_bidi: u64 = 1024 * 1024,
    /// Per-stream receive window for the client's unidirectional streams.
    max_stream_data_uni: u64 = 64 * 1024,
    /// Concurrent client request streams.
    max_streams_bidi: u32 = 100,
    /// Concurrent client unidirectional streams (HTTP/3 needs three).
    max_streams_uni: u32 = 8,
    /// Our unidirectional streams (HTTP/3 opens three).
    local_uni_streams: u32 = 3,
    max_ack_delay_ms: u64 = 25,
    /// Largest UDP payload we send (until PMTU discovery exists).
    max_datagram_size: u16 = 1200,
    congestion: recovery.Algorithm = .cubic,
    /// Length of the connection IDs we issue.
    cid_len: u8 = 8,
    /// Out-of-order CRYPTO data held per encryption level.
    max_crypto_buffer: u64 = 64 * 1024,
};

pub const Space = enum(u2) {
    initial,
    handshake,
    application,

    fn fromLevel(l: handshake.Level) Space {
        return @fromBackingInt(@backingInt(l));
    }

    fn packetType(s: Space) packet.PacketType {
        return switch (s) {
            .initial => .initial,
            .handshake => .handshake,
            .application => .one_rtt,
        };
    }
};

pub const State = enum(u8) { handshake, established, closing, draining, closed };

pub const Event = union(enum) {
    /// New data, the end of the stream, or a reset (see `streamResetCode`).
    stream_readable: u32,
    /// The peer asked us to stop sending (our side was reset with `code`).
    stop_sending: struct { slot: u32, code: u64 },
    /// Unacknowledged data fell below the level `streamWantWritable` set.
    stream_writable: u32,
    /// A client-initiated stream was opened.
    stream_opened: u32,
};

/// What a sent packet carried that may need sending again.
const Rec = union(enum) {
    /// The largest packet number in an ACK frame we sent.
    ack: u64,
    crypto: struct { offset: u64, len: u32 },
    stream: struct { slot: u32, gen: u32, offset: u64, len: u32, fin: bool },
    reset_stream: struct { slot: u32, gen: u32 },
    stop_sending: struct { slot: u32, gen: u32 },
    max_stream_data: struct { slot: u32, gen: u32 },
    max_data,
    max_streams_bidi,
    max_streams_uni,
    handshake_done,
    ping,
};

const Sent = sent_mod.SentPackets(Rec);
const NIL: u32 = std.math.maxInt(u32);
/// ACK ranges tracked per space (older ones are forgotten).
const max_ack_ranges = 32;
/// Packets with ack-eliciting frames received before an ACK is sent.
const ack_eliciting_threshold = 2;
/// Key updates we start after this many packets in one phase (AES-GCM's
/// confidentiality limit is 2^23, RFC 9001 §6.6).
const key_update_packets: u64 = 1 << 22;

const PnSpace = struct {
    rx: ?Keys = null,
    tx: ?Keys = null,
    discarded: bool = false,
    // Receiving.
    largest_rx: ?u64 = null,
    largest_rx_time: u64 = 0,
    rx_ranges: ranges.RangeSet = .{},
    /// Packets below this are treated as duplicates (ranges forgotten).
    rx_floor: u64 = 0,
    ack_eliciting_unacked: u32 = 0,
    /// Any packet received since our last ACK (for piggybacking).
    ack_wanted: bool = false,
    ack_deadline: ?u64 = null,
    // Sending.
    sent: Sent = .{},
    largest_acked: ?u64 = null,
    loss_time: ?u64 = null,
    last_ack_eliciting_time: u64 = 0,
    /// Probe packets owed after a PTO.
    probes: u8 = 0,
    crypto_rx: RecvStream = .{},
    crypto_tx: SendStream = .{},

    fn deinit(s: *PnSpace, a: Allocator) void {
        s.rx_ranges.deinit(a);
        s.sent.deinit(a);
        s.crypto_rx.deinit(a);
        s.crypto_tx.deinit(a);
        if (s.rx) |*k| k.wipe();
        if (s.tx) |*k| k.wipe();
    }
};

pub const StreamKind = enum(u8) { client_bidi, client_uni, server_uni };

pub const Stream = struct {
    id: u64 = 0,
    gen: u32 = 0,
    active: bool = false,
    kind: StreamKind = .client_bidi,
    recv: RecvStream = .{},
    send: SendStream = .{},
    /// The peer reset its side (RESET_STREAM) with this code.
    recv_reset: ?u64 = null,
    /// Our reset of the send side: pending, sent, acknowledged.
    reset_code: ?u64 = null,
    reset_sent: bool = false,
    reset_acked: bool = false,
    stop_code: ?u64 = null,
    stop_sent: bool = false,
    max_data_pending: bool = false,
    /// In the send queue.
    queued: bool = false,
    /// A readable event is pending.
    readable_queued: bool = false,
    /// Emit stream_writable once unacknowledged bytes fall to this.
    writable_at: ?usize = null,
    released: bool = false,
    /// Sending order (RFC 9218 priorities, set by HTTP/3): lower urgency
    /// first; incremental streams of one urgency take turns per packet.
    urgency: u3 = 3,
    incremental: bool = false,

    fn hasRecv(s: *const Stream) bool {
        return s.kind != .server_uni;
    }

    fn hasSend(s: *const Stream) bool {
        return s.kind != .client_uni;
    }

    fn recvDone(s: *const Stream) bool {
        return !s.hasRecv() or s.recv_reset != null or s.recv.finished() or s.stop_sent;
    }

    fn sendDone(s: *const Stream) bool {
        if (!s.hasSend()) return true;
        if (s.reset_code != null) return s.reset_acked;
        return s.send.allAcked();
    }

    /// Send queue order: our own streams (HTTP/3 control and QPACK) first,
    /// then by urgency; at one urgency non-incremental streams in stream
    /// order, then incremental ones in the order they were queued.
    fn sendsBefore(a: *const Stream, b: *const Stream) bool {
        const a_ours = a.kind == .server_uni;
        if (a_ours != (b.kind == .server_uni)) return a_ours;
        if (a.urgency != b.urgency) return a.urgency < b.urgency;
        if (a.incremental != b.incremental) return !a.incremental;
        return !a.incremental and a.id < b.id;
    }

    fn sharesWith(a: *const Stream, b: *const Stream) bool {
        return a.incremental and b.incremental and a.urgency == b.urgency and a.kind == b.kind;
    }
};

/// Where a client request stream ID stands.
pub const RequestStream = union(enum) {
    open: u32,
    /// Not opened yet, within the stream limit.
    idle,
    closed,
    /// Beyond the limit we advertised.
    over_limit,
};

pub const Conn = struct {
    const Self = @This();

    allocator: Allocator,
    cfg: *const Config,
    state: State = .handshake,
    hs: ?*handshake.Handshake = null,

    /// Our connection ID (sequence 0) and its stateless reset token.
    scid: Cid,
    reset_token: [16]u8,
    /// The client's: what we send to.
    dcid: Cid,
    /// The client's first Destination Connection ID.
    odcid: Cid,
    retry_scid: ?Cid = null,

    spaces: [3]PnSpace = .{ .{}, .{}, .{} },
    /// 1-RTT receive keys: the previous phase (for reordered packets), the
    /// current and the next. Header keys are in spaces[2].rx.
    rx_prev: ?PacketKey = null,
    rx_next: ?PacketKey = null,
    rx_secret: [protection.max_hash_len]u8 = @splat(0),
    rx_phase: u1 = 0,
    /// The first packet number received in the current phase.
    rx_phase_start: u64 = 0,
    prev_keys_until: ?u64 = null,
    tx_secret: [protection.max_hash_len]u8 = @splat(0),
    tx_phase: u1 = 0,
    tx_phase_packets: u64 = 0,
    /// The first packet number sent in the current phase; a key update may
    /// start once one of them is acknowledged.
    tx_phase_start: u64 = 0,
    tx_phase_acked: bool = true,
    suite: Suite = .aes_128_gcm_sha256,

    our_params_buf: [tp.max_encoded_len]u8 = undefined,
    peer: tp.Params = .{},
    handshake_complete: bool = false,
    /// The client's 0-RTT key, while 0-RTT packets may still come.
    zero_rtt_rx: ?Keys = null,
    handshake_done_pending: bool = false,
    address_validated: bool = false,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
    max_datagram: u16,

    rtt: recovery.Rtt = .{},
    cc: recovery.Congestion,
    pto_count: u32 = 0,
    loss_timer: ?u64 = null,
    last_activity: u64,
    /// An ack-eliciting packet was sent since the last receipt (idle timer).
    sent_since_rx: bool = false,

    // Streams.
    streams: []Stream,
    stream_map: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    free_slots: std.ArrayList(u32) = .empty,
    /// Client streams opened so far, and the limits we advertised.
    bidi_opened: u64 = 0,
    uni_opened: u64 = 0,
    bidi_closed: u64 = 0,
    uni_closed: u64 = 0,
    max_bidi: u64,
    max_uni: u64,
    max_streams_bidi_pending: bool = false,
    max_streams_uni_pending: bool = false,
    /// Our unidirectional streams opened, and the peer's limit.
    local_uni_opened: u64 = 0,
    peer_max_uni: u64 = 0,
    send_queue: std.ArrayList(u32) = .empty,
    events: std.ArrayList(Event) = .empty,
    event_pos: usize = 0,

    // Connection flow control.
    rx_max_data: u64,
    rx_highest: u64 = 0,
    rx_consumed: u64 = 0,
    max_data_pending: bool = false,
    tx_max_data: u64 = 0,
    tx_data: u64 = 0,

    // Closing.
    close_code: u64 = 0,
    close_app: bool = false,
    close_frame_type: u64 = 0,
    close_reason: []const u8 = "",
    close_pending: bool = false,
    close_deadline: u64 = 0,
    /// CONNECTION_CLOSE packets owed in reply to packets received while
    /// closing (rate limit).
    close_resends: u32 = 0,

    negotiated_alpn: ?[]const u8 = null,
    /// A PATH_CHALLENGE to answer.
    path_response: ?[8]u8 = null,
    lost_packets: u64 = 0,
    packets_received: u64 = 0,

    pub const InitOptions = struct {
        /// The client's Initial: its DCID, SCID.
        odcid: []const u8,
        client_scid: []const u8,
        /// Our connection ID (cfg.cid_len bytes) and its reset token.
        scid: []const u8,
        reset_token: [16]u8,
        /// When the worker validated the address with a Retry: the SCID of
        /// that Retry (the client's current DCID).
        retry_scid: ?[]const u8 = null,
        entropy: *const [handshake.entropy_len]u8,
        now: u64,
    };

    pub fn init(allocator: Allocator, cfg: *const Config, opts: InitOptions) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        const total = cfg.max_streams_bidi + cfg.max_streams_uni + cfg.local_uni_streams;
        const streams = try allocator.alloc(Stream, total);
        errdefer allocator.free(streams);
        @memset(streams, .{});
        self.* = .{
            .allocator = allocator,
            .cfg = cfg,
            .scid = .init(opts.scid),
            .reset_token = opts.reset_token,
            .dcid = .init(opts.client_scid),
            .odcid = .init(opts.odcid),
            .retry_scid = if (opts.retry_scid) |r| Cid.init(r) else null,
            .max_datagram = cfg.max_datagram_size,
            .cc = .init(cfg.max_datagram_size, cfg.congestion),
            .last_activity = opts.now,
            .streams = streams,
            .max_bidi = cfg.max_streams_bidi,
            .max_uni = cfg.max_streams_uni,
            .rx_max_data = cfg.max_data,
            // A Retry already proved the address.
            .address_validated = opts.retry_scid != null,
        };
        errdefer self.freeAll();
        try self.free_slots.ensureTotalCapacity(allocator, total);
        var i = total;
        while (i > 0) {
            i -= 1;
            self.free_slots.appendAssumeCapacity(i);
        }
        try self.stream_map.ensureTotalCapacity(allocator, total);
        try self.send_queue.ensureTotalCapacity(allocator, total);
        try self.events.ensureTotalCapacity(allocator, 2 * total);
        // The Initial keys come from the client's first DCID (the original
        // one, even after a Retry: RFC 9001 §5.2 uses the current DCID).
        const initial_dcid = if (opts.retry_scid) |r| r else opts.odcid;
        var secrets = protection.initialSecrets(initial_dcid);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&secrets));
        self.spaces[0].rx = .init(.aes_128_gcm_sha256, &secrets.client);
        self.spaces[0].tx = .init(.aes_128_gcm_sha256, &secrets.server);
        for (&self.spaces) |*s| {
            s.crypto_rx.reset(0);
            s.crypto_tx.reset(std.math.maxInt(u64));
        }
        const hs = try allocator.create(handshake.Handshake);
        hs.* = .init(allocator, cfg.tls, opts.entropy);
        self.hs = hs;
        return self;
    }

    fn freeAll(self: *Self) void {
        const a = self.allocator;
        if (self.hs) |hs| {
            hs.deinit();
            a.destroy(hs);
            self.hs = null;
        }
        for (&self.spaces) |*s| s.deinit(a);
        for (self.streams) |*s| {
            s.recv.deinit(a);
            s.send.deinit(a);
        }
        a.free(self.streams);
        self.stream_map.deinit(a);
        self.free_slots.deinit(a);
        self.send_queue.deinit(a);
        self.events.deinit(a);
        if (self.rx_prev) |*k| k.wipe();
        if (self.rx_next) |*k| k.wipe();
        if (self.zero_rtt_rx) |*k| k.wipe();
        std.crypto.secureZero(u8, &self.rx_secret);
        std.crypto.secureZero(u8, &self.tx_secret);
    }

    pub fn deinit(self: *Self) void {
        self.freeAll();
        self.allocator.destroy(self);
    }

    pub fn isClosed(self: *const Self) bool {
        return self.state == .closed;
    }

    /// The handshake completed (1-RTT data flows).
    pub fn isEstablished(self: *const Self) bool {
        return self.state == .established;
    }

    /// 0-RTT was accepted and the handshake isn't complete: stream data
    /// read now may be a replay (RFC 9001 §9.2).
    pub fn inEarlyData(self: *const Self) bool {
        const hs = self.hs orelse return false;
        return hs.early_accepted and self.state == .handshake;
    }

    /// Negotiated ALPN protocol.
    pub fn alpn(self: *const Self) ?[]const u8 {
        return if (self.hs) |hs| hs.alpn else self.negotiated_alpn;
    }

    // -- Closing --------------------------------------------------------------

    /// Closes with a transport error (CONNECTION_CLOSE 0x1c).
    pub fn closeTransport(self: *Self, code: TransportError, frame_type: u64, reason: []const u8, now: u64) void {
        self.startClose(@backingInt(code), false, frame_type, reason, now);
    }

    /// Closes with an application error (CONNECTION_CLOSE 0x1d).
    pub fn closeApp(self: *Self, code: u64, reason: []const u8, now: u64) void {
        self.startClose(code, true, 0, reason, now);
    }

    fn startClose(self: *Self, code: u64, app: bool, frame_type: u64, reason: []const u8, now: u64) void {
        if (self.state == .closing or self.state == .draining or self.state == .closed) return;
        self.close_code = code;
        self.close_app = app;
        self.close_frame_type = frame_type;
        self.close_reason = reason;
        self.close_pending = true;
        self.state = .closing;
        self.close_deadline = now + 3 * self.rtt.pto(self.peerMaxAckDelay());
    }

    fn fail(self: *Self, code: TransportError, frame_type: u64, now: u64) void {
        self.closeTransport(code, frame_type, "", now);
    }

    fn peerMaxAckDelay(self: *const Self) u64 {
        return self.peer.max_ack_delay * 1000;
    }

    // -- Receiving ------------------------------------------------------------

    /// Processes one datagram (its packets are decrypted in place).
    /// Returns whether any packet in it was authenticated, for the worker
    /// to trust its source address.
    pub fn recv(self: *Self, datagram: []u8, now: u64) bool {
        if (self.state == .closed or self.state == .draining) return false;
        self.bytes_received += datagram.len;
        if (self.state == .closing) {
            // Answer with our CONNECTION_CLOSE again, at a bounded rate.
            if (self.close_resends < 8) {
                self.close_resends += 1;
                self.close_pending = true;
            }
            return false;
        }
        const before = self.packets_received;
        var rest = datagram;
        var first_dcid: ?[]const u8 = null;
        while (rest.len > 0) {
            const h = packet.parseHeader(rest, self.cfg.cid_len) catch break;
            const pkt = rest[0..h.len];
            rest = rest[h.len..];
            // §12.2: coalesced packets share the DCID; others are dropped.
            if (first_dcid) |d| {
                if (!std.mem.eql(u8, d, h.dcid)) continue;
            } else first_dcid = h.dcid;
            self.recvPacket(h, pkt, now);
            if (self.state == .closing or self.state == .draining or self.state == .closed) break;
        }
        return self.packets_received != before;
    }

    fn recvPacket(self: *Self, h: packet.Header, pkt: []u8, now: u64) void {
        const space: Space = switch (h.type) {
            .initial => .initial,
            .handshake => .handshake,
            // 0-RTT and 1-RTT share the application space.
            .one_rtt, .zero_rtt => .application,
            else => return,
        };
        const sp = &self.spaces[@backingInt(space)];
        if (sp.discarded) return;
        // 0-RTT: only with the early key (accepted, and not yet dropped).
        const keys = if (h.type == .zero_rtt) self.zero_rtt_rx orelse return else sp.rx orelse return;
        const pn_info = keys.header.unprotect(pkt, h.pn_offset) catch return;
        const pn = packet.decodePn(sp.largest_rx, pn_info.truncated, pn_info.len);
        const header_len = h.pn_offset + pn_info.len;

        var key: *const PacketKey = &keys.packet;
        var phase_change = false;
        if (h.type == .one_rtt) {
            const phase: u1 = @intCast((pkt[0] >> 2) & 1);
            if (phase != self.rx_phase) {
                if (pn < self.rx_phase_start) {
                    key = if (self.rx_prev) |*p| p else return;
                } else {
                    key = if (self.rx_next) |*n| n else return;
                    phase_change = true;
                }
            }
        }
        const payload = key.open(pkt, header_len, pn) catch return;
        // Reserved bits must be zero once protection is removed (§17.2).
        const reserved: u8 = if (h.type == .one_rtt) 0x18 else 0x0c;
        if (pkt[0] & reserved != 0) return self.fail(.protocol_violation, 0, now);
        if (pn < sp.rx_floor or sp.rx_ranges.contains(pn)) return; // duplicate
        self.packets_received += 1;
        if (phase_change) self.commitKeyUpdate(pn, now);
        if (h.type == .one_rtt) {
            // The client has 1-RTT keys: no more 0-RTT (§4.9.3 allows a
            // short wait for reordered ones; they would be retransmitted).
            if (self.zero_rtt_rx) |*k| k.wipe();
            self.zero_rtt_rx = null;
        }

        if (space == .handshake and !self.spaces[0].discarded) {
            // RFC 9001 §4.9.1; and a Handshake packet proves the address.
            self.address_validated = true;
            self.discardSpace(.initial);
        }
        if (space == .initial and h.type == .initial) {
            // A client that saw our Initial switched to our SCID; until then
            // it may resend with its original DCID.
        }

        var r: packet.Reader = .{ .data = payload };
        var ack_eliciting = false;
        if (payload.len == 0) return self.fail(.protocol_violation, 0, now);
        while (r.left() > 0) {
            switch (frame.parse(&r)) {
                .failure => |f| return self.fail(f.code, f.frame_type, now),
                .frame => |f| {
                    if (!frame.allowed(f, h.type)) return self.fail(.protocol_violation, frameTypeOf(f), now);
                    if (frame.ackEliciting(f)) ack_eliciting = true;
                    self.onFrame(space, f, now);
                    if (self.state == .closing or self.state == .draining or self.state == .closed) return;
                },
            }
        }

        // Record the packet for acknowledgement.
        sp.rx_ranges.insert(self.allocator, pn, pn + 1, max_ack_ranges) catch |err| switch (err) {
            error.TooManyRanges => {
                // Forget the oldest range; packets below it count as duplicates.
                const first = sp.rx_ranges.first().?;
                sp.rx_floor = first.end;
                sp.rx_ranges.dropFirst();
                sp.rx_ranges.insert(self.allocator, pn, pn + 1, max_ack_ranges) catch {};
            },
            error.OutOfMemory => return self.fail(.internal_error, 0, now),
        };
        const out_of_order = if (sp.largest_rx) |l| pn < l or pn > l + 1 else false;
        if (sp.largest_rx == null or pn > sp.largest_rx.?) {
            sp.largest_rx = pn;
            sp.largest_rx_time = now;
        }
        sp.ack_wanted = true;
        if (ack_eliciting) {
            sp.ack_eliciting_unacked += 1;
            if (space != .application or out_of_order or sp.ack_eliciting_unacked >= ack_eliciting_threshold) {
                sp.ack_deadline = now;
            } else if (sp.ack_deadline == null) {
                sp.ack_deadline = now + self.cfg.max_ack_delay_ms * 1000;
            }
        }
        self.last_activity = now;
        self.sent_since_rx = false;
    }

    fn frameTypeOf(f: frame.Frame) u64 {
        return switch (f) {
            .padding => 0x00,
            .ping => 0x01,
            .ack => 0x02,
            .reset_stream => 0x04,
            .stop_sending => 0x05,
            .crypto => 0x06,
            .new_token => 0x07,
            .stream => 0x08,
            .max_data => 0x10,
            .max_stream_data => 0x11,
            .max_streams => |m| if (m.bidi) 0x12 else 0x13,
            .data_blocked => 0x14,
            .stream_data_blocked => 0x15,
            .streams_blocked => |s| if (s.bidi) 0x16 else 0x17,
            .new_connection_id => 0x18,
            .retire_connection_id => 0x19,
            .path_challenge => 0x1a,
            .path_response => 0x1b,
            .connection_close => |c| if (c.app) 0x1d else 0x1c,
            .handshake_done => 0x1e,
        };
    }

    fn onFrame(self: *Self, space: Space, f: frame.Frame, now: u64) void {
        switch (f) {
            .padding, .ping => {},
            .ack => |ack| self.onAck(space, ack, now),
            .crypto => |c| self.onCrypto(space, c.offset, c.data, now),
            .stream => |s| self.onStream(s, now),
            .reset_stream => |rs| self.onResetStream(rs.id, rs.code, rs.final_size, now),
            .stop_sending => |ss| self.onStopSending(ss.id, ss.code, now),
            .max_data => |m| self.tx_max_data = @max(self.tx_max_data, m),
            .max_stream_data => |m| self.onMaxStreamData(m.id, m.max, now),
            .max_streams => |m| {
                if (!m.bidi) self.peer_max_uni = @max(self.peer_max_uni, m.max);
            },
            .data_blocked, .stream_data_blocked, .streams_blocked => {},
            .new_connection_id => |n| {
                // We hold only the client's first ID (no migration yet), but
                // an ID from a client that uses empty IDs is an error.
                if (self.dcid.len == 0) return self.fail(.protocol_violation, 0x18, now);
                _ = n;
            },
            .retire_connection_id => |seq| {
                // We issued only sequence 0, which is in use.
                if (seq > 0) return self.fail(.protocol_violation, 0x19, now);
            },
            .path_challenge => |data| {
                self.path_response = data;
            },
            .path_response => {},
            .connection_close => {
                self.state = .draining;
                self.close_deadline = now + 3 * self.rtt.pto(self.peerMaxAckDelay());
            },
            .new_token, .handshake_done => unreachable, // filtered by frame.allowed
        }
    }

    // -- CRYPTO and the TLS handshake -------------------------------------

    fn onCrypto(self: *Self, space: Space, offset: u64, data: []const u8, now: u64) void {
        const sp = &self.spaces[@backingInt(space)];
        if (offset + data.len > sp.crypto_rx.read_off + self.cfg.max_crypto_buffer)
            return self.fail(.crypto_buffer_exceeded, 0x06, now);
        _ = sp.crypto_rx.recv(self.allocator, offset, data, false) catch |err| switch (err) {
            error.OutOfMemory => return self.fail(.internal_error, 0x06, now),
            else => return self.fail(.protocol_violation, 0x06, now),
        };
        const readable = sp.crypto_rx.readable();
        if (readable.len == 0) return;
        const hs = self.hs orelse {
            // Post-handshake messages: we never send NewSessionTicket
            // requests, and KeyUpdate is forbidden in QUIC (RFC 9001 §6).
            return self.fail(TransportError.crypto(@backingInt(std.crypto.tls.Alert.Description.unexpected_message)), 0x06, now);
        };
        var sink: TlsSink = .{ .conn = self, .now = now };
        hs.feed(@fromBackingInt(@backingInt(space)), readable, &sink) catch |err| {
            const code: TransportError = switch (err) {
                error.TransportParameter => .transport_parameter_error,
                error.OutOfMemory => .internal_error,
                else => |e| TransportError.crypto(@backingInt(tls_errors.alertFor(@errorCast(e)))),
            };
            return self.fail(code, 0x06, now);
        };
        sp.crypto_rx.consume(readable.len);
        if (hs.isDone()) self.onHandshakeComplete(now);
    }

    fn onHandshakeComplete(self: *Self, now: u64) void {
        _ = now;
        const hs = self.hs.?;
        self.negotiated_alpn = hs.alpn;
        hs.deinit();
        self.allocator.destroy(hs);
        self.hs = null;
        self.handshake_complete = true;
        self.state = .established;
        // RFC 9001 §4.1.2: the server's handshake is confirmed at
        // completion; HANDSHAKE_DONE tells the client.
        self.handshake_done_pending = true;
        self.address_validated = true;
        self.discardSpace(.handshake);
    }

    const TlsSink = struct {
        conn: *Self,
        now: u64,
        pub const Error = error{ OutOfMemory, TransportParameter };

        pub fn handshakeData(self: *TlsSink, level: handshake.Level, bytes: []const u8) Error!void {
            try self.conn.spaces[@backingInt(level)].crypto_tx.write(self.conn.allocator, bytes);
        }

        pub fn changeCipherSpec(_: *TlsSink) Error!void {}

        pub fn writeSecret(self: *TlsSink, level: handshake.Level, suite: Suite, secret: []const u8) Error!void {
            const c = self.conn;
            c.suite = suite;
            c.spaces[@backingInt(level)].tx = .init(suite, secret);
            if (level == .application) @memcpy(c.tx_secret[0..secret.len], secret);
        }

        pub fn readSecret(self: *TlsSink, level: handshake.Level, suite: Suite, secret: []const u8) Error!void {
            const c = self.conn;
            if (level == .early) {
                c.zero_rtt_rx = .init(suite, secret);
                return;
            }
            c.spaces[@backingInt(level)].rx = .init(suite, secret);
            if (level == .application) {
                @memcpy(c.rx_secret[0..secret.len], secret);
                const next = protection.nextSecret(suite, &c.rx_secret);
                c.rx_next = .init(suite, &next);
            }
        }

        pub fn transportParameters(self: *TlsSink, client: []const u8) Error![]const u8 {
            const c = self.conn;
            c.peer = try tp.decodeClient(client);
            // §7.3: the client's initial_source_connection_id must match the
            // SCID of its Initial packets.
            const isc = c.peer.initial_source_connection_id orelse return error.TransportParameter;
            if (!isc.eql(c.dcid.slice())) return error.TransportParameter;
            c.tx_max_data = c.peer.initial_max_data;
            c.peer_max_uni = c.peer.initial_max_streams_uni;
            c.max_datagram = @intCast(@min(c.cfg.max_datagram_size, c.peer.max_udp_payload_size));
            const ours: tp.Params = .{
                .original_destination_connection_id = c.odcid,
                .initial_source_connection_id = c.scid,
                .retry_source_connection_id = c.retry_scid,
                .stateless_reset_token = c.reset_token,
                .max_idle_timeout = c.cfg.max_idle_timeout_ms,
                .initial_max_data = c.cfg.max_data,
                .initial_max_stream_data_bidi_remote = c.cfg.max_stream_data_bidi,
                .initial_max_stream_data_uni = c.cfg.max_stream_data_uni,
                .initial_max_streams_bidi = c.cfg.max_streams_bidi,
                .initial_max_streams_uni = c.cfg.max_streams_uni,
                .max_ack_delay = c.cfg.max_ack_delay_ms,
                .disable_active_migration = true,
            };
            return tp.encodeServer(&c.our_params_buf, &ours);
        }
    };

    /// Drops a packet number space's keys and recovery state (RFC 9002 §6.4).
    fn discardSpace(self: *Self, space: Space) void {
        const sp = &self.spaces[@backingInt(space)];
        if (sp.discarded) return;
        sp.discarded = true;
        var it = sp.sent.iterator();
        while (it.next()) |e| {
            if (e.packet.in_flight) self.cc.onDiscarded(e.packet.size);
            sp.sent.remove(e.packet);
        }
        sp.sent.compact();
        sp.loss_time = null;
        sp.probes = 0;
        sp.ack_deadline = null;
        sp.ack_wanted = false;
        if (sp.rx) |*k| k.wipe();
        if (sp.tx) |*k| k.wipe();
        sp.rx = null;
        sp.tx = null;
        self.pto_count = 0;
    }

    // -- Key updates (RFC 9001 §6) ------------------------------------------

    fn commitKeyUpdate(self: *Self, pn: u64, now: u64) void {
        const sp = &self.spaces[2];
        if (self.rx_prev) |*p| p.wipe();
        self.rx_prev = sp.rx.?.packet;
        sp.rx.?.packet = self.rx_next.?;
        self.rx_secret = protection.nextSecret(self.suite, &self.rx_secret);
        const next = protection.nextSecret(self.suite, &self.rx_secret);
        self.rx_next = .init(self.suite, &next);
        self.rx_phase ^= 1;
        self.rx_phase_start = pn;
        self.prev_keys_until = now + 3 * self.rtt.pto(self.peerMaxAckDelay());
        // Answer a peer-initiated update with our own.
        if (self.tx_phase != self.rx_phase) self.updateTxKeys();
    }

    fn updateTxKeys(self: *Self) void {
        const sp = &self.spaces[2];
        self.tx_secret = protection.nextSecret(self.suite, &self.tx_secret);
        sp.tx.?.packet.wipe();
        sp.tx.?.packet = .init(self.suite, &self.tx_secret);
        self.tx_phase ^= 1;
        self.tx_phase_packets = 0;
        self.tx_phase_start = sp.sent.nextPn();
        self.tx_phase_acked = false;
    }

    // -- ACKs and loss detection (RFC 9002) ---------------------------------

    fn onAck(self: *Self, space: Space, ack: frame.Ack, now: u64) void {
        const sp = &self.spaces[@backingInt(space)];
        if (ack.largest >= sp.sent.nextPn()) return self.fail(.protocol_violation, 0x02, now);
        if (sp.largest_acked == null or ack.largest > sp.largest_acked.?) sp.largest_acked = ack.largest;

        const in_flight_before = self.cc.in_flight;
        var largest_newly: ?u64 = null;
        var largest_time: u64 = 0;
        var any_eliciting = false;
        // Packets below the oldest live one were all resolved already.
        const floor = sp.sent.oldest() orelse return;
        var it = ack.iterator();
        while (it.next()) |rg| {
            if (rg.largest < floor) break;
            var pn = @min(rg.largest, sp.sent.nextPn() - 1);
            const low = @max(rg.smallest, floor);
            while (true) : (pn -= 1) {
                if (sp.sent.get(pn)) |p| {
                    if (largest_newly == null) {
                        largest_newly = pn;
                        largest_time = p.time_sent;
                    }
                    if (p.ack_eliciting) any_eliciting = true;
                    if (space == .application and pn >= self.tx_phase_start) self.tx_phase_acked = true;
                    for (sp.sent.recordsOf(p)) |rec| self.onRecordAcked(space, rec);
                    if (p.in_flight) self.cc.onAcked(p.size, p.time_sent, now, &self.rtt, in_flight_before);
                    sp.sent.remove(p);
                }
                if (pn == low) break;
            }
        }
        if (largest_newly == null) return;
        if (largest_newly.? == ack.largest and any_eliciting) {
            var ack_delay: u64 = 0;
            if (space == .application) {
                ack_delay = ack.delay << @intCast(self.peer.ack_delay_exponent);
                ack_delay = @min(ack_delay, self.peerMaxAckDelay());
            }
            self.rtt.update(now -| largest_time, ack_delay);
        }
        self.detectLoss(space, now);
        self.pto_count = 0;
        sp.sent.compact();
        self.setLossTimer(now);
    }

    fn onRecordAcked(self: *Self, space: Space, rec: Rec) void {
        const a = self.allocator;
        const sp = &self.spaces[@backingInt(space)];
        switch (rec) {
            .ack => |largest| {
                // §13.2.4: no need to acknowledge these again.
                if (largest + 1 > sp.rx_floor) {
                    sp.rx_floor = largest + 1;
                    sp.rx_ranges.removeBelow(sp.rx_floor);
                }
            },
            .crypto => |c| sp.crypto_tx.onAcked(a, c.offset, c.len, false) catch {},
            .stream => |s| {
                const st = self.streamAt(s.slot, s.gen) orelse return;
                st.send.onAcked(a, s.offset, s.len, s.fin) catch {};
                if (st.writable_at) |level| {
                    if (st.send.buffered() <= level) {
                        st.writable_at = null;
                        self.pushEvent(.{ .stream_writable = s.slot });
                    }
                }
                self.maybeFree(s.slot);
            },
            .reset_stream => |s| {
                const st = self.streamAt(s.slot, s.gen) orelse return;
                st.reset_acked = true;
                self.maybeFree(s.slot);
            },
            .stop_sending, .max_stream_data, .max_data, .max_streams_bidi, .max_streams_uni, .handshake_done, .ping => {},
        }
    }

    fn onRecordLost(self: *Self, space: Space, rec: Rec) void {
        const a = self.allocator;
        const sp = &self.spaces[@backingInt(space)];
        switch (rec) {
            .ack, .ping => {},
            .crypto => |c| sp.crypto_tx.onLost(a, c.offset, c.len, false) catch {},
            .stream => |s| {
                const st = self.streamAt(s.slot, s.gen) orelse return;
                if (st.reset_code != null) return;
                st.send.onLost(a, s.offset, s.len, s.fin) catch {};
                self.queueSend(s.slot);
            },
            .reset_stream => |s| {
                const st = self.streamAt(s.slot, s.gen) orelse return;
                if (!st.reset_acked) st.reset_sent = false;
            },
            .stop_sending => |s| {
                const st = self.streamAt(s.slot, s.gen) orelse return;
                if (st.recv_reset == null and !st.recv.complete()) st.stop_sent = false;
            },
            .max_stream_data => |s| {
                const st = self.streamAt(s.slot, s.gen) orelse return;
                if (st.recv_reset == null and st.recv.final_size == null) st.max_data_pending = true;
            },
            .max_data => self.max_data_pending = true,
            .max_streams_bidi => self.max_streams_bidi_pending = true,
            .max_streams_uni => self.max_streams_uni_pending = true,
            .handshake_done => self.handshake_done_pending = true,
        }
    }

    fn detectLoss(self: *Self, space: Space, now: u64) void {
        const sp = &self.spaces[@backingInt(space)];
        const largest_acked = sp.largest_acked orelse return;
        const loss_delay = self.rtt.lossDelay();
        const lost_send_time = now -| loss_delay;
        sp.loss_time = null;
        var lost_any = false;
        var newest_lost_time: u64 = 0;
        var oldest_lost_time: u64 = std.math.maxInt(u64);
        var it = sp.sent.iterator();
        while (it.next()) |e| {
            if (e.pn > largest_acked) break;
            const p = e.packet;
            if (p.time_sent <= lost_send_time or largest_acked >= e.pn + recovery.packet_threshold) {
                for (sp.sent.recordsOf(p)) |rec| self.onRecordLost(space, rec);
                if (p.in_flight) {
                    self.cc.onLost(p.size);
                    lost_any = true;
                    newest_lost_time = @max(newest_lost_time, p.time_sent);
                    if (p.ack_eliciting) oldest_lost_time = @min(oldest_lost_time, p.time_sent);
                }
                sp.sent.remove(p);
                self.lost_packets += 1;
            } else {
                const t = p.time_sent + loss_delay;
                sp.loss_time = if (sp.loss_time) |l| @min(l, t) else t;
            }
        }
        if (lost_any) {
            self.cc.onCongestionEvent(newest_lost_time, now);
            // Persistent congestion (§7.6), approximated by the span of the
            // lost packets.
            if (self.rtt.has_sample and oldest_lost_time != std.math.maxInt(u64)) {
                const duration = (self.rtt.smoothed + @max(4 * self.rtt.variance, recovery.granularity) + self.peerMaxAckDelay()) * recovery.persistent_congestion_threshold;
                if (newest_lost_time - oldest_lost_time > duration) self.cc.onPersistentCongestion();
            }
        }
    }

    fn ackElicitingInFlight(self: *const Self) bool {
        for (&self.spaces) |*sp| if (sp.sent.ack_eliciting_in_flight > 0) return true;
        return false;
    }

    const PtoTime = struct { time: u64, space: Space };

    fn ptoTime(self: *const Self) ?PtoTime {
        var best: ?PtoTime = null;
        const backoff = @as(u64, 1) << @intCast(@min(self.pto_count, 16));
        for (&self.spaces, 0..) |*sp, i| {
            if (sp.sent.ack_eliciting_in_flight == 0) continue;
            const space: Space = @fromBackingInt(@as(u2, @intCast(i)));
            var duration = self.rtt.pto(0) * backoff;
            if (space == .application) {
                if (!self.handshake_complete) continue;
                duration += self.peerMaxAckDelay() * backoff;
            }
            const t = sp.last_ack_eliciting_time + duration;
            if (best == null or t < best.?.time) best = .{ .time = t, .space = space };
        }
        return best;
    }

    fn amplificationBlocked(self: *const Self) bool {
        return !self.address_validated and self.bytes_sent >= 3 * self.bytes_received;
    }

    fn setLossTimer(self: *Self, now: u64) void {
        _ = now;
        for (&self.spaces) |*sp| {
            if (sp.loss_time) |t| {
                if (self.loss_timer == null or t < self.loss_timer.?) self.loss_timer = t;
            }
        }
        var earliest: ?u64 = null;
        for (&self.spaces) |*sp| {
            if (sp.loss_time) |t| earliest = if (earliest) |e| @min(e, t) else t;
        }
        if (earliest) |t| {
            self.loss_timer = t;
            return;
        }
        if (self.amplificationBlocked() or !self.ackElicitingInFlight()) {
            self.loss_timer = null;
            return;
        }
        self.loss_timer = if (self.ptoTime()) |p| p.time else null;
    }

    fn onLossTimeout(self: *Self, now: u64) void {
        // A loss time first.
        var earliest: ?struct { t: u64, s: Space } = null;
        for (&self.spaces, 0..) |*sp, i| {
            if (sp.loss_time) |t| {
                if (earliest == null or t < earliest.?.t) earliest = .{ .t = t, .s = @fromBackingInt(@as(u2, @intCast(i))) };
            }
        }
        if (earliest) |e| {
            self.detectLoss(e.s, now);
            self.spaces[@backingInt(e.s)].sent.compact();
            self.setLossTimer(now);
            return;
        }
        // A probe timeout: send one or two ack-eliciting packets.
        const pto = self.ptoTime() orelse {
            self.loss_timer = null;
            return;
        };
        self.pto_count += 1;
        const sp = &self.spaces[@backingInt(pto.space)];
        sp.probes = 2;
        // Probe with the oldest unacknowledged data, if any.
        var it = sp.sent.iterator();
        while (it.next()) |e| {
            if (!e.packet.ack_eliciting) continue;
            for (sp.sent.recordsOf(e.packet)) |rec| self.onRecordLost(pto.space, rec);
            break;
        }
        self.setLossTimer(now);
        self.loss_timer = null; // re-armed when the probes are sent
    }

    // -- Timers ---------------------------------------------------------------

    fn idleTimeout(self: *const Self) ?u64 {
        const ours = self.cfg.max_idle_timeout_ms;
        const theirs = self.peer.max_idle_timeout;
        var ms = if (ours == 0) theirs else if (theirs == 0) ours else @min(ours, theirs);
        if (ms == 0) {
            // Neither side set one: still bound a connection that never
            // finishes its handshake.
            if (self.handshake_complete) return null;
            ms = 10_000;
        }
        return @max(ms * 1000, 3 * self.rtt.pto(self.peerMaxAckDelay()));
    }

    /// When `onTimeout` should run next, if ever.
    pub fn deadline(self: *const Self) ?u64 {
        if (self.state == .closed) return null;
        if (self.state == .closing or self.state == .draining) return self.close_deadline;
        var t: ?u64 = self.loss_timer;
        if (self.idleTimeout()) |idle| t = min(t, self.last_activity + idle);
        for (&self.spaces) |*sp| {
            if (sp.ack_deadline) |d| {
                if (sp.ack_wanted and !sp.rx_ranges.isEmpty() and !sp.discarded) t = min(t, d);
            }
        }
        if (self.prev_keys_until) |d| t = min(t, d);
        return t;
    }

    fn min(a: ?u64, b: u64) u64 {
        return if (a) |x| @min(x, b) else b;
    }

    pub fn onTimeout(self: *Self, now: u64) void {
        switch (self.state) {
            .closed => return,
            .closing, .draining => {
                if (now >= self.close_deadline) self.state = .closed;
                return;
            },
            else => {},
        }
        if (self.idleTimeout()) |idle| {
            if (now >= self.last_activity + idle) {
                self.state = .closed;
                return;
            }
        }
        if (self.prev_keys_until) |d| {
            if (now >= d) {
                if (self.rx_prev) |*p| p.wipe();
                self.rx_prev = null;
                self.prev_keys_until = null;
            }
        }
        if (self.loss_timer) |t| {
            if (now >= t) {
                self.loss_timer = null;
                self.onLossTimeout(now);
            }
        }
        // ACK deadlines are met by `send`; drop any with nothing to send.
        for (&self.spaces) |*sp| {
            if (sp.ack_deadline != null and (!sp.ack_wanted or sp.rx_ranges.isEmpty() or sp.discarded)) sp.ack_deadline = null;
        }
    }

    // -- Streams --------------------------------------------------------------

    fn streamAt(self: *Self, slot: u32, gen: u32) ?*Stream {
        const s = &self.streams[slot];
        return if (s.active and s.gen == gen) s else null;
    }

    pub fn stream(self: *Self, slot: u32) *Stream {
        return &self.streams[slot];
    }

    fn pushEvent(self: *Self, e: Event) void {
        self.events.append(self.allocator, e) catch {};
    }

    pub fn nextEvent(self: *Self) ?Event {
        if (self.event_pos == self.events.items.len) {
            self.events.clearRetainingCapacity();
            self.event_pos = 0;
            return null;
        }
        const e = self.events.items[self.event_pos];
        self.event_pos += 1;
        if (e == .stream_readable) self.streams[e.stream_readable].readable_queued = false;
        return e;
    }

    fn markReadable(self: *Self, slot: u32) void {
        const s = &self.streams[slot];
        if (s.readable_queued) return;
        s.readable_queued = true;
        self.pushEvent(.{ .stream_readable = slot });
    }

    fn openSlot(self: *Self, id: u64, kind: StreamKind) ?u32 {
        const slot = self.free_slots.pop() orelse return null;
        const s = &self.streams[slot];
        const gen = s.gen;
        s.recv.reset(switch (kind) {
            .client_bidi => self.cfg.max_stream_data_bidi,
            .client_uni => self.cfg.max_stream_data_uni,
            .server_uni => 0,
        });
        s.send.reset(switch (kind) {
            // The client's limit for streams it opened is its "local" one
            // (RFC 9000 §18.2).
            .client_bidi => self.peer.initial_max_stream_data_bidi_local,
            .client_uni => 0,
            .server_uni => self.peer.initial_max_stream_data_uni,
        });
        s.* = .{ .recv = s.recv, .send = s.send, .id = id, .gen = gen, .active = true, .kind = kind };
        self.stream_map.putAssumeCapacity(id, slot);
        return slot;
    }

    /// The slot for a client-initiated stream, opening it (and every lower
    /// stream of its type, §3.2) as needed. null: closed long ago, or a
    /// failure (the connection is closing).
    fn clientStream(self: *Self, id: u64, now: u64) ?u32 {
        if (self.stream_map.get(id)) |slot| return slot;
        const bidi = id & 2 == 0;
        const index = id >> 2;
        const opened = if (bidi) &self.bidi_opened else &self.uni_opened;
        if (index < opened.*) return null; // already closed
        const limit = if (bidi) self.max_bidi else self.max_uni;
        if (index >= limit) {
            self.fail(.stream_limit_error, 0x08, now);
            return null;
        }
        var slot: u32 = NIL;
        while (opened.* <= index) {
            const sid = (opened.* << 2) | (id & 3);
            slot = self.openSlot(sid, if (bidi) .client_bidi else .client_uni) orelse {
                self.fail(.internal_error, 0x08, now);
                return null;
            };
            opened.* += 1;
            self.pushEvent(.{ .stream_opened = slot });
        }
        return slot;
    }

    /// Looks up a stream a frame names. `send_side`: the frame is about our
    /// sending (STOP_SENDING, MAX_STREAM_DATA), else about the peer's.
    fn frameStream(self: *Self, id: u64, send_side: bool, frame_type: u64, now: u64) ?*Stream {
        const server_initiated = id & 1 == 1;
        const uni = id & 2 != 0;
        if (server_initiated) {
            // Our bidirectional streams: we never open any. Our
            // unidirectional streams can't be sent on by the peer.
            if (!uni or !send_side or (id >> 2) >= self.local_uni_opened) {
                self.fail(.stream_state_error, frame_type, now);
                return null;
            }
            const slot = self.stream_map.get(id) orelse return null;
            return &self.streams[slot];
        }
        if (uni and send_side) {
            // The client's unidirectional streams have no sending side here.
            self.fail(.stream_state_error, frame_type, now);
            return null;
        }
        const slot = self.clientStream(id, now) orelse return null;
        return &self.streams[slot];
    }

    fn onStream(self: *Self, f: frame.Stream, now: u64) void {
        const s = self.frameStream(f.id, false, 0x08, now) orelse return;
        if (s.recv_reset != null) return;
        const raised = s.recv.recv(self.allocator, f.offset, f.data, f.fin) catch |err| return self.fail(switch (err) {
            error.FlowControl => .flow_control_error,
            error.FinalSize => .final_size_error,
            error.Fragmented => .protocol_violation,
            error.OutOfMemory => .internal_error,
        }, 0x08, now);
        self.rx_highest += raised;
        if (self.rx_highest > self.rx_max_data) return self.fail(.flow_control_error, 0x08, now);
        if (s.recv.readable().len > 0 or s.recv.complete()) self.markReadable(self.slotOf(s));
    }

    fn slotOf(self: *const Self, s: *const Stream) u32 {
        return @intCast((@intFromPtr(s) - @intFromPtr(self.streams.ptr)) / @sizeOf(Stream));
    }

    fn onResetStream(self: *Self, id: u64, code: u64, final_size: u64, now: u64) void {
        const s = self.frameStream(id, false, 0x04, now) orelse return;
        if (s.recv.final_size) |fs| {
            if (fs != final_size) return self.fail(.final_size_error, 0x04, now);
        }
        if (final_size < s.recv.highest) return self.fail(.final_size_error, 0x04, now);
        if (s.recv_reset != null) return;
        const raised = final_size - s.recv.highest;
        self.rx_highest += raised;
        if (self.rx_highest > self.rx_max_data) return self.fail(.flow_control_error, 0x04, now);
        // Unread bytes no longer hold connection credit.
        self.creditConnection(final_size - s.recv.read_off);
        s.recv.final_size = final_size;
        s.recv_reset = code;
        self.markReadable(self.slotOf(s));
    }

    fn onStopSending(self: *Self, id: u64, code: u64, now: u64) void {
        const s = self.frameStream(id, true, 0x05, now) orelse return;
        const slot = self.slotOf(s);
        // §3.5: answer with RESET_STREAM.
        if (s.reset_code == null and !s.send.allAcked()) {
            self.resetSend(slot, code);
            self.pushEvent(.{ .stop_sending = .{ .slot = slot, .code = code } });
        }
    }

    fn onMaxStreamData(self: *Self, id: u64, max: u64, now: u64) void {
        const s = self.frameStream(id, true, 0x11, now) orelse return;
        if (max > s.send.max_data) {
            s.send.max_data = max;
            if (s.send.hasPending()) self.queueSend(self.slotOf(s));
        }
    }

    fn queueSend(self: *Self, slot: u32) void {
        const s = &self.streams[slot];
        if (s.queued) return;
        s.queued = true;
        self.insertQueued(slot);
    }

    /// Inserts into the send queue at its place.
    fn insertQueued(self: *Self, slot: u32) void {
        const s = &self.streams[slot];
        var j: usize = 0;
        while (j < self.send_queue.items.len and !s.sendsBefore(&self.streams[self.send_queue.items[j]])) j += 1;
        self.send_queue.insertAssumeCapacity(j, slot);
    }

    fn creditConnection(self: *Self, n: u64) void {
        self.rx_consumed += n;
        if (self.rx_max_data - self.rx_consumed < self.cfg.max_data / 2) {
            self.rx_max_data = self.rx_consumed + self.cfg.max_data;
            self.max_data_pending = true;
        }
    }

    /// Frees a slot whose stream is finished both ways and released.
    fn maybeFree(self: *Self, slot: u32) void {
        const s = &self.streams[slot];
        if (!s.active or !s.released or !s.recvDone() or !s.sendDone()) return;
        if (s.queued) return; // freed when it leaves the queue
        _ = self.stream_map.remove(s.id);
        switch (s.kind) {
            .client_bidi => {
                self.bidi_closed += 1;
                const target = self.bidi_closed + self.cfg.max_streams_bidi;
                if (target - self.max_bidi >= @max(1, self.cfg.max_streams_bidi / 4)) {
                    self.max_bidi = target;
                    self.max_streams_bidi_pending = true;
                }
            },
            .client_uni => {
                self.uni_closed += 1;
                const target = self.uni_closed + self.cfg.max_streams_uni;
                if (target > self.max_uni) {
                    self.max_uni = target;
                    self.max_streams_uni_pending = true;
                }
            },
            .server_uni => {},
        }
        s.active = false;
        s.gen +%= 1;
        self.free_slots.appendAssumeCapacity(slot);
    }

    // -- Stream API (for the application) ------------------------------------

    /// Contiguous received bytes not yet consumed.
    pub fn streamReadable(self: *Self, slot: u32) []u8 {
        return self.streams[slot].recv.readable();
    }

    pub fn streamConsume(self: *Self, slot: u32, n: usize) void {
        const s = &self.streams[slot];
        s.recv.consume(n);
        self.creditConnection(n);
        // Raise the stream's window at half.
        const window = if (s.kind == .client_bidi) self.cfg.max_stream_data_bidi else self.cfg.max_stream_data_uni;
        if (s.recv.final_size == null and s.recv.max_data - s.recv.read_off < window / 2) {
            s.recv.max_data = s.recv.read_off + window;
            s.max_data_pending = true;
            self.queueSend(slot);
        }
    }

    /// All data was received and consumed.
    pub fn streamFinished(self: *Self, slot: u32) bool {
        return self.streams[slot].recv.finished();
    }

    /// All data was received (the FIN and everything before it).
    pub fn streamComplete(self: *Self, slot: u32) bool {
        return self.streams[slot].recv.complete();
    }

    /// The peer reset its sending side with this code.
    pub fn streamResetCode(self: *Self, slot: u32) ?u64 {
        return self.streams[slot].recv_reset;
    }

    pub fn streamId(self: *Self, slot: u32) u64 {
        return self.streams[slot].id;
    }

    pub fn streamWrite(self: *Self, slot: u32, data: []const u8) Allocator.Error!void {
        const s = &self.streams[slot];
        if (s.reset_code != null) return;
        try s.send.write(self.allocator, data);
        self.queueSend(slot);
    }

    /// Room in the stream's send buffer to write into directly.
    pub fn streamReserve(self: *Self, slot: u32, n: usize) Allocator.Error![]u8 {
        return self.streams[slot].send.reserve(self.allocator, n);
    }

    pub fn streamCommit(self: *Self, slot: u32, n: usize) void {
        const s = &self.streams[slot];
        s.send.commit(n);
        if (s.reset_code == null) self.queueSend(slot);
    }

    pub fn streamFinish(self: *Self, slot: u32) void {
        const s = &self.streams[slot];
        if (s.reset_code != null or s.send.fin) return;
        s.send.finish();
        self.queueSend(slot);
    }

    /// Client request streams not yet finished both ways (and freed).
    pub fn openRequestStreams(self: *const Self) u64 {
        return self.bidi_opened - self.bidi_closed;
    }

    /// Bytes written and not yet acknowledged.
    pub fn streamBuffered(self: *Self, slot: u32) usize {
        return self.streams[slot].send.buffered();
    }

    /// Ask for a stream_writable event once buffered bytes fall to `level`.
    pub fn streamWantWritable(self: *Self, slot: u32, level: usize) void {
        self.streams[slot].writable_at = level;
    }

    /// Sets the stream's priority, moving it in the send queue.
    pub fn streamSetPriority(self: *Self, slot: u32, urgency: u3, incremental: bool) void {
        const s = &self.streams[slot];
        if (s.urgency == urgency and s.incremental == incremental) return;
        s.urgency = urgency;
        s.incremental = incremental;
        if (!s.queued) return;
        const i = std.mem.indexOfScalar(u32, self.send_queue.items, slot).?;
        _ = self.send_queue.orderedRemove(i);
        self.insertQueued(slot);
    }

    /// Whether the stream has data to send that waits for other streams
    /// (or the congestion window), not for its own or the connection's
    /// flow control limit.
    pub fn streamWaiting(self: *const Self, slot: u32) bool {
        const s = &self.streams[slot];
        return s.queued and s.reset_code == null and s.send.hasPending() and self.tx_data < self.tx_max_data;
    }

    /// Classifies a client-initiated bidirectional stream ID.
    pub fn requestStream(self: *const Self, id: u64) RequestStream {
        std.debug.assert(id & 3 == 0);
        if (self.stream_map.get(id)) |slot| return .{ .open = slot };
        const index = id >> 2;
        if (index < self.bidi_opened) return .closed;
        if (index >= self.max_bidi) return .over_limit;
        return .idle;
    }

    /// Abandons our sending side (RESET_STREAM).
    pub fn resetSend(self: *Self, slot: u32, code: u64) void {
        const s = &self.streams[slot];
        if (!s.hasSend() or s.reset_code != null or s.send.allAcked()) return;
        s.reset_code = code;
        s.send.lost.clear();
        self.queueSend(slot);
    }

    /// Asks the peer to stop sending (STOP_SENDING).
    pub fn stopSending(self: *Self, slot: u32, code: u64) void {
        const s = &self.streams[slot];
        if (!s.hasRecv() or s.stop_code != null or s.recv_reset != null or s.recv.complete()) return;
        s.stop_code = code;
        self.queueSend(slot);
    }

    /// The application is done with the stream; the slot is reused once
    /// both directions are finished.
    pub fn releaseStream(self: *Self, slot: u32) void {
        const s = &self.streams[slot];
        s.released = true;
        // Unread data no longer holds connection credit.
        if (s.hasRecv() and s.recv_reset == null) {
            const unread = s.recv.buffered();
            if (unread > 0) {
                s.recv.consume(unread);
                self.creditConnection(unread);
            }
        }
        self.maybeFree(slot);
    }

    /// Opens one of our unidirectional streams.
    pub fn openUni(self: *Self) ?u32 {
        if (self.local_uni_opened >= self.peer_max_uni) return null;
        const id = (self.local_uni_opened << 2) | 3;
        const slot = self.openSlot(id, .server_uni) orelse return null;
        self.local_uni_opened += 1;
        return slot;
    }

    // -- Sending --------------------------------------------------------------

    /// Fills `out` with the next datagram. Returns its length, 0 when there
    /// is nothing to send now.
    pub fn send(self: *Self, out: []u8, now: u64) usize {
        switch (self.state) {
            .closed, .draining => return 0,
            .closing => return self.sendClose(out, now),
            else => {},
        }
        var max = @min(out.len, self.max_datagram);
        if (!self.address_validated) {
            const budget = 3 * self.bytes_received -| self.bytes_sent;
            if (budget < max) max = @intCast(budget);
        }
        if (max < 64) return 0;
        var b: Builder = .{ .out = out[0..max] };
        var has_initial = false;
        for ([_]Space{ .initial, .handshake, .application }) |space| {
            const sp = &self.spaces[@backingInt(space)];
            if (sp.tx == null or sp.discarded) continue;
            if (b.room() < 64) break;
            const before = b.packets;
            self.buildPacket(&b, space, now) catch |err| switch (err) {
                error.OutOfMemory => {
                    self.fail(.internal_error, 0, now);
                    return 0;
                },
            };
            if (space == .initial and b.packets > before and b.last_eliciting) has_initial = true;
        }
        if (b.packets == 0) return 0;
        // §14.1: datagrams with ack-eliciting Initial packets are padded.
        if (has_initial and b.pos < 1200 and out.len >= 1200 and max >= 1200) b.padTo(1200);
        // A nearly full datagram is padded to the full size, so runs of
        // them are equal and go out as one GSO send.
        if (b.open and b.space == .application and b.pos + protection.tag_len + 64 >= max and b.pos + protection.tag_len < max) b.padTo(max);
        self.sealLast(&b, now);
        self.bytes_sent += b.pos;
        return b.pos;
    }

    /// A datagram under construction: packets are sealed one behind, so the
    /// last one can still be padded.
    const Builder = struct {
        out: []u8,
        pos: usize = 0,
        packets: u32 = 0,
        // The last packet, not yet sealed.
        open: bool = false,
        start: usize = 0,
        pn_offset: usize = 0,
        pn_len: usize = 0,
        pn: u64 = 0,
        long: bool = false,
        space: Space = .initial,
        last_eliciting: bool = false,
        last_in_flight: bool = false,
        rec_mark: u64 = 0,

        fn room(b: *const Builder) usize {
            return b.out.len - b.pos;
        }

        /// Pads the open packet so the sealed datagram is `n` bytes.
        fn padTo(b: *Builder, n: usize) void {
            const end = n - protection.tag_len;
            if (!b.open or b.pos >= end) return;
            @memset(b.out[b.pos..end], 0);
            b.pos = end;
            b.last_in_flight = true;
        }
    };

    fn sealLast(self: *Self, b: *Builder, now: u64) void {
        if (!b.open) return;
        b.open = false;
        const sp = &self.spaces[@backingInt(b.space)];
        // The header protection sample needs 4 bytes after the packet
        // number's start (§5.4.2).
        const min_end = b.pn_offset + 4;
        if (b.pos < min_end) {
            @memset(b.out[b.pos..min_end], 0);
            b.pos = min_end;
        }
        const end = b.pos + protection.tag_len;
        if (b.long) {
            // The Length field (two bytes, reserved) covers the packet
            // number, payload and tag.
            _ = packet.writeVarintLen(b.out[b.pn_offset - 2 ..], end - b.pn_offset, 2);
        }
        const pkt = b.out[b.start..end];
        sp.tx.?.protect(pkt, b.pn_offset - b.start, b.pn_len, b.pn);
        b.pos = end;
        const size: u32 = @intCast(end - b.start);
        sp.sent.add(self.allocator, b.rec_mark, now, size, b.last_eliciting, b.last_in_flight or b.last_eliciting) catch {
            self.fail(.internal_error, 0, now);
            return;
        };
        if (b.last_eliciting or b.last_in_flight) self.cc.onSent(size);
        if (b.last_eliciting) {
            sp.last_ack_eliciting_time = now;
            if (!self.sent_since_rx) {
                self.sent_since_rx = true;
                self.last_activity = now;
            }
            if (sp.probes > 0) sp.probes -= 1;
        }
        if (b.space == .application) self.tx_phase_packets += 1;
        self.setLossTimer(now);
    }

    fn ackDue(sp: *const PnSpace, now: u64) bool {
        return if (sp.ack_deadline) |d| now >= d else false;
    }

    /// Something ack-eliciting to send in this space (ignoring the window).
    fn hasData(self: *Self, space: Space) bool {
        const sp = &self.spaces[@backingInt(space)];
        if (sp.crypto_tx.hasPending()) return true;
        if (space != .application) return false;
        if (self.handshake_done_pending or self.max_data_pending or self.max_streams_bidi_pending or
            self.max_streams_uni_pending or self.path_response != null) return true;
        return self.send_queue.items.len > 0;
    }

    fn buildPacket(self: *Self, b: *Builder, space: Space, now: u64) Allocator.Error!void {
        const sp = &self.spaces[@backingInt(space)];
        const want_ack = sp.ack_wanted and !sp.rx_ranges.isEmpty();
        const ack_due = want_ack and ackDue(sp, now);
        const probing = sp.probes > 0;
        const cwnd_ok = self.cc.in_flight < self.cc.window or probing;
        const data = cwnd_ok and self.hasData(space);
        if (!ack_due and !data and !probing) return;

        // Seal the previous packet in the datagram first.
        self.sealLast(b, now);
        if (b.room() < 64) return;

        // Header.
        const pn = sp.sent.nextPn();
        const pn_len = packet.pnLen(pn, sp.largest_acked);
        var w: packet.Writer = .{ .buf = b.out[b.pos..] };
        const long = space != .application;
        if (long) {
            w.byte(0xc0 | packet.longTypeBits(space.packetType()) | @as(u8, @intCast(pn_len - 1)));
            w.int(u32, packet.version_1);
            w.byte(self.dcid.len);
            w.bytes(self.dcid.slice());
            w.byte(self.scid.len);
            w.bytes(self.scid.slice());
            if (space == .initial) w.varint(0); // no token
            w.int(u16, 0); // Length, filled when sealed
        } else {
            w.byte(0x40 | (@as(u8, self.tx_phase) << 2) | @as(u8, @intCast(pn_len - 1)));
            w.bytes(self.dcid.slice());
        }
        const pn_offset = b.pos + w.pos;
        var pn_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_buf, @truncate(pn), .big);
        w.bytes(pn_buf[4 - pn_len ..]);
        const header_end = w.pos;

        const mark = sp.sent.recordMark();
        b.open = true;
        b.start = b.pos;
        b.pn_offset = pn_offset;
        b.pn_len = pn_len;
        b.pn = pn;
        b.long = long;
        b.space = space;
        b.last_eliciting = false;
        b.last_in_flight = false;
        b.rec_mark = mark;

        // Room for frames: what's left minus the tag.
        const limit = w.buf.len -| protection.tag_len;
        var fw: packet.Writer = .{ .buf = w.buf[0..limit], .pos = header_end };

        if (want_ack) try self.writeAck(sp, &fw, now);
        if (data or probing) {
            if (space == .application) try self.writeControl(&fw);
            try self.writeCrypto(sp, &fw);
            // Responses to 0-RTT requests go out at 0.5-RTT.
            if (space == .application and (self.handshake_complete or self.inEarlyData())) try self.writeStreams(&fw);
        }
        var eliciting = sp.sent.recordMark() != mark and self.recordsElicit(sp, mark);
        if (!eliciting and probing) {
            fw.byte(0x01); // PING
            try sp.sent.addRecord(self.allocator, .ping);
            eliciting = true;
        }
        if (fw.pos == header_end) {
            // Nothing fit: abandon the packet.
            sp.sent.discardRecordsSince(mark);
            b.open = false;
            return;
        }
        b.last_eliciting = eliciting;
        b.pos += fw.pos;
        b.packets += 1;
    }

    fn recordsElicit(_: *Self, sp: *PnSpace, mark: u64) bool {
        const recs = sp.sent.records.items[@intCast(mark - sp.sent.rec_base)..];
        for (recs) |r| if (r != .ack) return true;
        return false;
    }

    fn writeAck(self: *Self, sp: *PnSpace, w: *packet.Writer, now: u64) Allocator.Error!void {
        var list: [max_ack_ranges]frame.Range = undefined;
        var n: usize = 0;
        var i = sp.rx_ranges.count();
        while (i > 0 and n < list.len) {
            i -= 1;
            const r = sp.rx_ranges.items.items[i];
            list[n] = .{ .smallest = r.start, .largest = r.end - 1 };
            n += 1;
        }
        const exponent = 3; // the default ack_delay_exponent, which we advertise
        const delay = (now -| sp.largest_rx_time) >> exponent;
        // Shed the oldest ranges if the frame doesn't fit.
        while (n > 0 and frame.ackFrameLen(list[0..n], delay) > w.left()) n -= 1;
        if (n == 0) return;
        frame.writeAckFrame(w, list[0..n], delay);
        try sp.sent.addRecord(self.allocator, .{ .ack = list[0].largest });
        sp.ack_wanted = false;
        sp.ack_eliciting_unacked = 0;
        sp.ack_deadline = null;
    }

    fn writeControl(self: *Self, w: *packet.Writer) Allocator.Error!void {
        const sp = &self.spaces[2];
        const a = self.allocator;
        if (self.handshake_done_pending and w.left() >= 1) {
            w.byte(0x1e);
            try sp.sent.addRecord(a, .handshake_done);
            self.handshake_done_pending = false;
        }
        if (self.path_response) |data| {
            if (w.left() >= 9) {
                frame.writePathResponse(w, data);
                self.path_response = null;
                try sp.sent.addRecord(a, .ping);
            }
        }
        if (self.max_data_pending and w.left() >= 9) {
            frame.writeMaxData(w, self.rx_max_data);
            try sp.sent.addRecord(a, .max_data);
            self.max_data_pending = false;
        }
        if (self.max_streams_bidi_pending and w.left() >= 9) {
            frame.writeMaxStreams(w, true, self.max_bidi);
            try sp.sent.addRecord(a, .max_streams_bidi);
            self.max_streams_bidi_pending = false;
        }
        if (self.max_streams_uni_pending and w.left() >= 9) {
            frame.writeMaxStreams(w, false, self.max_uni);
            try sp.sent.addRecord(a, .max_streams_uni);
            self.max_streams_uni_pending = false;
        }
    }

    fn writeCrypto(self: *Self, sp: *PnSpace, w: *packet.Writer) Allocator.Error!void {
        while (true) {
            const hdr = frame.cryptoHeaderLen(sp.crypto_tx.sent_off, 1 << 14);
            if (w.left() <= hdr) return;
            const chunk = sp.crypto_tx.next(w.left() - hdr, std.math.maxInt(u64)) orelse return;
            if (chunk.data.len == 0) return;
            frame.writeCryptoHeader(w, chunk.offset, chunk.data.len);
            w.bytes(chunk.data);
            try sp.sent.addRecord(self.allocator, .{ .crypto = .{ .offset = chunk.offset, .len = @intCast(chunk.data.len) } });
            try sp.crypto_tx.onSent(self.allocator, chunk);
        }
    }

    fn writeStreams(self: *Self, w: *packet.Writer) Allocator.Error!void {
        const sp = &self.spaces[2];
        const a = self.allocator;
        var i: usize = 0;
        while (i < self.send_queue.items.len) {
            if (w.left() < 24) return;
            const slot = self.send_queue.items[i];
            const s = &self.streams[slot];
            const gen = s.gen;
            // Control frames for the stream.
            if (s.reset_code) |code| {
                if (!s.reset_sent) {
                    frame.writeResetStream(w, s.id, code, s.send.writeOff());
                    try sp.sent.addRecord(a, .{ .reset_stream = .{ .slot = slot, .gen = gen } });
                    s.reset_sent = true;
                }
            }
            if (s.stop_code) |code| {
                if (!s.stop_sent and w.left() >= 17) {
                    frame.writeStopSending(w, s.id, code);
                    try sp.sent.addRecord(a, .{ .stop_sending = .{ .slot = slot, .gen = gen } });
                    s.stop_sent = true;
                }
            }
            if (s.max_data_pending and w.left() >= 17) {
                frame.writeMaxStreamData(w, s.id, s.recv.max_data);
                try sp.sent.addRecord(a, .{ .max_stream_data = .{ .slot = slot, .gen = gen } });
                s.max_data_pending = false;
            }
            // Data.
            var rotated = false;
            if (s.reset_code == null) {
                while (true) {
                    const hdr = frame.streamHeaderLen(s.id, s.send.writeOff(), 1 << 14, true);
                    if (w.left() <= hdr) break;
                    const credit = self.tx_max_data -| self.tx_data;
                    const chunk = s.send.next(w.left() - hdr, credit) orelse break;
                    frame.writeStreamHeader(w, s.id, chunk.offset, chunk.data.len, chunk.fin, true);
                    w.bytes(chunk.data);
                    try sp.sent.addRecord(a, .{ .stream = .{ .slot = slot, .gen = gen, .offset = chunk.offset, .len = @intCast(chunk.data.len), .fin = chunk.fin } });
                    if (!chunk.retransmit) self.tx_data += chunk.data.len;
                    try s.send.onSent(a, chunk);
                    if (chunk.data.len == 0) break;
                    // Incremental streams of one urgency take turns: this
                    // one goes behind the others.
                    if (s.send.hasPending() and i + 1 < self.send_queue.items.len and s.sharesWith(&self.streams[self.send_queue.items[i + 1]])) {
                        _ = self.send_queue.orderedRemove(i);
                        var j = i;
                        while (j < self.send_queue.items.len and s.sharesWith(&self.streams[self.send_queue.items[j]])) j += 1;
                        self.send_queue.insertAssumeCapacity(j, slot);
                        rotated = true;
                        break;
                    }
                }
            }
            // The next stream of the group is at `i` now.
            if (rotated) continue;
            const control = (s.reset_code != null and !s.reset_sent) or
                (s.stop_code != null and !s.stop_sent) or s.max_data_pending;
            const data_left = s.reset_code == null and s.send.hasPending();
            if (control or data_left) {
                // The packet is full, or new data waits for connection
                // credit: keep the stream's place. Another stream may
                // still have retransmissions or control frames.
                if (w.left() >= 24) {
                    i += 1;
                    continue;
                }
                return;
            }
            // Done for now: finished, or blocked by the stream's own limit
            // (MAX_STREAM_DATA queues it again).
            _ = self.send_queue.orderedRemove(i);
            s.queued = false;
            self.maybeFree(slot);
        }
    }

    fn sendClose(self: *Self, out: []u8, now: u64) usize {
        if (!self.close_pending) return 0;
        self.close_pending = false;
        var pos: usize = 0;
        // During the handshake the client may lack 1-RTT (or Handshake)
        // keys: send in every space we have (§10.2.3), as a transport
        // error in Initial and Handshake.
        for ([_]Space{ .initial, .handshake, .application }) |space| {
            const sp = &self.spaces[@backingInt(space)];
            if (sp.tx == null or sp.discarded) continue;
            if (space == .application and !self.handshake_complete and self.spaces[1].tx != null) continue;
            const app = self.close_app and space == .application;
            const code = if (self.close_app and !app) @backingInt(TransportError.application_error) else self.close_code;
            const reason = if (app or !self.close_app) self.close_reason else "";
            const n = self.closePacket(out[pos..@min(out.len, self.max_datagram)], space, app, code, reason);
            pos += n;
        }
        _ = now;
        self.bytes_sent += pos;
        return pos;
    }

    fn closePacket(self: *Self, out: []u8, space: Space, app: bool, code: u64, reason_in: []const u8) usize {
        const sp = &self.spaces[@backingInt(space)];
        const reason = reason_in[0..@min(reason_in.len, 64)];
        const pn = sp.sent.nextPn();
        const pn_len: usize = 4;
        var w: packet.Writer = .{ .buf = out };
        const long = space != .application;
        const need = 64 + reason.len + self.dcid.len + self.scid.len;
        if (out.len < need) return 0;
        if (long) {
            w.byte(0xc0 | packet.longTypeBits(space.packetType()) | 3);
            w.int(u32, packet.version_1);
            w.byte(self.dcid.len);
            w.bytes(self.dcid.slice());
            w.byte(self.scid.len);
            w.bytes(self.scid.slice());
            if (space == .initial) w.varint(0);
            w.int(u16, 0);
        } else {
            w.byte(0x40 | (@as(u8, self.tx_phase) << 2) | 3);
            w.bytes(self.dcid.slice());
        }
        const pn_offset = w.pos;
        w.int(u32, @truncate(pn));
        frame.writeConnectionClose(&w, app, code, self.close_frame_type, reason);
        const end = w.pos + protection.tag_len;
        if (long) _ = packet.writeVarintLen(out[pn_offset - 2 ..], end - pn_offset, 2);
        sp.tx.?.protect(out[0..end], pn_offset, pn_len, pn);
        // Consume the packet number (nothing is tracked for it).
        sp.sent.add(self.allocator, sp.sent.recordMark(), 0, @intCast(end), false, false) catch {};
        if (sp.sent.get(pn)) |p| sp.sent.remove(p);
        return end;
    }

    /// Whether `send` would produce something now (the worker's hint).
    pub fn wantsSend(self: *Self, now: u64) bool {
        if (self.state == .closing) return self.close_pending;
        if (self.state != .handshake and self.state != .established) return false;
        for ([_]Space{ .initial, .handshake, .application }) |space| {
            const sp = &self.spaces[@backingInt(space)];
            if (sp.tx == null or sp.discarded) continue;
            if (sp.probes > 0) return true;
            if (sp.ack_wanted and ackDue(sp, now)) return true;
            if (self.cc.in_flight < self.cc.window and self.hasData(space)) return true;
        }
        return false;
    }

    /// Starts a key update of our own when the current keys have been used
    /// long enough (and the last update was acknowledged).
    pub fn maybeUpdateKeys(self: *Self) void {
        if (!self.handshake_complete or !self.tx_phase_acked) return;
        if (self.tx_phase_packets < key_update_packets) return;
        self.updateTxKeys();
    }
};
