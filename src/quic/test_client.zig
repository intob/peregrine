//! A minimal QUIC client for tests: TLS 1.3 with X25519 and AES-128-GCM,
//! certificate not verified (the server's Finished is), CRYPTO and STREAM
//! data with crude retransmission (everything unacknowledged is resent on
//! `retransmit`), and ACKs for everything received, with ECN counts of the
//! codepoints it was given (`recvEcn`). Enough to drive conn.zig through
//! handshakes, streams, flow control, loss, ECN and errors.
const std = @import("std");
const packet = @import("./packet.zig");
const protection = @import("./protection.zig");
const frame = @import("./frame.zig");
const stream_mod = @import("./stream.zig");
const ranges = @import("./ranges.zig");
const key_schedule = @import("../tls/key_schedule.zig");
const Keys = protection.Keys;
const Allocator = std.mem.Allocator;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const ks = key_schedule.Sha256;

pub const Options = struct {
    alpn: []const u8 = "h3",
    /// Raw transport parameters; null for a sensible default set.
    transport_params: ?[]const u8 = null,
    dcid: [8]u8 = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
    scid: []const u8 = &.{ 0xc1, 0xc2, 0xc3, 0xc4 },
    seed: u8 = 1,
    max_stream_data: u64 = 1 << 20,
    max_data: u64 = 1 << 24,
};

const Space = struct {
    rx: ?Keys = null,
    tx: ?Keys = null,
    next_pn: u64 = 0,
    largest_rx: ?u64 = null,
    rx_pns: ranges.RangeSet = .{},
    ack_needed: bool = false,
    crypto_rx: stream_mod.RecvStream = .{},
    crypto_tx: stream_mod.SendStream = .{},
    /// Crypto frames per packet number, for acks: (pn, offset, len).
    sent: std.ArrayList(SentFrame) = .empty,
    /// Packets received with ECT(0), ECT(1) and CE, as our ACKs report
    /// them; the server's counts in its last ACK_ECN (null: plain ACKs).
    ecn: [3]u64 = @splat(0),
    peer_ecn: ?[3]u64 = null,
    acks_seen: u32 = 0,
};

/// How the client reports ECN counts in its ACKs.
pub const EcnMode = enum {
    /// What it received.
    honest,
    /// Never: plain ACK frames.
    none,
    /// ACK_ECN with the counts as they are now, never raised again.
    frozen,
};

const SentFrame = struct { pn: u64, kind: enum { crypto, stream }, id: u64 = 0, offset: u64, len: u64, fin: bool = false };

pub const Stream = struct {
    recv: stream_mod.RecvStream = .{},
    send: stream_mod.SendStream = .{},
    reset_code: ?u64 = null,
    stop_code: ?u64 = null,
};

pub const Client = struct {
    const Self = @This();

    a: Allocator,
    opts: Options,
    spaces: [3]Space = .{ .{}, .{}, .{} },
    server_cid: ?[]u8 = null,
    // TLS.
    kp: X25519.KeyPair,
    transcript: Sha256 = .init(.{}),
    hs_secret: ks.Secret = undefined,
    c_hs: ks.Secret = undefined,
    s_hs: ks.Secret = undefined,
    app_rx_secret: ks.Secret = undefined,
    app_tx_secret: ks.Secret = undefined,
    alpn: ?[]u8 = null,
    server_params: ?[]u8 = null,
    handshake_complete: bool = false,
    handshake_done: bool = false,
    /// NewSessionTickets received (not used to resume).
    tickets: u32 = 0,
    key_phase: u1 = 0,
    /// The phase of the receive keys, and the keys before the last update
    /// (packets of the old phase can still be on their way).
    rx_phase: u1 = 0,
    prev_rx_packet: ?@FieldType(Keys, "packet") = null,
    // Connection state.
    streams: std.AutoHashMapUnmanaged(u64, *Stream) = .empty,
    next_bidi: u64 = 0,
    next_uni: u64 = 2,
    closed: ?struct { code: u64, app: bool, frame_type: u64 } = null,
    max_streams_bidi: u64 = 0,
    max_data_seen: u64 = 0,
    peer_max_stream_data_bidi: u64 = 0,
    peer_max_stream_data_uni: u64 = 0,
    peer_max_data: u64 = 0,
    data_sent: u64 = 0,
    /// Frames to append to the next 1-RTT packet (raw, for error tests).
    inject: std.ArrayList(u8) = .empty,
    path_responses: u32 = 0,
    new_cids: u32 = 0,
    stateless_reset_tokens: u32 = 0,
    ecn_mode: EcnMode = .honest,
    /// Datagrams received with each codepoint (by its value).
    datagrams_ecn: [4]u64 = @splat(0),

    pub fn init(a: Allocator, opts: Options) !*Self {
        const self = try a.create(Self);
        var seed: [32]u8 = @splat(opts.seed);
        seed[0] = 7;
        self.* = .{ .a = a, .opts = opts, .kp = X25519.KeyPair.generateDeterministic(seed) };
        for (&self.spaces) |*s| {
            s.crypto_rx.reset(0);
            s.crypto_tx.reset(std.math.maxInt(u64));
        }
        const secrets = protection.initialSecrets(&opts.dcid);
        self.spaces[0].tx = .init(.aes_128_gcm_sha256, &secrets.client);
        self.spaces[0].rx = .init(.aes_128_gcm_sha256, &secrets.server);
        try self.writeClientHello();
        return self;
    }

    pub fn deinit(self: *Self) void {
        const a = self.a;
        for (&self.spaces) |*s| {
            s.rx_pns.deinit(a);
            s.crypto_rx.deinit(a);
            s.crypto_tx.deinit(a);
            s.sent.deinit(a);
        }
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            s.*.recv.deinit(a);
            s.*.send.deinit(a);
            a.destroy(s.*);
        }
        self.streams.deinit(a);
        if (self.server_cid) |c| a.free(c);
        if (self.alpn) |x| a.free(x);
        if (self.server_params) |x| a.free(x);
        self.inject.deinit(a);
        a.destroy(self);
    }

    fn defaultParams(self: *Self, buf: []u8) []const u8 {
        var w: packet.Writer = .{ .buf = buf };
        const put = struct {
            fn f(wr: *packet.Writer, id: u64, v: u64) void {
                wr.varint(id);
                wr.varint(packet.varintLen(v));
                wr.varint(v);
            }
        }.f;
        put(&w, 0x04, self.opts.max_data);
        // Streams we open (local) get the real limit; the server's
        // bidirectional streams (never opened) a different one, so a mix-up
        // shows.
        put(&w, 0x05, self.opts.max_stream_data);
        put(&w, 0x06, 1000);
        put(&w, 0x07, self.opts.max_stream_data);
        put(&w, 0x08, 100);
        put(&w, 0x09, 100);
        put(&w, 0x01, 30_000);
        w.varint(0x0f);
        w.varint(self.opts.scid.len);
        w.bytes(self.opts.scid);
        return w.written();
    }

    fn writeClientHello(self: *Self) !void {
        var buf: [1024]u8 = undefined;
        var w: packet.Writer = .{ .buf = &buf };
        w.byte(1);
        const len_at = w.pos;
        w.pos += 3;
        w.int(u16, 0x0303);
        var random: [32]u8 = @splat(self.opts.seed);
        w.bytes(&random);
        w.byte(0); // session id
        w.int(u16, 2);
        w.int(u16, 0x1301);
        w.byte(1);
        w.byte(0);
        const exts_at = w.pos;
        w.pos += 2;
        // supported_versions
        w.int(u16, 43);
        w.int(u16, 3);
        w.byte(2);
        w.int(u16, 0x0304);
        // supported_groups
        w.int(u16, 10);
        w.int(u16, 4);
        w.int(u16, 2);
        w.int(u16, 0x001d);
        // signature_algorithms
        w.int(u16, 13);
        w.int(u16, 8);
        w.int(u16, 6);
        w.int(u16, 0x0403);
        w.int(u16, 0x0503);
        w.int(u16, 0x0807);
        // key_share
        w.int(u16, 51);
        w.int(u16, 2 + 4 + 32);
        w.int(u16, 4 + 32);
        w.int(u16, 0x001d);
        w.int(u16, 32);
        w.bytes(&self.kp.public_key);
        // alpn
        w.int(u16, 16);
        w.int(u16, @intCast(2 + 1 + self.opts.alpn.len));
        w.int(u16, @intCast(1 + self.opts.alpn.len));
        w.byte(@intCast(self.opts.alpn.len));
        w.bytes(self.opts.alpn);
        // quic_transport_parameters
        var pbuf: [256]u8 = undefined;
        const params = self.opts.transport_params orelse self.defaultParams(&pbuf);
        w.int(u16, 57);
        w.int(u16, @intCast(params.len));
        w.bytes(params);
        std.mem.writeInt(u16, buf[exts_at..][0..2], @intCast(w.pos - exts_at - 2), .big);
        std.mem.writeInt(u24, buf[len_at..][0..3], @intCast(w.pos - len_at - 3), .big);
        self.transcript.update(w.written());
        try self.spaces[0].crypto_tx.write(self.a, w.written());
    }

    // -- Receiving -----------------------------------------------------------

    pub fn recv(self: *Self, datagram: []const u8) !void {
        return self.recvEcn(datagram, .not_ect);
    }

    /// A datagram that arrived with the ECN codepoint `ecn`.
    pub fn recvEcn(self: *Self, datagram: []const u8, ecn: packet.Ecn) !void {
        self.datagrams_ecn[@backingInt(ecn)] += 1;
        var copy = try self.a.dupe(u8, datagram);
        defer self.a.free(copy);
        var rest: []u8 = copy[0..];
        while (rest.len > 0) {
            const h = packet.parseHeader(rest, self.opts.scid.len) catch return;
            const pkt = rest[0..h.len];
            rest = rest[h.len..];
            const idx: usize = switch (h.type) {
                .initial => 0,
                .handshake => 1,
                .one_rtt => 2,
                else => return error.UnexpectedPacket,
            };
            if (h.type == .initial and self.server_cid == null) self.server_cid = try self.a.dupe(u8, h.scid);
            const sp = &self.spaces[idx];
            const keys = sp.rx orelse continue;
            const pn_info = keys.header.unprotect(pkt, h.pn_offset) catch continue;
            const pn = packet.decodePn(sp.largest_rx, pn_info.truncated, pn_info.len);
            const pk = if (idx == 2 and ((pkt[0] >> 2) & 1) != self.rx_phase and self.prev_rx_packet != null) self.prev_rx_packet.? else keys.packet;
            const payload = pk.open(pkt, h.pn_offset + pn_info.len, pn) catch return error.Undecryptable;
            if (sp.largest_rx == null or pn > sp.largest_rx.?) sp.largest_rx = pn;
            if (!sp.rx_pns.contains(pn) and self.ecn_mode != .frozen) switch (ecn) {
                .not_ect => {},
                .ect0 => sp.ecn[0] += 1,
                .ect1 => sp.ecn[1] += 1,
                .ce => sp.ecn[2] += 1,
            };
            sp.rx_pns.insert(self.a, pn, pn + 1, 1 << 20) catch unreachable;
            var r: packet.Reader = .{ .data = payload };
            while (r.left() > 0) {
                const f = switch (frame.parse(&r)) {
                    .frame => |f| f,
                    .failure => return error.BadFrame,
                };
                if (frame.ackEliciting(f)) sp.ack_needed = true;
                try self.onFrame(idx, f);
            }
        }
    }

    fn onFrame(self: *Self, idx: usize, f: frame.Frame) !void {
        const a = self.a;
        const sp = &self.spaces[idx];
        switch (f) {
            .padding, .ping => {},
            .ack => |ack| {
                sp.peer_ecn = ack.ecn;
                sp.acks_seen += 1;
                var it = ack.iterator();
                while (it.next()) |rg| {
                    var i: usize = 0;
                    while (i < sp.sent.items.len) {
                        const s = sp.sent.items[i];
                        if (s.pn >= rg.smallest and s.pn <= rg.largest) {
                            switch (s.kind) {
                                .crypto => try sp.crypto_tx.onAcked(a, s.offset, s.len, false),
                                .stream => if (self.streams.get(s.id)) |st| try st.send.onAcked(a, s.offset, s.len, s.fin),
                            }
                            _ = sp.sent.swapRemove(i);
                        } else i += 1;
                    }
                }
            },
            .crypto => |c| {
                _ = try sp.crypto_rx.recv(a, c.offset, c.data, false);
                const data = sp.crypto_rx.readable();
                var used: usize = 0;
                while (data.len - used >= 4) {
                    const len = std.mem.readInt(u24, data[used + 1 ..][0..3], .big);
                    if (data.len - used < 4 + len) break;
                    try self.onHandshakeMessage(idx, data[used..][0 .. 4 + len]);
                    used += 4 + len;
                }
                sp.crypto_rx.consume(used);
            },
            .stream => |s| {
                const st = try self.getStream(s.id);
                _ = try st.recv.recv(a, s.offset, s.data, s.fin);
            },
            .reset_stream => |rs| {
                const st = try self.getStream(rs.id);
                st.reset_code = rs.code;
            },
            .stop_sending => |ss| {
                const st = try self.getStream(ss.id);
                st.stop_code = ss.code;
            },
            .max_streams => |m| {
                if (m.bidi) self.max_streams_bidi = m.max;
            },
            .max_data => |m| {
                self.max_data_seen = m;
                self.peer_max_data = @max(self.peer_max_data, m);
            },
            .max_stream_data => |m| {
                const st = try self.getStream(m.id);
                st.send.max_data = @max(st.send.max_data, m.max);
            },
            .handshake_done => {
                self.handshake_done = true;
                // Initial and Handshake keys can go.
                self.spaces[0].tx = null;
                self.spaces[1].tx = null;
            },
            .connection_close => |c| self.closed = .{ .code = c.code, .app = c.app, .frame_type = c.frame_type },
            .path_response => self.path_responses += 1,
            .new_connection_id => self.new_cids += 1,
            .new_token, .data_blocked, .stream_data_blocked, .streams_blocked, .retire_connection_id, .path_challenge => {},
        }
    }

    pub fn getStream(self: *Self, id: u64) !*Stream {
        const gop = try self.streams.getOrPut(self.a, id);
        if (!gop.found_existing) {
            const s = try self.a.create(Stream);
            s.* = .{};
            s.recv.reset(0);
            s.send.reset(if (id & 2 == 0) self.peer_max_stream_data_bidi else if (id & 1 == 0) self.peer_max_stream_data_uni else 0);
            gop.value_ptr.* = s;
        }
        return gop.value_ptr.*;
    }

    fn onHandshakeMessage(self: *Self, idx: usize, msg: []const u8) !void {
        switch (msg[0]) {
            2 => { // ServerHello
                std.debug.assert(idx == 0);
                var r: packet.Reader = .{ .data = msg[4..] };
                _ = try r.bytes(2 + 32);
                _ = try r.bytes(try r.byte());
                if (try r.int(u16) != 0x1301) return error.UnexpectedSuite;
                _ = try r.byte();
                const exts = try r.bytes(try r.int(u16));
                var e: packet.Reader = .{ .data = exts };
                var server_pub: ?[32]u8 = null;
                while (e.left() > 0) {
                    const ty = try e.int(u16);
                    const body = try e.bytes(try e.int(u16));
                    if (ty == 51) {
                        if (body.len != 4 + 32) return error.BadKeyShare;
                        server_pub = body[4..36].*;
                    }
                }
                self.transcript.update(msg);
                const shared = try X25519.scalarmult(self.kp.secret_key, server_pub orelse return error.NoKeyShare);
                self.hs_secret = ks.handshakeSecret(ks.earlySecret(), &shared);
                var th: [32]u8 = undefined;
                var t = self.transcript;
                t.final(&th);
                self.c_hs = ks.deriveSecret(self.hs_secret, "c hs traffic", &th);
                self.s_hs = ks.deriveSecret(self.hs_secret, "s hs traffic", &th);
                self.spaces[1].rx = .init(.aes_128_gcm_sha256, &self.s_hs);
                self.spaces[1].tx = .init(.aes_128_gcm_sha256, &self.c_hs);
            },
            8 => { // EncryptedExtensions
                var r: packet.Reader = .{ .data = msg[4..] };
                const exts = try r.bytes(try r.int(u16));
                var e: packet.Reader = .{ .data = exts };
                while (e.left() > 0) {
                    const ty = try e.int(u16);
                    const body = try e.bytes(try e.int(u16));
                    if (ty == 16) self.alpn = try self.a.dupe(u8, body[3..]);
                    if (ty == 57) {
                        self.server_params = try self.a.dupe(u8, body);
                        self.readServerParams(body) catch return error.BadParams;
                    }
                }
                self.transcript.update(msg);
            },
            11, 15 => self.transcript.update(msg), // Certificate, CertificateVerify
            20 => { // Finished
                var th: [32]u8 = undefined;
                var t = self.transcript;
                t.final(&th);
                const expected = ks.finishedVerifyData(self.s_hs, &th);
                if (!std.mem.eql(u8, &expected, msg[4..])) return error.BadFinished;
                self.transcript.update(msg);
                t = self.transcript;
                t.final(&th);
                const master = ks.masterSecret(self.hs_secret);
                self.app_tx_secret = ks.deriveSecret(master, "c ap traffic", &th);
                self.app_rx_secret = ks.deriveSecret(master, "s ap traffic", &th);
                // Client Finished.
                const verify = ks.finishedVerifyData(self.c_hs, &th);
                var fin: [4 + 32]u8 = undefined;
                fin[0] = 20;
                std.mem.writeInt(u24, fin[1..4], 32, .big);
                fin[4..].* = verify;
                try self.spaces[1].crypto_tx.write(self.a, &fin);
                self.spaces[2].rx = .init(.aes_128_gcm_sha256, &self.app_rx_secret);
                self.spaces[2].tx = .init(.aes_128_gcm_sha256, &self.app_tx_secret);
                self.handshake_complete = true;
            },
            4 => { // NewSessionTicket, after the handshake
                if (idx != 2 or !self.handshake_complete) return error.UnexpectedMessage;
                self.tickets += 1;
            },
            else => return error.UnexpectedMessage,
        }
    }

    fn readServerParams(self: *Self, body: []const u8) !void {
        var r: packet.Reader = .{ .data = body };
        while (r.left() > 0) {
            const id = try r.varint();
            const v = try r.vector();
            var vr: packet.Reader = .{ .data = v };
            switch (id) {
                0x04 => self.peer_max_data = try vr.varint(),
                0x06 => self.peer_max_stream_data_bidi = try vr.varint(),
                0x07 => self.peer_max_stream_data_uni = try vr.varint(),
                0x08 => self.max_streams_bidi = try vr.varint(),
                else => {},
            }
        }
    }

    /// The server's transport parameter `id`, raw.
    pub fn serverParam(self: *const Self, id: u64) ?[]const u8 {
        var r: packet.Reader = .{ .data = self.server_params orelse return null };
        while (r.left() > 0) {
            const pid = r.varint() catch return null;
            const v = r.vector() catch return null;
            if (pid == id) return v;
        }
        return null;
    }

    // -- Streams ----------------------------------------------------------------

    pub fn openUni(self: *Self) !u64 {
        const id = self.next_uni;
        self.next_uni += 4;
        _ = try self.getStream(id);
        return id;
    }

    pub fn openBidi(self: *Self) !u64 {
        const id = self.next_bidi;
        self.next_bidi += 4;
        _ = try self.getStream(id);
        return id;
    }

    pub fn write(self: *Self, id: u64, data: []const u8, fin: bool) !void {
        const s = try self.getStream(id);
        try s.send.write(self.a, data);
        if (fin) s.send.finish();
    }

    pub fn readAll(self: *Self, id: u64) []const u8 {
        const s = self.streams.get(id) orelse return "";
        return s.recv.readable();
    }

    pub fn finished(self: *Self, id: u64) bool {
        const s = self.streams.get(id) orelse return false;
        return s.recv.complete();
    }

    /// Marks everything sent but unacknowledged as lost.
    pub fn retransmit(self: *Self) !void {
        for (&self.spaces) |*sp| {
            for (sp.sent.items) |s| switch (s.kind) {
                .crypto => try sp.crypto_tx.onLost(self.a, s.offset, s.len, false),
                .stream => if (self.streams.get(s.id)) |st| try st.send.onLost(self.a, s.offset, s.len, s.fin),
            };
            sp.sent.clearRetainingCapacity();
        }
    }

    pub fn initiateKeyUpdate(self: *Self) void {
        self.app_tx_secret = protection.nextSecret(.aes_128_gcm_sha256, &self.app_tx_secret)[0..32].*;
        self.spaces[2].tx.?.packet = .init(.aes_128_gcm_sha256, &self.app_tx_secret);
        self.key_phase ^= 1;
    }

    /// Accepts a server key update: the next receive keys.
    pub fn followKeyUpdate(self: *Self) void {
        self.app_rx_secret = protection.nextSecret(.aes_128_gcm_sha256, &self.app_rx_secret)[0..32].*;
        self.prev_rx_packet = self.spaces[2].rx.?.packet;
        self.rx_phase ^= 1;
        self.spaces[2].rx.?.packet = .init(.aes_128_gcm_sha256, &self.app_rx_secret);
    }

    // -- Sending --------------------------------------------------------------

    /// The next datagram, or 0 bytes when there is nothing to send.
    pub fn send(self: *Self, out: []u8) !usize {
        var pos: usize = 0;
        var has_initial = false;
        for (0..3) |idx| {
            const sp = &self.spaces[idx];
            if (sp.tx == null) continue;
            if (idx == 2 and !self.handshake_complete) continue;
            const n = try self.buildPacket(idx, out[pos..@min(out.len, 1350)]);
            if (n > 0 and idx == 0) has_initial = true;
            pos += n;
        }
        if (has_initial and pos < 1200) {
            // Pad with a trailing padding-only... instead, rebuild padded:
            // simplest is to extend the datagram with zero bytes, which the
            // server must ignore as an invalid trailing packet (§12.2).
            @memset(out[pos..1200], 0);
            pos = 1200;
        }
        return pos;
    }

    fn buildPacket(self: *Self, idx: usize, out: []u8) !usize {
        const a = self.a;
        const sp = &self.spaces[idx];
        if (out.len < 100) return 0;
        var payload: [1400]u8 = undefined;
        var w: packet.Writer = .{ .buf = payload[0..@min(payload.len, out.len - 60)] };
        const pn = sp.next_pn;
        var records: [64]SentFrame = undefined;
        var nrec: usize = 0;
        if (sp.ack_needed and !sp.rx_pns.isEmpty()) {
            var list: [32]frame.Range = undefined;
            var n: usize = 0;
            var i = sp.rx_pns.count();
            while (i > 0 and n < list.len) {
                i -= 1;
                const r = sp.rx_pns.items.items[i];
                list[n] = .{ .smallest = r.start, .largest = r.end - 1 };
                n += 1;
            }
            const report = self.ecn_mode != .none and (sp.ecn[0] | sp.ecn[1] | sp.ecn[2]) != 0;
            frame.writeAckFrame(&w, list[0..n], 0, if (report) sp.ecn else null);
            sp.ack_needed = false;
        }
        while (sp.crypto_tx.next(w.left() -| 16, std.math.maxInt(u64))) |c| {
            if (c.data.len == 0) break;
            frame.writeCryptoHeader(&w, c.offset, c.data.len);
            w.bytes(c.data);
            try sp.crypto_tx.onSent(a, c);
            records[nrec] = .{ .pn = pn, .kind = .crypto, .offset = c.offset, .len = c.data.len };
            nrec += 1;
        }
        if (idx == 2) {
            if (self.inject.items.len > 0 and w.left() >= self.inject.items.len) {
                w.bytes(self.inject.items);
                self.inject.clearRetainingCapacity();
            }
            var it = self.streams.iterator();
            while (it.next()) |e| {
                const id = e.key_ptr.*;
                const s = e.value_ptr.*;
                while (nrec < records.len) {
                    const hdr = frame.streamHeaderLen(id, s.send.writeOff(), 1 << 14, true);
                    if (w.left() <= hdr + 1) break;
                    const credit = self.peer_max_data -| self.data_sent;
                    const c = s.send.next(w.left() - hdr, credit) orelse break;
                    frame.writeStreamHeader(&w, id, c.offset, c.data.len, c.fin, true);
                    w.bytes(c.data);
                    if (!c.retransmit) self.data_sent += c.data.len;
                    try s.send.onSent(a, c);
                    records[nrec] = .{ .pn = pn, .kind = .stream, .id = id, .offset = c.offset, .len = c.data.len, .fin = c.fin };
                    nrec += 1;
                    if (c.data.len == 0) break;
                }
            }
        }
        if (w.pos == 0) return 0;
        // Pad so the header protection sample exists.
        while (w.pos < 4) w.byte(0);
        for (records[0..nrec]) |r| try sp.sent.append(a, r);
        sp.next_pn += 1;

        var o: packet.Writer = .{ .buf = out };
        const server_cid = self.server_cid orelse &self.opts.dcid;
        const pn_len: usize = 2;
        if (idx < 2) {
            o.byte(0xc0 | @as(u8, if (idx == 0) 0 else 2) << 4 | 1);
            o.int(u32, 1);
            o.byte(@intCast(server_cid.len));
            o.bytes(server_cid);
            o.byte(@intCast(self.opts.scid.len));
            o.bytes(self.opts.scid);
            if (idx == 0) o.varint(0);
            o.int(u16, @intCast((pn_len + w.pos + 16) | 0x4000));
        } else {
            o.byte(0x40 | @as(u8, self.key_phase) << 2 | 1);
            o.bytes(server_cid);
        }
        const pn_offset = o.pos;
        o.int(u16, @truncate(pn));
        o.bytes(w.written());
        const end = o.pos + 16;
        sp.tx.?.protect(out[0..end], pn_offset, pn_len, pn);
        return end;
    }

    /// Sends a raw frame sequence in its own 1-RTT packet next time.
    pub fn injectFrames(self: *Self, bytes: []const u8) !void {
        try self.inject.appendSlice(self.a, bytes);
    }
};
