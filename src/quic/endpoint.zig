//! A worker's QUIC endpoint: its UDP socket, the HTTP/3 connections it
//! owns, found by connection ID, and their timers. The worker calls
//! `onReadable` when the socket is readable and `onTimers` every loop
//! turn, and waits no longer than `timeoutMs`. Everything stays on the
//! worker's thread: SO_REUSEPORT steering (udp.zig) brings a connection's
//! packets to the worker named in its connection IDs.
//!
//! Packets for no connection: an Initial in a datagram of at least 1200
//! bytes starts one (after a Retry, if address validation is on), other
//! versions get Version Negotiation, short headers get a stateless reset
//! (rate limited), everything else is dropped.
const std = @import("std");
const sys = @import("../sys.zig");
const quic = @import("./conn.zig");
const packet = @import("./packet.zig");
const protection = @import("./protection.zig");
const udp = @import("./udp.zig");
const handshake = @import("../tls/handshake.zig");
const h3 = @import("../h3/conn.zig");
const exchange = @import("../http/exchange.zig");
const BufferPool = @import("../http/session.zig").BufferPool;
const date = @import("../http/date.zig");
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const Allocator = std.mem.Allocator;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

/// Set in an exchange's conn_slot when it belongs to a QUIC connection.
pub const exchange_slot_flag: u32 = 0x8000_0000;

/// Datagrams received per recvmmsg, and their buffer size (larger
/// datagrams than 1500 bytes are rare on the Internet; QUIC clients send
/// 1200-1500).
const batch_len = 32;
const datagram_buf = 2048;

pub const RetryMode = enum {
    /// Never: the anti-amplification limit protects us.
    never,
    /// Validate every client's address with a Retry (one more round trip).
    always,
};

pub const Options = struct {
    quic: quic.Config,
    h3: h3.Options = .{},
    max_connections: u32 = 4096,
    worker_index: u8 = 0,
    worker_count: u8 = 1,
    retry: RetryMode = .never,
    /// Stateless resets sent per second, at most.
    max_resets_per_second: u32 = 100,
};

const CidKey = struct {
    len: u8 = 0,
    bytes: [packet.max_cid_len]u8 = @splat(0),

    fn init(b: []const u8) CidKey {
        var k: CidKey = .{ .len = @intCast(b.len) };
        @memcpy(k.bytes[0..b.len], b);
        return k;
    }
};

pub fn Endpoint(comptime Handler: type) type {
    return struct {
        const Self = @This();

        const Slot = struct {
            q: ?*quic.Conn = null,
            h: ?*h3.Conn = null,
            gen: u32 = 0,
            peer: udp.Addr = .{},
            cid: u64 = 0,
            odcid: CidKey = .{},
            /// The deadline this slot has in the heap.
            scheduled: ?u64 = null,
            dirty: bool = false,
        };

        const Timer = struct { at: u64, slot: u32, gen: u32 };

        allocator: Allocator,
        opts: Options,
        fd: sys.fd_t,
        gso: bool,
        /// The kernel refused the TOS control message on this socket, by
        /// `udp.tosKind` (IP_TOS, IPV6_TCLASS): those sends go unmarked
        /// (each connection's ECN validation then fails, which ends its
        /// marking).
        tos_refused: [2]bool = .{ false, false },
        slots: []Slot,
        free: std.ArrayList(u32) = .empty,
        count: u32 = 0,
        by_cid: std.AutoHashMapUnmanaged(u64, u32) = .empty,
        by_odcid: std.AutoHashMapUnmanaged(CidKey, u32) = .empty,
        heap: std.ArrayList(Timer) = .empty,
        dirty: std.ArrayList(u32) = .empty,
        rng: std.Random.ChaCha,
        reset_key: [32]u8,
        token_key: [16]u8,
        batch: *udp.RecvBatch(batch_len, datagram_buf),
        send_buf: []u8,
        resets_second: u64 = 0,
        resets: u32 = 0,
        shutting_down: bool = false,

        // The worker's, for HTTP/3 connections.
        handler: *Handler = undefined,
        req: *Request = undefined,
        resp: *Response = undefined,
        date_line: *const [date.header_len]u8 = undefined,
        now_s: *const u32 = undefined,
        exchanges: *exchange.Slab = undefined,
        pool: *BufferPool = undefined,

        pub fn init(allocator: Allocator, opts: Options, fd: sys.fd_t) !Self {
            const slots = try allocator.alloc(Slot, opts.max_connections);
            errdefer allocator.free(slots);
            @memset(slots, .{});
            const batch = try allocator.create(udp.RecvBatch(batch_len, datagram_buf));
            errdefer allocator.destroy(batch);
            const send_buf = try allocator.alloc(u8, 64 * 1024);
            errdefer allocator.free(send_buf);
            var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
            sys.randomBytes(&seed);
            defer std.crypto.secureZero(u8, &seed);
            var self: Self = .{
                .allocator = allocator,
                .opts = opts,
                .fd = fd,
                .gso = udp.gsoSupported(fd),
                .slots = slots,
                .rng = .init(seed),
                .reset_key = undefined,
                .token_key = undefined,
                .batch = batch,
                .send_buf = send_buf,
            };
            sys.randomBytes(&self.reset_key);
            sys.randomBytes(&self.token_key);
            try self.free.ensureTotalCapacity(allocator, opts.max_connections);
            var i = opts.max_connections;
            while (i > 0) {
                i -= 1;
                self.free.appendAssumeCapacity(i);
            }
            try self.by_cid.ensureTotalCapacity(allocator, opts.max_connections);
            try self.by_odcid.ensureTotalCapacity(allocator, opts.max_connections);
            try self.dirty.ensureTotalCapacity(allocator, opts.max_connections);
            return self;
        }

        /// The worker's request, response, exchange slab and read buffers,
        /// which HTTP/3 shares with its TCP connections.
        pub fn bindWorker(self: *Self, handler: *Handler, req: *Request, resp: *Response, date_line: *const [date.header_len]u8, now_s: *const u32, exchanges: *exchange.Slab, pool: *BufferPool) void {
            self.handler = handler;
            self.req = req;
            self.resp = resp;
            self.date_line = date_line;
            self.now_s = now_s;
            self.exchanges = exchanges;
            self.pool = pool;
        }

        pub fn deinit(self: *Self) void {
            for (self.slots, 0..) |*s, i| {
                if (s.q != null) self.destroy(@intCast(i), 0);
            }
            const a = self.allocator;
            a.free(self.slots);
            self.free.deinit(a);
            self.by_cid.deinit(a);
            self.by_odcid.deinit(a);
            self.heap.deinit(a);
            self.dirty.deinit(a);
            a.destroy(self.batch);
            a.free(self.send_buf);
            std.crypto.secureZero(u8, &self.reset_key);
            std.crypto.secureZero(u8, &self.token_key);
        }

        pub fn connections(self: *const Self) u32 {
            return self.count;
        }

        fn ctx(self: *Self, slot: u32, now_us: u64) h3.Context(Handler) {
            return .{
                .handler = self.handler,
                .req = self.req,
                .resp = self.resp,
                .date = self.date_line,
                .now = self.now_s.*,
                .now_us = now_us,
                .exchanges = self.exchanges,
                .conn_slot = slot | exchange_slot_flag,
                .conn_gen = self.slots[slot].gen,
                .pool = self.pool,
                .fd = self.fd,
                .early_data = if (self.slots[slot].q) |q| q.inEarlyData() else false,
            };
        }

        // -- Receiving ------------------------------------------------------------

        pub fn onReadable(self: *Self, now_us: u64) void {
            // A bounded number of batches per wake-up, fair to TCP.
            for (0..16) |_| {
                const n = self.batch.recv(self.fd);
                for (0..n) |i| {
                    const d = self.batch.get(i);
                    self.onDatagram(d.data, &d.from, d.ecn, now_us);
                }
                if (n < batch_len) break;
            }
            self.flushDirty(now_us);
        }

        fn onDatagram(self: *Self, data: []u8, from: *const udp.Addr, ecn: packet.Ecn, now_us: u64) void {
            // Port 0 is no address to answer at (and a send there fails).
            if (data.len == 0 or from.port() == 0) return;
            const cid_len = self.opts.quic.cid_len;
            var slot: ?u32 = null;
            if (data[0] & 0x80 == 0) {
                if (data.len < 1 + cid_len) return;
                slot = self.by_cid.get(std.mem.readInt(u64, data[1..9], .little));
                if (slot == null) return self.statelessReset(data, from, now_us);
            } else {
                const h = packet.parseHeader(data, cid_len) catch return;
                if (h.type == .unsupported_version) {
                    // §6.1, §14.1: only for datagrams a client's Initial could be.
                    if (data.len < packet.min_initial_datagram) return;
                    var out: [7 + 2 * 255 + 8]u8 = undefined;
                    const n = packet.writeVersionNegotiation(&out, h, self.rng.random().int(u8));
                    udp.send(self.fd, from, out[0..n], null, .not_ect) catch {};
                    return;
                }
                if (h.dcid.len == cid_len and cid_len == 8) slot = self.by_cid.get(std.mem.readInt(u64, h.dcid[0..8], .little));
                if (slot == null) slot = self.by_odcid.get(CidKey.init(h.dcid));
                if (slot == null) {
                    if (h.type != .initial or self.shutting_down) return;
                    // §14.1: a client's Initial comes in a full-size datagram;
                    // §7.2: its first DCID has at least 8 bytes.
                    if (data.len < packet.min_initial_datagram or h.dcid.len < 8) return;
                    slot = self.accept(h, data, from, ecn, now_us) orelse return;
                    return;
                }
            }
            const s = slot.?;
            const st = &self.slots[s];
            if (st.q.?.recv(data, ecn, now_us) and !st.peer.eql(from)) {
                // The newest non-probing packet, authenticated, from a new
                // address (NAT rebinding; we ask clients not to migrate; a
                // reordered datagram from the old one doesn't count, RFC
                // 9000 §9.3): answer there, and test ECN on the new path.
                st.peer = from.*;
                st.q.?.onPathChange();
            }
            self.markDirty(s);
        }

        fn markDirty(self: *Self, slot: u32) void {
            const st = &self.slots[slot];
            if (st.dirty) return;
            st.dirty = true;
            self.dirty.appendAssumeCapacity(slot);
        }

        /// A new connection from a client's first Initial.
        fn accept(self: *Self, h: packet.Header, data: []u8, from: *const udp.Addr, ecn: packet.Ecn, now_us: u64) ?u32 {
            var retry_scid: ?[]const u8 = null;
            var odcid = h.dcid;
            var odcid_buf: [packet.max_cid_len]u8 = undefined;
            if (self.opts.retry == .always) {
                if (h.token.len == 0) {
                    self.sendRetry(h, from, now_us);
                    return null;
                }
                // The token carries the original DCID; the client's current
                // DCID is the SCID our Retry gave it.
                const len = self.validateToken(h.token, from, now_us, &odcid_buf) orelse return null;
                odcid = odcid_buf[0..len];
                retry_scid = h.dcid;
            }
            const slot = self.free.pop() orelse return null;
            const st = &self.slots[slot];
            var scid: [8]u8 = undefined;
            while (true) {
                self.newCid(&scid);
                if (!self.by_cid.contains(std.mem.readInt(u64, &scid, .little))) break;
            }
            var entropy: [handshake.entropy_len]u8 = undefined;
            self.rng.fill(&entropy);
            defer std.crypto.secureZero(u8, &entropy);
            const q = quic.Conn.init(self.allocator, &self.opts.quic, .{
                .odcid = odcid,
                .client_scid = h.scid,
                .scid = &scid,
                .reset_token = self.resetToken(&scid),
                .retry_scid = retry_scid,
                .entropy = &entropy,
                .now = now_us,
            }) catch {
                self.free.appendAssumeCapacity(slot);
                return null;
            };
            const hc = h3.Conn.init(self.allocator, self.opts.h3, q) catch {
                q.deinit();
                self.free.appendAssumeCapacity(slot);
                return null;
            };
            const gen = st.gen +% 1;
            st.* = .{ .q = q, .h = hc, .gen = gen, .peer = from.*, .cid = std.mem.readInt(u64, &scid, .little) };
            self.by_cid.putAssumeCapacity(st.cid, slot);
            // Until the client switches to our ID, its Initials use the
            // DCID it chose (after a Retry: the one the Retry gave it).
            st.odcid = CidKey.init(h.dcid);
            self.by_odcid.putAssumeCapacity(st.odcid, slot);
            self.count += 1;
            _ = q.recv(data, ecn, now_us);
            self.markDirty(slot);
            return slot;
        }

        /// An 8-byte connection ID whose first byte names this worker
        /// (modulo the worker count, as the steering program reads it).
        fn newCid(self: *Self, out: *[8]u8) void {
            self.rng.fill(out);
            const count = @max(self.opts.worker_count, 1);
            const index = self.opts.worker_index;
            const choices = (255 - @as(u32, index)) / count + 1;
            out[0] = @intCast(index + count * self.rng.random().uintLessThan(u32, choices));
        }

        fn resetToken(self: *const Self, cid: []const u8) [16]u8 {
            var mac: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&mac, cid, &self.reset_key);
            return mac[0..16].*;
        }

        /// RFC 9000 §10.3: a packet that looks like a short header packet
        /// and ends with the reset token of the DCID it was sent to.
        fn statelessReset(self: *Self, data: []const u8, from: *const udp.Addr, now_us: u64) void {
            const cid_len = self.opts.quic.cid_len;
            // Smaller than what triggered it (no loops), at least 21 bytes.
            if (data.len < 22 or data.len < 1 + cid_len) return;
            const second = now_us / std.time.us_per_s;
            if (second != self.resets_second) {
                self.resets_second = second;
                self.resets = 0;
            }
            if (self.resets >= self.opts.max_resets_per_second) return;
            self.resets += 1;
            var out: [43]u8 = undefined;
            const len = @min(data.len - 1, out.len);
            self.rng.fill(out[0 .. len - 16]);
            out[0] = 0x40 | (out[0] & 0x3f);
            out[len - 16 ..][0..16].* = self.resetToken(data[1 .. 1 + cid_len]);
            udp.send(self.fd, from, out[0..len], null, .not_ect) catch {};
        }

        // -- Retry (address validation) -------------------------------------

        /// Token: nonce, then sealed {seconds, ODCID length, ODCID}, bound
        /// to the client's address as associated data.
        fn sendRetry(self: *Self, h: packet.Header, from: *const udp.Addr, now_us: u64) void {
            var token: [12 + 4 + 1 + packet.max_cid_len + 16]u8 = undefined;
            const nonce = token[0..12];
            self.rng.fill(nonce);
            var plain: [4 + 1 + packet.max_cid_len]u8 = undefined;
            std.mem.writeInt(u32, plain[0..4], @intCast(now_us / std.time.us_per_s), .big);
            plain[4] = @intCast(h.dcid.len);
            @memcpy(plain[5..][0..h.dcid.len], h.dcid);
            const plen = 5 + h.dcid.len;
            Aes128Gcm.encrypt(token[12..][0..plen], token[12 + plen ..][0..16], plain[0..plen], from.bytes(), nonce.*, self.token_key);
            var scid: [8]u8 = undefined;
            self.newCid(&scid);
            var out: [7 + 2 * packet.max_cid_len + token.len + 16]u8 = undefined;
            const n = protection.writeRetry(&out, h.dcid, h.scid, &scid, token[0 .. 12 + plen + 16], self.rng.random().int(u8));
            udp.send(self.fd, from, out[0..n], null, .not_ect) catch {};
        }

        /// The original DCID from a valid token, or null.
        fn validateToken(self: *Self, token: []const u8, from: *const udp.Addr, now_us: u64, odcid: *[packet.max_cid_len]u8) ?usize {
            if (token.len < 12 + 5 + 16 or token.len > 12 + 5 + packet.max_cid_len + 16) return null;
            const plen = token.len - 12 - 16;
            var plain: [5 + packet.max_cid_len]u8 = undefined;
            Aes128Gcm.decrypt(plain[0..plen], token[12..][0..plen], token[token.len - 16 ..][0..16].*, from.bytes(), token[0..12].*, self.token_key) catch return null;
            const issued = std.mem.readInt(u32, plain[0..4], .big);
            const now_s: u32 = @intCast(now_us / std.time.us_per_s);
            if (now_s -% issued > 10) return null;
            const len = plain[4];
            if (len != plen - 5) return null;
            @memcpy(odcid[0..len], plain[5..][0..len]);
            return len;
        }

        // -- Running connections ----------------------------------------------

        /// Runs HTTP/3 on every connection that received something, sends
        /// what they have, and reschedules their timers.
        fn flushDirty(self: *Self, now_us: u64) void {
            var i: usize = 0;
            while (i < self.dirty.items.len) : (i += 1) {
                const slot = self.dirty.items[i];
                self.slots[slot].dirty = false;
                self.service(slot, now_us);
            }
            self.dirty.clearRetainingCapacity();
        }

        fn service(self: *Self, slot: u32, now_us: u64) void {
            const st = &self.slots[slot];
            const q = st.q orelse return;
            const c = self.ctx(slot, now_us);
            st.h.?.process(Handler, &c);
            self.flush(slot, now_us);
            if (q.isClosed()) return self.destroy(slot, now_us);
            if (!q.isEstablished() or q.spaces[0].discarded) {
                // The client stopped using its original DCID once it sent
                // a Handshake packet.
                if (q.spaces[0].discarded and st.odcid.len > 0) {
                    _ = self.by_odcid.remove(st.odcid);
                    st.odcid.len = 0;
                }
            }
            self.schedule(slot);
        }

        fn flush(self: *Self, slot: u32, now_us: u64) void {
            const st = &self.slots[slot];
            const q = st.q.?;
            const seg: usize = q.max_datagram;
            var pos: usize = 0;
            var segments: usize = 0;
            // One GSO send has one ECN codepoint: a change ends the batch.
            var ecn: packet.Ecn = .not_ect;
            while (true) {
                const next_ecn: packet.Ecn = if (self.tos_refused[udp.tosKind(&st.peer)]) .not_ect else q.sendEcn();
                if (pos + seg > self.send_buf.len or (pos > 0 and next_ecn != ecn)) {
                    self.sendOut(st, pos, seg, segments, ecn);
                    pos = 0;
                    segments = 0;
                }
                ecn = next_ecn;
                const n = q.send(self.send_buf[pos..][0..seg], now_us);
                if (n == 0) break;
                if (!self.gso) {
                    self.sendTo(&st.peer, self.send_buf[0..n], null, ecn);
                    continue;
                }
                pos += n;
                segments += 1;
                // GSO sends equal segments with a shorter last one: a short
                // datagram ends the batch.
                if (n < seg or segments == 64) {
                    self.sendOut(st, pos, seg, segments, ecn);
                    pos = 0;
                    segments = 0;
                }
            }
            if (pos > 0) self.sendOut(st, pos, seg, segments, ecn);
        }

        fn sendOut(self: *Self, st: *Slot, len: usize, seg: usize, segments: usize, ecn: packet.Ecn) void {
            if (len == 0) return;
            self.sendTo(&st.peer, self.send_buf[0..len], if (segments > 1) @intCast(seg) else null, ecn);
        }

        fn sendTo(self: *Self, to: *const udp.Addr, data: []const u8, segment: ?u16, ecn: packet.Ecn) void {
            udp.send(self.fd, to, data, segment, ecn) catch |err| switch (err) {
                error.TosRefused => self.tos_refused[udp.tosKind(to)] = true,
                // A send that fails is a lost packet to QUIC; recovery
                // resends.
                error.WouldBlock, error.Unexpected => {},
            };
        }

        fn destroy(self: *Self, slot: u32, now_us: u64) void {
            const st = &self.slots[slot];
            if (st.h) |hc| {
                const c = self.ctx(slot, now_us);
                hc.abortAll(&c);
                hc.deinit();
            }
            st.q.?.deinit();
            _ = self.by_cid.remove(st.cid);
            if (st.odcid.len > 0) _ = self.by_odcid.remove(st.odcid);
            st.* = .{ .gen = st.gen };
            self.free.appendAssumeCapacity(slot);
            self.count -= 1;
        }

        // -- Timers ---------------------------------------------------------

        fn schedule(self: *Self, slot: u32) void {
            const st = &self.slots[slot];
            const d = st.q.?.deadline() orelse {
                st.scheduled = null;
                return;
            };
            if (st.scheduled != null and st.scheduled.? == d) return;
            st.scheduled = d;
            self.heapPush(.{ .at = d, .slot = slot, .gen = st.gen });
        }

        /// Runs expired connection timers.
        pub fn onTimers(self: *Self, now_us: u64) void {
            // Expired connections are collected first and serviced once
            // each: a deadline that is still due afterwards waits for the
            // next turn instead of spinning here.
            while (self.heap.items.len > 0 and self.heap.items[0].at <= now_us) {
                const t = self.heapPop();
                const st = &self.slots[t.slot];
                if (st.q == null or st.gen != t.gen or st.scheduled == null or st.scheduled.? != t.at) continue;
                st.scheduled = null;
                st.q.?.onTimeout(now_us);
                self.markDirty(t.slot);
            }
            self.flushDirty(now_us);
            // Stale entries pile up as deadlines move: rebuild now and then.
            if (self.heap.items.len > 4 * @as(usize, self.count) + 1024) self.rebuildHeap();
        }

        /// Milliseconds until the next timer (rounded up), or null for none.
        pub fn timeoutMs(self: *Self, now_us: u64) ?i32 {
            while (self.heap.items.len > 0) {
                const t = self.heap.items[0];
                const st = &self.slots[t.slot];
                if (st.q == null or st.gen != t.gen or st.scheduled == null or st.scheduled.? != t.at) {
                    _ = self.heapPop();
                    continue;
                }
                if (t.at <= now_us) return 0;
                return @intCast(@min((t.at - now_us + 999) / 1000, std.math.maxInt(i32)));
            }
            return null;
        }

        fn rebuildHeap(self: *Self) void {
            self.heap.clearRetainingCapacity();
            for (self.slots, 0..) |*st, i| {
                if (st.q == null) continue;
                if (st.scheduled) |d| self.heapPush(.{ .at = d, .slot = @intCast(i), .gen = st.gen });
            }
        }

        fn heapPush(self: *Self, t: Timer) void {
            self.heap.append(self.allocator, t) catch return;
            var i = self.heap.items.len - 1;
            const items = self.heap.items;
            while (i > 0) {
                const parent = (i - 1) / 2;
                if (items[parent].at <= items[i].at) break;
                std.mem.swap(Timer, &items[parent], &items[i]);
                i = parent;
            }
        }

        fn heapPop(self: *Self) Timer {
            const items = self.heap.items;
            const top = items[0];
            const last = self.heap.pop().?;
            if (self.heap.items.len == 0) return top;
            self.heap.items[0] = last;
            var i: usize = 0;
            const h = self.heap.items;
            while (true) {
                const l = 2 * i + 1;
                if (l >= h.len) break;
                var m = l;
                if (l + 1 < h.len and h[l + 1].at < h[l].at) m = l + 1;
                if (h[i].at <= h[m].at) break;
                std.mem.swap(Timer, &h[i], &h[m]);
                i = m;
            }
            return top;
        }

        // -- Exchanges and shutdown ---------------------------------------------

        fn slotFor(self: *Self, conn_slot: u32, conn_gen: u32) ?u32 {
            const slot = conn_slot & ~exchange_slot_flag;
            if (slot >= self.slots.len) return null;
            const st = &self.slots[slot];
            if (st.q == null or st.gen != conn_gen) return null;
            return slot;
        }

        pub fn onExchangePosted(self: *Self, conn_slot: u32, conn_gen: u32, ex_slot: u32, now_us: u64) void {
            const slot = self.slotFor(conn_slot, conn_gen) orelse return;
            const c = self.ctx(slot, now_us);
            self.slots[slot].h.?.onExchangePosted(Handler, &c, ex_slot);
            self.service(slot, now_us);
        }

        pub fn onExchangeTimeout(self: *Self, conn_slot: u32, conn_gen: u32, ex_slot: u32, now_us: u64) void {
            const slot = self.slotFor(conn_slot, conn_gen) orelse return;
            const c = self.ctx(slot, now_us);
            self.slots[slot].h.?.onExchangeTimeout(Handler, &c, ex_slot);
            self.service(slot, now_us);
        }

        /// GOAWAY on every connection; new connections are refused.
        pub fn shutdown(self: *Self, now_us: u64) void {
            self.shutting_down = true;
            for (self.slots, 0..) |*st, i| {
                const hc = st.h orelse continue;
                hc.shutdown(now_us);
                self.service(@intCast(i), now_us);
            }
        }
    };
}
