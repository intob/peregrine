//! Completion-based (io_uring) event loop for Linux. Same Session state
//! machine as worker.zig, different I/O:
//!
//! - multishot accept on the worker's own SO_REUSEPORT listener
//! - recv with kernel-selected provided buffers, so idle connections hold no
//!   buffer; a recv is armed only when the connection is ready for more input
//!   (natural backpressure). A connection holding part of a request, record
//!   or frame receives the rest straight into that buffer instead
//! - writes queued as SQEs, so one io_uring_enter submits every recv and write
//!   produced by a batch of completions
//! - TLS like worker.zig: records are decrypted in place in the kernel buffer
//!   or straight into the session; output is encrypted from the connection's
//!   Out as the wire buffer drains
const std = @import("std");
const linux = std.os.linux;
const IoUring = linux.IoUring;
const sys = @import("../sys.zig");
const session = @import("./session.zig");
const date = @import("./date.zig");
const Session = session.Session;
const BufferPool = session.BufferPool;
const Out = session.Out;
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const ws = @import("../ws/conn.zig");
const WsConn = ws.Conn;
const tls = @import("../tls/conn.zig");
const TlsConn = tls.Conn;
const Options = @import("./worker.zig").Options;
const mailbox_mod = @import("../mailbox.zig");
const Mailbox = mailbox_mod.Mailbox;
const exchange = @import("./exchange.zig");
const quic_endpoint = @import("../quic/endpoint.zig");
const h2 = @import("../h2/conn.zig");
const H2Conn = h2.Conn;
const h2_preface = @import("../h2/frame.zig").preface;

const NIL: u32 = std.math.maxInt(u32);
const SPECIAL_SLOT: u32 = 0xFF_FFFF;
const BUFFER_GROUP_ID: u16 = 1;

const Op = enum(u8) {
    recv,
    recv_plain,
    write,
    cancel,
    accept,
    waker,
    tick,
    /// The HTTP/3 UDP socket is readable (multishot poll).
    udp,
    /// The next QUIC timer.
    quic_timer,
};

inline fn userData(gen: u32, slot: u32, op: Op) u64 {
    return (@as(u64, gen) << 32) | (@as(u64, slot) << 8) | @backingInt(op);
}

/// Whether io_uring with the features this worker needs is usable (it may be
/// disabled by seccomp in containers, or by sysctl).
pub fn available() bool {
    var ring = IoUring.init(8, 0) catch return false;
    defer ring.deinit();
    const probe = ring.get_probe() catch return false;
    return probe.is_supported(.ACCEPT) and probe.is_supported(.RECV) and
        probe.is_supported(.WRITEV) and probe.is_supported(.ASYNC_CANCEL) and
        probe.is_supported(.TIMEOUT);
}

pub fn Worker(comptime Handler: type) type {
    return struct {
        const Self = @This();

        const ListId = enum(u8) { none, idle, active };

        const Conn = struct {
            fd: sys.fd_t = -1,
            gen: u32 = 0,
            open: bool = false,
            closing: bool = false,
            /// Operations submitted to the kernel and not yet completed. The
            /// slot is only reused once this is zero.
            inflight: u8 = 0,
            recv_armed: bool = false,
            write_inflight: bool = false,
            peer_closed: bool = false,
            /// Draining input after an error response (see Session.linger).
            lingering: bool = false,
            lingered: u32 = 0,
            after_write: enum(u8) { none, close, upgrade, exchange_done } = .none,
            list: ListId = .none,
            prev: u32 = NIL,
            next: u32 = NIL,
            deadline: u32 = 0,
            session: Session = .{},
            /// Set after a WebSocket upgrade; the session is then unused.
            ws: ?*WsConn = null,
            /// Set on TLS listeners: sits between the socket and the
            /// session (or the WebSocket decoder).
            tls: ?*TlsConn = null,
            /// Set once the connection speaks HTTP/2 (ALPN or h2c).
            h2: ?*H2Conn = null,
            proto_decided: bool = false,
            /// The session buffer is a kernel-provided recv buffer.
            borrowed: bool = false,
            /// This connection's output. Owned while a write is in flight.
            out: Out = .{ .buf = &.{} },
            out_body_owned: []u8 = &.{},
            /// Bytes of `out` written, or with TLS, encrypted.
            sent: usize = 0,
            iov: [3]sys.iovec_const = undefined,
            /// The exchange whose response this connection is waiting
            /// for or writing (a slot in the worker's slab), or NIL.
            exchange: u32 = NIL,
            /// Borrowed exchange bytes in `out`, released once written.
            release: ?exchange.Release = null,
        };

        const List = struct {
            head: u32 = NIL,
            tail: u32 = NIL,
            timeout: u32,
        };

        id: usize,
        allocator: std.mem.Allocator,
        handler: *Handler,
        shutdown: *const std.atomic.Value(bool),
        opts: Options,
        ring: IoUring,
        buffers: IoUring.BufferGroup,
        /// SINGLE_ISSUER: once the worker thread has enabled the ring, only it
        /// may unregister the buffer ring, so it does so as it exits.
        buffers_live: bool = false,
        listener: sys.fd_t,
        waker: sys.Waker,
        waker_buf: u64 = 0,
        /// WebSocket connections and exchanges with new output (posted
        /// from any thread).
        mailbox: Mailbox,
        exchanges: exchange.Slab = undefined,
        tick_ts: linux.kernel_timespec = .{ .sec = 1, .nsec = 0 },
        tick_armed: bool = false,
        /// HTTP/3 connections on this worker's UDP socket.
        quic: ?quic_endpoint.Endpoint(Handler) = null,
        udp: sys.fd_t = -1,
        quic_ts: linux.kernel_timespec = .{ .sec = 0, .nsec = 0 },
        /// When the armed QUIC timeout fires (monotonic microseconds).
        quic_timer_at: ?u64 = null,
        conns: []Conn,
        free_slots: []u32,
        free_len: usize,
        /// Session buffers for leftovers (partial requests) and large bodies.
        pool: BufferPool,
        /// Per-connection output buffers.
        out_pool: BufferPool,
        req: *Request,
        resp: *Response,
        date_line: [date.header_len]u8 = undefined,
        now: u32,
        last_realtime: i64 = 0,
        idle: List,
        active: List,
        open_count: usize = 0,
        h2_count: usize = 0,
        thread: ?std.Thread = null,
        tls_pools: ?tls.Pools = null,
        /// Handshake randomness, seeded from the OS once per worker.
        rng: std.Random.ChaCha,

        pub const InitConfig = struct {
            id: usize,
            allocator: std.mem.Allocator,
            handler: *Handler,
            shutdown: *const std.atomic.Value(bool),
            listener: sys.fd_t,
            opts: Options,
            ring_entries: u16 = 4096,
            recv_buffer_count: u16 = 256,
            /// A UDP socket for HTTP/3 (with `opts.quic`), owned by the worker.
            udp: sys.fd_t = -1,
        };

        pub fn init(self: *Self, cfg: InitConfig) !void {
            const allocator = cfg.allocator;
            const opts = cfg.opts;
            const req = try Request.init(allocator);
            errdefer req.deinit();
            const resp = try Response.init(allocator, opts.response_body_buffer_size, opts.response_header_buffer_size);
            errdefer resp.deinit();
            const out_size = @max(session.headRoom(resp), 16 * 1024);
            const waker = try sys.Waker.init();
            errdefer waker.deinit();
            var mailbox = try Mailbox.init(allocator, opts.max_connections + opts.max_exchanges, waker);
            errdefer mailbox.deinit();
            const conns = try allocator.alloc(Conn, opts.max_connections);
            errdefer allocator.free(conns);
            @memset(conns, .{});
            const free_slots = try allocator.alloc(u32, opts.max_connections);
            errdefer allocator.free(free_slots);
            for (free_slots, 0..) |*s, i| s.* = @intCast(opts.max_connections - 1 - i);
            var pool = try BufferPool.init(allocator, opts.read_buffer_size, opts.buffer_pool_size / 4 + 1);
            errdefer pool.deinit();
            var out_pool = try BufferPool.init(allocator, out_size, opts.buffer_pool_size);
            errdefer out_pool.deinit();
            var tls_pools: ?tls.Pools = if (opts.tls != null) try tls.Pools.init(allocator, opts.tls_buffer_pool_size) else null;
            errdefer if (tls_pools) |*p| p.deinit();
            var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
            sys.randomBytes(&seed);
            defer std.crypto.secureZero(u8, &seed);
            self.* = .{
                .id = cfg.id,
                .allocator = allocator,
                .handler = cfg.handler,
                .shutdown = cfg.shutdown,
                .opts = opts,
                .ring = undefined,
                .buffers = undefined,
                .listener = cfg.listener,
                .waker = waker,
                .mailbox = mailbox,
                .conns = conns,
                .free_slots = free_slots,
                .free_len = free_slots.len,
                .pool = pool,
                .out_pool = out_pool,
                .req = req,
                .resp = resp,
                .now = sys.monotonicSeconds(),
                .idle = .{ .timeout = opts.keep_alive_timeout_s },
                .active = .{ .timeout = opts.request_timeout_s },
                .tls_pools = tls_pools,
                .rng = .init(seed),
            };
            // SINGLE_ISSUER + DEFER_TASKRUN: completions are only processed
            // when this worker enters the kernel, with no cross-thread
            // locking. The ring is bound to the first thread that enables it,
            // so it starts disabled and the worker thread enables it in run().
            self.ring = try IoUring.init(cfg.ring_entries, linux.IORING_SETUP_SINGLE_ISSUER |
                linux.IORING_SETUP_DEFER_TASKRUN | linux.IORING_SETUP_R_DISABLED);
            errdefer self.ring.deinit();
            // Note: BufferGroup stores a pointer to the ring, so the ring must
            // not move after this (the worker lives in a stable slice).
            self.buffers = try IoUring.BufferGroup.init(
                &self.ring,
                allocator,
                BUFFER_GROUP_ID,
                @intCast(opts.read_buffer_size),
                cfg.recv_buffer_count,
            );
            self.buffers_live = true;
            self.exchanges = try exchange.Slab.init(allocator, opts.max_exchanges, &self.mailbox, opts.exchange);
            errdefer self.exchanges.deinit();
            self.resp.exchanges = &self.exchanges;
            self.resp.now = &self.now;
            try self.resp.setPresetHeaders(opts.preset_headers);
            self.refreshDate();
            if (cfg.udp >= 0) {
                if (opts.quic) |qopts| {
                    self.udp = cfg.udp;
                    self.quic = try .init(allocator, qopts, cfg.udp);
                    self.quic.?.bindWorker(self.handler, self.req, self.resp, &self.date_line, &self.now, &self.exchanges);
                }
            }
        }

        pub fn spawn(self: *Self, stack_size: usize, pin: bool) !void {
            self.thread = try std.Thread.spawn(.{ .stack_size = stack_size }, run, .{ self, pin });
        }

        pub fn wake(self: *Self) void {
            self.waker.wake();
        }

        pub fn join(self: *Self) void {
            if (self.thread) |t| t.join();
            self.thread = null;
        }

        pub fn deinit(self: *Self) void {
            for (self.conns) |*c| {
                if (c.open) {
                    sys.close(c.fd);
                    self.freeConnResources(c);
                }
            }
            sys.close(self.listener);
            if (self.quic) |*ep| ep.deinit();
            if (self.udp >= 0) sys.close(self.udp);
            self.freeBuffers();
            self.ring.deinit();
            self.exchanges.deinit();
            self.mailbox.deinit();
            self.waker.deinit();
            self.pool.deinit();
            self.out_pool.deinit();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.conns);
            self.allocator.free(self.free_slots);
            if (self.tls_pools) |*p| p.deinit();
        }

        fn freeBuffers(self: *Self) void {
            if (!self.buffers_live) return;
            self.buffers.deinit(self.allocator);
            self.buffers_live = false;
        }

        fn run(self: *Self, pin: bool) void {
            defer self.freeBuffers();
            if (pin) sys.pinToCpu(self.id);
            self.mailbox.bind();
            const rc = linux.io_uring_register(self.ring.fd, .REGISTER_ENABLE_RINGS, null, 0);
            if (std.posix.errno(rc) != .SUCCESS) {
                std.debug.print("io_uring enable failed: {s}\n", .{@tagName(std.posix.errno(rc))});
                return;
            }
            self.armAccept();
            self.armWaker();
            if (self.quic != null) self.armUdp();
            var cqes: [512]linux.io_uring_cqe = undefined;
            while (!self.shutdown.load(.acquire)) {
                _ = self.ring.submit_and_wait(1) catch |err| switch (err) {
                    error.SignalInterrupt => continue,
                    else => {
                        std.debug.print("io_uring submit failed: {s}\n", .{@errorName(err)});
                        return;
                    },
                };
                const n = self.ring.copy_cqes(&cqes, 0) catch 0;
                self.tick();
                for (cqes[0..n]) |cqe| self.dispatch(cqe);
                // WebSocket output queued by handlers during this batch, or
                // by other threads (which also wrote the waker).
                self.drainMailbox();
                if (self.quic) |*ep| {
                    ep.onTimers(nowUs());
                    self.armQuicTimer();
                }
            }
            if (self.quic) |*ep| ep.shutdown(nowUs());
            // Shutting down: one GOAWAY per HTTP/2 connection, best effort.
            for (self.conns) |*c| {
                if (!c.open or c.h2 == null or c.closing or c.write_inflight) continue;
                const conn = c.h2.?;
                conn.shutdown();
                if (c.tls) |t| {
                    if (t.isEstablished() and !t.hasWire()) {
                        const n = t.encrypt(&.{conn.wireBytes()}) catch 0;
                        conn.advance(n);
                        tlsWriteOnce(c, t);
                    }
                } else {
                    const n = sys.write(c.fd, conn.wireBytes()) catch 0;
                    conn.advance(n);
                }
            }
        }

        fn dispatch(self: *Self, cqe: linux.io_uring_cqe) void {
            const ud = cqe.user_data;
            const op: Op = @fromBackingInt(@intCast(@as(u8, @truncate(ud))));
            const slot: u32 = @truncate((ud >> 8) & 0xFF_FFFF);
            const gen: u32 = @intCast(ud >> 32);
            switch (op) {
                .accept => return self.onAccept(cqe),
                .waker => return self.armWaker(),
                .tick => {
                    self.tick_armed = false;
                    self.armTick();
                    return;
                },
                .udp => {
                    self.quic.?.onReadable(nowUs());
                    if (cqe.flags & linux.IORING_CQE_F_MORE == 0) self.armUdp();
                    return;
                },
                .quic_timer => {
                    // Timers run after the batch; arm the next one then.
                    if (self.quic_timer_at) |at| {
                        if (at <= nowUs()) self.quic_timer_at = null;
                    }
                    return;
                },
                else => {},
            }
            const c = &self.conns[slot];
            if (c.gen != gen) return; // completions of a reused slot never happen (inflight gating)
            c.inflight -= 1;
            switch (op) {
                .recv => self.onRecv(c, cqe),
                .recv_plain => self.onRecvPlain(c, cqe),
                .write => if (c.ws != null) self.onWsWrite(c, cqe) else if (c.h2 != null) self.onH2Write(c, cqe) else self.onWrite(c, cqe),
                .cancel => {},
                else => unreachable,
            }
            if (c.closing and c.inflight == 0) self.finishClose(c);
        }

        // -- SQE helpers ---------------------------------------------------

        fn getSqe(self: *Self) *linux.io_uring_sqe {
            while (true) {
                return self.ring.get_sqe() catch {
                    // Full: flush what we have to the kernel and retry.
                    _ = self.ring.submit() catch {};
                    continue;
                };
            }
        }

        fn armAccept(self: *Self) void {
            const sqe = self.getSqe();
            sqe.prep_multishot_accept(self.listener, null, null, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC);
            sqe.user_data = userData(0, SPECIAL_SLOT, .accept);
        }

        fn nowUs() u64 {
            return sys.nanoTimestamp() / std.time.ns_per_us;
        }

        fn armUdp(self: *Self) void {
            const sqe = self.getSqe();
            sqe.prep_poll_add(self.udp, linux.POLL.IN);
            sqe.len = linux.IORING_POLL_ADD_MULTI;
            sqe.user_data = userData(0, SPECIAL_SLOT, .udp);
        }

        /// A timeout for the earliest QUIC timer, unless one at least as
        /// early is armed already.
        fn armQuicTimer(self: *Self) void {
            const now = nowUs();
            const ms = self.quic.?.timeoutMs(now) orelse return;
            const at = now + @as(u64, @intCast(ms)) * 1000;
            if (self.quic_timer_at) |armed| {
                if (armed <= at and armed > now) return;
            }
            self.quic_timer_at = at;
            self.quic_ts = .{ .sec = @intCast(@divTrunc(ms, 1000)), .nsec = @intCast(@rem(ms, 1000) * std.time.ns_per_ms) };
            const sqe = self.getSqe();
            sqe.prep_timeout(&self.quic_ts, 0, 0);
            sqe.user_data = userData(0, SPECIAL_SLOT, .quic_timer);
            // The connection tick also drives HTTP/3 exchange deadlines.
            self.armTick();
        }

        fn armWaker(self: *Self) void {
            const sqe = self.getSqe();
            sqe.prep_read(self.waker.read_fd, std.mem.asBytes(&self.waker_buf), 0);
            sqe.user_data = userData(0, SPECIAL_SLOT, .waker);
        }

        fn armTick(self: *Self) void {
            const quic_conns = if (self.quic) |*ep| ep.connections() else 0;
            if (self.tick_armed or (self.open_count == 0 and quic_conns == 0)) return;
            const sqe = self.getSqe();
            sqe.prep_timeout(&self.tick_ts, 0, 0);
            sqe.user_data = userData(0, SPECIAL_SLOT, .tick);
            self.tick_armed = true;
        }

        fn armRecv(self: *Self, c: *Conn) void {
            if (c.recv_armed or c.closing or c.peer_closed) return;
            if (!c.lingering and holdsPartialInput(c)) return self.armRecvPlain(c);
            const sqe = self.getSqe();
            sqe.prep_rw(.RECV, c.fd, 0, 0, 0);
            sqe.flags |= linux.IOSQE_BUFFER_SELECT;
            sqe.buf_index = BUFFER_GROUP_ID;
            sqe.user_data = userData(c.gen, self.slotOf(c), .recv);
            c.recv_armed = true;
            c.inflight += 1;
        }

        /// Whether the connection holds part of a request, TLS record or
        /// WebSocket frame. The rest is then received straight into the
        /// buffer holding it, as on epoll: through a kernel buffer it would
        /// be copied, and requests split across two receives are common
        /// (most 12 KiB uploads under load).
        fn holdsPartialInput(c: *const Conn) bool {
            std.debug.assert(!c.borrowed);
            if (c.tls) |t| return t.partialRecordNeed() > 0;
            if (c.ws) |w| return w.decoder.buf.len > 0;
            if (c.h2) |conn| return conn.reader.buf.len > 0;
            return c.session.buf.len > 0;
        }

        /// Receives into a pooled buffer: the one holding partial input, or
        /// a fresh one when the provided-buffer ring is exhausted.
        fn armRecvPlain(self: *Self, c: *Conn) void {
            const space = if (c.tls) |t|
                t.readSpace() catch return self.closeConn(c)
            else if (c.ws) |w|
                w.decoder.readSpace(&self.pool) catch return self.closeConn(c)
            else if (c.h2) |conn|
                conn.readSpace(&self.pool) catch return self.closeConn(c)
            else
                c.session.readSpace(&self.pool, self.opts.session) catch return self.closeConn(c);
            const sqe = self.getSqe();
            sqe.prep_recv(c.fd, space, 0);
            sqe.user_data = userData(c.gen, self.slotOf(c), .recv_plain);
            c.recv_armed = true;
            c.inflight += 1;
        }

        fn submitWrite(self: *Self, c: *Conn) void {
            var n: usize = 0;
            const head_rest = c.out.buf[@min(c.sent, c.out.len)..c.out.len];
            if (head_rest.len > 0) {
                c.iov[n] = .{ .base = head_rest.ptr, .len = head_rest.len };
                n += 1;
            }
            const body_sent = c.sent -| c.out.len;
            if (c.out.body.len > body_sent) {
                const rest = c.out.body[body_sent..];
                c.iov[n] = .{ .base = rest.ptr, .len = rest.len };
                n += 1;
            }
            const tail_sent = c.sent -| (c.out.len + c.out.body.len);
            if (c.out.tail.len > tail_sent) {
                const rest = c.out.tail[tail_sent..];
                c.iov[n] = .{ .base = rest.ptr, .len = rest.len };
                n += 1;
            }
            const sqe = self.getSqe();
            sqe.prep_writev(c.fd, c.iov[0..n], 0);
            sqe.user_data = userData(c.gen, self.slotOf(c), .write);
            c.write_inflight = true;
            c.inflight += 1;
        }

        // -- Time and timeouts (as in worker.zig) ----------------------------

        fn refreshDate(self: *Self) void {
            const t = sys.realtimeSeconds();
            if (t != self.last_realtime) {
                self.last_realtime = t;
                date.formatHeader(&self.date_line, t);
            }
        }

        fn tick(self: *Self) void {
            const now = sys.monotonicSeconds();
            if (now == self.now) return;
            self.now = now;
            self.refreshDate();
            self.expire(&self.idle);
            self.expire(&self.active);
            self.expireExchanges();
            self.tickH2();
        }

        fn tickH2(self: *Self) void {
            if (self.h2_count == 0) return;
            for (self.conns) |*c| {
                if (!c.open or c.h2 == null or c.closing) continue;
                const ctx = self.h2Context(c);
                c.h2.?.tick(Handler, &ctx);
                self.h2Drive(c);
            }
        }

        fn expireExchanges(self: *Self) void {
            if (self.exchanges.active_count == 0) return;
            for (self.exchanges.entries, 0..) |*e, slot| {
                if (!e.active) continue;
                if (@as(i32, @bitCast(e.deadline -% self.now)) > 0) continue;
                if (e.conn_slot & quic_endpoint.exchange_slot_flag != 0) {
                    if (self.quic) |*ep| ep.onExchangeTimeout(e.conn_slot, e.conn_gen, @intCast(slot), nowUs());
                    continue;
                }
                const c = &self.conns[e.conn_slot];
                if (!c.open or c.gen != e.conn_gen or c.closing) continue;
                if (c.h2) |conn| {
                    const ctx = self.h2Context(c);
                    conn.onExchangeTimeout(Handler, &ctx, @intCast(slot));
                    self.h2Drive(c);
                } else if (c.exchange == slot) {
                    self.closeConn(c);
                }
            }
        }

        fn expire(self: *Self, list: *List) void {
            while (list.head != NIL) {
                const c = &self.conns[list.head];
                if (@as(i32, @bitCast(c.deadline -% self.now)) > 0) break;
                self.closeConn(c);
            }
        }

        fn listFor(self: *Self, id: ListId) *List {
            return switch (id) {
                .idle => &self.idle,
                .active => &self.active,
                .none => unreachable,
            };
        }

        fn unlink(self: *Self, c: *Conn) void {
            if (c.list == .none) return;
            const list = self.listFor(c.list);
            if (c.prev != NIL) self.conns[c.prev].next = c.next else list.head = c.next;
            if (c.next != NIL) self.conns[c.next].prev = c.prev else list.tail = c.prev;
            c.prev = NIL;
            c.next = NIL;
            c.list = .none;
        }

        fn arm(self: *Self, c: *Conn, id: ListId) void {
            self.unlink(c);
            const list = self.listFor(id);
            const slot = self.slotOf(c);
            c.list = id;
            // `now` is truncated to the second, so add one: the timeout
            // then fires between T and T+1 seconds after arming, never
            // before T.
            c.deadline = self.now +% list.timeout +% 1;
            c.prev = list.tail;
            c.next = NIL;
            if (list.tail != NIL) self.conns[list.tail].next = slot else list.head = slot;
            list.tail = slot;
        }

        fn updateTimer(self: *Self, c: *Conn) void {
            const handshaking = c.tls != null and c.tls.?.isHandshaking();
            if (c.exchange != NIL and !c.write_inflight) {
                self.unlink(c);
                return;
            }
            if (c.session.inRequest() or c.write_inflight or handshaking) {
                if (c.list != .active) self.arm(c, .active);
            } else {
                self.arm(c, .idle);
            }
        }

        inline fn slotOf(self: *Self, c: *Conn) u32 {
            return @intCast((@intFromPtr(c) - @intFromPtr(self.conns.ptr)) / @sizeOf(Conn));
        }

        // -- Connection lifecycle ------------------------------------------

        fn onAccept(self: *Self, cqe: linux.io_uring_cqe) void {
            if (cqe.flags & linux.IORING_CQE_F_MORE == 0 and !self.shutdown.load(.acquire)) {
                self.armAccept();
            }
            if (cqe.res < 0) return;
            const fd: sys.fd_t = cqe.res;
            if (self.free_len == 0) {
                sys.close(fd);
                return;
            }
            self.free_len -= 1;
            const slot = self.free_slots[self.free_len];
            const c = &self.conns[slot];
            c.* = .{ .fd = fd, .gen = c.gen +% 1, .open = true };
            self.open_count += 1;
            if (self.opts.tls) |cfg| {
                self.attachTls(c, cfg) catch {
                    sys.close(fd);
                    self.releaseSlot(c);
                    return;
                };
            }
            self.arm(c, .active);
            self.armTick();
            self.armRecv(c);
        }

        fn attachTls(self: *Self, c: *Conn, cfg: *const tls.Config) !void {
            var entropy: [tls.entropy_len]u8 = undefined;
            self.rng.fill(&entropy);
            defer std.crypto.secureZero(u8, &entropy);
            const t = try self.allocator.create(TlsConn);
            errdefer self.allocator.destroy(t);
            t.* = try TlsConn.init(self.allocator, &self.tls_pools.?, cfg, &entropy);
            c.tls = t;
        }

        /// Close after the final response, lingering if the session asks.
        fn finish(self: *Self, c: *Conn) void {
            if (c.tls) |t| {
                // No write is in flight here, so a direct write keeps the
                // stream in order.
                t.close();
                tlsWriteOnce(c, t);
            }
            if (!c.session.linger or c.peer_closed) return self.closeConn(c);
            sys.shutdownWrite(c.fd);
            if (c.borrowed) {
                c.session.buf = &.{};
                c.borrowed = false;
            }
            c.session.deinit(&self.pool);
            c.lingering = true;
            self.arm(c, .active);
            self.armRecv(c);
        }

        fn closeConn(self: *Self, c: *Conn) void {
            if (c.closing) return;
            c.closing = true;
            if (c.tls) |t| {
                // close_notify, unless an alert went out, output is stuck,
                // or a write is in flight (which a direct write would
                // overtake).
                if (t.isEstablished() and !t.hasWire() and !c.write_inflight) {
                    t.close();
                    tlsWriteOnce(c, t);
                }
            }
            self.unlink(c);
            if (c.recv_armed) {
                const sqe = self.getSqe();
                sqe.prep_cancel(userData(c.gen, self.slotOf(c), .recv), 0);
                sqe.user_data = userData(c.gen, self.slotOf(c), .cancel);
                c.inflight += 1;
            }
            // Shutting down the socket fails any in-flight write promptly.
            if (c.write_inflight) _ = linux.shutdown(c.fd, linux.SHUT.RDWR);
            if (c.inflight == 0) self.finishClose(c);
        }

        fn finishClose(self: *Self, c: *Conn) void {
            sys.close(c.fd);
            self.freeConnResources(c);
            self.releaseSlot(c);
        }

        fn freeConnResources(self: *Self, c: *Conn) void {
            if (c.borrowed) {
                c.session.buf = &.{};
                c.borrowed = false;
            }
            c.session.deinit(&self.pool);
            if (c.out.buf.len > 0) self.out_pool.release(c.out.buf);
            c.out = .{ .buf = &.{} };
            if (c.out_body_owned.len > 0) self.allocator.free(c.out_body_owned);
            c.out_body_owned = &.{};
            if (c.release) |r| {
                r.call();
                c.release = null;
            }
            if (c.exchange != NIL) _ = self.dropExchange(c, true);
            if (c.h2) |conn| {
                const ctx = self.h2Context(c);
                conn.abortAll(&ctx);
                conn.deinit(&self.pool);
                self.allocator.destroy(conn);
                c.h2 = null;
                self.h2_count -= 1;
            }
            if (c.ws) |w| {
                if (@hasDecl(Handler, "handleWSDisconn")) self.handler.handleWSDisconn(w);
                w.destroy(&self.pool);
                c.ws = null;
            }
            if (c.tls) |t| {
                t.deinit();
                self.allocator.destroy(t);
                c.tls = null;
            }
        }

        fn releaseSlot(self: *Self, c: *Conn) void {
            self.unlink(c);
            c.open = false;
            c.closing = false;
            c.fd = -1;
            self.free_slots[self.free_len] = self.slotOf(c);
            self.free_len += 1;
            self.open_count -= 1;
        }

        /// The upgrade response has been written: the connection stays on
        /// this worker and speaks WebSocket from here on.
        fn upgradeConn(self: *Self, c: *Conn) void {
            if (!@hasDecl(Handler, "handleWSFrame")) return self.closeConn(c);
            const w = WsConn.create(self.allocator, c.fd, self.opts.websocket, &self.mailbox, self.slotOf(c), c.gen) catch {
                return self.closeConn(c);
            };
            c.ws = w;
            if (c.out.buf.len > 0) {
                self.out_pool.release(c.out.buf);
                c.out = .{ .buf = &.{} };
            }
            // Bytes after the upgrade request are the first frames. A
            // kernel buffer goes back to the ring, so copy out of it.
            const s = &c.session;
            if (c.borrowed) {
                const leftover = s.buf[s.start..s.end];
                c.borrowed = false;
                s.* = .{};
                const space = w.decoder.readSpace(&self.pool) catch return self.closeConn(c);
                std.debug.assert(space.len >= leftover.len);
                @memcpy(space[0..leftover.len], leftover);
                w.decoder.commitRead(leftover.len);
            } else {
                w.decoder.adopt(s.buf, s.start, s.end);
                s.* = .{};
            }
            self.unlink(c);
            if (@hasDecl(Handler, "handleWSConn")) self.handler.handleWSConn(w);
            _ = w.process(Handler, self.handler);
            // Records after the upgrade request not yet decrypted.
            if (c.tls) |t| {
                if (t.hasBufferedInput() and !self.tlsDecrypt(c, t)) return;
            }
            self.wsDrive(c);
        }

        // -- Completions -----------------------------------------------------

        fn onRecv(self: *Self, c: *Conn, cqe: linux.io_uring_cqe) void {
            c.recv_armed = false;
            if (cqe.res < 0) {
                if (c.closing) return;
                if (cqe.err() == .NOBUFS and !c.lingering) return self.armRecvPlain(c);
                return self.closeConn(c);
            }
            if (c.lingering) {
                if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) self.buffers.put(cqe) catch {};
                c.lingered +|= @intCast(cqe.res);
                if (cqe.res == 0 or c.lingered > sys.max_linger_bytes) return self.closeConn(c);
                return self.armRecv(c);
            }
            if (cqe.res == 0) {
                if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) self.buffers.put(cqe) catch {};
                c.peer_closed = true;
                if (c.closing) return;
                if (c.ws != null) return self.wsDrive(c);
                return self.drive(c);
            }
            const data = self.buffers.get(cqe) catch return self.closeConn(c);
            defer self.buffers.put(cqe) catch {};
            if (c.closing) return;
            if (c.tls) |t| return self.tlsFeed(c, t, data);
            if (c.ws != null) return self.wsFeed(c, data);
            if (c.h2 != null) return self.h2Feed(c, data);
            if (c.session.buf.len == 0) {
                // Zero-copy: parse straight out of the kernel's buffer.
                c.session.buf = data;
                c.session.start = 0;
                c.session.end = data.len;
                c.borrowed = true;
            } else {
                self.appendInput(c, data) catch return self.closeConn(c);
            }
            self.drive(c);
            // The kernel buffer goes back when this returns; keep leftovers.
            if (c.borrowed) self.unborrow(c) catch return self.closeConn(c);
        }

        fn onRecvPlain(self: *Self, c: *Conn, cqe: linux.io_uring_cqe) void {
            c.recv_armed = false;
            if (c.closing) return;
            if (cqe.res < 0) return self.closeConn(c);
            if (c.tls) |t| {
                if (cqe.res == 0) {
                    c.peer_closed = true;
                } else {
                    t.commitRead(@intCast(cqe.res));
                    if (!self.tlsDecrypt(c, t)) return;
                }
                return if (c.ws != null) self.wsDrive(c) else self.drive(c);
            }
            if (c.ws) |w| {
                if (cqe.res == 0) {
                    c.peer_closed = true;
                } else {
                    w.decoder.commitRead(@intCast(cqe.res));
                    _ = w.process(Handler, self.handler);
                }
                return self.wsDrive(c);
            }
            if (c.h2) |conn| {
                if (cqe.res == 0) {
                    c.peer_closed = true;
                } else {
                    conn.commitRead(@intCast(cqe.res));
                    if (!self.h2Process(c)) return;
                }
                return self.h2Drive(c);
            }
            if (cqe.res == 0) {
                c.peer_closed = true;
            } else {
                c.session.commitRead(@intCast(cqe.res));
            }
            self.drive(c);
        }

        fn appendInput(self: *Self, c: *Conn, data: []const u8) !void {
            var rest = data;
            while (rest.len > 0) {
                const space = try c.session.readSpace(&self.pool, self.opts.session);
                const n = @min(space.len, rest.len);
                @memcpy(space[0..n], rest[0..n]);
                c.session.commitRead(n);
                rest = rest[n..];
            }
        }

        fn unborrow(self: *Self, c: *Conn) !void {
            c.borrowed = false;
            const s = &c.session;
            const leftover = s.buf[s.start..s.end];
            s.buf = &.{};
            s.start = 0;
            s.end = 0;
            if (leftover.len > 0) try self.appendInput(c, leftover);
        }

        fn onWrite(self: *Self, c: *Conn, cqe: linux.io_uring_cqe) void {
            c.write_inflight = false;
            if (c.closing) return;
            if (cqe.res < 0) return self.closeConn(c);
            if (cqe.res > 0) self.arm(c, .active);
            if (c.tls) |t| {
                t.advance(@intCast(cqe.res));
                if (self.tlsSubmit(c, t) != .idle) return;
            } else {
                c.sent += @intCast(cqe.res);
                if (c.sent < c.out.totalLen()) return self.submitWrite(c);
            }
            c.out.clear();
            c.sent = 0;
            if (c.out_body_owned.len > 0) {
                self.allocator.free(c.out_body_owned);
                c.out_body_owned = &.{};
            }
            if (c.release) |r| {
                r.call();
                c.release = null;
            }
            switch (c.after_write) {
                .close => return self.finish(c),
                .upgrade => return self.upgradeConn(c),
                .exchange_done => {
                    c.after_write = .none;
                    return self.exchangeDone(c);
                },
                .none => if (c.exchange != NIL) self.exchangeDrive(c) else self.drive(c),
            }
        }

        // -- Exchanges ----------------------------------------------------

        /// The session returned `.wait`: bind the handler's exchange to
        /// this connection.
        fn bindExchange(self: *Self, c: *Conn) void {
            const ex = self.resp.exchange;
            c.exchange = ex.slot;
            self.exchanges.bindHttp1(ex, self.slotOf(c), c.gen, &c.session, self.resp, self.now);
        }

        /// Queues a write of the exchange's output, if any. Nothing is
        /// read while an exchange is pending, unless its request body is
        /// streaming in (and no write is in flight).
        fn exchangeDrive(self: *Self, c: *Conn) void {
            if (c.write_inflight or c.closing) return;
            if (c.out.buf.len == 0) {
                c.out.buf = self.out_pool.acquire() catch return self.closeConn(c);
            }
            const ex = self.exchanges.handle(c.exchange);
            const r = ex.fill(&c.out, &self.date_line, self.now);
            if (r.aborted) return self.closeConn(c);
            c.release = r.release;
            if (r.notify and @hasDecl(Handler, "handleWritable")) self.handler.handleWritable(ex);
            if (!c.out.isEmpty()) {
                c.after_write = if (r.done) .exchange_done else .none;
                if (c.tls) |t| {
                    if (self.tlsSubmit(c, t) == .closed) return;
                } else self.submitWrite(c);
                if (c.list != .active) self.arm(c, .active);
                return;
            }
            if (r.done) return self.exchangeDone(c);
            self.out_pool.release(c.out.buf);
            c.out = .{ .buf = &.{} };
            self.unlink(c);
            if (c.session.wantsBody()) self.drive(c);
        }

        fn exchangeDone(self: *Self, c: *Conn) void {
            const keep_alive = self.exchanges.entry(c.exchange).keep_alive;
            if (self.dropExchange(c, false)) {
                // Answered before its body was all in: the rest can't be
                // told from the next request.
                c.session.linger = true;
                return self.finish(c);
            }
            if (!keep_alive) return self.finish(c);
            self.drive(c);
        }

        /// Returns whether a streamed request body was still arriving.
        fn dropExchange(self: *Self, c: *Conn, gone: bool) bool {
            const slot = c.exchange;
            c.exchange = NIL;
            const unread = c.session.endWait();
            if (gone and @hasDecl(Handler, "handleAbort")) {
                const e = self.exchanges.entry(slot);
                e.mutex.lock();
                const in_use = e.state == .later or e.state == .streaming;
                e.mutex.unlock();
                if (in_use) self.handler.handleAbort(self.exchanges.handle(slot));
            }
            self.exchanges.release(slot);
            return unread;
        }

        fn exchangePosted(self: *Self, slot: u32, gen: u31) void {
            const e = self.exchanges.entry(slot);
            if (!e.active or (e.gen & 0x7fffffff) != gen or !e.bound) return;
            if (e.conn_slot & quic_endpoint.exchange_slot_flag != 0) {
                if (self.quic) |*ep| ep.onExchangePosted(e.conn_slot, e.conn_gen, slot, nowUs());
                return;
            }
            const c = &self.conns[e.conn_slot];
            if (!c.open or c.gen != e.conn_gen or c.closing) return;
            if (c.h2) |conn| {
                const ctx = self.h2Context(c);
                conn.onExchangePosted(Handler, &ctx, slot);
                return self.h2Drive(c);
            }
            if (c.exchange != slot or c.ws != null or c.lingering) return;
            if (self.exchanges.handle(slot).takeResume()) c.session.body_paused = false;
            self.exchangeDrive(c);
        }

        // -- HTTP/2 ---------------------------------------------------------

        fn h2Context(self: *Self, c: *Conn) h2.Context(Handler) {
            return .{
                .handler = self.handler,
                .req = self.req,
                .resp = self.resp,
                .date = &self.date_line,
                .now = self.now,
                .exchanges = &self.exchanges,
                .conn_slot = self.slotOf(c),
                .conn_gen = c.gen,
            };
        }

        /// Switches to HTTP/2, adopting the session's bytes (copied out of
        /// a kernel buffer if that is where they are).
        fn attachH2(self: *Self, c: *Conn) bool {
            const conn = self.allocator.create(H2Conn) catch return false;
            conn.* = H2Conn.init(self.allocator, self.opts.h2) catch {
                self.allocator.destroy(conn);
                return false;
            };
            const s = &c.session;
            if (s.buf.len > 0) {
                const leftover = s.buf[s.start..s.end];
                if (c.borrowed) {
                    c.borrowed = false;
                    var rest = leftover;
                    while (rest.len > 0) {
                        const space = conn.readSpace(&self.pool) catch {
                            conn.deinit(&self.pool);
                            self.allocator.destroy(conn);
                            s.* = .{};
                            return false;
                        };
                        const n = @min(space.len, rest.len);
                        @memcpy(space[0..n], rest[0..n]);
                        conn.commitRead(n);
                        rest = rest[n..];
                    }
                } else {
                    conn.reader.buf = s.buf;
                    conn.reader.start = s.start;
                    conn.reader.end = s.end;
                }
                s.* = .{};
            }
            if (c.out.buf.len > 0) {
                self.out_pool.release(c.out.buf);
                c.out = .{ .buf = &.{} };
            }
            c.h2 = conn;
            c.proto_decided = true;
            self.h2_count += 1;
            return true;
        }

        /// Plaintext with h2c: the first bytes decide. False while more
        /// bytes are needed (or the connection was closed).
        fn decideProto(self: *Self, c: *Conn) bool {
            if (c.proto_decided) return true;
            if (c.tls) |t| {
                // ALPN decides, once the handshake is done. Application
                // data from the same read may already sit in the session
                // buffer; attachH2 adopts it.
                // Nothing to decide yet: carry on (the handshake flight
                // still has to be written), and look again later.
                if (!t.isEstablished()) return true;
                c.proto_decided = true;
                if (t.alpn != null and std.mem.eql(u8, t.alpn.?, "h2")) {
                    if (!self.attachH2(c)) {
                        self.closeConn(c);
                        return false;
                    }
                }
                return true;
            }
            if (!self.opts.h2c) {
                c.proto_decided = true;
                return true;
            }
            const s = &c.session;
            const data = s.buf[s.start..s.end];
            if (data.len < h2_preface.len) {
                if (std.mem.startsWith(u8, h2_preface, data)) return false;
                c.proto_decided = true;
                return true;
            }
            if (std.mem.eql(u8, data[0..h2_preface.len], h2_preface)) {
                if (!self.attachH2(c)) {
                    self.closeConn(c);
                    return false;
                }
                return true;
            }
            c.proto_decided = true;
            return true;
        }

        /// Copies received bytes into the connection and runs it, a
        /// buffer's worth at a time (frames are consumed as they complete,
        /// so a chunk always fits in the end).
        fn h2Feed(self: *Self, c: *Conn, data: []const u8) void {
            const conn = c.h2.?;
            var rest = data;
            while (rest.len > 0) {
                const space = conn.readSpace(&self.pool) catch return self.closeConn(c);
                const n = @min(space.len, rest.len);
                @memcpy(space[0..n], rest[0..n]);
                conn.commitRead(n);
                rest = rest[n..];
                self.h2Run(c);
            }
            self.h2Drive(c);
        }

        /// Runs the connection over buffered input without driving I/O.
        fn h2Run(self: *Self, c: *Conn) void {
            if (c.closing) return;
            const conn = c.h2 orelse return;
            const ctx = self.h2Context(c);
            _ = conn.process(Handler, &ctx);
        }

        /// Runs the connection over buffered input and queues its output.
        /// Output is double-buffered, so this is fine while a write is in
        /// flight. Returns false if the connection is gone.
        fn h2Process(self: *Self, c: *Conn) bool {
            if (c.closing) return false;
            const conn = c.h2 orelse return false;
            const gen = c.gen;
            const ctx = self.h2Context(c);
            _ = conn.process(Handler, &ctx);
            self.h2Drive(c);
            // The close may have completed at once (no operation in
            // flight), releasing the slot: `closing` is false again then.
            return c.open and c.gen == gen and !c.closing and c.h2 != null;
        }

        /// Queues a write of pending frames, or arms the next recv when
        /// there is nothing to write. One write at a time; no recv while
        /// a write is in flight (backpressure).
        fn h2Drive(self: *Self, c: *Conn) void {
            if (c.closing or c.write_inflight) return;
            const conn = c.h2 orelse return;
            if (c.tls) |t| {
                switch (self.tlsSubmit(c, t)) {
                    .idle => {},
                    .writing => {
                        c.after_write = .none;
                        if (c.list != .active) self.arm(c, .active);
                        return;
                    },
                    .closed => return,
                }
            }
            const bytes = if (c.tls != null) "" else conn.wireBytes();
            if (bytes.len > 0) {
                c.iov[0] = .{ .base = bytes.ptr, .len = bytes.len };
                const sqe = self.getSqe();
                sqe.prep_writev(c.fd, c.iov[0..1], 0);
                sqe.user_data = userData(c.gen, self.slotOf(c), .write);
                c.write_inflight = true;
                c.inflight += 1;
                if (c.list != .active) self.arm(c, .active);
                return;
            }
            if (conn.wantsClose() or c.peer_closed) return self.closeConn(c);
            conn.releaseIfIdle(&self.pool);
            if (c.tls) |t| t.releaseIfIdle();
            if (conn.activeStreams() == 0 and !conn.inFrame()) {
                self.arm(c, .idle);
            } else {
                self.unlink(c);
            }
            self.armRecv(c);
        }

        fn onH2Write(self: *Self, c: *Conn, cqe: linux.io_uring_cqe) void {
            c.write_inflight = false;
            if (c.closing) return;
            if (cqe.res < 0) return self.closeConn(c);
            const conn = c.h2.?;
            if (c.tls) |t| t.advance(@intCast(cqe.res)) else conn.advance(@intCast(cqe.res));
            if (cqe.res > 0) self.arm(c, .active);
            if (c.tls) |t| {
                if (t.hasWire()) return self.h2Drive(c);
            }
            if (conn.hasWire()) return self.h2Drive(c);
            // Written: streams waiting for room continue, then input that
            // arrived while output was pending is processed.
            const ctx = self.h2Context(c);
            conn.pump(Handler, &ctx);
            if (conn.hasWire()) return self.h2Drive(c);
            if (!self.h2Process(c)) return;
            self.h2Drive(c);
        }

        /// Runs the session until it needs input, or output must be written
        /// first. Arms the next recv when idle.
        fn drive(self: *Self, c: *Conn) void {
            if (c.write_inflight or c.closing) return;
            if (c.h2 != null) return self.h2Drive(c);
            if (!c.proto_decided) {
                if (!self.decideProto(c)) {
                    // Part of a preface: keep it and wait for the rest.
                    if (c.closing) return;
                    if (c.peer_closed) return self.closeConn(c);
                    if (c.borrowed) self.unborrow(c) catch return self.closeConn(c);
                    self.updateTimer(c);
                    return self.armRecv(c);
                }
                if (c.h2 != null) return self.h2Drive(c);
            }
            const ctx: session.Context(Handler) = .{
                .handler = self.handler,
                .req = self.req,
                .resp = self.resp,
                .date = &self.date_line,
                .opts = self.opts.session,
            };
            while (true) {
                if (c.out.buf.len == 0) {
                    c.out.buf = self.out_pool.acquire() catch return self.closeConn(c);
                }
                const action = session.process(Handler, &c.session, &ctx, &c.out);
                if (action == .wait and c.exchange == NIL) self.bindExchange(c);
                if (!c.out.isEmpty()) {
                    self.ownBody(c) catch return self.closeConn(c);
                    c.after_write = switch (action) {
                        .close => .close,
                        .upgrade => .upgrade,
                        .flush, .need_more, .wait => .none,
                    };
                    if (c.tls) |t| {
                        if (self.tlsSubmit(c, t) == .closed) return;
                    } else self.submitWrite(c);
                    self.updateTimer(c);
                    return;
                }
                switch (action) {
                    .flush => continue,
                    .need_more => break,
                    .close => return self.finish(c),
                    .upgrade => return self.upgradeConn(c),
                    .wait => return self.exchangeDrive(c),
                }
            }
            if (c.out.buf.len > 0) {
                self.out_pool.release(c.out.buf);
                c.out = .{ .buf = &.{} };
            }
            if (c.tls) |t| {
                // Handshake messages or a KeyUpdate answer; reading resumes
                // when they are written.
                switch (self.tlsSubmit(c, t)) {
                    .idle => {},
                    .writing => {
                        c.after_write = .none;
                        self.updateTimer(c);
                        return;
                    },
                    .closed => return,
                }
            }
            if (c.peer_closed) return self.closeConn(c);
            // Keep a partial request before the kernel buffer goes back.
            if (c.borrowed) self.unborrow(c) catch return self.closeConn(c);
            c.session.releaseIfIdle(&self.pool);
            if (c.tls) |t| t.releaseIfIdle();
            self.updateTimer(c);
            self.armRecv(c);
        }

        /// The worker's response buffer is reused by the next request on any
        /// connection, so a body pointing into it must be copied before the
        /// write is queued. Borrowed bodies are immutable until sent.
        fn ownBody(self: *Self, c: *Conn) !void {
            const body = c.out.body;
            if (body.len == 0) return;
            const rb = self.resp.body_buf;
            const in_resp_buf = @intFromPtr(body.ptr) >= @intFromPtr(rb.ptr) and
                @intFromPtr(body.ptr) < @intFromPtr(rb.ptr) + rb.len;
            if (!in_resp_buf) return;
            if (body.len <= c.out.buf.len - c.out.len) {
                @memcpy(c.out.buf[c.out.len..][0..body.len], body);
                c.out.len += body.len;
                c.out.body = "";
            } else {
                c.out_body_owned = try self.allocator.dupe(u8, body);
                c.out.body = c.out_body_owned;
            }
        }

        // -- TLS ---------------------------------------------------------------

        /// Decrypts ciphertext from a kernel buffer (which goes back to the
        /// ring when this returns), then runs the session or WebSocket.
        /// Records are decrypted in place in the kernel buffer, or straight
        /// into the session; only a record that spans two receives is
        /// copied into the TLS buffer, up to its end, and a partial record
        /// left at the end of the chunk is kept there.
        fn tlsFeed(self: *Self, c: *Conn, t: *TlsConn, data: []u8) void {
            var rest = data;
            while (rest.len > 0) {
                if (t.canBorrow()) {
                    t.borrowInput(rest);
                    if (!self.tlsDecrypt(c, t)) return;
                    t.endBorrow() catch return self.closeConn(c);
                    break;
                }
                const space = t.readSpace() catch return self.closeConn(c);
                std.debug.assert(space.len > 0);
                const need = t.partialRecordNeed();
                const n = @min(space.len, rest.len, if (need > 0) need else rest.len);
                @memcpy(space[0..n], rest[0..n]);
                t.commitRead(n);
                rest = rest[n..];
                if (!self.tlsDecrypt(c, t)) return;
                // The rest is never read: the peer closed, or the
                // WebSocket is closing (tlsDecrypt stopped early).
                if (t.peer_closed or (c.ws != null and c.ws.?.wantsClose())) break;
            }
            if (c.ws != null) self.wsDrive(c) else if (c.h2 != null) self.h2Drive(c) else self.drive(c);
        }

        /// Decrypts every complete record into the session (or the
        /// WebSocket decoder, processing frames as they land). On a TLS
        /// failure sends the alert and closes. Returns false if the
        /// connection was closed.
        fn tlsDecrypt(self: *Self, c: *Conn, t: *TlsConn) bool {
            if (!c.proto_decided and t.isEstablished()) {
                c.proto_decided = true;
                if (t.alpn != null and std.mem.eql(u8, t.alpn.?, "h2")) {
                    if (!self.attachH2(c)) {
                        self.closeConn(c);
                        return false;
                    }
                }
            }
            while (t.hasBufferedInput()) {
                if (c.h2) |conn| {
                    const space = conn.readSpace(&self.pool) catch {
                        self.closeConn(c);
                        return false;
                    };
                    conn.commitRead(t.readPlain(space));
                    // Run only: I/O is driven once the input is consumed
                    // (arming a recv now, with plaintext still untaken,
                    // would give it an empty buffer and read as EOF).
                    self.h2Run(c);
                    continue;
                }
                if (c.ws) |w| {
                    const space = w.decoder.readSpace(&self.pool) catch {
                        self.closeConn(c);
                        return false;
                    };
                    w.decoder.commitRead(t.readPlain(space));
                    if (w.process(Handler, self.handler) == .close) break;
                } else {
                    const space = c.session.readSpace(&self.pool, self.opts.session) catch {
                        self.closeConn(c);
                        return false;
                    };
                    c.session.commitRead(t.readPlain(space));
                }
            }
            if (t.failed) {
                // No write is in flight while input is processed.
                tlsWriteOnce(c, t);
                self.closeConn(c);
                return false;
            }
            if (t.peer_closed) c.peer_closed = true;
            return true;
        }

        const Submit = enum { idle, writing, closed };

        /// Encrypts pending output (the response in `out`, or WebSocket
        /// bytes) into the TLS wire buffer and queues a write of it.
        fn tlsSubmit(self: *Self, c: *Conn, t: *TlsConn) Submit {
            std.debug.assert(!c.write_inflight);
            if (t.isEstablished()) {
                if (c.ws) |w| {
                    const bytes = w.wireBytes();
                    if (bytes.len > 0) {
                        const n = t.encrypt(&.{bytes}) catch {
                            self.closeConn(c);
                            return .closed;
                        };
                        w.advance(n);
                    }
                } else if (c.h2) |conn| {
                    const bytes = conn.wireBytes();
                    if (bytes.len > 0) {
                        const n = t.encrypt(&.{bytes}) catch {
                            self.closeConn(c);
                            return .closed;
                        };
                        conn.advance(n);
                    }
                } else if (c.sent < c.out.totalLen()) {
                    const head = c.out.buf[@min(c.sent, c.out.len)..c.out.len];
                    const body = c.out.body[@min(c.sent -| c.out.len, c.out.body.len)..];
                    const tail = c.out.tail[c.sent -| (c.out.len + c.out.body.len)..];
                    c.sent += t.encrypt(&.{ head, body, tail }) catch {
                        self.closeConn(c);
                        return .closed;
                    };
                }
            }
            if (!t.hasWire()) return .idle;
            const bytes = t.wireBytes();
            c.iov[0] = .{ .base = bytes.ptr, .len = bytes.len };
            const sqe = self.getSqe();
            sqe.prep_writev(c.fd, c.iov[0..1], 0);
            sqe.user_data = userData(c.gen, self.slotOf(c), .write);
            c.write_inflight = true;
            c.inflight += 1;
            return .writing;
        }

        /// Best effort before closing (alerts, close_notify): one direct
        /// write. Only when no write is in flight.
        fn tlsWriteOnce(c: *Conn, t: *TlsConn) void {
            if (!t.hasWire()) return;
            const n = sys.write(c.fd, t.wireBytes()) catch return;
            t.advance(n);
        }

        // -- WebSocket ---------------------------------------------------------

        /// Copies received bytes into the decoder's buffer, running the
        /// protocol as each chunk lands (a frame held whole may need the
        /// buffer compacted before the rest fits).
        fn wsFeed(self: *Self, c: *Conn, data: []const u8) void {
            const w = c.ws.?;
            var rest = data;
            while (rest.len > 0) {
                const space = w.decoder.readSpace(&self.pool) catch return self.closeConn(c);
                const n = @min(space.len, rest.len);
                @memcpy(space[0..n], rest[0..n]);
                w.decoder.commitRead(n);
                rest = rest[n..];
                if (w.process(Handler, self.handler) == .close) break;
            }
            self.wsDrive(c);
        }

        /// Writes queued output, or arms the next recv when there is none.
        /// A recv is armed only while no write is in flight (backpressure).
        fn wsDrive(self: *Self, c: *Conn) void {
            if (c.closing or c.write_inflight) return;
            const w = c.ws.?;
            if (c.tls) |t| {
                switch (self.tlsSubmit(c, t)) {
                    .idle => {},
                    .writing => {
                        if (c.list != .active) self.arm(c, .active);
                        return;
                    },
                    .closed => return,
                }
            }
            const bytes = if (c.tls != null) "" else w.wireBytes();
            if (bytes.len > 0) {
                c.iov[0] = .{ .base = bytes.ptr, .len = bytes.len };
                const sqe = self.getSqe();
                sqe.prep_writev(c.fd, c.iov[0..1], 0);
                sqe.user_data = userData(c.gen, self.slotOf(c), .write);
                c.write_inflight = true;
                c.inflight += 1;
                if (c.list != .active) self.arm(c, .active);
                return;
            }
            if (w.wantsClose() or c.peer_closed) return self.closeConn(c);
            w.decoder.releaseIfIdle(&self.pool);
            if (c.tls) |t| t.releaseIfIdle();
            // Only a pending close handshake has a deadline.
            if (w.closeSent()) {
                if (c.list != .active) self.arm(c, .active);
            } else {
                self.unlink(c);
            }
            self.armRecv(c);
        }

        fn onWsWrite(self: *Self, c: *Conn, cqe: linux.io_uring_cqe) void {
            c.write_inflight = false;
            if (c.closing) return;
            if (cqe.res < 0) return self.closeConn(c);
            // With TLS the WebSocket bytes were consumed when encrypted.
            if (c.tls) |t| t.advance(@intCast(cqe.res)) else c.ws.?.advance(@intCast(cqe.res));
            // Progress extends the deadline; a stalled reader times out.
            if (cqe.res > 0) self.arm(c, .active);
            self.wsDrive(c);
        }

        fn drainMailbox(self: *Self) void {
            var entries: [64]mailbox_mod.Entry = undefined;
            while (true) {
                const n = self.mailbox.drain(&entries);
                if (n == 0) break;
                for (entries[0..n]) |e| switch (e.kind) {
                    .ws => {
                        const c = &self.conns[e.slot];
                        if (c.open and (c.gen & 0x7fffffff) == e.gen) self.wsFlushPosted(c);
                    },
                    .exchange => self.exchangePosted(e.slot, e.gen),
                };
            }
            if (self.mailbox.takeOverflow()) {
                for (self.exchanges.entries, 0..) |*e, slot| {
                    if (e.active and e.bound and e.conn_slot & quic_endpoint.exchange_slot_flag != 0)
                        self.exchangePosted(@intCast(slot), @intCast(e.gen & 0x7fffffff));
                }
                for (self.conns) |*c| {
                    if (!c.open or c.closing) continue;
                    if (c.ws != null) {
                        self.wsFlushPosted(c);
                    } else if (c.h2 != null) {
                        for (self.exchanges.entries, 0..) |*e, slot| {
                            if (e.active and e.bound and e.conn_slot == self.slotOf(c) and e.conn_gen == c.gen) {
                                self.exchangePosted(@intCast(slot), @intCast(e.gen & 0x7fffffff));
                            }
                        }
                    } else if (c.exchange != NIL and !c.lingering) {
                        self.exchangePosted(c.exchange, @intCast(self.exchanges.entry(c.exchange).gen & 0x7fffffff));
                    }
                }
            }
        }

        fn wsFlushPosted(self: *Self, c: *Conn) void {
            const w = c.ws orelse return;
            w.clearPosted();
            self.wsDrive(c);
        }
    };
}
