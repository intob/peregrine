//! Readiness-based (epoll/kqueue) event loop. Each worker owns its
//! connections end to end: it accepts them (its own SO_REUSEPORT listener on
//! Linux), reads, runs the session state machine, and writes.
const std = @import("std");
const sys = @import("../sys.zig");
const Poller = @import("../poller.zig").Poller;
const session = @import("./session.zig");
const date = @import("./date.zig");
const Session = session.Session;
const BufferPool = session.BufferPool;
const Out = session.Out;
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const File = @import("../response.zig").File;
const ws = @import("../ws/conn.zig");
const WsConn = ws.Conn;
const tls = @import("../tls/conn.zig");
const TlsConn = tls.Conn;
const mailbox_mod = @import("../mailbox.zig");
const Mailbox = mailbox_mod.Mailbox;
const exchange = @import("./exchange.zig");
const h2 = @import("../h2/conn.zig");
const H2Conn = h2.Conn;
const h2_preface = @import("../h2/frame.zig").preface;
const quic_endpoint = @import("../quic/endpoint.zig");

const LISTENER_TOKEN: u64 = std.math.maxInt(u64);
const WAKER_TOKEN: u64 = std.math.maxInt(u64) - 1;
const UDP_TOKEN: u64 = std.math.maxInt(u64) - 2;
const NIL: u32 = std.math.maxInt(u32);

/// The ALPN protocol is HTTP/2.
fn isH2(alpn: ?[]const u8) bool {
    return if (alpn) |p| std.mem.eql(u8, p, "h2") else false;
}
/// Connections accepted per listener event, to stay fair to existing ones.
const ACCEPT_BATCH = 64;
/// TLS record content types (kTLS control records).
const tls_alert: u8 = 21;
const tls_handshake: u8 = 22;
/// File body bytes read at a time where sendfile isn't used (one TLS
/// record).
const file_chunk = 16 * 1024;

pub const Options = struct {
    session: session.Options,
    max_connections: u32,
    read_buffer_size: usize,
    buffer_pool_size: usize,
    out_buffer_size: usize,
    response_body_buffer_size: usize,
    response_header_buffer_size: usize,
    keep_alive_timeout_s: u32,
    request_timeout_s: u32,
    /// Linux: try reading right after accept (the listener uses
    /// TCP_DEFER_ACCEPT, so data is usually already there).
    read_on_accept: bool,
    websocket: ws.Options,
    /// Exchanges (`resp.later()`, `resp.stream()`) per worker.
    max_exchanges: u32 = 1024,
    exchange: exchange.Options = .{},
    /// HTTP/2 with prior knowledge on plaintext connections (the client
    /// sends the connection preface instead of an HTTP/1.1 request).
    h2c: bool = false,
    /// HTTP/2 connection settings (over TLS with ALPN "h2", or h2c).
    h2: h2.Options = .{},
    /// TLS for every connection, if set.
    tls: ?*const tls.Config = null,
    /// TLS record buffers preallocated per worker (input and output each).
    tls_buffer_pool_size: usize = 0,
    /// Linux: before the first file body on an HTTP/1.1 connection over
    /// TLS, hand the sending side to the kernel (kTLS), so the file goes
    /// out with sendfile (and everything after as plaintext writes). Not
    /// otherwise: our own record encryption is cheaper than the kernel's
    /// for bytes already in memory. Quietly off where the kernel can't.
    ktls: bool = true,
    /// HTTP/3 on the worker's UDP socket, if it has one.
    quic: ?quic_endpoint.Options = null,
    /// Header lines added to every response, e.g. "alt-svc: ...\r\n".
    preset_headers: []const u8 = "",
};

pub fn Worker(comptime Handler: type) type {
    return struct {
        const Self = @This();

        const ListId = enum(u8) { none, idle, active };

        const Conn = struct {
            fd: sys.fd_t = -1,
            gen: u32 = 0,
            open: bool = false,
            /// The kernel may have unread data (edge-triggered).
            read_ready: bool = false,
            peer_closed: bool = false,
            /// Draining input after an error response (see Session.linger).
            lingering: bool = false,
            lingered: u32 = 0,
            after_flush: enum(u8) { none, close, upgrade, exchange_done } = .none,
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
            /// Set once the connection speaks HTTP/2 (ALPN or h2c); the
            /// session is then unused.
            h2: ?*H2Conn = null,
            /// HTTP/1.1 or HTTP/2 has been decided (ALPN, or the first
            /// bytes on a plaintext listener with h2c).
            proto_decided: bool = false,
            /// Unsent output after a partial write: an owned copy of the
            /// serialised head bytes, then the body (owned or borrowed),
            /// then the tail (static).
            pending_head: []u8 = &.{},
            pending_head_pos: usize = 0,
            pending_body: []const u8 = "",
            pending_body_owned: []u8 = &.{},
            pending_tail: []const u8 = "",
            /// A file body still to send, after the plaintext above
            /// (`offset` and `len` advance as it goes out).
            pending_file: ?File = null,
            /// The exchange whose response this connection is waiting
            /// for or writing (a slot in the worker's slab), or NIL.
            exchange: u32 = NIL,
            /// Borrowed exchange bytes in the output, released once written.
            release: ?exchange.Release = null,

            /// Output not yet written: plaintext waiting to be written (or
            /// encrypted), or TLS records waiting to be written.
            inline fn hasPending(c: *const Conn) bool {
                return c.hasPendingPlain() or (c.tls != null and c.tls.?.hasWire());
            }

            /// Unsent HTTP/2 output: frames, or TLS records holding them.
            inline fn h2HasWire(c: *const Conn) bool {
                return c.h2.?.hasWire() or (c.tls != null and c.tls.?.hasWire());
            }

            inline fn hasPendingPlain(c: *const Conn) bool {
                return c.pendingBytes() or c.pending_file != null;
            }

            inline fn pendingBytes(c: *const Conn) bool {
                return c.pending_head_pos < c.pending_head.len or c.pending_body.len > 0 or c.pending_tail.len > 0;
            }
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
        poller: Poller,
        listener: sys.fd_t,
        owns_listener: bool,
        waker: sys.Waker,
        /// WebSocket connections and exchanges with new output (posted
        /// from any thread).
        mailbox: Mailbox,
        exchanges: exchange.Slab = undefined,
        conns: []Conn,
        free_slots: []u32,
        free_len: usize,
        pool: BufferPool,
        req: *Request,
        resp: *Response,
        out: Out,
        out_buf: []u8,
        /// Where file bodies are read when sendfile can't send them (TLS,
        /// or a file it doesn't support).
        file_buf: []u8,
        /// kTLS is wanted and, as far as this worker knows, available.
        ktls_on: bool,
        date_line: [date.header_len]u8 = undefined,
        now: u32,
        last_realtime: i64 = 0,
        idle: List,
        active: List,
        open_count: usize = 0,
        /// Connections speaking HTTP/2 (their streams are ticked once a second).
        h2_count: usize = 0,
        thread: ?std.Thread = null,
        tls_pools: ?tls.Pools = null,
        /// Handshake randomness, seeded from the OS once per worker.
        rng: std.Random.ChaCha,
        /// HTTP/3 connections on this worker's UDP socket.
        quic: ?quic_endpoint.Endpoint(Handler) = null,
        udp: sys.fd_t = -1,

        pub const InitConfig = struct {
            id: usize,
            allocator: std.mem.Allocator,
            handler: *Handler,
            shutdown: *const std.atomic.Value(bool),
            listener: sys.fd_t,
            owns_listener: bool,
            opts: Options,
            /// A UDP socket for HTTP/3 (with `opts.quic`), owned by the worker.
            udp: sys.fd_t = -1,
        };

        pub fn init(self: *Self, cfg: InitConfig) !void {
            const allocator = cfg.allocator;
            const opts = cfg.opts;
            var poller = try Poller.init();
            errdefer poller.deinit();
            const waker = try sys.Waker.init();
            errdefer waker.deinit();
            var mailbox = try Mailbox.init(allocator, opts.max_connections + opts.max_exchanges, waker);
            errdefer mailbox.deinit();
            const conns = try allocator.alloc(Conn, opts.max_connections);
            errdefer allocator.free(conns);
            @memset(conns, .{});
            const free_slots = try allocator.alloc(u32, opts.max_connections);
            errdefer allocator.free(free_slots);
            // Hand out low slots first (better cache locality).
            for (free_slots, 0..) |*s, i| s.* = @intCast(opts.max_connections - 1 - i);
            var pool = try BufferPool.init(allocator, opts.read_buffer_size, opts.buffer_pool_size);
            errdefer pool.deinit();
            h2.preparePool(&pool, opts.h2);
            const req = try Request.init(allocator);
            errdefer req.deinit();
            const resp = try Response.init(allocator, opts.response_body_buffer_size, opts.response_header_buffer_size);
            errdefer resp.deinit();
            resp.ws_deflate_options = opts.websocket.deflate;
            if (opts.out_buffer_size < session.headRoom(resp)) return error.OutBufferTooSmall;
            const out_buf = try allocator.alloc(u8, opts.out_buffer_size);
            errdefer allocator.free(out_buf);
            const file_buf = try allocator.alloc(u8, file_chunk);
            errdefer allocator.free(file_buf);
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
                .poller = poller,
                .listener = cfg.listener,
                .owns_listener = cfg.owns_listener,
                .waker = waker,
                .mailbox = mailbox,
                .conns = conns,
                .free_slots = free_slots,
                .free_len = free_slots.len,
                .pool = pool,
                .req = req,
                .resp = resp,
                .out_buf = out_buf,
                .out = .{ .buf = out_buf },
                .file_buf = file_buf,
                .ktls_on = opts.ktls and sys.is_linux,
                .now = sys.monotonicSeconds(),
                .idle = .{ .timeout = opts.keep_alive_timeout_s },
                .active = .{ .timeout = opts.request_timeout_s },
                .tls_pools = tls_pools,
                .rng = .init(seed),
            };
            self.refreshDate();
            // The slab posts to this worker's mailbox, which must not move
            // (workers live in a stable slice).
            self.exchanges = try exchange.Slab.init(allocator, opts.max_exchanges, &self.mailbox, opts.exchange);
            errdefer self.exchanges.deinit();
            self.resp.exchanges = &self.exchanges;
            self.resp.now = &self.now;
            try self.resp.setPresetHeaders(opts.preset_headers);
            try self.poller.add(self.listener, LISTENER_TOKEN, .level_read);
            try self.poller.add(self.waker.read_fd, WAKER_TOKEN, .level_read);
            if (cfg.udp >= 0) {
                if (opts.quic) |qopts| {
                    self.udp = cfg.udp;
                    self.quic = try .init(allocator, qopts, cfg.udp);
                    self.quic.?.bindWorker(self.handler, self.req, self.resp, &self.date_line, &self.now, &self.exchanges, &self.pool);
                    try self.poller.add(cfg.udp, UDP_TOKEN, .level_read);
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
                if (c.open) self.closeConn(c);
            }
            if (self.owns_listener) sys.close(self.listener);
            if (self.quic) |*ep| ep.deinit();
            if (self.udp >= 0) sys.close(self.udp);
            self.poller.deinit();
            self.exchanges.deinit();
            self.mailbox.deinit();
            self.waker.deinit();
            self.pool.deinit();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.out_buf);
            self.allocator.free(self.file_buf);
            self.allocator.free(self.conns);
            self.allocator.free(self.free_slots);
            if (self.tls_pools) |*p| p.deinit();
        }

        fn run(self: *Self, pin: bool) void {
            if (pin) sys.pinToCpu(self.id);
            self.mailbox.bind();
            var events: [512]Poller.Event = undefined;
            while (!self.shutdown.load(.acquire)) {
                // With no connections there are no timers to run, so block
                // until something happens (shutdown uses the waker); but
                // the tick goes on until output buffers kept for reuse are
                // freed.
                var timeout: i32 = if (self.open_count == 0 and !self.pool.holdsOutput()) -1 else 1000;
                if (self.quic) |*ep| {
                    // QUIC timers need millisecond resolution; exchanges on
                    // HTTP/3 still want the per-second tick.
                    if (ep.connections() > 0 and timeout < 0) timeout = 1000;
                    if (ep.timeoutMs(nowUs())) |ms| timeout = if (timeout < 0) ms else @min(timeout, ms);
                }
                const n = self.poller.wait(&events, timeout);
                self.tick();
                for (events[0..n]) |ev| {
                    switch (Poller.token(ev)) {
                        LISTENER_TOKEN => self.acceptConnections(),
                        WAKER_TOKEN => self.drainWaker(),
                        UDP_TOKEN => self.quic.?.onReadable(nowUs()),
                        else => |token| self.onConnEvent(ev, token),
                    }
                }
                // WebSocket output queued by handlers during this batch, or
                // by other threads (which also wrote the waker).
                self.drainMailbox();
                if (self.quic) |*ep| ep.onTimers(nowUs());
            }
            if (self.quic) |*ep| ep.shutdown(nowUs());
            // Shutting down: tell HTTP/2 clients with one GOAWAY each
            // (best effort, one write), before deinit closes the sockets.
            for (self.conns) |*c| {
                if (!c.open or c.h2 == null) continue;
                const conn = c.h2.?;
                conn.shutdown();
                if (userTls(c)) |t| {
                    if (t.isEstablished() and !t.hasWire()) {
                        const n = t.encrypt(&.{conn.wireBytes()}) catch 0;
                        conn.advance(n);
                        self.tlsWriteOnce(c, t);
                    }
                } else if (!c.hasPending()) {
                    const n = sys.write(c.fd, conn.wireBytes()) catch 0;
                    conn.advance(n);
                }
            }
        }

        fn nowUs() u64 {
            return sys.nanoTimestamp() / std.time.ns_per_us;
        }

        fn drainWaker(self: *Self) void {
            var buf: [64]u8 = undefined;
            _ = sys.read(self.waker.read_fd, &buf) catch {};
        }

        // -- Time and timeouts -------------------------------------------

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
            self.pool.trim();
            self.tickH2();
        }

        /// Stream timeouts inside HTTP/2 connections.
        fn tickH2(self: *Self) void {
            if (self.h2_count == 0) return;
            for (self.conns) |*c| {
                if (!c.open or c.h2 == null or c.lingering) continue;
                const ctx = self.h2Context(c);
                c.h2.?.tick(Handler, &ctx);
                if (!self.h2Flush(c)) continue;
            }
        }

        /// Exchanges have their own deadlines (set per exchange), so they
        /// are scanned rather than kept on an ordered list.
        fn expireExchanges(self: *Self) void {
            if (self.exchanges.active_count == 0) return;
            for (self.exchanges.entries, 0..) |*e, slot| {
                if (!e.active or (e.tunnel and !e.tunnel_timed)) continue;
                if (@as(i32, @bitCast(e.deadline -% self.now)) > 0) continue;
                if (e.conn_slot & quic_endpoint.exchange_slot_flag != 0) {
                    if (self.quic) |*ep| ep.onExchangeTimeout(e.conn_slot, e.conn_gen, @intCast(slot), nowUs());
                    continue;
                }
                const c = &self.conns[e.conn_slot];
                if (!c.open or c.gen != e.conn_gen) continue;
                if (c.h2) |conn| {
                    // One stream's deadline: reset it, keep the connection.
                    const ctx = self.h2Context(c);
                    conn.onExchangeTimeout(Handler, &ctx, @intCast(slot));
                    _ = self.h2Flush(c);
                } else if (c.exchange == slot) {
                    self.closeConn(c);
                }
            }
        }

        fn expire(self: *Self, list: *List) void {
            // Lists are ordered by deadline because each has a fixed timeout
            // and connections are appended when (re)armed.
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

        /// Append to a list with a fresh deadline.
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

        /// Idle connections get the keep-alive timeout. A partially received
        /// request or unsent response gets the request timeout, which is not
        /// extended by further reads (slowloris), only by write progress.
        fn updateTimer(self: *Self, c: *Conn) void {
            const handshaking = c.tls != null and c.tls.?.isHandshaking();
            if (c.exchange != NIL and !c.hasPending()) {
                // The exchange's own deadline applies.
                self.unlink(c);
                return;
            }
            if (c.session.inRequest() or c.hasPending() or handshaking) {
                if (c.list != .active) self.arm(c, .active);
            } else {
                self.arm(c, .idle);
            }
        }

        inline fn slotOf(self: *Self, c: *Conn) u32 {
            return @intCast((@intFromPtr(c) - @intFromPtr(self.conns.ptr)) / @sizeOf(Conn));
        }

        // -- Connection lifecycle ----------------------------------------

        fn acceptConnections(self: *Self) void {
            for (0..ACCEPT_BATCH) |_| {
                const fd = sys.accept(self.listener) catch |err| switch (err) {
                    error.WouldBlock => return,
                    error.Aborted => continue,
                    error.FdLimit, error.Unexpected => return,
                };
                if (self.free_len == 0) {
                    // At capacity: shed load rather than queue unboundedly.
                    sys.close(fd);
                    continue;
                }
                self.free_len -= 1;
                const slot = self.free_slots[self.free_len];
                const c = &self.conns[slot];
                const gen = c.gen +% 1;
                c.* = .{ .fd = fd, .gen = gen, .open = true };
                self.open_count += 1;
                if (self.opts.tls) |cfg| {
                    self.attachTls(c, cfg) catch {
                        self.closeConn(c);
                        continue;
                    };
                }
                self.poller.add(fd, (@as(u64, gen) << 32) | slot, .connection) catch {
                    self.closeConn(c);
                    continue;
                };
                self.arm(c, .active);
                if (self.opts.read_on_accept) {
                    c.read_ready = true;
                    self.onReadable(c);
                }
            }
        }

        fn attachTls(self: *Self, c: *Conn, cfg: *const tls.Config) !void {
            var entropy: [tls.entropy_len]u8 = undefined;
            self.rng.fill(&entropy);
            defer std.crypto.secureZero(u8, &entropy);
            c.tls = try self.tls_pools.?.createConn(cfg, &entropy);
        }

        /// Close after the final response, lingering if the session asks.
        fn finish(self: *Self, c: *Conn) void {
            if (c.tls) |t| {
                t.close();
                self.tlsWriteOnce(c, t);
            }
            if (!c.session.linger or c.peer_closed) return self.closeConn(c);
            sys.shutdownWrite(c.fd);
            c.session.deinit(&self.pool);
            c.lingering = true;
            self.arm(c, .active);
            self.drainLingering(c);
        }

        fn drainLingering(self: *Self, c: *Conn) void {
            var scratch: [16 * 1024]u8 = undefined;
            while (true) {
                const n = sys.read(c.fd, &scratch) catch |err| switch (err) {
                    error.WouldBlock => {
                        c.read_ready = false;
                        return;
                    },
                    else => return self.closeConn(c),
                };
                c.lingered +|= @intCast(n);
                if (n == 0 or c.lingered > sys.max_linger_bytes) return self.closeConn(c);
            }
        }

        fn closeConn(self: *Self, c: *Conn) void {
            if (c.tls) |t| {
                // close_notify, unless an alert went out or output is stuck.
                if (t.isEstablished() and !t.hasWire()) {
                    t.close();
                    self.tlsWriteOnce(c, t);
                }
            }
            sys.close(c.fd);
            self.releaseConn(c);
        }

        fn releaseConn(self: *Self, c: *Conn) void {
            self.unlink(c);
            c.session.deinit(&self.pool);
            self.freePending(c);
            if (c.exchange != NIL) _ = self.dropExchange(c, true);
            if (c.ws) |w| {
                if (@hasDecl(Handler, "handleWSDisconn")) self.handler.handleWSDisconn(w);
                w.destroy();
                c.ws = null;
            }
            if (c.h2) |conn| {
                const ctx = self.h2Context(c);
                conn.abortAll(&ctx);
                conn.deinit(&self.pool);
                self.allocator.destroy(conn);
                c.h2 = null;
                self.h2_count -= 1;
            }
            if (c.tls) |t| {
                self.tls_pools.?.destroyConn(t);
                c.tls = null;
            }
            c.open = false;
            c.fd = -1;
            self.free_slots[self.free_len] = self.slotOf(c);
            self.free_len += 1;
            self.open_count -= 1;
        }

        /// The upgrade response has been written: the connection stays on
        /// this worker and speaks WebSocket from here on.
        fn upgradeConn(self: *Self, c: *Conn) void {
            if (!@hasDecl(Handler, "handleWSFrame")) return self.closeConn(c);
            const w = WsConn.create(self.allocator, &self.pool, c.fd, self.opts.websocket, &self.mailbox, .{ .kind = .ws, .slot = self.slotOf(c), .gen = @intCast(c.gen & 0x7fffffff) }) catch {
                return self.closeConn(c);
            };
            c.ws = w;
            w.enableDeflate(c.session.ws_deflate);
            // Bytes after the upgrade request are the first frames.
            w.decoder.adopt(c.session.buf, c.session.start, c.session.end);
            c.session = .{};
            self.unlink(c);
            if (@hasDecl(Handler, "handleWSConn")) self.handler.handleWSConn(w);
            if (!self.wsProcess(c)) return;
            if (c.read_ready or (c.tls != null and c.tls.?.hasBufferedInput())) self.wsReadable(c);
        }

        fn freePending(self: *Self, c: *Conn) void {
            if (c.pending_head.len > 0) self.allocator.free(c.pending_head);
            if (c.pending_body_owned.len > 0) self.allocator.free(c.pending_body_owned);
            c.pending_head = &.{};
            c.pending_head_pos = 0;
            c.pending_body = "";
            c.pending_body_owned = &.{};
            c.pending_tail = "";
            if (c.pending_file) |f| f.release();
            c.pending_file = null;
            if (c.release) |r| {
                r.call();
                c.release = null;
            }
        }

        // -- Exchanges ----------------------------------------------------

        /// The session returned `.wait`: the handler took an exchange for
        /// this request. Bind it to the connection.
        fn bindExchange(self: *Self, c: *Conn) void {
            const ex = self.resp.exchange;
            c.exchange = ex.slot;
            self.exchanges.bindHttp1(ex, self.slotOf(c), c.gen, &c.session, self.resp, self.now);
        }

        /// Writes queued exchange output until the socket is full or the
        /// queue is empty. Returns false if the connection is gone.
        fn exchangeFlush(self: *Self, c: *Conn) bool {
            while (!c.hasPending()) {
                const ex = self.exchanges.handle(c.exchange);
                const r = ex.fill(&self.out, &self.date_line, self.now);
                if (r.aborted) {
                    self.out.clear();
                    self.closeConn(c);
                    return false;
                }
                c.release = r.release;
                if (!self.out.isEmpty()) {
                    if (!self.writeOut(c)) return false;
                }
                if (r.notify and @hasDecl(Handler, "handleWritable")) self.handler.handleWritable(ex);
                if (c.hasPending()) {
                    c.after_flush = if (r.done) .exchange_done else .none;
                    self.arm(c, .active);
                    return true;
                }
                if (c.release) |rel| {
                    rel.call();
                    c.release = null;
                }
                if (r.done) {
                    self.exchangeDone(c);
                    return false;
                }
                if (!r.progressed) break;
            }
            return true;
        }

        /// Ends the exchange and lets the connection go on: close if the
        /// request asked for it, otherwise the next pipelined request.
        fn exchangeDone(self: *Self, c: *Conn) void {
            const keep_alive = self.exchanges.entry(c.exchange).keep_alive;
            if (self.dropExchange(c, false)) {
                // Answered before its body was all in: the rest can't be
                // told from the next request.
                c.session.linger = true;
                return self.finish(c);
            }
            if (!keep_alive) return self.finish(c);
            self.onReadable(c);
        }

        /// Frees the connection's exchange. `gone` means it did not end
        /// through the handle: the handler is told through handleAbort if
        /// it may still be using it. Returns whether a streamed request
        /// body was still arriving.
        fn dropExchange(self: *Self, c: *Conn, gone: bool) bool {
            const slot = c.exchange;
            c.exchange = NIL;
            const unread = c.session.endWait();
            if (c.release) |r| {
                r.call();
                c.release = null;
            }
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

        /// A post from the mailbox for an exchange.
        fn exchangePosted(self: *Self, slot: u32, gen: u31) void {
            const e = self.exchanges.entry(slot);
            if (!e.active or (e.gen & 0x7fffffff) != gen or !e.bound) return;
            if (e.conn_slot & quic_endpoint.exchange_slot_flag != 0) {
                if (self.quic) |*ep| ep.onExchangePosted(e.conn_slot, e.conn_gen, slot, nowUs());
                return;
            }
            const c = &self.conns[e.conn_slot];
            if (!c.open or c.gen != e.conn_gen) return;
            if (c.h2) |conn| {
                if (c.lingering) return;
                const ctx = self.h2Context(c);
                conn.onExchangePosted(Handler, &ctx, slot);
                _ = self.h2Flush(c);
                return;
            }
            if (c.exchange != slot or c.ws != null or c.lingering) return;
            if (self.exchanges.handle(slot).takeResume()) c.session.body_paused = false;
            if (!self.exchangeFlush(c)) return;
            self.resumeBody(c);
        }

        /// Reads on while a streamed request body is wanted and no output
        /// is stalled (the body's bytes may already be buffered).
        fn resumeBody(self: *Self, c: *Conn) void {
            if (c.session.wantsBody() and !c.hasPending()) self.onReadable(c);
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
                .pool = &self.pool,
                .fd = c.fd,
                .early_data = earlyData(c),
            };
        }

        /// The connection's input is TLS early data (0-RTT).
        fn earlyData(c: *const Conn) bool {
            return if (c.tls) |t| t.inEarlyData() else false;
        }

        /// Switches the connection to HTTP/2, adopting any bytes the
        /// session already holds (the preface, perhaps more).
        fn attachH2(self: *Self, c: *Conn) bool {
            const conn = self.allocator.create(H2Conn) catch return false;
            conn.* = H2Conn.init(self.allocator, self.opts.h2, &self.pool) catch {
                self.allocator.destroy(conn);
                return false;
            };
            const s = &c.session;
            if (s.buf.len > 0) {
                conn.reader.buf = s.buf;
                conn.reader.start = s.start;
                conn.reader.end = s.end;
                s.* = .{};
            }
            c.h2 = conn;
            c.proto_decided = true;
            self.h2_count += 1;
            return true;
        }

        /// Plaintext with h2c: the first bytes decide. Returns false while
        /// undecided (more bytes needed).
        fn decideProto(self: *Self, c: *Conn) bool {
            if (c.proto_decided) return true;
            if (c.tls) |t| {
                // ALPN decides, once the handshake is done. Application
                // data from the same read may already sit in the session
                // buffer; attachH2 adopts it.
                // Nothing to decide yet: carry on (the handshake flight
                // still has to be written), and look again later. With
                // 0-RTT accepted, ALPN is known before the handshake ends.
                if (!t.isEstablished() and !t.inEarlyData()) return true;
                c.proto_decided = true;
                if (isH2(t.earlyAlpn())) {
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

        fn onH2Event(self: *Self, c: *Conn, ev: Poller.Event) void {
            if (Poller.writable(ev) and c.h2HasWire()) {
                if (!self.h2Flush(c)) return;
                // Output drained: pending stream data and parsing resume.
                if (!c.h2HasWire() and !self.h2Process(c)) return;
            }
            const tls_buffered = c.tls != null and c.tls.?.hasBufferedInput();
            if ((c.read_ready or tls_buffered) and !c.h2HasWire()) self.h2Readable(c);
        }

        fn h2Readable(self: *Self, c: *Conn) void {
            // Our SETTINGS, queued when the connection switched to
            // HTTP/2, go out first: input already decrypted (the client's
            // first requests, perhaps in 0-RTT data) mustn't wait behind
            // them for another read event.
            if (c.h2HasWire() and !self.h2Flush(c)) return;
            while (!c.h2HasWire()) {
                const tls_buffered = c.tls != null and c.tls.?.hasBufferedInput();
                if (!c.read_ready and !tls_buffered) break;
                if (c.read_ready and !self.readSocket(c)) return;
                if (c.tls) |t| {
                    if (!self.tlsDecrypt(c, t)) return;
                }
                if (!self.h2Process(c)) return;
                if (c.peer_closed) return self.closeConn(c);
            }
            self.h2Timer(c);
        }

        /// Runs the connection over buffered input and writes its output.
        /// Returns false if the connection is gone.
        fn h2Process(self: *Self, c: *Conn) bool {
            const conn = c.h2.?;
            while (true) {
                const ctx = self.h2Context(c);
                const action = conn.process(Handler, &ctx);
                if (!self.h2Flush(c)) return false;
                switch (action) {
                    .flush => if (c.h2HasWire()) break,
                    .need_more => break,
                    .close => {
                        if (c.h2HasWire()) break;
                        self.closeConn(c);
                        return false;
                    },
                }
            }
            conn.releaseIfIdle(&self.pool);
            if (c.tls) |t| t.releaseIfIdle();
            self.h2Timer(c);
            return true;
        }

        /// Writes queued frames (through TLS if set). Closes once drained
        /// if the connection wants it. Returns false if it is gone.
        fn h2Flush(self: *Self, c: *Conn) bool {
            const conn = c.h2.?;
            while (true) {
                if (userTls(c)) |t| {
                    const progressed = self.tlsFlush(c, t) orelse return false;
                    if (t.hasWire()) {
                        self.h2Timer(c);
                        _ = progressed;
                        return true;
                    }
                    const bytes = conn.wireBytes();
                    if (bytes.len == 0) break;
                    const n = t.encrypt(&.{bytes}) catch {
                        self.closeConn(c);
                        return false;
                    };
                    conn.advance(n);
                    continue;
                }
                const bytes = conn.wireBytes();
                if (bytes.len == 0) break;
                switch (self.kernelGate(c)) {
                    .ready => {},
                    .blocked => {
                        self.h2Timer(c);
                        return true;
                    },
                    .closed => return false,
                }
                const n = sys.write(c.fd, bytes) catch |err| switch (err) {
                    error.WouldBlock => {
                        self.h2Timer(c);
                        return true;
                    },
                    else => {
                        self.closeConn(c);
                        return false;
                    },
                };
                conn.advance(n);
                if (!self.kernelWrote(c, n)) return false;
                if (n < bytes.len) {
                    self.h2Timer(c);
                    return true;
                }
            }
            if (conn.wantsClose()) {
                self.closeConn(c);
                return false;
            }
            // Output drained: streams waiting for room continue.
            const ctx = self.h2Context(c);
            conn.pump(Handler, &ctx);
            if (conn.hasWire()) return self.h2Flush(c);
            // Written: buffers go back (exchange posts and deadlines end
            // here, not in h2Process).
            conn.releaseIfIdle(&self.pool);
            if (c.tls) |t| t.releaseIfIdle();
            self.h2Timer(c);
            return true;
        }

        /// Stalled output gets the request timeout; an idle connection the
        /// keep-alive timeout; one with streams in flight relies on the
        /// stream and exchange deadlines.
        fn h2Timer(self: *Self, c: *Conn) void {
            const conn = c.h2.?;
            if (c.h2HasWire()) {
                if (c.list != .active) self.arm(c, .active);
            } else if (conn.activeStreams() == 0 and !conn.inFrame()) {
                self.arm(c, .idle);
            } else {
                self.unlink(c);
            }
        }

        // -- I/O -----------------------------------------------------------

        fn onConnEvent(self: *Self, ev: Poller.Event, token: u64) void {
            const slot: u32 = @truncate(token);
            const gen: u32 = @intCast(token >> 32);
            const c = &self.conns[slot];
            // The slot may have been closed (and reused) earlier in this batch.
            if (!c.open or c.gen != gen) return;
            if (Poller.readable(ev)) c.read_ready = true;
            if (c.ws != null) return self.onWsEvent(c, ev);
            if (c.h2 != null) return self.onH2Event(c, ev);
            if (c.lingering) {
                if (c.read_ready) self.drainLingering(c);
                return;
            }
            if (Poller.writable(ev) and c.hasPending()) {
                if (!self.writePending(c)) return;
            }
            // Reading pauses while output is stalled, and while an
            // exchange is pending (its response goes out before any
            // further pipelined request is parsed), unless its request
            // body is streaming in.
            if (c.read_ready and !c.hasPending() and (c.exchange == NIL or c.session.wantsBody())) self.onReadable(c);
        }

        fn onReadable(self: *Self, c: *Conn) void {
            while (true) {
                if (c.read_ready and !self.readSocket(c)) return;
                if (c.tls) |t| {
                    if (!self.tlsDecrypt(c, t)) return;
                }
                if (c.h2 != null) return self.h2Readable(c);
                if (!self.decideProto(c)) {
                    if (!c.open) return;
                    if (c.h2 != null) return self.h2Readable(c);
                    if (c.peer_closed) return self.closeConn(c);
                    // Part of a preface: wait for the rest.
                    if (!c.read_ready) break;
                    continue;
                }
                if (c.h2 != null) return self.h2Readable(c);
                switch (self.processBuffered(c)) {
                    .ok => {},
                    .blocked => return self.updateTimer(c),
                    .gone => return,
                }
                if (c.peer_closed) return self.closeConn(c);
                if (!c.read_ready and !(c.tls != null and c.tls.?.hasBufferedInput())) break;
            }
            c.session.releaseIfIdle(&self.pool);
            if (c.tls) |t| t.releaseIfIdle();
            self.updateTimer(c);
        }

        /// Reads into the TLS connection, else the WebSocket decoder, else
        /// the session. Returns false if the connection was closed.
        fn readSocket(self: *Self, c: *Conn) bool {
            const space = blk: {
                if (c.tls) |t| break :blk t.readSpace();
                if (c.ws) |w| break :blk w.decoder.readSpace();
                if (c.h2) |conn| break :blk conn.readSpace(&self.pool);
                break :blk c.session.readSpace(&self.pool, self.opts.session);
            } catch {
                self.closeConn(c);
                return false;
            };
            // TLS: decrypted data not yet taken fills the buffer.
            if (space.len == 0) return true;
            if (sys.read(c.fd, space)) |n| {
                if (n == 0) {
                    c.peer_closed = true;
                    c.read_ready = false;
                    return true;
                }
                if (c.tls) |t| {
                    t.commitRead(n);
                } else if (c.ws) |w| {
                    w.decoder.commitRead(n);
                } else if (c.h2) |conn| {
                    conn.commitRead(n);
                } else {
                    c.session.commitRead(n);
                }
                // A short read drained the socket; edge triggering reports
                // any newer data. Saves a read() == EAGAIN.
                if (n < space.len) c.read_ready = false;
            } else |err| switch (err) {
                error.WouldBlock => c.read_ready = false,
                else => {
                    self.closeConn(c);
                    return false;
                },
            }
            return true;
        }

        const ProcessResult = enum { ok, blocked, gone };

        fn processBuffered(self: *Self, c: *Conn) ProcessResult {
            const ctx: session.Context(Handler) = .{
                .handler = self.handler,
                .req = self.req,
                .resp = self.resp,
                .date = &self.date_line,
                .opts = self.opts.session,
                .early_data = earlyData(c),
            };
            while (true) {
                const action = session.process(Handler, &c.session, &ctx, &self.out);
                if (!self.out.isEmpty()) {
                    if (!self.writeOut(c)) return .gone;
                    if (c.hasPending()) {
                        c.after_flush = switch (action) {
                            .close => .close,
                            .upgrade => .upgrade,
                            .flush, .need_more => .none,
                            .wait => blk: {
                                if (c.exchange == NIL) self.bindExchange(c);
                                break :blk .none;
                            },
                        };
                        return .blocked;
                    }
                }
                switch (action) {
                    .flush => continue,
                    .need_more => return .ok,
                    .close => {
                        self.finish(c);
                        return .gone;
                    },
                    .upgrade => {
                        self.upgradeConn(c);
                        return .gone;
                    },
                    .wait => {
                        if (c.exchange == NIL) self.bindExchange(c);
                        if (!self.exchangeFlush(c)) return .gone;
                        // A streamed body: deliver what is buffered.
                        if (c.session.wantsBody() and !c.hasPending()) continue;
                        return .blocked;
                    },
                }
            }
        }

        /// Writes the worker's Out buffer. Anything unsent is copied into
        /// the connection (Out and the response are reused). Returns false
        /// if the connection was closed.
        fn writeOut(self: *Self, c: *Conn) bool {
            if (userTls(c)) |t| {
                // A file body: the kernel sends it (kTLS and sendfile), from
                // now on everything on this connection.
                if (self.out.file != null) self.tryKernelTx(c, t);
                if (!t.kernel_tx) return self.tlsWriteOut(c, t);
            }
            var iov: [3]sys.iovec_const = undefined;
            const total = self.out.totalLen();
            const gate = self.kernelGate(c);
            if (gate == .closed) {
                if (self.out.file) |f| f.release();
                self.out.clear();
                return false;
            }
            const n = if (gate == .blocked) 0 else sys.writev(c.fd, self.out.iovecs(&iov)) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => {
                    if (self.out.file) |f| f.release();
                    self.out.clear();
                    self.closeConn(c);
                    return false;
                },
            };
            if (n > 0 and !self.kernelWrote(c, n)) {
                if (self.out.file) |f| f.release();
                self.out.clear();
                return false;
            }
            if (n == total) {
                const file = self.out.file;
                self.out.clear();
                if (file) |f| {
                    c.pending_file = f;
                    return self.writeFile(c) != null;
                }
                return true;
            }
            self.savePending(c, n) catch {
                self.out.clear();
                self.closeConn(c);
                return false;
            };
            self.out.clear();
            return true;
        }

        fn savePending(self: *Self, c: *Conn, written: usize) !void {
            const out = &self.out;
            // Whatever happens next, the connection owns the file now.
            c.pending_file = out.file;
            out.file = null;
            if (written < out.len) {
                c.pending_head = try self.allocator.dupe(u8, out.buf[written..out.len]);
                c.pending_head_pos = 0;
            }
            const body_written = @min(written -| out.len, out.body.len);
            c.pending_tail = out.tail[written -| (out.len + out.body.len)..];
            const body_rest = out.body[body_written..];
            if (body_rest.len == 0) return;
            const resp_buf = self.resp.body_buf;
            const in_resp_buf = @intFromPtr(body_rest.ptr) >= @intFromPtr(resp_buf.ptr) and
                @intFromPtr(body_rest.ptr) < @intFromPtr(resp_buf.ptr) + resp_buf.len;
            if (in_resp_buf) {
                // The worker's response buffer is reused by the next request.
                c.pending_body_owned = try self.allocator.dupe(u8, body_rest);
                c.pending_body = c.pending_body_owned;
            } else {
                // Borrowed bodies are immutable until sent (setBodyBorrowed).
                c.pending_body = body_rest;
            }
        }

        /// Continues a partial write. Returns false if the connection is gone.
        fn writePending(self: *Self, c: *Conn) bool {
            const progressed = (if (userTls(c)) |t| self.tlsWritePending(c, t) else self.writePendingPlain(c)) orelse
                return false;
            if (c.hasPending()) {
                // Progress extends the deadline; a stalled reader still times out.
                if (progressed) self.arm(c, .active);
                return true;
            }
            self.freePending(c);
            switch (c.after_flush) {
                .close => {
                    self.finish(c);
                    return false;
                },
                .upgrade => {
                    self.upgradeConn(c);
                    return false;
                },
                .exchange_done => {
                    c.after_flush = .none;
                    self.exchangeDone(c);
                    return false;
                },
                .none => {},
            }
            if (c.exchange != NIL) {
                if (self.exchangeFlush(c)) self.resumeBody(c);
                return false;
            }
            // Resume: buffered requests may be waiting even if no new data
            // arrives.
            self.onReadable(c);
            return false;
        }

        /// Writes pending plaintext. Returns whether bytes were written, or
        /// null if the connection was closed.
        fn writePendingPlain(self: *Self, c: *Conn) ?bool {
            var iov: [3]sys.iovec_const = undefined;
            var iov_len: usize = 0;
            const head_rest = c.pending_head[c.pending_head_pos..];
            if (head_rest.len > 0) {
                iov[iov_len] = .{ .base = head_rest.ptr, .len = head_rest.len };
                iov_len += 1;
            }
            if (c.pending_body.len > 0) {
                iov[iov_len] = .{ .base = c.pending_body.ptr, .len = c.pending_body.len };
                iov_len += 1;
            }
            if (c.pending_tail.len > 0) {
                iov[iov_len] = .{ .base = c.pending_tail.ptr, .len = c.pending_tail.len };
                iov_len += 1;
            }
            switch (self.kernelGate(c)) {
                .ready => {},
                .blocked => return false,
                .closed => return null,
            }
            var n: usize = 0;
            if (iov_len > 0) {
                n = sys.writev(c.fd, iov[0..iov_len]) catch |err| switch (err) {
                    error.WouldBlock => return false,
                    else => {
                        self.closeConn(c);
                        return null;
                    },
                };
                advancePending(c, n);
                if (!self.kernelWrote(c, n)) return null;
                if (c.pendingBytes()) return n > 0;
            }
            const file_progress = self.writeFile(c) orelse return null;
            return n > 0 or file_progress;
        }

        /// Sends the pending file body until it is done or the socket is
        /// full: sendfile(2), or read and write where it isn't supported.
        /// Returns whether bytes were written, or null if the connection
        /// was closed.
        fn writeFile(self: *Self, c: *Conn) ?bool {
            var progressed = false;
            while (c.pending_file) |*f| {
                if (f.len == 0) {
                    f.release();
                    c.pending_file = null;
                    break;
                }
                switch (self.kernelGate(c)) {
                    .ready => {},
                    .blocked => return progressed,
                    .closed => return null,
                }
                const count: usize = @intCast(@min(f.len, 1 << 30));
                const n = sys.sendfile(c.fd, f.fd, f.offset, count) catch |err| switch (err) {
                    error.WouldBlock => return progressed,
                    error.Unsupported => self.writeFileCopy(c, f) catch |e| switch (e) {
                        error.WouldBlock => return progressed,
                        else => {
                            self.closeConn(c);
                            return null;
                        },
                    },
                    else => {
                        // A connection error, or the file shrank: the
                        // response can't be completed.
                        self.closeConn(c);
                        return null;
                    },
                };
                f.offset += n;
                f.len -= n;
                progressed = true;
                if (!self.kernelWrote(c, n)) return null;
            }
            return progressed;
        }

        /// The connection's TLS, if we still encrypt its output (not once
        /// the kernel does: then writes are plaintext).
        inline fn userTls(c: *const Conn) ?*TlsConn {
            const t = c.tls orelse return null;
            return if (t.kernel_tx) null else t;
        }

        /// Counts records the kernel made for `n` bytes written (kTLS).
        fn kernelWrote(_: *Self, c: *Conn, n: usize) bool {
            if (c.tls) |t| {
                if (t.kernel_tx) t.kernelWrote(n);
            }
            return true;
        }

        const Gate = enum { ready, blocked, closed };

        /// Before writing data through the kernel (kTLS): our KeyUpdate,
        /// if due, goes first (RFC 8446 §4.6.3), then the kernel gets the
        /// next key. `.blocked`: the socket is full, wait for room. Closes
        /// the connection if the kernel can't switch keys (before TLS 1.3
        /// rekey support).
        fn kernelGate(self: *Self, c: *Conn) Gate {
            const t = c.tls orelse return .ready;
            if (!t.kernel_tx or !t.kernel_key_update) return .ready;
            const msg = TlsConn.kernel_key_update_message;
            const n = sys.ktls.sendRecord(c.fd, tls_handshake, msg) catch |err| switch (err) {
                error.WouldBlock => return .blocked,
                else => 0,
            };
            if (n == msg.len) {
                t.kernelNextKey();
                var info: [56]u8 = undefined;
                defer std.crypto.secureZero(u8, &info);
                if (sys.ktls.rekeyTx(c.fd, t.kernelTxInfo(&info))) |_| return .ready else |_| {}
            }
            // Our records no longer match the client's keys: no alert.
            t.close_sent = true;
            self.closeConn(c);
            return .closed;
        }

        /// Hands the sending side to the kernel, before an HTTP/1.1 file
        /// body (see Options.ktls), if our own records are all written.
        fn tryKernelTx(self: *Self, c: *Conn, t: *TlsConn) void {
            if (!self.ktls_on or !t.kernelTxReady()) return;
            var info: [56]u8 = undefined;
            sys.ktls.enableTx(c.fd, t.kernelTxInfo(&info)) catch |err| {
                std.crypto.secureZero(u8, &info);
                // No tls module: don't try again on this worker.
                if (err == error.NoModule) self.ktls_on = false;
                return;
            };
            std.crypto.secureZero(u8, &info);
            t.startKernelTx();
        }

        fn writeFileCopy(self: *Self, c: *Conn, f: *const File) !usize {
            const chunk = self.file_buf[0..@intCast(@min(f.len, self.file_buf.len))];
            const got = try sys.pread(f.fd, chunk, f.offset);
            if (got < chunk.len) return error.FileTruncated;
            return sys.write(c.fd, chunk);
        }

        fn advancePending(c: *Conn, n: usize) void {
            const from_head = @min(n, c.pending_head.len - c.pending_head_pos);
            c.pending_head_pos += from_head;
            const from_body = @min(n - from_head, c.pending_body.len);
            c.pending_body = c.pending_body[from_body..];
            c.pending_tail = c.pending_tail[n - from_head - from_body ..];
        }

        // -- TLS I/O --------------------------------------------------------

        /// Moves decrypted application data into the session (or the
        /// WebSocket decoder), at most one buffer's worth: the caller
        /// processes it and calls again while `hasBufferedInput`. Also
        /// writes TLS output such as the handshake. Returns false if the
        /// connection was closed.
        fn tlsDecrypt(self: *Self, c: *Conn, t: *TlsConn) bool {
            if (!c.proto_decided and (t.isEstablished() or t.inEarlyData())) {
                // ALPN decided the protocol.
                c.proto_decided = true;
                if (isH2(t.earlyAlpn())) {
                    if (!self.attachH2(c)) {
                        self.closeConn(c);
                        return false;
                    }
                }
            }
            if (t.hasBufferedInput()) {
                const space = blk: {
                    if (c.ws) |w| break :blk w.decoder.readSpace();
                    if (c.h2) |conn| break :blk conn.readSpace(&self.pool);
                    break :blk c.session.readSpace(&self.pool, self.opts.session);
                } catch {
                    self.closeConn(c);
                    return false;
                };
                const n = t.readPlain(space);
                if (c.ws) |w| w.decoder.commitRead(n) else if (c.h2) |conn| conn.commitRead(n) else c.session.commitRead(n);
            }
            if (t.failed) {
                // Send the alert, then give up on the connection.
                self.tlsWriteOnce(c, t);
                self.closeConn(c);
                return false;
            }
            if (t.peer_closed) c.peer_closed = true;
            if (self.kernelGate(c) == .closed) return false;
            return self.tlsFlush(c, t) != null;
        }

        /// Writes TLS records until done or the socket is full. Returns
        /// whether bytes were written, or null if the connection was closed.
        fn tlsFlush(self: *Self, c: *Conn, t: *TlsConn) ?bool {
            if (t.kernel_tx) {
                // Only an alert of ours can be waiting.
                const alert = t.kernel_alert orelse return false;
                _ = sys.ktls.sendRecord(c.fd, tls_alert, &alert) catch |err| switch (err) {
                    error.WouldBlock => return false,
                    else => {
                        self.closeConn(c);
                        return null;
                    },
                };
                t.kernel_alert = null;
                return true;
            }
            var progressed = false;
            while (t.hasWire()) {
                const n = sys.write(c.fd, t.wireBytes()) catch |err| switch (err) {
                    error.WouldBlock => return progressed,
                    else => {
                        self.closeConn(c);
                        return null;
                    },
                };
                t.advance(n);
                progressed = true;
            }
            return progressed;
        }

        /// Best effort before closing (alerts, close_notify): one write.
        fn tlsWriteOnce(_: *Self, c: *Conn, t: *TlsConn) void {
            if (t.kernel_tx) {
                const alert = t.kernel_alert orelse return;
                _ = sys.ktls.sendRecord(c.fd, tls_alert, &alert) catch {};
                t.kernel_alert = null;
                return;
            }
            if (!t.hasWire()) return;
            const n = sys.write(c.fd, t.wireBytes()) catch return;
            t.advance(n);
        }

        /// Encrypts the worker's Out buffer and writes it. Plaintext that
        /// didn't fit in the TLS output buffer is kept like an unsent
        /// response. Returns false if the connection was closed.
        fn tlsWriteOut(self: *Self, c: *Conn, t: *TlsConn) bool {
            const out = &self.out;
            defer out.clear();
            const total = out.totalLen();
            var consumed: usize = 0;
            // Encrypt and write until done or the socket is full. Stopping
            // with the wire drained but plaintext left would wait for a
            // writability edge that never comes.
            while (true) {
                const head = out.buf[@min(consumed, out.len)..out.len];
                const body = out.body[@min(consumed -| out.len, out.body.len)..];
                const tail = out.tail[consumed -| (out.len + out.body.len)..];
                consumed += t.encrypt(&.{ head, body, tail }) catch {
                    self.closeConn(c);
                    return false;
                };
                if (self.tlsFlush(c, t) == null) return false;
                if (consumed == total or t.hasWire()) break;
            }
            if (consumed < total or out.file != null) {
                self.savePending(c, consumed) catch {
                    self.closeConn(c);
                    return false;
                };
                // A file body follows the head: encrypt it as the socket
                // takes it.
                if (consumed == total and !t.hasWire()) return self.tlsWritePending(c, t) != null;
            }
            return true;
        }

        /// Writes TLS records, encrypting pending plaintext as they drain.
        fn tlsWritePending(self: *Self, c: *Conn, t: *TlsConn) ?bool {
            var progressed = false;
            while (true) {
                progressed = (self.tlsFlush(c, t) orelse return null) or progressed;
                if (t.hasWire() or !c.hasPendingPlain()) return progressed;
                if (!c.pendingBytes()) {
                    // The file body: a record's worth at a time.
                    const f = &c.pending_file.?;
                    if (f.len == 0) {
                        f.release();
                        c.pending_file = null;
                        continue;
                    }
                    const chunk = self.file_buf[0..@intCast(@min(f.len, self.file_buf.len))];
                    const got = sys.pread(f.fd, chunk, f.offset) catch 0;
                    if (got < chunk.len) {
                        self.closeConn(c);
                        return null;
                    }
                    const consumed = t.encrypt(&.{chunk}) catch {
                        self.closeConn(c);
                        return null;
                    };
                    f.offset += consumed;
                    f.len -= consumed;
                    continue;
                }
                const consumed = t.encrypt(&.{ c.pending_head[c.pending_head_pos..], c.pending_body, c.pending_tail }) catch {
                    self.closeConn(c);
                    return null;
                };
                advancePending(c, consumed);
            }
        }

        // -- WebSocket I/O ------------------------------------------------

        /// A stalled write: WebSocket bytes, or TLS records, not yet written.
        fn wsHasWire(c: *const Conn) bool {
            return c.ws.?.hasWire() or (c.tls != null and c.tls.?.hasWire());
        }

        fn onWsEvent(self: *Self, c: *Conn, ev: Poller.Event) void {
            if (Poller.writable(ev) and wsHasWire(c)) {
                if (!self.wsFlush(c)) return;
            }
            // Reading pauses while output is stalled (backpressure).
            if (c.read_ready and !wsHasWire(c)) self.wsReadable(c);
        }

        fn wsReadable(self: *Self, c: *Conn) void {
            while (!wsHasWire(c)) {
                const tls_buffered = c.tls != null and c.tls.?.hasBufferedInput();
                if (!c.read_ready and !tls_buffered) break;
                if (c.read_ready and !self.readSocket(c)) return;
                if (c.tls) |t| {
                    if (!self.tlsDecrypt(c, t)) return;
                }
                if (!self.wsProcess(c)) return;
                if (c.peer_closed) return self.closeConn(c);
            }
        }

        /// Runs the protocol over buffered input and writes its output.
        /// Returns false if the connection is gone.
        fn wsProcess(self: *Self, c: *Conn) bool {
            const w = c.ws.?;
            _ = w.process(Handler, self.handler);
            if (!self.wsFlush(c)) return false;
            w.decoder.releaseIfIdle();
            return true;
        }

        /// Writes queued output. Closes the socket once it is drained if
        /// the close handshake is over. Returns false if the connection is
        /// gone.
        fn wsFlush(self: *Self, c: *Conn) bool {
            const w = c.ws.?;
            while (true) {
                if (userTls(c)) |t| {
                    // TLS records first, then encrypt more WebSocket output.
                    const progressed = self.tlsFlush(c, t) orelse return false;
                    if (t.hasWire()) {
                        self.wsTimer(c, progressed);
                        return true;
                    }
                    const bytes = w.wireBytes();
                    if (bytes.len == 0) break;
                    const n = t.encrypt(&.{bytes}) catch {
                        self.closeConn(c);
                        return false;
                    };
                    w.advance(n);
                    continue;
                }
                const bytes = w.wireBytes();
                if (bytes.len == 0) break;
                switch (self.kernelGate(c)) {
                    .ready => {},
                    .blocked => {
                        self.wsTimer(c, false);
                        return true;
                    },
                    .closed => return false,
                }
                const n = sys.write(c.fd, bytes) catch |err| switch (err) {
                    error.WouldBlock => {
                        self.wsTimer(c, false);
                        return true;
                    },
                    else => {
                        self.closeConn(c);
                        return false;
                    },
                };
                w.advance(n);
                if (!self.kernelWrote(c, n)) return false;
                if (n < bytes.len) {
                    // Socket buffer full: wait for writability.
                    self.wsTimer(c, true);
                    return true;
                }
            }
            if (w.wantsClose()) {
                self.closeConn(c);
                return false;
            }
            self.wsTimer(c, false);
            return true;
        }

        /// A stalled write or a pending close handshake gets the request
        /// timeout; otherwise WebSocket connections have no timeout.
        fn wsTimer(self: *Self, c: *Conn, progress: bool) void {
            const w = c.ws.?;
            if (wsHasWire(c)) {
                if (progress or c.list != .active) self.arm(c, .active);
            } else if (w.closeSent()) {
                if (c.list != .active) self.arm(c, .active);
            } else {
                self.unlink(c);
            }
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
                    if (!c.open or c.lingering) continue;
                    if (c.ws != null) {
                        self.wsFlushPosted(c);
                    } else if (c.h2 != null) {
                        for (self.exchanges.entries, 0..) |*e, slot| {
                            if (e.active and e.bound and e.conn_slot == self.slotOf(c) and e.conn_gen == c.gen) {
                                self.exchangePosted(@intCast(slot), @intCast(e.gen & 0x7fffffff));
                            }
                        }
                    } else if (c.exchange != NIL) {
                        self.exchangePosted(c.exchange, @intCast(self.exchanges.entry(c.exchange).gen & 0x7fffffff));
                    }
                }
            }
        }

        fn wsFlushPosted(self: *Self, c: *Conn) void {
            const w = c.ws orelse return;
            w.clearPosted();
            if (!self.wsFlush(c)) return;
            // Output may have been stalled; reading resumes once it drains.
            if (c.read_ready and !wsHasWire(c)) self.wsReadable(c);
        }
    };
}
