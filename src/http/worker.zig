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
const ws = @import("../ws/conn.zig");
const WsConn = ws.Conn;
const tls = @import("../tls/conn.zig");
const TlsConn = tls.Conn;
const mailbox_mod = @import("../mailbox.zig");
const Mailbox = mailbox_mod.Mailbox;
const exchange = @import("./exchange.zig");

const LISTENER_TOKEN: u64 = std.math.maxInt(u64);
const WAKER_TOKEN: u64 = std.math.maxInt(u64) - 1;
const NIL: u32 = std.math.maxInt(u32);
/// Connections accepted per listener event, to stay fair to existing ones.
const ACCEPT_BATCH = 64;

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
    /// TLS for every connection, if set.
    tls: ?*const tls.Config = null,
    /// TLS record buffers preallocated per worker (input and output each).
    tls_buffer_pool_size: usize = 0,
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
            /// Unsent output after a partial write: an owned copy of the
            /// serialised head bytes, then the body (owned or borrowed),
            /// then the tail (static).
            pending_head: []u8 = &.{},
            pending_head_pos: usize = 0,
            pending_body: []const u8 = "",
            pending_body_owned: []u8 = &.{},
            pending_tail: []const u8 = "",
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

            inline fn hasPendingPlain(c: *const Conn) bool {
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
        date_line: [date.header_len]u8 = undefined,
        now: u32,
        last_realtime: i64 = 0,
        idle: List,
        active: List,
        open_count: usize = 0,
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
            owns_listener: bool,
            opts: Options,
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
            const req = try Request.init(allocator);
            errdefer req.deinit();
            const resp = try Response.init(allocator, opts.response_body_buffer_size, opts.response_header_buffer_size);
            errdefer resp.deinit();
            if (opts.out_buffer_size < session.headRoom(resp)) return error.OutBufferTooSmall;
            const out_buf = try allocator.alloc(u8, opts.out_buffer_size);
            errdefer allocator.free(out_buf);
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
            try self.poller.add(self.listener, LISTENER_TOKEN, .level_read);
            try self.poller.add(self.waker.read_fd, WAKER_TOKEN, .level_read);
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
            self.poller.deinit();
            self.exchanges.deinit();
            self.mailbox.deinit();
            self.waker.deinit();
            self.pool.deinit();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.out_buf);
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
                // until something happens (shutdown uses the waker).
                const timeout: i32 = if (self.open_count == 0) -1 else 1000;
                const n = self.poller.wait(&events, timeout);
                self.tick();
                for (events[0..n]) |ev| {
                    switch (Poller.token(ev)) {
                        LISTENER_TOKEN => self.acceptConnections(),
                        WAKER_TOKEN => self.drainWaker(),
                        else => |token| self.onConnEvent(ev, token),
                    }
                }
                // WebSocket output queued by handlers during this batch, or
                // by other threads (which also wrote the waker).
                self.drainMailbox();
            }
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
        }

        /// Exchanges have their own deadlines (set per exchange), so they
        /// are scanned rather than kept on an ordered list.
        fn expireExchanges(self: *Self) void {
            if (self.exchanges.active_count == 0) return;
            for (self.exchanges.entries, 0..) |*e, slot| {
                if (!e.active) continue;
                if (@as(i32, @bitCast(e.deadline -% self.now)) > 0) continue;
                const c = &self.conns[e.conn_slot];
                if (c.open and c.gen == e.conn_gen and c.exchange == slot) self.closeConn(c);
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
            const t = try self.allocator.create(TlsConn);
            errdefer self.allocator.destroy(t);
            t.* = try TlsConn.init(self.allocator, &self.tls_pools.?, cfg, &entropy);
            c.tls = t;
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
            if (c.exchange != NIL) self.dropExchange(c, true);
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
            const w = WsConn.create(self.allocator, c.fd, self.opts.websocket, &self.mailbox, self.slotOf(c), c.gen) catch {
                return self.closeConn(c);
            };
            c.ws = w;
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
            const e = self.exchanges.entry(ex.slot);
            const s = &c.session;
            c.exchange = ex.slot;
            e.mutex.lock();
            e.conn_slot = self.slotOf(c);
            e.conn_gen = c.gen;
            e.bound = true;
            e.keep_alive = s.wait_keep_alive;
            e.is_head = s.wait_is_head;
            e.http10 = s.wait_http10;
            if (self.resp.mode == .stream) {
                // The session wrote the head; fix the body framing now.
                // beginStream set the state when stream() was called;
                // the handler may have written or finished since.
                e.head_pending = false;
                e.framing = exchange.streamFraming(self.resp.status, s.wait_is_head, s.wait_http10, self.resp.content_length);
                e.deadline = self.now +% self.opts.exchange.request_timeout_s +% 1;
            } else {
                e.head_pending = true;
            }
            e.mutex.unlock();
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
            self.dropExchange(c, false);
            if (!keep_alive) return self.finish(c);
            self.onReadable(c);
        }

        /// Frees the connection's exchange. `gone` means it did not end
        /// through the handle: the handler is told through handleAbort if
        /// it may still be using it.
        fn dropExchange(self: *Self, c: *Conn, gone: bool) void {
            const slot = c.exchange;
            c.exchange = NIL;
            c.session.waiting = false;
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
        }

        /// A post from the mailbox for an exchange.
        fn exchangePosted(self: *Self, slot: u32, gen: u31) void {
            const e = self.exchanges.entry(slot);
            if (!e.active or (e.gen & 0x7fffffff) != gen or !e.bound) return;
            const c = &self.conns[e.conn_slot];
            if (!c.open or c.gen != e.conn_gen or c.exchange != slot) return;
            if (c.ws != null or c.lingering) return;
            _ = self.exchangeFlush(c);
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
            if (c.lingering) {
                if (c.read_ready) self.drainLingering(c);
                return;
            }
            if (Poller.writable(ev) and c.hasPending()) {
                if (!self.writePending(c)) return;
            }
            // Reading pauses while output is stalled, and while an
            // exchange is pending (its response goes out before any
            // further pipelined request is parsed).
            if (c.read_ready and !c.hasPending() and c.exchange == NIL) self.onReadable(c);
        }

        fn onReadable(self: *Self, c: *Conn) void {
            while (true) {
                if (c.read_ready and !self.readSocket(c)) return;
                if (c.tls) |t| {
                    if (!self.tlsDecrypt(c, t)) return;
                }
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
                if (c.ws) |w| break :blk w.decoder.readSpace(&self.pool);
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
                        return .blocked;
                    },
                }
            }
        }

        /// Writes the worker's Out buffer. Anything unsent is copied into
        /// the connection (Out and the response are reused). Returns false
        /// if the connection was closed.
        fn writeOut(self: *Self, c: *Conn) bool {
            if (c.tls) |t| return self.tlsWriteOut(c, t);
            var iov: [3]sys.iovec_const = undefined;
            const total = self.out.totalLen();
            const n = sys.writev(c.fd, self.out.iovecs(&iov)) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => {
                    self.out.clear();
                    self.closeConn(c);
                    return false;
                },
            };
            if (n == total) {
                self.out.clear();
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
            if (written < out.len) {
                c.pending_head = try self.allocator.dupe(u8, out.buf[written..out.len]);
                c.pending_head_pos = 0;
            }
            const body_written = @min(written -| out.len, out.body.len);
            c.pending_tail = out.tail[written -| (out.len + out.body.len) ..];
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
            const progressed = (if (c.tls) |t| self.tlsWritePending(c, t) else self.writePendingPlain(c)) orelse
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
                _ = self.exchangeFlush(c);
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
            const n = sys.writev(c.fd, iov[0..iov_len]) catch |err| switch (err) {
                error.WouldBlock => return false,
                else => {
                    self.closeConn(c);
                    return null;
                },
            };
            advancePending(c, n);
            return n > 0;
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
            if (t.hasBufferedInput()) {
                const space = blk: {
                    if (c.ws) |w| break :blk w.decoder.readSpace(&self.pool);
                    break :blk c.session.readSpace(&self.pool, self.opts.session);
                } catch {
                    self.closeConn(c);
                    return false;
                };
                const n = t.readPlain(space);
                if (c.ws) |w| w.decoder.commitRead(n) else c.session.commitRead(n);
            }
            if (t.failed) {
                // Send the alert, then give up on the connection.
                self.tlsWriteOnce(c, t);
                self.closeConn(c);
                return false;
            }
            if (t.peer_closed) c.peer_closed = true;
            return self.tlsFlush(c, t) != null;
        }

        /// Writes TLS records until done or the socket is full. Returns
        /// whether bytes were written, or null if the connection was closed.
        fn tlsFlush(self: *Self, c: *Conn, t: *TlsConn) ?bool {
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
            if (consumed < total) {
                self.savePending(c, consumed) catch {
                    self.closeConn(c);
                    return false;
                };
            }
            return true;
        }

        /// Writes TLS records, encrypting pending plaintext as they drain.
        fn tlsWritePending(self: *Self, c: *Conn, t: *TlsConn) ?bool {
            var progressed = false;
            while (true) {
                progressed = (self.tlsFlush(c, t) orelse return null) or progressed;
                if (t.hasWire() or !c.hasPendingPlain()) return progressed;
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
            w.decoder.releaseIfIdle(&self.pool);
            return true;
        }

        /// Writes queued output. Closes the socket once it is drained if
        /// the close handshake is over. Returns false if the connection is
        /// gone.
        fn wsFlush(self: *Self, c: *Conn) bool {
            const w = c.ws.?;
            while (true) {
                if (c.tls) |t| {
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
                for (self.conns) |*c| {
                    if (!c.open) continue;
                    if (c.ws != null) {
                        self.wsFlushPosted(c);
                    } else if (c.exchange != NIL and !c.lingering) {
                        _ = self.exchangeFlush(c);
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
