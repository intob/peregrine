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
            after_flush: enum(u8) { none, close, upgrade } = .none,
            list: ListId = .none,
            prev: u32 = NIL,
            next: u32 = NIL,
            deadline: u32 = 0,
            session: Session = .{},
            /// Set after a WebSocket upgrade; the session is then unused.
            ws: ?*WsConn = null,
            /// Unsent output after a partial write: an owned copy of the
            /// serialised head bytes, then the body (owned or borrowed).
            pending_head: []u8 = &.{},
            pending_head_pos: usize = 0,
            pending_body: []const u8 = "",
            pending_body_owned: []u8 = &.{},

            inline fn hasPending(c: *const Conn) bool {
                return c.pending_head_pos < c.pending_head.len or c.pending_body.len > 0;
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
        /// WebSocket connections with new output (posted from any thread).
        mailbox: ws.Mailbox,
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
            var mailbox = try ws.Mailbox.init(allocator, opts.max_connections, waker);
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
            };
            self.refreshDate();
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
            self.mailbox.deinit();
            self.waker.deinit();
            self.pool.deinit();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.out_buf);
            self.allocator.free(self.conns);
            self.allocator.free(self.free_slots);
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
            c.deadline = self.now +% list.timeout;
            c.prev = list.tail;
            c.next = NIL;
            if (list.tail != NIL) self.conns[list.tail].next = slot else list.head = slot;
            list.tail = slot;
        }

        /// Idle connections get the keep-alive timeout. A partially received
        /// request or unsent response gets the request timeout, which is not
        /// extended by further reads (slowloris), only by write progress.
        fn updateTimer(self: *Self, c: *Conn) void {
            if (c.session.inRequest() or c.hasPending()) {
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

        /// Close after the final response, lingering if the session asks.
        fn finish(self: *Self, c: *Conn) void {
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
            sys.close(c.fd);
            self.releaseConn(c);
        }

        fn releaseConn(self: *Self, c: *Conn) void {
            self.unlink(c);
            c.session.deinit(&self.pool);
            self.freePending(c);
            if (c.ws) |w| {
                if (@hasDecl(Handler, "handleWSDisconn")) self.handler.handleWSDisconn(w);
                w.destroy(&self.pool);
                c.ws = null;
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
            const w = WsConn.create(self.allocator, c.fd, self.opts.websocket, &self.mailbox, self.slotOf(c)) catch {
                return self.closeConn(c);
            };
            c.ws = w;
            // Bytes after the upgrade request are the first frames.
            w.decoder.adopt(c.session.buf, c.session.start, c.session.end);
            c.session = .{};
            self.unlink(c);
            if (@hasDecl(Handler, "handleWSConn")) self.handler.handleWSConn(w);
            if (!self.wsProcess(c)) return;
            if (c.read_ready) self.wsReadable(c);
        }

        fn freePending(self: *Self, c: *Conn) void {
            if (c.pending_head.len > 0) self.allocator.free(c.pending_head);
            if (c.pending_body_owned.len > 0) self.allocator.free(c.pending_body_owned);
            c.pending_head = &.{};
            c.pending_head_pos = 0;
            c.pending_body = "";
            c.pending_body_owned = &.{};
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
            if (c.read_ready and !c.hasPending()) self.onReadable(c);
        }

        fn onReadable(self: *Self, c: *Conn) void {
            while (true) {
                if (c.read_ready) {
                    const space = c.session.readSpace(&self.pool, self.opts.session) catch {
                        return self.closeConn(c);
                    };
                    if (sys.read(c.fd, space)) |n| {
                        if (n == 0) {
                            c.peer_closed = true;
                            c.read_ready = false;
                        } else {
                            c.session.commitRead(n);
                            // A short read drained the socket; edge triggering
                            // reports any newer data. Saves a read() == EAGAIN.
                            if (n < space.len) c.read_ready = false;
                        }
                    } else |err| switch (err) {
                        error.WouldBlock => c.read_ready = false,
                        else => return self.closeConn(c),
                    }
                }
                switch (self.processBuffered(c)) {
                    .ok => {},
                    .blocked => return self.updateTimer(c),
                    .gone => return,
                }
                if (c.peer_closed) return self.closeConn(c);
                if (!c.read_ready) break;
            }
            c.session.releaseIfIdle(&self.pool);
            self.updateTimer(c);
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
                }
            }
        }

        /// Writes the worker's Out buffer. Anything unsent is copied into
        /// the connection (Out and the response are reused). Returns false
        /// if the connection was closed.
        fn writeOut(self: *Self, c: *Conn) bool {
            var iov: [2]sys.iovec_const = undefined;
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
            const body_written = written -| out.len;
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
            var iov: [2]sys.iovec_const = undefined;
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
            const n = sys.writev(c.fd, iov[0..iov_len]) catch |err| switch (err) {
                error.WouldBlock => return true,
                else => {
                    self.closeConn(c);
                    return false;
                },
            };
            const from_head = @min(n, head_rest.len);
            c.pending_head_pos += from_head;
            c.pending_body = c.pending_body[n - from_head ..];
            if (c.hasPending()) {
                // Progress extends the deadline; a stalled reader still times out.
                if (n > 0) self.arm(c, .active);
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
                .none => {},
            }
            // Resume: buffered requests may be waiting even if no new data
            // arrives.
            self.onReadable(c);
            return false;
        }

        // -- WebSocket I/O ------------------------------------------------

        fn onWsEvent(self: *Self, c: *Conn, ev: Poller.Event) void {
            const w = c.ws.?;
            if (Poller.writable(ev) and w.hasWire()) {
                if (!self.wsFlush(c)) return;
            }
            // Reading pauses while output is stalled (backpressure).
            if (c.read_ready and !w.hasWire()) self.wsReadable(c);
        }

        fn wsReadable(self: *Self, c: *Conn) void {
            const w = c.ws.?;
            while (c.read_ready and !w.hasWire()) {
                const space = w.decoder.readSpace(&self.pool) catch return self.closeConn(c);
                if (sys.read(c.fd, space)) |n| {
                    if (n == 0) {
                        c.peer_closed = true;
                        c.read_ready = false;
                    } else {
                        w.decoder.commitRead(n);
                        if (n < space.len) c.read_ready = false;
                    }
                } else |err| switch (err) {
                    error.WouldBlock => c.read_ready = false,
                    else => return self.closeConn(c),
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
            if (w.hasWire()) {
                if (progress or c.list != .active) self.arm(c, .active);
            } else if (w.closeSent()) {
                if (c.list != .active) self.arm(c, .active);
            } else {
                self.unlink(c);
            }
        }

        fn drainMailbox(self: *Self) void {
            var slots: [64]u32 = undefined;
            while (true) {
                const n = self.mailbox.drain(&slots);
                if (n == 0) return;
                for (slots[0..n]) |slot| {
                    const c = &self.conns[slot];
                    const w = c.ws orelse continue;
                    w.clearPosted();
                    if (!self.wsFlush(c)) continue;
                    // Output may have been stalled; reading resumes once it
                    // drains.
                    if (c.read_ready and !w.hasWire()) self.wsReadable(c);
                }
            }
        }
    };
}
