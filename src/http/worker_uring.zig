//! Completion-based (io_uring) event loop for Linux. Same Session state
//! machine as worker.zig, different I/O:
//!
//! - multishot accept on the worker's own SO_REUSEPORT listener
//! - recv with kernel-selected provided buffers, so idle connections hold no
//!   buffer; a recv is armed only when the connection is ready for more input
//!   (natural backpressure)
//! - writes queued as SQEs, so one io_uring_enter submits every recv and write
//!   produced by a batch of completions
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
const WebsocketServer = @import("../ws/server.zig").WebsocketServer;
const Options = @import("./worker.zig").Options;

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
};

inline fn userData(gen: u32, slot: u32, op: Op) u64 {
    return (@as(u64, gen) << 32) | (@as(u64, slot) << 8) | @intFromEnum(op);
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
            after_write: enum(u8) { none, close, upgrade } = .none,
            list: ListId = .none,
            prev: u32 = NIL,
            next: u32 = NIL,
            deadline: u32 = 0,
            session: Session = .{},
            /// The session buffer is a kernel-provided recv buffer.
            borrowed: bool = false,
            /// This connection's output. Owned while a write is in flight.
            out: Out = .{ .buf = &.{} },
            out_body_owned: []u8 = &.{},
            sent: usize = 0,
            iov: [2]sys.iovec_const = undefined,
        };

        const List = struct {
            head: u32 = NIL,
            tail: u32 = NIL,
            timeout: u32,
        };

        id: usize,
        allocator: std.mem.Allocator,
        handler: *Handler,
        ws: *WebsocketServer(Handler),
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
        tick_ts: linux.kernel_timespec = .{ .sec = 1, .nsec = 0 },
        tick_armed: bool = false,
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
        thread: ?std.Thread = null,

        pub const InitConfig = struct {
            id: usize,
            allocator: std.mem.Allocator,
            handler: *Handler,
            ws: *WebsocketServer(Handler),
            shutdown: *const std.atomic.Value(bool),
            listener: sys.fd_t,
            opts: Options,
            ring_entries: u16 = 4096,
            recv_buffer_count: u16 = 256,
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
            self.* = .{
                .id = cfg.id,
                .allocator = allocator,
                .handler = cfg.handler,
                .ws = cfg.ws,
                .shutdown = cfg.shutdown,
                .opts = opts,
                .ring = undefined,
                .buffers = undefined,
                .listener = cfg.listener,
                .waker = waker,
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
            self.refreshDate();
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
            self.freeBuffers();
            self.ring.deinit();
            self.waker.deinit();
            self.pool.deinit();
            self.out_pool.deinit();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.conns);
            self.allocator.free(self.free_slots);
        }

        fn freeBuffers(self: *Self) void {
            if (!self.buffers_live) return;
            self.buffers.deinit(self.allocator);
            self.buffers_live = false;
        }

        fn run(self: *Self, pin: bool) void {
            defer self.freeBuffers();
            if (pin) sys.pinToCpu(self.id);
            const rc = linux.io_uring_register(self.ring.fd, .REGISTER_ENABLE_RINGS, null, 0);
            if (std.posix.errno(rc) != .SUCCESS) {
                std.debug.print("io_uring enable failed: {s}\n", .{@tagName(std.posix.errno(rc))});
                return;
            }
            self.armAccept();
            self.armWaker();
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
            }
        }

        fn dispatch(self: *Self, cqe: linux.io_uring_cqe) void {
            const ud = cqe.user_data;
            const op: Op = @enumFromInt(@as(u8, @truncate(ud)));
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
                else => {},
            }
            const c = &self.conns[slot];
            if (c.gen != gen) return; // completions of a reused slot never happen (inflight gating)
            c.inflight -= 1;
            switch (op) {
                .recv => self.onRecv(c, cqe),
                .recv_plain => self.onRecvPlain(c, cqe),
                .write => self.onWrite(c, cqe),
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

        fn armWaker(self: *Self) void {
            const sqe = self.getSqe();
            sqe.prep_read(self.waker.read_fd, std.mem.asBytes(&self.waker_buf), 0);
            sqe.user_data = userData(0, SPECIAL_SLOT, .waker);
        }

        fn armTick(self: *Self) void {
            if (self.tick_armed or self.open_count == 0) return;
            const sqe = self.getSqe();
            sqe.prep_timeout(&self.tick_ts, 0, 0);
            sqe.user_data = userData(0, SPECIAL_SLOT, .tick);
            self.tick_armed = true;
        }

        fn armRecv(self: *Self, c: *Conn) void {
            if (c.recv_armed or c.closing or c.peer_closed) return;
            const sqe = self.getSqe();
            sqe.prep_rw(.RECV, c.fd, 0, 0, 0);
            sqe.flags |= linux.IOSQE_BUFFER_SELECT;
            sqe.buf_index = BUFFER_GROUP_ID;
            sqe.user_data = userData(c.gen, self.slotOf(c), .recv);
            c.recv_armed = true;
            c.inflight += 1;
        }

        /// Fallback when the provided-buffer ring is exhausted: receive into
        /// a pooled session buffer instead.
        fn armRecvPlain(self: *Self, c: *Conn) void {
            const space = c.session.readSpace(&self.pool, self.opts.session) catch {
                return self.closeConn(c);
            };
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
            c.deadline = self.now +% list.timeout;
            c.prev = list.tail;
            c.next = NIL;
            if (list.tail != NIL) self.conns[list.tail].next = slot else list.head = slot;
            list.tail = slot;
        }

        fn updateTimer(self: *Self, c: *Conn) void {
            if (c.session.inRequest() or c.write_inflight) {
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
            self.arm(c, .active);
            self.armTick();
            self.armRecv(c);
        }

        /// Close after the final response, lingering if the session asks.
        fn finish(self: *Self, c: *Conn) void {
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

        fn upgradeConn(self: *Self, c: *Conn) void {
            const fd = c.fd;
            self.freeConnResources(c);
            self.releaseSlot(c);
            self.ws.addSocket(fd) catch sys.close(fd);
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
                if (!c.closing) self.drive(c);
                return;
            }
            const data = self.buffers.get(cqe) catch return self.closeConn(c);
            defer self.buffers.put(cqe) catch {};
            if (c.closing) return;
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
            c.sent += @intCast(cqe.res);
            if (cqe.res > 0) self.arm(c, .active);
            if (c.sent < c.out.totalLen()) return self.submitWrite(c);
            c.out.clear();
            c.sent = 0;
            if (c.out_body_owned.len > 0) {
                self.allocator.free(c.out_body_owned);
                c.out_body_owned = &.{};
            }
            switch (c.after_write) {
                .close => return self.finish(c),
                .upgrade => return self.upgradeConn(c),
                .none => self.drive(c),
            }
        }

        /// Runs the session until it needs input, or output must be written
        /// first. Arms the next recv when idle.
        fn drive(self: *Self, c: *Conn) void {
            if (c.write_inflight or c.closing) return;
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
                if (!c.out.isEmpty()) {
                    self.ownBody(c) catch return self.closeConn(c);
                    c.after_write = switch (action) {
                        .close => .close,
                        .upgrade => .upgrade,
                        .flush, .need_more => .none,
                    };
                    self.submitWrite(c);
                    self.updateTimer(c);
                    return;
                }
                switch (action) {
                    .flush => continue,
                    .need_more => break,
                    .close => return self.finish(c),
                    .upgrade => return self.upgradeConn(c),
                }
            }
            if (c.out.buf.len > 0) {
                self.out_pool.release(c.out.buf);
                c.out = .{ .buf = &.{} };
            }
            if (c.peer_closed) return self.closeConn(c);
            if (!c.borrowed) c.session.releaseIfIdle(&self.pool);
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
    };
}
