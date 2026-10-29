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
const File = @import("../response.zig").File;
/// TLS record content types (kTLS control records).
const tls_alert: u8 = 21;
const tls_handshake: u8 = 22;
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
const NIL16: u16 = std.math.maxInt(u16);

/// The ALPN protocol is HTTP/2.
fn isH2(alpn: ?[]const u8) bool {
    return if (alpn) |p| std.mem.eql(u8, p, "h2") else false;
}
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
    /// The socket has room again, for a file body sent with sendfile.
    write_ready,
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
    if (!(probe.is_supported(.ACCEPT) and probe.is_supported(.RECV) and
        probe.is_supported(.SEND) and probe.is_supported(.SENDMSG) and probe.is_supported(.ASYNC_CANCEL) and
        probe.is_supported(.TIMEOUT))) return false;
    var buffers = RecvBuffers.init(ring.fd, std.heap.page_allocator, 64, 1) catch return false;
    buffers.deinit(ring.fd, std.heap.page_allocator);
    return true;
}

/// Registers (or unregisters) a provided-buffer ring. Ubuntu 24.04's
/// kernels from 6.8.0-136 refuse every registration whose reserved words
/// are zero, as the kernel requires (a backport of "io_uring/kbuf: use
/// mem_is_zero()" inverted the check), so after EINVAL this tries once
/// more with a reserved word set, which a correct kernel refuses too.
fn registerBufRing(fd: linux.fd_t, opcode: linux.IORING_REGISTER, addr: u64, entries: u16, group: u16) !void {
    // Not incremental consumption (6.12): it packs receives into buffers
    // back to back, so a request often starts near the end of one and is
    // split across two receives (and copied); 12 KiB uploads cost about 5%
    // more server CPU with it.
    var reg = std.mem.zeroInit(linux.io_uring_buf_reg, .{
        .ring_addr = addr,
        .ring_entries = entries,
        .bgid = group,
    });
    var rc = linux.io_uring_register(fd, opcode, &reg, 1);
    if (linux.errno(rc) == .INVAL) {
        reg.resv[0] = 1;
        rc = linux.io_uring_register(fd, opcode, &reg, 1);
    }
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .INVAL => return error.ArgumentsInvalid,
        else => |e| return std.posix.unexpectedErrno(e),
    }
}

/// A connection's parked receive buffers, oldest first.
const Parked = struct {
    head: u16 = NIL16,
    tail: u16 = NIL16,
};

/// Kernel-provided receive buffers (a registered buffer ring), posted to
/// the kernel from a LIFO stack of free buffers. The kernel takes buffers
/// from the ring in order, so a ring holding every buffer cycles through
/// all of them, each receive landing in cold memory. Only as many as
/// recent batches used (`target`) are posted; the rest wait on the stack,
/// most recently used on top. A receive that finds the ring empty gets
/// ENOBUFS (and a pooled buffer instead), and doubles the target.
const RecvBuffers = struct {
    br: *align(std.heap.page_size_min) linux.io_uring_buf_ring,
    memory: []u8,
    size: u32,
    count: u16,
    /// Free buffer ids, not posted; the most recently used last.
    free: []u16,
    free_len: u16,
    /// Buffers held by a connection whose session couldn't take their
    /// bytes yet (`Conn.parked`): the next one in its list, and the bytes
    /// not yet taken.
    next: []u16,
    lo: []u32,
    hi: []u32,
    /// Buffers in the ring.
    posted: u16 = 0,
    /// Buffers to keep in the ring.
    target: u16,
    /// Buffers taken out of the ring since the last `topUp`, and the most
    /// in one batch since the last `adapt`.
    taken: u16 = 0,
    taken_max: u16 = 0,
    starved: bool = false,

    const min_target = 8;

    fn init(ring_fd: linux.fd_t, allocator: std.mem.Allocator, size: u32, count: u16) !RecvBuffers {
        const memory = try allocator.alloc(u8, @as(usize, size) * count);
        errdefer allocator.free(memory);
        const free = try allocator.alloc(u16, count);
        errdefer allocator.free(free);
        const next = try allocator.alloc(u16, count);
        errdefer allocator.free(next);
        const lo = try allocator.alloc(u32, count);
        errdefer allocator.free(lo);
        const hi = try allocator.alloc(u32, count);
        errdefer allocator.free(hi);
        // Buffer 0 on top.
        for (free, 0..) |*id, i| id.* = @intCast(count - 1 - i);
        const len = @as(usize, count) * @sizeOf(linux.io_uring_buf);
        const map = try std.posix.mmap(null, len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
        errdefer std.posix.munmap(map);
        const br: *align(std.heap.page_size_min) linux.io_uring_buf_ring = @ptrCast(map.ptr);
        try registerBufRing(ring_fd, .REGISTER_PBUF_RING, @intFromPtr(br), count, BUFFER_GROUP_ID);
        IoUring.buf_ring_init(br);
        var self: RecvBuffers = .{
            .br = br,
            .memory = memory,
            .size = size,
            .count = count,
            .free = free,
            .free_len = count,
            .next = next,
            .lo = lo,
            .hi = hi,
            .target = @min(count, 2 * min_target),
        };
        self.topUp();
        return self;
    }

    fn deinit(self: *RecvBuffers, ring_fd: linux.fd_t, allocator: std.mem.Allocator) void {
        // Unregistering before the ring goes avoids std's second
        // unregistration, whose ENOENT it reports with a stack trace.
        registerBufRing(ring_fd, .UNREGISTER_PBUF_RING, 0, 0, BUFFER_GROUP_ID) catch {};
        const map: [*]align(std.heap.page_size_min) u8 = @ptrCast(self.br);
        std.posix.munmap(map[0 .. @as(usize, self.count) * @sizeOf(linux.io_uring_buf)]);
        allocator.free(self.memory);
        allocator.free(self.free);
        allocator.free(self.next);
        allocator.free(self.lo);
        allocator.free(self.hi);
    }

    /// The received bytes of a completion that carries a buffer.
    fn get(self: *RecvBuffers, cqe: linux.io_uring_cqe) ![]u8 {
        const id = try cqe.buffer_id();
        return self.memory[@as(usize, self.size) * id ..][0..@intCast(cqe.res)];
    }

    /// Done with a completion's buffer. Called once for every completion
    /// that carries one, unless its buffer is parked.
    fn put(self: *RecvBuffers, cqe: linux.io_uring_cqe) void {
        const id = cqe.buffer_id() catch return;
        self.leftRing();
        self.release(id);
    }

    /// Keeps a completion's buffer, from `taken` bytes in, at the end of
    /// a connection's list.
    fn park(self: *RecvBuffers, cqe: linux.io_uring_cqe, taken: usize, list: *Parked) void {
        const id = cqe.buffer_id() catch unreachable;
        self.leftRing();
        self.lo[id] = @intCast(taken);
        self.hi[id] = @intCast(cqe.res);
        self.next[id] = NIL16;
        if (list.tail == NIL16) list.head = id else self.next[list.tail] = id;
        list.tail = id;
    }

    /// The bytes of a list's first buffer not yet taken.
    fn parkedBytes(self: *RecvBuffers, list: *const Parked) []u8 {
        const id = list.head;
        return self.memory[@as(usize, self.size) * id ..][self.lo[id]..self.hi[id]];
    }

    /// Takes `n` bytes of a list's first buffer, releasing it once empty.
    fn unpark(self: *RecvBuffers, list: *Parked, n: usize) void {
        const id = list.head;
        self.lo[id] += @intCast(n);
        if (self.lo[id] < self.hi[id]) return;
        list.head = self.next[id];
        if (list.head == NIL16) list.tail = NIL16;
        self.release(id);
    }

    fn unparkAll(self: *RecvBuffers, list: *Parked) void {
        while (list.head != NIL16) self.unpark(list, self.hi[list.head] - self.lo[list.head]);
    }

    /// A buffer has left the ring.
    fn leftRing(self: *RecvBuffers) void {
        self.posted -= 1;
        self.taken += 1;
    }

    fn release(self: *RecvBuffers, id: u16) void {
        self.free[self.free_len] = id;
        self.free_len += 1;
    }

    /// A receive found no buffer: post more from now on.
    fn starve(self: *RecvBuffers) void {
        self.starved = true;
        self.target = @intCast(@min(self.count, @as(u32, self.target) * 2));
    }

    /// Refills the ring up to `target`, hottest buffers first. Called once
    /// per batch, before submitting.
    fn topUp(self: *RecvBuffers) void {
        self.taken_max = @max(self.taken_max, self.taken);
        self.taken = 0;
        const mask = IoUring.buf_ring_mask(self.count);
        var added: u16 = 0;
        while (self.posted + added < self.target and self.free_len > 0) : (added += 1) {
            self.free_len -= 1;
            const id = self.free[self.free_len];
            IoUring.buf_ring_add(self.br, self.memory[@as(usize, self.size) * id ..][0..self.size], id, mask, added);
        }
        if (added == 0) return;
        IoUring.buf_ring_advance(self.br, added);
        self.posted += added;
    }

    /// Periodically: aim for twice the most taken in one batch lately,
    /// unless a receive went without.
    fn adapt(self: *RecvBuffers) void {
        if (!self.starved) {
            const want = @max(min_target, 2 * @as(u32, self.taken_max));
            self.target = @intCast(@min(self.count, @max(want, self.target / 2)));
        }
        self.starved = false;
        self.taken_max = 0;
    }
};

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
            /// The armed receive is multishot: it stays armed across
            /// completions until cancelled or ended by the kernel.
            recv_multi: bool = false,
            /// A cancel for the armed receive is in flight.
            recv_cancelling: bool = false,
            /// The armed receive's operation (`.recv` or `.recv_plain`).
            recv_op: Op = .recv,
            /// Received bytes the session had no room for yet, still in the
            /// kernel's buffers (plaintext HTTP/1.1, whose multishot receive
            /// can bring several buffers' worth at once). They go in before
            /// anything more is received.
            parked: Parked = .{},
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
            /// sendmsg's header, for `iov`.
            msg: linux.msghdr_const = undefined,
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
        buffers: RecvBuffers,
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
        /// Where TLS reads file bodies to encrypt them.
        file_buf: []u8,
        /// kTLS is wanted and, as far as this worker knows, available.
        ktls_on: bool,
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
            resp.ws_deflate_options = opts.websocket.deflate;
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
            const file_buf = try allocator.alloc(u8, 16 * 1024);
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
                .file_buf = file_buf,
                .ktls_on = opts.ktls,
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
            self.buffers = try .init(
                self.ring.fd,
                allocator,
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
                    self.quic.?.bindWorker(self.handler, self.req, self.resp, &self.date_line, &self.now, &self.exchanges, &self.pool);
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
            self.allocator.free(self.file_buf);
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.conns);
            self.allocator.free(self.free_slots);
            if (self.tls_pools) |*p| p.deinit();
        }

        fn freeBuffers(self: *Self) void {
            if (!self.buffers_live) return;
            self.buffers.deinit(self.ring.fd, self.allocator);
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
                self.buffers.topUp();
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
                if (userTls(c)) |t| {
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
            self.drainConns(&cqes);
        }

        /// Closes every connection and waits for the operations still in
        /// flight (shutting the sockets down fails writes at once), so no
        /// send is left reading a buffer after it went back or was freed.
        /// Connections accepted meanwhile are closed. Gives up after two
        /// seconds; deinit frees what is left.
        fn drainConns(self: *Self, cqes: []linux.io_uring_cqe) void {
            for (self.conns) |*c| {
                if (c.open) self.closeConn(c);
            }
            const deadline = sys.monotonicSeconds() + 2;
            while (self.open_count > 0 and sys.monotonicSeconds() < deadline) {
                _ = self.ring.submit_and_wait(1) catch |err| switch (err) {
                    error.SignalInterrupt => continue,
                    else => return,
                };
                const n = self.ring.copy_cqes(cqes, 0) catch 0;
                for (cqes[0..n]) |cqe| {
                    const op: Op = @fromBackingInt(@intCast(@as(u8, @truncate(cqe.user_data))));
                    if (op == .accept) {
                        if (cqe.res >= 0) sys.close(cqe.res);
                        continue;
                    }
                    self.dispatch(cqe);
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
            // A multishot receive stays in flight until its last completion.
            if (op != .recv or cqe.flags & linux.IORING_CQE_F_MORE == 0) c.inflight -= 1;
            switch (op) {
                .recv => self.onRecv(c, cqe),
                .recv_plain => self.onRecvPlain(c, cqe),
                .write => if (c.ws != null) self.onWsWrite(c, cqe) else if (c.h2 != null) self.onH2Write(c, cqe) else self.onWrite(c, cqe),
                .write_ready => {
                    c.write_inflight = false;
                    if (c.closing) return;
                    if (cqe.res < 0) return self.closeConn(c);
                    // Room again: carry on with what was waiting.
                    if (c.ws != null) {
                        self.wsDrive(c);
                    } else if (c.h2 != null) {
                        self.h2Drive(c);
                    } else if (c.sent < c.out.totalLen()) {
                        self.submitWrite(c);
                    } else if (c.out.file != null) {
                        self.sendFile(c);
                    }
                },
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
            if (c.recv_armed or c.closing or c.peer_closed or c.parked.head != NIL16) return;
            if (!c.lingering and holdsPartialInput(c)) return self.armRecvPlain(c);
            self.armRecvBuffered(c);
        }

        /// A receive into a kernel-provided buffer.
        fn armRecvBuffered(self: *Self, c: *Conn) void {
            if (c.recv_armed or c.closing or c.peer_closed) return;
            const sqe = self.getSqe();
            sqe.prep_rw(.RECV, c.fd, 0, 0, 0);
            sqe.flags |= linux.IOSQE_BUFFER_SELECT;
            sqe.buf_index = BUFFER_GROUP_ID;
            sqe.user_data = userData(c.gen, self.slotOf(c), .recv);
            // Plaintext HTTP/1.1 keeps one receive armed across requests,
            // instead of a receive (and a poll armed by the kernel) per
            // request. Input that can't all be taken at once parks and
            // cancels it (onRecv), which keeps backpressure.
            if (c.tls == null and c.ws == null and c.h2 == null and c.proto_decided and !c.lingering) {
                sqe.ioprio |= linux.IORING_RECV_MULTISHOT;
                c.recv_multi = true;
            }
            c.recv_op = .recv;
            c.recv_armed = true;
            c.inflight += 1;
        }

        /// Cancels the armed receive; its last completion follows.
        fn cancelRecv(self: *Self, c: *Conn) void {
            if (!c.recv_armed or c.recv_cancelling) return;
            const sqe = self.getSqe();
            sqe.prep_cancel(userData(c.gen, self.slotOf(c), c.recv_op), 0);
            sqe.user_data = userData(c.gen, self.slotOf(c), .cancel);
            c.recv_cancelling = true;
            c.inflight += 1;
        }

        /// Whether the connection holds part of a request, TLS record or
        /// WebSocket frame. The rest is then received straight into the
        /// buffer holding it, as on epoll: through a kernel buffer it would
        /// be copied, and requests split across two receives are common
        /// (most 12 KiB uploads under load).
        fn holdsPartialInput(c: *const Conn) bool {
            std.debug.assert(!c.borrowed);
            if (c.parked.head != NIL16) return true;
            if (c.tls) |t| return t.partialRecordNeed() > 0;
            if (c.ws) |w| return w.decoder.holdsPartialFrame();
            if (c.h2) |conn| return conn.reader.buf.len > 0;
            return c.session.buf.len > 0;
        }

        /// Receives into a pooled buffer: the one holding partial input, or
        /// a fresh one when the provided-buffer ring is exhausted.
        fn armRecvPlain(self: *Self, c: *Conn) void {
            const space = if (c.tls) |t|
                t.readSpace() catch return self.closeConn(c)
            else if (c.ws) |w|
                w.decoder.readSpace() catch return self.closeConn(c)
            else if (c.h2) |conn|
                conn.readSpace(&self.pool) catch return self.closeConn(c)
            else
                c.session.readSpace(&self.pool, self.opts.session) catch return self.closeConn(c);
            const sqe = self.getSqe();
            sqe.prep_recv(c.fd, space, 0);
            sqe.user_data = userData(c.gen, self.slotOf(c), .recv_plain);
            c.recv_op = .recv_plain;
            c.recv_armed = true;
            c.inflight += 1;
        }

        fn submitWrite(self: *Self, c: *Conn) void {
            if (!self.kernelGate(c)) return;
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
            // send(msg) rather than writev: sockets only, so skip the VFS.
            if (n == 1) {
                sqe.prep_send(c.fd, c.iov[0].base[0..c.iov[0].len], linux.MSG.NOSIGNAL);
            } else {
                c.msg = .{ .name = null, .namelen = 0, .iov = &c.iov, .iovlen = n, .control = null, .controllen = 0, .flags = 0 };
                sqe.prep_sendmsg(c.fd, &c.msg, linux.MSG.NOSIGNAL);
            }
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
            self.buffers.adapt();
            self.expire(&self.idle);
            self.expire(&self.active);
            self.expireExchanges();
            self.pool.trim();
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
                if (!e.active or (e.tunnel and !e.tunnel_timed)) continue;
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
            c.tls = try self.tls_pools.?.createConn(cfg, &entropy);
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
            // Parked input is discarded like the rest.
            self.buffers.unparkAll(&c.parked);
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
            self.cancelRecv(c);
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
            self.buffers.unparkAll(&c.parked);
            if (c.borrowed) {
                c.session.buf = &.{};
                c.borrowed = false;
            }
            c.session.deinit(&self.pool);
            if (c.out.file) |f| f.release();
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
                w.destroy();
                c.ws = null;
            }
            if (c.tls) |t| {
                self.tls_pools.?.destroyConn(t);
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
            const w = WsConn.create(self.allocator, &self.pool, c.fd, self.opts.websocket, &self.mailbox, .{ .kind = .ws, .slot = self.slotOf(c), .gen = @intCast(c.gen & 0x7fffffff) }) catch {
                return self.closeConn(c);
            };
            c.ws = w;
            w.enableDeflate(c.session.ws_deflate);
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
                const space = w.decoder.readSpace() catch return self.closeConn(c);
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
            if (cqe.flags & linux.IORING_CQE_F_MORE == 0) {
                c.recv_armed = false;
                c.recv_multi = false;
                c.recv_cancelling = false;
            }
            // Stop receiving into kernel buffers when the input can't all
            // be taken: it arrived while a response was being written (and
            // is held until that's done), or part of a request or body is
            // left over (the rest goes straight into the buffer holding it,
            // as much as fits). Upgraded connections receive one at a time.
            const busy = c.write_inflight;
            defer if (c.recv_multi and !c.closing and (busy or c.ws != null or c.h2 != null or
                (!c.borrowed and holdsPartialInput(c)))) self.cancelRecv(c);
            if (cqe.res < 0) {
                if (c.closing) return;
                if (cqe.err() == .NOBUFS) {
                    self.buffers.starve();
                    if (!c.lingering) return self.armRecvPlain(c);
                }
                // Cancelled for backpressure: receive again once ready.
                if (cqe.err() == .CANCELED) return self.carryOn(c);
                return self.closeConn(c);
            }
            if (c.lingering) {
                if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) self.buffers.put(cqe);
                c.lingered +|= @intCast(cqe.res);
                if (cqe.res == 0 or c.lingered > sys.max_linger_bytes) return self.closeConn(c);
                return self.armRecv(c);
            }
            if (cqe.res == 0) {
                if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) self.buffers.put(cqe);
                c.peer_closed = true;
                if (c.closing) return;
                return self.carryOn(c);
            }
            const data = self.buffers.get(cqe) catch return self.closeConn(c);
            var parked = false;
            defer if (!parked) self.buffers.put(cqe);
            if (c.closing) return;
            if (c.tls) |t| return self.tlsFeed(c, t, data);
            if (c.ws != null) return self.wsFeed(c, data);
            if (c.h2 != null) return self.h2Feed(c, data);
            if (c.parked.head != NIL16) {
                // Behind input already waiting for room.
                self.buffers.park(cqe, 0, &c.parked);
                parked = true;
                return;
            }
            if (c.session.buf.len == 0) {
                // Zero-copy: parse straight out of the kernel's buffer.
                c.session.buf = data;
                c.session.start = 0;
                c.session.end = data.len;
                c.borrowed = true;
            } else {
                const n = self.appendInput(c, data) catch return self.closeConn(c);
                if (n < data.len) {
                    // No room yet (more arrived while a response was being
                    // written or a body is paused): drive takes it later.
                    self.buffers.park(cqe, n, &c.parked);
                    parked = true;
                }
            }
            self.drive(c);
            // The kernel buffer goes back when this returns; keep leftovers.
            if (c.borrowed) self.unborrow(c) catch return self.closeConn(c);
        }

        fn onRecvPlain(self: *Self, c: *Conn, cqe: linux.io_uring_cqe) void {
            c.recv_armed = false;
            c.recv_cancelling = false;
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

        /// Copies as much of `data` into the session as it has room for
        /// (it grows up to the request size limits).
        fn appendInput(self: *Self, c: *Conn, data: []const u8) !usize {
            var done: usize = 0;
            while (done < data.len) {
                const space = c.session.readSpace(&self.pool, self.opts.session) catch |err| switch (err) {
                    error.BufferFull => return done,
                    else => |e| return e,
                };
                const n = @min(space.len, data.len - done);
                @memcpy(space[0..n], data[done..][0..n]);
                c.session.commitRead(n);
                done += n;
            }
            return done;
        }

        /// Moves parked input into the session as far as it has room.
        /// Whether any moved.
        fn feedParked(self: *Self, c: *Conn) !bool {
            var moved = false;
            while (c.parked.head != NIL16) {
                const bytes = self.buffers.parkedBytes(&c.parked);
                const n = try self.appendInput(c, bytes);
                if (n == 0) break;
                moved = true;
                self.buffers.unpark(&c.parked, n);
                if (n < bytes.len) break;
            }
            return moved;
        }

        /// Carries on with whatever the connection was doing.
        fn carryOn(self: *Self, c: *Conn) void {
            if (c.ws != null) return self.wsDrive(c);
            return self.drive(c);
        }

        fn unborrow(self: *Self, c: *Conn) !void {
            c.borrowed = false;
            const s = &c.session;
            const leftover = s.buf[s.start..s.end];
            s.buf = &.{};
            s.start = 0;
            s.end = 0;
            if (leftover.len > 0 and try self.appendInput(c, leftover) < leftover.len) return error.BufferFull;
        }

        fn onWrite(self: *Self, c: *Conn, cqe: linux.io_uring_cqe) void {
            c.write_inflight = false;
            if (c.closing) return;
            if (cqe.res < 0) return self.closeConn(c);
            if (cqe.res > 0) self.arm(c, .active);
            if (userTls(c)) |t| {
                t.advance(@intCast(cqe.res));
                if (self.tlsSubmit(c, t) != .idle) return;
            } else {
                if (!self.kernelWrote(c, @intCast(cqe.res))) return;
                c.sent += @intCast(cqe.res);
                if (c.sent < c.out.totalLen()) return self.submitWrite(c);
                if (c.out.file != null) return self.sendFile(c);
            }
            self.writeDone(c);
        }

        /// Sends the file body after the head with sendfile(2), straight
        /// from this completion (the socket is non-blocking), waiting for
        /// POLLOUT when the socket is full. Where sendfile doesn't work,
        /// reads a buffer's worth into Out (written by now) and writes it.
        fn sendFile(self: *Self, c: *Conn) void {
            const f = &c.out.file.?;
            var progressed = false;
            while (f.len > 0) {
                if (!self.kernelGate(c)) return;
                const count: usize = @intCast(@min(f.len, 1 << 30));
                const n = sys.sendfile(c.fd, f.fd, f.offset, count) catch |err| switch (err) {
                    error.WouldBlock => {
                        if (progressed) self.arm(c, .active);
                        const sqe = self.getSqe();
                        sqe.prep_poll_add(c.fd, linux.POLL.OUT);
                        sqe.user_data = userData(c.gen, self.slotOf(c), .write_ready);
                        c.write_inflight = true;
                        c.inflight += 1;
                        return;
                    },
                    error.Unsupported => {
                        const chunk = c.out.buf[0..@intCast(@min(f.len, c.out.buf.len))];
                        const got = sys.pread(f.fd, chunk, f.offset) catch 0;
                        if (got < chunk.len) return self.closeConn(c);
                        f.offset += got;
                        f.len -= got;
                        c.out.len = got;
                        c.out.body = "";
                        c.out.tail = "";
                        c.sent = 0;
                        return self.submitWrite(c);
                    },
                    // A connection error, or the file shrank.
                    else => return self.closeConn(c),
                };
                f.offset += n;
                f.len -= n;
                progressed = true;
                if (!self.kernelWrote(c, n)) return;
            }
            if (progressed) self.arm(c, .active);
            f.release();
            c.out.file = null;
            self.writeDone(c);
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

        /// Before writing data through the kernel (kTLS), with no write in
        /// flight: our KeyUpdate, if due, goes first (RFC 8446 §4.6.3),
        /// then the kernel gets the next key. Returns false if the caller
        /// must stop: the socket is full (a POLLOUT wait is armed, and
        /// `write_ready` resumes), or the connection was closed (the kernel
        /// can't switch keys, before TLS 1.3 rekey support).
        fn kernelGate(self: *Self, c: *Conn) bool {
            const t = c.tls orelse return true;
            if (!t.kernel_tx or !t.kernel_key_update) return true;
            const msg = TlsConn.kernel_key_update_message;
            const n = sys.ktls.sendRecord(c.fd, tls_handshake, msg) catch |err| switch (err) {
                error.WouldBlock => {
                    const sqe = self.getSqe();
                    sqe.prep_poll_add(c.fd, linux.POLL.OUT);
                    sqe.user_data = userData(c.gen, self.slotOf(c), .write_ready);
                    c.write_inflight = true;
                    c.inflight += 1;
                    return false;
                },
                else => 0,
            };
            if (n == msg.len) {
                t.kernelNextKey();
                var info: [56]u8 = undefined;
                defer std.crypto.secureZero(u8, &info);
                if (sys.ktls.rekeyTx(c.fd, t.kernelTxInfo(&info))) |_| return true else |_| {}
            }
            // Our records no longer match the client's keys: no alert.
            t.close_sent = true;
            self.closeConn(c);
            return false;
        }

        /// Hands the sending side to the kernel, before an HTTP/1.1 file
        /// body (worker.Options.ktls), if our own records are all written.
        fn tryKernelTx(self: *Self, c: *Conn, t: *TlsConn) void {
            if (!self.ktls_on or !t.kernelTxReady()) return;
            var info: [56]u8 = undefined;
            defer std.crypto.secureZero(u8, &info);
            sys.ktls.enableTx(c.fd, t.kernelTxInfo(&info)) catch |err| {
                if (err == error.NoModule) self.ktls_on = false;
                return;
            };
            t.startKernelTx();
        }

        /// The response in Out is all written: release it and carry on.
        fn writeDone(self: *Self, c: *Conn) void {
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
                if (userTls(c)) |t| {
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
                .pool = &self.pool,
                .fd = c.fd,
                .early_data = earlyData(c),
            };
        }

        /// The connection's input is TLS early data (0-RTT).
        fn earlyData(c: *const Conn) bool {
            return if (c.tls) |t| t.inEarlyData() else false;
        }

        /// Switches to HTTP/2, adopting the session's bytes (copied out of
        /// a kernel buffer if that is where they are).
        fn attachH2(self: *Self, c: *Conn) bool {
            const conn = self.allocator.create(H2Conn) catch return false;
            conn.* = H2Conn.init(self.allocator, self.opts.h2, &self.pool) catch {
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
            if (userTls(c)) |t| {
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
            const bytes = if (userTls(c) != null) "" else conn.wireBytes();
            if (bytes.len > 0) {
                if (!self.kernelGate(c)) return;
                const sqe = self.getSqe();
                sqe.prep_send(c.fd, bytes, linux.MSG.NOSIGNAL);
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
            if (userTls(c)) |t| {
                t.advance(@intCast(cqe.res));
                if (t.hasWire()) return self.h2Drive(c);
            } else {
                conn.advance(@intCast(cqe.res));
                if (!self.kernelWrote(c, @intCast(cqe.res))) return;
            }
            if (cqe.res > 0) self.arm(c, .active);
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
                .early_data = earlyData(c),
            };
            input: while (true) {
                if (c.out.buf.len == 0) {
                    c.out.buf = self.out_pool.acquire() catch return self.closeConn(c);
                }
                const action = session.process(Handler, &c.session, &ctx, &c.out);
                if (action == .wait and c.exchange == NIL) self.bindExchange(c);
                if (!c.out.isEmpty()) {
                    self.ownBody(c) catch return self.closeConn(c);
                    // A file body: the kernel sends it (kTLS and
                    // sendfile), from now on everything on this connection.
                    if (c.out.file != null) {
                        if (userTls(c)) |t| self.tryKernelTx(c, t);
                    }
                    c.after_write = switch (action) {
                        .close => .close,
                        .upgrade => .upgrade,
                        .flush, .need_more, .wait => .none,
                    };
                    if (userTls(c)) |t| {
                        if (self.tlsSubmit(c, t) == .closed) return;
                    } else {
                        self.submitWrite(c);
                        // Everything received is answered: receive the
                        // next request in the same submission as this
                        // response instead of after its completion. A
                        // request arriving during the write is held until
                        // it ends (one receive's worth at most).
                        if (action == .need_more and c.after_write == .none and
                            c.session.start == c.session.end and c.out.file == null and
                            c.parked.head == NIL16)
                        {
                            if (!c.borrowed) c.session.releaseIfIdle(&self.pool);
                            self.armRecvBuffered(c);
                        }
                    }
                    self.updateTimer(c);
                    return;
                }
                switch (action) {
                    .flush => continue,
                    .need_more => {
                        if (c.parked.head == NIL16) break;
                        // Parked input first. None fitting means a request
                        // beyond the size limits, as when receiving into a
                        // full buffer.
                        if (c.borrowed) self.unborrow(c) catch return self.closeConn(c);
                        const moved = self.feedParked(c) catch return self.closeConn(c);
                        if (!moved) return self.closeConn(c);
                        continue :input;
                    },
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
            while (true) {
                // ALPN decides, once the handshake is done or 0-RTT data
                // starts (readPlain stops there).
                if (!c.proto_decided and (t.isEstablished() or t.inEarlyData())) {
                    c.proto_decided = true;
                    if (isH2(t.earlyAlpn())) {
                        if (!self.attachH2(c)) {
                            self.closeConn(c);
                            return false;
                        }
                    }
                }
                if (!t.hasBufferedInput()) break;
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
                    const space = w.decoder.readSpace() catch {
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
            if (t.kernel_key_update and !c.write_inflight and !self.kernelGate(c)) return !c.closing;
            return true;
        }

        const Submit = enum { idle, writing, closed };

        /// Encrypts pending output (the response in `out`, or WebSocket
        /// bytes) into the TLS wire buffer and queues a write of it.
        fn tlsSubmit(self: *Self, c: *Conn, t: *TlsConn) Submit {
            std.debug.assert(!c.write_inflight);
            // The kernel encrypts: output is written as plaintext elsewhere.
            if (t.kernel_tx) return .idle;
            // Responses to 0-RTT requests go out before the handshake ends.
            if (t.isEstablished() or t.inEarlyData()) {
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
                } else if (c.out.file) |*f| {
                    // A file body: a record's worth at a time.
                    if (f.len == 0) {
                        f.release();
                        c.out.file = null;
                    } else {
                        const chunk = self.file_buf[0..@intCast(@min(f.len, self.file_buf.len))];
                        const got = sys.pread(f.fd, chunk, f.offset) catch 0;
                        if (got < chunk.len) {
                            self.closeConn(c);
                            return .closed;
                        }
                        const n = t.encrypt(&.{chunk}) catch {
                            self.closeConn(c);
                            return .closed;
                        };
                        f.offset += n;
                        f.len -= n;
                    }
                }
            }
            if (!t.hasWire()) return .idle;
            const bytes = t.wireBytes();
            const sqe = self.getSqe();
            sqe.prep_send(c.fd, bytes, linux.MSG.NOSIGNAL);
            sqe.user_data = userData(c.gen, self.slotOf(c), .write);
            c.write_inflight = true;
            c.inflight += 1;
            return .writing;
        }

        /// Best effort before closing (alerts, close_notify): one direct
        /// write. Only when no write is in flight.
        fn tlsWriteOnce(c: *Conn, t: *TlsConn) void {
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

        // -- WebSocket ---------------------------------------------------------

        /// Copies received bytes into the decoder's buffer, running the
        /// protocol as each chunk lands (a frame held whole may need the
        /// buffer compacted before the rest fits).
        fn wsFeed(self: *Self, c: *Conn, data: []const u8) void {
            const w = c.ws.?;
            var rest = data;
            while (rest.len > 0) {
                const space = w.decoder.readSpace() catch return self.closeConn(c);
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
            if (userTls(c)) |t| {
                switch (self.tlsSubmit(c, t)) {
                    .idle => {},
                    .writing => {
                        if (c.list != .active) self.arm(c, .active);
                        return;
                    },
                    .closed => return,
                }
            }
            const bytes = if (userTls(c) != null) "" else w.wireBytes();
            if (bytes.len > 0) {
                if (!self.kernelGate(c)) return;
                const sqe = self.getSqe();
                sqe.prep_send(c.fd, bytes, linux.MSG.NOSIGNAL);
                sqe.user_data = userData(c.gen, self.slotOf(c), .write);
                c.write_inflight = true;
                c.inflight += 1;
                if (c.list != .active) self.arm(c, .active);
                return;
            }
            if (w.wantsClose() or c.peer_closed) return self.closeConn(c);
            w.decoder.releaseIfIdle();
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
            if (userTls(c)) |t| {
                t.advance(@intCast(cqe.res));
            } else {
                c.ws.?.advance(@intCast(cqe.res));
                if (!self.kernelWrote(c, @intCast(cqe.res))) return;
            }
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
