const std = @import("std");
const posix = std.posix;
const sys = @import("./sys.zig");
const parser = @import("./http/parser.zig");
const Request = @import("./request.zig").Request;
const Response = @import("./response.zig").Response;
const http_worker = @import("./http/worker.zig");
const worker_uring = if (sys.is_linux) @import("./http/worker_uring.zig") else struct {};

pub const Backend = enum {
    /// Currently epoll/kqueue everywhere. io_uring measured no faster for
    /// keep-alive and pipelined plaintext (see PLAN.md), and epoll also works
    /// under Docker's default seccomp profile, which blocks io_uring.
    auto,
    /// epoll on Linux, kqueue on BSD/macOS.
    epoll,
    /// Linux only. Fails at init if io_uring is unavailable.
    io_uring,
};
const WebsocketServer = @import("./ws/server.zig").WebsocketServer;

pub const Config = struct {
    /// I/O backend.
    backend: Backend = .auto,
    /// Listening IP address (IPv4 or IPv6 literal).
    ip: []const u8 = "0.0.0.0",
    /// Number of worker threads. Defaults to CPU core count.
    worker_thread_count: usize = 0,
    /// Stack size for each worker thread.
    worker_stack_size: usize = 1024 * 1024,
    /// Linux: pin worker N to the Nth allowed CPU.
    pin_workers: bool = true,
    /// Maximum open connections per worker. Further connections are
    /// accepted and immediately closed.
    max_connections_per_worker: u32 = 16 * 1024,
    /// Size of each pooled read buffer. Requests larger than this (head plus
    /// body) temporarily use a heap buffer, up to the limits below.
    read_buffer_size: usize = 16 * 1024,
    /// Read buffers preallocated per worker. Only connections with
    /// unprocessed bytes hold one; idle keep-alive connections don't.
    buffer_pool_size: usize = 256,
    /// Per-worker buffer for Response.setBody. Bodies set with
    /// setBodyBorrowed are not copied and have no size limit.
    response_body_buffer_size: usize = 1024 * 1024,
    /// Per-worker buffer for serialised response headers.
    response_header_buffer_size: usize = 8 * 1024,
    /// Per-worker buffer that batches responses into one write.
    out_buffer_size: usize = 64 * 1024,
    /// Request size limits.
    limits: parser.Limits = .{},
    /// Close idle keep-alive connections after this many seconds.
    keep_alive_timeout_s: u32 = 5,
    /// Maximum time to receive a complete request or make progress writing a
    /// response, in seconds.
    request_timeout_s: u32 = 10,
    /// 0 means unlimited.
    max_requests_per_connection: u32 = 0,
    /// WebSocket reader buffer size.
    websocket_buffer_size: usize = 1024 * 32,
    /// Install SIGINT/SIGTERM handlers that shut the server down.
    handle_signals: bool = true,
};

/// The server that a signal handler should stop.
var signal_target: ?*const SignalTarget = null;

const SignalTarget = struct {
    shutdown: *std.atomic.Value(bool),
    wakers: []const sys.Waker,
};

fn handleSignal(_: posix.SIG) callconv(.c) void {
    const target = signal_target orelse return;
    target.shutdown.store(true, .release);
    // write(2) is async-signal-safe.
    for (target.wakers) |w| w.wake();
}

pub fn Server(comptime Handler: type) type {
    comptime {
        if (!@hasDecl(Handler, "init")) {
            @compileError("Handler must implement init(std.mem.Allocator) !*@This()");
        }
        if (!@hasDecl(Handler, "deinit")) {
            @compileError("Handler must implement deinit(*@This()) void");
        }
        if (!@hasDecl(Handler, "handleRequest")) {
            @compileError("Handler must implement handleRequest(*@This(), *Request, *Response) void");
        }
    }
    return struct {
        const Self = @This();
        const PollWorker = http_worker.Worker(Handler);
        const UringWorker = if (sys.is_linux) worker_uring.Worker(Handler) else void;

        const AnyWorker = union(enum) {
            poll: PollWorker,
            uring: UringWorker,

            fn spawn(self: *AnyWorker, stack_size: usize, pin: bool) !void {
                switch (self.*) {
                    .poll => |*w| try w.spawn(stack_size, pin),
                    .uring => |*w| if (sys.is_linux) try w.spawn(stack_size, pin) else unreachable,
                }
            }

            fn wake(self: *AnyWorker) void {
                switch (self.*) {
                    .poll => |*w| w.wake(),
                    .uring => |*w| if (sys.is_linux) w.wake() else unreachable,
                }
            }

            fn join(self: *AnyWorker) void {
                switch (self.*) {
                    .poll => |*w| w.join(),
                    .uring => |*w| if (sys.is_linux) w.join() else unreachable,
                }
            }

            fn deinit(self: *AnyWorker) void {
                switch (self.*) {
                    .poll => |*w| w.deinit(),
                    .uring => |*w| if (sys.is_linux) w.deinit() else unreachable,
                }
            }

            fn waker(self: *const AnyWorker) sys.Waker {
                return switch (self.*) {
                    .poll => |*w| w.waker,
                    .uring => |*w| if (sys.is_linux) w.waker else unreachable,
                };
            }
        };

        allocator: std.mem.Allocator,
        handler: *Handler,
        ws: *WebsocketServer(Handler),
        workers: []AnyWorker,
        backend: Backend,
        wakers: []sys.Waker,
        shutdown_flag: std.atomic.Value(bool),
        signal_target: SignalTarget,
        cfg: Config,
        port: u16,

        pub fn init(allocator: std.mem.Allocator, port: u16, cfg: Config) !*Self {
            const address = try std.Io.net.IpAddress.parse(cfg.ip, port);
            const worker_count = if (cfg.worker_thread_count > 0)
                cfg.worker_thread_count
            else
                try std.Thread.getCpuCount();
            const backend: Backend = switch (cfg.backend) {
                .auto => .epoll,
                .io_uring => if (sys.is_linux and worker_uring.available()) .io_uring else return error.IoUringUnavailable,
                .epoll => .epoll,
            };

            // A write to a closed socket must return EPIPE, not kill us.
            var ignore = posix.Sigaction{
                .handler = .{ .handler = posix.SIG.IGN },
                .mask = posix.sigemptyset(),
                .flags = 0,
            };
            posix.sigaction(.PIPE, &ignore, null);

            const srv = try allocator.create(Self);
            errdefer allocator.destroy(srv);
            const handler = try Handler.init(allocator);
            errdefer handler.deinit();
            const ws = try WebsocketServer(Handler).init(allocator, handler, cfg.websocket_buffer_size);
            errdefer ws.deinit();
            srv.* = .{
                .allocator = allocator,
                .handler = handler,
                .ws = ws,
                .workers = try allocator.alloc(AnyWorker, worker_count),
                .backend = backend,
                .wakers = try allocator.alloc(sys.Waker, worker_count),
                .shutdown_flag = .init(false),
                .signal_target = undefined,
                .cfg = cfg,
                .port = port,
            };
            errdefer {
                allocator.free(srv.workers);
                allocator.free(srv.wakers);
            }

            // Linux load-balances SO_REUSEPORT listeners across workers, so
            // each worker gets its own: no shared accept queue, no handoff.
            // Elsewhere, workers share one listener.
            const per_worker = sys.is_linux or @hasDecl(posix.SO, "REUSEPORT_LB");
            var shared: sys.fd_t = -1;
            errdefer {
                if (!per_worker and shared >= 0) sys.close(shared);
            }
            var initialised: usize = 0;
            errdefer for (srv.workers[0..initialised]) |*w| w.deinit();
            var bind_address = address;
            for (srv.workers, 0..) |*w, i| {
                const listener = if (per_worker or shared < 0) blk: {
                    const fd = try sys.listenTcp(bind_address, .{ .reuse_port = per_worker });
                    if (i == 0) {
                        // With port 0, the others must bind the chosen port.
                        srv.port = try sys.localPort(fd);
                        bind_address.setPort(srv.port);
                    }
                    if (sys.is_linux) {
                        // Only wake accept() once data has arrived.
                        sys.setsockoptInt(fd, posix.IPPROTO.TCP, std.os.linux.TCP.DEFER_ACCEPT, 1) catch {};
                    }
                    if (!per_worker) shared = fd;
                    break :blk fd;
                } else shared;
                const opts: http_worker.Options = .{
                    .session = .{
                        .limits = cfg.limits,
                        .max_requests_per_connection = cfg.max_requests_per_connection,
                    },
                    .max_connections = cfg.max_connections_per_worker,
                    .read_buffer_size = cfg.read_buffer_size,
                    .buffer_pool_size = cfg.buffer_pool_size,
                    .out_buffer_size = cfg.out_buffer_size,
                    .response_body_buffer_size = cfg.response_body_buffer_size,
                    .response_header_buffer_size = cfg.response_header_buffer_size,
                    .keep_alive_timeout_s = cfg.keep_alive_timeout_s,
                    .request_timeout_s = cfg.request_timeout_s,
                    .read_on_accept = sys.is_linux,
                };
                const result = switch (backend) {
                    .io_uring => if (sys.is_linux) blk: {
                        w.* = .{ .uring = undefined };
                        break :blk w.uring.init(.{
                            .id = i,
                            .allocator = allocator,
                            .handler = handler,
                            .ws = ws,
                            .shutdown = &srv.shutdown_flag,
                            .listener = listener,
                            .opts = opts,
                        });
                    } else unreachable,
                    else => blk: {
                        w.* = .{ .poll = undefined };
                        break :blk w.poll.init(.{
                            .id = i,
                            .allocator = allocator,
                            .handler = handler,
                            .ws = ws,
                            .shutdown = &srv.shutdown_flag,
                            .listener = listener,
                            .owns_listener = per_worker,
                            .opts = opts,
                        });
                    },
                };
                result catch |err| {
                    if (per_worker) sys.close(listener);
                    return err;
                };
                initialised += 1;
                srv.wakers[i] = w.waker();
            }
            srv.signal_target = .{ .shutdown = &srv.shutdown_flag, .wakers = srv.wakers };
            return srv;
        }

        /// The I/O backend in use (resolves `.auto`).
        pub fn getBackend(self: *const Self) Backend {
            return self.backend;
        }

        /// The bound port (useful after binding port 0).
        pub fn getPort(self: *const Self) u16 {
            return self.port;
        }

        /// Blocks until the server is shut down, then frees it.
        pub fn start(self: *Self) !void {
            if (self.cfg.handle_signals) {
                signal_target = &self.signal_target;
                var action = posix.Sigaction{
                    .handler = .{ .handler = handleSignal },
                    .mask = posix.sigemptyset(),
                    .flags = 0,
                };
                posix.sigaction(.INT, &action, null);
                posix.sigaction(.TERM, &action, null);
            }
            var spawned: usize = 0;
            errdefer {
                self.shutdown();
                for (self.workers[0..spawned]) |*w| w.join();
            }
            const pin = self.cfg.pin_workers and sys.is_linux;
            for (self.workers) |*w| {
                try w.spawn(self.cfg.worker_stack_size, pin);
                spawned += 1;
            }
            for (self.workers) |*w| w.join();
            if (self.cfg.handle_signals) signal_target = null;
            self.destroy();
        }

        /// Thread-safe. Workers stop promptly; start() then returns.
        pub fn shutdown(self: *Self) void {
            self.shutdown_flag.store(true, .release);
            for (self.workers) |*w| w.wake();
        }

        fn destroy(self: *Self) void {
            const shared_listener = if (self.workers.len > 0 and self.workers[0] == .poll and
                !self.workers[0].poll.owns_listener)
                self.workers[0].poll.listener
            else
                -1;
            for (self.workers) |*w| w.deinit();
            if (shared_listener >= 0) sys.close(shared_listener);
            self.ws.deinit();
            self.handler.deinit();
            self.allocator.free(self.workers);
            self.allocator.free(self.wakers);
            self.allocator.destroy(self);
        }
    };
}
