const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Request = @import("./request.zig").Request;
const Response = @import("./response.zig").Response;
const worker = @import("./worker.zig");
const WebsocketServer = @import("./ws/server.zig").WebsocketServer;

var should_shutdown: std.atomic.Value(bool) = undefined;

fn handleSignal(sig: c_int) callconv(.C) void {
    std.debug.print("received sig {d}\n", .{sig});
    should_shutdown.store(true, .release);
}

pub const ServerConfig = struct {
    /// Listening IP address
    ip: []const u8 = "0.0.0.0",
    /// Number of worker threads processing requests.
    /// Defaults to CPU core count.
    worker_thread_count: usize = 0,
    /// Stack size for each worker thread. Defaults to 1MB.
    worker_stack_size: usize = 1024 * 1024,
    /// Number of threads accepting connections. Defaults to
    /// worker_thread_count / 6.
    accept_thread_count: usize = 0,
    /// Disable Nagle's algorithm. Default is true (disabled).
    tcp_nodelay: bool = true,
    /// Defaults to 10MB. Each worker has it's own buffer.
    /// Size is aligned internally.
    response_body_buffer_size: usize = 1024 * 1024 * 10,
    /// Defaults to 1MB. Each worker has it's own buffer.
    request_buffer_size: usize = 1024 * 1024,
    /// WebSocket reader buffer size. Defaults to 32KB.
    /// Size is aligned internally.
    websocket_buffer_size: usize = 1024 * 32,
};

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
        const ListenerIOHandler = switch (native_os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => ListenerKqueue,
            .linux => ListenerEpoll,
            else => @compileError("Unsupported OS"),
        };

        allocator: std.mem.Allocator,
        handler: *Handler,
        ws: *WebsocketServer(Handler),
        address: std.net.Address,
        workers: []worker.Worker(Handler),
        next_worker: usize = 0,
        listener: posix.socket_t,
        accept_threads: []std.Thread,
        io_handler: ListenerIOHandler,
        tcp_nodelay: bool,

        pub fn init(allocator: std.mem.Allocator, port: u16, cfg: ServerConfig) !*Self {
            const sock_type: u32 = posix.SOCK.STREAM | posix.SOCK.NONBLOCK;
            const address = try std.net.Address.parseIp(cfg.ip, port);
            const listener = try posix.socket(address.any.family, sock_type, posix.IPPROTO.TCP);
            try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
            // REUSEPORT allows accepting connections from multiple threads.
            if (@hasDecl(posix.SO, "REUSEPORT_LB")) {
                try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEPORT_LB, &std.mem.toBytes(@as(c_int, 1)));
            } else if (@hasDecl(posix.SO, "REUSEPORT")) {
                try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
            }
            try posix.bind(listener, &address.any, address.getOsSockLen());
            var sig_action = posix.Sigaction{
                .handler = .{ .handler = handleSignal },
                .mask = posix.empty_sigset,
                .flags = 0,
            };
            posix.sigaction(posix.SIG.INT, &sig_action, null);
            posix.sigaction(posix.SIG.TERM, &sig_action, null);
            const worker_thread_count = if (cfg.worker_thread_count > 0)
                cfg.worker_thread_count
            else
                try std.Thread.getCpuCount();
            const accept_thread_count = if (cfg.accept_thread_count > 0)
                cfg.accept_thread_count
            else
                @max(1, worker_thread_count / 6);
            const io_handler = try ListenerIOHandler.init(listener);
            const srv = try allocator.create(Self);
            errdefer allocator.destroy(srv);
            const handler = try Handler.init(allocator);
            srv.* = .{
                .allocator = allocator,
                .handler = handler,
                .ws = try WebsocketServer(Handler).init(allocator, handler, cfg.websocket_buffer_size),
                .address = address,
                .workers = try allocator.alloc(worker.Worker(Handler), worker_thread_count),
                .listener = listener,
                .accept_threads = try allocator.alloc(std.Thread, accept_thread_count),
                .io_handler = io_handler,
                .tcp_nodelay = cfg.tcp_nodelay,
            };
            for (srv.workers, 0..) |*w, i| {
                try w.init(.{
                    .allocator = allocator,
                    .id = i,
                    .resp_body_buffer_size = cfg.response_body_buffer_size,
                    .req_buffer_size = cfg.request_buffer_size,
                    .stack_size = cfg.worker_stack_size,
                    .handler = srv.handler,
                    .ws = srv.ws,
                });
            }
            for (srv.accept_threads) |*thread| {
                thread.* = try std.Thread.spawn(.{
                    .allocator = allocator,
                    .stack_size = 1024,
                }, loop, .{srv});
            }
            return srv;
        }

        /// Blocks until the server is shutdown.
        pub fn start(self: *Self) posix.ListenError!void {
            should_shutdown = std.atomic.Value(bool).init(false);
            try posix.listen(self.listener, 1024);
            self.waitForShutdown();
        }

        pub fn shutdown(self: *Self) void {
            should_shutdown.store(true, .monotonic);
            self.waitForShutdown();
        }

        fn loop(self: *Self) !void {
            while (!should_shutdown.load(.unordered)) {
                const have_connection = try self.io_handler.poll();
                if (have_connection) {
                    self.acceptConnection() catch |err| switch (err) {
                        error.WouldBlock => {}, // Expected case
                        else => std.debug.print("error accepting connection: {any}\n", .{err}),
                    };
                }
            }
        }

        fn acceptConnection(self: *Self) !void {
            const clsock = try posix.accept(self.listener, null, null, posix.SOCK.NONBLOCK);
            errdefer posix.close(clsock);
            try self.setClientSockOpt(clsock);
            const worker_id = @atomicRmw(usize, &self.next_worker, .Add, 1, .monotonic) % self.workers.len;
            try self.workers[worker_id].addClient(clsock);
        }

        fn waitForShutdown(self: *Self) void {
            for (self.accept_threads, 0..) |t, i| {
                t.join();
                std.debug.print("accept-thread-{d} joined\n", .{i});
            }
            for (self.workers) |*w| {
                w.deinit();
            }
            self.cleanup();
            std.debug.print("shutdown complete\n", .{});
        }

        fn cleanup(self: *Self) void {
            posix.close(self.listener);
            self.handler.deinit();
            self.allocator.free(self.workers);
            self.allocator.free(self.accept_threads);
            self.ws.deinit();
            self.allocator.destroy(self);
        }

        fn setClientSockOpt(self: *Self, sock: posix.socket_t) !void {
            // KEEPALIVE sends periodic probes on idle connections, detects if a peer is still alive,
            // and closes connections automatically if the peer doesn't respond.
            try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(c_int, 1)));
            // Disable Nagle's algorithm.
            const TCP_NODELAY: u32 = 1; // posix.TCP is unavailable for macOS
            const nodelay_opt: c_int = if (self.tcp_nodelay) 0 else 1; // Zero disables Nagle's algorithm
            try posix.setsockopt(sock, posix.IPPROTO.TCP, TCP_NODELAY, &std.mem.toBytes(@as(c_int, nodelay_opt)));
            // Set send/recv timeouts
            const send_timeout = posix.timeval{ .sec = 3, .usec = 0 };
            const recv_timeout = posix.timeval{ .sec = 3, .usec = 0 };
            try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(send_timeout));
            try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(recv_timeout));
        }
    };
}

const ListenerKqueue = struct {
    const Self = @This();

    kfd: i32,
    timeout: posix.timespec,
    listener_ident: usize,

    fn init(listener: posix.socket_t) !Self {
        const kfd = try posix.kqueue();
        try initializeEvents(kfd, listener);
        return .{
            .kfd = kfd,
            .timeout = posix.timespec{ .sec = 0, .nsec = 50_000_000 },
            .listener_ident = @intCast(listener),
        };
    }

    fn initializeEvents(kfd: i32, listener: posix.socket_t) !void {
        const events = [_]posix.Kevent{.{
            .ident = @intCast(listener),
            .filter = posix.system.EVFILT.READ,
            // Edge-triggered causes multiple threads to accept the connection.
            .flags = posix.system.EV.ADD, // | posix.system.EV.CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = @intCast(listener),
        }};
        const result = try posix.kevent(kfd, &events, &.{}, null);
        if (result < 0) {
            return error.EventRegistrationFailed;
        }
    }

    fn poll(self: *Self) !bool {
        var events: [1]posix.Kevent = undefined;
        _ = try posix.kevent(self.kfd, &.{}, &events, &self.timeout);
        if (events[0].ident == self.listener_ident) {
            return true;
        }
        return false;
    }
};

const ListenerEpoll = struct {
    const Self = @This();

    epfd: i32,
    listener: posix.socket_t,

    fn init(listener: posix.socket_t) !Self {
        const epfd = try posix.epoll_create1(0);
        try initializeEvents(epfd, listener);
        return .{ .epfd = epfd, .listener = listener };
    }

    fn initializeEvents(epfd: i32, listener: posix.socket_t) !void {
        var evt = linux.epoll_event{
            // Edge-triggered causes multiple threads to accept the connection.
            .events = linux.EPOLL.IN, // | linux.EPOLL.ET,
            .data = .{ .fd = listener },
        };
        try posix.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, listener, &evt);
    }

    fn poll(self: *Self) !bool {
        var events: [1]linux.epoll_event = undefined;
        const n = posix.epoll_wait(self.epfd, &events, 50);
        if (n == 0) return false;
        const event = events[0];
        if (event.data.fd == self.listener) {
            return true;
        }
        return false;
    }
};
