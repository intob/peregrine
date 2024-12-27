const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Request = @import("./request.zig").Request;
const Response = @import("./response.zig").Response;
const worker = @import("./worker.zig");

var should_shutdown: std.atomic.Value(bool) = undefined;

fn handleSignal(sig: c_int) callconv(.C) void {
    std.debug.print("received sig {d}\n", .{sig});
    should_shutdown.store(true, .release);
}

pub const ServerConfig = struct {
    allocator: std.mem.Allocator,
    ip: []const u8 = "0.0.0.0",
    port: u16,
    on_request: worker.RequestHandler,
    worker_count: usize = 0, // Defaults to CPU core count
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    address: std.net.Address,
    workers: []worker.Worker,
    next_worker: usize,
    listener: posix.socket_t,
    accept_threads: []std.Thread,
    io_handler: IOHandler,

    const Self = @This();

    const IOHandler = switch (native_os) {
        .freebsd, .netbsd, .openbsd, .dragonfly, .macos => KqueueHandler,
        .linux => EpollHandler,
        else => @compileError("Unsupported OS"),
    };

    pub fn init(cfg: ServerConfig) !*Self {
        const allocator = cfg.allocator;
        const sock_type: u32 = posix.SOCK.STREAM | posix.SOCK.NONBLOCK;
        const address = try std.net.Address.parseIp(cfg.ip, cfg.port);
        const listener = try posix.socket(address.any.family, sock_type, posix.IPPROTO.TCP);
        try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        // Reuse port
        // https://www.openmymind.net/TCP-Server-In-Zig-Part-8-Epoll-and-Kqueue/
        if (@hasDecl(posix.SO, "REUSEPORT_LB")) {
            std.debug.print("set REUSEPORT_LB\n", .{});
            try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEPORT_LB, &std.mem.toBytes(@as(c_int, 1)));
        } else if (@hasDecl(posix.SO, "REUSEPORT")) {
            std.debug.print("set REUSEPORT\n", .{});
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
        const worker_count = if (cfg.worker_count > 0) cfg.worker_count else try std.Thread.getCpuCount();
        const io_handler = switch (native_os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => try KqueueHandler.init(listener),
            .linux => try EpollHandler.init(listener),
            else => unreachable,
        };
        const srv = try allocator.create(Self);
        errdefer allocator.destroy(srv);
        srv.* = .{
            .allocator = allocator,
            .address = address,
            .workers = try allocator.alloc(worker.Worker, worker_count),
            .next_worker = 0,
            .listener = listener,
            .accept_threads = try allocator.alloc(std.Thread, @max(1, (worker_count / 3))), // maybe tweak this
            .io_handler = io_handler,
        };
        for (srv.workers, 0..) |*w, i| {
            try w.init(.{ .allocator = allocator, .id = i, .on_request = cfg.on_request });
        }
        for (srv.accept_threads) |*thread| {
            thread.* = try std.Thread.spawn(.{}, loop, .{srv});
        }
        return srv;
    }

    /// Blocks until the server is shutdown.
    pub fn start(self: *Self) !void {
        should_shutdown = std.atomic.Value(bool).init(false);
        try posix.listen(self.listener, 1024);
        self.waitForShutdown();
    }

    fn loop(self: *Self) !void {
        while (!should_shutdown.load(.acquire)) {
            try self.io_handler.poll(self);
        }
    }

    fn acceptConnection(self: *Self) !void {
        const clsock = try posix.accept(self.listener, null, null, posix.SOCK.NONBLOCK);
        errdefer posix.close(clsock);
        try setClientSockOpt(clsock);
        const worker_id = @atomicRmw(usize, &self.next_worker, .Add, 1, .monotonic) % self.workers.len;
        //std.debug.print("accepted sock {d}, sent to worker {d}\n", .{ clsock, worker_id });
        try self.workers[worker_id].addClient(clsock);
    }

    pub fn shutdown(self: *Self) void {
        should_shutdown.store(true, .release);
        self.waitForShutdown();
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
        self.allocator.free(self.workers);
        self.allocator.free(self.accept_threads);
        self.allocator.destroy(self);
    }
};

const KqueueHandler = struct {
    kfd: i32,
    timeout: posix.timespec,
    listener_ident: usize,

    const Self = @This();

    fn init(listener: posix.socket_t) !Self {
        const kfd = try posix.kqueue();
        try initializeEvents(kfd, listener);
        return .{
            .kfd = kfd,
            .timeout = posix.timespec{ .sec = 1, .nsec = 0 },
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

    fn poll(self: *Self, srv: *Server) !void {
        var events: [1]posix.Kevent = undefined;
        _ = try posix.kevent(self.kfd, &.{}, &events, &self.timeout);
        if (events[0].ident == self.listener_ident) {
            srv.acceptConnection() catch |err| switch (err) {
                error.WouldBlock => {},
                else => std.debug.print("error accepting connection: {any}\n", .{err}),
            };
        }
    }
};

const EpollHandler = struct {
    epfd: i32,

    const Self = @This();

    fn init(listener: posix.socket_t) !Self {
        const epfd = try posix.epoll_create1(0);
        try initializeEvents(epfd, listener);
        return .{ .epfd = epfd };
    }

    fn initializeEvents(epfd: i32, listener: posix.socket_t) !void {
        var evt = linux.epoll_event{
            // Edge-triggered causes multiple threads to accept the connection.
            .events = linux.EPOLL.IN, // | linux.EPOLL.ET,
            .data = .{ .fd = listener },
        };
        try posix.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, listener, &evt);
    }

    fn poll(self: *Self, srv: *Server) !void {
        var events: [1]linux.epoll_event = undefined;
        const n = posix.epoll_wait(self.epfd, &events, 50);
        if (n == 0) return;
        const event = events[0];
        if (event.data.fd == srv.listener) {
            srv.acceptConnection() catch |err| switch (err) {
                error.WouldBlock => {},
                else => std.debug.print("error accepting connection: {any}\n", .{err}),
            };
        }
    }
};

fn setClientSockOpt(sock: posix.socket_t) !void {
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(c_int, 1)));
    //try posix.setsockopt(sock, posix.IPPROTO.TCP, posix.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
    const send_timeout = posix.timeval{ .sec = 2, .usec = 500_000 };
    const recv_timeout = posix.timeval{ .sec = 10_000, .usec = 0 };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(send_timeout));
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(recv_timeout));
}
