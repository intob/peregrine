const os = @import("builtin").os.tag;
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
    thread: std.Thread,
    io_handler: IOHandler,

    const Self = @This();

    const IOHandler = switch (os) {
        .freebsd, .netbsd, .openbsd, .dragonfly, .macos => KqueueHandler,
        .linux => EpollHandler,
        else => @compileError("Unsupported OS"),
    };

    pub fn init(cfg: ServerConfig) !*Self {
        const allocator = cfg.allocator;
        const s = try allocator.create(Self);
        errdefer allocator.destroy(s);
        const sock_type: u32 = posix.SOCK.STREAM | posix.SOCK.NONBLOCK;
        const address = try std.net.Address.parseIp(cfg.ip, cfg.port);
        const listener = try posix.socket(address.any.family, sock_type, posix.IPPROTO.TCP);
        try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        try posix.bind(listener, &address.any, address.getOsSockLen());
        // Init interrupt signal handler
        var act = posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = posix.empty_sigset,
            .flags = 0,
        };
        posix.sigaction(posix.SIG.INT, &act, null);
        posix.sigaction(posix.SIG.TERM, &act, null);
        const worker_count = if (cfg.worker_count > 0) cfg.worker_count else try std.Thread.getCpuCount();
        const io_handler = switch (os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => try KqueueHandler.init(listener),
            .linux => try EpollHandler.init(listener),
            else => unreachable,
        };
        s.* = .{
            .allocator = allocator,
            .address = address,
            .workers = try allocator.alloc(worker.Worker, worker_count),
            .next_worker = 0,
            .listener = listener,
            .thread = undefined,
            .io_handler = io_handler,
        };
        for (s.workers, 0..) |*w, i| {
            try w.init(allocator, i, cfg.on_request);
        }
        return s;
    }

    /// Blocks until the server is shutdown.
    pub fn start(self: *Self) !void {
        should_shutdown = std.atomic.Value(bool).init(false);
        try posix.listen(self.listener, 128);
        const Runner = struct {
            fn run(srv: *Self) !void {
                while (!should_shutdown.load(.acquire)) {
                    try switch (os) {
                        .freebsd, .netbsd, .openbsd, .dragonfly, .macos => srv.pollKqueue(),
                        .linux => srv.pollEpoll(),
                        else => unreachable,
                    };
                }
                try srv.cleanup();
            }
        };
        self.thread = try std.Thread.spawn(.{}, Runner.run, .{self});
        self.thread.join();
    }

    fn pollKqueue(self: *Self) !void {
        var events: [1]posix.Kevent = undefined;
        _ = try posix.kevent(self.io_handler.kfd, &.{}, &events, null);
        if (events[0].filter == posix.system.EVFILT.SIGNAL) {
            should_shutdown.store(true, .release);
            return;
        }
        try self.acceptConnection();
    }

    fn pollEpoll(self: *Self) !void {
        var events: [1]linux.epoll_event = undefined;
        const n = posix.epoll_wait(self.io_handler.epfd, &events, 50);
        if (n == 0) return;
        const event = events[0];
        if (event.events & (linux.EPOLL.ERR | linux.EPOLL.HUP) != 0) {
            should_shutdown.store(true, .release);
            return;
        }
        if (event.data.fd == self.listener) {
            try self.acceptConnection();
        }
    }

    fn acceptConnection(self: *Self) !void {
        const clsock = try posix.accept(self.listener, null, null, posix.SOCK.NONBLOCK);
        errdefer posix.close(clsock);
        try setClientSockOpt(clsock);
        try self.workers[self.next_worker].addClient(clsock);
        self.next_worker = (self.next_worker + 1) % self.workers.len;
    }

    pub fn shutdown(self: *Self) void {
        should_shutdown.store(true, .release);
        self.thread.join();
    }

    fn cleanup(self: *Self) !void {
        std.debug.print("CLEANUP\n", .{});
        posix.close(self.listener);
        for (self.workers) |*w| {
            w.deinit();
        }
        self.allocator.free(self.workers);
        self.allocator.destroy(self);
    }
};

const KqueueHandler = struct {
    kfd: i32,

    fn init(listener: posix.socket_t) !@This() {
        const kfd = try posix.kqueue();
        try initializeEvents(kfd, listener);
        return .{ .kfd = kfd };
    }

    fn initializeEvents(kfd: i32, listener: posix.socket_t) !void {
        const events = [_]posix.Kevent{
            .{
                .ident = @intCast(listener),
                .filter = posix.system.EVFILT.READ,
                .flags = posix.system.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = @intCast(listener),
            },
            .{
                .ident = posix.SIG.INT,
                .filter = posix.system.EVFILT.SIGNAL,
                .flags = posix.system.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            },
            .{
                .ident = posix.SIG.TERM,
                .filter = posix.system.EVFILT.SIGNAL,
                .flags = posix.system.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            },
        };
        _ = try posix.kevent(kfd, &events, &.{}, null);
    }
};

const EpollHandler = struct {
    epfd: i32,

    fn init(listener: posix.socket_t) !@This() {
        const epfd = try posix.epoll_create1(0);
        try initializeEvents(epfd, listener);
        return .{ .epfd = epfd };
    }

    fn initializeEvents(epfd: i32, listener: posix.socket_t) !void {
        var evt = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .fd = listener },
        };
        try posix.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, listener, &evt);
    }
};

fn setClientSockOpt(sock: posix.socket_t) !void {
    const timeout = posix.timeval{ .sec = 2, .usec = 500_000 };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(timeout));
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(timeout));
}
