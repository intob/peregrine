const std = @import("std");
const posix = std.posix;
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
    listener: posix.socket_t,
    main_kfd: i32,
    main_thread: std.Thread,

    const Self = @This();

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
        s.* = .{
            .allocator = allocator,
            .address = address,
            .workers = try allocator.alloc(worker.Worker, worker_count),
            .listener = listener,
            .main_kfd = undefined,
            .main_thread = undefined,
        };
        for (s.workers, 0..) |*w, i| {
            try w.init(allocator, i, cfg.on_request);
        }
        // OS-specific async IO
        try s.initPoll();
        return s;
    }

    // TODO: implement OS-specific polling (kqueue and epoll)
    fn initPoll(self: *Self) !void {
        self.main_kfd = try posix.kqueue();
        _ = try posix.kevent(self.main_kfd, &.{
            .{
                .ident = @intCast(self.listener),
                .filter = posix.system.EVFILT.READ,
                .flags = posix.system.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = @intCast(self.listener),
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
        }, &.{}, null);
    }

    /// Blocks until the the server is stopped.
    pub fn start(self: *Self) !void {
        should_shutdown = std.atomic.Value(bool).init(false);
        self.main_thread = try std.Thread.spawn(.{}, run, .{self});
        self.main_thread.join();
    }

    // TODO: implement OS-specific polling (kqueue and epoll)
    fn run(self: *Self) !void {
        try posix.listen(self.listener, 128);
        var events: [1]posix.Kevent = undefined;
        var next_worker: usize = 0;
        while (true) {
            if (should_shutdown.load(.acquire)) break;
            // Blocks until there's an incoming connection or interrupt signal
            _ = try posix.kevent(self.main_kfd, &.{}, &events, null);
            if (events[0].filter == posix.system.EVFILT.SIGNAL) { // TODO: maybe just break directly????
                should_shutdown.store(true, .release);
                continue;
            }
            const clsock = try posix.accept(self.listener, null, null, posix.SOCK.NONBLOCK);
            const timeout = posix.timeval{ .sec = 2, .usec = 500_000 };
            try posix.setsockopt(clsock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(timeout));
            try posix.setsockopt(clsock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(timeout));
            const w = &self.workers[next_worker];
            next_worker = (next_worker + 1) % self.workers.len; // Round-robin distribution to workers
            _ = try posix.kevent(w.kfd, &.{.{
                .ident = @intCast(clsock),
                .flags = posix.system.EV.ADD,
                .filter = posix.system.EVFILT.READ,
                .fflags = 0,
                .data = 0,
                .udata = @intCast(clsock),
            }}, &.{}, null);
        }
        std.debug.print("shutting down...\n", .{});
        posix.close(self.listener);
        for (self.workers) |*w| {
            w.deinit();
        }
        self.allocator.free(self.workers);
        posix.close(self.main_kfd);
        self.allocator.destroy(self);
        std.debug.print("shutdown complete\n", .{});
    }

    pub fn stop(self: *Self) void {
        should_shutdown.store(true, .release);
        self.main_thread.join();
    }
};
