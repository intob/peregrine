const std = @import("std");
const net = std.net;
const posix = std.posix;
const Worker = @import("./worker.zig").Worker;

var should_shutdown: bool = false;
fn handleSignal(sig: c_int) callconv(.C) void {
    std.debug.print("received sig {d}\n", .{sig});
    should_shutdown = true;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    var act = posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);
    const worker_count = try std.Thread.getCpuCount();
    var workers = try allocator.alloc(Worker, worker_count);
    defer allocator.free(workers);
    for (workers, 0..) |*w, i| {
        try w.init(allocator, i);
    }
    const address = try std.net.Address.parseIp("0.0.0.0", 5882);
    const tpe: u32 = posix.SOCK.STREAM | posix.SOCK.NONBLOCK;
    const listener = try posix.socket(address.any.family, tpe, posix.IPPROTO.TCP);
    defer posix.close(listener);
    try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(listener, &address.any, address.getOsSockLen());
    try posix.listen(listener, 128);
    const main_kfd = try posix.kqueue();
    defer posix.close(main_kfd);
    _ = try posix.kevent(main_kfd, &.{
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
    }, &.{}, null);
    var events: [1]posix.Kevent = undefined;
    var next_worker: usize = 0;
    while (!should_shutdown) {
        // Blocks until there's an incoming connection or signal
        _ = try posix.kevent(main_kfd, &.{}, &events, null);
        if (events[0].filter == posix.system.EVFILT.SIGNAL) {
            should_shutdown = true;
            continue;
        }
        const clsock = posix.accept(listener, null, null, posix.SOCK.NONBLOCK) catch |err| {
            std.debug.print("accept error: {}\n", .{err});
            continue;
        };
        const timeout = posix.timeval{ .sec = 2, .usec = 500_000 };
        posix.setsockopt(clsock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(timeout)) catch |err| {
            std.debug.print("error setting sock opt: {}\n", .{err});
            posix.close(clsock);
            continue;
        };
        posix.setsockopt(clsock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, &std.mem.toBytes(timeout)) catch |err| {
            std.debug.print("error setting sock opt: {}\n", .{err});
            posix.close(clsock);
            continue;
        };
        const w = &workers[next_worker]; // Round-robin distribution to workers
        next_worker = (next_worker + 1) % worker_count;
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
    for (workers) |*w| {
        w.deinit();
    }
    std.debug.print("shutdown complete\n", .{});
}
