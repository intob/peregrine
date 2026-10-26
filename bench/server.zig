//! Plaintext benchmark server (TechEmpower-style "Hello, World!").
//! Usage: bench-server [workers] [auto|epoll|io_uring] [port]
const std = @import("std");
const per = @import("peregrine");

const Handler = struct {
    pub fn init(allocator: std.mem.Allocator) !*Handler {
        return try allocator.create(Handler);
    }

    pub fn deinit(_: *Handler) void {}

    pub fn handleRequest(_: *Handler, _: *per.Request, resp: *per.Response) void {
        resp.addNewHeader("content-type", "text/plain") catch {};
        resp.setBodyBorrowed("Hello, World!");
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const workers = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 0;
    const backend = if (args.len > 2) std.meta.stringToEnum(per.Backend, args[2]) orelse return error.BadBackend else .auto;
    const port = if (args.len > 3) try std.fmt.parseInt(u16, args[3], 10) else 8080;
    const srv = try per.Server(Handler).init(std.heap.smp_allocator, port, .{
        .worker_thread_count = workers,
        .backend = backend,
    });
    std.debug.print("listening on :{d} ({s}, {d} workers)\n", .{ srv.getPort(), @tagName(srv.getBackend()), srv.workers.len });
    try srv.start();
}
