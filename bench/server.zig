//! Benchmark server. Every path answers "Hello, World!" (TechEmpower
//! plaintext) except `/64k`, a 64 KiB body (four full TLS records); request
//! bodies are read and discarded.
//! Usage: bench-server [workers] [auto|epoll|io_uring] [port] [tls|h3]
//! With `tls`, serves TLS 1.3 with the self-signed P-256 certificate in
//! this directory, with ALPN "h2" and "http/1.1"; `h3` adds HTTP/3 on the
//! same UDP port. Plaintext serves HTTP/1.1 and HTTP/2 with prior
//! knowledge (h2c).
const std = @import("std");
const per = @import("peregrine");

const big_body: [64 * 1024]u8 = @splat('x');

const Handler = struct {
    pub fn init(allocator: std.mem.Allocator) !*Handler {
        return try allocator.create(Handler);
    }

    pub fn deinit(_: *Handler) void {}

    pub fn handleRequest(_: *Handler, req: *per.Request, resp: *per.Response) void {
        resp.addNewHeader("content-type", "text/plain") catch {};
        if (std.mem.eql(u8, req.getPath(), "/64k")) {
            resp.setBodyBorrowed(&big_body);
        } else {
            resp.setBodyBorrowed("Hello, World!");
        }
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const workers = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 0;
    const backend = if (args.len > 2) std.meta.stringToEnum(per.Backend, args[2]) orelse return error.BadBackend else .auto;
    const port = if (args.len > 3) try std.fmt.parseInt(u16, args[3], 10) else 8080;
    const use_h3 = args.len > 4 and std.mem.eql(u8, args[4], "h3");
    const use_tls = use_h3 or (args.len > 4 and std.mem.eql(u8, args[4], "tls"));
    const srv = try per.Server(Handler).init(std.heap.smp_allocator, port, .{
        .worker_thread_count = workers,
        .backend = backend,
        .h2c = true,
        .tls = if (use_tls) .{
            .cert_pem = @embedFile("cert.pem"),
            .key_pem = @embedFile("key.pem"),
            .alpn = &.{ "h2", "http/1.1" },
        } else null,
        .http3 = if (use_h3) .{} else null,
    });
    std.debug.print("listening on :{d} ({s}, {d} workers{s})\n", .{ srv.getPort(), @tagName(srv.getBackend()), srv.workers.len, if (use_h3) ", tls, h3" else if (use_tls) ", tls" else "" });
    try srv.start();
}
