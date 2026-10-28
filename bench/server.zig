//! Benchmark server. Every path answers "Hello, World!" (TechEmpower
//! plaintext) except `/64k`, a 64 KiB body (four full TLS records), and
//! `/ws`, a WebSocket echo (HTTP/1.1 Upgrade, or extended CONNECT on HTTP/2
//! and HTTP/3); request bodies are read and discarded.
//! Usage: bench-server [workers] [auto|epoll|io_uring] [port] [tls|h3|plain] [stream] [rsa]
//! With `tls`, serves TLS 1.3 with the self-signed P-256 certificate in
//! this directory (`rsa`: the RSA-2048 one), with ALPN "h2" and
//! "http/1.1"; `h3` adds HTTP/3 on the
//! same UDP port. Plaintext serves HTTP/1.1 and HTTP/2 with prior
//! knowledge (h2c). With `stream`, every request body is streamed to the
//! handler (handleHead, handleBody) and the response follows its end, for
//! conformance and interop runs of that path.
const std = @import("std");
const per = @import("peregrine");

const big_body: [64 * 1024]u8 = @splat('x');

const Handler = struct {
    pub fn init(allocator: std.mem.Allocator) !*Handler {
        return try allocator.create(Handler);
    }

    pub fn deinit(_: *Handler) void {}

    pub fn handleRequest(_: *Handler, req: *per.Request, resp: *per.Response) void {
        if (std.mem.eql(u8, req.getPath(), "/ws")) {
            per.ws.upgrader.handleUpgrade(undefined, req, resp) catch {
                resp.status = .bad_request;
            };
            return;
        }
        resp.addNewHeader("content-type", "text/plain") catch {};
        if (std.mem.eql(u8, req.getPath(), "/64k")) {
            resp.setBodyBorrowed(&big_body);
        } else {
            resp.setBodyBorrowed("Hello, World!");
        }
    }

    pub fn handleWSFrame(_: *Handler, conn: *per.ws.Conn, frame: *per.ws.Frame) void {
        switch (frame.opcode) {
            .text, .binary => conn.send(frame.getPayload(), frame.opcode == .binary) catch {},
            else => {},
        }
    }
};

/// Streams every body: counts it, then answers once it has ended.
const StreamHandler = struct {
    pub fn init(allocator: std.mem.Allocator) !*StreamHandler {
        return try allocator.create(StreamHandler);
    }

    pub fn deinit(_: *StreamHandler) void {}

    pub fn handleHead(_: *StreamHandler, _: *per.Request, _: *per.Response) per.BodyMode {
        return .stream;
    }

    pub fn handleRequest(_: *StreamHandler, _: *per.Request, resp: *per.Response) void {
        _ = resp.later() catch {
            resp.status = .service_unavailable;
        };
    }

    pub fn handleBody(_: *StreamHandler, ex: per.Exchange, _: []const u8, end: ?[]const per.Header) per.BodyAction {
        if (end != null) {
            ex.respond(.{ .headers = &.{.{ .key = "content-type", .value = "text/plain" }} }, "Hello, World!") catch {};
        }
        return .more;
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args[@min(args.len, 5)..]) |arg| {
        if (std.mem.eql(u8, arg, "stream")) return serve(StreamHandler, args);
    }
    return serve(Handler, args);
}

fn serve(comptime H: type, args: []const [:0]const u8) !void {
    const workers = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 0;
    const backend = if (args.len > 2) std.meta.stringToEnum(per.Backend, args[2]) orelse return error.BadBackend else .auto;
    const port = if (args.len > 3) try std.fmt.parseInt(u16, args[3], 10) else 8080;
    const use_h3 = args.len > 4 and std.mem.eql(u8, args[4], "h3");
    const use_tls = use_h3 or (args.len > 4 and std.mem.eql(u8, args[4], "tls"));
    var use_rsa = false;
    for (args[@min(args.len, 5)..]) |arg| use_rsa = use_rsa or std.mem.eql(u8, arg, "rsa");
    const srv = try per.Server(H).init(std.heap.smp_allocator, port, .{
        .worker_thread_count = workers,
        .backend = backend,
        .h2c = true,
        .tls = if (use_tls) .{
            .cert_pem = if (use_rsa) @embedFile("rsa.pem") else @embedFile("cert.pem"),
            .key_pem = if (use_rsa) @embedFile("rsa.key") else @embedFile("key.pem"),
            .alpn = &.{ "h2", "http/1.1" },
        } else null,
        .http3 = if (use_h3) .{} else null,
    });
    std.debug.print("listening on :{d} ({s}, {d} workers{s}{s})\n", .{ srv.getPort(), @tagName(srv.getBackend()), srv.workers.len, if (use_h3) ", tls, h3" else if (use_tls) ", tls" else "", if (H == StreamHandler) ", streamed bodies" else "" });
    try srv.start();
}
