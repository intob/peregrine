//! End-to-end tests over real sockets.
const std = @import("std");
const posix = std.posix;
const system = posix.system;
const sys = @import("./sys.zig");
const Server = @import("./server.zig").Server;
const Config = @import("./server.zig").Config;
const Backend = @import("./server.zig").Backend;
const Request = @import("./request.zig").Request;
const Response = @import("./response.zig").Response;
const testing = std.testing;

const big_body_len = 8 * 1024 * 1024;
var big_body: [big_body_len]u8 = undefined;

const TestHandler = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*TestHandler {
        const h = try allocator.create(TestHandler);
        h.* = .{ .allocator = allocator };
        return h;
    }

    pub fn deinit(self: *TestHandler) void {
        self.allocator.destroy(self);
    }

    pub fn handleRequest(_: *TestHandler, req: *Request, resp: *Response) void {
        const path = req.getPath();
        if (std.mem.eql(u8, path, "/echo")) {
            _ = resp.setBody(req.body) catch {
                resp.status = .payload_too_large;
            };
        } else if (std.mem.eql(u8, path, "/big")) {
            resp.setBodyBorrowed(&big_body);
        } else if (std.mem.eql(u8, path, "/copy-big")) {
            // Large copied body: unsent bytes must survive the response
            // buffer being reused.
            const buf = resp.bodyWriteBuffer();
            for (buf, 0..) |*b, i| b.* = @truncate(i *% 7);
            resp.commitBody(buf.len);
        } else {
            resp.addNewHeader("x-path", path) catch {};
            resp.setBodyBorrowed("ok");
        }
    }
};

const Running = struct {
    srv: *Server(TestHandler),
    thread: std.Thread,
    port: u16,

    fn start(backend: Backend, cfg: Config) !Running {
        var c = cfg;
        c.backend = backend;
        c.ip = "127.0.0.1";
        c.handle_signals = false;
        if (c.worker_thread_count == 0) c.worker_thread_count = 2;
        c.max_connections_per_worker = 256;
        c.buffer_pool_size = 4;
        const srv = try Server(TestHandler).init(testing.allocator, 0, c);
        std.debug.assert(srv.getBackend() == backend);
        const thread = try std.Thread.spawn(.{}, runServer, .{srv});
        return .{ .srv = srv, .thread = thread, .port = srv.getPort() };
    }

    fn runServer(srv: *Server(TestHandler)) void {
        srv.start() catch |err| std.debug.panic("server failed: {s}", .{@errorName(err)});
    }

    fn stop(self: Running) void {
        self.srv.shutdown();
        self.thread.join();
    }
};

const Client = struct {
    fd: sys.fd_t,
    buf: [64 * 1024]u8 = undefined,
    len: usize = 0,

    fn connect(port: u16) !Client {
        const rc = system.socket(posix.AF.INET, posix.SOCK.STREAM, posix.IPPROTO.TCP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
        const fd: sys.fd_t = @intCast(rc);
        var addr = std.mem.zeroes(posix.sockaddr.in);
        addr.family = posix.AF.INET;
        addr.port = std.mem.nativeToBig(u16, port);
        addr.addr = @bitCast([4]u8{ 127, 0, 0, 1 });
        if (posix.errno(system.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in))) != .SUCCESS) {
            return error.ConnectFailed;
        }
        const timeout = posix.timeval{ .sec = 5, .usec = 0 };
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        return .{ .fd = fd };
    }

    fn close(self: *Client) void {
        sys.close(self.fd);
    }

    fn send(self: *Client, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0) rest = rest[try sys.write(self.fd, rest)..];
    }

    fn fill(self: *Client) !usize {
        const n = try sys.read(self.fd, self.buf[self.len..]);
        self.len += n;
        return n;
    }

    const Parsed = struct { status: u16, head: []const u8, body_len: usize };

    /// Reads one response; the body is checked by `expectBody` (or skipped).
    fn readResponse(self: *Client, out_head: []u8, body: ?[]u8) !Parsed {
        const head_end = while (true) {
            if (std.mem.indexOf(u8, self.buf[0..self.len], "\r\n\r\n")) |i| break i + 4;
            if (try self.fill() == 0) return error.EndOfStream;
        };
        @memcpy(out_head[0..head_end], self.buf[0..head_end]);
        const head = out_head[0..head_end];
        const status = try std.fmt.parseInt(u16, head[9..12], 10);
        const cl_start = (std.mem.indexOf(u8, head, "content-length: ") orelse return error.NoLength) + 16;
        const cl_end = std.mem.indexOfScalarPos(u8, head, cl_start, '\r').?;
        const body_len = try std.fmt.parseInt(usize, head[cl_start..cl_end], 10);
        // Consume head, then the body (possibly larger than our buffer).
        self.consume(head_end);
        var got: usize = 0;
        while (got < body_len) {
            if (self.len == 0) {
                if (try self.fill() == 0) return error.EndOfStream;
            }
            const take = @min(self.len, body_len - got);
            if (body) |b| @memcpy(b[got..][0..take], self.buf[0..take]);
            got += take;
            self.consume(take);
        }
        return .{ .status = status, .head = head, .body_len = body_len };
    }

    fn consume(self: *Client, n: usize) void {
        std.mem.copyForwards(u8, self.buf[0 .. self.len - n], self.buf[n..self.len]);
        self.len -= n;
    }

    fn expectClosed(self: *Client) !void {
        while (true) {
            const n = sys.read(self.fd, self.buf[self.len..]) catch |err| switch (err) {
                error.ConnectionClosed => return,
                else => return err,
            };
            if (n == 0) return;
        }
    }
};

/// Runs an end-to-end test against every backend available here.
fn forEachBackend(comptime f: fn (Backend) anyerror!void) !void {
    try f(.epoll);
    // io_uring is often blocked in containers (Docker's default seccomp
    // profile); the auto backend then falls back to epoll, tested above.
    if (sys.is_linux and @import("./http/worker_uring.zig").available()) {
        try f(.io_uring);
    }
}

fn sleepMs(ms: u64) void {
    var ts: posix.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = system.nanosleep(&ts, &ts);
}

test "keep-alive, pipelining and split requests" {
    try forEachBackend(testKeepAlive);
}

fn testKeepAlive(backend: Backend) !void {
    const r = try Running.start(backend, .{});
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    var head: [4096]u8 = undefined;
    var body: [64]u8 = undefined;

    try c.send("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    var res = try c.readResponse(&head, &body);
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("ok", body[0..res.body_len]);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /a\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, res.head, "\r\ndate: ") != null);

    // Three pipelined requests in one write, answered in order.
    try c.send("GET /1 HTTP/1.1\r\nHost: x\r\n\r\nPOST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /3 HTTP/1.1\r\nHost: x\r\n\r\n");
    res = try c.readResponse(&head, &body);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /1\r\n") != null);
    res = try c.readResponse(&head, &body);
    try testing.expectEqualStrings("hello", body[0..res.body_len]);
    res = try c.readResponse(&head, &body);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /3\r\n") != null);

    // A request split across several TCP segments.
    const parts = [_][]const u8{ "PO", "ST /echo HTTP/1.1\r\nHo", "st: x\r\nTransfer-Encoding: chunked\r\n", "\r\n3\r\nabc\r", "\n0\r\n\r\n" };
    for (parts) |p| {
        try c.send(p);
        sleepMs(5);
    }
    res = try c.readResponse(&head, &body);
    try testing.expectEqualStrings("abc", body[0..res.body_len]);
}

test "large responses survive partial writes" {
    try forEachBackend(testLargeResponses);
}

fn testLargeResponses(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const r = try Running.start(backend, .{ .worker_thread_count = 1 });
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    var head: [4096]u8 = undefined;
    const got = try testing.allocator.alloc(u8, big_body_len);
    defer testing.allocator.free(got);

    // Pipeline two large responses plus a small one, and read slowly enough
    // that the server's socket buffer fills up.
    try c.send("GET /big HTTP/1.1\r\nHost: x\r\n\r\nGET /copy-big HTTP/1.1\r\nHost: x\r\n\r\nGET /end HTTP/1.1\r\nHost: x\r\n\r\n");
    sleepMs(50);
    var res = try c.readResponse(&head, got);
    try testing.expectEqual(@as(usize, big_body_len), res.body_len);
    try testing.expect(std.mem.eql(u8, &big_body, got));

    res = try c.readResponse(&head, got);
    const copy_len = (Config{}).response_body_buffer_size;
    try testing.expectEqual(copy_len, res.body_len);
    for (got[0..copy_len], 0..) |b, i| {
        if (b != @as(u8, @truncate(i *% 7))) return error.CorruptCopiedBody;
    }
    res = try c.readResponse(&head, null);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /end\r\n") != null);

    // Meanwhile, another connection on the same worker is served.
    var c2 = try Client.connect(r.port);
    defer c2.close();
    try c2.send("GET /other HTTP/1.1\r\nHost: x\r\n\r\n");
    res = try c2.readResponse(&head, null);
    try testing.expectEqual(@as(u16, 200), res.status);
}

test "malformed requests get an error and close" {
    try forEachBackend(testMalformed);
}

fn testMalformed(backend: Backend) !void {
    const r = try Running.start(backend, .{});
    defer r.stop();
    var head: [4096]u8 = undefined;
    const cases = [_]struct { req: []const u8, status: u16 }{
        .{ .req = "GET / HTTP/1.1\r\nHost: x\r\nBad Header: v\r\n\r\n", .status = 400 },
        .{ .req = "GET / HTTP/1.1\r\n\r\n", .status = 400 },
        .{ .req = "BREW / HTTP/1.1\r\nHost: x\r\n\r\n", .status = 501 },
        .{ .req = "GET / HTTP/3.0\r\nHost: x\r\n\r\n", .status = 505 },
        .{ .req = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", .status = 400 },
        .{ .req = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n", .status = 413 },
    };
    for (cases) |case| {
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send(case.req);
        const res = try c.readResponse(&head, null);
        try testing.expectEqual(case.status, res.status);
        try testing.expect(std.mem.indexOf(u8, res.head, "connection: close\r\n") != null);
        try c.expectClosed();
    }
}

test "error response survives an ongoing upload (lingering close)" {
    try forEachBackend(testLingering);
}

fn testLingering(backend: Backend) !void {
    const r = try Running.start(backend, .{ .limits = .{ .max_body_size = 1024 } });
    defer r.stop();
    var head: [4096]u8 = undefined;
    for (0..3) |_| {
        var c = try Client.connect(r.port);
        defer c.close();
        // Announce a body over the limit and keep uploading after the server
        // answers 413. Closing with unread input makes the kernel send a
        // reset, which can destroy the response in flight; lingering sends a
        // FIN and drains instead.
        try c.send("POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 4194304\r\n\r\n");
        const uploader = try std.Thread.spawn(.{}, struct {
            fn upload(fd: sys.fd_t) void {
                var chunk: [16 * 1024]u8 = @splat('u');
                var sent: usize = 0;
                while (sent < 256 * 1024) sent += sys.write(fd, &chunk) catch return;
            }
        }.upload, .{c.fd});
        uploader.join();
        sleepMs(20);
        const res = try c.readResponse(&head, null);
        try testing.expectEqual(@as(u16, 413), res.status);
        // A clean EOF (FIN), not ECONNRESET.
        try testing.expectEqual(@as(usize, 0), try sys.read(c.fd, &c.buf));
    }
}

test "HTTP/1.0 and Connection: close" {
    try forEachBackend(testHttp10);
}

fn testHttp10(backend: Backend) !void {
    const r = try Running.start(backend, .{});
    defer r.stop();
    var head: [4096]u8 = undefined;
    {
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send("GET / HTTP/1.0\r\n\r\n");
        _ = try c.readResponse(&head, null);
        try c.expectClosed();
    }
    {
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        const res = try c.readResponse(&head, null);
        try testing.expect(std.mem.indexOf(u8, res.head, "connection: keep-alive\r\n") != null);
        _ = try c.readResponse(&head, null);
        try c.expectClosed();
    }
}

test "idle and slow connections time out" {
    try forEachBackend(testTimeouts);
}

fn testTimeouts(backend: Backend) !void {
    const r = try Running.start(backend, .{ .keep_alive_timeout_s = 1, .request_timeout_s = 1 });
    defer r.stop();
    var head: [4096]u8 = undefined;
    var idle = try Client.connect(r.port);
    defer idle.close();
    try idle.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try idle.readResponse(&head, null);
    // Slowloris: trickle a request without finishing it.
    var slow = try Client.connect(r.port);
    defer slow.close();
    for ("GET / HTTP/1.1\r\nHo") |b| {
        slow.send(&.{b}) catch break;
        sleepMs(150);
    }
    const start = sys.nanoTimestamp();
    try idle.expectClosed();
    try slow.expectClosed();
    // Within the 5 s client receive timeout, so the server closed them.
    try testing.expect(sys.nanoTimestamp() - start < 4 * std.time.ns_per_s);
}

test "shutdown is prompt with idle workers" {
    try forEachBackend(testShutdown);
}

fn testShutdown(backend: Backend) !void {
    const r = try Running.start(backend, .{ .worker_thread_count = 4 });
    sleepMs(20);
    const start = sys.nanoTimestamp();
    r.stop();
    try testing.expect(sys.nanoTimestamp() - start < 500 * std.time.ns_per_ms);
}

test "accepted sockets inherit TCP_NODELAY and O_NONBLOCK" {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    const listener = try sys.listenTcp(address, .{ .reuse_port = false });
    defer sys.close(listener);
    var c = try Client.connect(try sys.localPort(listener));
    defer c.close();
    const fd = while (true) {
        break sys.accept(listener) catch |err| switch (err) {
            error.WouldBlock => {
                sleepMs(1);
                continue;
            },
            else => return err,
        };
    };
    defer sys.close(fd);
    try testing.expect(sys.isNonBlocking(fd));
    try testing.expect(try sys.getsockoptInt(fd, posix.IPPROTO.TCP, sys.TCP_NODELAY) != 0);
}
