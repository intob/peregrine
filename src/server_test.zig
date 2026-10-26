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
const ws = @import("./ws/ws.zig");
const testing = std.testing;

const big_body_len = 8 * 1024 * 1024;
var big_body: [big_body_len]u8 = undefined;

const TestHandler = struct {
    allocator: std.mem.Allocator,
    ws_conns: std.atomic.Value(usize) = .init(0),
    ws_disconns: std.atomic.Value(usize) = .init(0),
    /// Set when a flood hit the send queue limit.
    queue_full: std.atomic.Value(bool) = .init(false),
    /// The last close code received from a client (0 = none).
    close_code: std.atomic.Value(u16) = .init(0),

    pub fn init(allocator: std.mem.Allocator) !*TestHandler {
        const h = try allocator.create(TestHandler);
        h.* = .{ .allocator = allocator };
        return h;
    }

    pub fn deinit(self: *TestHandler) void {
        self.allocator.destroy(self);
    }

    pub fn handleWSConn(self: *TestHandler, _: *ws.Conn) void {
        _ = self.ws_conns.fetchAdd(1, .monotonic);
    }

    pub fn handleWSDisconn(self: *TestHandler, _: *ws.Conn) void {
        _ = self.ws_disconns.fetchAdd(1, .monotonic);
    }

    pub fn handleWSFrame(self: *TestHandler, conn: *ws.Conn, frame: *ws.Frame) void {
        const data = frame.getPayload();
        switch (frame.opcode) {
            .close => {
                self.close_code.store(frame.closeCode() orelse 0, .monotonic);
                return;
            },
            .ping, .pong => return,
            .binary => {
                conn.send(data, true) catch unreachable;
                return;
            },
            .text => {},
            else => unreachable,
        }
        if (std.mem.eql(u8, data, "flood")) {
            // Send until the queue limit stops us (the client isn't reading).
            var chunk: [16 * 1024]u8 = @splat('f');
            var sent: usize = 0;
            while (sent < 64 * 1024 * 1024) : (sent += chunk.len) {
                conn.send(&chunk, true) catch |err| {
                    if (err == error.SendQueueFull) self.queue_full.store(true, .monotonic);
                    return;
                };
            }
        } else if (std.mem.eql(u8, data, "close-me")) {
            conn.close(1000, "bye") catch unreachable;
        } else if (std.mem.eql(u8, data, "async")) {
            // Sends from another thread must wake the owning worker.
            const t = std.Thread.spawn(.{}, struct {
                fn run(c: *ws.Conn) void {
                    sleepMs(20);
                    c.send("later", false) catch unreachable;
                }
            }.run, .{conn}) catch unreachable;
            t.detach();
        } else {
            conn.send(data, false) catch unreachable;
        }
    }

    pub fn handleRequest(_: *TestHandler, req: *Request, resp: *Response) void {
        const path = req.getPath();
        if (std.mem.eql(u8, path, "/ws")) {
            ws.upgrader.handleUpgrade(undefined, req, resp) catch {
                resp.status = .bad_request;
            };
        } else if (std.mem.eql(u8, path, "/echo")) {
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

    // -- WebSocket client ------------------------------------------------

    const upgrade_request = "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

    /// Reads the 101 response; bytes after it stay buffered.
    fn readUpgrade(self: *Client) !void {
        const head_end = while (true) {
            if (std.mem.indexOf(u8, self.buf[0..self.len], "\r\n\r\n")) |i| break i + 4;
            if (try self.fill() == 0) return error.EndOfStream;
        };
        const head = self.buf[0..head_end];
        try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 101 "));
        try testing.expect(std.mem.indexOf(u8, head, "sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, head, "upgrade: websocket\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, head, "connection: upgrade\r\n") != null);
        self.consume(head_end);
    }

    fn wsFrame(out: []u8, fin: bool, opcode: ws.Opcode, payload: []const u8) []u8 {
        return ws.protocol.encodeFrame(out, fin, opcode, payload, .{ 0x12, 0x34, 0x56, 0x78 });
    }

    fn wsSend(self: *Client, fin: bool, opcode: ws.Opcode, payload: []const u8) !void {
        const out = try testing.allocator.alloc(u8, payload.len + ws.protocol.max_header_len);
        defer testing.allocator.free(out);
        try self.send(wsFrame(out, fin, opcode, payload));
    }

    const WsFrame = struct { opcode: ws.Opcode, fin: bool, payload: []u8 };

    /// Reads one (unmasked) server frame into `payload_buf`.
    fn wsRead(self: *Client, payload_buf: []u8) !WsFrame {
        while (self.len < 2) {
            if (try self.fill() == 0) return error.EndOfStream;
        }
        const b0 = self.buf[0];
        const b1 = self.buf[1];
        if (b1 & 0x80 != 0) return error.ServerFrameMasked;
        var hdr: usize = 2;
        var len: usize = b1 & 0x7F;
        if (len == 126) {
            while (self.len < 4) _ = try self.fill();
            len = std.mem.readInt(u16, self.buf[2..4], .big);
            hdr = 4;
        } else if (len == 127) {
            while (self.len < 10) _ = try self.fill();
            len = @intCast(std.mem.readInt(u64, self.buf[2..10], .big));
            hdr = 10;
        }
        self.consume(hdr);
        if (len > payload_buf.len) return error.PayloadTooLarge;
        var got: usize = 0;
        while (got < len) {
            if (self.len == 0) {
                if (try self.fill() == 0) return error.EndOfStream;
            }
            const take = @min(self.len, len - got);
            @memcpy(payload_buf[got..][0..take], self.buf[0..take]);
            got += take;
            self.consume(take);
        }
        return .{
            .opcode = ws.Opcode.fromByte(b0 & 0x0F) orelse return error.BadOpcode,
            .fin = b0 & 0x80 != 0,
            .payload = payload_buf[0..len],
        };
    }

    fn expectWsText(self: *Client, expected: []const u8) !void {
        var buf: [1024]u8 = undefined;
        const f = try self.wsRead(&buf);
        try testing.expectEqual(ws.Opcode.text, f.opcode);
        try testing.expectEqualStrings(expected, f.payload);
    }

    fn expectWsClose(self: *Client, code: u16) !void {
        var buf: [128]u8 = undefined;
        const f = try self.wsRead(&buf);
        try testing.expectEqual(ws.Opcode.close, f.opcode);
        try testing.expectEqual(code, std.mem.readInt(u16, f.payload[0..2], .big));
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

test "websocket: upgrade, framing, ping, large messages, close handshake" {
    try forEachBackend(testWebSocket);
}

fn testWebSocket(backend: Backend) !void {
    const r = try Running.start(backend, .{ .worker_thread_count = 1 });
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    var out: [256]u8 = undefined;
    var payload: [1024]u8 = undefined;

    // Frames in the same packet as the upgrade request, several per read.
    var first: [512]u8 = undefined;
    var n: usize = 0;
    @memcpy(first[0..Client.upgrade_request.len], Client.upgrade_request);
    n += Client.upgrade_request.len;
    n += Client.wsFrame(first[n..], true, .text, "early").len;
    n += Client.wsFrame(first[n..], true, .text, "second").len;
    n += Client.wsFrame(first[n..], true, .ping, "p1").len;
    try c.send(first[0..n]);
    try c.readUpgrade();
    try c.expectWsText("early");
    try c.expectWsText("second");
    var f = try c.wsRead(&payload);
    try testing.expectEqual(ws.Opcode.pong, f.opcode);
    try testing.expectEqualStrings("p1", f.payload);

    // A fragmented text message with a ping in the middle.
    n = 0;
    n += Client.wsFrame(out[n..], false, .text, "frag").len;
    n += Client.wsFrame(out[n..], true, .ping, "").len;
    n += Client.wsFrame(out[n..], false, .continuation, "men").len;
    n += Client.wsFrame(out[n..], true, .continuation, "ted").len;
    try c.send(out[0..n]);
    f = try c.wsRead(&payload);
    try testing.expectEqual(ws.Opcode.pong, f.opcode);
    try c.expectWsText("fragmented");

    // A message larger than the read buffer, echoed back as binary.
    const big = try testing.allocator.alloc(u8, 300 * 1024);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 11);
    try c.wsSend(true, .binary, big);
    const got = try testing.allocator.alloc(u8, big.len);
    defer testing.allocator.free(got);
    f = try c.wsRead(got);
    try testing.expectEqual(ws.Opcode.binary, f.opcode);
    try testing.expect(f.fin);
    try testing.expectEqualSlices(u8, big, f.payload);

    // A message sent from another thread.
    try c.wsSend(true, .text, "async");
    try c.expectWsText("later");

    // Client-initiated close: echoed with the code, then FIN.
    try c.wsSend(true, .close, "\x03\xe8bye");
    try c.expectWsClose(1000);
    try c.expectClosed();
    sleepMs(20);
    try testing.expectEqual(@as(u16, 1000), r.srv.handler.close_code.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), r.srv.handler.ws_conns.load(.monotonic));
    try testing.expectEqual(@as(usize, 1), r.srv.handler.ws_disconns.load(.monotonic));

    // Server-initiated close: the handler's close frame, our reply, FIN.
    var c2 = try Client.connect(r.port);
    defer c2.close();
    try c2.send(Client.upgrade_request);
    try c2.readUpgrade();
    try c2.wsSend(true, .text, "close-me");
    var cbuf: [128]u8 = undefined;
    f = try c2.wsRead(&cbuf);
    try testing.expectEqual(ws.Opcode.close, f.opcode);
    try testing.expectEqualStrings("\x03\xe8bye", f.payload);
    try c2.wsSend(true, .close, "\x03\xe8");
    try c2.expectClosed();

    // HTTP still works on the same worker afterwards.
    var c3 = try Client.connect(r.port);
    defer c3.close();
    try c3.send("GET /after HTTP/1.1\r\nHost: x\r\n\r\n");
    var head: [4096]u8 = undefined;
    const res = try c3.readResponse(&head, null);
    try testing.expectEqual(@as(u16, 200), res.status);
}

test "websocket: protocol violations fail with the right close code" {
    try forEachBackend(testWebSocketErrors);
}

fn testWebSocketErrors(backend: Backend) !void {
    const r = try Running.start(backend, .{ .websocket_max_message_size = 1024 });
    defer r.stop();
    const unmasked = [_]u8{ 0x81, 0x02, 'h', 'i' };
    var big_hdr: [8]u8 = .{ 0x82, 0xFE, 0x10, 0x00, 1, 2, 3, 4 };
    var out: [256]u8 = undefined;
    const cases = [_]struct { bytes: []const u8, code: u16 }{
        .{ .bytes = &unmasked, .code = 1002 },
        .{ .bytes = Client.wsFrame(&out, true, .text, "\xff\xfe"), .code = 1007 },
        .{ .bytes = &big_hdr, .code = 1009 },
    };
    for (cases) |case| {
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send(Client.upgrade_request);
        try c.readUpgrade();
        try c.send(case.bytes);
        try c.expectWsClose(case.code);
        try c.expectClosed();
    }
    // A control frame over 125 bytes, and an unexpected continuation.
    {
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send(Client.upgrade_request);
        try c.readUpgrade();
        const long: [126]u8 = @splat('p');
        try c.wsSend(true, .ping, &long);
        try c.expectWsClose(1002);
        try c.expectClosed();
    }
    {
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send(Client.upgrade_request);
        try c.readUpgrade();
        try c.wsSend(true, .continuation, "x");
        try c.expectWsClose(1002);
        try c.expectClosed();
    }
}

test "websocket: a client that stops reading is cut off, others are served" {
    try forEachBackend(testWebSocketSlowReader);
}

fn testWebSocketSlowReader(backend: Backend) !void {
    const r = try Running.start(backend, .{
        .worker_thread_count = 1,
        .request_timeout_s = 1,
        // More than loopback socket buffers can absorb (8 MB on macOS).
        .websocket_max_send_queue_bytes = 16 * 1024 * 1024,
    });
    defer r.stop();
    var stuck = try Client.connect(r.port);
    defer stuck.close();
    try stuck.send(Client.upgrade_request);
    try stuck.readUpgrade();
    // The handler floods us with more than the socket buffers and the send
    // queue can hold, and we never read it.
    try stuck.wsSend(true, .text, "flood");
    sleepMs(100);
    try testing.expect(r.srv.handler.queue_full.load(.monotonic));

    // Meanwhile the same worker serves another WebSocket and HTTP.
    var other = try Client.connect(r.port);
    defer other.close();
    try other.send(Client.upgrade_request);
    try other.readUpgrade();
    try other.wsSend(true, .text, "still here");
    try other.expectWsText("still here");
    var http = try Client.connect(r.port);
    defer http.close();
    try http.send("GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    var head: [4096]u8 = undefined;
    _ = try http.readResponse(&head, null);

    // No write progress within request_timeout_s: the server closes it
    // (reading now would count as progress, so wait first).
    const start = sys.nanoTimestamp();
    while (r.srv.handler.ws_disconns.load(.monotonic) == 0) {
        if (sys.nanoTimestamp() - start > 4 * std.time.ns_per_s) return error.StalledConnectionNotClosed;
        sleepMs(20);
    }
    // Draining what the kernel buffered ends in FIN or a reset.
    var drained: usize = 0;
    while (true) {
        const n = sys.read(stuck.fd, &stuck.buf) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        drained += n;
    }
    try testing.expect(drained > 0);
    // The other WebSocket is unaffected.
    try other.wsSend(true, .text, "and after");
    try other.expectWsText("and after");
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
