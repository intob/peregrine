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
const Exchange = @import("./http/exchange.zig").Exchange;
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
    /// Exchange hooks and state.
    aborts: std.atomic.Value(usize) = .init(0),
    writable_calls: std.atomic.Value(usize) = .init(0),
    releases: std.atomic.Value(usize) = .init(0),
    /// A streamed flood: bytes still to send on the exchange in `flood`.
    flood_left: usize = 0,
    flood: ?Exchange = null,

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

    pub fn handleWritable(self: *TestHandler, ex: Exchange) void {
        _ = self.writable_calls.fetchAdd(1, .monotonic);
        self.pumpFlood(ex);
    }

    pub fn handleAbort(self: *TestHandler, _: Exchange) void {
        _ = self.aborts.fetchAdd(1, .monotonic);
        self.flood = null;
    }

    fn release(ctx: ?*anyopaque) void {
        const self: *TestHandler = @ptrCast(@alignCast(ctx.?));
        _ = self.releases.fetchAdd(1, .monotonic);
    }

    /// Streams the flood until the queue is full or the body is done.
    fn pumpFlood(self: *TestHandler, ex: Exchange) void {
        while (self.flood_left > 0) {
            const n = @min(self.flood_left, 64 * 1024);
            ex.writeBorrowed(big_body[0..n], null) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return,
            };
            self.flood_left -= n;
        }
        ex.finish(&.{}) catch {};
        self.flood = null;
    }

    fn laterThread(self: *TestHandler, ex: Exchange, kind: u8) void {
        sleepMs(20);
        switch (kind) {
            'r' => ex.respond(.{ .status = .accepted, .headers = &.{.{ .key = "x-later", .value = "1" }} }, "later-body") catch unreachable,
            's' => {
                ex.startStream(.{ .headers = &.{.{ .key = "x-later", .value = "stream" }} }) catch unreachable;
                ex.write("part1,") catch unreachable;
                ex.writeBorrowed(big_body[0..100], .{ .ctx = self, .func = release }) catch unreachable;
                ex.write("part3") catch unreachable;
                ex.finish(&.{.{ .key = "x-trailer", .value = "end" }}) catch unreachable;
            },
            else => unreachable,
        }
    }

    pub fn handleRequest(self: *TestHandler, req: *Request, resp: *Response) void {
        const path = req.getPath();
        if (std.mem.eql(u8, path, "/later") or std.mem.eql(u8, path, "/later-stream")) {
            // Answered from another thread, after the handler returns.
            const ex = resp.later() catch unreachable;
            const t = std.Thread.spawn(.{}, laterThread, .{ self, ex, @as(u8, if (path.len == 6) 'r' else 's') }) catch unreachable;
            t.detach();
            return;
        }
        if (std.mem.eql(u8, path, "/stream")) {
            resp.addNewHeader("x-stream", "1") catch {};
            const ex = resp.stream() catch unreachable;
            ex.write("hello ") catch unreachable;
            ex.writeBorrowed(big_body[0 .. 200 * 1024], .{ .ctx = self, .func = release }) catch unreachable;
            ex.write(" world") catch unreachable;
            ex.finish(&.{.{ .key = "x-trailer", .value = "t" }}) catch unreachable;
            return;
        }
        if (std.mem.eql(u8, path, "/stream-cl")) {
            resp.setContentLength(11);
            const ex = resp.stream() catch unreachable;
            ex.write("hello world") catch unreachable;
            ex.finish(&.{}) catch unreachable;
            return;
        }
        if (std.mem.eql(u8, path, "/flood-stream")) {
            // 64 MB through backpressure: more than the queue, the socket
            // buffers and the client's patience in one go.
            const ex = resp.stream() catch unreachable;
            self.flood = ex;
            self.flood_left = 64 * 1024 * 1024;
            self.pumpFlood(ex);
            return;
        }
        if (std.mem.eql(u8, path, "/hang")) {
            // Never answered: the client leaves, or the timeout ends it.
            _ = resp.later() catch unreachable;
            return;
        }
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

    /// Reads a head without requiring Content-Length.
    fn readHead(self: *Client, out_head: []u8) ![]const u8 {
        const head_end = while (true) {
            if (std.mem.indexOf(u8, self.buf[0..self.len], "\r\n\r\n")) |i| break i + 4;
            if (try self.fill() == 0) return error.EndOfStream;
        };
        @memcpy(out_head[0..head_end], self.buf[0..head_end]);
        self.consume(head_end);
        return out_head[0..head_end];
    }

    fn readLine(self: *Client) ![]const u8 {
        const end = while (true) {
            if (std.mem.indexOf(u8, self.buf[0..self.len], "\r\n")) |i| break i;
            if (try self.fill() == 0) return error.EndOfStream;
        };
        // Valid until the next consume; callers copy what they need.
        return self.buf[0..end];
    }

    fn readExact(self: *Client, out: []u8) !void {
        var got: usize = 0;
        while (got < out.len) {
            if (self.len == 0) {
                if (try self.fill() == 0) return error.EndOfStream;
            }
            const take = @min(self.len, out.len - got);
            @memcpy(out[got..][0..take], self.buf[0..take]);
            got += take;
            self.consume(take);
        }
    }

    /// Decodes a chunked body into `body` (null discards), returning the
    /// body length and the trailer lines.
    fn readChunked(self: *Client, body: ?[]u8, trailers: []u8) !struct { body_len: usize, trailers: []const u8 } {
        var total: usize = 0;
        var tlen: usize = 0;
        while (true) {
            const line = try self.readLine();
            const size = try std.fmt.parseInt(usize, line, 16);
            self.consume(line.len + 2);
            if (size == 0) break;
            if (body) |b| {
                try self.readExact(b[total..][0..size]);
            } else {
                var sink: [4096]u8 = undefined;
                var left = size;
                while (left > 0) {
                    const n = @min(left, sink.len);
                    try self.readExact(sink[0..n]);
                    left -= n;
                }
            }
            total += size;
            var crlf: [2]u8 = undefined;
            try self.readExact(&crlf);
            try testing.expectEqualStrings("\r\n", &crlf);
        }
        while (true) {
            const line = try self.readLine();
            if (line.len == 0) {
                self.consume(2);
                break;
            }
            @memcpy(trailers[tlen..][0..line.len], line);
            tlen += line.len;
            trailers[tlen] = '\n';
            tlen += 1;
            self.consume(line.len + 2);
        }
        return .{ .body_len = total, .trailers = trailers[0..tlen] };
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

// -- Exchanges: later() and stream() ---------------------------------------

test "exchange: later() answered from another thread, pipelined requests wait" {
    try forEachBackend(testLater);
}

fn testLater(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const r = try Running.start(backend, .{ .worker_thread_count = 1 });
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    var head: [4096]u8 = undefined;
    var body: [256]u8 = undefined;
    // Three pipelined requests: the deferred one first, then two sync
    // ones that must wait and come out in order.
    try c.send("GET /later HTTP/1.1\r\nHost: x\r\n\r\nGET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n");
    var res = try c.readResponse(&head, &body);
    try testing.expectEqual(@as(u16, 202), res.status);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-later: 1\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, res.head, "\r\ndate: ") != null);
    try testing.expectEqualStrings("later-body", body[0..res.body_len]);
    res = try c.readResponse(&head, &body);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /a\r\n") != null);
    res = try c.readResponse(&head, &body);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /b\r\n") != null);

    // later() turned into a stream from the other thread, with trailers.
    try c.send("GET /later-stream HTTP/1.1\r\nHost: x\r\n\r\n");
    const h = try c.readHead(&head);
    try testing.expect(std.mem.startsWith(u8, h, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, h, "transfer-encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, h, "x-later: stream\r\n") != null);
    var trailers: [256]u8 = undefined;
    const ch = try c.readChunked(&body, &trailers);
    try testing.expectEqual(@as(usize, 6 + 100 + 5), ch.body_len);
    try testing.expectEqualStrings("part1,", body[0..6]);
    try testing.expectEqualSlices(u8, big_body[0..100], body[6..106]);
    try testing.expectEqualStrings("part3", body[106..111]);
    try testing.expectEqualStrings("x-trailer: end\n", ch.trailers);
    sleepMs(10);
    try testing.expectEqual(@as(usize, 1), r.srv.handler.releases.load(.monotonic));

    // HEAD and HTTP/1.0 through later().
    try c.send("HEAD /later HTTP/1.1\r\nHost: x\r\n\r\n");
    const hh = try c.readHead(&head);
    try testing.expect(std.mem.indexOf(u8, hh, "content-length: 10\r\n") != null);
    try c.send("GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    res = try c.readResponse(&head, &body);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /x\r\n") != null);
    var c10 = try Client.connect(r.port);
    defer c10.close();
    try c10.send("GET /later-stream HTTP/1.0\r\n\r\n");
    const h10 = try c10.readHead(&head);
    try testing.expect(std.mem.indexOf(u8, h10, "connection: close\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, h10, "chunked") == null);
    var raw: [111]u8 = undefined;
    try c10.readExact(&raw);
    try testing.expectEqualStrings("part3", raw[106..]);
    try c10.expectClosed();
}

test "exchange: stream() with chunked and content-length framing" {
    try forEachBackend(testStream);
}

fn testStream(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const r = try Running.start(backend, .{ .worker_thread_count = 1 });
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    var head: [4096]u8 = undefined;
    const body = try testing.allocator.alloc(u8, 256 * 1024);
    defer testing.allocator.free(body);
    var trailers: [256]u8 = undefined;
    for (0..3) |_| {
        try c.send("GET /stream HTTP/1.1\r\nHost: x\r\n\r\n");
        const h = try c.readHead(&head);
        try testing.expect(std.mem.startsWith(u8, h, "HTTP/1.1 200 OK\r\nx-stream: 1\r\ntransfer-encoding: chunked\r\ndate: "));
        const ch = try c.readChunked(body, &trailers);
        try testing.expectEqual(@as(usize, 6 + 200 * 1024 + 6), ch.body_len);
        try testing.expectEqualStrings("hello ", body[0..6]);
        try testing.expectEqualSlices(u8, big_body[0 .. 200 * 1024], body[6 .. 6 + 200 * 1024]);
        try testing.expectEqualStrings(" world", body[6 + 200 * 1024 ..][0..6]);
        try testing.expectEqualStrings("x-trailer: t\n", ch.trailers);
    }
    try testing.expectEqual(@as(usize, 3), r.srv.handler.releases.load(.monotonic));
    // Pipelined behind a stream, a content-length stream, a sync request.
    try c.send("GET /stream-cl HTTP/1.1\r\nHost: x\r\n\r\nGET /after HTTP/1.1\r\nHost: x\r\n\r\n");
    var res = try c.readResponse(&head, body);
    try testing.expectEqual(@as(usize, 11), res.body_len);
    try testing.expectEqualStrings("hello world", body[0..11]);
    try testing.expect(std.mem.indexOf(u8, res.head, "chunked") == null);
    res = try c.readResponse(&head, body);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /after\r\n") != null);
    // HEAD of a stream: head only, and the connection goes on.
    try c.send("HEAD /stream HTTP/1.1\r\nHost: x\r\n\r\nGET /after2 HTTP/1.1\r\nHost: x\r\n\r\n");
    const hh = try c.readHead(&head);
    try testing.expect(std.mem.indexOf(u8, hh, "x-stream: 1\r\n") != null);
    res = try c.readResponse(&head, body);
    try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /after2\r\n") != null);
}

test "exchange: backpressure with handleWritable, abort on disconnect, timeout" {
    try forEachBackend(testStreamBackpressure);
}

fn testStreamBackpressure(backend: Backend) !void {
    const r = try Running.start(backend, .{
        .worker_thread_count = 1,
        .max_exchange_queue_bytes = 256 * 1024,
        .response_timeout_s = 1,
        .request_timeout_s = 1,
    });
    defer r.stop();
    // 64 MB through a 256 KB queue to a client that reads slowly.
    {
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send("GET /flood-stream HTTP/1.1\r\nHost: x\r\n\r\n");
        var head: [4096]u8 = undefined;
        _ = try c.readHead(&head);
        var trailers: [16]u8 = undefined;
        const ch = try c.readChunked(null, &trailers);
        try testing.expectEqual(@as(usize, 64 * 1024 * 1024), ch.body_len);
        try testing.expect(r.srv.handler.writable_calls.load(.monotonic) > 0);
        // Another request on the connection afterwards.
        try c.send("GET /after HTTP/1.1\r\nHost: x\r\n\r\n");
        const res = try c.readResponse(&head, null);
        try testing.expectEqual(@as(u16, 200), res.status);
    }
    // The client leaves while a stream is in progress: handleAbort.
    {
        var c = try Client.connect(r.port);
        try c.send("GET /flood-stream HTTP/1.1\r\nHost: x\r\n\r\n");
        sleepMs(50);
        c.close();
        const start = sys.nanoTimestamp();
        while (r.srv.handler.aborts.load(.monotonic) == 0) {
            if (sys.nanoTimestamp() - start > 4 * std.time.ns_per_s) return error.NoAbort;
            sleepMs(10);
        }
    }
    // A later() exchange nobody answers times out: the connection closes
    // and handleAbort runs.
    {
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send("GET /hang HTTP/1.1\r\nHost: x\r\n\r\n");
        const start = sys.nanoTimestamp();
        try c.expectClosed();
        const elapsed = sys.nanoTimestamp() - start;
        try testing.expect(elapsed < 3 * std.time.ns_per_s);
        sleepMs(10);
        try testing.expectEqual(@as(usize, 2), r.srv.handler.aborts.load(.monotonic));
    }
}

// -- TLS --------------------------------------------------------------------

const tls_testdata = @import("./tls/credentials.zig").testdata;
const StdTls = std.crypto.tls.Client;

/// std's TLS client over a TCP connection to the test server.
const TlsClient = struct {
    fd: sys.fd_t,
    file_reader: std.Io.File.Reader,
    file_writer: std.Io.File.Writer,
    in_buf: [StdTls.min_buffer_len]u8 = undefined,
    out_buf: [StdTls.min_buffer_len]u8 = undefined,
    read_buf: [StdTls.min_buffer_len]u8 = undefined,
    write_buf: [StdTls.min_buffer_len]u8 = undefined,
    client: StdTls = undefined,

    fn connect(port: u16) !*TlsClient {
        const raw = try Client.connect(port);
        errdefer sys.close(raw.fd);
        const self = try testing.allocator.create(TlsClient);
        errdefer testing.allocator.destroy(self);
        const file: std.Io.File = .{ .handle = raw.fd, .flags = .{ .nonblocking = false } };
        self.* = .{
            .fd = raw.fd,
            .file_reader = undefined,
            .file_writer = undefined,
        };
        self.file_reader = file.readerStreaming(testing.io, &self.in_buf);
        self.file_writer = file.writerStreaming(testing.io, &self.out_buf);
        var entropy: [StdTls.Options.entropy_len]u8 = undefined;
        sys.randomBytes(&entropy);
        self.client = try StdTls.init(&self.file_reader.interface, &self.file_writer.interface, .{
            .host = .{ .explicit = "localhost" },
            .ca = .self_signed,
            .read_buffer = &self.read_buf,
            .write_buffer = &self.write_buf,
            .entropy = &entropy,
            .realtime_now = .{ .nanoseconds = @as(i96, sys.realtimeSeconds()) * std.time.ns_per_s },
        });
        return self;
    }

    fn close(self: *TlsClient) void {
        sys.close(self.fd);
        testing.allocator.destroy(self);
    }

    fn send(self: *TlsClient, bytes: []const u8) !void {
        try self.client.writer.writeAll(bytes);
        try self.client.writer.flush();
        try self.file_writer.interface.flush();
    }

    /// Reads one response. The body is copied into `body` if given.
    fn readResponse(self: *TlsClient, body: ?[]u8) !struct { status: u16, body_len: usize, close: bool } {
        const r = &self.client.reader;
        const status_line = try r.takeDelimiterInclusive('\n');
        const status = try std.fmt.parseInt(u16, status_line[9..12], 10);
        var body_len: usize = 0;
        var closing = false;
        while (true) {
            const line = try r.takeDelimiterInclusive('\n');
            if (line.len == 2) break;
            if (std.mem.startsWith(u8, line, "content-length: ")) {
                body_len = try std.fmt.parseInt(usize, line[16 .. line.len - 2], 10);
            } else if (std.mem.eql(u8, line, "connection: close\r\n")) {
                closing = true;
            }
        }
        if (body) |b| try r.readSliceAll(b[0..body_len]) else try r.discardAll(body_len);
        return .{ .status = status, .body_len = body_len, .close = closing };
    }

    /// The server's close_notify ends the stream cleanly; a bare FIN would
    /// make std's client report a truncation attack.
    fn expectCleanClose(self: *TlsClient) !void {
        var b: [1]u8 = undefined;
        try testing.expectError(error.EndOfStream, self.client.reader.readSliceAll(&b));
    }

    fn wsRead(self: *TlsClient, payload: []u8) !struct { opcode: ws.Opcode, data: []u8 } {
        const r = &self.client.reader;
        const b0 = try r.takeByte();
        const b1 = try r.takeByte();
        var len: usize = b1 & 0x7f;
        if (len == 126) len = try r.takeInt(u16, .big) else if (len == 127) len = @intCast(try r.takeInt(u64, .big));
        try r.readSliceAll(payload[0..len]);
        return .{ .opcode = ws.Opcode.fromByte(b0 & 0x0f).?, .data = payload[0..len] };
    }
};

fn tlsConfig() Config {
    return .{ .tls = .{ .cert_pem = tls_testdata.p256_cert, .key_pem = tls_testdata.p256_key } };
}

test "tls: keep-alive, pipelining, large responses and close_notify" {
    try forEachBackend(testTlsKeepAlive);
}

fn testTlsKeepAlive(backend: Backend) !void {
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);

    const c = try TlsClient.connect(r.port);
    defer c.close();
    var body: [64]u8 = undefined;
    try c.send("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    var resp = try c.readResponse(&body);
    try testing.expectEqual(200, resp.status);
    try testing.expectEqualStrings("ok", body[0..resp.body_len]);

    // Pipelined, with a body.
    try c.send("GET /b HTTP/1.1\r\nHost: x\r\n\r\nPOST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhelloGET /c HTTP/1.1\r\nHost: x\r\n\r\n");
    resp = try c.readResponse(&body);
    try testing.expectEqualStrings("ok", body[0..resp.body_len]);
    resp = try c.readResponse(&body);
    try testing.expectEqualStrings("hello", body[0..resp.body_len]);
    resp = try c.readResponse(&body);
    try testing.expectEqualStrings("ok", body[0..resp.body_len]);

    // A body of many full records, which span the server's reads (on
    // io_uring, its kernel buffers).
    const upload = try testing.allocator.alloc(u8, 300 * 1024);
    defer testing.allocator.free(upload);
    for (upload, 0..) |*b, i| b.* = @truncate(i *% 7);
    var head_buf: [96]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&head_buf, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{upload.len}));
    try c.send(upload);
    const echoed = try testing.allocator.alloc(u8, upload.len);
    defer testing.allocator.free(echoed);
    resp = try c.readResponse(echoed);
    try testing.expectEqual(upload.len, resp.body_len);
    try testing.expectEqualSlices(u8, upload, echoed);

    // Larger than the TLS output buffer and the socket buffer: encrypted in
    // pieces as the socket drains.
    const got = try testing.allocator.alloc(u8, big_body_len);
    defer testing.allocator.free(got);
    try c.send("GET /big HTTP/1.1\r\nHost: x\r\n\r\nGET /copy-big HTTP/1.1\r\nHost: x\r\n\r\n");
    resp = try c.readResponse(got);
    try testing.expectEqual(big_body_len, resp.body_len);
    try testing.expectEqualSlices(u8, &big_body, got);
    resp = try c.readResponse(null);
    try testing.expect(resp.body_len > 0);

    // A streamed response over TLS: head, chunks (one borrowed, larger
    // than a record), trailers, then a pipelined sync request.
    try c.send("GET /stream HTTP/1.1\r\nHost: x\r\n\r\nGET /after HTTP/1.1\r\nHost: x\r\n\r\n");
    {
        const rd = &c.client.reader;
        const status_line = try rd.takeDelimiterInclusive('\n');
        try testing.expect(std.mem.startsWith(u8, status_line, "HTTP/1.1 200"));
        var chunked = false;
        while (true) {
            const line = try rd.takeDelimiterInclusive('\n');
            if (line.len == 2) break;
            if (std.mem.eql(u8, line, "transfer-encoding: chunked\r\n")) chunked = true;
        }
        try testing.expect(chunked);
        var total: usize = 0;
        while (true) {
            const size_line = try rd.takeDelimiterInclusive('\n');
            const size = try std.fmt.parseInt(usize, size_line[0 .. size_line.len - 2], 16);
            if (size == 0) break;
            try rd.readSliceAll(got[total..][0..size]);
            total += size;
            _ = try rd.takeDelimiterInclusive('\n');
        }
        const trailer = try rd.takeDelimiterInclusive('\n');
        try testing.expectEqualStrings("x-trailer: t\r\n", trailer);
        _ = try rd.takeDelimiterInclusive('\n');
        try testing.expectEqual(@as(usize, 6 + 200 * 1024 + 6), total);
        try testing.expectEqualSlices(u8, big_body[0 .. 200 * 1024], got[6 .. 6 + 200 * 1024]);
    }
    resp = try c.readResponse(&body);
    try testing.expectEqualStrings("ok", body[0..resp.body_len]);

    try c.send("GET /last HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    resp = try c.readResponse(&body);
    try testing.expect(resp.close);
    try c.expectCleanClose();
}

test "tls: websocket echo and server-initiated sends" {
    try forEachBackend(testTlsWebSocket);
}

fn testTlsWebSocket(backend: Backend) !void {
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    const c = try TlsClient.connect(r.port);
    defer c.close();
    try c.send(Client.upgrade_request);
    const head = try c.client.reader.takeDelimiterInclusive('\n');
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 101 "));
    while ((try c.client.reader.takeDelimiterInclusive('\n')).len != 2) {}

    var frame: [64 * 1024 + 16]u8 = undefined;
    var payload: [64 * 1024]u8 = undefined;
    try c.send(Client.wsFrame(&frame, true, .text, "hello"));
    var f = try c.wsRead(&payload);
    try testing.expectEqual(ws.Opcode.text, f.opcode);
    try testing.expectEqualStrings("hello", f.data);

    // Larger than one TLS record, both ways.
    var big: [40 * 1024]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);
    try c.send(Client.wsFrame(&frame, true, .binary, &big));
    f = try c.wsRead(&payload);
    try testing.expectEqualSlices(u8, &big, f.data);

    // A send from another thread wakes the worker, which encrypts it.
    try c.send(Client.wsFrame(&frame, true, .text, "async"));
    f = try c.wsRead(&payload);
    try testing.expectEqualStrings("later", f.data);

    try c.send(Client.wsFrame(&frame, true, .text, "close-me"));
    f = try c.wsRead(&payload);
    try testing.expectEqual(ws.Opcode.close, f.opcode);
    try c.send(Client.wsFrame(&frame, true, .close, &.{ 0x03, 0xe8 }));
    try c.expectCleanClose();
}

test "tls: plaintext HTTP to a TLS port gets an alert" {
    try forEachBackend(testTlsPlaintextRejected);
}

fn testTlsPlaintextRejected(backend: Backend) !void {
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    try c.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    while (c.len < 7) {
        if (try c.fill() == 0) break;
    }
    // 'G' is not a record type: unexpected_message, in a plaintext record.
    try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, 10 }, c.buf[0..7]);
    try c.expectClosed();
}

test "tls: bad credentials fail init" {
    var cfg = tlsConfig();
    cfg.handle_signals = false;
    cfg.tls.?.key_pem = tls_testdata.p384_key;
    try testing.expectError(error.KeyCertificateMismatch, Server(TestHandler).init(testing.allocator, 0, cfg));
}
