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
const BodyMode = @import("./http/exchange.zig").BodyMode;
const BodyAction = @import("./http/exchange.zig").BodyAction;
const Header = @import("./header.zig").Header;
const ws = @import("./ws/ws.zig");
const h2frame = @import("./h2/frame.zig");
const hpack = @import("./h2/hpack.zig");
const BufferPool = @import("./http/session.zig").BufferPool;
const tls_conn = @import("./tls/conn.zig");
const testing = std.testing;

const big_body_len = 8 * 1024 * 1024;
var big_body: [big_body_len]u8 = undefined;
/// A file holding big_body, for the /file paths (see testFiles).
var test_file_fd: sys.fd_t = -1;
/// The last owned duplicate of it handed to the server.
var last_owned_fd = std.atomic.Value(sys.fd_t).init(-1);

fn dupFd(fd: sys.fd_t) sys.fd_t {
    return @intCast(std.posix.system.dup(fd));
}

fn isOpen(fd: sys.fd_t) bool {
    return std.posix.errno(std.posix.system.fcntl(fd, std.posix.F.GETFD, @as(usize, 0))) != .BADF;
}

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
    /// Streamed request bodies in progress (any worker), and one held
    /// paused until a test resumes it.
    uploads_mutex: sys.Mutex = .{},
    uploads: std.AutoHashMapUnmanaged(Exchange, Upload) = .empty,
    held: ?Exchange = null,

    const Upload = struct {
        len: u64 = 0,
        hash: std.hash.Fnv1a_32 = .init(),
        /// `early`: answered on the first chunk, before the rest.
        pause: enum { none, each, hold, early } = .none,
    };

    pub fn init(allocator: std.mem.Allocator) !*TestHandler {
        const h = try allocator.create(TestHandler);
        h.* = .{ .allocator = allocator };
        return h;
    }

    pub fn deinit(self: *TestHandler) void {
        self.uploads.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn handleHead(_: *TestHandler, req: *Request, resp: *Response) BodyMode {
        const path = req.getPath();
        if (!std.mem.startsWith(u8, path, "/upload")) return .buffer;
        if (std.mem.eql(u8, path, "/upload-reject")) {
            resp.status = .payload_too_large;
            resp.setBodyBorrowed("too much");
            return .reject;
        }
        return .stream;
    }

    /// Streamed uploads: the length, an FNV-1a hash of the bytes and the
    /// trailers come back in the response.
    pub fn handleBody(self: *TestHandler, ex: Exchange, chunk: []const u8, end: ?[]const Header) BodyAction {
        self.uploads_mutex.lock();
        defer self.uploads_mutex.unlock();
        const up = self.uploads.getPtr(ex) orelse return .more;
        up.len += chunk.len;
        up.hash.update(chunk);
        if (end) |trailers| {
            var buf: [512]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            w.print("n={d} hash={x}", .{ up.len, up.hash.final() }) catch unreachable;
            for (trailers) |t| w.print(" {s}={s}", .{ t.key, t.value }) catch unreachable;
            _ = self.uploads.remove(ex);
            ex.respond(.{}, w.buffered()) catch unreachable;
            return .more;
        }
        switch (up.pause) {
            .none => return .more,
            .each => {
                // Resumed through the mailbox, from the worker's own thread.
                ex.resumeBody() catch unreachable;
                return .pause;
            },
            .hold => {
                up.pause = .none;
                self.held = ex;
                return .pause;
            },
            .early => {
                _ = self.uploads.remove(ex);
                ex.respond(.{}, "early") catch unreachable;
                return .more;
            },
        }
    }

    /// Test thread: resumes the held upload.
    fn resumeHeld(self: *TestHandler) !void {
        self.uploads_mutex.lock();
        const ex = self.held orelse {
            self.uploads_mutex.unlock();
            return error.NothingHeld;
        };
        self.held = null;
        self.uploads_mutex.unlock();
        try ex.resumeBody();
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

    pub fn handleAbort(self: *TestHandler, ex: Exchange) void {
        _ = self.aborts.fetchAdd(1, .monotonic);
        self.flood = null;
        self.uploads_mutex.lock();
        defer self.uploads_mutex.unlock();
        _ = self.uploads.remove(ex);
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
        if (std.mem.startsWith(u8, path, "/upload")) {
            if (std.mem.eql(u8, path, "/upload-sync")) {
                // Answered at once: the body is not read.
                resp.setBodyBorrowed("early");
                return;
            }
            const ex = resp.later() catch unreachable;
            self.uploads_mutex.lock();
            defer self.uploads_mutex.unlock();
            self.uploads.put(self.allocator, ex, .{
                .pause = if (std.mem.eql(u8, path, "/upload-pause"))
                    .each
                else if (std.mem.eql(u8, path, "/upload-hold"))
                    .hold
                else if (std.mem.eql(u8, path, "/upload-early"))
                    .early
                else
                    .none,
            }) catch unreachable;
            return;
        }
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
        if (std.mem.startsWith(u8, path, "/kf/") or std.mem.startsWith(u8, path, "/km/")) {
            // /kf/OFF/LEN: big_body[OFF..][0..LEN] from the file;
            // /km/LEN: big_body[0..LEN] from memory.
            var it = std.mem.tokenizeScalar(u8, path[4..], '/');
            const a = std.fmt.parseInt(usize, it.next() orelse "0", 10) catch 0;
            const len = if (path[2] == 'm') 0 else std.fmt.parseInt(usize, it.next() orelse "0", 10) catch 0;
            if (a > big_body_len or len > big_body_len - a) {
                resp.status = .bad_request;
                return;
            }
            if (path[2] == 'm') {
                resp.setBodyBorrowed(big_body[0..a]);
            } else {
                resp.sendFile(.{ .fd = test_file_fd, .offset = a, .len = len });
            }
            return;
        }
        if (std.mem.startsWith(u8, path, "/file")) {
            // big_body from a file: whole, a range, an owned duplicate, or
            // a length past the end (the file "shrank").
            if (std.mem.eql(u8, path, "/file-range")) {
                resp.sendFile(.{ .fd = test_file_fd, .offset = 1000, .len = 5000 });
            } else if (std.mem.eql(u8, path, "/file-owned")) {
                const fd = dupFd(test_file_fd);
                last_owned_fd.store(fd, .release);
                resp.sendFile(.{ .fd = fd, .len = big_body_len, .close = true });
            } else if (std.mem.eql(u8, path, "/file-truncated")) {
                resp.sendFile(.{ .fd = test_file_fd, .len = big_body_len + 10 });
            } else {
                resp.sendFile(.{ .fd = test_file_fd, .len = big_body_len });
            }
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
    /// A pause before each read: a slow reader.
    pace_ms: u64 = 0,

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
        if (self.pace_ms > 0) sleepMs(self.pace_ms);
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

test "a pipelined burst beyond the request buffer is answered in order" {
    try forEachBackend(testPipelinedBurst);
}

fn testPipelinedBurst(backend: Backend) !void {
    // The session takes about 22 KiB at most with these limits.
    const r = try Running.start(backend, .{ .worker_thread_count = 1, .limits = .{ .max_body_size = 1024 } });
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    var head: [4096]u8 = undefined;
    var body: [512]u8 = undefined;
    // One request first: on io_uring the next ones arrive through the
    // connection's multishot receive, several buffers at a time.
    try c.send("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try c.readResponse(&head, &body);

    // About 80 KB in one write, every 100th request with a body.
    const n = 2000;
    var burst: std.ArrayList(u8) = .empty;
    defer burst.deinit(testing.allocator);
    for (0..n) |i| {
        if (i % 100 == 99) {
            try burst.print(testing.allocator, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 300\r\n\r\n", .{});
            try burst.appendNTimes(testing.allocator, @truncate('a' + i / 100), 300);
        } else {
            try burst.print(testing.allocator, "GET /p{d} HTTP/1.1\r\nHost: x\r\n\r\n", .{i});
        }
    }
    try c.send(burst.items);
    var expected: [32]u8 = undefined;
    for (0..n) |i| {
        const res = try c.readResponse(&head, &body);
        try testing.expectEqual(@as(u16, 200), res.status);
        if (i % 100 == 99) {
            try testing.expectEqual(@as(usize, 300), res.body_len);
            try testing.expect(std.mem.allEqual(u8, body[0..300], @truncate('a' + i / 100)));
        } else {
            const want = try std.fmt.bufPrint(&expected, "x-path: /p{d}\r\n", .{i});
            try testing.expect(std.mem.indexOf(u8, res.head, want) != null);
        }
    }
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

test "file bodies: sendfile on HTTP/1.1, and over TLS, h2c and HTTP/3" {
    try forEachBackend(testFiles);
}

fn testFiles(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const file = try tmp.dir.createFile(io, "big", .{ .read = true });
    defer file.close(io);
    try file.writeStreamingAll(io, &big_body);
    test_file_fd = file.handle;
    defer test_file_fd = -1;
    const got = try testing.allocator.alloc(u8, big_body_len);
    defer testing.allocator.free(got);
    var head: [4096]u8 = undefined;
    // HTTP/1.1 with sendfile, then with its read-and-write fallback.
    for ([_]bool{ false, true }) |no_sendfile| {
        sys.sendfile_disabled = no_sendfile;
        defer sys.sendfile_disabled = false;
        // HTTP/1.1, pipelined and read slowly: the socket fills mid-file.
        const r = try Running.start(backend, h2Config());
        defer r.stop();
        var c = try Client.connect(r.port);
        defer c.close();
        try c.send("GET /file HTTP/1.1\r\nHost: x\r\n\r\nGET /file-range HTTP/1.1\r\nHost: x\r\n\r\n" ++
            "HEAD /file HTTP/1.1\r\nHost: x\r\n\r\nGET /file-owned HTTP/1.1\r\nHost: x\r\n\r\nGET /end HTTP/1.1\r\nHost: x\r\n\r\n");
        sleepMs(50);
        var res = try c.readResponse(&head, got);
        try testing.expectEqual(@as(usize, big_body_len), res.body_len);
        try testing.expect(std.mem.eql(u8, &big_body, got));
        res = try c.readResponse(&head, got);
        try testing.expectEqualSlices(u8, big_body[1000..6000], got[0..res.body_len]);
        // HEAD: the length, no body.
        const head_res = try c.readHead(&head);
        try testing.expect(std.mem.indexOf(u8, head_res, "content-length: 8388608\r\n") != null);
        res = try c.readResponse(&head, got);
        try testing.expectEqual(@as(usize, big_body_len), res.body_len);
        try testing.expect(std.mem.eql(u8, &big_body, got));
        res = try c.readResponse(&head, null);
        try testing.expect(std.mem.indexOf(u8, res.head, "x-path: /end\r\n") != null);
        // The owned file was closed once sent.
        var tries: usize = 0;
        while (isOpen(last_owned_fd.load(.acquire)) and tries < 100) : (tries += 1) sleepMs(10);
        try testing.expect(!isOpen(last_owned_fd.load(.acquire)));
        // A file shorter than its length: the connection closes mid-body.
        var c2 = try Client.connect(r.port);
        defer c2.close();
        try c2.send("GET /file-truncated HTTP/1.1\r\nHost: x\r\n\r\n");
        if (c2.readResponse(&head, got)) |_| return error.TestUnexpectedResult else |_| {}

        // h2c.
        const h = try H2Client.connect(r.port);
        defer h.close();
        var reply: H2Client.Reply = .{};
        defer reply.deinit();
        try h.fetch(1, "GET", "/file", null, &reply);
        try testing.expectEqual(@as(u16, 200), reply.status);
        try testing.expect(std.mem.eql(u8, &big_body, reply.body.items));
        var range: H2Client.Reply = .{};
        defer range.deinit();
        try h.fetch(3, "GET", "/file-range", null, &range);
        try testing.expectEqualSlices(u8, big_body[1000..6000], range.body.items);
    }
    {
        // TLS (read and encrypted) and HTTP/3.
        var cfg = tlsConfig();
        cfg.http3 = .{};
        const r = try Running.start(backend, cfg);
        defer r.stop();
        const c = try TlsClient.connect(r.port);
        defer c.close();
        try c.send("GET /file HTTP/1.1\r\nHost: x\r\n\r\nGET /file-range HTTP/1.1\r\nHost: x\r\n\r\n");
        var res = try c.readResponse(got);
        try testing.expectEqual(@as(usize, big_body_len), res.body_len);
        try testing.expect(std.mem.eql(u8, &big_body, got));
        res = try c.readResponse(got);
        try testing.expectEqualSlices(u8, big_body[1000..6000], got[0..res.body_len]);

        var h3 = try H3Client.connect(r.srv.getQuicPort());
        defer h3.close();
        try h3.start();
        const id = try h3.request("GET", "/file-range", "");
        try h3.waitFinished(&.{id});
        var a = try h3.response(id);
        defer a.body.deinit(testing.allocator);
        try testing.expectEqualSlices(u8, big_body[1000..6000], a.body.items);
    }
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
    // Part of a request, then nothing (io_uring then receives into the
    // buffer holding it, and closing must cancel that receive).
    var stalled = try Client.connect(r.port);
    defer stalled.close();
    try stalled.send("GET / HTTP/1.1\r\nHo");
    // Slowloris: trickle a request without finishing it.
    var slow = try Client.connect(r.port);
    defer slow.close();
    for ("GET / HTTP/1.1\r\nHo") |b| {
        slow.send(&.{b}) catch break;
        sleepMs(150);
    }
    const start = sys.nanoTimestamp();
    try idle.expectClosed();
    try stalled.expectClosed();
    try slow.expectClosed();
    // Within the 5 s client receive timeout, so the server closed them.
    try testing.expect(sys.nanoTimestamp() - start < 4 * std.time.ns_per_s);
}

test "a slow reader of pipelined responses: each response's progress renews the request timeout" {
    try forEachBackend(testSlowPipelinedReader);
}

fn testSlowPipelinedReader(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const r = try Running.start(backend, .{ .request_timeout_s = 1 });
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    var head: [4096]u8 = undefined;
    try c.send("GET /km/10 HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try c.readResponse(&head, null);
    // Small socket buffers at both ends (no autotuning to swallow it
    // all): the server's writes stop short often, and each time the
    // socket has room again a few responses finish and the next one
    // stops short.
    const server_fd = peerSocket(c.fd) orelse return error.NoServerSocket;
    try sys.setsockoptInt(server_fd, posix.SOL.SOCKET, posix.SO.SNDBUF, 64 * 1024);
    try sys.setsockoptInt(c.fd, posix.SOL.SOCKET, posix.SO.RCVBUF, 128 * 1024);
    // 120 responses of 32 KiB read at about 1 MB/s: over 3 s in all,
    // never long without progress.
    const n = 120;
    const len = 32 * 1024;
    var reqs: std.Io.Writer.Allocating = .init(testing.allocator);
    defer reqs.deinit();
    for (0..n) |_| try reqs.writer.print("GET /km/{d} HTTP/1.1\r\nHost: x\r\n\r\n", .{len});
    try c.send(reqs.written());
    c.pace_ms = 50;
    var body: [len]u8 = undefined;
    for (0..n) |_| {
        const res = try c.readResponse(&head, &body);
        try testing.expectEqual(200, res.status);
        try testing.expectEqual(len, res.body_len);
        try testing.expectEqualSlices(u8, big_body[0..len], &body);
    }
}

/// The server's end of a loopback connection (same process): the socket
/// whose peer is `fd`'s local address.
fn peerSocket(fd: sys.fd_t) ?sys.fd_t {
    var local: posix.sockaddr.in = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    if (posix.errno(system.getsockname(fd, @ptrCast(&local), &len)) != .SUCCESS) return null;
    var other: sys.fd_t = 3;
    while (other < 4096) : (other += 1) {
        if (other == fd) continue;
        var peer: posix.sockaddr.in = undefined;
        len = @sizeOf(posix.sockaddr.in);
        if (posix.errno(system.getpeername(other, @ptrCast(&peer), &len)) != .SUCCESS) continue;
        if (peer.family == posix.AF.INET and peer.port == local.port and peer.addr == local.addr) return other;
    }
    return null;
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

// -- HTTP/2 over cleartext (h2c, prior knowledge) ---------------------------

/// An HTTP/2 client over TCP: HPACK, frames, and flow control enough to
/// drive the server.
fn setBlocking(fd: sys.fd_t, blocking: bool) void {
    const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    if (sys.is_linux) {
        const flags: u32 = @truncate(std.os.linux.fcntl(fd, posix.F.GETFL, 0));
        _ = std.os.linux.fcntl(fd, posix.F.SETFL, if (blocking) flags & ~nonblock else flags | nonblock);
    } else {
        const flags: u32 = @bitCast(system.fcntl(fd, posix.F.GETFL, @as(c_int, 0)));
        _ = system.fcntl(fd, posix.F.SETFL, @as(c_int, @bitCast(if (blocking) flags & ~nonblock else flags | nonblock)));
    }
}

fn fnv(bytes: []const u8) u32 {
    var h: std.hash.Fnv1a_32 = .init();
    h.update(bytes);
    return h.final();
}

/// Reads one response and checks its status and body.
fn expectResponse(c: *Client, status: u16, body: []const u8) !void {
    var head: [1024]u8 = undefined;
    var got: [512]u8 = undefined;
    const r = try c.readResponse(&head, &got);
    try testing.expectEqual(status, r.status);
    try testing.expectEqualStrings(body, got[0..r.body_len]);
}

test "streamed request bodies: beyond max_body_size, chunked trailers, 100-continue, reject, early answer" {
    try forEachBackend(testUploads);
}

fn testUploads(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    // Buffered bodies stay limited to 64 KiB; streamed ones are not.
    const r = try Running.start(backend, .{ .limits = .{ .max_body_size = 64 * 1024 } });
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    var expected: [128]u8 = undefined;

    // 6 MB with Content-Length, sent in pieces, then a request after it.
    const body = big_body[0 .. 6 * 1024 * 1024];
    try c.send("POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 6291456\r\n\r\n");
    var rest: []const u8 = body;
    while (rest.len > 0) {
        const n = @min(rest.len, 100_000);
        try c.send(rest[0..n]);
        rest = rest[n..];
    }
    try c.send("GET /after HTTP/1.1\r\nHost: x\r\n\r\n");
    try expectResponse(&c, 200, try std.fmt.bufPrint(&expected, "n={d} hash={x}", .{ body.len, fnv(body) }));
    try expectResponse(&c, 200, "ok");

    // Chunked, with trailers.
    try c.send("POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Sum: 11\r\nX-Other: b\r\n\r\n");
    try expectResponse(&c, 200, try std.fmt.bufPrint(&expected, "n=11 hash={x} X-Sum=11 X-Other=b", .{fnv("hello world")}));

    // 100-continue: the interim response first, then the body is wanted.
    try c.send("PUT /upload-pause HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\nExpect: 100-continue\r\n\r\n");
    try testing.expectEqualStrings("HTTP/1.1 100 Continue", try c.readLine());
    c.consume("HTTP/1.1 100 Continue\r\n\r\n".len);
    try c.send(big_body[0..1000000]);
    try expectResponse(&c, 200, try std.fmt.bufPrint(&expected, "n=1000000 hash={x}", .{fnv(big_body[0..1000000])}));

    // Rejected on its head: no 100 Continue, and the connection closes.
    try c.send("PUT /upload-reject HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\nExpect: 100-continue\r\n\r\n");
    var head: [1024]u8 = undefined;
    var got: [64]u8 = undefined;
    const rej = try c.readResponse(&head, &got);
    try testing.expectEqual(@as(u16, 413), rej.status);
    try testing.expect(std.mem.indexOf(u8, rej.head, "connection: close\r\n") != null);
    try c.expectClosed();

    // Answered before the body: the rest is drained, the connection closes.
    var c2 = try Client.connect(r.port);
    defer c2.close();
    try c2.send("POST /upload-sync HTTP/1.1\r\nHost: x\r\nContent-Length: 300000\r\n\r\n");
    try c2.send(big_body[0..100000]);
    try expectResponse(&c2, 200, "early");
    c2.send(big_body[0..200000]) catch {};
    try c2.expectClosed();

    // The same from the exchange, as the body starts arriving.
    var c4 = try Client.connect(r.port);
    defer c4.close();
    try c4.send("POST /upload-early HTTP/1.1\r\nHost: x\r\nContent-Length: 300000\r\n\r\n");
    try c4.send(big_body[0..1000]);
    try expectResponse(&c4, 200, "early");
    c4.send(big_body[0..299000]) catch {};
    try c4.expectClosed();

    // A client that leaves mid-body: the handler hears of it.
    const aborts = r.srv.handler.aborts.load(.monotonic);
    var c3 = try Client.connect(r.port);
    try c3.send("POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 300000\r\n\r\n");
    try c3.send(big_body[0..1000]);
    sleepMs(50);
    c3.close();
    var waited: usize = 0;
    while (r.srv.handler.aborts.load(.monotonic) == aborts and waited < 200) : (waited += 1) sleepMs(10);
    try testing.expect(r.srv.handler.aborts.load(.monotonic) > aborts);
}

test "streamed request bodies: a paused body holds the client back" {
    try forEachBackend(testUploadHold);
}

fn testUploadHold(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const r = try Running.start(backend, .{ .worker_thread_count = 1 });
    defer r.stop();
    var c = try Client.connect(r.port);
    defer c.close();
    const total = 64 * 1024 * 1024;
    try c.send("POST /upload-hold HTTP/1.1\r\nHost: x\r\nContent-Length: 67108864\r\n\r\n");
    // Non-blocking: send until the server stops taking bytes.
    setBlocking(c.fd, false);
    var sent: usize = 0;
    var stalls: usize = 0;
    while (stalls < 20) {
        const piece = big_body[sent % big_body.len ..][0..@min(64 * 1024, big_body.len - sent % big_body.len)];
        const n = sys.write(c.fd, piece) catch |err| switch (err) {
            error.WouldBlock => {
                stalls += 1;
                sleepMs(10);
                continue;
            },
            else => return err,
        };
        sent += n;
        stalls = 0;
    }
    // Socket buffers and one read buffer hold the difference.
    try testing.expect(sent < 16 * 1024 * 1024);
    setBlocking(c.fd, true);
    try r.srv.handler.resumeHeld();
    var hash: std.hash.Fnv1a_32 = .init();
    var i: usize = 0;
    while (i < sent) {
        const n = @min(sent - i, big_body.len - i % big_body.len);
        hash.update(big_body[i % big_body.len ..][0..n]);
        i += n;
    }
    while (sent < total) {
        const off = sent % big_body.len;
        const n = @min(total - sent, big_body.len - off);
        try c.send(big_body[off..][0..n]);
        hash.update(big_body[off..][0..n]);
        sent += n;
    }
    var expected: [64]u8 = undefined;
    try expectResponse(&c, 200, try std.fmt.bufPrint(&expected, "n={d} hash={x}", .{ total, hash.final() }));
}

const H2Client = struct {
    tcp: Client,
    enc: hpack.Encoder,
    dec: hpack.Decoder,
    pool: BufferPool,
    reader: h2frame.Reader = .{},
    /// Our receive windows, replenished in batches.
    conn_consumed: u32 = 0,
    max_frame_size: u32 = 16384,
    /// The server sent SETTINGS_ENABLE_CONNECT_PROTOCOL=1.
    connect_protocol: bool = false,
    /// Over TLS (ALPN h2) instead of `tcp` alone.
    tls: ?*TlsAlpnClient = null,
    /// SETTINGS and PING go unanswered: nothing is sent that would make
    /// the server read again.
    quiet: bool = false,

    const Reply = struct {
        status: u16 = 0,
        /// "name=value\n" lines of the head, then of the trailers.
        head: std.ArrayList(u8) = .empty,
        trailers: std.ArrayList(u8) = .empty,
        body: std.ArrayList(u8) = .empty,
        done: bool = false,
        rst: ?h2frame.ErrorCode = null,
        consumed: u32 = 0,

        fn deinit(r: *Reply) void {
            r.head.deinit(testing.allocator);
            r.trailers.deinit(testing.allocator);
            r.body.deinit(testing.allocator);
        }
    };

    fn connect(port: u16) !*H2Client {
        const self = try open(port, false);
        try self.send(h2frame.preface);
        var buf: [64]u8 = undefined;
        try self.send(try settings(&buf));
        return self;
    }

    /// Connected (over TLS, with the handshake done but for our
    /// Finished), nothing sent yet.
    fn open(port: u16, tls: bool) !*H2Client {
        const a = testing.allocator;
        const self = try a.create(H2Client);
        errdefer a.destroy(self);
        const t = if (tls) try TlsAlpnClient.connect(port, "h2") else null;
        errdefer if (t) |x| x.close();
        self.* = .{
            .tcp = if (t) |x| x.tcp else try Client.connect(port),
            .tls = t,
            .enc = try hpack.Encoder.init(a, 4096),
            .dec = try hpack.Decoder.init(a, .{ .max_header_list_size = 1 << 20 }),
            .pool = try BufferPool.init(a, 16 * 1024 + 9, 1),
        };
        return self;
    }

    fn settings(buf: []u8) ![]const u8 {
        return buf[0..try h2frame.writeSettings(buf, &.{.{ .id = .max_concurrent_streams, .value = 1000 }})];
    }

    fn send(self: *H2Client, bytes: []const u8) !void {
        if (self.tls) |t| return t.send(bytes);
        try self.tcp.send(bytes);
    }

    fn close(self: *H2Client) void {
        if (self.tls) |t| t.close() else self.tcp.close();
        self.enc.deinit();
        self.dec.deinit();
        self.reader.deinit(&self.pool);
        self.pool.deinit();
        testing.allocator.destroy(self);
    }

    fn request(self: *H2Client, stream: u31, method: []const u8, path: []const u8, body: ?[]const u8) !void {
        var hdr: [1100]u8 = undefined;
        try self.send(try self.headers(&hdr, stream, method, path, body == null));
        if (body) |b| {
            var rest = b;
            while (true) {
                const k = @min(rest.len, self.max_frame_size);
                const out = try testing.allocator.alloc(u8, k + h2frame.header_len);
                defer testing.allocator.free(out);
                const dn = try h2frame.writeData(out, stream, k == rest.len, rest[0..k]);
                try self.send(out[0..dn]);
                rest = rest[k..];
                if (rest.len == 0) break;
            }
        }
    }

    /// A request's HEADERS frame, in `out`.
    fn headers(self: *H2Client, out: []u8, stream: u31, method: []const u8, path: []const u8, end_stream: bool) ![]const u8 {
        var block: [1024]u8 = undefined;
        var bn: usize = 0;
        bn += try self.enc.encode(block[bn..], ":method", method, .{});
        bn += try self.enc.encode(block[bn..], ":scheme", if (self.tls != null) "https" else "http", .{});
        bn += try self.enc.encode(block[bn..], ":path", path, .{});
        bn += try self.enc.encode(block[bn..], ":authority", "localhost", .{});
        var flags: u8 = h2frame.flag.end_headers;
        if (end_stream) flags |= h2frame.flag.end_stream;
        return out[0..try h2frame.writeHeaders(out, stream, flags, block[0..bn])];
    }

    fn sendWindow(self: *H2Client, stream: u31, inc: u31) !void {
        var buf: [h2frame.header_len + 4]u8 = undefined;
        const n = try h2frame.writeWindowUpdate(&buf, stream, inc);
        try self.send(buf[0..n]);
    }

    /// Reads frames until every response in `responses` (indexed by
    /// stream id) is done, or a GOAWAY arrives. Answers SETTINGS and PING,
    /// replenishes windows.
    fn collect(self: *H2Client, responses: *std.AutoHashMap(u31, *Reply)) !?h2frame.ErrorCode {
        while (true) {
            var pending: usize = 0;
            var it = responses.valueIterator();
            while (it.next()) |r| {
                if (!r.*.done) pending += 1;
            }
            if (pending == 0) return null;
            if (try self.readFrames(responses)) |code| return code;
        }
    }

    /// Reads until `reply` has at least `len` body bytes (WebSockets).
    fn collectBody(self: *H2Client, responses: *std.AutoHashMap(u31, *Reply), reply: *const Reply, len: usize) !void {
        while (reply.body.items.len < len) {
            if (try self.readFrames(responses)) |_| return error.GoAway;
        }
    }

    /// One read, and the frames in it. Returns a GOAWAY's code.
    fn readFrames(self: *H2Client, responses: *std.AutoHashMap(u31, *Reply)) !?h2frame.ErrorCode {
        const a = testing.allocator;
        {
            const space = try self.reader.readSpace(&self.pool, .{});
            const n = if (self.tls) |t| try t.read(space) else try sys.read(self.tcp.fd, space);
            if (n == 0) return error.EndOfStream;
            self.reader.commitRead(n);
            while (true) {
                switch (self.reader.next(.{})) {
                    .need_more => break,
                    .failure => return error.BadServerFrame,
                    .frame => |fr| switch (fr) {
                        .settings => |st| {
                            if (st.ack) continue;
                            var sit = st.iterator();
                            while (sit.next()) |setting| {
                                if (setting.id == .max_frame_size) self.max_frame_size = setting.value;
                                if (setting.id == .enable_connect_protocol) self.connect_protocol = setting.value == 1;
                            }
                            if (self.quiet) continue;
                            var buf: [h2frame.header_len]u8 = undefined;
                            _ = try h2frame.writeSettingsAck(&buf);
                            try self.send(&buf);
                        },
                        .ping => |p| {
                            if (p.ack or self.quiet) continue;
                            var buf: [h2frame.header_len + 8]u8 = undefined;
                            const pn = try h2frame.writePing(&buf, true, p.data);
                            try self.send(buf[0..pn]);
                        },
                        .goaway => |g| return g.code,
                        .headers => |h| {
                            const r = responses.get(h.stream_id) orelse return error.UnknownStream;
                            const Sink = struct {
                                r: *Reply,
                                trailers: bool,
                                pub fn header(sk: *@This(), name: []const u8, value: []const u8) !void {
                                    if (std.mem.eql(u8, name, ":status")) {
                                        sk.r.status = try std.fmt.parseInt(u16, value, 10);
                                        return;
                                    }
                                    const list = if (sk.trailers) &sk.r.trailers else &sk.r.head;
                                    try list.print(testing.allocator, "{s}={s}\n", .{ name, value });
                                }
                            };
                            var sink: Sink = .{ .r = r, .trailers = r.status != 0 };
                            try self.dec.decode(h.fragment, &sink);
                            if (h.end_stream) r.done = true;
                        },
                        .data => |d| {
                            const r = responses.get(d.stream_id) orelse return error.UnknownStream;
                            try r.body.appendSlice(a, d.data);
                            if (d.end_stream) r.done = true;
                            self.conn_consumed += d.flow_len;
                            r.consumed += d.flow_len;
                            if (self.conn_consumed >= 32 * 1024) {
                                try self.sendWindow(0, @intCast(self.conn_consumed));
                                self.conn_consumed = 0;
                            }
                            if (!r.done and r.consumed >= 32 * 1024) {
                                try self.sendWindow(d.stream_id, @intCast(r.consumed));
                                r.consumed = 0;
                            }
                        },
                        .rst_stream => |rs| {
                            const r = responses.get(rs.stream_id) orelse return error.UnknownStream;
                            r.rst = rs.code;
                            r.done = true;
                        },
                        .window_update, .continuation, .priority, .priority_update, .unknown => {},
                    },
                }
            }
            self.reader.releaseIfIdle(&self.pool);
        }
        return null;
    }

    /// An extended CONNECT for a WebSocket (RFC 8441).
    fn connectWs(self: *H2Client, stream: u31, path: []const u8) !void {
        var block: [1024]u8 = undefined;
        var bn: usize = 0;
        for ([_][2][]const u8{ .{ ":method", "CONNECT" }, .{ ":protocol", "websocket" }, .{ ":scheme", "http" }, .{ ":path", path }, .{ ":authority", "localhost" }, .{ "sec-websocket-version", "13" } }) |f|
            bn += try self.enc.encode(block[bn..], f[0], f[1], .{});
        var hdr: [1100]u8 = undefined;
        const n = try h2frame.writeHeaders(&hdr, stream, h2frame.flag.end_headers, block[0..bn]);
        try self.send(hdr[0..n]);
    }

    /// One masked WebSocket frame, in DATA frames.
    fn wsSend(self: *H2Client, stream: u31, op: ws.Opcode, payload: []const u8, end: bool) !void {
        const a = testing.allocator;
        const wire = try a.alloc(u8, payload.len + ws.protocol.max_header_len);
        defer a.free(wire);
        var rest = ws.protocol.encodeFrame(wire, true, op, payload, .{ 0x11, 0x22, 0x33, 0x44 });
        while (true) {
            const k = @min(rest.len, self.max_frame_size);
            const out = try a.alloc(u8, k + h2frame.header_len);
            defer a.free(out);
            const dn = try h2frame.writeData(out, stream, end and k == rest.len, rest[0..k]);
            try self.send(out[0..dn]);
            rest = rest[k..];
            if (rest.len == 0) break;
        }
    }

    /// One request, one response.
    fn fetch(self: *H2Client, stream: u31, method: []const u8, path: []const u8, body: ?[]const u8, out: *Reply) !void {
        try self.request(stream, method, path, body);
        var map = std.AutoHashMap(u31, *Reply).init(testing.allocator);
        defer map.deinit();
        try map.put(stream, out);
        const goaway = try self.collect(&map);
        if (goaway != null) return error.GoAway;
    }
};

fn h2Config() Config {
    return .{ .h2c = true, .worker_thread_count = 1 };
}

test "h2c: many concurrent streams, and HTTP/1.1 on the same port" {
    try forEachBackend(testH2Streams);
}

fn testH2Streams(backend: Backend) !void {
    const r = try Running.start(backend, h2Config());
    defer r.stop();
    const c = try H2Client.connect(r.port);
    defer c.close();
    // 100 requests before reading anything.
    const count = 100;
    var responses: [count]H2Client.Reply = undefined;
    for (&responses) |*x| x.* = .{};
    defer for (&responses) |*x| x.deinit();
    var map = std.AutoHashMap(u31, *H2Client.Reply).init(testing.allocator);
    defer map.deinit();
    var path: [16]u8 = undefined;
    for (0..count) |i| {
        const stream: u31 = @intCast(2 * i + 1);
        const p = try std.fmt.bufPrint(&path, "/s{d}", .{i});
        if (i % 10 == 9) {
            try c.request(stream, "POST", "/echo", p);
        } else {
            try c.request(stream, "GET", p, null);
        }
        try map.put(stream, &responses[i]);
    }
    try testing.expectEqual(@as(?h2frame.ErrorCode, null), try c.collect(&map));
    for (&responses, 0..) |*x, i| {
        try testing.expectEqual(@as(u16, 200), x.status);
        const p = try std.fmt.bufPrint(&path, "/s{d}", .{i});
        if (i % 10 == 9) {
            try testing.expectEqualStrings(p, x.body.items);
        } else {
            try testing.expectEqualStrings("ok", x.body.items);
            var expected: [32]u8 = undefined;
            try testing.expect(std.mem.indexOf(u8, x.head.items, try std.fmt.bufPrint(&expected, "x-path={s}\n", .{p})) != null);
        }
        try testing.expect(std.mem.indexOf(u8, x.head.items, "date=") != null);
    }
    // The connection is reusable afterwards.
    var again: H2Client.Reply = .{};
    defer again.deinit();
    try c.fetch(2 * count + 1, "GET", "/again", null, &again);
    try testing.expectEqualStrings("ok", again.body.items);
    // Meanwhile HTTP/1.1 on the same port, and a bad preface is HTTP/1.1
    // (501: PRI is not a method we know).
    var h1 = try Client.connect(r.port);
    defer h1.close();
    try h1.send("GET /one HTTP/1.1\r\nHost: x\r\n\r\n");
    var head: [4096]u8 = undefined;
    const res = try h1.readResponse(&head, null);
    try testing.expectEqual(@as(u16, 200), res.status);
    var bad = try Client.connect(r.port);
    defer bad.close();
    try bad.send("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nX");
    // The preface is complete and matched before the X: HTTP/2, and X is
    // not a frame header yet. Send a full preface mismatch instead.
    var bad2 = try Client.connect(r.port);
    defer bad2.close();
    try bad2.send("PRI * HTTP/2.0\r\n\r\nSX\r\n\r\n");
    const res2 = try bad2.readResponse(&head, null);
    try testing.expectEqual(@as(u16, 501), res2.status);
}

test "h2c: a request in the write with the preface is answered with no more input" {
    try forEachBackend(testH2FirstWrite);
}

fn testH2FirstWrite(backend: Backend) !void {
    const r = try Running.start(backend, h2Config());
    defer r.stop();
    try expectFirstWriteAnswered(r.port, false);
}

/// The preface, SETTINGS and a request in one write (over TLS, with the
/// client's Finished too) are answered with nothing more sent, not even
/// the SETTINGS ACK: the server must not wait for another read.
fn expectFirstWriteAnswered(port: u16, tls: bool) !void {
    const c = try H2Client.open(port, tls);
    defer c.close();
    if (c.tls) |t| try testing.expectEqualStrings("h2", t.alpn[0..t.alpn_len]);
    c.quiet = true;
    var buf: [2048]u8 = undefined;
    var n = h2frame.preface.len;
    @memcpy(buf[0..n], h2frame.preface);
    n += (try H2Client.settings(buf[n..])).len;
    n += (try c.headers(buf[n..], 1, "GET", "/first", true)).len;
    try c.send(buf[0..n]);
    var reply: H2Client.Reply = .{};
    defer reply.deinit();
    var map = std.AutoHashMap(u31, *H2Client.Reply).init(testing.allocator);
    defer map.deinit();
    try map.put(1, &reply);
    try testing.expectEqual(@as(?h2frame.ErrorCode, null), try c.collect(&map));
    try testing.expectEqual(@as(u16, 200), reply.status);
    try testing.expectEqualStrings("ok", reply.body.items);
}

test "h2c: large bodies through flow control, both directions" {
    try forEachBackend(testH2LargeBodies);
}

test "h2c: output buffers kept for reuse are freed once every client has left" {
    try forEachBackend(testH2OutputFreed);
}

fn testH2OutputFreed(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const r = try Running.start(backend, h2Config());
    defer r.stop();
    {
        const c = try H2Client.connect(r.port);
        defer c.close();
        var big: H2Client.Reply = .{};
        defer big.deinit();
        try c.fetch(1, "GET", "/big", null, &big);
        try testing.expectEqual(@as(usize, big_body_len), big.body.items.len);
    }
    // With no connections the workers would wait for events with no
    // timeout; they tick on until what they kept is freed (two ticks).
    // What each holds is published at its tick: seen held, then none.
    var seen = false;
    var tries: u32 = 0;
    while (!seen or workersHoldOutput(r.srv)) : (tries += 1) {
        if (tries == 120) return if (seen) error.OutputBuffersKept else error.OutputBuffersNeverSeen;
        seen = seen or workersHoldOutput(r.srv);
        sleepMs(50);
    }
}

fn workersHoldOutput(srv: *Server(TestHandler)) bool {
    for (srv.workers) |*w| switch (w.*) {
        .poll => |*p| if (poolHoldsOutput(&p.pool)) return true,
        .uring => |*u| if (sys.is_linux) {
            if (poolHoldsOutput(&u.pool)) return true;
        },
    };
    return false;
}

fn poolHoldsOutput(pool: anytype) bool {
    return pool.output_held.load(.acquire) > 0;
}

fn testH2LargeBodies(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const r = try Running.start(backend, h2Config());
    defer r.stop();
    const c = try H2Client.connect(r.port);
    defer c.close();
    // 8 MB down, through 65535-byte windows replenished by the client.
    var big: H2Client.Reply = .{};
    defer big.deinit();
    try c.fetch(1, "GET", "/big", null, &big);
    try testing.expectEqual(@as(u16, 200), big.status);
    try testing.expectEqual(@as(usize, big_body_len), big.body.items.len);
    try testing.expect(std.mem.eql(u8, &big_body, big.body.items));
    // 600 KB up (within the server's 1 MiB stream window), echoed.
    const upload = big_body[0 .. 600 * 1024];
    var echo: H2Client.Reply = .{};
    defer echo.deinit();
    try c.fetch(3, "POST", "/echo", upload, &echo);
    try testing.expectEqual(@as(u16, 200), echo.status);
    try testing.expectEqualSlices(u8, upload, echo.body.items);
    // 1 MiB up in 10000-byte frames, so frames straddle the server's
    // receive buffers (a regression: the io_uring worker armed a receive
    // while still copying the previous one).
    c.max_frame_size = 10000;
    const upload2 = big_body[0 .. 1000 * 1000];
    var echo2: H2Client.Reply = .{};
    defer echo2.deinit();
    try c.fetch(5, "POST", "/echo", upload2, &echo2);
    try testing.expectEqual(@as(u16, 200), echo2.status);
    try testing.expectEqualSlices(u8, upload2, echo2.body.items);
    c.max_frame_size = 16384;
    // Two large responses interleaved on one connection.
    var a: H2Client.Reply = .{};
    defer a.deinit();
    var b: H2Client.Reply = .{};
    defer b.deinit();
    var map = std.AutoHashMap(u31, *H2Client.Reply).init(testing.allocator);
    defer map.deinit();
    try c.request(7, "GET", "/copy-big", null);
    try c.request(9, "GET", "/big", null);
    try map.put(7, &a);
    try map.put(9, &b);
    try testing.expectEqual(@as(?h2frame.ErrorCode, null), try c.collect(&map));
    try testing.expectEqual((Config{}).response_body_buffer_size, a.body.items.len);
    for (a.body.items, 0..) |byte, i| {
        if (byte != @as(u8, @truncate(i *% 7))) return error.CorruptCopiedBody;
    }
    try testing.expect(std.mem.eql(u8, &big_body, b.body.items));
}

test "h2c: later() from another thread, stream() with trailers" {
    try forEachBackend(testH2Exchanges);
}

fn testH2Exchanges(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const r = try Running.start(backend, h2Config());
    defer r.stop();
    const c = try H2Client.connect(r.port);
    defer c.close();
    var later: H2Client.Reply = .{};
    defer later.deinit();
    var stream: H2Client.Reply = .{};
    defer stream.deinit();
    var later_stream: H2Client.Reply = .{};
    defer later_stream.deinit();
    var sync: H2Client.Reply = .{};
    defer sync.deinit();
    var map = std.AutoHashMap(u31, *H2Client.Reply).init(testing.allocator);
    defer map.deinit();
    try c.request(1, "GET", "/later", null);
    try c.request(3, "GET", "/stream", null);
    try c.request(5, "GET", "/later-stream", null);
    try c.request(7, "GET", "/sync", null);
    try map.put(1, &later);
    try map.put(3, &stream);
    try map.put(5, &later_stream);
    try map.put(7, &sync);
    try testing.expectEqual(@as(?h2frame.ErrorCode, null), try c.collect(&map));
    try testing.expectEqual(@as(u16, 202), later.status);
    try testing.expect(std.mem.indexOf(u8, later.head.items, "x-later=1\n") != null);
    try testing.expectEqualStrings("later-body", later.body.items);
    try testing.expectEqual(@as(u16, 200), stream.status);
    try testing.expectEqual(@as(usize, 6 + 200 * 1024 + 6), stream.body.items.len);
    try testing.expectEqualStrings("hello ", stream.body.items[0..6]);
    try testing.expectEqualSlices(u8, big_body[0 .. 200 * 1024], stream.body.items[6 .. 6 + 200 * 1024]);
    try testing.expectEqualStrings("x-trailer=t\n", stream.trailers.items);
    try testing.expectEqualStrings("x-later=stream\n", later_stream.head.items[0..15]);
    try testing.expectEqual(@as(usize, 111), later_stream.body.items.len);
    try testing.expectEqualStrings("x-trailer=end\n", later_stream.trailers.items);
    try testing.expectEqualStrings("ok", sync.body.items);
    sleepMs(10);
    try testing.expect(r.srv.handler.releases.load(.monotonic) >= 2);
    // A stream reset by the client while its exchange is pending: handleAbort.
    try c.request(9, "GET", "/hang", null);
    var buf: [h2frame.header_len + 4]u8 = undefined;
    const n = try h2frame.writeRstStream(&buf, 9, .cancel);
    try c.tcp.send(buf[0..n]);
    const start = sys.nanoTimestamp();
    while (r.srv.handler.aborts.load(.monotonic) == 0) {
        if (sys.nanoTimestamp() - start > 4 * std.time.ns_per_s) return error.NoAbort;
        sleepMs(10);
    }
    // And the connection still works.
    var after: H2Client.Reply = .{};
    defer after.deinit();
    try c.fetch(11, "GET", "/after", null, &after);
    try testing.expectEqualStrings("ok", after.body.items);
}

test "h2c: streamed uploads, a held body resumed from another thread, reject" {
    try forEachBackend(testH2Uploads);
}

/// Resumes the upload the handler holds, once it holds one.
fn resumeHeldSoon(h: *TestHandler) !void {
    var tries: usize = 0;
    while (true) : (tries += 1) {
        h.resumeHeld() catch |err| switch (err) {
            error.NothingHeld => {
                if (tries > 500) return err;
                sleepMs(5);
                continue;
            },
            else => return err,
        };
        return;
    }
}

fn testH2Uploads(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var cfg = h2Config();
    cfg.limits.max_body_size = 64 * 1024;
    const r = try Running.start(backend, cfg);
    defer r.stop();
    const c = try H2Client.connect(r.port);
    defer c.close();
    var expected: [64]u8 = undefined;
    // Beyond max_body_size (within the windows: the client doesn't wait).
    var up: H2Client.Reply = .{};
    defer up.deinit();
    const body = big_body[0 .. 600 * 1024];
    try c.fetch(1, "POST", "/upload", body, &up);
    try testing.expectEqual(@as(u16, 200), up.status);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "n={d} hash={x}", .{ body.len, fnv(body) }), up.body.items);
    // Held after the first DATA, resumed from this thread.
    var held: H2Client.Reply = .{};
    defer held.deinit();
    const body2 = big_body[0 .. 300 * 1024];
    try c.request(3, "POST", "/upload-hold", body2);
    try resumeHeldSoon(r.srv.handler);
    var map = std.AutoHashMap(u31, *H2Client.Reply).init(testing.allocator);
    defer map.deinit();
    try map.put(3, &held);
    try testing.expectEqual(@as(?h2frame.ErrorCode, null), try c.collect(&map));
    try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "n={d} hash={x}", .{ body2.len, fnv(body2) }), held.body.items);
    // Rejected on its head.
    var rej: H2Client.Reply = .{};
    defer rej.deinit();
    try c.fetch(5, "POST", "/upload-reject", "abc", &rej);
    try testing.expectEqual(@as(u16, 413), rej.status);
    try testing.expectEqualStrings("too much", rej.body.items);
}

/// A server WebSocket frame (unmasked), for comparing bytes.
fn wsServerFrame(out: []u8, op: ws.Opcode, payload: []const u8) []const u8 {
    return ws.protocol.encodeFrame(out, true, op, payload, null);
}

test "h2c: WebSockets over HTTP/2 (RFC 8441) beside requests on one connection" {
    try forEachBackend(testH2WebSocket);
}

fn testH2WebSocket(backend: Backend) !void {
    const r = try Running.start(backend, h2Config());
    defer r.stop();
    const c = try H2Client.connect(r.port);
    defer c.close();
    const big = try testing.allocator.alloc(u8, 100 * 1024);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 13);
    var one: H2Client.Reply = .{};
    defer one.deinit();
    var two: H2Client.Reply = .{};
    defer two.deinit();
    var get: H2Client.Reply = .{};
    defer get.deinit();
    var map = std.AutoHashMap(u31, *H2Client.Reply).init(testing.allocator);
    defer map.deinit();
    try map.put(1, &one);
    try map.put(3, &two);
    try map.put(5, &get);
    // Two WebSockets and a request, interleaved.
    try c.connectWs(1, "/ws");
    try c.connectWs(3, "/ws");
    try c.wsSend(1, .text, "hello one", false);
    try c.wsSend(3, .binary, big, false);
    try c.request(5, "GET", "/plain", null);
    try c.wsSend(1, .text, "async", false);
    var expect1: std.ArrayList(u8) = .empty;
    defer expect1.deinit(testing.allocator);
    var fb: [64]u8 = undefined;
    try expect1.appendSlice(testing.allocator, wsServerFrame(&fb, .text, "hello one"));
    try expect1.appendSlice(testing.allocator, wsServerFrame(&fb, .text, "later"));
    try c.collectBody(&map, &one, expect1.items.len);
    try c.collectBody(&map, &two, big.len + 4);
    try testing.expect(c.connect_protocol);
    try testing.expectEqual(@as(u16, 200), one.status);
    try testing.expectEqual(@as(u16, 200), two.status);
    try testing.expectEqualSlices(u8, expect1.items, one.body.items);
    try testing.expectEqualSlices(u8, &.{ 0x82, 0x7f }, two.body.items[0..2]);
    try testing.expectEqualSlices(u8, big, two.body.items[10..]);
    while (!get.done) _ = try c.readFrames(&map);
    try testing.expectEqualStrings("ok", get.body.items);
    try testing.expectEqual(@as(usize, 2), r.srv.handler.ws_conns.load(.monotonic));

    // The client closes the first: echo, END_STREAM, RST_STREAM(NO_ERROR).
    one.body.clearRetainingCapacity();
    try c.wsSend(1, .close, "\x03\xe8", false);
    while (!one.done or one.rst == null) _ = try c.readFrames(&map);
    try testing.expectEqualSlices(u8, "\x88\x02\x03\xe8", one.body.items);
    try testing.expectEqual(h2frame.ErrorCode.no_error, one.rst.?);
    // The server closes the second; our close with END_STREAM ends it.
    two.body.clearRetainingCapacity();
    try c.wsSend(3, .text, "close-me", false);
    try c.collectBody(&map, &two, 7);
    try testing.expectEqualSlices(u8, "\x88\x05\x03\xe8bye", two.body.items);
    try c.wsSend(3, .close, "\x03\xe8", true);
    while (!two.done) _ = try c.readFrames(&map);
    try testing.expectEqual(@as(?h2frame.ErrorCode, null), two.rst);
    sleepMs(20);
    try testing.expectEqual(@as(usize, 2), r.srv.handler.ws_disconns.load(.monotonic));
    try testing.expectEqual(@as(u16, 1000), r.srv.handler.close_code.load(.monotonic));
    // The connection goes on.
    var after: H2Client.Reply = .{};
    defer after.deinit();
    try c.fetch(7, "GET", "/after", null, &after);
    try testing.expectEqualStrings("ok", after.body.items);
}

test "h2c: GOAWAY on shutdown" {
    try forEachBackend(testH2Goaway);
}

fn testH2Goaway(backend: Backend) !void {
    const r = try Running.start(backend, h2Config());
    const c = try H2Client.connect(r.port);
    defer c.close();
    // A request to make sure the connection is established as HTTP/2.
    var first: H2Client.Reply = .{};
    defer first.deinit();
    try c.fetch(1, "GET", "/", null, &first);
    try testing.expectEqualStrings("ok", first.body.items);
    // Shut the server down: GOAWAY, then the connection closes.
    r.stop();
    var never: H2Client.Reply = .{};
    defer never.deinit();
    var map = std.AutoHashMap(u31, *H2Client.Reply).init(testing.allocator);
    defer map.deinit();
    try map.put(3, &never);
    const result = c.collect(&map);
    try testing.expectEqual(@as(?h2frame.ErrorCode, .no_error), try result);
    try c.tcp.expectClosed();
}

test "h2c: shutdown with sends stuck on readers that stopped, while clients keep connecting" {
    try forEachBackend(testH2ShutdownStuck);
}

fn testH2ShutdownStuck(backend: Backend) !void {
    const r = try Running.start(backend, h2Config());
    // Clients that ask for 8 MiB bodies with huge windows and never read:
    // the worker's writes fill the sockets and stay pending (on io_uring,
    // sends in flight on the output buffers).
    var clients: [6]*H2Client = undefined;
    for (&clients) |*c| {
        c.* = try H2Client.connect(r.port);
        var buf: [64]u8 = undefined;
        const n = try h2frame.writeSettings(&buf, &.{.{ .id = .initial_window_size, .value = h2frame.max_window_size }});
        try c.*.tcp.send(buf[0..n]);
        try c.*.sendWindow(0, h2frame.max_window_size - 65535);
        for (0..3) |i| try c.*.request(@intCast(1 + 2 * i), "GET", "/big", null);
    }
    defer for (clients) |c| c.close();
    sleepMs(300);
    // New connections arrive while the worker shuts down and drains.
    const Connector = struct {
        fn run(port: u16, stop: *std.atomic.Value(bool)) void {
            while (!stop.load(.acquire)) {
                var c = Client.connect(port) catch return;
                c.send(h2frame.preface) catch {};
                c.close();
            }
        }
    };
    var stop = std.atomic.Value(bool).init(false);
    const t = try std.Thread.spawn(.{}, Connector.run, .{ r.port, &stop });
    sleepMs(20);
    const start = sys.nanoTimestamp();
    r.stop();
    const took = sys.nanoTimestamp() - start;
    stop.store(true, .release);
    t.join();
    // Prompt: shutting the sockets down fails the pending writes.
    try testing.expect(took < 3 * std.time.ns_per_s);
}

test "h2c: the client's GOAWAY closes the connection, and the worker goes on" {
    try forEachBackend(testH2ClientGoaway);
}

fn testH2ClientGoaway(backend: Backend) !void {
    const r = try Running.start(backend, h2Config());
    defer r.stop();
    // What curl does: a request, then GOAWAY, then FIN. The connection is
    // closed while the worker is still feeding it input (a regression:
    // the io_uring worker used a freed connection afterwards).
    for (0..3) |_| {
        const c = try H2Client.connect(r.port);
        defer c.close();
        var first: H2Client.Reply = .{};
        defer first.deinit();
        try c.fetch(1, "GET", "/", null, &first);
        try testing.expectEqualStrings("ok", first.body.items);
        var buf: [h2frame.header_len + 8]u8 = undefined;
        const n = try h2frame.writeGoaway(&buf, 1, .no_error, "");
        try c.tcp.send(buf[0..n]);
        try c.tcp.expectClosed();
    }
    // GOAWAY in the same segment as the request: the response still comes.
    const c = try H2Client.connect(r.port);
    defer c.close();
    var block: [256]u8 = undefined;
    var bn: usize = 0;
    bn += try c.enc.encode(block[bn..], ":method", "GET", .{});
    bn += try c.enc.encode(block[bn..], ":scheme", "http", .{});
    bn += try c.enc.encode(block[bn..], ":path", "/", .{});
    var out: [512]u8 = undefined;
    var on = try h2frame.writeHeaders(&out, 1, h2frame.flag.end_headers | h2frame.flag.end_stream, block[0..bn]);
    on += try h2frame.writeGoaway(out[on..], 1, .no_error, "");
    try c.tcp.send(out[0..on]);
    var reply: H2Client.Reply = .{};
    defer reply.deinit();
    var map = std.AutoHashMap(u31, *H2Client.Reply).init(testing.allocator);
    defer map.deinit();
    try map.put(1, &reply);
    _ = c.collect(&map) catch |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    };
    try testing.expectEqualStrings("ok", reply.body.items);
    // The worker still serves others.
    var h1 = try Client.connect(r.port);
    defer h1.close();
    try h1.send("GET /one HTTP/1.1\r\nHost: x\r\n\r\n");
    var head: [4096]u8 = undefined;
    const res = try h1.readResponse(&head, null);
    try testing.expectEqual(@as(u16, 200), res.status);
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
        return connectHost(port, "localhost");
    }

    /// With `host` as SNI; the certificate must be for it.
    fn connectHost(port: u16, host: []const u8) !*TlsClient {
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
            .host = .{ .explicit = host },
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

    const Head = struct { status: u16, body_len: usize, close: bool };

    /// Reads one response. The body is copied into `body` if given.
    fn readResponse(self: *TlsClient, body: ?[]u8) !Head {
        const head = try self.readHead();
        const r = &self.client.reader;
        if (body) |b| try r.readSliceAll(b[0..head.body_len]) else try r.discardAll(head.body_len);
        return head;
    }

    /// Reads a response's head, up to its body.
    fn readHead(self: *TlsClient) !Head {
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

/// A TLS 1.3 client for what std's can't do: ALPN, and its Finished held
/// back to go out in one write with the first application data (as some
/// clients send them). TLS_AES_128_GCM_SHA256 with X25519 only; the
/// certificate is not checked (the server's Finished is).
const TlsAlpnClient = struct {
    const ks = @import("./tls/key_schedule.zig").Sha256;
    const Aes = std.crypto.aead.aes_gcm.Aes128Gcm;
    const X25519 = std.crypto.dh.X25519;
    const max_record = 5 + 16 * 1024 + 256;

    tcp: Client,
    tx: Keys = undefined,
    rx: Keys = undefined,
    /// The negotiated protocol, if any.
    alpn: [16]u8 = undefined,
    alpn_len: usize = 0,
    /// Our Finished, sealed, until the first `send`.
    finished: [64]u8 = undefined,
    finished_len: usize = 0,
    /// Received records not yet opened.
    in: [2 * max_record]u8 = undefined,
    in_start: usize = 0,
    in_end: usize = 0,
    /// Application data opened and not yet read.
    plain: []const u8 = &.{},

    const Keys = struct {
        key: [Aes.key_length]u8,
        iv: [Aes.nonce_length]u8,
        seq: u64 = 0,

        fn init(secret: ks.Secret) Keys {
            return .{ .key = ks.trafficKey(Aes.key_length, secret), .iv = ks.trafficIv(secret) };
        }

        fn nonce(k: *const Keys) [Aes.nonce_length]u8 {
            var n = k.iv;
            var seq: [8]u8 = undefined;
            std.mem.writeInt(u64, &seq, k.seq, .big);
            for (seq, 0..) |b, i| n[4 + i] ^= b;
            return n;
        }

        /// A record of content type `ty` holding `data`, in `out`.
        fn seal(k: *Keys, out: []u8, ty: u8, data: []const u8) []const u8 {
            var inner: [16 * 1024 + 1]u8 = undefined;
            @memcpy(inner[0..data.len], data);
            inner[data.len] = ty;
            const len = data.len + 1 + Aes.tag_length;
            out[0..5].* = .{ 23, 3, 3, 0, 0 };
            std.mem.writeInt(u16, out[3..5], @intCast(len), .big);
            Aes.encrypt(out[5..][0 .. data.len + 1], out[5 + data.len + 1 ..][0..Aes.tag_length], inner[0 .. data.len + 1], out[0..5], k.nonce(), k.key);
            k.seq += 1;
            return out[0 .. 5 + len];
        }

        /// Opens a record in place: its content type and data.
        fn open(k: *Keys, rec: []u8) !struct { ty: u8, data: []u8 } {
            if (rec.len < 5 + 1 + Aes.tag_length) return error.BadRecord;
            const body = rec[5 .. rec.len - Aes.tag_length];
            try Aes.decrypt(body, body, rec[rec.len - Aes.tag_length ..][0..Aes.tag_length].*, rec[0..5], k.nonce(), k.key);
            k.seq += 1;
            var end = body.len;
            while (end > 0 and body[end - 1] == 0) end -= 1;
            if (end == 0) return error.BadRecord;
            return .{ .ty = body[end - 1], .data = body[0 .. end - 1] };
        }
    };

    /// Connects and runs the handshake, offering `alpn` if given.
    fn connect(port: u16, alpn: ?[]const u8) !*TlsAlpnClient {
        const self = try testing.allocator.create(TlsAlpnClient);
        errdefer testing.allocator.destroy(self);
        self.* = .{ .tcp = try Client.connect(port) };
        errdefer self.tcp.close();
        var seed: [32]u8 = undefined;
        sys.randomBytes(&seed);
        const kp = X25519.KeyPair.generateDeterministic(seed);
        var transcript: std.crypto.hash.sha2.Sha256 = .init(.{});

        // ClientHello: TLS 1.3, AES-128-GCM, X25519, ECDSA P-256 (the
        // test certificate) and RSA-PSS signatures, SNI, ALPN.
        var hello: [512]u8 = undefined;
        var w: std.Io.Writer = .fixed(hello[5..]);
        const exts_len: usize = 7 + 18 + 8 + 10 + 42 + if (alpn) |p| 7 + p.len else 0;
        try w.writeAll(&.{ 1, 0, 0, 0, 3, 3 });
        try w.writeAll(&@as([32]u8, @splat(7)));
        try w.writeAll(&.{ 0, 0, 2, 0x13, 0x01, 1, 0 });
        try w.writeInt(u16, @intCast(exts_len), .big);
        try w.writeAll(&.{ 0, 43, 0, 3, 2, 3, 4 }); // supported_versions
        try w.writeAll(&[_]u8{ 0, 0, 0, 14, 0, 12, 0, 0, 9 } ++ "localhost"); // server_name
        try w.writeAll(&.{ 0, 10, 0, 4, 0, 2, 0, 0x1d }); // supported_groups
        try w.writeAll(&.{ 0, 13, 0, 6, 0, 4, 4, 3, 8, 4 }); // signature_algorithms
        try w.writeAll(&.{ 0, 51, 0, 38, 0, 36, 0, 0x1d, 0, 32 }); // key_share
        try w.writeAll(&kp.public_key);
        if (alpn) |p| {
            try w.writeAll(&.{ 0, 16 });
            try w.writeInt(u16, @intCast(3 + p.len), .big);
            try w.writeInt(u16, @intCast(1 + p.len), .big);
            try w.writeByte(@intCast(p.len));
            try w.writeAll(p);
        }
        const msg = w.buffered();
        std.mem.writeInt(u24, msg[1..4], @intCast(msg.len - 4), .big);
        std.debug.assert(msg.len - 4 == 43 + exts_len);
        hello[0..5].* = .{ 22, 3, 1, 0, 0 };
        std.mem.writeInt(u16, hello[3..5], @intCast(msg.len), .big);
        transcript.update(msg);
        try self.tcp.send(hello[0 .. 5 + msg.len]);

        // The server's flight: ServerHello, then handshake messages under
        // the handshake keys, perhaps several to a record.
        var hs_secret: ks.Secret = undefined;
        var c_hs: ks.Secret = undefined;
        var s_hs: ks.Secret = undefined;
        var msgs: [16 * 1024]u8 = undefined;
        var msgs_len: usize = 0;
        while (true) {
            const rec = try self.nextRecord();
            switch (rec[0]) {
                20 => continue, // change_cipher_spec
                22 => {
                    // ServerHello: the key share is the last 32 bytes of
                    // its key_share extension.
                    const sh = rec[5..];
                    if (sh[0] != 2) return error.UnexpectedMessage;
                    const ks_at = std.mem.indexOf(u8, sh, &.{ 0, 51, 0, 36, 0, 0x1d, 0, 32 }) orelse return error.NoKeyShare;
                    const shared = try X25519.scalarmult(kp.secret_key, sh[ks_at + 8 ..][0..32].*);
                    transcript.update(sh);
                    hs_secret = ks.handshakeSecret(ks.earlySecret(), &shared);
                    const th = hashOf(transcript);
                    c_hs = ks.deriveSecret(hs_secret, "c hs traffic", &th);
                    s_hs = ks.deriveSecret(hs_secret, "s hs traffic", &th);
                    self.rx = .init(s_hs);
                },
                23 => {
                    const r = try self.rx.open(rec);
                    if (r.ty != 22) return error.UnexpectedRecord;
                    @memcpy(msgs[msgs_len..][0..r.data.len], r.data);
                    msgs_len += r.data.len;
                    var used: usize = 0;
                    while (msgs_len - used >= 4) {
                        const m = msgs[used..msgs_len];
                        const len = std.mem.readInt(u24, m[1..4], .big);
                        if (m.len < 4 + len) break;
                        used += 4 + len;
                        if (m[0] == 8) self.readAlpn(m[4..][0..len]);
                        if (m[0] != 20) {
                            transcript.update(m[0 .. 4 + len]);
                            continue;
                        }
                        // The server's Finished: ours, then application keys.
                        if (!std.mem.eql(u8, m[4..][0..len], &ks.finishedVerifyData(s_hs, &hashOf(transcript)))) return error.BadFinished;
                        transcript.update(m[0 .. 4 + len]);
                        const th = hashOf(transcript);
                        const master = ks.masterSecret(hs_secret);
                        const fin = [4]u8{ 20, 0, 0, 32 } ++ ks.finishedVerifyData(c_hs, &th);
                        var hs_tx: Keys = .init(c_hs);
                        self.finished_len = hs_tx.seal(&self.finished, 22, &fin).len;
                        self.tx = .init(ks.deriveSecret(master, "c ap traffic", &th));
                        self.rx = .init(ks.deriveSecret(master, "s ap traffic", &th));
                        return self;
                    }
                    std.mem.copyForwards(u8, msgs[0 .. msgs_len - used], msgs[used..msgs_len]);
                    msgs_len -= used;
                },
                else => return error.UnexpectedRecord,
            }
        }
    }

    fn hashOf(transcript: std.crypto.hash.sha2.Sha256) [32]u8 {
        var t = transcript;
        var h: [32]u8 = undefined;
        t.final(&h);
        return h;
    }

    fn readAlpn(self: *TlsAlpnClient, ee: []const u8) void {
        var i: usize = 2;
        while (i + 4 <= ee.len) {
            const ty = std.mem.readInt(u16, ee[i..][0..2], .big);
            const len = std.mem.readInt(u16, ee[i + 2 ..][0..2], .big);
            if (ty == 16) {
                self.alpn_len = ee[i + 6];
                @memcpy(self.alpn[0..self.alpn_len], ee[i + 7 ..][0..self.alpn_len]);
            }
            i += 4 + len;
        }
    }

    fn close(self: *TlsAlpnClient) void {
        self.tcp.close();
        testing.allocator.destroy(self);
    }

    /// The next whole record, valid until the next call.
    fn nextRecord(self: *TlsAlpnClient) ![]u8 {
        while (true) {
            const avail = self.in[self.in_start..self.in_end];
            if (avail.len >= 5) {
                const len = 5 + @as(usize, std.mem.readInt(u16, avail[3..5], .big));
                if (len > max_record) return error.BadRecord;
                if (avail.len >= len) {
                    self.in_start += len;
                    return avail[0..len];
                }
            }
            if (self.in_end + max_record > self.in.len) {
                std.mem.copyForwards(u8, self.in[0..avail.len], avail);
                self.in_start = 0;
                self.in_end = avail.len;
            }
            const n = try sys.read(self.tcp.fd, self.in[self.in_end..]);
            if (n == 0) return error.EndOfStream;
            self.in_end += n;
        }
    }

    /// Our Finished if not sent yet, then `bytes`, in one write.
    fn send(self: *TlsAlpnClient, bytes: []const u8) !void {
        const out = try testing.allocator.alloc(u8, self.finished_len + bytes.len + (bytes.len / (16 * 1024) + 1) * 32);
        defer testing.allocator.free(out);
        var n = self.finished_len;
        @memcpy(out[0..n], self.finished[0..n]);
        self.finished_len = 0;
        var rest = bytes;
        while (rest.len > 0) {
            const k = @min(rest.len, 16 * 1024);
            n += self.tx.seal(out[n..], 23, rest[0..k]).len;
            rest = rest[k..];
        }
        try self.tcp.send(out[0..n]);
    }

    /// Application data into `buf`; 0 at the server's close_notify.
    fn read(self: *TlsAlpnClient, buf: []u8) !usize {
        while (self.plain.len == 0) {
            const r = try self.rx.open(try self.nextRecord());
            switch (r.ty) {
                23 => self.plain = r.data,
                22 => {}, // NewSessionTicket
                21 => return 0,
                else => return error.UnexpectedRecord,
            }
        }
        const n = @min(buf.len, self.plain.len);
        @memcpy(buf[0..n], self.plain[0..n]);
        self.plain = self.plain[n..];
        return n;
    }

    /// Reads into `buf` until it holds `needle`.
    fn readUntil(self: *TlsAlpnClient, buf: []u8, needle: []const u8) ![]const u8 {
        var len: usize = 0;
        while (std.mem.indexOf(u8, buf[0..len], needle) == null) {
            const n = try self.read(buf[len..]);
            if (n == 0) return error.EndOfStream;
            len += n;
        }
        return buf[0..len];
    }
};

fn tlsConfig() Config {
    return .{ .tls = .{ .cert_pem = tls_testdata.p256_cert, .key_pem = tls_testdata.p256_key } };
}

test "tls: SNI chooses the certificate" {
    try forEachBackend(testTlsSni);
}

fn testTlsSni(backend: Backend) !void {
    var cfg = tlsConfig();
    cfg.tls.?.certificates = &.{
        .{ .cert_pem = tls_testdata.sni_a_cert, .key_pem = tls_testdata.sni_a_key },
        .{ .cert_pem = tls_testdata.sni_wild_cert, .key_pem = tls_testdata.sni_wild_key },
    };
    const r = try Running.start(backend, cfg);
    defer r.stop();
    // std's client checks the certificate is for the name it sent.
    for ([_][]const u8{ "a.example", "www.b.example", "b.example", "localhost" }) |host| {
        const c = try TlsClient.connectHost(r.port, host);
        defer c.close();
        try c.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        try testing.expectEqual(@as(u16, 200), (try c.readResponse(null)).status);
    }
    // No certificate for this name: the default, which isn't for it.
    try testing.expectError(error.CertificateHostMismatch, TlsClient.connectHost(r.port, "c.example"));
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

test "tls: a streamed upload, then a request on the same connection" {
    try forEachBackend(testTlsUpload);
}

fn testTlsUpload(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var cfg = tlsConfig();
    cfg.limits.max_body_size = 64 * 1024;
    const r = try Running.start(backend, cfg);
    defer r.stop();
    const c = try TlsClient.connect(r.port);
    defer c.close();
    const body = big_body[0 .. 3 * 1024 * 1024];
    try c.send("POST /upload-pause HTTP/1.1\r\nHost: x\r\nContent-Length: 3145728\r\n\r\n");
    try c.send(body);
    try c.send("GET /x HTTP/1.1\r\nHost: x\r\n\r\n");
    var got: [128]u8 = undefined;
    var expected: [64]u8 = undefined;
    const a = try c.readResponse(&got);
    try testing.expectEqual(@as(u16, 200), a.status);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "n={d} hash={x}", .{ body.len, fnv(body) }), got[0..a.body_len]);
    const b = try c.readResponse(&got);
    try testing.expectEqualStrings("ok", got[0..b.body_len]);
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

test "tls: kernel TLS (Linux): responses, a file with sendfile, close_notify" {
    if (!sys.is_linux) return error.SkipZigTest;
    try forEachBackend(testKernelTls);
}

fn testKernelTls(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const file = try tmp.dir.createFile(io, "big", .{ .read = true });
    defer file.close(io);
    try file.writeStreamingAll(io, &big_body);
    test_file_fd = file.handle;
    defer test_file_fd = -1;
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    const before = tls_conn.kernel_tx_count.load(.monotonic);
    const c = try TlsClient.connect(r.port);
    defer c.close();
    var small: [64]u8 = undefined;
    try c.send("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    var res = try c.readResponse(&small);
    try testing.expectEqualStrings("ok", small[0..res.body_len]);
    const got = try testing.allocator.alloc(u8, big_body_len);
    defer testing.allocator.free(got);
    try c.send("GET /file HTTP/1.1\r\nHost: x\r\n\r\nGET /file-range HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    res = try c.readResponse(got);
    try testing.expect(std.mem.eql(u8, &big_body, got[0..res.body_len]));
    res = try c.readResponse(got);
    try testing.expectEqualSlices(u8, big_body[1000..6000], got[0..res.body_len]);
    // close_notify, sent through the kernel as an alert record.
    try c.expectCleanClose();
    // Without a tls module (Docker Desktop's kernel) connections stay in
    // user space.
    const ktls = kernelTlsAvailable();
    if (ktls) try testing.expect(tls_conn.kernel_tx_count.load(.monotonic) > before);

    // Our KeyUpdates every 4 records: the kernel switches keys at least
    // 128 times in a file through sendfile (TLS 1.3 rekey, Linux 6.14 on),
    // or the connection closes at the first; in user space we do. Either
    // way no key carries more than 4 records, however much one sendfile
    // could take (a fast reader drains the socket as the kernel fills it:
    // all 8 MiB in one call).
    tls_conn.test_key_update_limit = 4;
    defer tls_conn.test_key_update_limit = null;
    const c2 = try TlsClient.connect(r.port);
    defer c2.close();
    try c2.send("GET /file HTTP/1.1\r\nHost: x\r\n\r\n");
    const kbuf = try testing.allocator.alloc(u8, big_body_len + 4096);
    defer testing.allocator.free(kbuf);
    var k = KeyChecker.init(c2, 4, kbuf);
    var pos: usize = 0;
    if (k.expectResponse(&pos, &big_body)) |_| {
        try testing.expect(!ktls or kernelRekeySupported());
        try testing.expect(k.key_updates >= big_body_len / (4 * 16384));
    } else |err| {
        try testing.expect(err != error.KeyUpdateMissed and err != error.BodyMismatch);
        try testing.expect(ktls and !kernelRekeySupported());
    }
}

// -- Record limits per key, through the kernel (kTLS) or not ------------------

/// Reads a TLS stream with std's client a record at a time, keeping the
/// plaintext, and fails as soon as more than `limit` records come under one
/// key (std counts them in read_seq, which a KeyUpdate resets; one more is
/// allowed for close_notify, as for a KeyUpdate).
const KeyChecker = struct {
    c: *TlsClient,
    limit: u64,
    buf: []u8,
    len: usize = 0,
    seq: u64 = 0,
    key_updates: usize = 0,
    key: [16]u8,
    closed: bool = false,
    /// Sleep now and then: the server's socket fills and its writes stop
    /// short.
    slow: bool = false,
    fills: usize = 0,

    /// The first bytes of the server's current traffic secret.
    fn serverKey(client: *const StdTls) [16]u8 {
        return switch (client.application_cipher) {
            inline else => |*p| p.tls_1_3.server_secret[0..16].*,
        };
    }

    fn init(c: *TlsClient, limit: u64, buf: []u8) KeyChecker {
        // A send that can't finish (the server stopped reading) fails
        // instead of hanging the test.
        const timeout = posix.timeval{ .sec = 5, .usec = 0 };
        posix.setsockopt(c.fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
        return .{ .c = c, .limit = limit, .buf = buf, .seq = c.client.read_seq, .key = serverKey(&c.client) };
    }

    /// One record (or what is buffered). error.EndOfStream after
    /// close_notify.
    fn step(self: *KeyChecker) !void {
        if (self.closed) return error.EndOfStream;
        const r = &self.c.client.reader;
        if (r.bufferedLen() == 0) {
            if (self.slow) {
                self.fills += 1;
                if (self.fills % 4 == 0) sleepMs(1);
            }
            try r.fillMore();
        }
        const seq = self.c.client.read_seq;
        // One record per fill: a KeyUpdate changed the server's key.
        const key = serverKey(&self.c.client);
        if (!std.mem.eql(u8, &key, &self.key)) self.key_updates += 1;
        self.key = key;
        self.seq = seq;
        self.closed = self.c.client.eof();
        if (seq > self.limit + @intFromBool(self.closed)) return error.KeyUpdateMissed;
        const k = r.bufferedLen();
        if (self.len + k > self.buf.len) return error.TooMuchData;
        @memcpy(self.buf[self.len..][0..k], r.buffered());
        r.toss(k);
        self.len += k;
    }

    fn untilLen(self: *KeyChecker, n: usize) !void {
        while (self.len < n) try self.step();
    }

    fn untilClose(self: *KeyChecker) !void {
        while (!self.closed) try self.step();
    }

    /// Reads one response at `pos.*` and checks its body is `body`.
    fn expectResponse(self: *KeyChecker, pos: *usize, body: []const u8) !void {
        const head_end = while (true) {
            if (std.mem.indexOf(u8, self.buf[pos.*..self.len], "\r\n\r\n")) |i| break pos.* + i + 4;
            try self.step();
        };
        const head = self.buf[pos.*..head_end];
        try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200 "));
        const cl = (std.mem.indexOf(u8, head, "content-length: ") orelse return error.NoContentLength) + 16;
        const cl_end = std.mem.indexOfScalarPos(u8, head, cl, '\r').?;
        try testing.expectEqual(body.len, try std.fmt.parseInt(usize, head[cl..cl_end], 10));
        try self.untilLen(head_end + body.len);
        if (!std.mem.eql(u8, body, self.buf[head_end..][0..body.len])) return error.BodyMismatch;
        pos.* = head_end + body.len;
    }

    /// Reads one server WebSocket frame at `pos.*`.
    fn expectWsFrame(self: *KeyChecker, pos: *usize, opcode: ws.Opcode, payload: []const u8) !void {
        try self.untilLen(pos.* + 2);
        const b0 = self.buf[pos.*];
        var len: usize = self.buf[pos.* + 1] & 0x7f;
        var hl: usize = 2;
        if (len == 126) {
            try self.untilLen(pos.* + 4);
            len = std.mem.readInt(u16, self.buf[pos.* + 2 ..][0..2], .big);
            hl = 4;
        } else if (len == 127) {
            try self.untilLen(pos.* + 10);
            len = @intCast(std.mem.readInt(u64, self.buf[pos.* + 2 ..][0..8], .big));
            hl = 10;
        }
        try testing.expectEqual(@backingInt(opcode), b0 & 0x0f);
        // A server's frames are never masked (RFC 6455 §5.1).
        try testing.expectEqual(0, self.buf[pos.* + 1] & 0x80);
        try self.untilLen(pos.* + hl + len);
        if (!std.mem.eql(u8, payload, self.buf[pos.* + hl ..][0..len])) return error.PayloadMismatch;
        pos.* += hl + len;
    }
};

/// Sends KeyUpdate(update_requested) as std's client's next record, then
/// switches its sending key (RFC 8446 §4.6.3); std's client answers the
/// server's KeyUpdate itself.
fn sendKeyUpdateRequest(c: *TlsClient) !void {
    try c.client.writer.flush();
    try c.file_writer.interface.flush();
    var rec: [5 + 6 + 16]u8 = undefined;
    switch (c.client.application_cipher) {
        inline else => |*p| {
            const pv = &p.tls_1_3;
            const P = @TypeOf(p.*);
            comptime std.debug.assert(P.AEAD.tag_length == 16);
            // KeyUpdate(update_requested), then the inner content type.
            const clear = [_]u8{ 24, 0, 0, 1, 1, 22 };
            rec[0..5].* = .{ 23, 3, 3, 0, clear.len + 16 };
            const V = @Vector(P.AEAD.nonce_length, u8);
            const pad: [P.AEAD.nonce_length - 8]u8 = @splat(0);
            var seq: [8]u8 = undefined;
            std.mem.writeInt(u64, &seq, c.client.write_seq, .big);
            const nonce: [P.AEAD.nonce_length]u8 = @as(V, pv.client_iv) ^ @as(V, pad ++ seq);
            P.AEAD.encrypt(rec[5..][0..clear.len], rec[5 + clear.len ..][0..16], &clear, rec[0..5], nonce, pv.client_key);
            const secret = std.crypto.tls.hkdfExpandLabel(P.Hkdf, pv.client_secret, "traffic upd", "", P.Hash.digest_length);
            pv.client_secret = secret;
            pv.client_key = std.crypto.tls.hkdfExpandLabel(P.Hkdf, secret, "key", "", P.AEAD.key_length);
            pv.client_iv = std.crypto.tls.hkdfExpandLabel(P.Hkdf, secret, "iv", "", P.AEAD.nonce_length);
        },
    }
    c.client.write_seq = 0;
    var rest: []const u8 = &rec;
    while (rest.len > 0) rest = rest[try sys.write(c.fd, rest)..];
}

/// The outcome of a stream checked with KeyChecker: complete, or (kTLS
/// without rekey) cut short when the first KeyUpdate came due, never with
/// more records under a key than allowed.
fn expectKeyLimitOutcome(result: anyerror!void, ktls: bool) !void {
    if (result) |_| {
        // Complete: every KeyUpdate due went out (or none came due).
    } else |err| {
        if (err == error.KeyUpdateMissed or err == error.BodyMismatch or err == error.PayloadMismatch or
            err == error.TooMuchData or err == error.TestUnexpectedResult or err == error.TestExpectedEqual)
        {
            std.debug.print("key limit check failed: {s}\n", .{@errorName(err)});
            return err;
        }
        if (!(ktls and !rekeyOk())) {
            std.debug.print("unexpected error: {s}\n", .{@errorName(err)});
            return err;
        }
    }
}

fn ktlsOk() bool {
    if (comptime !sys.is_linux) return false;
    return kernelTlsAvailable();
}

fn rekeyOk() bool {
    if (comptime !sys.is_linux) return false;
    return kernelRekeySupported();
}

const KfReq = struct { kind: u8, off: usize, len: usize };

fn kfPath(buf: []u8, q: KfReq) ![]const u8 {
    return if (q.kind == 'f')
        std.fmt.bufPrint(buf, "/kf/{d}/{d}", .{ q.off, q.len })
    else
        std.fmt.bufPrint(buf, "/km/{d}", .{q.len});
}

fn kfBody(q: KfReq) []const u8 {
    return if (q.kind == 'f') big_body[q.off..][0..q.len] else big_body[0..q.len];
}

fn setupKfFile(tmp: *std.testing.TmpDir) !std.Io.File {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    const io = testing.io;
    const file = try tmp.dir.createFile(io, "big", .{ .read = true });
    try file.writeStreamingAll(io, &big_body);
    test_file_fd = file.handle;
    return file;
}

/// Files and in-memory bodies of sizes around record multiples and the
/// per-write cap, on one connection: pipelined all at once, or one at a
/// time.
fn kfRequests(limit: u64, list: *std.ArrayList(KfReq)) !void {
    const R = 16384;
    const cap = limit * R;
    const a = testing.allocator;
    try list.append(a, .{ .kind = 'm', .off = 0, .len = 2 }); // user space
    try list.append(a, .{ .kind = 'f', .off = 0, .len = 1 }); // kTLS from here
    try list.append(a, .{ .kind = 'm', .off = 0, .len = R - 1 });
    try list.append(a, .{ .kind = 'f', .off = 0, .len = R });
    try list.append(a, .{ .kind = 'f', .off = 1, .len = R + 1 });
    try list.append(a, .{ .kind = 'm', .off = 0, .len = R });
    try list.append(a, .{ .kind = 'm', .off = 0, .len = R + 1 });
    try list.append(a, .{ .kind = 'f', .off = 7, .len = R - 1 });
    for ([_]usize{ 2 * R - 1, 2 * R, 2 * R + 1, 3 * R - 1, 3 * R, 3 * R + 1 }) |n| {
        try list.append(a, .{ .kind = 'f', .off = 0, .len = n });
        try list.append(a, .{ .kind = 'm', .off = 0, .len = n });
    }
    for ([_]usize{ cap - 1, cap, cap + 1, 2 * cap - 1, 2 * cap + 1 }) |n| {
        if (n > 4 << 20) continue;
        try list.append(a, .{ .kind = 'f', .off = 4095, .len = n });
        try list.append(a, .{ .kind = 'm', .off = 0, .len = n });
    }
    try list.append(a, .{ .kind = 'm', .off = 0, .len = 300000 });
    try list.append(a, .{ .kind = 'f', .off = 123, .len = 1000000 });
    try list.append(a, .{ .kind = 'f', .off = 0, .len = 1 });
}

test "tls: key record limits (1, 2, 3, 4, 5, 37, 256), kernel TLS or not: pipelined and sequential files and bodies around record multiples" {
    try forEachBackend(testKeyLimitsMixed);
}

fn testKeyLimitsMixed(backend: Backend) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try setupKfFile(&tmp);
    defer file.close(testing.io);
    defer test_file_fd = -1;
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    const ktls = ktlsOk();
    const buf = try testing.allocator.alloc(u8, 32 << 20);
    defer testing.allocator.free(buf);
    defer tls_conn.test_key_update_limit = null;
    for ([_]u64{ 1, 2, 3, 4, 5, 37, 256 }) |limit| {
        for ([_]bool{ false, true }) |no_sendfile| {
            for ([_]bool{ true, false }) |pipelined| {
                sys.sendfile_disabled = no_sendfile;
                defer sys.sendfile_disabled = false;
                tls_conn.test_key_update_limit = limit;
                var list: std.ArrayList(KfReq) = .empty;
                defer list.deinit(testing.allocator);
                try kfRequests(limit, &list);
                const c = try TlsClient.connect(r.port);
                defer c.close();
                var k = KeyChecker.init(c, limit, buf);
                const res = runKf(c, &k, list.items, pipelined);
                expectKeyLimitOutcome(res, ktls) catch |err| {
                    std.debug.print("backend {s} limit {d} no_sendfile {} pipelined {}: {d} bytes, {d} key updates\n", .{ @tagName(backend), limit, no_sendfile, pipelined, k.len, k.key_updates });
                    return err;
                };
            }
        }
    }
}

fn runKf(c: *TlsClient, k: *KeyChecker, list: []const KfReq, pipelined: bool) !void {
    var req_buf: [64 << 10]u8 = undefined;
    var w: std.Io.Writer = .fixed(&req_buf);
    var path_buf: [64]u8 = undefined;
    var pos: usize = 0;
    for (list, 0..) |q, i| {
        const last = i == list.len - 1;
        try w.print("GET {s} HTTP/1.1\r\nHost: x\r\n{s}\r\n", .{ try kfPath(&path_buf, q), if (last) "Connection: close\r\n" else "" });
        if (!pipelined) {
            try c.send(w.buffered());
            _ = w.consumeAll();
            try k.expectResponse(&pos, kfBody(q));
        }
    }
    if (pipelined) {
        try c.send(w.buffered());
        for (list) |q| try k.expectResponse(&pos, kfBody(q));
    }
    try k.untilClose();
    try testing.expectEqual(pos, k.len);
}

test "tls: key record limits with a slow reader (the server's writes stop short)" {
    try forEachBackend(testKeyLimitsSlow);
}

fn testKeyLimitsSlow(backend: Backend) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try setupKfFile(&tmp);
    defer file.close(testing.io);
    defer test_file_fd = -1;
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    const ktls = ktlsOk();
    const buf = try testing.allocator.alloc(u8, 16 << 20);
    defer testing.allocator.free(buf);
    defer tls_conn.test_key_update_limit = null;
    for ([_]u64{ 1000000, 1, 3, 37 }) |limit| {
        for ([_]bool{ false, true }) |no_sendfile| {
            sys.sendfile_disabled = no_sendfile;
            defer sys.sendfile_disabled = false;
            tls_conn.test_key_update_limit = limit;
            const c = try TlsClient.connect(r.port);
            defer c.close();
            // Not much smaller: a window shrunk well below the MSS (which
            // Linux keeps at half the largest window seen, ~42 KiB here)
            // is only sent into on the zero-window probe timer, a window
            // per ~200 ms. With 4 KiB the server's 2.6 MiB socket buffer
            // then takes over 10 s to become writable on the arm64 VMs,
            // and the request timeout rightly ends the connection.
            sys.setsockoptInt(c.fd, posix.SOL.SOCKET, posix.SO.RCVBUF, 16384) catch {};
            var k = KeyChecker.init(c, limit, buf);
            k.slow = true;
            const list = [_]KfReq{
                .{ .kind = 'm', .off = 0, .len = 2 },
                .{ .kind = 'f', .off = 3, .len = 1 << 20 },
                .{ .kind = 'm', .off = 0, .len = 200000 },
                .{ .kind = 'f', .off = 0, .len = 3 * 16384 - 1 },
                .{ .kind = 'f', .off = 0, .len = 512 << 10 },
            };
            // Requests first, then nothing read for a while: every write
            // the server tries runs into a full socket.
            const res = runKfSlow(c, &k, &list);
            // With no KeyUpdate due, the connection must not end early either.
            expectKeyLimitOutcome(res, ktls and limit < 1000000) catch |err| {
                std.debug.print("backend {s} limit {d} no_sendfile {}: {d} bytes, {d} key updates\n", .{ @tagName(backend), limit, no_sendfile, k.len, k.key_updates });
                return err;
            };
        }
    }
}

fn runKfSlow(c: *TlsClient, k: *KeyChecker, list: []const KfReq) !void {
    var req_buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&req_buf);
    var path_buf: [64]u8 = undefined;
    for (list, 0..) |q, i| {
        try w.print("GET {s} HTTP/1.1\r\nHost: x\r\n{s}\r\n", .{ try kfPath(&path_buf, q), if (i == list.len - 1) "Connection: close\r\n" else "" });
    }
    try c.send(w.buffered());
    sleepMs(100);
    var pos: usize = 0;
    for (list) |q| try k.expectResponse(&pos, kfBody(q));
    try k.untilClose();
}

test "tls: key record limits: the client's KeyUpdate (update_requested) mid-file and while idle" {
    try forEachBackend(testKeyUpdateRequested);
}

fn testKeyUpdateRequested(backend: Backend) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try setupKfFile(&tmp);
    defer file.close(testing.io);
    defer test_file_fd = -1;
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    const ktls = ktlsOk();
    const buf = try testing.allocator.alloc(u8, 16 << 20);
    defer testing.allocator.free(buf);
    defer tls_conn.test_key_update_limit = null;
    for ([_]u64{ 2, 5, 1000000 }) |limit| {
        for ([_]bool{ false, true }) |no_sendfile| {
            sys.sendfile_disabled = no_sendfile;
            defer sys.sendfile_disabled = false;
            tls_conn.test_key_update_limit = limit;
            const c = try TlsClient.connect(r.port);
            defer c.close();
            var k = KeyChecker.init(c, limit, buf);
            const res = runKeyUpdateRequested(c, &k);
            // A large limit: no KeyUpdate of our own, only answers, which
            // kernels without rekey can't give either.
            expectKeyLimitOutcome(res, ktls) catch |err| {
                std.debug.print("backend {s} limit {d} no_sendfile {}: {d} bytes, {d} key updates\n", .{ @tagName(backend), limit, no_sendfile, k.len, k.key_updates });
                return err;
            };
            if (res) |_| {
                try testing.expect(k.key_updates >= 3);
            } else |_| {}
        }
    }
}

fn runKeyUpdateRequested(c: *TlsClient, k: *KeyChecker) !void {
    var pos: usize = 0;
    try c.send("GET /km/2 HTTP/1.1\r\nHost: x\r\n\r\nGET /kf/0/4000000 HTTP/1.1\r\nHost: x\r\n\r\n");
    try k.expectResponse(&pos, big_body[0..2]);
    // Part of the file, then our KeyUpdate: the answer comes before more
    // data, under the old key.
    try k.untilLen(pos + 300000);
    try sendKeyUpdateRequest(c);
    try k.untilLen(pos + 1000000);
    // Three in a row.
    try sendKeyUpdateRequest(c);
    try sendKeyUpdateRequest(c);
    try sendKeyUpdateRequest(c);
    try k.expectResponse(&pos, big_body[0..4000000]);
    // Idle (kTLS on): answered at once; then requests under our new key.
    const before = k.key_updates;
    try sendKeyUpdateRequest(c);
    while (k.key_updates == before) try k.step();
    try c.send("GET /km/70000 HTTP/1.1\r\nHost: x\r\n\r\n");
    try k.expectResponse(&pos, big_body[0..70000]);
    try sendKeyUpdateRequest(c);
    try c.send("GET /kf/9/100000 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    try k.expectResponse(&pos, big_body[9..][0..100000]);
    try k.untilClose();
}

test "tls: key record limits: a request while our KeyUpdate waits for room" {
    // Linux clamps tiny socket buffers to its minimum; macOS fails writes.
    if (!sys.is_linux) return error.SkipZigTest;
    try forEachBackend(testKeyUpdateWaitsForRoom);
}

fn testKeyUpdateWaitsForRoom(backend: Backend) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try setupKfFile(&tmp);
    defer file.close(testing.io);
    defer test_file_fd = -1;
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    const ktls = ktlsOk();
    const buf = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(buf);
    defer tls_conn.test_key_update_limit = null;
    // Our KeyUpdate due because the client asked for one, or because our
    // last write reached the limit (1: after every write; kernels without
    // rekey close at the first, before the case comes up).
    for ([_]u64{ 1000000, 1 }) |limit| for ([_]usize{ 100000, 300000 }) |len| {
        tls_conn.test_key_update_limit = limit;
        const c = try TlsClient.connect(r.port);
        defer c.close();
        var k = KeyChecker.init(c, limit, buf);
        const start = sys.nanoTimestamp();
        const res = runKeyUpdateWaitsForRoom(c, &k, len, limit == 1000000);
        expectKeyLimitOutcome(res, ktls) catch |err| {
            std.debug.print("backend {s} limit {d} len {d}: {d} bytes, {d} key updates\n", .{ @tagName(backend), limit, len, k.len, k.key_updates });
            return err;
        };
        // Answered (or, without kernel rekey, closed) as soon as there is
        // room, not left until a timeout (the client's 5 s receive
        // timeout, the server's keep-alive timeout).
        const ms = (sys.nanoTimestamp() - start) / std.time.ns_per_ms;
        if (ms >= 3000) {
            std.debug.print("backend {s} limit {d} len {d}: {d} ms ({s})\n", .{ @tagName(backend), limit, len, ms, if (res) |_| "complete" else |e| @errorName(e) });
            return error.TooSlow;
        }
    };
}

fn runKeyUpdateWaitsForRoom(c: *TlsClient, k: *KeyChecker, len: usize, request_key_update: bool) !void {
    var pos: usize = 0;
    try c.send("GET /kf/0/1 HTTP/1.1\r\nHost: x\r\n\r\n");
    try k.expectResponse(&pos, big_body[0..1]);
    // The next response, unread: the client takes what its window allows
    // (it doesn't grow while nothing is read) and the server's socket the
    // rest. Then the server's buffer shrinks to the smallest: the KeyUpdate
    // due next finds no room.
    var path: [64]u8 = undefined;
    try c.send(try std.fmt.bufPrint(&path, "GET /km/{d} HTTP/1.1\r\nHost: x\r\n\r\n", .{len}));
    sleepMs(100);
    const server_fd = peerSocket(c.fd) orelse return error.NoServerSocket;
    try sys.setsockoptInt(server_fd, posix.SOL.SOCKET, posix.SO.SNDBUF, 1);
    // The next request arrives while the KeyUpdate waits: it is answered
    // once the client reads and there is room again.
    if (request_key_update) try sendKeyUpdateRequest(c);
    try c.send("GET /km/10 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    sleepMs(100);
    try k.expectResponse(&pos, big_body[0..len]);
    try k.expectResponse(&pos, big_body[0..10]);
    try k.untilClose();
}

test "tls: key record limits: a WebSocket after a file on one connection (kernel TLS from the file on)" {
    try forEachBackend(testKeyLimitsWebSocket);
}

fn testKeyLimitsWebSocket(backend: Backend) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try setupKfFile(&tmp);
    defer file.close(testing.io);
    defer test_file_fd = -1;
    const r = try Running.start(backend, tlsConfig());
    defer r.stop();
    const ktls = ktlsOk();
    const buf = try testing.allocator.alloc(u8, 16 << 20);
    defer testing.allocator.free(buf);
    defer tls_conn.test_key_update_limit = null;
    for ([_]u64{ 1, 2, 3, 37 }) |limit| {
        for ([_]bool{ true, false }) |pipelined| {
            tls_conn.test_key_update_limit = limit;
            const c = try TlsClient.connect(r.port);
            defer c.close();
            var k = KeyChecker.init(c, limit, buf);
            const res = runKfWebSocket(c, &k, pipelined);
            expectKeyLimitOutcome(res, ktls) catch |err| {
                std.debug.print("backend {s} limit {d} pipelined {}: {d} bytes, {d} key updates\n", .{ @tagName(backend), limit, pipelined, k.len, k.key_updates });
                return err;
            };
        }
    }
}

fn runKfWebSocket(c: *TlsClient, k: *KeyChecker, pipelined: bool) !void {
    var pos: usize = 0;
    try c.send("GET /kf/0/100000 HTTP/1.1\r\nHost: x\r\n\r\n");
    if (!pipelined) try k.expectResponse(&pos, big_body[0..100000]);
    try c.send(Client.upgrade_request);
    if (pipelined) try k.expectResponse(&pos, big_body[0..100000]);
    while (true) {
        if (std.mem.indexOf(u8, k.buf[pos..k.len], "\r\n\r\n")) |i| {
            try testing.expect(std.mem.startsWith(u8, k.buf[pos..], "HTTP/1.1 101 "));
            pos += i + 4;
            break;
        }
        try k.step();
    }
    const frame = try testing.allocator.alloc(u8, 70000);
    defer testing.allocator.free(frame);
    const sizes = [_]usize{ 1, 16383, 16384, 16385, 16384 * 3 - 4, 60000, 125, 126, 65535 };
    if (pipelined) {
        // Less than the socket buffers hold, or neither side would read.
        const few = [_]usize{ 1, 16383, 16384, 16385, 125, 126 };
        for (few) |n| try c.send(Client.wsFrame(frame, true, .binary, big_body[n..][0..n]));
        for (few) |n| try k.expectWsFrame(&pos, .binary, big_body[n..][0..n]);
    } else {
        for (sizes) |n| {
            try c.send(Client.wsFrame(frame, true, .binary, big_body[n..][0..n]));
            try k.expectWsFrame(&pos, .binary, big_body[n..][0..n]);
        }
    }
    try c.send(Client.wsFrame(frame, true, .text, "close-me"));
    try k.untilLen(pos + 2);
    try testing.expectEqual(@backingInt(ws.Opcode.close), k.buf[pos] & 0x0f);
    try c.send(Client.wsFrame(frame, true, .close, &.{ 0x03, 0xe8 }));
    try k.untilClose();
}

/// Whether the kernel can switch TLS 1.3 sending keys (kTLS rekey).
fn kernelRekeySupported() bool {
    const linux = std.os.linux;
    const l: sys.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    defer sys.close(l);
    var addr: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.bind(l, @ptrCast(&addr), len) != 0) return false;
    _ = linux.listen(l, 1);
    _ = linux.getsockname(l, @ptrCast(&addr), &len);
    const c: sys.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    defer sys.close(c);
    if (linux.connect(c, @ptrCast(&addr), len) != 0) return false;
    // TLS 1.3, AES-128-GCM, any key: iv, key, salt, sequence number.
    var info: [40]u8 = @splat(7);
    info[0..4].* = .{ 0x04, 0x03, 51, 0 };
    sys.ktls.enableTx(c, &info) catch return false;
    sys.ktls.rekeyTx(c, &info) catch return false;
    return true;
}

/// Whether this kernel has TLS (the tls module): attaching it to a
/// connected loopback socket works.
fn kernelTlsAvailable() bool {
    const linux = std.os.linux;
    const l: sys.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    defer sys.close(l);
    var addr: linux.sockaddr.in = .{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    var len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.bind(l, @ptrCast(&addr), len) != 0) return false;
    _ = linux.listen(l, 1);
    _ = linux.getsockname(l, @ptrCast(&addr), &len);
    const c: sys.fd_t = @intCast(linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0));
    defer sys.close(c);
    if (linux.connect(c, @ptrCast(&addr), len) != 0) return false;
    const rc = linux.setsockopt(c, linux.IPPROTO.TCP, linux.TCP.ULP, "tls", 3);
    return std.posix.errno(rc) == .SUCCESS;
}

test "tls: application data in the write with the client's Finished is answered" {
    try forEachBackend(testTlsFinishedWithData);
}

fn testTlsFinishedWithData(backend: Backend) !void {
    var cfg = tlsConfig();
    cfg.tls.?.alpn = &.{ "h2", "http/1.1" };
    const r = try Running.start(backend, cfg);
    defer r.stop();
    // HTTP/2 (ALPN): the preface, SETTINGS and a request.
    try expectFirstWriteAnswered(r.port, true);
    var buf: [4096]u8 = undefined;
    // HTTP/1.1: a request.
    {
        const t = try TlsAlpnClient.connect(r.port, "http/1.1");
        defer t.close();
        try t.send("GET /first HTTP/1.1\r\nHost: x\r\n\r\n");
        const got = try t.readUntil(&buf, "\r\n\r\nok");
        try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 "));
    }
    // A WebSocket upgrade and its first frame.
    {
        const t = try TlsAlpnClient.connect(r.port, null);
        defer t.close();
        var first: [512]u8 = undefined;
        var n = Client.upgrade_request.len;
        @memcpy(first[0..n], Client.upgrade_request);
        n += Client.wsFrame(first[n..], true, .text, "early").len;
        try t.send(first[0..n]);
        const got = try t.readUntil(&buf, "\x81\x05early");
        try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 101 "));
    }
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

// -- io_uring with receives through pooled buffers --------------------------

test "io_uring: receives fall back to pooled buffers while the ring is empty" {
    if (sys.is_linux) {
        const worker_uring = @import("./http/worker_uring.zig");
        if (!worker_uring.available()) return error.SkipZigTest;
        // Each receive gets ENOBUFS and goes into a buffer of the
        // connection's own, which the kernel writes until the completion:
        // nothing may release or move it meanwhile, while the connection
        // is driven by ticks, posts from other threads and writes.
        worker_uring.test_ring_buffers = 0;
        defer worker_uring.test_ring_buffers = null;
        try testIdleAcrossTicks(.io_uring);
        inline for (.{
            testKeepAlive,    testPipelinedBurst, testLater,        testUploads,   testLingering,
            testWebSocket,    testH2Streams,      testH2Exchanges,  testH2Uploads, testH2WebSocket,
            testTlsKeepAlive, testTlsUpload,      testTlsWebSocket,
        }) |f| try f(.io_uring);
        // Two buffers: one is borrowed, the next parked for want of room,
        // and the receive after them finds none.
        worker_uring.test_ring_buffers = 2;
        inline for (.{ testPipelinedBurst, testKeepAlive, testUploads, testUploadHold }) |f| try f(.io_uring);
    } else return error.SkipZigTest;
}

/// HTTP/1.1, HTTP/2 and WebSocket connections used, left idle across two
/// worker ticks (which drive every HTTP/2 connection), sent to from
/// another thread while idle (WebSocket), then used again.
fn testIdleAcrossTicks(backend: Backend) !void {
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var cfg = h2Config();
    cfg.keep_alive_timeout_s = 10;
    const r = try Running.start(backend, cfg);
    defer r.stop();
    const h2 = try H2Client.connect(r.port);
    defer h2.close();
    var w = try Client.connect(r.port);
    defer w.close();
    var h1 = try Client.connect(r.port);
    defer h1.close();
    var head: [4096]u8 = undefined;
    const body = try testing.allocator.alloc(u8, big_body_len);
    defer testing.allocator.free(body);
    for (0..2) |round| {
        var reply: H2Client.Reply = .{};
        defer reply.deinit();
        try h2.fetch(@intCast(2 * round + 1), "GET", "/h2", null, &reply);
        try testing.expectEqualStrings("ok", reply.body.items);
        if (round == 0) {
            try w.send(Client.upgrade_request);
            try w.readUpgrade();
        }
        try w.wsSend(true, .text, "echo");
        try w.expectWsText("echo");
        // Answered from another thread while the connection waits.
        try w.wsSend(true, .text, "async");
        try w.expectWsText("later");
        // A response written in pieces while the next receive waits.
        try h1.send("GET /big HTTP/1.1\r\nHost: x\r\n\r\n");
        var res = try h1.readResponse(&head, body);
        try testing.expect(std.mem.eql(u8, &big_body, body[0..res.body_len]));
        try h1.send("GET /h1 HTTP/1.1\r\nHost: x\r\n\r\n");
        res = try h1.readResponse(&head, body);
        try testing.expectEqualStrings("ok", body[0..res.body_len]);
        if (round == 0) sleepMs(2200);
    }
}

// -- HTTP/3 over UDP ------------------------------------------------------------

const quic_test_client = @import("./quic/test_client.zig");
const quic_conn = @import("./quic/conn.zig");
const h3frame = @import("./h3/frame.zig");
const qpack = @import("./h3/qpack.zig");
const quic_packet = @import("./quic/packet.zig");
const quic_udp = @import("./quic/udp.zig");

/// The QUIC test client on a connected UDP socket, reading each datagram's
/// ECN codepoint as the server does.
const H3Client = struct {
    fd: sys.fd_t,
    c: *quic_test_client.Client,
    batch: *quic_udp.RecvBatch(8, 2048),
    /// Datagrams to the server wait this long (a path with a round trip
    /// of at least this), in `queue`.
    delay_ns: u64 = 0,
    queue: std.ArrayList(Delayed) = .empty,

    const Delayed = struct { due: u64, len: usize, buf: [1500]u8 };

    fn connect(port: u16) !H3Client {
        return connectTo(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } });
    }

    fn connectTo(address: std.Io.net.IpAddress) !H3Client {
        const nonblock: u32 = if (sys.is_linux) std.os.linux.SOCK.NONBLOCK else 0;
        const family: u32 = if (address == .ip6) posix.AF.INET6 else posix.AF.INET;
        const rc = system.socket(family, posix.SOCK.DGRAM | nonblock, posix.IPPROTO.UDP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
        const fd: sys.fd_t = @intCast(rc);
        errdefer sys.close(fd);
        const addr: quic_udp.Addr = .fromIp(address);
        if (posix.errno(system.connect(fd, addr.sockaddr(), addr.len)) != .SUCCESS) return error.ConnectFailed;
        if (!sys.is_linux) try sys.setNonBlocking(fd);
        sys.setsockoptInt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, 8 << 20) catch {};
        var dcid: [8]u8 = undefined;
        sys.randomBytes(&dcid);
        const c = try quic_test_client.Client.init(testing.allocator, .{ .dcid = dcid, .max_stream_data = 16 << 20, .max_data = 64 << 20 });
        errdefer c.deinit();
        return .{ .fd = fd, .c = c, .batch = try testing.allocator.create(quic_udp.RecvBatch(8, 2048)) };
    }

    fn close(self: *H3Client) void {
        self.queue.deinit(testing.allocator);
        self.c.deinit();
        testing.allocator.destroy(self.batch);
        sys.close(self.fd);
    }

    /// Reads the codepoint of what arrives, and sends with `ecn`.
    fn enableEcn(self: *H3Client, ecn: quic_packet.Ecn) !void {
        quic_udp.enableEcn(self.fd, false);
        try self.setEcn(ecn);
    }

    fn setEcn(self: *H3Client, ecn: quic_packet.Ecn) !void {
        try sys.setsockoptInt(self.fd, posix.IPPROTO.IP, posix.IP.TOS, @backingInt(ecn));
    }

    /// Exchanges datagrams until `done` holds or `ms` pass.
    fn runUntil(self: *H3Client, ms: u64, ctx: anytype, comptime done: fn (@TypeOf(ctx), *H3Client) bool) !void {
        const began = sys.nanoTimestamp();
        var buf: [65536]u8 = undefined;
        var quiet: u32 = 0;
        while (!done(ctx, self)) {
            if (sys.nanoTimestamp() - began > ms * std.time.ns_per_ms) return error.Timeout;
            while (true) {
                const n = try self.c.send(&buf);
                if (n == 0) break;
                if (self.delay_ns == 0) {
                    _ = sys.write(self.fd, buf[0..n]) catch {};
                } else {
                    try self.queue.append(testing.allocator, .{ .due = sys.nanoTimestamp() + self.delay_ns, .len = n, .buf = buf[0..1500].* });
                }
            }
            var due: usize = 0;
            while (due < self.queue.items.len and self.queue.items[due].due <= sys.nanoTimestamp()) : (due += 1) {
                const d = &self.queue.items[due];
                _ = sys.write(self.fd, d.buf[0..d.len]) catch {};
            }
            self.queue.replaceRangeAssumeCapacity(0, due, &.{});
            var got = false;
            while (true) {
                const n = self.batch.recv(self.fd);
                for (0..n) |i| {
                    const d = self.batch.get(i);
                    try self.c.recvEcn(d.data, d.ecn);
                }
                if (n == 0) break;
                got = true;
            }
            if (!got) {
                quiet += 1;
                // No loss on loopback in practice; resend now and then anyway.
                if (quiet % 200 == 0) try self.c.retransmit();
                sleepMs(1);
            } else quiet = 0;
        }
    }

    fn start(self: *H3Client) !void {
        try self.runUntil(5000, {}, struct {
            fn f(_: void, h: *H3Client) bool {
                return h.c.handshake_done;
            }
        }.f);
        const control = try self.c.openUni();
        try self.c.write(control, &.{ 0x00, 0x04, 0x00 }, false);
    }

    fn request(self: *H3Client, method: []const u8, path: []const u8, body: []const u8) !u64 {
        const id = try self.c.openBidi();
        var section: [512]u8 = undefined;
        var n: usize = 2;
        @memcpy(section[0..2], &qpack.section_prefix);
        for ([_][2][]const u8{ .{ ":method", method }, .{ ":scheme", "https" }, .{ ":authority", "localhost" }, .{ ":path", path } }) |f|
            n += try qpack.encodeField(section[n..], f[0], f[1]);
        var hdr: [16]u8 = undefined;
        var w: quic_packet.Writer = .{ .buf = &hdr };
        h3frame.writeHeader(&w, .headers, n);
        try self.c.write(id, w.written(), false);
        try self.c.write(id, section[0..n], body.len == 0);
        if (body.len > 0) {
            w = .{ .buf = &hdr };
            h3frame.writeHeader(&w, .data, body.len);
            try self.c.write(id, w.written(), false);
            try self.c.write(id, body, true);
        }
        return id;
    }

    /// An extended CONNECT for a WebSocket (RFC 9220).
    fn connectWs(self: *H3Client, path: []const u8) !u64 {
        const id = try self.c.openBidi();
        var section: [512]u8 = undefined;
        var n: usize = 2;
        @memcpy(section[0..2], &qpack.section_prefix);
        for ([_][2][]const u8{ .{ ":method", "CONNECT" }, .{ ":protocol", "websocket" }, .{ ":scheme", "https" }, .{ ":authority", "localhost" }, .{ ":path", path }, .{ "sec-websocket-version", "13" } }) |f|
            n += try qpack.encodeField(section[n..], f[0], f[1]);
        var hdr: [16]u8 = undefined;
        var w: quic_packet.Writer = .{ .buf = &hdr };
        h3frame.writeHeader(&w, .headers, n);
        try self.c.write(id, w.written(), false);
        try self.c.write(id, section[0..n], false);
        return id;
    }

    /// One masked WebSocket frame in a DATA frame.
    fn wsSend(self: *H3Client, id: u64, op: ws.Opcode, payload: []const u8, fin: bool) !void {
        const wire = try testing.allocator.alloc(u8, payload.len + ws.protocol.max_header_len);
        defer testing.allocator.free(wire);
        const f = ws.protocol.encodeFrame(wire, true, op, payload, .{ 0x11, 0x22, 0x33, 0x44 });
        var hdr: [16]u8 = undefined;
        var w: quic_packet.Writer = .{ .buf = &hdr };
        h3frame.writeHeader(&w, .data, f.len);
        try self.c.write(id, w.written(), false);
        try self.c.write(id, f, fin);
    }

    /// Drives the connection until stream `id` has `len` bytes of DATA.
    fn waitBody(self: *H3Client, id: u64, len: usize) !void {
        try self.runUntil(10_000, .{ id, len }, struct {
            fn f(want: struct { u64, usize }, h: *H3Client) bool {
                var r = h.response(want[0]) catch return false;
                defer r.body.deinit(testing.allocator);
                return r.body.items.len >= want[1];
            }
        }.f);
    }

    fn waitFinished(self: *H3Client, ids: []const u64) !void {
        try self.runUntil(10_000, ids, struct {
            fn f(list: []const u64, h: *H3Client) bool {
                for (list) |id| if (!h.c.finished(id)) return false;
                return true;
            }
        }.f);
    }

    const Resp = struct { status: [3]u8 = @splat('?'), body: std.ArrayList(u8) = .empty, trailers: usize = 0, alt_svc: bool = false };

    fn response(self: *H3Client, id: u64) !Resp {
        var r: Resp = .{};
        // waitBody polls while frames are still arriving: a DATA frame
        // read whole, then one cut short, must not leak the first.
        errdefer r.body.deinit(testing.allocator);
        var data = self.c.readAll(id);
        var dec = try qpack.Decoder.init(testing.allocator, .{});
        defer dec.deinit();
        var seen_headers = false;
        while (data.len > 0) {
            const fh = h3frame.parseHeader(data) orelse return error.Truncated;
            // A frame still arriving (waitBody tries again).
            if (data.len < fh.size + fh.len) return error.Truncated;
            const payload = data[fh.size..][0..@intCast(fh.len)];
            data = data[fh.size + payload.len ..];
            switch (fh.type) {
                .headers => {
                    const Sink = struct {
                        r: *Resp,
                        pub fn header(s: *@This(), name: []const u8, value: []const u8) !void {
                            if (std.mem.eql(u8, name, ":status")) s.r.status = value[0..3].*;
                            if (std.mem.eql(u8, name, "alt-svc") and std.mem.startsWith(u8, value, "h3=\":")) s.r.alt_svc = true;
                        }
                    };
                    var sink: Sink = .{ .r = &r };
                    try dec.decode(payload, &sink);
                    if (seen_headers) r.trailers += 1;
                    seen_headers = true;
                },
                .data => try r.body.appendSlice(testing.allocator, payload),
                else => {},
            }
        }
        return r;
    }
};

test "http3: pacing over a path with a 20 ms round trip" {
    try forEachBackend(testHttp3Pacing);
}

fn testHttp3Pacing(backend: Backend) !void {
    var cfg = tlsConfig();
    cfg.http3 = .{};
    const r = try Running.start(backend, cfg);
    defer r.stop();
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var cl = try H3Client.connect(r.srv.getQuicPort());
    defer cl.close();
    cl.delay_ns = 20 * std.time.ns_per_ms;
    try cl.start();
    // Process-wide, but tests run one at a time and each stops (joins) its
    // server before returning: only this test's server moves it now.
    const waits = quic_conn.test_paced_waits.load(.monotonic);
    const id = try cl.request("GET", "/big", "");
    // With the window spread over the round trip, the server waits for
    // its pacer between bursts, and its worker's timer resumes it: 8 MB
    // in under a second here, 15 s with only probe timeouts to resume it.
    try cl.runUntil(10_000, id, struct {
        fn f(want: u64, h: *H3Client) bool {
            return h.c.finished(want);
        }
    }.f);
    var a = try cl.response(id);
    defer a.body.deinit(testing.allocator);
    try testing.expectEqualStrings("200", &a.status);
    try testing.expect(std.mem.eql(u8, &big_body, a.body.items));
    try testing.expect(quic_conn.test_paced_waits.load(.monotonic) > waits);
}

test "http3: ECN marks go out and come back over UDP" {
    try forEachBackend(testHttp3Ecn);
}

fn testHttp3Ecn(backend: Backend) !void {
    var cfg = tlsConfig();
    cfg.http3 = .{};
    const r = try Running.start(backend, cfg);
    defer r.stop();
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var cl = try H3Client.connect(r.srv.getQuicPort());
    defer cl.close();
    try cl.enableEcn(.ect0);
    try cl.start();
    const id = try cl.request("GET", "/big", "");
    try cl.waitFinished(&.{id});
    var a = try cl.response(id);
    defer a.body.deinit(testing.allocator);
    try testing.expect(std.mem.eql(u8, &big_body, a.body.items));
    // The server marked its 1-RTT datagrams ECT(0) (GSO sends on Linux
    // included), the marks arrived, and our counts of them validated the
    // path: past its ten testing packets, it kept marking.
    const got = cl.c.datagrams_ecn;
    try testing.expect(got[@backingInt(quic_packet.Ecn.ect0)] > big_body.len / 1350 / 2);
    try testing.expectEqual(@as(u64, 0), got[@backingInt(quic_packet.Ecn.ect1)] + got[@backingInt(quic_packet.Ecn.ce)]);
    // Ours arrived marked too: the server counted them in its ACKs.
    const counts = cl.c.spaces[2].peer_ecn.?;
    try testing.expect(counts[0] > 0 and counts[1] == 0 and counts[2] == 0);
    // A request marked CE is counted as such.
    try cl.setEcn(.ce);
    const hello = try cl.request("GET", "/hello", "");
    try cl.waitFinished(&.{hello});
    try cl.setEcn(.ect0);
    try testing.expect(cl.c.spaces[2].peer_ecn.?[2] > 0);
}

test "http3: streamed uploads, a held body resumed from another thread" {
    try forEachBackend(testHttp3Uploads);
}

fn testHttp3Uploads(backend: Backend) !void {
    var cfg = tlsConfig();
    cfg.http3 = .{};
    cfg.limits.max_body_size = 64 * 1024;
    const r = try Running.start(backend, cfg);
    defer r.stop();
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var cl = try H3Client.connect(r.srv.getQuicPort());
    defer cl.close();
    try cl.start();
    const body = big_body[0 .. 3 * 1024 * 1024];
    const up = try cl.request("POST", "/upload", body);
    const held = try cl.request("POST", "/upload-hold", big_body[0 .. 2 * 1024 * 1024]);
    // Drive the client until the handler holds the second upload.
    try cl.runUntil(10_000, r.srv.handler, struct {
        fn f(h: *TestHandler, _: *H3Client) bool {
            h.uploads_mutex.lock();
            defer h.uploads_mutex.unlock();
            return h.held != null;
        }
    }.f);
    try r.srv.handler.resumeHeld();
    try cl.waitFinished(&.{ up, held });
    // One session ticket after the handshake (RFC 8446 §4.6.1).
    try testing.expectEqual(@as(u32, 1), cl.c.tickets);
    var expected: [64]u8 = undefined;
    var a = try cl.response(up);
    defer a.body.deinit(testing.allocator);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "n={d} hash={x}", .{ body.len, fnv(body) }), a.body.items);
    var b = try cl.response(held);
    defer b.body.deinit(testing.allocator);
    const body2 = big_body[0 .. 2 * 1024 * 1024];
    try testing.expectEqualStrings(try std.fmt.bufPrint(&expected, "n={d} hash={x}", .{ body2.len, fnv(body2) }), b.body.items);
}

test "http3: WebSockets over HTTP/3 (RFC 9220) beside requests on one connection" {
    try forEachBackend(testHttp3WebSocket);
}

fn testHttp3WebSocket(backend: Backend) !void {
    var cfg = tlsConfig();
    cfg.http3 = .{};
    const r = try Running.start(backend, cfg);
    defer r.stop();
    var cl = try H3Client.connect(r.srv.getQuicPort());
    defer cl.close();
    try cl.start();
    const big = try testing.allocator.alloc(u8, 100 * 1024);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 13);
    const one = try cl.connectWs("/ws");
    const two = try cl.connectWs("/ws");
    try cl.wsSend(one, .text, "hello one", false);
    try cl.wsSend(two, .binary, big, false);
    const get = try cl.request("GET", "/plain", "");
    try cl.wsSend(one, .text, "async", false);
    var fb: [64]u8 = undefined;
    var expect1: std.ArrayList(u8) = .empty;
    defer expect1.deinit(testing.allocator);
    try expect1.appendSlice(testing.allocator, wsServerFrame(&fb, .text, "hello one"));
    try expect1.appendSlice(testing.allocator, wsServerFrame(&fb, .text, "later"));
    try cl.waitBody(one, expect1.items.len);
    try cl.waitBody(two, big.len + 10);
    try cl.waitFinished(&.{get});
    {
        var a = try cl.response(one);
        defer a.body.deinit(testing.allocator);
        try testing.expectEqualStrings("200", &a.status);
        try testing.expectEqualSlices(u8, expect1.items, a.body.items);
        var b = try cl.response(two);
        defer b.body.deinit(testing.allocator);
        try testing.expectEqualSlices(u8, &.{ 0x82, 0x7f }, b.body.items[0..2]);
        try testing.expectEqualSlices(u8, big, b.body.items[10..]);
        var g = try cl.response(get);
        defer g.body.deinit(testing.allocator);
        try testing.expectEqualStrings("ok", g.body.items);
    }
    try testing.expectEqual(@as(usize, 2), r.srv.handler.ws_conns.load(.monotonic));
    // The client closes the first (echo, FIN); the server closes the
    // second, and our close with FIN ends it.
    try cl.wsSend(one, .close, "\x03\xe8", false);
    try cl.wsSend(two, .text, "close-me", false);
    try cl.waitFinished(&.{one});
    try cl.waitBody(two, big.len + 10 + 7);
    try cl.wsSend(two, .close, "\x03\xe8", true);
    try cl.waitFinished(&.{two});
    {
        var a = try cl.response(one);
        defer a.body.deinit(testing.allocator);
        try testing.expect(std.mem.endsWith(u8, a.body.items, "\x88\x02\x03\xe8"));
        var b = try cl.response(two);
        defer b.body.deinit(testing.allocator);
        try testing.expect(std.mem.endsWith(u8, b.body.items, "\x88\x05\x03\xe8bye"));
    }
    sleepMs(20);
    try testing.expectEqual(@as(usize, 2), r.srv.handler.ws_disconns.load(.monotonic));
    try testing.expectEqual(@as(u16, 1000), r.srv.handler.close_code.load(.monotonic));
}

test "http3: requests over UDP, large bodies, exchanges from other threads" {
    try forEachBackend(testHttp3);
}

fn testHttp3(backend: Backend) !void {
    var cfg = tlsConfig();
    cfg.http3 = .{};
    const r = try Running.start(backend, cfg);
    defer r.stop();
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    var cl = try H3Client.connect(r.srv.getQuicPort());
    defer cl.close();
    try cl.start();
    const hello = try cl.request("GET", "/hello", "");
    const big = try cl.request("GET", "/big", "");
    const later = try cl.request("GET", "/later", "");
    const streamed = try cl.request("GET", "/stream", "");
    const echo = try cl.request("POST", "/echo", "an upload body");
    try cl.waitFinished(&.{ hello, big, later, streamed, echo });

    var a = try cl.response(hello);
    defer a.body.deinit(testing.allocator);
    try testing.expectEqualStrings("200", &a.status);
    try testing.expectEqualStrings("ok", a.body.items);
    // Every response advertises HTTP/3 (Alt-Svc).
    try testing.expect(a.alt_svc);
    var b = try cl.response(big);
    defer b.body.deinit(testing.allocator);
    try testing.expectEqual(big_body.len, b.body.items.len);
    try testing.expect(std.mem.eql(u8, &big_body, b.body.items));
    var c = try cl.response(later);
    defer c.body.deinit(testing.allocator);
    try testing.expectEqualStrings("202", &c.status);
    try testing.expect(c.body.items.len > 0);
    var d = try cl.response(streamed);
    defer d.body.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 6 + 200 * 1024 + 6), d.body.items.len);
    try testing.expectEqual(@as(usize, 1), d.trailers);
    var e = try cl.response(echo);
    defer e.body.deinit(testing.allocator);
    try testing.expectEqualStrings("an upload body", e.body.items);
}

test "verify ECN: HTTP/3 on an IPv6 address: IPv6 clients, and IPv4 ones through a dual-stack socket" {
    try forEachBackend(testHttp3EcnIpv6);
}

/// A connected UDP socket to the server's QUIC port over IPv6 (::1), or
/// IPv4 (127.0.0.1).
fn h3ClientAt(port: u16, v6: bool) !H3Client {
    if (!v6) return H3Client.connect(port);
    var a: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = std.mem.zeroes([16]u8), .port = port } };
    a.ip6.bytes[15] = 1;
    return H3Client.connectTo(a);
}

fn testHttp3EcnIpv6(backend: Backend) !void {
    // A system without IPv6 loopback (some containers): nothing to test.
    {
        var probe: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = std.mem.zeroes([16]u8), .port = 0 } };
        probe.ip6.bytes[15] = 1;
        const fd = quic_udp.bind(probe, false) catch return error.SkipZigTest;
        sys.close(fd);
    }
    var cfg = tlsConfig();
    cfg.http3 = .{};
    cfg.backend = backend;
    cfg.ip = "::";
    cfg.handle_signals = false;
    cfg.worker_thread_count = 2;
    cfg.max_connections_per_worker = 256;
    cfg.buffer_pool_size = 4;
    const srv = try Server(TestHandler).init(testing.allocator, 0, cfg);
    const thread = try std.Thread.spawn(.{}, Running.runServer, .{srv});
    const r: Running = .{ .srv = srv, .thread = thread, .port = srv.getPort() };
    defer r.stop();
    for (&big_body, 0..) |*b, i| b.* = @truncate(i *% 31);
    for ([_]bool{ true, false }) |v6| {
        var cl = try h3ClientAt(r.srv.getQuicPort(), v6);
        defer cl.close();
        if (v6) {
            quic_udp.enableEcn(cl.fd, true);
            try sys.setsockoptInt(cl.fd, posix.IPPROTO.IPV6, posix.IPV6.TCLASS, @backingInt(quic_packet.Ecn.ect0));
        } else try cl.enableEcn(.ect0);
        try cl.start();
        const id = try cl.request("GET", "/big", "");
        try cl.waitFinished(&.{id});
        var a = try cl.response(id);
        defer a.body.deinit(testing.allocator);
        try testing.expect(std.mem.eql(u8, &big_body, a.body.items));
        const got = cl.c.datagrams_ecn;
        std.debug.print("{s}: datagrams not-ECT/ECT(1)/ECT(0)/CE {any}, server's counts {any}\n", .{ if (v6) "IPv6" else "IPv4-mapped", got, cl.c.spaces[2].peer_ecn });
        try testing.expect(got[@backingInt(quic_packet.Ecn.ect0)] > big_body.len / 1350 / 2);
        const counts = cl.c.spaces[2].peer_ecn.?;
        try testing.expect(counts[0] > 0 and counts[1] == 0 and counts[2] == 0);
    }
}
