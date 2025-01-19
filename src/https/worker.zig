const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Poller = @import("../poller.zig").Poller;
const Header = @import("../header.zig").Header;
const Request = @import("../request.zig").Request;
const TLSReader = @import("./reader.zig").TLSReader;
const Response = @import("../response.zig").Response;
const Status = @import("../status.zig").Status;
const WebsocketServer = @import("../ws/server.zig").WebsocketServer;

const CONNECTION_MAX_REQUESTS: u16 = 65535;
// This is added to a response that contains no body. This is more efficient than
// having the user provide the header to be serialised.
const CONTENT_LENGTH_ZERO_HEADER = "content-length: 0\r\n";
// These headers are added last, so they have an extra CRLF to terminate the headers.
// This is simpler and more efficient than appending \r\n separately.
const KEEP_ALIVE_HEADERS = "connection: keep-alive\r\nkeep-alive: timeout=3, max=65535\r\n\r\n";
const CLOSE_HEADER = "connection: close\r\n\r\n";
const UPGRADE_HEADER = "connection: upgrade\r\n\r\n";

const CommonIovecs = struct {
    const content_len_zero: posix.iovec_const align(64) = .{
        .base = CONTENT_LENGTH_ZERO_HEADER,
        .len = CONTENT_LENGTH_ZERO_HEADER.len,
    };
    const keep_alive: posix.iovec_const align(64) = .{
        .base = KEEP_ALIVE_HEADERS,
        .len = KEEP_ALIVE_HEADERS.len,
    };
    const close: posix.iovec_const align(64) = .{
        .base = CLOSE_HEADER,
        .len = CLOSE_HEADER.len,
    };
    const upgrade: posix.iovec_const align(64) = .{
        .base = UPGRADE_HEADER,
        .len = UPGRADE_HEADER.len,
    };
};

pub fn TLSWorker(comptime Handler: type) type {
    return struct {
        const Self = @This();
        const EventType = switch (native_os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.Kevent,
            .linux => linux.epoll_event,
            else => unreachable,
        };
        const WorkerConfig = struct {
            allocator: std.mem.Allocator,
            resp_body_buffer_size: usize,
            req_buffer_size: usize,
            stack_size: usize,
            handler: *Handler,
            ws: *WebsocketServer(Handler),
            cert_filename: []const u8,
            key_filename: []const u8,
        };
        const getFd = blk: {
            break :blk switch (native_os) {
                .freebsd, .netbsd, .openbsd, .dragonfly, .macos => struct {
                    fn get(event: posix.Kevent) i32 {
                        return @intCast(event.udata);
                    }
                }.get,
                .linux => struct {
                    fn get(event: linux.epoll_event) i32 {
                        return event.data.fd;
                    }
                }.get,
                else => unreachable,
            };
        };
        const ConnectionState = enum {
            ClientHello,
            Goodbye,
        };
        const Connection = struct {
            state: ConnectionState,
            requests: u16,
            client_random: [32]u8,

            pub fn reset(self: *Connection) void {
                self.state = .ClientHello;
                self.requests = 0;
            }
        };

        shutdown: std.atomic.Value(bool) align(64),
        connections: []Connection align(64),
        handler: *Handler,
        poller: Poller,
        reader: *TLSReader,
        req: *Request,
        resp: *Response,
        iovecs: [4]posix.iovec_const align(64),
        ws: *WebsocketServer(Handler),
        thread: std.Thread,
        allocator: std.mem.Allocator,

        pub fn init(self: *Self, cfg: WorkerConfig) !void {
            const allocator = cfg.allocator;
            self.allocator = allocator;
            self.handler = cfg.handler;
            self.poller = try Poller.init();
            self.req = try Request.init(allocator);
            self.resp = try Response.init(allocator, cfg.resp_body_buffer_size);
            self.reader = try TLSReader.init(self.allocator, cfg.req_buffer_size);
            self.connections = try allocator.alignedAlloc(Connection, 64, std.math.maxInt(i16));
            self.ws = cfg.ws;
            self.shutdown = std.atomic.Value(bool).init(false);
            self.thread = try std.Thread.spawn(.{
                .stack_size = cfg.stack_size,
                .allocator = allocator,
            }, workerLoop, .{self});
            std.debug.print("{s}, {s}\n", .{ cfg.cert_filename, cfg.key_filename });
        }

        pub fn deinit(self: *Self) void {
            self.shutdown.store(true, .monotonic);
            self.thread.join();
            self.reader.deinit();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.connections);
            // server frees worker
        }

        pub fn addClient(self: *Self, fd: posix.socket_t) !void {
            try self.poller.addSocket(fd);
        }

        fn workerLoop(self: *Self) void {
            var events: [1024]EventType align(64) = undefined;
            var ready_count: usize align(64) = 0;
            var fd: i32 align(64) = 0;
            var conn: *Connection = undefined;
            while (!self.shutdown.load(.unordered)) {
                ready_count = self.poller.wait(&events) catch |err| {
                    std.debug.print("error waiting for events: {any}\n", .{err});
                    continue;
                };
                for (events[0..ready_count]) |event| {
                    fd = getFd(event);
                    conn = &self.connections[@intCast(fd)];
                    self.readSocket(conn, fd) catch |err| {
                        posix.close(fd);
                        conn.reset();
                        switch (err) {
                            error.DoNotKeepAlive => {}, // Expected case
                            else => std.debug.print("error reading socket: {any}\n", .{err}),
                        }
                        continue;
                    };
                }
            }
        }

        inline fn readSocket(self: *Self, conn: *Connection, fd: posix.socket_t) !void {
            switch (conn.state) {
                .ClientHello => try self.readClientHello(conn, fd),
                else => std.debug.print("I'm a teapot\n", .{}),
            }

            var keep_alive: bool = undefined;
            if (conn.requests >= CONNECTION_MAX_REQUESTS - 1) {
                keep_alive = false;
            } else {
                conn.requests += 1;
                keep_alive = self.req.version == .@"HTTP/1.1" or self.req.keep_alive;
            }
            self.req.reset();
            self.reader.reset();
            //try self.reader.readRequest(fd, self.req);
            self.resp.reset();
            self.handler.handleRequest(self.req, self.resp);
            try self.respond(fd, keep_alive);
            if (self.resp.is_ws_upgrade) {
                conn.reset();
                try self.poller.removeSocket(fd);
                try self.ws.addSocket(fd);
            }
            if (!keep_alive and !self.resp.is_ws_upgrade) return error.DoNotKeepAlive;
        }

        pub fn readClientHello(self: *Self, conn: *Connection, fd: posix.socket_t) !void {
            // Read client random data
            const record_header = try self.reader.read(fd, 5);
            if (record_header[0] != 0x16) {
                std.debug.print("expected 0x16 got 0x{x}\n", .{record_header[0]});
                return error.ExpectedHandshakeRecord;
            }
            if (record_header[1] != 0x03 and record_header[2] != 0x04) {
                return error.IncompatibleTLSVersion;
            }
            const record_len = std.mem.readInt(u16, record_header[3..5], .big);
            const handshake = try self.reader.read(fd, @intCast(record_len));
            if (handshake[0] != 0x01) {
                return error.ExpectedClientHello;
            }
            const handshake_len = std.mem.readInt(u24, handshake[1..4], .big);
            std.debug.print("Handshake length: {}\n", .{handshake_len});
            // Discard client version (2 bytes)
            @memcpy(conn.client_random[0..], handshake[6 .. 6 + 32]);
            var i: usize = 6 + 32;
            // Discard session ID
            const session_id_len = handshake[i];
            i += 1 + session_id_len;
            // Read cipher suites
            const cipher_suites_len = std.mem.readInt(u16, handshake[i .. i + 2][0..2], .big);
            i += 2;
            //const cipher_suites = handshake[i .. i + cipher_suites_len];
            i += cipher_suites_len;
            // Discard compression methods (2 bytes)
            i += 2;
            const extensions_len = std.mem.readInt(u16, handshake[i .. i + 2][0..2], .big);
            i += 2;
            //const extensions = try self.reader.read(fd, @intCast(extensions_len));
            // TODO: parse extensions
            i += extensions_len;
        }

        inline fn respond(self: *Self, fd: posix.socket_t, keep_alive: bool) !void {
            const status_len = try self.resp.serialiseStatusAndHeaders();
            self.iovecs[0] = .{
                .base = @ptrCast(self.resp.status_buf[0..status_len]),
                .len = status_len,
            };
            var total = status_len;
            var iovecs_len: u8 = 1;
            if (self.resp.body_len == 0) {
                self.iovecs[1] = CommonIovecs.content_len_zero;
                iovecs_len += 1;
                total += CONTENT_LENGTH_ZERO_HEADER.len;
            }
            if (self.resp.is_ws_upgrade) {
                self.iovecs[iovecs_len] = CommonIovecs.upgrade;
                total += UPGRADE_HEADER.len;
            } else {
                if (keep_alive) {
                    self.iovecs[iovecs_len] = CommonIovecs.keep_alive;
                    total += KEEP_ALIVE_HEADERS.len;
                } else {
                    self.iovecs[iovecs_len] = CommonIovecs.close;
                    total += CLOSE_HEADER.len;
                }
            }
            iovecs_len += 1;
            if (self.resp.body_len > 0) {
                self.iovecs[iovecs_len] = .{
                    .base = @ptrCast(self.resp.body[0..self.resp.body_len]),
                    .len = self.resp.body_len,
                };
                iovecs_len += 1;
                total += self.resp.body_len;
            }
            const n = try posix.writev(fd, self.iovecs[0..iovecs_len]);
            if (n != total) {
                return error.PartialWrite;
            }
        }
    };
}
