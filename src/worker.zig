const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const aio = @import("./aio.zig");
const Header = @import("./header.zig").Header;
const Request = @import("./request.zig").Request;
const RequestReader = @import("./reader.zig").RequestReader;
const Response = @import("./response.zig").Response;
const Status = @import("./status.zig").Status;
const WebsocketServer = @import("./ws/server.zig").WebsocketServer;

const CONNECTION_MAX_REQUESTS: u8 = 200;
// This is added to a response that contains no body. This is more efficient than
// having the user provide the header to be serialised.
const CONTENT_LENGTH_ZERO_HEADER = "content-length: 0\r\n";
// These headers are added last, so they have an extra CRLF to terminate the headers.
// This is simpler and more efficient than appending \r\n separately.
// TODO: I think that adding an extra \r\n IOVEC after headers would be cleaner at this point.
const KEEP_ALIVE_HEADERS = "connection: keep-alive\r\nkeep-alive: timeout=3, max=200\r\n\r\n";
const CLOSE_HEADER = "connection: close\r\n\r\n";
const UPGRADE_HEADER = "connection: upgrade\r\n\r\n";

pub const WorkerConfig = struct {
    allocator: std.mem.Allocator,
    id: usize,
    resp_body_buffer_size: usize,
};

pub fn Worker(comptime Handler: type) type {
    return struct {
        const Self = @This();
        const EventType = switch (native_os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.Kevent,
            .linux => linux.epoll_event,
            else => unreachable,
        };
        const getFileDescriptor = blk: {
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

        allocator: std.mem.Allocator,
        io_handler: aio.IOHandler,
        id: usize,
        handler: *Handler,
        req: *Request,
        resp: *Response,
        resp_status_buf: []align(16) u8,
        reader: *RequestReader,
        iovecs: [4]posix.iovec_const,
        connection_requests: []u8,
        ws: *WebsocketServer(Handler),
        shutdown: std.atomic.Value(bool),
        thread: std.Thread,

        pub fn init(self: *Self, handler: *Handler, ws: *WebsocketServer(Handler), cfg: WorkerConfig) !void {
            const allocator = cfg.allocator;
            errdefer self.deinit();
            self.handler = handler;
            self.allocator = allocator;
            self.io_handler = try aio.IOHandler.init();
            self.id = cfg.id;
            self.req = try Request.init(allocator);
            self.resp = try Response.init(allocator, cfg.resp_body_buffer_size);
            const resp_status_size = try calcResponseStatusBufferSize(allocator);
            self.resp_status_buf = try allocator.alignedAlloc(u8, 16, resp_status_size);
            self.reader = try RequestReader.init(self.allocator, 50_000);
            self.connection_requests = try allocator.alloc(u8, std.math.maxInt(i16));
            self.ws = ws;
            self.shutdown = std.atomic.Value(bool).init(false);
            self.thread = try std.Thread.spawn(.{}, workerLoop, .{self});
        }

        pub fn deinit(self: *Self) void {
            self.shutdown.store(true, .monotonic);
            self.thread.join();
            self.reader.deinit();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.resp_status_buf);
            self.allocator.free(self.connection_requests);
            std.debug.print("worker-thread-{d} joined\n", .{self.id});
        }

        pub fn addClient(self: *Self, fd: posix.socket_t) !void {
            try self.io_handler.addSocket(fd);
        }

        fn workerLoop(self: *Self) void {
            var events: [256]EventType = undefined;
            while (!self.shutdown.load(.unordered)) {
                const ready_count = self.io_handler.wait(&events) catch |err| {
                    std.debug.print("error waiting for events: {any}\n", .{err});
                    continue;
                };
                for (events[0..ready_count]) |event| {
                    const fd: i32 = getFileDescriptor(event);
                    const fd_idx: usize = if (fd < 0) continue else @intCast(fd);
                    self.readSocket(fd) catch |err| {
                        posix.close(fd);
                        self.connection_requests[fd_idx] = 0;
                        switch (err) {
                            error.EOF => {}, // Expected case
                            else => std.debug.print("error reading socket: {any}\n", .{err}),
                        }
                        continue;
                    };
                    if (self.connection_requests[fd_idx] >= CONNECTION_MAX_REQUESTS) {
                        posix.close(fd);
                        self.connection_requests[fd_idx] = 0;
                    } else {
                        self.connection_requests[fd_idx] += 1;
                    }
                }
            }
        }

        fn readSocket(self: *Self, fd: posix.socket_t) !void {
            self.req.reset();
            try self.reader.readRequest(fd, self.req);
            self.resp.reset();
            self.handler.handleRequest(self.req, self.resp);
            const keep_alive = shouldKeepAlive(self.req);
            try self.respond(fd, keep_alive);
            if (self.resp.is_ws_upgrade) {
                self.connection_requests[@intCast(fd)] = 0;
                try self.io_handler.removeSocket(fd);
                try self.ws.addSocket(fd);
            }
            // Returning EOF causes the connection to be closed by the caller.
            if (!keep_alive) return error.EOF;
        }

        fn respond(self: *Self, fd: posix.socket_t, keep_alive: bool) !void {
            // Status line and user headers
            const status_len = try self.resp.serialiseStatusAndHeaders(&self.resp_status_buf);
            var total = status_len;
            self.iovecs[0] = .{
                .base = @ptrCast(self.resp_status_buf[0..status_len]),
                .len = status_len,
            };
            var iovecs_len: u2 = 1;
            // Set content-length header if zero
            if (self.resp.body_len == 0) {
                self.iovecs[1] = .{
                    .base = CONTENT_LENGTH_ZERO_HEADER,
                    .len = CONTENT_LENGTH_ZERO_HEADER.len,
                };
                iovecs_len += 1;
                total += CONTENT_LENGTH_ZERO_HEADER.len;
            }
            // Connection header
            if (self.resp.is_ws_upgrade) {
                self.iovecs[iovecs_len] = .{
                    .base = UPGRADE_HEADER,
                    .len = UPGRADE_HEADER.len,
                };
                total += UPGRADE_HEADER.len;
            } else {
                if (keep_alive) {
                    self.iovecs[iovecs_len] = .{
                        .base = KEEP_ALIVE_HEADERS,
                        .len = KEEP_ALIVE_HEADERS.len,
                    };
                    total += KEEP_ALIVE_HEADERS.len;
                } else {
                    self.iovecs[iovecs_len] = .{
                        .base = CLOSE_HEADER,
                        .len = CLOSE_HEADER.len,
                    };
                    total += CLOSE_HEADER.len;
                }
            }
            iovecs_len += 1;
            // Body
            if (self.resp.body_len > 0) {
                self.iovecs[iovecs_len] = .{
                    .base = @ptrCast(self.resp.body[0..self.resp.body_len]),
                    .len = self.resp.body_len,
                };
                iovecs_len += 1;
                total += self.resp.body_len;
            }
            // Write to socket
            const n = try posix.writev(fd, self.iovecs[0..iovecs_len]);
            if (n != total) {
                return error.PartialWrite;
            }
        }
    };
}

fn shouldKeepAlive(req: *Request) bool {
    if (req.version == .@"HTTP/1.1") {
        if (req.findHeader("connection")) |connection| {
            if (connection.len == "close".len and
                connection[0] == 'c' and
                connection[1] == 'l') return false;
        }
        return true; // HTTP/1.1 defaults to keep-alive
    }
    return false; // HTTP/1.0
}

// Calculate response status and header buffer size.
fn calcResponseStatusBufferSize(allocator: std.mem.Allocator) !usize {
    const h = Header{};
    const resp = try Response.init(allocator, 0);
    defer resp.deinit();
    const headers_size = (h.key_buf.len + h.value_buf.len + 4) * resp.headers.len;
    const resp_buf_size = headers_size + "HTTP/1.1 500 Internal Server Error\r\n".len;
    return std.mem.alignForward(usize, resp_buf_size, 16);
}

test "keep alive" {
    const allocator = std.testing.allocator;
    const req = try Request.init(allocator);
    defer req.deinit();
    const resp = try Response.init(allocator, 1024);
    defer resp.deinit();
    // HTTP/1.1 default is true
    req.version = .@"HTTP/1.1";
    try std.testing.expectEqual(true, shouldKeepAlive(req));
    // HTTP/1.1 default is false
    req.version = .@"HTTP/1.0";
    try std.testing.expectEqual(false, shouldKeepAlive(req));
    // HTTP/1.1 client closed connection
    req.headers[0] = try Header.init("Connection", "close");
    req.headers_len = 1;
    req.version = .@"HTTP/1.1";
    try std.testing.expectEqual(false, shouldKeepAlive(req));
}
