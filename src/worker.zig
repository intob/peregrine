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
const FdMap = @import("./fdmap.zig").FdMap;

const CONNECTION_MAX_REQUESTS: u32 = 200;
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
        allocator: std.mem.Allocator,
        io_handler: aio.IOHandler,
        id: usize,
        handler: *Handler,
        req: *Request,
        resp: *Response,
        resp_status_buf: []align(16) u8,
        // TODO: Benchmark use of fixed size array for iovecs.
        // As for headers, it could be much faster than ArrayList.
        iovecs: [3]posix.iovec_const,
        connection_requests: *FdMap,
        ws: *WebsocketServer(Handler),
        shutdown: std.atomic.Value(bool),
        thread: std.Thread,

        const Self = @This();

        pub fn init(self: *Self, handler: *Handler, ws: *WebsocketServer(Handler), cfg: WorkerConfig) !void {
            const allocator = cfg.allocator;
            errdefer self.deinit();
            self.handler = handler;
            self.allocator = allocator;
            self.io_handler = try aio.IOHandler.init();
            self.id = cfg.id;
            self.req = try Request.init(allocator);
            // TODO: make body buffer size configurable
            self.resp = try Response.init(allocator, cfg.resp_body_buffer_size); // Aligned internally
            self.resp_status_buf = try allocator.alignedAlloc(u8, 16, try calcResponseStatusBufferSize(allocator));
            self.connection_requests = try FdMap.init(allocator, 1_000_000);
            self.ws = ws;
            self.shutdown = std.atomic.Value(bool).init(false);
            self.thread = try std.Thread.spawn(.{}, workerLoop, .{self});
        }

        pub fn deinit(self: *Self) void {
            self.shutdown.store(true, .monotonic);
            self.thread.join();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.resp_status_buf);
            self.connection_requests.deinit();
            std.debug.print("worker-thread-{d} joined\n", .{self.id});
        }

        pub fn addClient(self: *Self, fd: posix.socket_t) !void {
            try self.io_handler.addSocket(fd);
        }

        fn workerLoop(self: *Self) void {
            const EventType = switch (native_os) {
                .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.Kevent,
                .linux => linux.epoll_event,
                else => unreachable,
            };
            var events: [256]EventType = undefined;
            // TODO: make request reader buffer size configurable
            // Buffer is aligned internally
            const reader = RequestReader.init(self.allocator, 4096) catch |err| {
                std.debug.print("error allocating reader: {any}\n", .{err});
                return;
            };
            defer reader.deinit();
            while (!self.shutdown.load(.unordered)) {
                const ready_count = self.io_handler.wait(&events) catch |err| {
                    std.debug.print("error waiting for events: {any}\n", .{err});
                    continue;
                };
                for (events[0..ready_count]) |event| {
                    const fd: i32 = switch (native_os) {
                        .freebsd, .netbsd, .openbsd, .dragonfly, .macos => @intCast(event.udata),
                        .linux => event.data.fd,
                        else => unreachable,
                    };
                    self.readSocket(fd, reader) catch |err| {
                        self.closeSocket(fd);
                        switch (err) {
                            error.EOF => {}, // Expected case
                            else => std.debug.print("error reading socket: {any}\n", .{err}),
                        }
                        continue;
                    };
                    const requests_handled = self.connection_requests.get(fd) orelse 0;
                    if (requests_handled >= CONNECTION_MAX_REQUESTS) {
                        self.closeSocket(fd);
                    } else {
                        self.connection_requests.put(fd, requests_handled + 1) catch |err| {
                            std.debug.print("error updating socket request count: {any}\n", .{err});
                        };
                    }
                }
            }
        }

        fn closeSocket(self: *Self, fd: posix.socket_t) void {
            posix.close(fd);
            _ = self.connection_requests.remove(fd);
        }

        fn readSocket(self: *Self, fd: posix.socket_t, reader: *RequestReader) !void {
            var keep_alive = false;
            // Is this correct? What if we have read part of the next request?
            // The advantage is that this is faster than compacting the buffer.
            reader.reset();
            self.req.reset();
            try reader.readRequest(fd, self.req);
            keep_alive = shouldKeepAlive(self.req);
            self.resp.reset();
            self.handler.handleRequest(self.req, self.resp);
            try self.respond(fd, keep_alive);
            // TODO: Think about how to make this nice for the user.
            // Currently, they have to handle the upgrade by calling the upgrade handler.
            // This requirement makes the protocol explicit, not doing magic behind the
            // scenes. Also, if a user does not want to support websockets, they simply
            // don't implement the upgrade handler.
            if (self.resp.is_ws_upgrade) {
                // Transfer socket to WS event bus
                std.debug.print("transfer socket {d} to ws server\n", .{fd});
                _ = self.connection_requests.remove(fd);
                try self.io_handler.removeSocket(fd);
                try self.ws.addSocket(fd);
            }
            // Returning EOF causes the connection to be closed by the caller.
            if (!keep_alive) return error.EOF;
        }

        fn respond(self: *Self, fd: posix.socket_t, keep_alive: bool) !void {
            // Status line and user headers
            const status_len = try self.resp.serialiseStatusAndHeaders(&self.resp_status_buf);
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
            }
            // Connection header
            if (self.resp.is_ws_upgrade) {
                self.iovecs[iovecs_len] = .{
                    .base = UPGRADE_HEADER,
                    .len = UPGRADE_HEADER.len,
                };
            } else {
                self.iovecs[iovecs_len] = .{
                    .base = if (keep_alive) KEEP_ALIVE_HEADERS else CLOSE_HEADER,
                    .len = if (keep_alive) KEEP_ALIVE_HEADERS.len else CLOSE_HEADER.len,
                };
            }
            iovecs_len += 1;
            // Body
            if (self.resp.body_len > 0) {
                self.iovecs[iovecs_len] = .{
                    .base = @ptrCast(self.resp.body[0..self.resp.body_len]),
                    .len = self.resp.body_len,
                };
                iovecs_len += 1;
            }
            // Write to socket
            _ = try posix.writev(fd, self.iovecs[0..iovecs_len]);
        }
    };
}

fn shouldKeepAlive(req: *Request) bool {
    if (req.version == .@"HTTP/1.1") {
        if (req.findHeader("connection")) |connection| {
            return !std.mem.eql(u8, connection, "close");
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
