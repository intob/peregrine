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
};

pub fn Worker(comptime Handler: type) type {
    return struct {
        allocator: std.mem.Allocator,
        io_handler: aio.IOHandler,
        id: usize,
        handler: *Handler,
        req: *Request,
        resp: *Response,
        resp_header_buf: []align(16) u8,
        // TODO: Benchmark use of fixed size array for iovecs.
        // As for headers, it could be much faster than ArrayList.
        iovecs: std.ArrayList(posix.iovec_const),
        connection_requests: std.AutoHashMap(posix.socket_t, u32),
        ws: *WebsocketServer(Handler),
        shutdown: std.atomic.Value(bool),
        shutdown_cond: std.Thread.Condition,
        shutdown_mutex: std.Thread.Mutex,
        shutdown_done: bool,
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
            self.resp = try Response.init(allocator, 200_000); // Aligned internally
            // Up to 32 headers, each  with [64]u8 key and [256]u8 value, plus ": " and "\n"
            const max_header_size = ((64 + 256 + 3) * 32) + "HTTP/1.1 500 Internal Server Error\n".len;
            const aligned_header_size = std.mem.alignForward(usize, max_header_size, 16);
            self.resp_header_buf = try allocator.alignedAlloc(u8, 16, aligned_header_size);
            self.iovecs = std.ArrayList(posix.iovec_const).init(allocator);
            self.connection_requests = std.AutoHashMap(posix.socket_t, u32).init(allocator);
            self.ws = ws;
            self.shutdown = std.atomic.Value(bool).init(false);
            self.shutdown_cond = std.Thread.Condition{};
            self.shutdown_mutex = std.Thread.Mutex{};
            self.thread = try std.Thread.spawn(.{}, workerLoop, .{self});
        }

        pub fn deinit(self: *Self) void {
            self.shutdown.store(true, .release);
            {
                self.shutdown_mutex.lock();
                defer self.shutdown_mutex.unlock();
                while (!self.shutdown_done) {
                    self.shutdown_cond.wait(&self.shutdown_mutex);
                }
            }
            self.thread.join(); // Finish handling any requests
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.resp_header_buf);
            self.iovecs.deinit();
            self.connection_requests.deinit();
            std.debug.print("worker-thread-{d} joined\n", .{self.id});
        }

        pub fn addClient(self: *Self, fd: posix.socket_t) !void {
            try self.io_handler.addSocket(fd);
        }

        fn workerLoop(self: *Self) void {
            defer {
                self.shutdown_mutex.lock();
                defer self.shutdown_mutex.unlock();
                self.shutdown_done = true;
                self.shutdown_cond.signal();
            }
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
            while (!self.shutdown.load(.acquire)) {
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
            self.iovecs.clearRetainingCapacity();
            // Status line and user headers
            const status_len = try self.resp.serialiseStatusAndHeaders(&self.resp_header_buf);
            try self.iovecs.append(.{
                .base = @ptrCast(self.resp_header_buf[0..status_len]),
                .len = status_len,
            });
            // Set content-length header if zero
            if (self.resp.body_len == 0) {
                try self.iovecs.append(.{
                    .base = CONTENT_LENGTH_ZERO_HEADER,
                    .len = CONTENT_LENGTH_ZERO_HEADER.len,
                });
            }
            // Connection header
            if (self.resp.is_ws_upgrade) {
                try self.iovecs.append(.{
                    .base = UPGRADE_HEADER,
                    .len = UPGRADE_HEADER.len,
                });
            } else {
                try self.iovecs.append(.{
                    .base = if (keep_alive) KEEP_ALIVE_HEADERS else CLOSE_HEADER,
                    .len = if (keep_alive) KEEP_ALIVE_HEADERS.len else CLOSE_HEADER.len,
                });
            }
            // Body
            if (self.resp.body_len > 0) {
                try self.iovecs.append(.{
                    .base = @ptrCast(self.resp.body[0..self.resp.body_len]),
                    .len = self.resp.body_len,
                });
            }
            // Write to socket
            // Maybe remove this length calculation, as it's unnecessary overhead...
            var total_len = status_len + (if (self.resp.body_len == 0) CONTENT_LENGTH_ZERO_HEADER.len else 0);
            if (self.resp.is_ws_upgrade) {
                total_len += UPGRADE_HEADER.len;
            } else {
                total_len += if (keep_alive) KEEP_ALIVE_HEADERS.len else CLOSE_HEADER.len;
                total_len += self.resp.body_len;
            }
            const written = try posix.writev(fd, self.iovecs.items);
            if (written != total_len) {
                return error.WriteError;
            }
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
