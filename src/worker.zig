const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Header = @import("./header.zig").Header;
const Request = @import("./request.zig").Request;
const RequestReader = @import("./reader.zig").RequestReader;
const Response = @import("./response.zig").Response;
const Status = @import("./status.zig").Status;

// Extra CRLF to terminate headers
const CONNECTION_MAX_REQUESTS: u32 = 200;
const KEEP_ALIVE_HEADERS = "Connection: keep-alive\r\nKeep-Alive: timeout=3, max=200\r\n\r\n";
const CLOSE_HEADER = "Connection: close\r\n\r\n";

pub const WorkerConfig = struct {
    allocator: std.mem.Allocator,
    id: usize,
};

pub fn Worker(comptime Handler: type) type {
    return struct {
        allocator: std.mem.Allocator,
        io_handler: IOHandler,
        id: usize,
        handler: *Handler,
        req: *Request,
        resp: *Response,
        resp_header_buf: []align(16) u8,
        iovecs: std.ArrayList(posix.iovec_const),
        connection_requests: std.AutoHashMap(posix.socket_t, u32),
        shutdown: std.atomic.Value(bool),
        shutdown_cond: std.Thread.Condition,
        shutdown_mutex: std.Thread.Mutex,
        shutdown_done: bool,
        thread: std.Thread,

        const IOHandler = switch (native_os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => KqueueHandler,
            .linux => EpollHandler,
            else => @compileError("Unsupported OS"),
        };

        const Self = @This();

        pub fn init(self: *Self, cfg: WorkerConfig) !void {
            const allocator = cfg.allocator;
            errdefer self.deinit();
            self.handler = try Handler.init(allocator);
            self.allocator = allocator;
            self.io_handler = try IOHandler.init();
            self.id = cfg.id;
            self.req = try Request.init(allocator);
            // TODO: make body buffer size configurable
            self.resp = try Response.init(allocator, 4096); // Aligned internally
            // Up to 32 headers, each  with [64]u8 key and [256]u8 value, plus ": " and "\n"
            const max_header_size = ((64 + 256 + 3) * 32) + "HTTP/1.1 500 Internal Server Error\n".len;
            const aligned_header_size = std.mem.alignForward(usize, max_header_size, 16);
            self.resp_header_buf = try allocator.alignedAlloc(u8, 16, aligned_header_size);
            self.iovecs = std.ArrayList(posix.iovec_const).init(allocator);
            self.connection_requests = std.AutoHashMap(posix.socket_t, u32).init(allocator);
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
            self.handler.deinit();
            self.req.deinit();
            self.resp.deinit();
            self.allocator.free(self.resp_header_buf);
            self.iovecs.deinit();
            self.connection_requests.deinit();
            std.debug.print("worker-thread-{d} joined\n", .{self.id});
        }

        pub fn addClient(self: *Self, socket: posix.socket_t) !void {
            try self.io_handler.addSocket(socket);
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
                    const socket: i32 = switch (native_os) {
                        .freebsd, .netbsd, .openbsd, .dragonfly, .macos => @intCast(event.udata),
                        .linux => event.data.fd,
                        else => unreachable,
                    };
                    self.readSocket(socket, reader) catch |err| {
                        posix.close(socket);
                        _ = self.connection_requests.remove(socket);
                        switch (err) {
                            error.EOF => {}, // Expected case
                            else => std.debug.print("error reading socket: {any}\n", .{err}),
                        }
                        continue;
                    };
                    const requests_handled = self.connection_requests.get(socket) orelse 0;
                    if (requests_handled >= CONNECTION_MAX_REQUESTS) {
                        posix.close(socket);
                        _ = self.connection_requests.remove(socket);
                    } else {
                        self.connection_requests.put(socket, requests_handled + 1) catch |err| {
                            std.debug.print("error updating socket request count: {any}\n", .{err});
                        };
                    }
                }
            }
        }

        fn readSocket(self: *Self, socket: posix.socket_t, reader: *RequestReader) !void {
            var keep_alive = false;
            // Is this correct? What if we have read part of the next request?
            // The advantage is that this is faster than compacting the buffer.
            reader.reset();
            self.req.reset();
            try reader.readRequest(socket, self.req);
            keep_alive = shouldKeepAlive(self.req);
            self.resp.reset();
            self.handler.handle(self.req, self.resp);
            if (!self.resp.hijacked) {
                try self.respond(socket, keep_alive);
                // Returning EOF causes the connection to be closed by the caller.
                if (!keep_alive) return error.EOF;
            }
        }

        fn respond(self: *Self, socket: posix.socket_t, keep_alive: bool) !void {
            const headers_len = try self.resp.serialiseHeaders(&self.resp_header_buf);
            self.iovecs.clearRetainingCapacity();
            try self.iovecs.appendSlice(&.{
                .{
                    .base = @ptrCast(self.resp_header_buf[0..headers_len]),
                    .len = headers_len,
                },
                .{
                    .base = if (keep_alive) KEEP_ALIVE_HEADERS else CLOSE_HEADER,
                    .len = if (keep_alive) KEEP_ALIVE_HEADERS.len else CLOSE_HEADER.len,
                },
            });
            if (self.resp.body_len > 0) {
                try self.iovecs.append(.{
                    .base = @ptrCast(self.resp.body[0..self.resp.body_len]),
                    .len = self.resp.body_len,
                });
            }
            const total_len = headers_len +
                (if (keep_alive) KEEP_ALIVE_HEADERS.len else CLOSE_HEADER.len) +
                self.resp.body_len;
            const written = try posix.writev(socket, self.iovecs.items);
            if (written != total_len) {
                return error.WriteError;
            }
        }
    };
}

fn shouldKeepAlive(req: *Request) bool {
    if (req.version == .@"HTTP/1.1") {
        if (req.getHeader("Connection")) |connection| {
            return !std.mem.eql(u8, connection, "close");
        }
        return true; // HTTP/1.1 defaults to keep-alive
    }
    return false; // HTTP/1.0
}

const KqueueHandler = struct {
    kfd: i32,
    timeout: posix.timespec,

    const Self = @This();

    pub fn init() !Self {
        return .{
            .kfd = try posix.kqueue(),
            .timeout = posix.timespec{ .sec = 0, .nsec = 50_000_000 },
        };
    }

    pub fn addSocket(self: *Self, socket: posix.socket_t) !void {
        const event = posix.Kevent{
            .ident = @intCast(socket),
            .filter = posix.system.EVFILT.READ,
            .flags = posix.system.EV.ADD | posix.system.EV.CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = @intCast(socket),
        };
        _ = try posix.kevent(self.kfd, &[_]posix.Kevent{event}, &.{}, null);
    }

    pub fn wait(self: *Self, events: []posix.Kevent) !usize {
        return try posix.kevent(self.kfd, &.{}, events, &self.timeout);
    }

    pub fn deinit(self: *Self) void {
        posix.close(self.kfd);
    }
};

const EpollHandler = struct {
    epfd: i32,

    const Self = @This();

    pub fn init() !Self {
        const epfd = try posix.epoll_create1(0);
        return .{ .epfd = epfd };
    }

    pub fn addSocket(self: *Self, socket: posix.socket_t) !void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.IN | linux.EPOLL.ET,
            .data = .{ .fd = socket },
        };
        try posix.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, socket, &event);
    }

    pub fn wait(self: *Self, events: []linux.epoll_event) !usize {
        return posix.epoll_wait(self.epfd, events, 50); // 50ms timeout
    }

    pub fn deinit(self: *Self) void {
        posix.close(self.epfd);
    }
};

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
    req.headers[0] = try Header.init(.{ .key = "Connection", .value = "close" });
    req.headers_len = 1;
    req.version = .@"HTTP/1.1";
    try std.testing.expectEqual(false, shouldKeepAlive(req));
}
