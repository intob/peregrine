const os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const RequestReader = @import("./reader.zig").RequestReader;
const Request = @import("./request.zig").Request;
const Response = @import("./response.zig").Response;
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

pub const RequestHandler = *const fn (req: *Request, resp: *Response) void;

// Extra CRLF to terminate headers
const KEEP_ALIVE_HEADERS = "Connection: keep-alive\r\nKeep-Alive: timeout=10, max=100\r\n\r\n";
const CLOSE_HEADER = "Connection: close\r\n\r\n";

pub const WorkerConfig = struct {
    allocator: std.mem.Allocator,
    id: usize,
    on_request: RequestHandler,
};

pub const Worker = struct {
    allocator: std.mem.Allocator,
    io_handler: IOHandler,
    id: usize,
    on_request: RequestHandler,
    mutex: std.Thread.Mutex,
    req: *Request,
    resp: *Response,
    resp_header_buf: []align(16) u8,
    iovecs: std.ArrayList(posix.iovec_const),
    shutdown: std.atomic.Value(bool),
    shutdown_cond: std.Thread.Condition,
    shutdown_mutex: std.Thread.Mutex,
    shutdown_done: bool,
    thread: std.Thread,

    const IOHandler = switch (os) {
        .freebsd, .netbsd, .openbsd, .dragonfly, .macos => KqueueHandler,
        .linux => EpollHandler,
        else => @compileError("Unsupported OS"),
    };

    const Self = @This();

    pub fn init(self: *Self, cfg: WorkerConfig) !void {
        const allocator = cfg.allocator;
        errdefer self.deinit();
        self.allocator = allocator;
        self.io_handler = try IOHandler.init();
        self.id = cfg.id;
        self.on_request = cfg.on_request;
        self.mutex = std.Thread.Mutex{};
        self.req = try Request.init(allocator);
        // TODO: make body buffer size configurable
        self.resp = try Response.init(allocator, 4096); // Aligned internally
        // Up to 32 headers, each  with [64]u8 key and [256]u8 value, plus ": " and "\n"
        const max_header_size = ((64 + 256 + 3) * 32) + "HTTP/1.1 500 Internal Server Error\n".len;
        const aligned_header_size = std.mem.alignForward(usize, max_header_size, 16);
        self.resp_header_buf = try allocator.alignedAlloc(u8, 16, aligned_header_size);
        self.iovecs = std.ArrayList(posix.iovec_const).init(self.allocator);
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
        self.mutex.lock();
        defer self.mutex.unlock();
        self.req.deinit();
        self.resp.deinit();
        self.allocator.free(self.resp_header_buf);
        self.iovecs.deinit();
        self.thread.join();
        std.debug.print("worker-{d} shutdown\n", .{self.id});
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

        const EventType = switch (os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.Kevent,
            .linux => linux.epoll_event,
            else => unreachable,
        };

        var events: [128]EventType = undefined;
        // TODO: make request reader buffer size configurable
        // Buffer is aligned internally
        const reader = RequestReader.init(self.allocator, 4096) catch |err| {
            std.debug.print("error allocating reader: {any}\n", .{err});
            return;
        };
        defer reader.deinit();

        var connection_requests = std.AutoHashMap(posix.socket_t, u32).init(self.allocator);
        defer connection_requests.deinit();

        while (!self.shutdown.load(.acquire)) {
            const timeout = switch (os) {
                .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.timespec{ .sec = 0, .nsec = 50_000_000 },
                .linux => 50, // 50ms timeout
                else => unreachable,
            };

            const ready_count = switch (os) {
                .freebsd, .netbsd, .openbsd, .dragonfly, .macos => self.io_handler.wait(&events, &timeout),
                .linux => self.io_handler.wait(&events, timeout),
                else => unreachable,
            } catch |err| {
                std.debug.print("event wait error: {}\n", .{err});
                continue;
            };

            for (events[0..ready_count]) |event| {
                const socket: i32 = switch (os) {
                    .freebsd, .netbsd, .openbsd, .dragonfly, .macos => @intCast(event.udata),
                    .linux => event.data.fd,
                    else => unreachable,
                };
                const requests_handled = connection_requests.get(socket) orelse 0;
                if (requests_handled >= 100) {
                    posix.close(socket);
                    _ = connection_requests.remove(socket);
                    continue;
                }
                self.handleEvent(socket, reader) catch {};
                //std.debug.print("error handling event: {any}\n", .{err});
                connection_requests.put(socket, requests_handled + 1) catch |err| {
                    std.debug.print("error updating socket request count: {any}\n", .{err});
                };
            }
        }
    }

    fn handleEvent(self: *Self, socket: posix.socket_t, reader: *RequestReader) !void {
        const keep_alive = self.shouldKeepAlive();
        defer {
            if (!keep_alive) {
                posix.close(socket);
            }
        }
        self.req.reset();
        try reader.readRequest(socket, self.req);
        self.resp.reset();
        self.on_request(self.req, self.resp);
        if (!self.resp.hijacked) {
            try self.respond(socket, keep_alive);
        }
    }

    fn shouldKeepAlive(self: *Self) bool {
        if (self.req.version == .@"HTTP/1.1") {
            if (self.req.getHeader("Connection")) |connection| {
                return !std.mem.eql(u8, connection, "close");
            }
            return true; // HTTP/1.1 defaults to keep-alive
        }
        return false; // HTTP/1.0
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

const KqueueHandler = struct {
    kfd: i32,

    pub fn init() !@This() {
        const kfd = try posix.kqueue();
        return .{ .kfd = kfd };
    }

    pub fn addSocket(self: *@This(), socket: posix.socket_t) !void {
        const event = posix.Kevent{
            .ident = @intCast(socket),
            .filter = posix.system.EVFILT.READ,
            .flags = posix.system.EV.ADD,
            .fflags = 0,
            .data = 0,
            .udata = @intCast(socket),
        };
        _ = try posix.kevent(self.kfd, &[_]posix.Kevent{event}, &.{}, null);
    }

    pub fn wait(self: *@This(), events: []posix.Kevent, timeout: ?*const posix.timespec) !usize {
        return try posix.kevent(self.kfd, &.{}, events, timeout);
    }

    pub fn deinit(self: *@This()) void {
        posix.close(self.kfd);
    }
};

const EpollHandler = struct {
    epfd: i32,

    pub fn init() !@This() {
        const epfd = try posix.epoll_create1(0);
        return .{ .epfd = epfd };
    }

    pub fn addSocket(self: *@This(), socket: posix.socket_t) !void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .fd = socket },
        };
        try posix.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, socket, &event);
    }

    pub fn wait(self: *@This(), events: []linux.epoll_event, timeout_ms: i32) !usize {
        return posix.epoll_wait(self.epfd, events, timeout_ms);
    }

    pub fn deinit(self: *@This()) void {
        posix.close(self.epfd);
    }
};
