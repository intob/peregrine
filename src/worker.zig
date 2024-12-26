const os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const request = @import("./request.zig");
const Response = @import("./response.zig").Response;
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

pub const RequestHandler = *const fn (req: *request.Request, resp: *Response) void;

pub const Worker = struct {
    allocator: std.mem.Allocator,
    io_handler: IOHandler,
    id: usize,
    on_request: RequestHandler,
    mutex: std.Thread.Mutex,
    resp: *Response,
    resp_buf: []align(16) u8,
    req: *request.Request,
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

    pub fn init(self: *Self, allocator: std.mem.Allocator, id: usize, on_request: RequestHandler) !void {
        errdefer self.deinit();
        self.allocator = allocator;
        self.io_handler = try IOHandler.init();
        self.id = id;
        self.on_request = on_request;
        self.mutex = std.Thread.Mutex{};
        self.req = try request.Request.init(allocator);
        self.resp = try Response.init(allocator, 4096);
        self.resp_buf = try allocator.alignedAlloc(u8, 16, std.mem.alignForward(usize, 4096, 16));
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
        self.allocator.free(self.resp_buf);
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
        const reader = request.RequestReader.init(self.allocator, 4096) catch |err| {
            std.debug.print("error allocating reader: {any}\n", .{err});
            return;
        };
        defer reader.deinit();

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
                self.handleEvent(socket, reader) catch |err| {
                    std.debug.print("error handling event: {any}\n", .{err});
                };
            }
        }
    }

    fn handleEvent(self: *Self, socket: posix.socket_t, reader: *request.RequestReader) !void {
        defer posix.close(socket);
        self.req.reset();
        try reader.readRequest(socket, self.req);
        self.resp.reset();
        self.on_request(self.req, self.resp);
        if (!self.resp.hijacked) try self.respond(socket);
    }

    fn respond(self: *Self, socket: posix.socket_t) !void {
        const headers_len = try self.resp.serialiseHeaders(&self.resp_buf);
        if (self.resp.body_len > 0) {
            var iovecs = [_]posix.iovec_const{
                .{ .base = @ptrCast(self.resp_buf[0..headers_len]), .len = headers_len },
                .{ .base = @ptrCast(self.resp.body[0..self.resp.body_len]), .len = self.resp.body_len },
            };
            const written = try posix.writev(socket, &iovecs);
            if (written != headers_len + self.resp.body_len) {
                return error.WriteError;
            }
            return;
        }
        try writeAll(socket, self.resp_buf[0..headers_len]);
    }
};

pub fn writeAll(socket: posix.socket_t, payload: []u8) !void {
    var n: usize = 0;
    while (n < payload.len) {
        const written = posix.write(socket, payload[n..]) catch |err| {
            posix.close(socket);
            return err;
        };
        n += written;
    }
}

fn writeAllToBuffer(buf: *std.io.BufferedWriter(4096, std.fs.File.Writer), bytes: []const u8) !void {
    var n: usize = 0;
    while (n < bytes.len) {
        n += try buf.write(bytes[n..]);
    }
}

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
