const std = @import("std");
const posix = std.posix;
const request = @import("./request.zig");
const Response = @import("./response.zig").Response;
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

pub const RequestHandler = *const fn (req: *request.Request, resp: *Response) void;

pub const Worker = struct {
    id: usize,
    on_request: RequestHandler,
    mutex: std.Thread.Mutex,
    kfd: posix.fd_t,
    allocator: std.mem.Allocator,
    resp: *Response,
    resp_buf: []align(16) u8,
    req: *request.Request,
    shutdown: std.atomic.Value(bool),
    shutdown_cond: std.Thread.Condition,
    shutdown_mutex: std.Thread.Mutex,
    shutdown_done: bool,
    thread: std.Thread,

    pub fn init(self: *Worker, allocator: std.mem.Allocator, id: usize, on_request: RequestHandler) !void {
        errdefer self.deinit();
        self.id = id;
        self.on_request = on_request;
        self.mutex = std.Thread.Mutex{};
        self.kfd = try posix.kqueue();
        self.allocator = allocator;
        self.resp = try Response.init(allocator, 4096);
        self.resp_buf = try allocator.alignedAlloc(u8, 16, std.mem.alignForward(usize, 4096, 16));
        self.req = try allocator.create(request.Request);
        self.shutdown = std.atomic.Value(bool).init(false);
        self.shutdown_cond = std.Thread.Condition{};
        self.shutdown_mutex = std.Thread.Mutex{};
        self.thread = try std.Thread.spawn(.{}, workerLoop, .{self});
    }

    pub fn deinit(self: *Worker) void {
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
        posix.close(self.kfd);
        self.resp.deinit();
        self.allocator.destroy(self.req);
        self.allocator.free(self.resp_buf);
        self.thread.join();
        std.debug.print("w-{d} shutdown complete\n", .{self.id});
    }

    fn workerLoop(self: *Worker) void {
        defer {
            self.shutdown_mutex.lock();
            defer self.shutdown_mutex.unlock();
            self.shutdown_done = true;
            self.shutdown_cond.signal();
        }
        var ready_list: [128]posix.Kevent = undefined;
        const timeout = self.allocator.create(posix.timespec) catch |err| {
            std.debug.print("error allocating timeout: {any}\n", .{err});
            return;
        };
        defer self.allocator.destroy(timeout);
        timeout.* = .{ .sec = 0, .nsec = 50_000_000 };
        const reader = request.RequestReader.init(self.allocator, 64) catch |err| {
            std.debug.print("error allocating reader: {any}\n", .{err});
            return;
        };
        defer reader.deinit();
        while (true) {
            if (self.shutdown.load(.acquire)) break;
            const ready_count = posix.kevent(self.kfd, &.{}, &ready_list, timeout) catch |err| {
                std.debug.print("kevent error: {}\n", .{err});
                continue;
            };
            for (ready_list[0..ready_count]) |ready| {
                self.handleKevent(@intCast(ready.udata), reader) catch |err| {
                    std.debug.print("error handling event: {any}\n", .{err});
                };
            }
        }
    }

    fn handleKevent(self: *Worker, socket: posix.socket_t, reader: *request.RequestReader) !void {
        defer posix.close(socket);
        try reader.readRequest(socket, self.req);
        self.resp.reset();
        self.on_request(self.req, self.resp);
        try self.respond(socket);
    }

    fn respond(self: *Worker, socket: posix.socket_t) !void {
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

fn writeAll(socket: posix.socket_t, msg: []u8) !void {
    var n: usize = 0;
    while (n < msg.len) {
        const written = posix.write(socket, msg[n..]) catch |err| {
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
