const std = @import("std");
const posix = std.posix;
const request = @import("./request.zig");
const Response = @import("./response.zig").Response;
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;

pub const Worker = struct {
    id: usize,
    mutex: std.Thread.Mutex,
    kfd: posix.fd_t,
    allocator: std.mem.Allocator,
    resp: *Response,
    resp_buf: []u8,
    req: *request.Request,
    file: std.fs.File,
    file_buffer: *std.io.BufferedWriter(4096, std.fs.File.Writer),
    shutdown: std.atomic.Value(bool),
    shutdown_cond: std.Thread.Condition,
    shutdown_mutex: std.Thread.Mutex,
    shutdown_done: bool,
    thread: std.Thread,

    pub fn init(self: *Worker, allocator: std.mem.Allocator, id: usize) !void {
        self.id = id;
        self.mutex = std.Thread.Mutex{};
        self.kfd = try posix.kqueue();
        self.allocator = allocator;
        self.resp = try Response.init(self.allocator);
        self.resp_buf = try allocator.alloc(u8, 128);
        self.req = try allocator.create(request.Request);

        const filename = try std.fmt.allocPrint(allocator, "./logdata_{d}", .{self.id});
        defer allocator.free(filename);
        self.file = try std.fs.cwd().createFile(filename, .{ .truncate = false });
        self.file_buffer = try allocator.create(std.io.BufferedWriter(4096, std.fs.File.Writer));
        self.file_buffer.* = std.io.bufferedWriter(self.file.writer());
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
        self.file_buffer.flush() catch |err| {
            std.debug.print("error flushing buffer: {any}\n", .{err});
        };
        self.allocator.destroy(self.file_buffer);
        self.file.close();
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
        try self.handleRequest(socket);
    }

    fn handleRequest(self: *Worker, socket: posix.socket_t) !void {
        std.debug.print("kfd-{d} [{d}] got request: {any} {s}\n", .{
            self.kfd,
            socket,
            self.req.method,
            self.req.path_buf[0..self.req.path_len],
        });

        // Respond with Hello world
        //try resp.headers.append(Header{ .key = "Connection", .value = "close" });
        self.resp.status = Status.ok;
        self.resp.headers.clearRetainingCapacity();
        try self.resp.headers.append(Header{ .key = "Content-Length", .value = "11" });
        self.resp.body = "Hello world";
        const n = try self.resp.serialise(&self.resp_buf);
        _ = try writeAll(socket, self.resp_buf[0..n]);
    }
};

fn writeAllToBuffer(buf: *std.io.BufferedWriter(4096, std.fs.File.Writer), bytes: []const u8) !void {
    var n: usize = 0;
    while (n < bytes.len) {
        n += try buf.write(bytes[n..]);
    }
}

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
