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

const CONNECTION_MAX_REQUESTS: u16 = 65535;
// This is added to a response that contains no body. This is more efficient than
// having the user provide the header to be serialised.
const CONTENT_LENGTH_ZERO_HEADER = "content-length: 0\r\n";
// These headers are added last, so they have an extra CRLF to terminate the headers.
// This is simpler and more efficient than appending \r\n separately.
// TODO: I think that adding an extra \r\n IOVEC after headers would be cleaner at this point.
const KEEP_ALIVE_HEADERS = "connection: keep-alive\r\nkeep-alive: timeout=10, max=65535\r\n\r\n";
const CLOSE_HEADER = "connection: close\r\n\r\n";
const UPGRADE_HEADER = "connection: upgrade\r\n\r\n";

pub fn Worker(comptime Handler: type) type {
    return struct {
        const Self = @This();
        const EventType = switch (native_os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.Kevent,
            .linux => linux.epoll_event,
            else => unreachable,
        };
        const WorkerConfig = struct {
            allocator: std.mem.Allocator,
            id: usize,
            resp_body_buffer_size: usize,
            req_buffer_size: usize,
            stack_size: usize,
            handler: *Handler,
            ws: *WebsocketServer(Handler),
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

        allocator: std.mem.Allocator,
        handler: *Handler,
        io_handler: aio.IOHandler,
        id: usize,
        req: *Request,
        resp: *Response,
        resp_status_buf: []align(64) u8,
        reader: *RequestReader,
        iovecs: [4]posix.iovec_const,
        connection_requests: []u16,
        ws: *WebsocketServer(Handler),
        shutdown: std.atomic.Value(bool),
        thread: std.Thread,

        pub fn init(self: *Self, cfg: WorkerConfig) !void {
            const allocator = cfg.allocator;
            self.allocator = allocator;
            self.handler = cfg.handler;
            self.io_handler = try aio.IOHandler.init();
            self.id = cfg.id;
            self.req = try Request.init(allocator);
            self.resp = try Response.init(allocator, cfg.resp_body_buffer_size);
            const resp_status_size = try calcResponseStatusBufferSize(allocator);
            self.resp_status_buf = try allocator.alignedAlloc(u8, 64, resp_status_size);
            self.reader = try RequestReader.init(self.allocator, cfg.req_buffer_size);
            self.connection_requests = try allocator.alloc(u16, std.math.maxInt(i16));
            self.ws = cfg.ws;
            self.shutdown = std.atomic.Value(bool).init(false);
            self.thread = try std.Thread.spawn(.{
                .stack_size = cfg.stack_size,
                .allocator = allocator,
            }, workerLoop, .{self});
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
            // server frees worker
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
                    const fd: i32 = getFd(event);
                    const fd_idx: usize = @intCast(fd);
                    self.readSocket(fd, fd_idx) catch |err| {
                        posix.close(fd);
                        self.connection_requests[fd_idx] = 0;
                        switch (err) {
                            error.DoNotKeepAlive => {}, // Expected case
                            else => std.debug.print("error reading socket: {any}\n", .{err}),
                        }
                        continue;
                    };
                }
            }
        }

        inline fn readSocket(self: *Self, fd: posix.socket_t, fd_idx: usize) !void {
            var keep_alive: bool = undefined;
            if (self.connection_requests[fd_idx] >= CONNECTION_MAX_REQUESTS - 1) {
                keep_alive = false;
            } else {
                self.connection_requests[fd_idx] += 1;
                keep_alive = self.req.version == .@"HTTP/1.1" and self.req.keep_alive;
            }
            self.req.reset();
            try self.reader.readRequest(fd, self.req);
            self.resp.reset();
            self.handler.handleRequest(self.req, self.resp);
            try self.respond(fd, keep_alive);
            if (self.resp.is_ws_upgrade) {
                self.connection_requests[@intCast(fd)] = 0;
                try self.io_handler.removeSocket(fd);
                try self.ws.addSocket(fd);
            }
            if (!keep_alive) return error.DoNotKeepAlive;
        }

        inline fn respond(self: *Self, fd: posix.socket_t, keep_alive: bool) !void {
            const status_len = try self.resp.serialiseStatusAndHeaders(self.resp_status_buf);
            var total = status_len;
            self.iovecs[0] = .{
                .base = @ptrCast(self.resp_status_buf[0..status_len]),
                .len = status_len,
            };
            var iovecs_len: u8 = 1;
            if (self.resp.body_len == 0) {
                self.iovecs[1] = .{
                    .base = CONTENT_LENGTH_ZERO_HEADER,
                    .len = CONTENT_LENGTH_ZERO_HEADER.len,
                };
                iovecs_len += 1;
                total += CONTENT_LENGTH_ZERO_HEADER.len;
            }
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

fn calcResponseStatusBufferSize(allocator: std.mem.Allocator) !usize {
    const h = Header{};
    const resp = try Response.init(allocator, 1024);
    defer resp.deinit();
    const headers_size = (h.key_buf.len + h.value_buf.len + 4) * resp.headers.len;
    const resp_buf_size = headers_size + "HTTP/1.1 500 Internal Server Error\r\n".len;
    return std.mem.alignForward(usize, resp_buf_size, 16);
}
