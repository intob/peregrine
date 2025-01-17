const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Poller = @import("../poller.zig").Poller;
const WebsocketReader = @import("./reader.zig").WebsocketReader;
const Frame = @import("./frame.zig").Frame;

pub fn WebsocketServer(comptime Handler: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        handler: *Handler,
        poller: Poller,
        thread: std.Thread,
        reader: *WebsocketReader,
        frame: *Frame,
        shutdown: std.atomic.Value(bool),

        pub fn init(allocator: std.mem.Allocator, handler: *Handler, buffer_size: usize) !*Self {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .handler = handler,
                .poller = try Poller.init(),
                .thread = try std.Thread.spawn(.{}, loop, .{self}),
                .reader = try WebsocketReader.init(allocator, buffer_size),
                .frame = try Frame.init(allocator, buffer_size),
                .shutdown = std.atomic.Value(bool).init(false),
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.shutdown.store(true, .monotonic);
            self.thread.join();
            std.debug.print("websocket server shutdown\n", .{});
            self.reader.deinit();
            self.frame.deinit();
            self.allocator.destroy(self);
        }

        pub fn addSocket(self: *Self, fd: posix.socket_t) !void {
            try self.poller.addSocket(fd);
            if (@hasDecl(Handler, "handleWSConn")) {
                self.handler.handleWSConn(fd);
            } else {
                return error.HandlerDoesNotImplement_handleWSConn;
            }
        }

        fn loop(self: *Self) void {
            if (!@hasDecl(Handler, "handleWSFrame")) {
                std.debug.print("websocket loop joined (handler not implemented)\n", .{});
                return;
            }
            const EventType = switch (native_os) {
                .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.Kevent,
                .linux => linux.epoll_event,
                else => unreachable,
            };
            var events: [256]EventType = undefined;
            while (!self.shutdown.load(.unordered)) {
                const ready_count = self.poller.wait(&events) catch |err| {
                    std.debug.print("error waiting for events: {any}\n", .{err});
                    continue;
                };
                for (events[0..ready_count]) |event| {
                    const socket: i32 = switch (native_os) {
                        .freebsd, .netbsd, .openbsd, .dragonfly, .macos => @intCast(event.udata),
                        .linux => event.data.fd,
                        else => unreachable,
                    };
                    self.handleEvent(socket) catch |err| {
                        std.debug.print("error handling ws event: {any}\n", .{err});
                        self.poller.removeSocket(socket) catch |remove_err| {
                            std.debug.print("error removing socket: {any}\n", .{remove_err});
                        };
                        if (@hasDecl(Handler, "handleWSDisconn")) {
                            self.handler.handleWSDisconn(socket);
                        } else {
                            std.debug.print("handler does not implement handleWSDisconn\n", .{});
                        }
                    };
                }
            }
        }

        fn handleEvent(self: *Self, fd: posix.socket_t) !void {
            try self.reader.readFrame(fd, self.frame);
            if (@hasDecl(Handler, "handleWSFrame")) {
                self.handler.handleWSFrame(fd, self.frame);
            } else {
                return error.HandlerDoesNotImplement_handleWSFrame;
            }
        }
    };
}
