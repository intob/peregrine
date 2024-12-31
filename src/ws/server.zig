const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const aio = @import("../aio.zig");
const WebsocketReader = @import("./reader.zig").WebsocketReader;
const Frame = @import("./frame.zig").Frame;

pub fn WebsocketServer(comptime Handler: type) type {
    return struct {
        allocator: std.mem.Allocator,
        handler: *Handler,
        io_handler: aio.IOHandler,
        thread: std.Thread,
        reader: *WebsocketReader,
        frame: *Frame,

        pub fn init(allocator: std.mem.Allocator, handler: *Handler, buffer_size: usize) !*@This() {
            const self = try allocator.create(@This());
            self.* = .{
                .allocator = allocator,
                .handler = handler,
                .io_handler = try aio.IOHandler.init(),
                .thread = try std.Thread.spawn(.{}, loop, .{self}),
                .reader = try WebsocketReader.init(allocator, buffer_size),
                .frame = try Frame.init(allocator, buffer_size),
            };
            return self;
        }

        pub fn deinit(self: *@This()) void {
            self.reader.deinit();
            self.frame.deinit();
            self.allocator.destroy(self);
        }

        pub fn addSocket(self: *@This(), fd: posix.socket_t) !void {
            try self.io_handler.addSocket(fd);
            if (@hasDecl(Handler, "handleWSConn")) {
                self.handler.handleWSConn(fd);
            } else {
                return error.HandlerDoesNotImplement_handleWSConn;
            }
        }

        fn loop(self: *@This()) void {
            std.debug.print("ws loop started\n", .{});
            const EventType = switch (native_os) {
                .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.Kevent,
                .linux => linux.epoll_event,
                else => unreachable,
            };
            var events: [256]EventType = undefined;
            while (true) {
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
                    self.handleEvent(socket) catch |err| {
                        std.debug.print("error handling ws event: {any}\n", .{err});
                        self.io_handler.removeSocket(socket) catch |remove_err| {
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

        fn handleEvent(self: *@This(), fd: posix.socket_t) !void {
            try self.reader.readFrame(fd, self.frame);
            if (@hasDecl(Handler, "handleWSFrame")) {
                self.handler.handleWSFrame(fd, self.frame);
            } else {
                return error.HandlerDoesNotImplement_handleWSFrame;
            }
        }
    };
}
