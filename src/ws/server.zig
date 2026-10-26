const std = @import("std");
const sys = @import("../sys.zig");
const Poller = @import("../poller.zig").Poller;
const WebsocketReader = @import("./reader.zig").WebsocketReader;
const Frame = @import("./frame.zig").Frame;

const WAKER_TOKEN: u64 = std.math.maxInt(u64);

pub fn WebsocketServer(comptime Handler: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        handler: *Handler,
        poller: Poller,
        waker: sys.Waker,
        thread: ?std.Thread,
        reader: *WebsocketReader,
        frame: *Frame,
        shutdown: std.atomic.Value(bool),

        pub fn init(allocator: std.mem.Allocator, handler: *Handler, buffer_size: usize) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            const reader = try WebsocketReader.init(allocator, buffer_size);
            errdefer reader.deinit();
            const frame = try Frame.init(allocator, buffer_size);
            errdefer frame.deinit();
            var poller = try Poller.init();
            errdefer poller.deinit();
            const waker = try sys.Waker.init();
            errdefer waker.deinit();
            self.* = .{
                .allocator = allocator,
                .handler = handler,
                .poller = poller,
                .waker = waker,
                .thread = null,
                .reader = reader,
                .frame = frame,
                .shutdown = std.atomic.Value(bool).init(false),
            };
            try self.poller.add(waker.read_fd, WAKER_TOKEN, .level_read);
            // Spawn last: the thread reads every field above.
            if (@hasDecl(Handler, "handleWSFrame")) {
                self.thread = try std.Thread.spawn(.{}, loop, .{self});
            }
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.shutdown.store(true, .release);
            self.waker.wake();
            if (self.thread) |t| t.join();
            self.reader.deinit();
            self.frame.deinit();
            self.poller.deinit();
            self.waker.deinit();
            self.allocator.destroy(self);
        }

        /// Called by HTTP workers after a successful upgrade.
        pub fn addSocket(self: *Self, fd: sys.fd_t) !void {
            if (!@hasDecl(Handler, "handleWSFrame")) return error.HandlerDoesNotImplement_handleWSFrame;
            if (@hasDecl(Handler, "handleWSConn")) self.handler.handleWSConn(fd);
            // Level-triggered: the reader handles one frame per event.
            try self.poller.add(fd, @intCast(fd), .level_read);
        }

        fn loop(self: *Self) void {
            var events: [256]Poller.Event = undefined;
            while (!self.shutdown.load(.acquire)) {
                const ready_count = self.poller.wait(&events, -1);
                for (events[0..ready_count]) |event| {
                    const token = Poller.token(event);
                    if (token == WAKER_TOKEN) continue;
                    const socket: sys.fd_t = @intCast(token);
                    self.handleEvent(socket) catch {
                        self.poller.remove(socket);
                        if (@hasDecl(Handler, "handleWSDisconn")) {
                            self.handler.handleWSDisconn(socket);
                        }
                        sys.close(socket);
                    };
                }
            }
        }

        fn handleEvent(self: *Self, fd: sys.fd_t) !void {
            try self.reader.readFrame(fd, self.frame);
            self.handler.handleWSFrame(fd, self.frame);
        }
    };
}
