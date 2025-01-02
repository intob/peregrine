const std = @import("std");
const posix = std.posix;
const pereg = @import("peregrine");

const DIR = "./example/websocket/static";

const Handler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    counter: std.atomic.Value(usize),
    dirServer: *pereg.util.DirServer,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd_path);
        std.debug.print("cwd: {s}\n", .{cwd_path});
        const abs_path = try std.fs.path.join(allocator, &.{ cwd_path, DIR });
        defer allocator.free(abs_path);
        const handler = try allocator.create(Self);
        handler.* = .{
            .allocator = allocator,
            .counter = std.atomic.Value(usize).init(0),
            .dirServer = try pereg.util.DirServer.init(allocator, abs_path, .{}),
        };
        return handler;
    }

    pub fn deinit(self: *Self) void {
        self.dirServer.deinit();
        self.allocator.destroy(self);
    }

    pub fn handleRequest(self: *Self, req: *pereg.Request, resp: *pereg.Response) void {
        self.handleRequestWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleRequestWithError(self: *Self, req: *pereg.Request, resp: *pereg.Response) !void {
        if (std.mem.eql(u8, req.getPath(), "/ws")) {
            // Explicitly handle the upgrade to support websockets.
            try pereg.ws.upgrader.handleUpgrade(self.allocator, req, resp);
            return;
        }
        try self.dirServer.serve(req, resp);
    }

    pub fn handleWSConn(_: *Self, fd: posix.socket_t) void {
        std.debug.print("{d} handle ws conn...\n", .{fd});
    }

    pub fn handleWSDisconn(_: *Self, fd: posix.socket_t) void {
        std.debug.print("{d} handle ws disconn...\n", .{fd});
    }

    pub fn handleWSFrame(_: *Self, fd: posix.socket_t, frame: *pereg.ws.Frame) void {
        if (frame.opcode == pereg.ws.Opcode.close) {
            std.debug.print("{d} client closed websocket\n", .{fd});
            return;
        }
        std.debug.print("{d} handle ws frame... {s} {s}\n", .{
            fd,
            frame.opcode.toString(),
            frame.getPayload(),
        });
        pereg.ws.writer.writeMessage(fd, "Hello client!", false) catch |err| {
            std.debug.print("{d} error writing websocket: {any}\n", .{ fd, err });
        };
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try pereg.Server(Handler).init(allocator, 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
