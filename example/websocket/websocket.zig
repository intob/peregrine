const std = @import("std");
const per = @import("peregrine");

const DIR = "./example/websocket/static";

const Handler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    counter: std.atomic.Value(usize),
    dirServer: *per.util.DirServer,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const abs_path = try absolutePath(allocator, DIR);
        defer allocator.free(abs_path);
        const handler = try allocator.create(Self);
        handler.* = .{
            .allocator = allocator,
            .counter = std.atomic.Value(usize).init(0),
            .dirServer = try per.util.DirServer.init(allocator, abs_path, .{}),
        };
        return handler;
    }

    pub fn deinit(self: *Self) void {
        self.dirServer.deinit();
        self.allocator.destroy(self);
    }

    pub fn handleRequest(self: *Self, req: *per.Request, resp: *per.Response) void {
        self.handleRequestWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleRequestWithError(self: *Self, req: *per.Request, resp: *per.Response) !void {
        if (std.mem.eql(u8, req.getPath(), "/ws")) {
            // Explicitly handle the upgrade to support websockets.
            try per.ws.upgrader.handleUpgrade(self.allocator, req, resp);
            return;
        }
        try self.dirServer.serve(req, resp);
    }

    pub fn handleWSConn(_: *Self, fd: std.posix.fd_t) void {
        std.debug.print("{d} handle ws conn...\n", .{fd});
    }

    pub fn handleWSDisconn(_: *Self, fd: std.posix.fd_t) void {
        std.debug.print("{d} handle ws disconn...\n", .{fd});
    }

    pub fn handleWSFrame(_: *Self, fd: std.posix.fd_t, frame: *per.ws.Frame) void {
        if (frame.opcode == per.ws.Opcode.close) {
            std.debug.print("{d} client closed websocket\n", .{fd});
            return;
        }
        std.debug.print("{d} handle ws frame... {s} {s}\n", .{
            fd,
            frame.opcode.toString(),
            frame.getPayload(),
        });
        per.ws.writer.writeMessage(fd, "Hello client!", false) catch |err| {
            std.debug.print("{d} error writing websocket: {any}\n", .{ fd, err });
        };
    }
};

pub fn main(init: std.process.Init) !void {
    const srv = try per.Server(Handler).init(init.gpa, 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}

fn absolutePath(allocator: std.mem.Allocator, rel: []const u8) ![:0]u8 {
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    return try std.Io.Dir.cwd().realPathFileAlloc(threaded.io(), rel, allocator);
}
