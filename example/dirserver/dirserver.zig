const std = @import("std");
const per = @import("peregrine");

const DIR = "./example/dirserver/static";

const Handler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    dirServer: *per.util.DirServer,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const abs_path = try absolutePath(allocator, DIR);
        defer allocator.free(abs_path);
        const dirServer = try per.util.DirServer.init(allocator, abs_path, .{});
        const handler = try allocator.create(Self);
        handler.* = .{ .allocator = allocator, .dirServer = dirServer };
        return handler;
    }

    pub fn deinit(self: *Self) void {
        self.dirServer.deinit();
        self.allocator.destroy(self);
    }

    pub fn handleRequest(self: *Self, req: *per.Request, resp: *per.Response) void {
        self.dirServer.serve(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
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
