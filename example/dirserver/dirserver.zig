const std = @import("std");
const per = @import("peregrine");

const DIR = "./example/dirserver/static";

const Handler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    dirServer: *per.util.DirServer,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd_path);
        std.debug.print("cwd: {s}\n", .{cwd_path});
        const abs_path = try std.fs.path.join(allocator, &.{ cwd_path, DIR });
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const srv = try per.Server(Handler).init(gpa.allocator(), 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
