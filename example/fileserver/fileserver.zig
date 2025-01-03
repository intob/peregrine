const std = @import("std");
const per = @import("peregrine");

const FILE = "./example/fileserver/example.html";

const Handler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    fileServer: *per.util.FileServer,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd_path);
        std.debug.print("cwd: {s}\n", .{cwd_path});
        const abs_file_path = try std.fs.path.join(allocator, &.{ cwd_path, FILE });
        defer allocator.free(abs_file_path);
        const fileServer = try per.util.FileServer.init(allocator, abs_file_path, .{});
        const handler = try allocator.create(Self);
        handler.* = .{
            .allocator = allocator,
            .fileServer = fileServer,
        };
        return handler;
    }

    pub fn deinit(self: *Self) void {
        self.fileServer.deinit();
        self.allocator.destroy(self);
    }

    pub fn handleRequest(self: *Self, req: *per.Request, resp: *per.Response) void {
        self.handleWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleWithError(self: *Self, _: *per.Request, resp: *per.Response) !void {
        try self.fileServer.serve(resp);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const srv = try per.Server(Handler).init(gpa.allocator(), 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
