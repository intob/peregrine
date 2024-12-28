const std = @import("std");
const pereg = @import("peregrine");

const FILE = "./example/fileserver/example.html";

const Handler = struct {
    allocator: std.mem.Allocator,
    fileServer: *pereg.helper.FileServer,

    pub fn init(allocator: std.mem.Allocator) !*@This() {
        const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd_path);
        std.debug.print("cwd: {s}\n", .{cwd_path});
        const abs_file_path = try std.fs.path.join(allocator, &.{ cwd_path, FILE });
        defer allocator.free(abs_file_path);
        const fileServer = try pereg.helper.FileServer.init(allocator, abs_file_path, .{});
        const handler = try allocator.create(@This());
        handler.* = .{
            .allocator = allocator,
            .fileServer = fileServer,
        };
        return handler;
    }

    pub fn deinit(self: *@This()) void {
        self.fileServer.deinit();
        self.allocator.destroy(self);
    }

    pub fn handle(self: *@This(), req: *pereg.Request, resp: *pereg.Response) void {
        self.handleWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleWithError(self: *@This(), _: *pereg.Request, resp: *pereg.Response) !void {
        try self.fileServer.serve(resp);
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
