const std = @import("std");
const pereg = @import("peregrine");

const MyHandler = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    fileServer: *pereg.helper.FileServer,

    pub fn init(allocator: std.mem.Allocator) !*@This() {
        const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd_path);
        std.debug.print("cwd: {s}\n", .{cwd_path});
        const file = try std.fs.cwd().createFile("./example/index.html", .{
            .read = true,
            .truncate = false,
        });
        try file.chmod(0o666);
        // By default, the file will be lazy loaded on the first request. You can
        // override this using the configuration struct.
        const fileServer = try pereg.helper.FileServer.init(allocator, file, .{});
        const handler = try allocator.create(@This());
        handler.* = .{
            .allocator = allocator,
            .file = file,
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
    const srv = try pereg.Server(MyHandler).init(allocator, 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
