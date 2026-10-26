const std = @import("std");
const per = @import("peregrine");

const FILE = "./example/fileserver/example.html";

const Handler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    fileServer: *per.util.FileServer,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const fileServer = try per.util.FileServer.init(allocator, FILE, .{});
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

pub fn main(init: std.process.Init) !void {
    const srv = try per.Server(Handler).init(init.gpa, 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
