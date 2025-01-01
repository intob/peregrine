const std = @import("std");
const pereg = @import("peregrine");

const Handler = struct {
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        return try allocator.create(Self);
    }

    pub fn deinit(_: *Self) void {}

    pub fn handleRequest(_: *Self, _: *pereg.Request, resp: *pereg.Response) void {
        _ = try resp.setBody("Kawww\n");
        try resp.addNewHeader("Content-Length", "6");
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try pereg.Server(Handler).init(allocator, 3000, .{
        .worker_thread_count = 18,
        .accept_thread_count = 2,
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
