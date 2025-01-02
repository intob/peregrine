const std = @import("std");
const pereg = @import("peregrine");

const Handler = struct {
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        return try allocator.create(Self);
    }

    pub fn deinit(_: *Self) void {}

    pub fn handleRequest(_: *Self, _: *pereg.Request, resp: *pereg.Response) void {
        _ = resp.setBody("Kawww\n") catch {};
        resp.addNewHeader("Content-Length", "6") catch {};
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
