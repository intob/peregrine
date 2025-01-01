const std = @import("std");
const pereg = @import("peregrine");

const Handler = struct {
    pub fn init(allocator: std.mem.Allocator) !*@This() {
        return try allocator.create(@This());
    }

    pub fn deinit(_: *@This()) void {}

    pub fn handleRequest(self: *@This(), req: *pereg.Request, resp: *pereg.Response) void {
        self.handleWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleWithError(_: *@This(), _: *pereg.Request, resp: *pereg.Response) !void {
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
