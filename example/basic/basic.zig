const std = @import("std");
const per = @import("peregrine");

const Handler = struct {
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        return try allocator.create(Self);
    }

    pub fn deinit(_: *Self) void {}

    pub fn handleRequest(_: *Self, _: *per.Request, resp: *per.Response) void {
        _ = resp.setBody("Kawww\n") catch {};
        resp.addNewHeader("content-length", "6") catch {};
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try per.Server(Handler, .TLSEnabled).init(allocator, 3000, .{
        .accept_thread_count = 1,
        .worker_thread_count = 6,
        .tls_cert_filename = "./example/basic/server.pem",
        .tls_key_filename = "./example/basic/server.key",
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
