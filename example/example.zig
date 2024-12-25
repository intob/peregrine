const std = @import("std");
const peregrine = @import("peregrine");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try peregrine.Server.init(.{
        .allocator = allocator,
        .port = 3000,
        .on_request = on_request,
        // .ip defaults to 0.0.0.0
        // .worker_count defaults to CPU core count
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // This blocks if there is no error
}

fn on_request(req: *peregrine.Request, resp: *peregrine.Response) void {
    std.debug.print("got request: {any} {s}\n", .{ req.method, req.getPath() });
    resp.setBody("Kawww\n") catch {};
    resp.headers.append(.{ .key = "Content-Length", .value = "6" }) catch {};
}
