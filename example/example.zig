const std = @import("std");
const net = std.net;
const posix = std.posix;
const peregrine = @import("peregrine");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try peregrine.Server.init(
        allocator,
        "0.0.0.0",
        3000,
        on_request,
        try std.Thread.getCpuCount(),
    );
    std.debug.print("Listening on 0.0.0.0:3000\n", .{});
    try srv.start();
}

fn on_request(req: *peregrine.Request, _: *peregrine.Response) void {
    std.debug.print("got request: {any} {s}\n", .{ req.method, req.getPath() });
}
