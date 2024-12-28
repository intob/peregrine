const std = @import("std");
const pereg = @import("peregrine");

const MyHandler = struct {
    const vtable: pereg.HandlerVTable = .{
        .handle = handle,
    };

    pub fn handle(ptr: *anyopaque, req: *pereg.Request, resp: *pereg.Response) void {
        // Use @alignCast and @ptrCast together for safe pointer conversion
        const self = @as(*@This(), @alignCast(@ptrCast(ptr)));
        self.handleWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    inline fn handleWithError(_: *@This(), _: *pereg.Request, resp: *pereg.Response) !void {
        _ = try resp.setBody("Kawww\n");
        const len_header = try pereg.Header.init(.{ .key = "Content-Length", .value = "6" });
        try resp.headers.append(len_header);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const handler = try allocator.create(MyHandler);
    defer allocator.destroy(handler);
    const srv = try pereg.Server.init(.{
        .allocator = allocator,
        .handler = handler,
        .handler_vtable = &MyHandler.vtable,
        .port = 3000,
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
