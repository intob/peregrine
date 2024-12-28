const std = @import("std");
const pereg = @import("peregrine");

const MyHandler = struct {
    pub fn init(allocator: std.mem.Allocator) !*@This() {
        return try allocator.create(@This());
    }

    pub fn deinit(_: *@This()) void {}

    pub fn handle(self: *@This(), req: *pereg.Request, resp: *pereg.Response) void {
        self.handleWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleWithError(_: *@This(), _: *pereg.Request, resp: *pereg.Response) !void {
        _ = try resp.setBody("Kawww\n");
        const len_header = try pereg.Header.init(.{ .key = "Content-Length", .value = "6" });
        try resp.headers.append(len_header);
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
