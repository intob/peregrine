const std = @import("std");
const pereg = @import("peregrine");

const Handler = struct {
    allocator: std.mem.Allocator,
    counter: std.atomic.Value(usize),

    pub fn init(allocator: std.mem.Allocator) !*@This() {
        const handler = try allocator.create(@This());
        handler.* = .{
            .allocator = allocator,
            .counter = std.atomic.Value(usize).init(0),
        };
        return handler;
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.destroy(self);
    }

    // Be mindful that this handler can be called from multiple threads
    // concurrently. You will need to handle synchronization. This is why
    // an atomic value is used in this example.
    pub fn handleRequest(self: *@This(), req: *pereg.Request, resp: *pereg.Response) void {
        self.handleWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleWithError(self: *@This(), _: *pereg.Request, resp: *pereg.Response) !void {
        const count = self.counter.fetchAdd(1, .monotonic);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const buf = try std.fmt.allocPrint(allocator, "counter={d}\n", .{count});
        _ = try resp.setBody(buf);
        const len_buf = try std.fmt.allocPrint(allocator, "{d}", .{buf.len});
        try resp.addNewHeader("Content-Length", len_buf);
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
