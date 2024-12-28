const std = @import("std");
const pereg = @import("peregrine");

const MyHandler = struct {
    main_allocator: std.mem.Allocator,
    counter: std.atomic.Value(usize),
    // ArenaAllocator lets us free all of a request's allocations at once.
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator) !*@This() {
        const handler = try allocator.create(@This());
        handler.* = .{
            .main_allocator = allocator,
            .counter = std.atomic.Value(usize).init(0),
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
        return handler;
    }

    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
        self.main_allocator.destroy(self);
    }

    // Be mindful that this handler can be called from multiple threads
    // concurrently. You will need to handle synchronization. This is why
    // an atomic value is used in this example.
    pub fn handle(self: *@This(), req: *pereg.Request, resp: *pereg.Response) void {
        self.handleWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleWithError(self: *@This(), _: *pereg.Request, resp: *pereg.Response) !void {
        const count = self.counter.fetchAdd(1, .monotonic);
        const allocator = self.arena.allocator();
        const buf = try std.fmt.allocPrint(allocator, "counter={d}\n", .{count});
        _ = try resp.setBody(buf);
        const len_buf = try std.fmt.allocPrint(allocator, "{d}", .{buf.len});
        const len_header = try pereg.Header.init(.{ .key = "Content-Length", .value = len_buf });
        try resp.headers.append(len_header);
        _ = self.arena.reset(.retain_capacity);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try pereg.Server(MyHandler).init(.{
        .allocator = allocator,
        .port = 3000,
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
