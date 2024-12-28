const std = @import("std");
const pereg = @import("peregrine");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try pereg.Server.init(.{
        .allocator = allocator,
        .on_request = handler,
        .port = 3000,
        // .ip defaults to 0.0.0.0
        // .worker_thread_count defaults to CPU core count
        // .accept_thread_count defaults to worker_thread_count/3
        //    with a minimum of 1
        // .tcp_nodelay defaults to true (Nagle's algorithm disabled)
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}

fn handler(req: *pereg.Request, resp: *pereg.Response) void {
    handle(req, resp) catch {}; // Error handling omitted for brevity
}

fn handle(req: *pereg.Request, resp: *pereg.Response) !void {
    // The query is only parsed if you explicitly call parseQuery
    if (try req.parseQuery()) |query| {
        var iter = query.iterator();
        while (iter.next()) |param| {
            std.debug.print("query parameter {s}: {s}\n", .{
                param.key_ptr.*,
                param.value_ptr.*,
            });
        }
    }
    // After calling parseQuery, it is safe to access the query hash map directly
    // std.debug.print("got {d} query params\n", .{req.query.count()});

    // Remember to set Content-Length header
    try resp.setBody("Kaaawwwwwwwwwww\r\n");
    try resp.headers.append(try pereg.Header.init(.{
        .key = "Content-Length", // Max length of 64 (see Header.init)
        .value = "17", // Max length of 256 (see Header.init)
    }));
}

fn hijack(_: *pereg.Request, resp: *pereg.Response) !void {
    resp.hijack();
    // If you need, you can take total control by writing the response to
    // the socket yourself. If you do this, note that the worker uses
    // vectored IO to write the headers and body with a single syscall.
    // You will need to implement that yourself, or lose some performance.
}
