const std = @import("std");
const pereg = @import("peregrine");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try pereg.Server.init(.{
        .allocator = allocator,
        .port = 3000,
        .on_request = mainHandler,
        // .ip defaults to 0.0.0.0
        // .worker_count defaults to CPU core count
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // This blocks if there is no error
}

fn mainHandler(req: *pereg.Request, resp: *pereg.Response) void {
    handle(req, resp) catch {}; // Error handling omitted for brevity
}

fn handle(req: *pereg.Request, resp: *pereg.Response) !void {
    if (try req.parseQuery()) |query| {
        var iter = query.iterator();
        while (iter.next()) |entry| {
            std.debug.print("query param {s}: {s}\n", .{
                entry.key_ptr.*,
                entry.value_ptr.*,
            });
        }
    }
    try resp.setBody("Kawww\n");
    try resp.headers.append(try pereg.Header.init(.{
        .key = "Content-Length",
        .value = "6",
    }));
}

fn hijack(_: *pereg.Request, resp: *pereg.Response) !void {
    resp.hijack();
    // If you need, you can take total control by writing the response to
    // the socket yourself. If you do this, note that the worker uses
    // vectored IO to write the headers and body simultaneously. You will
    // need to implement that yourself, or lose some performance.
}
