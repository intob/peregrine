const std = @import("std");
const pereg = @import("peregrine");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try pereg.Server.init(.{
        .allocator = allocator,
        .port = 3000,
        .on_request = handleRequest,
        // .ip defaults to 0.0.0.0
        // .worker_count defaults to CPU core count
        .worker_count = 8,
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    std.debug.print("with {d} worker-threads\n", .{srv.workers.len});
    try srv.start(); // This blocks if there is no error
}

// Error handling omitted for brevity
fn handleRequest(req: *pereg.Request, resp: *pereg.Response) void {
    if (std.mem.eql(u8, "/hijack", req.getPath())) {
        hijack(req, resp) catch {};
        return;
    }
    default(resp) catch {};
}

fn default(resp: *pereg.Response) !void {
    try resp.setBody("Kawww\n");
    try resp.headers.append(try pereg.Header.init(.{
        .key = "Content-Length",
        .value = "6",
    }));
}

// If you need, you can take total control by writing the response to
// the socket yourself. If you do this, note that the worker uses
// vectored IO to write the headers and body simultaneously. You will
// need to implement that yourself, or lose some performance.
fn hijack(req: *pereg.Request, resp: *pereg.Response) !void {
    resp.hijack();
    try resp.setBody("Hijacked response\n");
    try resp.headers.append(try pereg.Header.init(.{
        .key = "Content-Length",
        .value = "18",
    }));
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    var buf = try allocator.alloc(u8, 128);
    defer allocator.free(buf);
    const hlen = try resp.serialiseHeaders(&buf);
    @memcpy(buf[hlen .. hlen + resp.body_len], resp.body[0..resp.body_len]);
    try pereg.worker.writeAll(req.socket, buf[0 .. hlen + resp.body_len]);
}
