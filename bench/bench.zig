const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const num_requests = 100_000;
    const uri = try std.Uri.parse("http://127.0.0.1:3000/");
    var successful_requests: usize = 0;
    var i: usize = 0;
    //var resp = std.ArrayList(u8).init(allocator);
    var timer = try std.time.Timer.start();
    const start_time = timer.read();
    while (i < num_requests) : (i += 1) {
        const req = client.fetch(.{
            .location = .{ .uri = uri },
            .method = .GET,
            .keep_alive = true,
            .response_storage = .ignore,
        }) catch |err| switch (err) {
            error.ConnectionResetByPeer => continue,
            else => return err,
        };
        if (req.status == std.http.Status.ok) {
            successful_requests += 1;
        }
    }
    const total_time = timer.read() - start_time;
    const avg_time = @divFloor(total_time, successful_requests);
    const requests_per_sec = @divFloor(std.time.ns_per_s * successful_requests, total_time);
    try std.io.getStdOut().writer().print(
        \\Benchmark Results:
        \\Successful Requests: {d}/{d}
        \\Total Time: {d}ms
        \\Average Time: {d}µs
        \\Requests/second: {d}
        \\
    , .{
        successful_requests,
        num_requests,
        total_time / std.time.ns_per_ms,
        avg_time / std.time.ns_per_us,
        requests_per_sec,
    });
}
