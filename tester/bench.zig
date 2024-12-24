const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    // Create HTTP client
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    // Benchmark configuration
    const num_requests = 10_000;
    const uri = try std.Uri.parse("http://127.0.0.1:5882/");

    // Timing variables
    var timer = try std.time.Timer.start();
    var total_time: u64 = 0;
    var successful_requests: usize = 0;

    // Run benchmark
    var i: usize = 0;
    while (i < num_requests) : (i += 1) {
        timer.reset();
        _ = client.fetch(.{
            .location = .{ .uri = uri },
            .method = .GET,
            .keep_alive = false, // Disable keep-alive to avoid connection resets
        }) catch |err| switch (err) {
            error.ConnectionResetByPeer => {},
            else => return err,
        };
        total_time += timer.read();
        successful_requests += 1;
    }

    // Calculate and print results
    const avg_time = @divFloor(total_time, successful_requests);
    const requests_per_sec = @divFloor(std.time.ns_per_s * successful_requests, total_time);

    try std.io.getStdOut().writer().print("Benchmark Results:\n" ++
        "Successful Requests: {d}/{d}\n" ++
        "Average Time: {d}ns\n" ++
        "Requests/second: {d}\n", .{ successful_requests, num_requests, avg_time, requests_per_sec });
}
