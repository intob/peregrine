//! Micro-benchmarks for the request parser and session state machine.
//! Run with `zig build bench` (always built with -O fast).
const std = @import("std");
const per = @import("peregrine");
const parser = per.internal.parser;
const session = per.internal.session;
const sys = per.internal.sys;

const request =
    "GET /path/to/resource?x=1 HTTP/1.1\r\n" ++
    "Host: example.com\r\n" ++
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36\r\n" ++
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" ++
    "Accept-Language: en-GB,en;q=0.5\r\n" ++
    "Accept-Encoding: gzip, deflate, br\r\n" ++
    "Cookie: session=0123456789abcdef0123456789abcdef; theme=dark\r\n" ++
    "Connection: keep-alive\r\n\r\n";

const Handler = struct {
    pub fn handleRequest(_: *Handler, _: *per.Request, resp: *per.Response) void {
        resp.setBodyBorrowed("Hello, World!");
    }
};

fn report(name: []const u8, iterations: usize, ns: u64, bytes: usize) void {
    const per_op = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(iterations));
    const gbps = @as(f64, @floatFromInt(bytes * iterations)) / @as(f64, @floatFromInt(ns));
    std.debug.print("{s:<40} {d:>8.1} ns/op  {d:>6.2} GB/s\n", .{ name, per_op, gbps });
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const req = try per.Request.init(gpa);
    defer req.deinit();

    // 1. findHeadEnd + parseHead on a realistic browser request.
    {
        const iterations: usize = 5_000_000;
        const start = sys.nanoTimestamp();
        for (0..iterations) |_| {
            var scan: usize = 0;
            const len = (try parser.findHeadEnd(request, &scan, .{})).?;
            const head = try parser.parseHead(request[0..len], req, .{});
            std.mem.doNotOptimizeAway(head);
        }
        report("parse request (8 headers, 437 B)", iterations, sys.nanoTimestamp() - start, request.len);
    }

    // 2. Full session: parse, handle, serialise, for 16 pipelined requests.
    {
        var pool = try session.BufferPool.init(gpa, 16 * 1024, 1);
        defer pool.deinit();
        const resp = try per.Response.init(gpa, 4096, 4096);
        defer resp.deinit();
        const out_buf = try gpa.alloc(u8, 64 * 1024);
        defer gpa.free(out_buf);
        var out: session.Out = .{ .buf = out_buf };
        var handler: Handler = .{};
        var date_line: [per.internal.date.header_len]u8 = undefined;
        per.internal.date.formatHeader(&date_line, 0);
        const ctx: session.Context(Handler) = .{ .handler = &handler, .req = req, .resp = resp, .date = &date_line, .opts = .{} };
        const batch = request;
        var s: session.Session = .{};
        const iterations: usize = 300_000;
        const start = sys.nanoTimestamp();
        for (0..iterations) |_| {
            const space = try s.readSpace(&pool, .{});
            for (0..16) |k| @memcpy(space[k * batch.len ..][0..batch.len], batch);
            s.commitRead(16 * batch.len);
            while (true) {
                const action = session.process(Handler, &s, &ctx, &out);
                out.clear();
                if (action != .flush) break;
            }
            s.releaseIfIdle(&pool);
        }
        const ns = sys.nanoTimestamp() - start;
        report("session: 16 pipelined requests, per request", iterations * 16, ns, request.len);
    }
}
