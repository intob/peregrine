//! Body-checking server for HTTP/2 churn tests (bench/scripts/h2-churn.py
//! is the client). Every body is a window into one pattern, so a client
//! can check every byte and a buffer that reaches the wrong connection
//! shows: the pattern is 64-bit little-endian words, word w holding
//! w * 8 | 0xA5 << 56 (so the bytes at offset `off` are unique to it).
//!
//!   /p/OFF/LEN       borrowed body (h2 copies it into DATA frames)
//!   /f/OFF/LEN       file body (pread into DATA frames)
//!   /s/OFF/LEN       resp.stream() from another thread, chunks of random
//!                    size, copied and borrowed in turn (mailbox posts
//!                    while writes are in flight)
//!   /t/OFF/LEN       later() + startStream, finished with a trailer
//!                    `x-off: OFF` from another thread
//!   /h/OFF/LEN/PAD   borrowed body after an `x-pad` header of PAD bytes
//!   /e/OFF/LEN/PAD   a request body that must be that window, after a
//!                    request `x-pad` header of PAD bytes (and an `x-off:
//!                    OFF` trailer if any): answered with the window and
//!                    `x-trailers: N`, or 500 saying what was wrong
//!   /ws              WebSocket echo (extended CONNECT over h2)
//!
//! Usage: verify-server WORKERS BACKEND PORT tls|plain [out_limit=N]
//!        [max_frame=N] [rbuf=N] [pool=N]
const std = @import("std");
const per = @import("peregrine");

pub const pattern_len = 32 * 1024 * 1024;
var pattern: [pattern_len]u8 align(8) = undefined;
var pad_bytes: [256 * 1024]u8 = undefined;

fn fillPattern() void {
    const words = std.mem.bytesAsSlice(u64, &pattern);
    for (words, 0..) |*w, i| w.* = std.mem.nativeToLittle(u64, @as(u64, i) * 8 | (@as(u64, 0xA5) << 56));
    for (&pad_bytes, 0..) |*b, i| b.* = 'a' + @as(u8, @intCast(i % 26));
}

fn sleepMs(ms: u64) void {
    var ts: std.posix.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = std.posix.system.nanosleep(&ts, &ts);
}

const Parsed = struct { off: usize, len: usize, pad: usize = 0 };

fn parse(rest: []const u8) ?Parsed {
    var it = std.mem.splitScalar(u8, rest, '/');
    const off = std.fmt.parseInt(usize, it.next() orelse return null, 10) catch return null;
    const len = std.fmt.parseInt(usize, it.next() orelse return null, 10) catch return null;
    var pad: usize = 0;
    if (it.next()) |p| pad = std.fmt.parseInt(usize, p, 10) catch return null;
    if (off + len > pattern_len or pad > pad_bytes.len) return null;
    return .{ .off = off, .len = len, .pad = pad };
}

const Handler = struct {
    file: std.Io.File,

    pub fn init(allocator: std.mem.Allocator) !*Handler {
        var threaded: std.Io.Threaded = .init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const dir = std.Io.Dir.cwd();
        const path = "/tmp/peregrine-verify-body";
        const file = try dir.createFile(io, path, .{ .read = true });
        errdefer file.close(io);
        try file.writeStreamingAll(io, &pattern);
        dir.deleteFile(io, path) catch {};
        const h = try allocator.create(Handler);
        h.* = .{ .file = file };
        return h;
    }

    pub fn deinit(_: *Handler) void {}

    pub fn handleRequest(self: *Handler, req: *per.Request, resp: *per.Response) void {
        const path = req.getPath();
        if (std.mem.eql(u8, path, "/ws")) {
            per.ws.upgrader.handleUpgrade(undefined, req, resp) catch {
                resp.status = .bad_request;
            };
            return;
        }
        if (path.len < 3 or path[0] != '/' or path[2] != '/') return notFound(resp);
        const p = parse(path[3..]) orelse return notFound(resp);
        switch (path[1]) {
            'p' => resp.setBodyBorrowed(pattern[p.off..][0..p.len]),
            'f' => resp.sendFile(.{ .fd = self.file.handle, .offset = p.off, .len = p.len }),
            'h' => {
                resp.addHeader(.{ .key = "x-pad", .value = pad_bytes[0..p.pad] }) catch {
                    resp.status = .internal_server_error;
                    return;
                };
                resp.setBodyBorrowed(pattern[p.off..][0..p.len]);
            },
            'e' => {
                const wrong: ?[]const u8 = check: {
                    if (!std.mem.eql(u8, req.body, pattern[p.off..][0..p.len])) break :check "request body\n";
                    var pad: ?[]const u8 = null;
                    for (req.getHeaders()) |h| {
                        if (std.mem.eql(u8, h.key, "x-pad")) pad = h.value;
                    }
                    if (p.pad > 0 and !std.mem.eql(u8, pad orelse "", pad_bytes[0..p.pad])) break :check "x-pad\n";
                    var buf: [24]u8 = undefined;
                    const off_s = std.fmt.bufPrint(&buf, "{d}", .{p.off}) catch unreachable;
                    for (req.trailers) |t| {
                        if (!std.mem.eql(u8, t.key, "x-off") or !std.mem.eql(u8, t.value, off_s)) break :check "trailer\n";
                    }
                    break :check null;
                };
                if (wrong) |what| {
                    resp.status = .internal_server_error;
                    resp.setBodyBorrowed(what);
                    return;
                }
                const counts = [_][]const u8{ "0", "1", "2", "3" };
                resp.addHeader(.{ .key = "x-trailers", .value = counts[@min(req.trailers.len, 3)] }) catch {};
                resp.setBodyBorrowed(pattern[p.off..][0..p.len]);
            },
            's' => {
                if (p.off % 2 == 0) resp.setContentLength(p.len);
                const ex = resp.stream() catch {
                    resp.status = .service_unavailable;
                    return;
                };
                spawn(ex, p, false);
            },
            't' => {
                const ex = resp.later() catch {
                    resp.status = .service_unavailable;
                    return;
                };
                spawn(ex, p, true);
            },
            else => notFound(resp),
        }
    }

    fn notFound(resp: *per.Response) void {
        resp.status = .not_found;
        resp.setBodyBorrowed("no such path\n");
    }

    pub fn handleWSFrame(_: *Handler, conn: *per.ws.Conn, frame: *per.ws.Frame) void {
        switch (frame.opcode) {
            .text, .binary => conn.send(frame.getPayload(), frame.opcode == .binary) catch {},
            else => {},
        }
    }
};

fn spawn(ex: per.Exchange, p: Parsed, trailers: bool) void {
    const t = std.Thread.spawn(.{ .stack_size = 128 * 1024 }, streamBody, .{ ex, p, trailers }) catch {
        ex.abort() catch {};
        return;
    };
    t.detach();
}

fn streamBody(ex: per.Exchange, p: Parsed, trailers: bool) void {
    var rng: std.Random.DefaultPrng = .init(p.off *% 0x9E3779B97F4A7C15 +% p.len);
    const r = rng.random();
    if (r.boolean()) sleepMs(r.uintLessThan(u64, 3));
    if (trailers) {
        ex.startStream(.{ .headers = &.{.{ .key = "content-type", .value = "application/octet-stream" }} }) catch return;
    }
    var sent: usize = 0;
    var i: usize = 0;
    while (sent < p.len) : (i += 1) {
        const max: usize = switch (r.uintLessThan(u8, 4)) {
            0 => 100,
            1 => 5000,
            2 => 20000,
            else => 70000,
        };
        const n = @min(p.len - sent, 1 + r.uintLessThan(usize, max));
        const chunk = pattern[p.off + sent ..][0..n];
        const res = if (i % 2 == 0) ex.write(chunk) else ex.writeBorrowed(chunk, null);
        res catch |err| switch (err) {
            error.WouldBlock => {
                sleepMs(1);
                continue;
            },
            else => return,
        };
        sent += n;
        if (r.uintLessThan(u8, 8) == 0) sleepMs(1);
    }
    var buf: [24]u8 = undefined;
    const off_s = std.fmt.bufPrint(&buf, "{d}", .{p.off}) catch unreachable;
    if (trailers) {
        ex.finish(&.{.{ .key = "x-off", .value = off_s }}) catch {};
    } else {
        ex.finish(&.{}) catch {};
    }
}

pub fn main(init: std.process.Init) !void {
    fillPattern();
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const workers = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 0;
    const backend = if (args.len > 2) std.meta.stringToEnum(per.Backend, args[2]) orelse return error.BadBackend else .auto;
    const port = if (args.len > 3) try std.fmt.parseInt(u16, args[3], 10) else 8080;
    const use_tls = args.len > 4 and std.mem.eql(u8, args[4], "tls");
    var h2: per.H2Options = .{};
    var rbuf: usize = 16 * 1024;
    var pool: usize = 256;
    for (args[@min(args.len, 5)..]) |arg| {
        const eq = std.mem.indexOfScalar(u8, arg, '=') orelse continue;
        const v = try std.fmt.parseInt(usize, arg[eq + 1 ..], 10);
        const k = arg[0..eq];
        if (std.mem.eql(u8, k, "out_limit")) h2.out_limit = v;
        if (std.mem.eql(u8, k, "max_frame")) h2.max_frame_size = @intCast(v);
        if (std.mem.eql(u8, k, "rbuf")) rbuf = v;
        if (std.mem.eql(u8, k, "pool")) pool = v;
    }
    const srv = try per.Server(Handler).init(std.heap.smp_allocator, port, .{
        .worker_thread_count = workers,
        .backend = backend,
        .h2c = true,
        .h2 = h2,
        .read_buffer_size = rbuf,
        .buffer_pool_size = pool,
        .response_header_buffer_size = 512 * 1024,
        .out_buffer_size = 1024 * 1024,
        .max_exchanges_per_worker = 4096,
        .max_exchange_queue_bytes = 256 * 1024,
        .tls = if (use_tls) .{
            .cert_pem = @embedFile("cert.pem"),
            .key_pem = @embedFile("key.pem"),
            .alpn = &.{ "h2", "http/1.1" },
        } else null,
    });
    std.debug.print("listening on :{d} ({s}, {d} workers{s}) out_limit={d} max_frame={d} rbuf={d}\n", .{ srv.getPort(), @tagName(srv.getBackend()), srv.workers.len, if (use_tls) ", tls" else "", h2.out_limit, h2.max_frame_size, rbuf });
    try srv.start();
}
