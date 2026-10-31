//! WebSocket load generator (Linux): echo round trips against a server's
//! WebSocket endpoint, with several messages in flight per connection.
//! Usage: ws-load [ip] [port] [threads] [connections] [depth] [size] [seconds] [binary|text] [path] [deflate]
//! Defaults: 127.0.0.1 8080 6 256 1 20 8 binary /ws.
//! `connections` is the total, spread over the threads, each with its own
//! epoll. Every connection upgrades with HTTP/1.1, then keeps `depth`
//! masked messages of `size` bytes in flight: each echo that arrives whole
//! is counted and answered with another message, written together with
//! the others completed in the same read. Echoes are checked for opcode,
//! FIN and length, and the first one on each connection byte by byte.
//! Prints the number of messages echoed and the rate; the caller reads
//! the server's CPU time around the run.
//!
//! With `deflate`, connections offer permessage-deflate and the message is
//! `size` bytes of JSON-like text sent compressed (compressed once, on its
//! own, so it is valid with or without context takeover). Echoes, which
//! may come back compressed, are checked for opcode and FIN only.
const std = @import("std");
const per = @import("peregrine");
const util = @import("util.zig");
const parseIp = util.parseIp;
const sleepMs = util.sleepMs;
const sys = per.internal.sys;
const posix = std.posix;
const linux = std.os.linux;

const Options = struct {
    ip: [4]u8 = .{ 127, 0, 0, 1 },
    port: u16 = 8080,
    threads: usize = 6,
    connections: usize = 256,
    depth: usize = 1,
    size: usize = 20,
    seconds: u64 = 8,
    text: bool = false,
    path: []const u8 = "/ws",
    deflate: bool = false,
};

const mask_key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
const payload_byte = 'x';

/// Echo frames come back unmasked: header length for a payload of `n`.
fn serverHeaderLen(n: usize) usize {
    return if (n < 126) 2 else if (n <= 0xffff) 4 else 10;
}

/// What each message's frame carries: `size` bytes of 'x', or with
/// `deflate`, `size` bytes of JSON-like text compressed (ending as RFC 7692
/// says: an empty stored block, its last four bytes left off).
fn buildBody(allocator: std.mem.Allocator, o: Options) ![]u8 {
    const plain = try allocator.alloc(u8, o.size);
    if (!o.deflate) {
        @memset(plain, payload_byte);
        return plain;
    }
    defer allocator.free(plain);
    const json = "{\"userId\":12345,\"action\":\"purchase\",\"items\":[{\"id\":\"A1B2C3\",\"name\":\"Wireless Mouse\",\"price\":25.99,\"quantity\":1}],\"status\":\"approved\"} ";
    for (plain, 0..) |*b, i| b.* = json[i % json.len];
    var out: std.Io.Writer.Allocating = try .initCapacity(allocator, o.size + 64);
    defer out.deinit();
    const window = try allocator.alloc(u8, std.compress.flate.max_window_len);
    defer allocator.free(window);
    const c = try allocator.create(std.compress.flate.Compress);
    defer allocator.destroy(c);
    c.* = try .init(&out.writer, window, .raw, .default);
    try c.writer.writeAll(plain);
    try c.writer.flush();
    try out.writer.writeByte(0);
    return out.toOwnedSlice();
}

/// `count` copies of one masked client frame, back to back.
fn buildFrames(allocator: std.mem.Allocator, o: Options, body: []const u8, count: usize) ![]u8 {
    const n = body.len;
    const head_len = serverHeaderLen(n) + 4;
    const frame_len = head_len + n;
    const buf = try allocator.alloc(u8, frame_len * count);
    const f = buf[0..frame_len];
    f[0] = 0x80 | @as(u8, if (o.text) 0x1 else 0x2) | @as(u8, if (o.deflate) 0x40 else 0);
    if (n < 126) {
        f[1] = 0x80 | @as(u8, @intCast(n));
    } else if (n <= 0xffff) {
        f[1] = 0x80 | 126;
        std.mem.writeInt(u16, f[2..4], @intCast(n), .big);
    } else {
        f[1] = 0x80 | 127;
        std.mem.writeInt(u64, f[2..10], n, .big);
    }
    @memcpy(f[head_len - 4 .. head_len], &mask_key);
    for (f[head_len..], body, 0..) |*b, x, i| b.* = x ^ mask_key[i % 4];
    var i: usize = 1;
    while (i < count) : (i += 1) @memcpy(buf[i * frame_len ..][0..frame_len], f);
    return buf;
}

const Conn = struct {
    fd: sys.fd_t,
    /// Bytes of messages still to write (whole frames of the periodic
    /// stream, less what has gone of the first).
    owed: usize = 0,
    /// Offset of the next byte within a frame.
    out_off: usize = 0,
    hdr: [10]u8 = undefined,
    hdr_len: usize = 0,
    payload_left: usize = 0,
    in_payload: bool = false,
    verified: bool = false,
};

const Worker = struct {
    o: *const Options,
    frames: []const u8,
    frame_len: usize,
    conn_count: usize,
    messages: std.atomic.Value(u64) = .init(0),
    failed: std.atomic.Value(bool) = .init(false),
    thread: std.Thread = undefined,

    fn fail(self: *Worker, comptime fmt: []const u8, args: anytype) void {
        std.debug.print("ws-load: " ++ fmt ++ "\n", args);
        self.failed.store(true, .release);
    }

    fn run(self: *Worker, stop: *std.atomic.Value(bool)) void {
        self.loop(stop) catch |err| self.fail("{s}", .{@errorName(err)});
    }

    fn loop(self: *Worker, stop: *std.atomic.Value(bool)) !void {
        const allocator = std.heap.smp_allocator;
        const conns = try allocator.alloc(Conn, self.conn_count);
        defer allocator.free(conns);
        const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (posix.errno(epfd_rc) != .SUCCESS) return error.EpollFailed;
        const epfd: i32 = @intCast(epfd_rc);
        defer sys.close(epfd);
        var opened: usize = 0;
        defer for (conns[0..opened]) |c| sys.close(c.fd);
        for (conns, 0..) |*c, i| {
            c.* = .{ .fd = try self.open() };
            opened += 1;
            var ev = linux.epoll_event{
                .events = linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.RDHUP | linux.EPOLL.ET,
                .data = .{ .u64 = i },
            };
            if (posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, c.fd, &ev)) != .SUCCESS) return error.EpollFailed;
            c.owed = self.o.depth * self.frame_len;
            try self.flush(c);
        }
        const in_buf = try allocator.alloc(u8, 256 * 1024);
        defer allocator.free(in_buf);
        var events: [256]linux.epoll_event = undefined;
        var count: u64 = 0;
        while (!stop.load(.acquire)) {
            const rc = linux.epoll_wait(epfd, &events, events.len, 100);
            if (posix.errno(rc) != .SUCCESS) continue;
            for (events[0..rc]) |ev| {
                const c = &conns[@intCast(ev.data.u64)];
                if (ev.events & linux.EPOLL.IN != 0) {
                    const done = try self.receive(c, in_buf);
                    count += done;
                    c.owed += done * self.frame_len;
                }
                if (ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR) != 0) return error.ConnectionClosed;
                try self.flush(c);
            }
            self.messages.store(count, .release);
        }
    }

    /// A blocking connect and upgrade, then non-blocking.
    fn open(self: *Worker) !sys.fd_t {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, linux.IPPROTO.TCP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
        const fd: sys.fd_t = @intCast(rc);
        errdefer sys.close(fd);
        var addr = std.mem.zeroes(linux.sockaddr.in);
        addr.family = linux.AF.INET;
        addr.port = std.mem.nativeToBig(u16, self.o.port);
        addr.addr = @bitCast(self.o.ip);
        if (posix.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) != .SUCCESS) return error.ConnectFailed;
        try sys.setsockoptInt(fd, linux.IPPROTO.TCP, sys.TCP_NODELAY, 1);
        var req_buf: [512]u8 = undefined;
        const req = try std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: bench\r\nUpgrade: websocket\r\n" ++
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{s}\r\n", .{
            self.o.path,
            if (self.o.deflate) "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n" else "",
        });
        var rest: []const u8 = req;
        while (rest.len > 0) rest = rest[try sys.write(fd, rest)..];
        // Nothing follows the 101 until we send, so the head ends the read.
        var resp: [1024]u8 = undefined;
        var len: usize = 0;
        while (std.mem.indexOf(u8, resp[0..len], "\r\n\r\n") == null) {
            if (len == resp.len) return error.ResponseTooLong;
            const n = try sys.read(fd, resp[len..]);
            if (n == 0) return error.ConnectionClosed;
            len += n;
        }
        if (!std.mem.startsWith(u8, resp[0..len], "HTTP/1.1 101")) {
            self.fail("upgrade refused: {s}", .{resp[0..@min(len, 64)]});
            return error.UpgradeRefused;
        }
        if (std.mem.indexOf(u8, resp[0..len], "\r\n\r\n").? + 4 != len) return error.UnexpectedData;
        if (self.o.deflate and std.ascii.findIgnoreCase(resp[0..len], "permessage-deflate") == null) {
            self.fail("permessage-deflate not accepted", .{});
            return error.NoDeflate;
        }
        try sys.setNonBlocking(fd);
        return fd;
    }

    fn flush(self: *Worker, c: *Conn) !void {
        while (c.owed > 0) {
            const chunk = self.frames[c.out_off..][0..@min(c.owed, self.frames.len - c.out_off)];
            const n = sys.write(c.fd, chunk) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };
            c.owed -= n;
            c.out_off = (c.out_off + n) % self.frame_len;
        }
    }

    /// Reads until EAGAIN; returns the echoes completed.
    fn receive(self: *Worker, c: *Conn, buf: []u8) !u64 {
        var done: u64 = 0;
        while (true) {
            const n = sys.read(c.fd, buf) catch |err| switch (err) {
                error.WouldBlock => return done,
                else => return err,
            };
            if (n == 0) return error.ConnectionClosed;
            done += try self.parse(c, buf[0..n]);
        }
    }

    fn parse(self: *Worker, c: *Conn, input: []const u8) !u64 {
        var done: u64 = 0;
        var in = input;
        while (in.len > 0) {
            if (c.in_payload) {
                const k = @min(in.len, c.payload_left);
                if (!c.verified) {
                    for (in[0..k]) |b| if (b != payload_byte) return error.BadPayload;
                }
                in = in[k..];
                c.payload_left -= k;
                if (c.payload_left == 0) {
                    c.in_payload = false;
                    c.verified = true;
                    done += 1;
                }
                continue;
            }
            c.hdr[c.hdr_len] = in[0];
            c.hdr_len += 1;
            in = in[1..];
            if (c.hdr_len < 2) continue;
            const want: usize = switch (c.hdr[1]) {
                126 => 4,
                127 => 10,
                else => 2,
            };
            const expected_op: u8 = if (self.o.text) 0x81 else 0x82;
            if (c.hdr[0] & ~@as(u8, if (self.o.deflate) 0x40 else 0) != expected_op) return error.BadOpcode;
            if (c.hdr_len < want) continue;
            const len: u64 = switch (c.hdr[1]) {
                126 => std.mem.readInt(u16, c.hdr[2..4], .big),
                127 => std.mem.readInt(u64, c.hdr[2..10], .big),
                else => |l| l,
            };
            if (!self.o.deflate and len != self.o.size) return error.BadLength;
            if (self.o.deflate) c.verified = true;
            c.hdr_len = 0;
            c.payload_left = len;
            c.in_payload = true;
            if (len == 0) {
                c.in_payload = false;
                done += 1;
            }
        }
        return done;
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var o: Options = .{};
    if (args.len > 1) o.ip = try parseIp(args[1]);
    if (args.len > 2) o.port = try std.fmt.parseInt(u16, args[2], 10);
    if (args.len > 3) o.threads = try std.fmt.parseInt(usize, args[3], 10);
    if (args.len > 4) o.connections = try std.fmt.parseInt(usize, args[4], 10);
    if (args.len > 5) o.depth = try std.fmt.parseInt(usize, args[5], 10);
    if (args.len > 6) o.size = try std.fmt.parseInt(usize, args[6], 10);
    if (args.len > 7) o.seconds = try std.fmt.parseInt(u64, args[7], 10);
    if (args.len > 8) o.text = std.mem.eql(u8, args[8], "text");
    if (args.len > 9) o.path = args[9];
    if (args.len > 10) o.deflate = std.mem.eql(u8, args[10], "deflate");
    if (o.threads == 0 or o.connections < o.threads or o.depth == 0) return error.BadArguments;

    const allocator = std.heap.smp_allocator;
    const body = try buildBody(allocator, o);
    defer allocator.free(body);
    const frame_len = serverHeaderLen(body.len) + 4 + body.len;
    // Enough copies of the frame to write a whole batch of echoes at once.
    const copies = @max(1, @min(o.depth, (256 * 1024) / frame_len));
    const frames = try buildFrames(allocator, o, body, copies);
    defer allocator.free(frames);

    const workers = try allocator.alloc(Worker, o.threads);
    defer allocator.free(workers);
    var stop: std.atomic.Value(bool) = .init(false);
    const start = sys.nanoTimestamp();
    for (workers, 0..) |*w, i| {
        w.* = .{
            .o = &o,
            .frames = frames,
            .frame_len = frame_len,
            .conn_count = o.connections / o.threads + @intFromBool(i < o.connections % o.threads),
        };
        w.thread = try std.Thread.spawn(.{}, Worker.run, .{ w, &stop });
    }
    sleepMs(o.seconds * 1000);
    stop.store(true, .release);
    for (workers) |*w| w.thread.join();
    const elapsed = sys.nanoTimestamp() - start;
    var total: u64 = 0;
    var failed = false;
    for (workers) |*w| {
        total += w.messages.load(.acquire);
        failed = failed or w.failed.load(.acquire);
    }
    const secs = @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s;
    std.debug.print("{d} conns, depth {d}, {d} B {s}: {d} messages in {d:.2} s, {d:.0} msg/s ({d:.1} MB/s each way)\n", .{
        o.connections,                         o.depth,                                              o.size, if (o.text) "text" else "binary", total, secs,
        @as(f64, @floatFromInt(total)) / secs, @as(f64, @floatFromInt(total * o.size)) / secs / 1e6,
    });
    if (failed) return error.Failed;
}
