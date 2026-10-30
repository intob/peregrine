//! conn.zig against the test client: handshakes, streams, flow control,
//! loss, key updates and protocol errors, with a fake clock.
const std = @import("std");
const conn_mod = @import("./conn.zig");
const packet = @import("./packet.zig");
const frame = @import("./frame.zig");
const test_client = @import("./test_client.zig");
const credentials = @import("../tls/credentials.zig");
const handshake = @import("../tls/handshake.zig");
const Conn = conn_mod.Conn;
const Client = test_client.Client;
const testing = std.testing;

const server_cid = [8]u8{ 0x5e, 0x5e, 1, 2, 3, 4, 5, 6 };

/// Answers request streams: reads to the end, then writes "echo:" + the
/// request (or `big` bytes when the request is "big N").
const EchoApp = struct {
    /// Running length and sum of "sum" uploads, by slot.
    var sums: [256]struct { len: u64 = 0, sum: u64 = 0, active: bool = false } = @splat(.{});

    fn run(c: *Conn) !void {
        while (c.nextEvent()) |e| switch (e) {
            .stream_readable => |slot| {
                if (c.stream(slot).kind != .client_bidi) {
                    c.streamConsume(slot, c.streamReadable(slot).len);
                    continue;
                }
                if (c.streamResetCode(slot) != null) {
                    c.resetSend(slot, 0x10c);
                    c.releaseStream(slot);
                    continue;
                }
                // Uploads are consumed as they arrive, or the window
                // never reopens.
                const avail = c.streamReadable(slot);
                if (sums[slot].active or std.mem.startsWith(u8, avail, "sum")) {
                    sums[slot].active = true;
                    for (avail) |b| sums[slot].sum +%= b;
                    sums[slot].len += avail.len;
                    c.streamConsume(slot, avail.len);
                    if (!c.stream(slot).recv.complete()) continue;
                    var out: [64]u8 = undefined;
                    try c.streamWrite(slot, try std.fmt.bufPrint(&out, "{d}:{d}", .{ sums[slot].len, sums[slot].sum }));
                    sums[slot] = .{};
                    c.streamFinish(slot);
                    c.releaseStream(slot);
                    continue;
                }
                if (!c.stream(slot).recv.complete()) continue;
                const req = c.streamReadable(slot);
                if (std.mem.startsWith(u8, req, "big ")) {
                    const n = try std.fmt.parseInt(usize, req[4..], 10);
                    c.streamConsume(slot, req.len);
                    var buf: [4096]u8 = undefined;
                    var written: usize = 0;
                    while (written < n) {
                        const k = @min(buf.len, n - written);
                        for (buf[0..k], 0..) |*b, i| b.* = @truncate(written + i);
                        try c.streamWrite(slot, buf[0..k]);
                        written += k;
                    }
                } else {
                    try c.streamWrite(slot, "echo:");
                    try c.streamWrite(slot, req);
                    c.streamConsume(slot, req.len);
                }
                c.streamFinish(slot);
                c.releaseStream(slot);
            },
            else => {},
        };
    }
};

const Harness = struct {
    a: std.mem.Allocator,
    creds: credentials.Credentials,
    tls_cfg: handshake.Config,
    cfg: conn_mod.Config,
    server: ?*Conn = null,
    client: *Client,
    now: u64 = 1_000_000,
    prng: std.Random.DefaultPrng,
    /// Percent of datagrams dropped in each direction.
    loss: u8 = 0,
    datagrams_to_server: usize = 0,
    datagrams_to_client: usize = 0,
    bytes_to_client: usize = 0,
    first_datagram_len: usize = 0,
    /// ECN on the path: the codepoint the client's datagrams arrive
    /// with; the server's marks cleared (`bleach`), its marked datagrams
    /// dropped (`drop_marked`), or `ce_marks` of them marked CE, one in
    /// every `ce_every` (the first and last at `ce_first`, `ce_last`).
    client_ecn: packet.Ecn = .not_ect,
    bleach: bool = false,
    drop_marked: bool = false,
    ce_marks: u32 = 0,
    ce_every: u32 = 1,
    ce_skipped: u32 = 0,
    ce_first: u64 = 0,
    ce_last: u64 = 0,
    /// The path's maximum datagram size towards the client: larger ones
    /// are dropped (DF set, no ICMP). The largest the server sent, and
    /// how many were too large.
    path_max: usize = std.math.maxInt(usize),
    largest_to_client: usize = 0,
    too_big: usize = 0,
    /// The client is at an IPv6 address; the worker's socket sets DF for it.
    ipv6: bool = false,
    dont_fragment: bool = true,
    /// Until then, every datagram is lost both ways (an outage).
    outage_until: u64 = 0,
    /// The server's interface: larger datagrams are refused (EMSGSIZE,
    /// in `runDelayed`), and how many were.
    iface_max: usize = std.math.maxInt(usize),
    refused: usize = 0,

    fn init(client_opts: test_client.Options, tweak: anytype) !*Harness {
        const a = testing.allocator;
        EchoApp.sums = @splat(.{});
        const h = try a.create(Harness);
        errdefer a.destroy(h);
        const td = credentials.testdata;
        h.* = .{
            .a = a,
            .creds = try .fromPem(a, td.p256_cert, td.p256_key),
            .tls_cfg = undefined,
            .cfg = undefined,
            .client = try Client.init(a, client_opts),
            .prng = .init(42),
        };
        h.tls_cfg = .{ .credentials = &h.creds, .alpn = &.{"h3"}, .quic = true, .groups = &.{.x25519} };
        h.cfg = .{ .tls = &h.tls_cfg };
        tweak(&h.cfg);
        return h;
    }

    fn deinit(h: *Harness) void {
        if (h.server) |s| s.deinit();
        h.client.deinit();
        h.creds.deinit();
        h.a.destroy(h);
    }

    fn dropped(h: *Harness) bool {
        return h.loss > 0 and h.prng.random().uintLessThan(u8, 100) < h.loss;
    }

    fn toServer(h: *Harness, dgram: []u8) !void {
        if (h.now < h.outage_until) return;
        h.datagrams_to_server += 1;
        if (h.server == null) {
            const hdr = try packet.parseHeader(dgram, 8);
            var entropy: [handshake.entropy_len]u8 = @splat(9);
            h.server = try Conn.init(h.a, &h.cfg, .{
                .odcid = hdr.dcid,
                .client_scid = hdr.scid,
                .scid = &server_cid,
                .reset_token = @splat(0xee),
                .entropy = &entropy,
                .now = h.now,
                .ipv6 = h.ipv6,
                .dont_fragment = h.dont_fragment,
            });
            h.first_datagram_len = dgram.len;
        }
        _ = h.server.?.recv(dgram, h.client_ecn, h.now);
        try EchoApp.run(h.server.?);
    }

    /// A datagram from the server, sent with `ecn`, over the path.
    fn toClient(h: *Harness, dgram: []const u8, ecn: packet.Ecn) !void {
        if (h.now < h.outage_until) return;
        h.largest_to_client = @max(h.largest_to_client, dgram.len);
        if (dgram.len > h.path_max) {
            h.too_big += 1;
            return;
        }
        var arrived = ecn;
        if (ecn != .not_ect) {
            if (h.drop_marked) return;
            if (h.bleach) arrived = .not_ect;
            if (h.ce_marks > 0) {
                h.ce_skipped += 1;
                if (h.ce_skipped >= h.ce_every) {
                    h.ce_skipped = 0;
                    h.ce_marks -= 1;
                    arrived = .ce;
                    if (h.ce_first == 0) h.ce_first = h.now;
                    h.ce_last = h.now;
                }
            }
        }
        try h.client.recvEcn(dgram, arrived);
    }

    /// Exchanges datagrams until neither side has anything to send, then
    /// runs the server's timers. Returns after `rounds` exchanges.
    fn run(h: *Harness, rounds: usize) !void {
        var buf: [1500]u8 = undefined;
        for (0..rounds) |_| {
            var progress = false;
            // Client to server.
            while (true) {
                const n = try h.client.send(&buf);
                if (n == 0) break;
                progress = true;
                if (!h.dropped()) try h.toServer(buf[0..n]);
            }
            // Server to client.
            if (h.server) |s| {
                while (true) {
                    const ecn = s.sendEcn();
                    const n = s.send(&buf, h.now);
                    if (n == 0) break;
                    progress = true;
                    h.datagrams_to_client += 1;
                    h.bytes_to_client += n;
                    if (!h.dropped()) try h.toClient(buf[0..n], ecn);
                }
                if (s.isClosed()) return;
            }
            h.now += 1000;
            if (!progress) {
                // Quiet: jump to the server's next deadline, and let the
                // client resend what is still unacknowledged.
                if (h.server) |s| {
                    // Timers a quiet connection would reach soon (loss and
                    // probe timeouts), not the idle timeout.
                    if (s.deadline()) |d| if (d < h.now + 2 * std.time.us_per_s) {
                        if (d > h.now) h.now = d;
                        s.onTimeout(h.now);
                        try EchoApp.run(s);
                    };
                }
                try h.client.retransmit();
            }
        }
    }

    /// Runs both ends over a path with a one-way delay of `delay` µs, the
    /// clock jumping from event to event (arrivals and the server's
    /// deadlines), until `done` holds. A connection with nothing in
    /// flight and no deadline before its idle timeout has stalled. Records
    /// what the server sent at each instant.
    fn runDelayed(h: *Harness, delay: u64, ctx: anytype, comptime done: fn (@TypeOf(ctx), *Harness) bool, bursts: *std.ArrayList(Burst)) !void {
        var queue: std.ArrayList(Flight) = .empty;
        defer queue.deinit(h.a);
        var head: usize = 0;
        const limit = h.now + 60 * std.time.us_per_s;
        var buf: [1500]u8 = undefined;
        while (!done(ctx, h)) {
            if (h.now > limit) return error.Timeout;
            while (true) {
                const n = try h.client.send(&buf);
                if (n == 0) break;
                try queue.append(h.a, .{ .at = h.now + delay, .to_server = true, .len = n, .buf = buf });
            }
            if (h.server) |s| {
                if (s.isClosed()) return error.Closed;
                const tokens = s.pacer.available(h.now, &s.cc, &s.rtt);
                var bytes: u64 = 0;
                while (true) {
                    const in_flight = s.cc.in_flight;
                    const ecn = s.sendEcn();
                    const mark = s.sendMark();
                    const max = s.max_datagram;
                    const n = s.send(&buf, h.now);
                    if (n == 0) break;
                    if (n > h.iface_max) {
                        // The interface refuses it, as the endpoint reports.
                        if (n > max) {
                            s.onProbeTooBig(h.now);
                        } else if (!s.onSendRefused(mark, n, h.now)) {
                            continue;
                        }
                        h.refused += 1;
                        continue;
                    }
                    bytes += s.cc.in_flight -| in_flight;
                    try queue.append(h.a, .{ .at = h.now + delay, .to_server = false, .len = n, .buf = buf, .ecn = ecn });
                }
                if (bytes > 0) try bursts.append(h.a, .{ .at = h.now, .bytes = bytes, .tokens = tokens, .window = s.cc.window });
            }
            var next: ?u64 = if (head < queue.items.len) queue.items[head].at else null;
            var timer: ?u64 = null;
            if (h.server) |s| {
                if (s.deadline()) |d| if (d < h.now + 2 * std.time.us_per_s) {
                    timer = @max(d, h.now);
                    next = if (next) |x| @min(x, timer.?) else timer;
                };
            }
            h.now = next orelse return error.Stalled;
            while (head < queue.items.len and queue.items[head].at <= h.now) : (head += 1) {
                const f = &queue.items[head];
                if (f.to_server) try h.toServer(f.buf[0..f.len]) else try h.toClient(f.buf[0..f.len], f.ecn);
            }
            if (timer) |t| if (t <= h.now) {
                h.server.?.onTimeout(h.now);
                try EchoApp.run(h.server.?);
            };
        }
    }
};

/// A datagram on its way over a delayed path.
const Flight = struct { at: u64, to_server: bool, len: usize, buf: [1500]u8, ecn: packet.Ecn = .not_ect };

/// In-flight bytes the server sent at one instant, what its pacer had
/// then, and its congestion window.
const Burst = struct { at: u64, bytes: u64, tokens: u64, window: u64 };

fn noTweak(_: *conn_mod.Config) void {}

fn noPacing(c: *conn_mod.Config) void {
    c.pacing = false;
}

test "QUIC handshake: keys, ALPN, transport parameters, HANDSHAKE_DONE" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    try h.run(20);
    const s = h.server.?;
    try testing.expect(s.isEstablished());
    try testing.expect(h.client.handshake_complete);
    try testing.expect(h.client.handshake_done);
    try testing.expectEqualStrings("h3", h.client.alpn.?);
    try testing.expectEqualStrings("h3", s.alpn().?);
    // The server's parameters name both connection IDs and a reset token.
    try testing.expectEqualSlices(u8, &h.client.opts.dcid, h.client.serverParam(0x00).?);
    try testing.expectEqualSlices(u8, &server_cid, h.client.serverParam(0x0f).?);
    try testing.expectEqual(@as(usize, 16), h.client.serverParam(0x02).?.len);
    // Initial and Handshake keys are gone on the server.
    try testing.expect(s.spaces[0].discarded and s.spaces[1].discarded);
    try testing.expect(h.first_datagram_len >= 1200);
}

test "QUIC streams: requests are answered, many at once" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    try h.run(10);
    var ids: [40]u64 = undefined;
    for (&ids, 0..) |*id, i| {
        id.* = try h.client.openBidi();
        var msg: [32]u8 = undefined;
        try h.client.write(id.*, try std.fmt.bufPrint(&msg, "request {d}", .{i}), true);
    }
    try h.run(50);
    for (ids, 0..) |id, i| {
        var want: [32]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "echo:request {d}", .{i}), h.client.readAll(id));
        try testing.expect(h.client.finished(id));
    }
    // Every stream was freed, and credit for more was granted.
    const s = h.server.?;
    try testing.expectEqual(@as(u64, 40), s.bidi_closed);
    try testing.expect(h.client.max_streams_bidi >= 100 + 25);
}

test "QUIC flow control: a 3 MB upload through 1 MB stream windows" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    try h.run(10);
    const id = try h.client.openBidi();
    const big = try testing.allocator.alloc(u8, 3 * 1024 * 1024);
    defer testing.allocator.free(big);
    var sum: u64 = 0;
    @memcpy(big[0..3], "sum");
    for (big[3..], 3..) |*b, i| b.* = @truncate(i * 7);
    for (big) |b| sum +%= b;
    try h.client.write(id, big, true);
    try h.run(3000);
    var want: [64]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "{d}:{d}", .{ big.len, sum }), h.client.readAll(id));
}

test "QUIC flow control: lost stream credit is sent again (an upload blocked at its window)" {
    // The server's MAX_STREAM_DATA (and every other datagram of its) lost
    // while the client fills its 1 MB window: the stream has nothing else
    // to send, so the credit must be queued again when declared lost, or
    // the client waits forever (it did, with aioquic under load).
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    try h.run(10);
    const id = try h.client.openBidi();
    const big = try testing.allocator.alloc(u8, 3 * 1024 * 1024);
    defer testing.allocator.free(big);
    var sum: u64 = 0;
    @memcpy(big[0..3], "sum");
    for (big[3..], 3..) |*b, i| b.* = @truncate(i * 7);
    for (big) |b| sum +%= b;
    try h.client.write(id, big, true);
    h.path_max = 0;
    try h.run(30);
    try testing.expectEqual(@as(u64, 1 << 20), (try h.client.getStream(id)).send.max_data);
    h.path_max = std.math.maxInt(usize);
    try h.run(4000);
    var want: [64]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "{d}:{d}", .{ big.len, sum }), h.client.readAll(id));
}

test "QUIC download: 2 MB response under congestion control" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, noTweak);
    defer h.deinit();
    try h.run(10);
    const id = try h.client.openBidi();
    try h.client.write(id, "big 2000000", true);
    try h.run(5000);
    const got = h.client.readAll(id);
    try testing.expectEqual(@as(usize, 2_000_000), got.len);
    for (got, 0..) |b, i| try testing.expectEqual(@as(u8, @truncate(i)), b);
    try testing.expect(h.client.finished(id));
    // The window grew past its initial ten datagrams.
    try testing.expect(h.server.?.cc.window > 12000);
}

test "QUIC loss: 15% of datagrams dropped both ways" {
    for (0..4) |seed| {
        const h = try Harness.init(.{ .seed = @intCast(seed + 1), .max_stream_data = 8 << 20 }, noTweak);
        defer h.deinit();
        h.prng = .init(seed);
        h.loss = 15;
        try h.run(200);
        try testing.expect(h.server.?.isEstablished());
        var ids: [10]u64 = undefined;
        for (&ids, 0..) |*id, i| {
            id.* = try h.client.openBidi();
            var msg: [32]u8 = undefined;
            try h.client.write(id.*, try std.fmt.bufPrint(&msg, "req {d}", .{i}), true);
        }
        const big = try h.client.openBidi();
        try h.client.write(big, "big 300000", true);
        try h.run(4000);
        for (ids, 0..) |id, i| {
            var want: [32]u8 = undefined;
            try testing.expectEqualStrings(try std.fmt.bufPrint(&want, "echo:req {d}", .{i}), h.client.readAll(id));
        }
        try testing.expectEqual(@as(usize, 300000), h.client.readAll(big).len);
        try testing.expect(h.server.?.lost_packets > 0);
    }
}

test "QUIC key update started by the client" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    try h.run(10);
    h.client.initiateKeyUpdate();
    // The server answers in the new phase: the client must follow.
    h.client.followKeyUpdate();
    const id = try h.client.openBidi();
    try h.client.write(id, "after update", true);
    try h.run(20);
    try testing.expectEqualStrings("echo:after update", h.client.readAll(id));
    try testing.expectEqual(@as(u1, 1), h.server.?.rx_phase);
    try testing.expectEqual(@as(u1, 1), h.server.?.tx_phase);
}

test "QUIC errors: stream limit, frame encoding, stream state, parameters" {
    {
        // A stream beyond the advertised limit (100 bidirectional).
        const h = try Harness.init(.{}, noTweak);
        defer h.deinit();
        try h.run(10);
        try h.client.injectFrames(&.{ 0x0b, 0x80, 0x00, 0x01, 0x90, 1, 'x' }); // stream 400
        try h.run(5);
        try testing.expectEqual(@as(u64, 0x4), h.client.closed.?.code);
    }
    {
        // An unknown frame type.
        const h = try Harness.init(.{}, noTweak);
        defer h.deinit();
        try h.run(10);
        try h.client.injectFrames(&.{0x1f});
        try h.run(5);
        try testing.expectEqual(@as(u64, 0x7), h.client.closed.?.code);
    }
    {
        // STREAM on our own unidirectional stream.
        const h = try Harness.init(.{}, noTweak);
        defer h.deinit();
        try h.run(10);
        try h.client.injectFrames(&.{ 0x0b, 0x03, 1, 'x' });
        try h.run(5);
        try testing.expectEqual(@as(u64, 0x5), h.client.closed.?.code);
    }
    {
        // A transport parameter only servers may send.
        const h = try Harness.init(.{ .transport_params = &.{ 0x00, 0x01, 0xaa, 0x0f, 0x04, 0xc1, 0xc2, 0xc3, 0xc4 } }, noTweak);
        defer h.deinit();
        try h.run(10);
        try testing.expectEqual(@as(u64, 0x8), h.client.closed.?.code);
    }
    {
        // A wrong initial_source_connection_id.
        const h = try Harness.init(.{ .transport_params = &.{ 0x0f, 0x04, 1, 2, 3, 4 } }, noTweak);
        defer h.deinit();
        try h.run(10);
        try testing.expectEqual(@as(u64, 0x8), h.client.closed.?.code);
    }
    {
        // No common application protocol: CRYPTO_ERROR(no_application_protocol).
        const h = try Harness.init(.{ .alpn = "h2" }, noTweak);
        defer h.deinit();
        try h.run(10);
        try testing.expectEqual(@as(u64, 0x100 + 120), h.client.closed.?.code);
    }
    {
        // Flow control: past the stream window without credit.
        const h = try Harness.init(.{}, struct {
            fn f(c: *conn_mod.Config) void {
                c.max_stream_data_bidi = 1000;
            }
        }.f);
        defer h.deinit();
        try h.run(10);
        try h.client.injectFrames(&.{ 0x0e, 0x00, 0x44, 0x00, 0x01, 'x' }); // offset 1024
        try h.run(5);
        try testing.expectEqual(@as(u64, 0x3), h.client.closed.?.code);
    }
}

test "QUIC amplification limit before the address is validated" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    // Deliver only the client's first datagram; never answer.
    var buf: [1500]u8 = undefined;
    const n = try h.client.send(&buf);
    try h.toServer(buf[0..n]);
    const s = h.server.?;
    var sent: usize = 0;
    for (0..20) |_| {
        while (true) {
            const k = s.send(&buf, h.now);
            if (k == 0) break;
            sent += k;
        }
        if (s.deadline()) |d| h.now = @max(h.now, d);
        s.onTimeout(h.now);
        if (s.isClosed()) break;
    }
    try testing.expect(sent > 0);
    try testing.expect(sent <= 3 * n);
}

test "QUIC idle timeout closes the connection" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    try testing.expect(s.isEstablished());
    h.now += 31 * std.time.us_per_s;
    s.onTimeout(h.now);
    try testing.expect(s.isClosed());
}

fn established(_: void, h: *Harness) bool {
    return h.client.handshake_done and h.server != null and h.server.?.isEstablished();
}

fn finishedStream(id: u64, h: *Harness) bool {
    return h.client.finished(id);
}

test "QUIC pacing: a download over a 50 ms path leaves in paced bursts" {
    var largest_paced: u64 = 0;
    var duration_paced: u64 = 0;
    inline for (.{ true, false }) |pacing| {
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, if (pacing) noTweak else noPacing);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(testing.allocator);
        try h.runDelayed(25_000, {}, established, &bursts);
        const s = h.server.?;
        try testing.expect(s.rtt.smoothed >= 50_000);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 1500000", true);
        bursts.clearRetainingCapacity();
        const began = h.now;
        // Completing at all shows the pacer's deadline brings the
        // connection back: with everything acknowledged and data held
        // back, nothing else would.
        try h.runDelayed(25_000, id, finishedStream, &bursts);
        const duration = h.now - began;
        const got = h.client.readAll(id);
        try testing.expectEqual(@as(usize, 1_500_000), got.len);
        for (got, 0..) |b, i| try testing.expectEqual(@as(u8, @truncate(i)), b);
        var largest: u64 = 0;
        for (bursts.items) |b| largest = @max(largest, b.bytes);
        // No probe timeouts, no spurious losses: every packet arrived.
        try testing.expectEqual(@as(u64, 0), s.lost_packets);
        if (pacing) {
            try testing.expect(s.paced_waits > 0);
            for (bursts.items) |b| {
                // Never more than the pacer had at that instant, which is
                // at most 2 ms of 1.25 · cwnd / 50 ms (and at least ten
                // datagrams).
                try testing.expect(b.bytes <= b.tokens);
                try testing.expect(b.tokens <= @max(10 * @as(u64, s.max_datagram), b.window / 20 + s.max_datagram));
            }
            largest_paced = largest;
            duration_paced = duration;
        } else {
            // Unpaced, slow start sends each round trip's window at once.
            try testing.expectEqual(@as(u64, 0), s.paced_waits);
            try testing.expect(largest > 4 * largest_paced);
            // Pacing costs at most a little time.
            try testing.expect(duration_paced < duration + duration / 4 + 50_000);
        }
    }
}

test "QUIC pacing: ACKs and probes don't wait; the pacer's timer releases data" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    var buf: [1500]u8 = undefined;
    const id = try h.client.openBidi();
    try h.client.write(id, "big 200000", true);
    try h.toServer(buf[0..try h.client.send(&buf)]);
    // An empty pacer holds the response back; the request alone doesn't
    // make an ACK due yet.
    s.pacer.tokens = 0;
    s.pacer.last = h.now;
    try testing.expectEqual(@as(usize, 0), s.send(&buf, h.now));
    try testing.expect(s.paced_waits > 0);
    const due = s.deadline().?;
    try testing.expectEqual(s.pacing_hold.?, due);
    try testing.expect(due > h.now and due < h.now + s.cfg.max_ack_delay_ms * 1000);

    // Two more ack-eliciting packets: the ACK is due now and goes alone.
    for (0..2) |_| {
        try h.client.injectFrames(&.{0x01}); // PING
        try h.toServer(buf[0..try h.client.send(&buf)]);
    }
    const in_flight = s.cc.in_flight;
    const ack = s.send(&buf, h.now);
    try testing.expect(ack > 0);
    try testing.expectEqual(in_flight, s.cc.in_flight);
    try h.client.recv(buf[0..ack]);
    try testing.expect(!s.spaces[2].ack_wanted);
    try testing.expectEqual(@as(usize, 0), s.send(&buf, h.now));
    try testing.expectEqual(due, s.deadline().?);

    // The timer fires: the data goes, a burst of it.
    h.now = due;
    s.onTimeout(h.now);
    var sent: usize = 0;
    while (true) {
        const n = s.send(&buf, h.now);
        if (n == 0) break;
        sent += 1;
    }
    try testing.expect(sent >= 2);
    try testing.expect(s.cc.in_flight > in_flight);

    // All of it is lost. The probe timeout's probes go out though the
    // pacer is empty again.
    const pto = s.loss_timer.?;
    h.now = pto;
    s.onTimeout(h.now);
    s.pacer.tokens = 0;
    s.pacer.last = h.now;
    for (0..2) |_| {
        const before = s.cc.in_flight;
        try testing.expect(s.send(&buf, h.now) > 0);
        try testing.expect(s.cc.in_flight > before);
    }
    try testing.expectEqual(@as(u8, 0), s.spaces[2].probes);
    try testing.expectEqual(@as(usize, 0), s.send(&buf, h.now));
    // And the rest still follows when the pacer allows.
    try h.run(400);
    try testing.expectEqual(@as(usize, 200_000), h.client.readAll(id).len);
}

test "QUIC pacing: no busy loop while the amplification limit leaves a few bytes" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    // Only the client's first datagram arrives; the client then goes quiet.
    var buf: [1500]u8 = undefined;
    try h.toServer(buf[0..try h.client.send(&buf)]);
    const s = h.server.?;
    while (s.send(&buf, h.now) > 0) {}
    // 30 bytes of budget left (a long first flight), the pacer dry.
    s.bytes_sent = 3 * s.bytes_received - 30;
    s.pacer.tokens = 0;
    for (0..20) |_| {
        // A probe timeout makes the handshake data pending again, but too
        // little budget is left to send any of it.
        try testing.expectEqual(@as(usize, 0), s.send(&buf, h.now));
        // Every deadline is ahead: a timer that fires doesn't come straight
        // back with nothing to do.
        const d = s.deadline() orelse break;
        try testing.expect(d > h.now);
        h.now = d;
        s.onTimeout(h.now);
        if (s.isClosed()) break;
    }
}

test "QUIC pacing: a small window waits only for the room it has" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    // After persistent congestion on a 100 ms path: two datagrams of window.
    s.rtt = .{};
    s.rtt.update(100_000, 0);
    s.cc.onPersistentCongestion();
    s.pacer.tokens = 0;
    s.pacer.last = h.now;
    var buf: [1500]u8 = undefined;
    const id = try h.client.openBidi();
    try h.client.write(id, "big 100000", true);
    try h.toServer(buf[0..try h.client.send(&buf)]);
    // Two more ack-eliciting packets so the ACK goes now and doesn't set
    // the next deadline.
    for (0..2) |_| {
        try h.client.injectFrames(&.{0x01});
        try h.toServer(buf[0..try h.client.send(&buf)]);
    }
    while (s.send(&buf, h.now) > 0) {}
    try testing.expect(s.cc.in_flight < s.cc.window);
    // 1.25 · 2400 bytes / 100 ms is 0.03 bytes/µs: the window's room comes
    // back in at most 80 ms (half the ten-datagram bucket would take 200).
    const d = s.deadline().?;
    try testing.expect(d > h.now and d <= h.now + 80_000);
    h.now = d;
    s.onTimeout(h.now);
    const in_flight = s.cc.in_flight;
    try testing.expect(s.send(&buf, h.now) > 0);
    try testing.expect(s.cc.in_flight > in_flight);
}

test "QUIC pacing: streams blocked by flow control don't arm the pacer's timer" {
    const h = try Harness.init(.{ .max_data = 20_000 }, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    const id = try h.client.openBidi();
    try h.client.write(id, "big 100000", true);
    try h.run(50);
    // The response waits for connection credit the client never gives.
    try testing.expect(h.client.readAll(id).len < 100_000);
    try testing.expectEqual(s.tx_max_data, s.tx_data);
    var buf: [1500]u8 = undefined;
    while (s.send(&buf, h.now) > 0) {}
    const before = s.deadline();
    const waits = s.paced_waits;
    s.pacer.tokens = 0;
    s.pacer.last = h.now;
    try testing.expectEqual(@as(usize, 0), s.send(&buf, h.now));
    try testing.expectEqual(before, s.deadline());
    try testing.expectEqual(waits, s.paced_waits);
}

test "QUIC pacing: a PATH_RESPONSE doesn't wait for the pacer" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    s.pacer.tokens = 0;
    s.pacer.last = h.now;
    var buf: [1500]u8 = undefined;
    try h.client.injectFrames(&.{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8 }); // PATH_CHALLENGE
    try h.toServer(buf[0..try h.client.send(&buf)]);
    const n = s.send(&buf, h.now);
    try testing.expect(n > 0);
    try h.client.recv(buf[0..n]);
    try testing.expectEqual(@as(u32, 1), h.client.path_responses);
}

test "QUIC pacing: a hold is timed after the datagram's last packet, and counted once" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    var buf: [1500]u8 = undefined;
    const id = try h.client.openBidi();
    try h.client.write(id, "big 100000", true);
    try h.toServer(buf[0..try h.client.send(&buf)]);
    // A path where the wait is for half the bucket (the window has room
    // for much more), and not quite a datagram's worth of tokens: the
    // response waits, but a PATH_RESPONSE goes, and it takes its tokens.
    s.rtt = .{};
    s.rtt.update(100_000, 0);
    s.cc.window = 1_200_000;
    s.pacer.tokens = s.max_datagram - 100;
    s.pacer.last = h.now;
    try h.client.injectFrames(&.{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8 });
    try h.toServer(buf[0..try h.client.send(&buf)]);
    const waits = s.paced_waits;
    try testing.expect(s.send(&buf, h.now) > 0);
    try testing.expect(s.pacer.tokens < s.max_datagram - 100);
    try testing.expectEqual(s.pacer.nextSend(s.max_datagram, s.cc.window - s.cc.in_flight, &s.cc, &s.rtt), s.pacing_hold);
    // More sends while it waits are the same wait.
    for (0..5) |_| try testing.expectEqual(@as(usize, 0), s.send(&buf, h.now));
    try testing.expectEqual(waits + 1, s.paced_waits);
}

// -- Adversarial pacing checks (verifier) ------------------------------------

test "verify pacing: an amplification budget under 64 bytes leaves no deadline in the past" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    var buf: [1500]u8 = undefined;
    try h.toServer(buf[0..try h.client.send(&buf)]);
    const s = h.server.?;
    // The first flight goes out (within the amplification limit).
    while (s.send(&buf, h.now) > 0) {}
    try testing.expect(!s.address_validated);
    // Data waiting in 1-RTT, a dry pacer, and 30 bytes of budget left.
    s.max_data_pending = true;
    s.pacer.tokens = 0;
    s.pacer.last = h.now;
    s.bytes_sent = 3 * s.bytes_received - 30;
    try testing.expectEqual(@as(usize, 0), s.send(&buf, h.now));
    // The endpoint's loop: wake at the deadline, onTimeout, send, re-arm.
    var wakeups: usize = 0;
    const start = h.now;
    while (h.now < start + 500_000) {
        const d = s.deadline() orelse break;
        if (d >= start + 500_000) break;
        if (d <= h.now) wakeups += 1;
        h.now = @max(h.now + 1, d);
        s.onTimeout(h.now);
        _ = s.send(&buf, h.now);
    }
    // A deadline that stays due while send can do nothing is a busy loop
    // (the endpoint polls with a 0 ms timeout).
    if (wakeups >= 5) std.debug.print("amplification: {d} wakeups with the deadline already due (deadline {d} us, now {d} us)\n", .{ wakeups, s.deadline().?, h.now });
    // It lasts until the connection gives up (nothing else changes).
    var due_ms: usize = 0;
    while (!s.isClosed()) {
        const d = s.deadline() orelse break;
        if (d <= h.now) due_ms += 1;
        h.now = @max(h.now + 1000, d);
        s.onTimeout(h.now);
        _ = s.send(&buf, h.now);
    }
    if (wakeups >= 5) std.debug.print("amplification: still due in {d} of the following 1 ms steps, until closed at {d} s\n", .{ due_ms, (h.now - start) / std.time.us_per_s });
    try testing.expect(wakeups < 5);
}

/// runDelayed with server-to-client loss.
fn runLossy(h: *Harness, delay: u64, loss: u8, id: u64) !void {
    var queue: std.ArrayList(Flight) = .empty;
    defer queue.deinit(h.a);
    var head: usize = 0;
    const limit = h.now + 120 * std.time.us_per_s;
    var buf: [1500]u8 = undefined;
    var hold_woke = false;
    while (!h.client.finished(id)) {
        if (h.now > limit) return error.Timeout;
        while (true) {
            const n = try h.client.send(&buf);
            if (n == 0) break;
            try queue.append(h.a, .{ .at = h.now + delay, .to_server = true, .len = n, .buf = buf });
        }
        const s = h.server.?;
        if (s.isClosed()) return error.Closed;
        var sent_now: usize = 0;
        while (true) {
            const ecn = s.sendEcn();
            const n = s.send(&buf, h.now);
            if (n == 0) break;
            sent_now += 1;
            if (h.prng.random().uintLessThan(u8, 100) < loss) continue;
            try queue.append(h.a, .{ .at = h.now + delay, .to_server = false, .len = n, .buf = buf, .ecn = ecn });
        }
        // A hold is always ahead of the send that set it.
        if (s.pacing_hold) |d| try testing.expect(d > h.now);
        if (hold_woke and sent_now == 0) lossy_idle_wakeups += 1;
        hold_woke = false;
        var next: ?u64 = if (head < queue.items.len) queue.items[head].at else null;
        var timer: ?u64 = null;
        if (s.deadline()) |d| if (d < h.now + 10 * std.time.us_per_s) {
            timer = @max(d, h.now);
            next = if (next) |x| @min(x, timer.?) else timer;
        };
        h.now = next orelse return error.Stalled;
        while (head < queue.items.len and queue.items[head].at <= h.now) : (head += 1) {
            const f = &queue.items[head];
            if (f.to_server) try h.toServer(f.buf[0..f.len]) else try h.toClient(f.buf[0..f.len], f.ecn);
        }
        if (timer) |t| if (t <= h.now) {
            if (s.pacing_hold) |ph| if (ph == t) {
                hold_woke = true;
                lossy_hold_wakeups += 1;
            };
            s.onTimeout(h.now);
            try EchoApp.run(s);
        };
    }
}

var lossy_hold_wakeups: usize = 0;
var lossy_idle_wakeups: usize = 0;

test "verify pacing: downloads complete with loss over delayed paths, paced within 2x" {
    const Case = struct { delay: u64, loss: u8, size: usize };
    const cases = [_]Case{
        .{ .delay = 10_000, .loss = 5, .size = 1_000_000 },
        .{ .delay = 25_000, .loss = 15, .size = 400_000 },
        .{ .delay = 1, .loss = 10, .size = 1_000_000 },
        .{ .delay = 250_000, .loss = 3, .size = 300_000 },
        .{ .delay = 2_000, .loss = 1, .size = 2_000_000 },
        .{ .delay = 250_000, .loss = 0, .size = 300_000 },
        .{ .delay = 100_000, .loss = 0, .size = 2_000_000 },
    };
    for (cases) |cs| {
        for (0..3) |seed| {
            var durations: [2]u64 = undefined;
            inline for (.{ true, false }, 0..) |pacing, pi| {
                const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, if (pacing) noTweak else noPacing);
                defer h.deinit();
                h.prng = .init(seed * 7 + 3);
                var bursts: std.ArrayList(Burst) = .empty;
                defer bursts.deinit(testing.allocator);
                try h.runDelayed(cs.delay, {}, established, &bursts);
                const id = try h.client.openBidi();
                var req: [32]u8 = undefined;
                try h.client.write(id, try std.fmt.bufPrint(&req, "big {d}", .{cs.size}), true);
                const began = h.now;
                runLossy(h, cs.delay, cs.loss, id) catch |e| {
                    std.debug.print("case delay={d} loss={d} seed={d} pacing={}: {s}\n", .{ cs.delay, cs.loss, seed, pacing, @errorName(e) });
                    return e;
                };
                durations[pi] = h.now - began;
                try testing.expectEqual(cs.size, h.client.readAll(id).len);
            }
            // Paced is 0-15% slower on clean long paths (slow start at 1.25 ·
            // cwnd / srtt), up to 57% at a 500 ms RTT with 3% loss.
            try testing.expect(durations[0] <= 2 * durations[1] + 4 * cs.delay);
            // Every time the pacer's timer fired, there was something to send.
            try testing.expectEqual(@as(usize, 0), lossy_idle_wakeups);
            lossy_hold_wakeups = 0;
            lossy_idle_wakeups = 0;
        }
    }
}

test "verify pacing: a stream blocked by flow control doesn't keep the timer busy" {
    const h = try Harness.init(.{ .max_stream_data = 100_000, .max_data = 16 << 20 }, noTweak);
    defer h.deinit();
    var bursts: std.ArrayList(Burst) = .empty;
    defer bursts.deinit(testing.allocator);
    try h.runDelayed(20_000, {}, established, &bursts);
    const id = try h.client.openBidi();
    try h.client.write(id, "big 1000000", true);
    // Run 3 s of the delayed path; count server timer wakeups.
    var queue: std.ArrayList(Flight) = .empty;
    defer queue.deinit(h.a);
    var head: usize = 0;
    var buf: [1500]u8 = undefined;
    const s = h.server.?;
    const start = h.now;
    var wakeups: usize = 0;
    while (h.now < start + 3 * std.time.us_per_s) {
        while (true) {
            const n = try h.client.send(&buf);
            if (n == 0) break;
            try queue.append(h.a, .{ .at = h.now + 20_000, .to_server = true, .len = n, .buf = buf });
        }
        while (true) {
            const ecn = s.sendEcn();
            const n = s.send(&buf, h.now);
            if (n == 0) break;
            try queue.append(h.a, .{ .at = h.now + 20_000, .to_server = false, .len = n, .buf = buf, .ecn = ecn });
        }
        var next: ?u64 = if (head < queue.items.len) queue.items[head].at else null;
        var timer: ?u64 = null;
        if (s.deadline()) |d| if (d < start + 3 * std.time.us_per_s) {
            timer = @max(d, h.now);
            next = if (next) |x| @min(x, timer.?) else timer;
        };
        h.now = next orelse break;
        while (head < queue.items.len and queue.items[head].at <= h.now) : (head += 1) {
            const f = &queue.items[head];
            if (f.to_server) try h.toServer(f.buf[0..f.len]) else try h.toClient(f.buf[0..f.len], f.ecn);
        }
        if (timer) |t| if (t <= h.now) {
            wakeups += 1;
            s.onTimeout(h.now);
            try EchoApp.run(s);
        };
    }
    try testing.expect(wakeups < 50);
}

test "verify pacing: pacer arithmetic at extremes" {
    var cc = recovery.Congestion.init(1200, .cubic);
    var rtt: recovery.Rtt = .{};
    var p = recovery.Pacer.init(1200, recovery.Pacer.default_burst_us);
    // Before any RTT sample.
    p.refill(0, &cc, &rtt);
    try testing.expectEqual(@as(u64, 12000), p.tokens);
    // A zero RTT, a huge window, a clock at its end.
    rtt.update(0, 0);
    cc.window = 1 << 40;
    p.refill(std.math.maxInt(u64), &cc, &rtt);
    try testing.expect(p.tokens >= 12000);
    p.onSent(std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, 0), p.tokens);
    const n = p.nextSend(1200, std.math.maxInt(u64), &cc, &rtt).?;
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), n);
    // Clock going backwards: no refill, no underflow.
    p.refill(5, &cc, &rtt);
    try testing.expectEqual(@as(u64, 0), p.tokens);
    // A huge RTT (an hour), the minimum window.
    rtt = .{};
    rtt.update(3600 * std.time.us_per_s, 0);
    cc.window = cc.minWindow();
    p = recovery.Pacer.init(1200, recovery.Pacer.default_burst_us);
    p.refill(1000, &cc, &rtt);
    p.onSent(12000);
    const due = p.nextSend(1200, std.math.maxInt(u64), &cc, &rtt).?;
    // 6000 bytes at 1.25 · 2400 B / hour.
    try testing.expect(due > 1000 + 3600 * std.time.us_per_s);
    // Long idle gap after.
    try testing.expectEqual(@as(u64, 12000), p.available(1000 + 1_000_000 * std.time.us_per_s, &cc, &rtt));
    // Burst setting of 0.
    var p0 = recovery.Pacer.init(1200, 0);
    rtt = .{};
    rtt.update(50_000, 0);
    try testing.expectEqual(@as(u64, 12000), p0.capacity(&cc, &rtt));
    p0.refill(0, &cc, &rtt);
    p0.onSent(12000);
    try testing.expect(p0.nextSend(1200, std.math.maxInt(u64), &cc, &rtt).? > 0);
    // No room in the window at all, and a zero-byte datagram.
    try testing.expect(p0.nextSend(1200, 0, &cc, &rtt).? > 0);
    try testing.expectEqual(@as(?u64, null), p0.nextSend(0, 0, &cc, &rtt));
}

test "verify pacing: CONNECTION_CLOSE goes at once while the pacer holds data back" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    var buf: [1500]u8 = undefined;
    const id = try h.client.openBidi();
    try h.client.write(id, "big 200000", true);
    try h.toServer(buf[0..try h.client.send(&buf)]);
    s.pacer.tokens = 0;
    s.pacer.last = h.now;
    try testing.expectEqual(@as(usize, 0), s.send(&buf, h.now));
    try testing.expect(s.deadline().? > h.now);
    s.closeApp(0x100, "bye", h.now);
    const n = s.send(&buf, h.now);
    try testing.expect(n > 0);
    try h.client.recv(buf[0..n]);
    try testing.expect(h.client.closed != null);
    // Closing: the deadline is the close timer, not the pacer.
    try testing.expectEqual(s.close_deadline, s.deadline());
}

test "verify pacing: a key update in the middle of a paced download over a 40 ms path" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, noTweak);
    defer h.deinit();
    var bursts: std.ArrayList(Burst) = .empty;
    defer bursts.deinit(testing.allocator);
    try h.runDelayed(20_000, {}, established, &bursts);
    const id = try h.client.openBidi();
    try h.client.write(id, "big 3000000", true);
    const Half = struct {
        fn f(want: u64, hh: *Harness) bool {
            return hh.client.readAll(want).len > 1_000_000;
        }
    };
    try h.runDelayed(20_000, id, Half.f, &bursts);
    h.client.initiateKeyUpdate();
    h.client.followKeyUpdate();
    try h.runDelayed(20_000, id, finishedStream, &bursts);
    try testing.expectEqual(@as(usize, 3_000_000), h.client.readAll(id).len);
    try testing.expectEqual(@as(u1, 1), h.server.?.rx_phase);
    try testing.expect(h.server.?.paced_waits > 0);
}

/// Like runLossy over several streams, checking after every send loop that
/// no deadline is already due while the server had nothing to send (a busy
/// loop in the worker) and that a hold is ahead of now.
fn runLossyMulti(h: *Harness, delay: u64, loss: u8, ids: []const u64) !void {
    var queue: std.ArrayList(Flight) = .empty;
    defer queue.deinit(h.a);
    var head: usize = 0;
    const limit = h.now + 300 * std.time.us_per_s;
    var buf: [1500]u8 = undefined;
    while (true) {
        var all = true;
        for (ids) |id| all = all and h.client.finished(id);
        if (all) return;
        if (h.now > limit) return error.Timeout;
        while (true) {
            const n = try h.client.send(&buf);
            if (n == 0) break;
            try queue.append(h.a, .{ .at = h.now + delay, .to_server = true, .len = n, .buf = buf });
        }
        const s = h.server.?;
        if (s.isClosed()) return error.Closed;
        while (true) {
            const ecn = s.sendEcn();
            const n = s.send(&buf, h.now);
            if (n == 0) break;
            if (h.prng.random().uintLessThan(u8, 100) < loss) continue;
            try queue.append(h.a, .{ .at = h.now + delay, .to_server = false, .len = n, .buf = buf, .ecn = ecn });
        }
        if (s.pacing_hold) |d| try testing.expect(d > h.now);
        if (s.deadline()) |d| if (d <= h.now) {
            // Due already: the worker would come straight back. Only fine
            // if that next send does something.
            s.onTimeout(h.now);
            const ecn = s.sendEcn();
            const n = s.send(&buf, h.now);
            if (n == 0 and !s.isClosed()) if (s.deadline()) |d2| if (d2 <= h.now) return error.BusyLoop;
            if (n > 0) try queue.append(h.a, .{ .at = h.now + delay, .to_server = false, .len = n, .buf = buf, .ecn = ecn });
        };
        var next: ?u64 = if (head < queue.items.len) queue.items[head].at else null;
        var timer: ?u64 = null;
        if (s.deadline()) |d| if (d < h.now + 10 * std.time.us_per_s) {
            timer = @max(d, h.now);
            next = if (next) |x| @min(x, timer.?) else timer;
        };
        h.now = next orelse return error.Stalled;
        while (head < queue.items.len and queue.items[head].at <= h.now) : (head += 1) {
            const f = &queue.items[head];
            if (f.to_server) try h.toServer(f.buf[0..f.len]) else try h.toClient(f.buf[0..f.len], f.ecn);
        }
        if (timer) |t| if (t <= h.now) {
            s.onTimeout(h.now);
            try EchoApp.run(s);
        };
    }
}

var random_burst_us: u64 = 0;
var random_pacing = true;
fn randomBurst(c: *conn_mod.Config) void {
    c.pacing_burst_us = random_burst_us;
    c.pacing = random_pacing;
}

test "verify pacing: random paths, losses and stream mixes all complete without a busy loop" {
    var prng: std.Random.DefaultPrng = .init(0x9ace);
    const r = prng.random();
    var fails: usize = 0;
    for (0..150) |iter| for ([_]bool{ true, false }) |pacing| {
        random_pacing = pacing;
        if (!pacing) prng = .init(0x9ace + iter * 1000) else prng = .init(0x9ace + iter * 1000);
        const delay: u64 = switch (r.uintLessThan(u8, 4)) {
            0 => 1 + r.uintLessThan(u64, 500),
            1 => 1000 + r.uintLessThan(u64, 5000),
            2 => 10_000 + r.uintLessThan(u64, 40_000),
            else => 50_000 + r.uintLessThan(u64, 150_000),
        };
        const loss = r.uintLessThan(u8, 12);
        random_burst_us = switch (r.uintLessThan(u8, 3)) {
            0 => 0,
            1 => 2000,
            else => 20_000,
        };
        const max_data: u64 = if (r.boolean()) 16 << 20 else 600_000;
        const h = try Harness.init(.{ .seed = @intCast(iter % 200 + 1), .max_stream_data = 4 << 20, .max_data = max_data }, randomBurst);
        defer h.deinit();
        h.prng = .init(iter);
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(testing.allocator);
        try h.runDelayed(delay, {}, established, &bursts);
        var ids: [8]u64 = undefined;
        var sizes: [8]usize = undefined;
        // Within the connection's credit: the test client never extends it.
        const n = 1 + r.uintLessThan(usize, 8);
        for (0..n) |i| {
            ids[i] = try h.client.openBidi();
            sizes[i] = 1 + r.uintLessThan(usize, if (r.boolean()) 4000 else if (max_data < 1 << 20) 70_000 else 250_000);
            var req: [32]u8 = undefined;
            try h.client.write(ids[i], try std.fmt.bufPrint(&req, "big {d}", .{sizes[i]}), true);
        }
        runLossyMulti(h, delay, loss, ids[0..n]) catch |e| {
            var got: usize = 0;
            for (0..n) |i| got += h.client.readAll(ids[i]).len;
            var want: usize = 0;
            for (0..n) |i| want += sizes[i];
            const s = h.server.?;
            std.debug.print("iter {d} pacing {}: delay {d} loss {d} burst {d} streams {d} max_data {d}: {s}; got {d}/{d}; window {d} in_flight {d} srtt {d} lost {d} pto_count {d} hold {?d} deadline {?d} now {d}\n", .{ iter, pacing, delay, loss, random_burst_us, n, max_data, @errorName(e), got, want, s.cc.window, s.cc.in_flight, s.rtt.smoothed, s.lost_packets, s.pto_count, s.pacing_hold, s.deadline(), h.now });
            fails += 1;
            continue;
        };
        for (0..n) |i| try testing.expectEqual(sizes[i], h.client.readAll(ids[i]).len);
    };
    try testing.expectEqual(@as(usize, 0), fails);
}

// -- ECN --------------------------------------------------------------------------

fn noEcn(c: *conn_mod.Config) void {
    c.ecn = false;
}

/// Downloads `n` bytes over the harness's instant path.
fn download(h: *Harness, n: usize) !void {
    const id = try h.client.openBidi();
    var req: [32]u8 = undefined;
    try h.client.write(id, try std.fmt.bufPrint(&req, "big {d}", .{n}), true);
    try h.run(3000);
    try testing.expectEqual(n, h.client.readAll(id).len);
    try testing.expect(h.client.finished(id));
}

/// Established, with ECN validated by the client's counts.
fn ecnCapable() !*Harness {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noTweak);
    errdefer h.deinit();
    try h.run(10);
    try download(h, 100_000);
    try testing.expectEqual(conn_mod.EcnState.capable, h.server.?.ecn);
    return h;
}

test "QUIC ECN: our ACKs count the codepoints received, per packet number space" {
    {
        // Not-ECT only: plain ACK frames.
        const h = try Harness.init(.{}, noTweak);
        defer h.deinit();
        try h.run(10);
        try download(h, 20_000);
        // (Handshake packets are acknowledged in 1-RTT ones, the space
        // gone.)
        for ([_]usize{ 0, 2 }) |i| {
            try testing.expect(h.client.spaces[i].acks_seen > 0);
            try testing.expectEqual(@as(?[3]u64, null), h.client.spaces[i].peer_ecn);
        }
    }
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    h.client_ecn = .ect0;
    try h.run(10);
    const s = h.server.?;
    try testing.expect(s.isEstablished());
    // The handshake's packets counted ECT(0) in their own spaces, and our
    // Initial ACKs said so (the client's last Initial and its Handshake
    // packets are never acknowledged: the spaces are gone by then).
    for (0..2) |i| {
        try testing.expect(s.spaces[i].ecn_rx[0] > 0);
        try testing.expectEqual(@as(u64, 0), s.spaces[i].ecn_rx[1] + s.spaces[i].ecn_rx[2]);
    }
    const initial = h.client.spaces[0].peer_ecn.?;
    try testing.expect(initial[0] > 0 and initial[0] <= s.spaces[0].ecn_rx[0] and initial[1] + initial[2] == 0);
    // In the application space, ECT(1) and CE count apart, a packet each.
    const base = s.spaces[2].ecn_rx;
    var pn = h.client.spaces[2].next_pn;
    var counts = base;
    for ([_]packet.Ecn{ .ect1, .ce, .ect0 }, [_]usize{ 1, 2, 0 }) |ecn, k| {
        h.client_ecn = ecn;
        const id = try h.client.openBidi();
        try h.client.write(id, "hello", true);
        try h.run(5);
        try testing.expectEqualStrings("echo:hello", h.client.readAll(id));
        counts[k] += h.client.spaces[2].next_pn - pn;
        pn = h.client.spaces[2].next_pn;
    }
    try testing.expectEqual(counts, s.spaces[2].ecn_rx);
    try testing.expect(counts[1] > base[1] and counts[2] > base[2]);
    const reported = h.client.spaces[2].peer_ecn.?;
    try testing.expect(reported[1] == counts[1] and reported[2] == counts[2]);

    // An ack-eliciting packet waits for the ACK delay; one marked CE is
    // acknowledged at once (§13.2.1); its duplicate counts nothing.
    try h.run(20);
    try testing.expectEqual(@as(?u64, null), s.spaces[2].ack_deadline);
    var buf: [1500]u8 = undefined;
    const id = try h.client.openBidi();
    try h.client.write(id, "x", false);
    h.client_ecn = .ect0;
    try h.toServer(buf[0..try h.client.send(&buf)]);
    try testing.expectEqual(h.now + 25_000, s.spaces[2].ack_deadline.?);
    h.now += 25_000;
    try testing.expect(s.send(&buf, h.now) > 0);
    try testing.expectEqual(@as(?u64, null), s.spaces[2].ack_deadline);
    try h.client.write(id, "y", false);
    const n = try h.client.send(&buf);
    const copy = buf;
    h.client_ecn = .ce;
    const ce = s.spaces[2].ecn_rx[2];
    try h.toServer(buf[0..n]);
    try testing.expectEqual(h.now, s.spaces[2].ack_deadline.?);
    try testing.expectEqual(ce + 1, s.spaces[2].ecn_rx[2]);
    buf = copy;
    try h.toServer(buf[0..n]);
    try testing.expectEqual(ce + 1, s.spaces[2].ecn_rx[2]);
}

test "QUIC ECN: a client that reports its counts validates the path; 1-RTT datagrams go out ECT(0)" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    // Handshake packets go unmarked.
    try testing.expectEqual(@as(u64, 0), s.spaces[0].ecn_sent + s.spaces[1].ecn_sent);
    try download(h, 500_000);
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
    try testing.expect(s.ecn_marked > 300);
    // Each marked datagram (one 1-RTT packet) counted ECT(0) at the
    // client, which reported it.
    try testing.expectEqual(s.ecn_marked, h.client.datagrams_ecn[@backingInt(packet.Ecn.ect0)]);
    try testing.expectEqual(s.ecn_marked, h.client.spaces[2].ecn[0]);
    try testing.expect(s.spaces[2].ecn_peer[0] > 300);
    try testing.expectEqual(@as(u64, 0), s.ecn_ce_events);
    try testing.expectEqual(@as(u64, 0), s.ecn_marked_lost);
}

/// Drives a download over a delayed path through CE marks (one
/// `runDelayed`: datagrams in flight survive between the steps).
const CeScript = struct {
    id: u64,
    rtt: u64,
    step: u8 = 0,
    // What each step saw.
    capable: bool = false,
    slow_start: bool = false,
    first_window: u64 = 0,
    first_ssthresh: u64 = 0,
    events_a_round_later: u64 = 0,
    marks_left: u32 = 0,
    second_window: u64 = 0,
    until: u64 = 0,

    fn done(c: *CeScript, h: *Harness) bool {
        const s = h.server.?;
        switch (c.step) {
            0 => if (s.cc.window > 120_000) {
                c.capable = s.ecn == .capable;
                c.slow_start = s.cc.ssthresh == std.math.maxInt(u64);
                // Five marks spread over a window, reported in several
                // ACKs.
                h.ce_marks = 5;
                h.ce_every = 8;
                c.step = 1;
            },
            1 => if (s.ecn_ce_events >= 1) {
                c.first_window = s.cc.window;
                c.first_ssthresh = s.cc.ssthresh;
                c.until = h.now + 3 * c.rtt;
                c.step = 2;
            },
            2 => if (h.now >= c.until) {
                c.events_a_round_later = s.ecn_ce_events;
                c.marks_left = h.ce_marks;
                // A mark more than a round trip later.
                h.ce_marks = 1;
                h.ce_every = 1;
                c.step = 3;
            },
            3 => if (s.ecn_ce_events >= 2) {
                c.second_window = s.cc.window;
                c.step = 4;
            },
            else => return h.client.finished(c.id),
        }
        return false;
    }
};

test "QUIC ECN: CE marks are a congestion event once per round trip, with nothing lost" {
    inline for (.{ .cubic, .new_reno }) |alg| {
        const h = try Harness.init(.{ .max_stream_data = 16 << 20, .max_data = 32 << 20 }, struct {
            fn f(c: *conn_mod.Config) void {
                c.congestion = alg;
            }
        }.f);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(testing.allocator);
        const delay = 10_000;
        try h.runDelayed(delay, {}, established, &bursts);
        const s = h.server.?;
        var script: CeScript = .{ .id = try h.client.openBidi(), .rtt = 2 * delay };
        try h.client.write(script.id, "big 6000000", true);
        try h.runDelayed(delay, &script, CeScript.done, &bursts);
        try testing.expectEqual(@as(usize, 6_000_000), h.client.readAll(script.id).len);
        try testing.expect(script.capable and script.slow_start);
        // The first mark ended slow start: the window is the new threshold.
        try testing.expectEqual(script.first_ssthresh, script.first_window);
        // The five marks came back over more than one ACK (bursts at least
        // 2 ms apart), all in one round trip: one event.
        try testing.expectEqual(@as(u32, 0), script.marks_left);
        try testing.expect(h.ce_last - h.ce_first > 2000);
        try testing.expectEqual(@as(u64, 1), script.events_a_round_later);
        // The next round trip's mark: a second event, a smaller window.
        try testing.expect(script.second_window < script.first_window);
        try testing.expectEqual(@as(u64, 2), s.ecn_ce_events);
        try testing.expectEqual([3]u64{ s.spaces[2].ecn_peer[0], 0, 6 }, s.spaces[2].ecn_peer);
        // Nothing was lost or sent again: CE only shrinks the window.
        try testing.expectEqual(@as(u64, 0), s.lost_packets);
        try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
    }
}

test "QUIC ECN: validation fails on missing, bogus or decreasing counts, and marking stops" {
    const Case = enum { not_reported, bleached, bleached_later, frozen, ect0_beyond_sent, ect1, ce_beyond_sent, ect0_becomes_ce };
    inline for (comptime std.enums.values(Case)) |case| {
        const h = switch (case) {
            .not_reported, .bleached => try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noTweak),
            else => try ecnCapable(),
        };
        defer h.deinit();
        const sp = &h.client.spaces[2];
        switch (case) {
            .not_reported => h.client.ecn_mode = .none,
            .bleached, .bleached_later => h.bleach = true,
            .frozen => h.client.ecn_mode = .frozen,
            .ect0_beyond_sent => sp.ecn[0] += 1_000_000,
            .ect1 => sp.ecn[1] += 1,
            .ce_beyond_sent => sp.ecn[2] += 1_000_000,
            // ECT(0) can still exceed what it was, CE too: only the fall
            // of the ECT(0) count is wrong.
            .ect0_becomes_ce => {
                sp.ecn[2] += sp.ecn[0];
                sp.ecn[0] = 0;
            },
        }
        try h.run(10);
        const s = h.server.?;
        try download(h, 200_000);
        try testing.expectEqual(conn_mod.EcnState.failed, s.ecn);
        // Not marking any more.
        const marked = s.ecn_marked;
        const unmarked = h.client.datagrams_ecn[@backingInt(packet.Ecn.not_ect)];
        try download(h, 100_000);
        try testing.expectEqual(marked, s.ecn_marked);
        try testing.expect(h.client.datagrams_ecn[@backingInt(packet.Ecn.not_ect)] > unmarked + 80);
        switch (case) {
            // Found by the first ACK of the testing packets.
            .not_reported, .bleached => try testing.expect(s.ecn_marked <= conn_mod.ecn_testing_packets),
            else => {},
        }
        // Bogus CE counts don't touch the window.
        try testing.expectEqual(@as(u64, 0), s.ecn_ce_events);
        try testing.expectEqual(@as(u64, std.math.maxInt(u64)), s.cc.ssthresh);
    }
}

test "QUIC ECN: a path that drops marked datagrams: marking stops when the testing packets are all lost" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noTweak);
    defer h.deinit();
    h.drop_marked = true;
    try h.run(10);
    try download(h, 300_000);
    const s = h.server.?;
    try testing.expectEqual(conn_mod.EcnState.lost, s.ecn);
    try testing.expectEqual(@as(u64, conn_mod.ecn_testing_packets), s.ecn_marked);
    try testing.expectEqual(s.ecn_marked, s.ecn_marked_lost);
}

test "QUIC ECN: an ACK that doesn't raise the largest acknowledged isn't validated" {
    const h = try ecnCapable();
    defer h.deinit();
    const s = h.server.?;
    const id = try h.client.openBidi();
    try h.client.write(id, "big 30000", true);
    var buf: [1500]u8 = undefined;
    while (true) {
        const n = try h.client.send(&buf);
        if (n == 0) break;
        try h.toServer(buf[0..n]);
    }
    var flights: [64]Flight = undefined;
    var count: usize = 0;
    while (count < flights.len) : (count += 1) {
        const ecn = s.sendEcn();
        const n = s.send(&flights[count].buf, h.now);
        if (n == 0) break;
        flights[count].len = n;
        flights[count].ecn = ecn;
    }
    try testing.expect(count > 10);
    // ACK one half, then both halves but the last datagram (so a packet
    // is still in flight); the second ACK arrives first.
    var acks: [2][1500]u8 = undefined;
    var lens: [2]usize = undefined;
    var counts: [2][3]u64 = undefined;
    for (0..2) |k| {
        const part = flights[k * count / 2 .. if (k == 0) count / 2 else count - 1];
        for (part) |*f| try h.toClient(f.buf[0..f.len], f.ecn);
        lens[k] = try h.client.send(&acks[k]);
        counts[k] = h.client.spaces[2].ecn;
    }
    try testing.expect(counts[0][0] < counts[1][0]);
    try h.toServer(acks[1][0..lens[1]]);
    try testing.expectEqual(counts[1], s.spaces[2].ecn_peer);
    try testing.expect(s.spaces[2].sent.live_count > 0);
    // The first ACK's counts are lower: validated, they would fail.
    try h.toServer(acks[0][0..lens[0]]);
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
    try testing.expectEqual(counts[1], s.spaces[2].ecn_peer);
    const last = &flights[count - 1];
    try h.toClient(last.buf[0..last.len], last.ecn);
    try h.run(50);
    try testing.expect(h.client.finished(id));
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
}

test "QUIC ECN: off, nothing is marked and no counts are reported" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20 }, noEcn);
    defer h.deinit();
    h.client_ecn = .ect0;
    try h.run(10);
    try download(h, 100_000);
    const s = h.server.?;
    try testing.expectEqual(conn_mod.EcnState.failed, s.ecn);
    try testing.expectEqual(@as(u64, 0), s.ecn_marked);
    try testing.expectEqual(@as(u64, 0), h.client.datagrams_ecn[@backingInt(packet.Ecn.ect0)]);
    try testing.expectEqual([3]u64{ 0, 0, 0 }, s.spaces[2].ecn_rx);
    try testing.expectEqual(@as(?[3]u64, null), h.client.spaces[2].peer_ecn);
}

// -- verify ECN: adversarial cases --------------------------------------------

/// A path for the verify ECN tests: a one-way delay plus up to `jitter` µs
/// more for each datagram (so datagrams overtake each other), `loss`
/// percent of datagrams dropped each way, and `ce` percent of the server's
/// marked datagrams turned CE.
/// `reorder` percent go without the delay (netem's `reorder`).
const Path = struct {
    delay: u64,
    jitter: u64 = 0,
    loss: u8 = 0,
    ce: u8 = 0,
    reorder: u8 = 0,
    gso: bool = false,

    fn arrival(p: Path, now: u64, rnd: std.Random) u64 {
        if (rnd.uintLessThan(u8, 100) < p.reorder) return now + 200;
        return now + p.delay + rnd.uintAtMost(u64, p.jitter);
    }
};

/// Runs both ends over `path` until `done` holds, the clock jumping from
/// event to event; the client resends what is unacknowledged when the
/// path goes quiet (its only loss recovery).
fn runPath(h: *Harness, path: Path, ctx: anytype, comptime done: fn (@TypeOf(ctx), *Harness) bool) !void {
    var queue: std.ArrayList(Flight) = .empty;
    defer queue.deinit(h.a);
    const limit = h.now + 300 * std.time.us_per_s;
    var buf: [1500]u8 = undefined;
    while (!done(ctx, h)) {
        if (h.now > limit) return error.Timeout;
        const rnd = h.prng.random();
        while (true) {
            const n = try h.client.send(&buf);
            if (n == 0) break;
            if (rnd.uintLessThan(u8, 100) < path.loss) continue;
            try queue.append(h.a, .{ .at = path.arrival(h.now, rnd), .to_server = true, .len = n, .buf = buf });
        }
        if (h.server) |s| {
            if (s.isClosed()) return error.Closed;
            // With `gso`, the datagrams of one send with one codepoint go
            // as one unit (one skb through netem on loopback).
            var unit: ?struct { at: u64, ecn: packet.Ecn } = null;
            while (true) {
                const sent_ecn = s.sendEcn();
                var ecn = sent_ecn;
                const n = s.send(&buf, h.now);
                if (n == 0) break;
                const at = if (path.gso and unit != null and unit.?.ecn == sent_ecn) unit.?.at else path.arrival(h.now, rnd);
                unit = .{ .at = at, .ecn = sent_ecn };
                if (rnd.uintLessThan(u8, 100) < path.loss) continue;
                if (ecn != .not_ect and rnd.uintLessThan(u8, 100) < path.ce) ecn = .ce;
                try queue.append(h.a, .{ .at = at, .to_server = false, .len = n, .buf = buf, .ecn = ecn });
            }
        }
        var next: ?u64 = null;
        for (queue.items) |f| next = if (next) |x| @min(x, f.at) else f.at;
        var timer: ?u64 = null;
        if (h.server) |s| if (s.deadline()) |d| if (d < h.now + 10 * std.time.us_per_s) {
            timer = @max(d, h.now);
            next = if (next) |x| @min(x, timer.?) else timer;
        };
        if (next == null) {
            h.now += 100_000;
            try h.client.retransmit();
            continue;
        }
        h.now = next.?;
        // Arrivals in time order.
        while (true) {
            var first: ?usize = null;
            for (queue.items, 0..) |f, i| {
                if (f.at > h.now) continue;
                if (first == null or f.at < queue.items[first.?].at) first = i;
            }
            const i = first orelse break;
            const f = queue.orderedRemove(i);
            if (f.to_server) try h.toServer(@constCast(f.buf[0..f.len])) else try h.toClient(f.buf[0..f.len], f.ecn);
        }
        if (timer) |t| if (t <= h.now) {
            h.server.?.onTimeout(h.now);
            try EchoApp.run(h.server.?);
        };
    }
}

fn clientReady(_: void, h: *Harness) bool {
    return h.client.handshake_complete;
}

fn allFinished(ids: []const u64, h: *Harness) bool {
    for (ids) |id| if (!h.client.finished(id)) return false;
    return true;
}

fn halfway(id: u64, h: *Harness) bool {
    return h.client.readAll(id).len > 400_000 or h.client.finished(id);
}

test "verify ECN: an honest client over lossy, reordering paths: validation never fails" {
    const paths = [_]Path{
        .{ .delay = 10_000, .jitter = 0, .loss = 5 },
        .{ .delay = 10_000, .jitter = 8_000 },
        .{ .delay = 10_000, .jitter = 15_000, .loss = 3 },
        .{ .delay = 20_000, .jitter = 30_000, .loss = 10, .ce = 2 },
        .{ .delay = 2_000, .jitter = 5_000, .loss = 1, .ce = 5 },
        .{ .delay = 5_000, .jitter = 20_000, .loss = 0, .ce = 1 },
    };
    var failures: usize = 0;
    var unknown: usize = 0;
    for (0..24) |run| {
        const path = paths[run % paths.len];
        const h = try Harness.init(.{ .seed = @intCast(run + 1), .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noTweak);
        defer h.deinit();
        h.prng = .init(run *% 7919 + 3);
        try runPath(h, path, {}, established);
        const s = h.server.?;
        var ids: [6]u64 = undefined;
        for (ids[0..5], 0..) |*id, i| {
            id.* = try h.client.openBidi();
            var msg: [32]u8 = undefined;
            try h.client.write(id.*, try std.fmt.bufPrint(&msg, "req {d}", .{i}), true);
        }
        ids[5] = try h.client.openBidi();
        try h.client.write(ids[5], "big 1000000", true);
        if (run % 2 == 1) {
            // Marked packets on both sides of a key update.
            try runPath(h, path, ids[5], halfway);
            h.client.initiateKeyUpdate();
            h.client.followKeyUpdate();
        }
        try runPath(h, path, @as([]const u64, &ids), allFinished);
        try testing.expectEqual(@as(usize, 1_000_000), h.client.readAll(ids[5]).len);
        if (s.ecn != .capable) {
            std.debug.print("run {d} path {any}: ecn {s}, marked {d} lost {d}, peer counts {any}, sent {d}, lost packets {d}\n", .{ run, path, @tagName(s.ecn), s.ecn_marked, s.ecn_marked_lost, s.spaces[2].ecn_peer, s.spaces[2].ecn_sent, s.lost_packets });
            if (s.ecn == .failed) failures += 1 else unknown += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), failures);
    try testing.expectEqual(@as(usize, 0), unknown);
}

test "verify ECN: testing packets acknowledged only by an ACK that doesn't raise the largest still validate" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noPacing);
    defer h.deinit();
    var buf: [1500]u8 = undefined;
    // The handshake, holding back everything the server sends once
    // established (its first marked datagrams).
    var held: std.ArrayList(Flight) = .empty;
    defer held.deinit(testing.allocator);
    var id: ?u64 = null;
    for (0..100) |_| {
        while (true) {
            const n = try h.client.send(&buf);
            if (n == 0) break;
            try h.toServer(buf[0..n]);
        }
        if (h.server) |s| while (true) {
            const ecn = s.sendEcn();
            const n = s.send(&buf, h.now);
            if (n == 0) break;
            if (s.isEstablished()) {
                try held.append(testing.allocator, .{ .at = h.now, .to_server = false, .len = n, .buf = buf, .ecn = ecn });
            } else try h.toClient(buf[0..n], ecn);
        };
        if (id == null and h.client.handshake_complete) {
            id = try h.client.openBidi();
            try h.client.write(id.?, "big 30000", true);
        }
        // (A request that went before the server had its keys.)
        if (held.items.len < 2) try h.client.retransmit();
        h.now += 1000;
    }
    const s = h.server.?;
    // Ten testing packets, then one unmarked (the window's end).
    try testing.expect(held.items.len > conn_mod.ecn_testing_packets);
    try testing.expectEqual(conn_mod.EcnState.unknown, s.ecn);
    const last = held.items[held.items.len - 1];
    try testing.expectEqual(packet.Ecn.not_ect, last.ecn);
    // The last (unmarked) datagram overtakes the rest: its ACK raises the
    // largest acknowledged, acknowledging nothing marked.
    try h.toClient(last.buf[0..last.len], last.ecn);
    var n = try h.client.send(&buf);
    try h.toServer(buf[0..n]);
    // Then the marked ones arrive: their ACK has the same largest.
    for (held.items[0 .. held.items.len - 1]) |*f| try h.toClient(f.buf[0..f.len], f.ecn);
    n = try h.client.send(&buf);
    try h.toServer(buf[0..n]);
    try testing.expectEqual(@as(u64, conn_mod.ecn_testing_packets), h.client.spaces[2].ecn[0]);
    std.debug.print("after both ACKs: ecn {s}, marked {d}, lost {d} (declared lost by the first ACK's packet threshold)\n", .{ @tagName(s.ecn), s.ecn_marked, s.ecn_marked_lost });
    try h.run(3000);
    try testing.expect(h.client.finished(id.?));
    // An honest client and a clean path: the marks were all counted.
    try download(h, 200_000);
    std.debug.print("after the reordered testing period: ecn {s}, marked {d}, peer counts {any}\n", .{ @tagName(s.ecn), s.ecn_marked, s.spaces[2].ecn_peer });
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
}

test "verify ECN: a receiver reporting every mark as CE slows us once a round trip, no further" {
    const h = try Harness.init(.{ .max_stream_data = 16 << 20, .max_data = 32 << 20 }, noTweak);
    defer h.deinit();
    var bursts: std.ArrayList(Burst) = .empty;
    defer bursts.deinit(testing.allocator);
    const delay = 10_000;
    try h.runDelayed(delay, {}, established, &bursts);
    h.client.ecn_mode = .all_ce;
    const s = h.server.?;
    const id = try h.client.openBidi();
    try h.client.write(id, "big 2000000", true);
    const start = h.now;
    try h.runDelayed(delay, id, finishedStream, &bursts);
    try testing.expectEqual(@as(usize, 2_000_000), h.client.readAll(id).len);
    const rtts = (h.now - start) / (2 * delay);
    std.debug.print("all-CE receiver: {d} CE events over {d} round trips, window {d}, state {s}\n", .{ s.ecn_ce_events, rtts, s.cc.window, @tagName(s.ecn) });
    // Valid counts (ECT(0) never falls): ECN stays on, and each round
    // trip's marks are one event at most.
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
    try testing.expect(s.ecn_ce_events > 3);
    try testing.expect(s.ecn_ce_events <= rtts + 1);
    try testing.expect(s.cc.window >= 2 * @as(u64, s.max_datagram));
    try testing.expectEqual(@as(u64, 0), s.lost_packets);
}

test "verify ECN: undecryptable, foreign and duplicate packets count nothing" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    h.client_ecn = .ect0;
    try h.run(10);
    const s = h.server.?;
    const before = s.spaces[2].ecn_rx;
    var buf: [1500]u8 = undefined;
    const id = try h.client.openBidi();
    try h.client.write(id, "x", false);
    const n = try h.client.send(&buf);
    const good = buf;
    h.client_ecn = .ce;
    // A byte of the payload flipped: authentication fails.
    buf[n - 3] ^= 1;
    try h.toServer(buf[0..n]);
    try testing.expectEqual(before, s.spaces[2].ecn_rx);
    // Garbage that looks like a short header packet (a stateless reset's
    // shape): nothing.
    var junk: [64]u8 = @splat(0x41);
    junk[0] = 0x40;
    @memcpy(junk[1..9], &server_cid);
    try h.toServer(&junk);
    try testing.expectEqual(before, s.spaces[2].ecn_rx);
    // The real one counts once, its duplicate not.
    buf = good;
    try h.toServer(buf[0..n]);
    buf = good;
    try h.toServer(buf[0..n]);
    try testing.expectEqual(before[2] + 1, s.spaces[2].ecn_rx[2]);
    try testing.expectEqual(before[0], s.spaces[2].ecn_rx[0]);
}

test "verify ECN: netem-style reordering (30% of datagrams undelayed, GSO sends whole): an honest client keeps ECN" {
    // By path model (datagrams alone, GSO units), then EcnState.
    var outcome: [2][4]usize = @splat(@splat(0));
    const runs = 200;
    for (0..runs) |run| {
        const h = try Harness.init(.{ .seed = @intCast(run % 250 + 1), .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noTweak);
        defer h.deinit();
        // Half of them unpaced: the first window leaves in one burst.
        h.cfg.pacing = run % 2 == 0;
        h.prng = .init(run *% 104729 + 11);
        // GSO sends travel whole on loopback (netem delays or reorders
        // the skb): half the runs like that.
        const path: Path = .{ .delay = 20_000, .reorder = 30, .gso = run % 4 < 2 };
        // The request goes with the client's Finished, as browsers do: the
        // server's first window carries HANDSHAKE_DONE and the response.
        try runPath(h, path, {}, clientReady);
        const s = h.server.?;
        var ids: [1]u64 = undefined;
        ids[0] = try h.client.openBidi();
        try h.client.write(ids[0], "big 100000", true);
        try runPath(h, path, @as([]const u64, &ids), allFinished);
        outcome[@intFromBool(path.gso)][@backingInt(s.ecn)] += 1;
    }
    for (outcome, 0..) |o, g| std.debug.print("{s}: testing {d}, unknown {d}, capable {d}, failed {d}\n", .{ if (g == 1) "GSO units" else "datagrams", o[0], o[1], o[2], o[3] });
    try testing.expectEqual(@as(usize, runs), outcome[0][@backingInt(conn_mod.EcnState.capable)] + outcome[1][@backingInt(conn_mod.EcnState.capable)]);
}

test "QUIC ECN: testing packets declared lost that arrive after all: the path is tested again" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noPacing);
    defer h.deinit();
    var buf: [1500]u8 = undefined;
    // Marked datagrams wait (a path reordering them behind the unmarked
    // ones that follow) until every testing packet is declared lost.
    var held: std.ArrayList(Flight) = .empty;
    defer held.deinit(testing.allocator);
    var id: ?u64 = null;
    var rounds: usize = 0;
    while (h.server == null or h.server.?.ecn != .lost) : (rounds += 1) {
        if (rounds == 200) return error.TestUnexpectedResult;
        // (A request that went before the server had its keys.)
        if (rounds % 20 == 19) try h.client.retransmit();
        while (true) {
            const n = try h.client.send(&buf);
            if (n == 0) break;
            try h.toServer(buf[0..n]);
        }
        if (h.server) |s| while (true) {
            const ecn = s.sendEcn();
            const n = s.send(&buf, h.now);
            if (n == 0) break;
            if (ecn != .not_ect) {
                try held.append(testing.allocator, .{ .at = h.now, .to_server = false, .len = n, .buf = buf, .ecn = ecn });
            } else try h.toClient(buf[0..n], ecn);
        };
        if (id == null and h.client.handshake_complete) {
            id = try h.client.openBidi();
            try h.client.write(id.?, "big 60000", true);
        }
        h.now += 1000;
    }
    const s = h.server.?;
    try testing.expectEqual(@as(usize, conn_mod.ecn_testing_packets), held.items.len);
    try testing.expectEqual(s.ecn_marked, s.ecn_marked_lost);
    // They arrive: the counts rise, and the path is tested again.
    for (held.items) |*f| try h.toClient(f.buf[0..f.len], f.ecn);
    try h.run(3000);
    try testing.expect(h.client.finished(id.?));
    try download(h, 200_000);
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
    try testing.expectEqual(@as(u8, 1), s.ecn_retests);
    try testing.expectEqual(s.spaces[2].ecn_sent, h.client.spaces[2].ecn[0]);
}

test "QUIC ECN: a new peer address is a new path: tested afresh" {
    const h = try ecnCapable();
    defer h.deinit();
    const s = h.server.?;
    // This path clears the marks: ECN fails.
    h.bleach = true;
    try download(h, 100_000);
    try testing.expectEqual(conn_mod.EcnState.failed, s.ecn);
    const marked = s.spaces[2].ecn_sent;
    // NAT rebinding to a path that carries them.
    h.bleach = false;
    s.onPathChange(h.now, h.ipv6, true);
    try testing.expectEqual(conn_mod.EcnState.testing, s.ecn);
    try download(h, 200_000);
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
    // (A window went out unmarked while the testing packets waited for
    // their ACK.) Marking every datagram again:
    const at_capable = s.spaces[2].ecn_sent;
    try testing.expect(at_capable > marked + conn_mod.ecn_testing_packets);
    try download(h, 100_000);
    try testing.expect(s.spaces[2].ecn_sent > at_capable + 80);
    try testing.expectEqual(@as(u64, 0), s.ecn_ce_events);
}

test "QUIC ECN: a CE event takes the window before the ACK carrying it grew it" {
    const h = try ecnCapable();
    defer h.deinit();
    const s = h.server.?;
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), s.cc.ssthresh);
    const id = try h.client.openBidi();
    try h.client.write(id, "big 400000", true);
    var buf: [1500]u8 = undefined;
    while (true) {
        const n = try h.client.send(&buf);
        if (n == 0) break;
        try h.toServer(buf[0..n]);
    }
    // A window's worth, one datagram marked CE on the way, then the
    // client's ACK of all of it.
    h.ce_marks = 1;
    var sent: usize = 0;
    while (true) : (sent += 1) {
        const ecn = s.sendEcn();
        const n = s.send(&buf, h.now);
        if (n == 0) break;
        try h.toClient(buf[0..n], ecn);
    }
    try testing.expect(sent > 10);
    const n = try h.client.send(&buf);
    const before = s.cc.window;
    try h.toServer(buf[0..n]);
    try testing.expectEqual(@as(u64, 1), s.ecn_ce_events);
    // CUBIC's β: 0.7 of the window the ACK found, not of the one its
    // acknowledged bytes would have grown (RFC 9002 §A.7: ECN first).
    try testing.expectEqual(@as(u64, @intFromFloat(@as(f64, @floatFromInt(before)) * 0.7)), s.cc.window);
    try h.run(100);
    try testing.expect(h.client.finished(id));
}

/// Starts a download and returns what the server sends at once (a window
/// of marked datagrams), undelivered.
fn heldWindow(h: *Harness, req: []const u8, out: []Flight) !usize {
    const s = h.server.?;
    const id = try h.client.openBidi();
    try h.client.write(id, req, true);
    var buf: [1500]u8 = undefined;
    while (true) {
        const n = try h.client.send(&buf);
        if (n == 0) break;
        try h.toServer(buf[0..n]);
    }
    var count: usize = 0;
    while (count < out.len) : (count += 1) {
        const ecn = s.sendEcn();
        const n = s.send(&out[count].buf, h.now);
        if (n == 0) break;
        out[count].len = n;
        out[count].ecn = ecn;
    }
    return count;
}

test "QUIC ECN: a new path isn't judged by the old one's packets: their loss doesn't fail it" {
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 32 << 20 }, noPacing);
    defer h.deinit();
    try h.run(10);
    try download(h, 300_000);
    const s = h.server.?;
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
    // Marked packets in flight on the old path, then the peer's address
    // changes: the new path's ten testing packets follow.
    var old: [32]Flight = undefined;
    const n = try heldWindow(h, "big 300000", &old);
    try testing.expectEqual(old.len, n);
    s.spaces[2].ecn_ce_pending = true;
    s.onPathChange(h.now, h.ipv6, true);
    try testing.expect(!s.spaces[2].ecn_ce_pending);
    var fresh: [32]Flight = undefined;
    var m: usize = 0;
    while (m < fresh.len) : (m += 1) {
        const ecn = s.sendEcn();
        const k = s.send(&fresh[m].buf, h.now);
        if (k == 0) break;
        fresh[m].len = k;
        fresh[m].ecn = ecn;
    }
    try testing.expect(m > conn_mod.ecn_testing_packets);
    try testing.expectEqual(conn_mod.EcnState.unknown, s.ecn);
    // The old path's last packet arrives, the rest of them is lost: not
    // this path's testing packets.
    const last = &old[n - 1];
    try h.toClient(last.buf[0..last.len], last.ecn);
    var buf: [1500]u8 = undefined;
    try h.toServer(buf[0..try h.client.send(&buf)]);
    try testing.expect(s.lost_packets >= n - 4);
    try testing.expectEqual(conn_mod.EcnState.unknown, s.ecn);
    try testing.expectEqual(@as(u64, 0), s.ecn_marked_lost);
    // The new path's arrive: validated.
    for (fresh[0..m]) |*f| try h.toClient(f.buf[0..f.len], f.ecn);
    try h.run(3000);
    try download(h, 100_000);
    try testing.expectEqual(conn_mod.EcnState.capable, s.ecn);
    try testing.expectEqual(@as(u8, 0), s.ecn_retests);
}

test "QUIC ECN: a new path isn't validated by the old one's packets: one dropping marks is found" {
    const h = try ecnCapable();
    defer h.deinit();
    const s = h.server.?;
    var flights: [64]Flight = undefined;
    const n = try heldWindow(h, "big 300000", &flights);
    try testing.expect(n > conn_mod.ecn_testing_packets);
    s.onPathChange(h.now, h.ipv6, true);
    // The old mapping still delivers what it carried; the new path drops
    // every marked datagram.
    for (flights[0..n]) |*f| try h.toClient(f.buf[0..f.len], f.ecn);
    h.drop_marked = true;
    try h.run(3000);
    try download(h, 100_000);
    try testing.expectEqual(conn_mod.EcnState.lost, s.ecn);
    try testing.expectEqual(@as(u64, conn_mod.ecn_testing_packets), s.ecn_marked);
    try testing.expectEqual(s.ecn_marked, s.ecn_marked_lost);
}

test "QUIC: only the newest non-probing packet may move the peer's address (RFC 9000 §9.3)" {
    const h = try Harness.init(.{}, noTweak);
    defer h.deinit();
    try h.run(10);
    const s = h.server.?;
    const id = try h.client.openBidi();
    var older: [1500]u8 = undefined;
    var newer: [1500]u8 = undefined;
    try h.client.write(id, "a", false);
    const n1 = try h.client.send(&older);
    try h.client.write(id, "b", false);
    const n2 = try h.client.send(&newer);
    // The newer first: it may; the older one after it (reordered, from
    // where the peer was) may not.
    try testing.expect(s.recv(newer[0..n2], .not_ect, h.now));
    try testing.expect(!s.recv(older[0..n1], .not_ect, h.now));
    // A duplicate may not either.
    try testing.expect(!s.recv(newer[0..n2], .not_ect, h.now));
    // Nor a probing packet (PATH_CHALLENGE and PADDING only).
    try h.client.injectFrames(&.{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0 });
    const n3 = try h.client.send(&older);
    try testing.expect(!s.recv(older[0..n3], .not_ect, h.now));
    try h.client.write(id, "c", true);
    const n4 = try h.client.send(&older);
    try testing.expect(s.recv(older[0..n4], .not_ect, h.now));
}

// -- PMTU discovery (pmtud.zig; RFC 9000 §14.3, RFC 8899) ---------------------

const pmtud = @import("./pmtud.zig");
const recovery = @import("./recovery.zig");

/// The server's defaults: 1350 bytes from the start, probing up to what a
/// 1500-byte IPv4 packet carries (1472).
fn pmtuOn(c: *conn_mod.Config) void {
    c.max_datagram_size = 1350;
    c.max_mtu = 1500;
}

fn pmtuOnCubicOrReno(comptime alg: recovery.Algorithm) fn (*conn_mod.Config) void {
    return struct {
        fn f(c: *conn_mod.Config) void {
            pmtuOn(c);
            c.congestion = alg;
        }
    }.f;
}

fn searchDone(_: void, h: *Harness) bool {
    const s = h.server orelse return false;
    return s.isEstablished() and s.pmtu.state == .complete;
}

fn finishedAndSearched(id: u64, h: *Harness) bool {
    return h.client.finished(id) and searchDone({}, h);
}

/// Bytes in flight as the live packets count them.
fn liveInFlight(s: *Conn) u64 {
    var sum: u64 = 0;
    for (&s.spaces) |*sp| {
        var it = sp.sent.iterator();
        while (it.next()) |e| if (e.packet.in_flight) {
            sum += e.packet.size;
        };
    }
    return sum;
}

fn expectBody(h: *Harness, id: u64, n: usize) !void {
    const got = h.client.readAll(id);
    try testing.expectEqual(n, got.len);
    for (got, 0..) |b, i| if (b != @as(u8, @truncate(i))) return error.Corrupt;
}

test "QUIC PMTU: the search converges to the path's limit; data then goes at it; probe losses aren't congestion" {
    const limits = [_]usize{ std.math.maxInt(usize), 1472, 1452, 1400, 1392, 1360 };
    for (limits) |limit| {
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
        defer h.deinit();
        h.path_max = limit;
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(10_000, {}, established, &bursts);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 2000000", true);
        try h.runDelayed(10_000, id, finishedAndSearched, &bursts);
        try expectBody(h, id, 2_000_000);
        const s = h.server.?;
        const want = @min(limit, 1472);
        try testing.expect(s.max_datagram <= want and want - s.max_datagram < pmtud.min_step);
        // Every datagram dropped for its size was a probe, and each lost
        // probe is a failed probe, not congestion: nothing else was lost,
        // no congestion event, the window never shrank.
        try testing.expectEqual(@as(usize, s.pmtu.probes_lost), h.too_big);
        try testing.expectEqual(@as(u64, 0), s.lost_packets);
        try testing.expectEqual(@as(?u64, null), s.cc.recovery_start);
        try testing.expect(s.pmtu.probes_lost == 0 or limit < 1472);
        // The congestion controller counts in the new size, and the
        // pacer's floor is ten of them.
        try testing.expectEqual(@as(u64, s.max_datagram), s.cc.mss);
        try testing.expect(s.pacer.capacity(&s.cc, &s.rtt) >= 10 * @as(u64, s.max_datagram));
        // The search took a few round trips: the data went at the larger
        // size, not only the probes.
        try testing.expect(h.largest_to_client >= s.max_datagram);
        try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
    }
}

test "QUIC PMTU: no probe before the handshake is confirmed, nor without room in the window" {
    const h = try Harness.init(.{}, pmtuOn);
    defer h.deinit();
    h.path_max = 1350;
    var confirmed_at: ?usize = null;
    for (0..40) |round| {
        try h.run(1);
        const s = h.server orelse continue;
        if (!s.handshake_complete) {
            try testing.expectEqual(@as(u32, 0), s.pmtu.probes_sent);
            try testing.expectEqual(pmtud.State.disabled, s.pmtu.state);
            try testing.expect(h.largest_to_client <= 1350);
        } else if (confirmed_at == null) confirmed_at = round;
    }
    try testing.expect(confirmed_at != null);
    const s = h.server.?;
    try testing.expect(s.pmtu.probes_sent > 0);
    // A probe due, and a window with less room than it: a probe waits
    // (data that fits in the room still goes).
    s.onPathChange(h.now, h.ipv6, true);
    try testing.expectEqual(@as(?u16, 1472), s.pmtu.due(h.now));
    const pad = s.cc.window - s.cc.in_flight - 1400;
    s.cc.in_flight += pad;
    var buf: [1500]u8 = undefined;
    const sent = s.pmtu.probes_sent;
    while (true) {
        const n = s.send(&buf, h.now);
        if (n == 0) break;
        try testing.expect(n <= s.max_datagram);
    }
    try testing.expectEqual(sent, s.pmtu.probes_sent);
    s.cc.in_flight -= pad;
    try testing.expectEqual(@as(usize, 1472), s.send(&buf, h.now));
    try testing.expectEqual(sent + 1, s.pmtu.probes_sent);
    // One at a time.
    try testing.expect(s.send(&buf, h.now) <= s.max_datagram);
    // Not into a buffer too small for it either (the worker's, when a GSO
    // run has filled most of it): the probe waits for the next.
    s.onPathChange(h.now, h.ipv6, true);
    try testing.expect(s.send(buf[0..1400], h.now) <= 1350);
    try testing.expectEqual(@as(usize, 1472), s.send(&buf, h.now));
}

test "QUIC PMTU: lost probes on an idle connection end the search below the path's limit, no congestion" {
    inline for (.{ .cubic, .new_reno }) |alg| {
        const h = try Harness.init(.{}, pmtuOnCubicOrReno(alg));
        defer h.deinit();
        h.path_max = 1350;
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(20_000, {}, searchDone, &bursts);
        const s = h.server.?;
        try testing.expectEqual(@as(u16, 1350), s.max_datagram);
        // 1472, 1411, 1380 and 1365 failed, three probes each.
        try testing.expectEqual(@as(u32, 4 * pmtud.max_probes), s.pmtu.probes_lost);
        try testing.expectEqual(@as(u64, 0), s.lost_packets);
        try testing.expectEqual(@as(?u64, null), s.cc.recovery_start);
        try testing.expect(s.cc.window >= recovery.Congestion.initialWindow(1350));
        try testing.expectEqual(@as(u64, 1350), s.cc.mss);
        try testing.expectEqual(@as(u32, 0), s.pmtu.black_holes);
        // And the connection still works.
        const id = try h.client.openBidi();
        try h.client.write(id, "big 100000", true);
        try h.runDelayed(20_000, id, finishedStream, &bursts);
        try expectBody(h, id, 100_000);
    }
}

test "QUIC PMTU: a lost probe doesn't stretch a loss into persistent congestion" {
    const h = try Harness.init(.{}, pmtuOn);
    defer h.deinit();
    try h.run(20);
    const s = h.server.?;
    try testing.expect(s.isEstablished());
    const a = testing.allocator;
    const sp = &s.spaces[2];
    // A packet at t0, a probe 5 s later, another packet 50 ms after it,
    // none of them seen by the client; then an ACK of the last alone.
    const Fake = struct {
        fn add(sp_: anytype, s_: *Conn, a_: std.mem.Allocator, t: u64, size: u32, probe: bool) !u64 {
            const pn = sp_.sent.nextPn();
            const mark = sp_.sent.recordMark();
            try sp_.sent.addRecord(a_, .ping);
            try sp_.sent.add(a_, mark, t, size, .{ .ack_eliciting = true, .in_flight = true, .pmtu_probe = probe });
            s_.cc.onSent(size);
            return pn;
        }
    };
    const t0 = h.now;
    _ = try Fake.add(sp, s, a, t0, 1350, false);
    s.onPathChange(t0, false, true);
    const probe = try Fake.add(sp, s, a, t0 + 5 * std.time.us_per_s, 1472, true);
    s.pmtu.onProbeSent(probe);
    const last = try Fake.add(sp, s, a, t0 + 5 * std.time.us_per_s + 50_000, 1350, false);
    h.now = t0 + 5 * std.time.us_per_s + 60_000;
    const window = s.cc.window;
    var ack_buf: [32]u8 = undefined;
    var w: packet.Writer = .{ .buf = &ack_buf };
    frame.writeAckFrame(&w, &.{.{ .smallest = last, .largest = last }}, 0, null);
    try h.client.injectFrames(w.written());
    var buf: [1500]u8 = undefined;
    const n = try h.client.send(&buf);
    try h.toServer(buf[0..n]);
    // The first packet's loss is a congestion event; with the probe, the
    // losses would span 5 s, persistent congestion, the minimum window.
    try testing.expect(s.cc.recovery_start != null);
    try testing.expect(s.cc.window < window);
    try testing.expect(s.cc.window > s.cc.minWindow());
    try testing.expectEqual(@as(u32, 1), s.pmtu.probes_lost);
    try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
}

test "QUIC PMTU: a black hole after validation: back to 1200, then up to the new limit, with nothing stalled" {
    // In a plain download every packet is full-sized: the probe
    // timeouts' 1200-byte packets are what gets through.
    for ([_]usize{ 1300, 1232, 1400 }) |new_limit| {
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(10_000, {}, established, &bursts);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 4000000", true);
        try h.runDelayed(15_000, id, halfway, &bursts);
        const s = h.server.?;
        try testing.expectEqual(@as(u16, 1472), s.max_datagram);
        // The path shrinks (a route change into a tunnel), silently.
        h.path_max = new_limit;
        const changed = h.now;
        try h.runDelayed(15_000, id, finishedAndSearched, &bursts);
        try expectBody(h, id, 4_000_000);
        try testing.expectEqual(@as(u32, 1), s.pmtu.black_holes);
        try testing.expect(s.max_datagram <= new_limit and new_limit - s.max_datagram < pmtud.min_step);
        try testing.expectEqual(@as(u64, s.max_datagram), s.cc.mss);
        // Bytes in flight stayed what the live packets add up to.
        try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
        // Recovered within a few seconds (simulated) of the change.
        const took = h.now - changed;
        try testing.expect(took < 5 * std.time.us_per_s);
    }
}

test "QUIC PMTU: a path below the start size from the beginning: the handshake completes, datagrams fall to 1200" {
    // A 1280-byte IPv6 MTU (1232 bytes of payload) under our 1350.
    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
    defer h.deinit();
    h.path_max = 1232;
    try runPath(h, .{ .delay = 10_000 }, {}, established);
    const id = try h.client.openBidi();
    try h.client.write(id, "big 300000", true);
    try runPath(h, .{ .delay = 10_000 }, id, finishedAndSearched);
    try expectBody(h, id, 300_000);
    const s = h.server.?;
    try testing.expectEqual(@as(u32, 1), s.pmtu.black_holes);
    try testing.expect(s.max_datagram <= 1232 and 1232 - s.max_datagram < pmtud.min_step);
}

test "QUIC PMTU: the client's max_udp_payload_size bounds every datagram, probes included" {
    {
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20, .max_udp_payload_size = 1400 }, pmtuOn);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(10_000, {}, established, &bursts);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 500000", true);
        try h.runDelayed(10_000, id, finishedAndSearched, &bursts);
        const s = h.server.?;
        try testing.expectEqual(@as(u16, 1400), s.max_datagram);
        try testing.expectEqual(@as(usize, 1400), h.largest_to_client);
        try testing.expectEqual(@as(u32, 1), s.pmtu.probes_sent);
    }
    {
        // Under our start size: from the start, with the congestion
        // window counted in it (RFC 9002 §7.2), and nothing to probe for.
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20, .max_udp_payload_size = 1250 }, pmtuOn);
        defer h.deinit();
        try h.run(1);
        const s = h.server.?;
        try testing.expectEqual(@as(u16, 1250), s.max_datagram);
        try testing.expectEqual(@as(u64, 1250), s.cc.mss);
        try testing.expectEqual(@as(u64, 12500), s.cc.window);
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(10_000, {}, established, &bursts);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 300000", true);
        try h.runDelayed(10_000, id, finishedAndSearched, &bursts);
        try testing.expectEqual(@as(usize, 1250), h.largest_to_client);
        try testing.expectEqual(@as(u32, 0), s.pmtu.probes_sent);
    }
    {
        // Off: our start size throughout, whatever the path.
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, struct {
            fn f(c: *conn_mod.Config) void {
                c.max_datagram_size = 1350;
            }
        }.f);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(10_000, {}, established, &bursts);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 300000", true);
        try h.runDelayed(10_000, id, finishedStream, &bursts);
        try testing.expectEqual(@as(usize, 1350), h.largest_to_client);
        try testing.expectEqual(@as(u32, 0), h.server.?.pmtu.probes_sent);
    }
}

test "QUIC PMTU: an IPv6 path's ceiling is 20 bytes lower; EMSGSIZE fails a probe at once" {
    const h = try Harness.init(.{}, pmtuOn);
    defer h.deinit();
    h.ipv6 = true;
    try h.run(20);
    const s = h.server.?;
    try testing.expect(s.isEstablished());
    try testing.expectEqual(@as(u16, 1452), s.max_datagram);
    // A new path: back to the start size, searched again.
    s.onPathChange(h.now, h.ipv6, true);
    try testing.expectEqual(@as(u16, 1350), s.max_datagram);
    try testing.expectEqual(@as(u64, 1350), s.cc.mss);
    var buf: [1500]u8 = undefined;
    const in_flight = s.cc.in_flight;
    try testing.expectEqual(@as(usize, 1452), s.send(&buf, h.now));
    try testing.expectEqual(in_flight + 1452, s.cc.in_flight);
    // The interface refused it: out of the flight, the size failed, the
    // next probe halves the range at once.
    s.onProbeTooBig(h.now);
    try testing.expectEqual(in_flight, s.cc.in_flight);
    try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
    try testing.expectEqual(@as(u16, 1451), s.pmtu.ceiling);
    try testing.expectEqual(@as(usize, 1350 + (1451 - 1350 + 1) / 2), s.send(&buf, h.now));
    s.onProbeTooBig(h.now);
    try testing.expectEqual(@as(u16, 1400), s.pmtu.ceiling);
    // A refusal with no probe in flight changes nothing.
    s.onProbeTooBig(h.now);
    try testing.expectEqual(@as(u16, 1400), s.pmtu.ceiling);
    try testing.expectEqual(in_flight, s.cc.in_flight);
    try testing.expectEqual(@as(u16, 1350), s.max_datagram);
}

/// The server's interface shrinks once the download is halfway.
const IfaceChange = struct {
    id: u64,
    to: usize,
    changed: bool = false,

    fn done(c: *IfaceChange, h: *Harness) bool {
        if (!c.changed and halfway(c.id, h)) {
            c.changed = true;
            h.iface_max = c.to;
        }
        return finishedAndSearched(c.id, h);
    }
};

/// Everything lost both ways for `ms` once the download is halfway.
const Outage = struct {
    id: u64,
    ms: u64,
    started: bool = false,

    fn done(c: *Outage, h: *Harness) bool {
        if (!c.started and halfway(c.id, h)) {
            c.started = true;
            h.outage_until = h.now + c.ms * 1000;
        }
        return finishedAndSearched(c.id, h);
    }
};

test "QUIC PMTU: an outage that looks like a black hole costs one probe, not the size" {
    // Outages ending between the first and second probe timeouts: the
    // second's 1200-byte packets arrive after the full-sized ones were
    // lost. The size that failed is probed first again, so it comes back.
    var mistaken: u32 = 0;
    var ms: u64 = 40;
    while (ms <= 400) : (ms += 30) {
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(15_000, {}, established, &bursts);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 2000000", true);
        var outage: Outage = .{ .id = id, .ms = ms };
        try h.runDelayed(15_000, &outage, Outage.done, &bursts);
        try expectBody(h, id, 2_000_000);
        const s = h.server.?;
        mistaken += s.pmtu.black_holes;
        try testing.expectEqual(@as(u16, 1472), s.max_datagram);
        try testing.expectEqual(@as(u16, 1472), s.pmtu.ceiling);
    }
    std.debug.print("outages taken for black holes: {d} of 13\n", .{mistaken});
}

test "QUIC PMTU: datagrams the interface refuses go again at 1200, no congestion event, no probe timeout" {
    // In the handshake: the server's first flight (1350 bytes) refused.
    {
        const h = try Harness.init(.{}, pmtuOn);
        defer h.deinit();
        var buf: [1500]u8 = undefined;
        const n0 = try h.client.send(&buf);
        try h.toServer(buf[0..n0]);
        const s = h.server.?;
        const mark = s.sendMark();
        var refused: usize = 0;
        while (s.send(&buf, h.now) > 0) refused += 1;
        try testing.expect(refused > 0);
        try testing.expect(s.cc.in_flight > 0);
        try testing.expect(s.onSendRefused(mark, 1350, h.now));
        try testing.expectEqual(@as(u16, 1200), s.max_datagram);
        try testing.expectEqual(@as(u64, 0), s.cc.in_flight);
        try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
        // Everything again, at 1200, at once: the handshake completes
        // without a probe timeout.
        h.path_max = 1300;
        for (0..10) |_| {
            while (true) {
                const n = s.send(&buf, h.now);
                if (n == 0) break;
                // (Once established, a probe up to the lowered ceiling.)
                try testing.expect(n <= 1200 or (s.isEstablished() and n <= 1349));
                try h.toClient(buf[0..n], .not_ect);
            }
            while (true) {
                const n = try h.client.send(&buf);
                if (n == 0) break;
                try h.toServer(buf[0..n]);
            }
            h.now += 1000;
        }
        try testing.expect(s.isEstablished() and h.client.handshake_complete);
        try testing.expectEqual(@as(u32, 0), s.pto_count);
        try testing.expectEqual(@as(u16, 1349), s.pmtu.ceiling);
    }
    // Mid-download at 1472: the interface shrinks to 1400.
    {
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(10_000, {}, established, &bursts);
        const s = h.server.?;
        const lost = s.lost_packets;
        const recovery_start = s.cc.recovery_start;
        const id = try h.client.openBidi();
        try h.client.write(id, "big 2000000", true);
        var change: IfaceChange = .{ .id = id, .to = 1400 };
        try h.runDelayed(10_000, &change, IfaceChange.done, &bursts);
        try expectBody(h, id, 2_000_000);
        try testing.expect(h.refused > 0);
        // Nothing lost, no congestion event: the refused datagrams went
        // again at the smaller size.
        try testing.expectEqual(lost, s.lost_packets);
        try testing.expectEqual(recovery_start, s.cc.recovery_start);
        try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
        try testing.expect(s.max_datagram <= 1400 and 1400 - s.max_datagram < pmtud.min_step);
        std.debug.print("refused {d} datagrams; then up to {d}\n", .{ h.refused, s.max_datagram });
        // At 1200 there's nowhere lower: a refusal is a loss like any other.
        s.max_datagram = 1200;
        try testing.expect(!s.onSendRefused(s.sendMark(), 1200, h.now));
    }
}

test "QUIC PMTU: no discovery where the socket can't set DF; a ceiling under the start lowers the start" {
    {
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
        defer h.deinit();
        h.dont_fragment = false;
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(10_000, {}, established, &bursts);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 300000", true);
        try h.runDelayed(10_000, id, finishedStream, &bursts);
        try testing.expectEqual(@as(usize, 1350), h.largest_to_client);
        try testing.expectEqual(@as(u32, 0), h.server.?.pmtu.probes_sent);
        // A new path whose family has DF: discovery starts.
        h.server.?.onPathChange(h.now, false, true);
        try testing.expectEqual(@as(?u16, 1472), h.server.?.pmtu.due(h.now));
    }
    {
        // max_mtu 1300 over IPv4: 1272 bytes from the first datagram.
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, struct {
            fn f(c: *conn_mod.Config) void {
                pmtuOn(c);
                c.max_mtu = 1300;
            }
        }.f);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(10_000, {}, established, &bursts);
        const s = h.server.?;
        try testing.expectEqual(@as(u16, 1272), s.max_datagram);
        try testing.expectEqual(@as(u64, 1272), s.cc.mss);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 300000", true);
        try h.runDelayed(10_000, id, finishedStream, &bursts);
        try testing.expectEqual(@as(usize, 1272), h.largest_to_client);
        // After a black hole the confirmation probe stays under it too.
        _ = s.pmtu.onBlackHole(h.now);
        try testing.expectEqual(@as(?u16, 1272), s.pmtu.due(h.now));
    }
}

test "QUIC PMTU: a new path's family sets its ceiling, and a refusal on the old route is forgotten" {
    const h = try Harness.init(.{}, pmtuOn);
    defer h.deinit();
    try h.run(20);
    const s = h.server.?;
    try testing.expectEqual(@as(u16, 1472), s.max_datagram);
    s.onPathChange(h.now, false, true);
    var buf: [1500]u8 = undefined;
    try testing.expectEqual(@as(usize, 1472), s.send(&buf, h.now));
    s.onProbeTooBig(h.now);
    try testing.expectEqual(@as(u16, 1471), s.pmtu.ceiling);
    // To an IPv6 address: 1452.
    s.onPathChange(h.now, true, true);
    try testing.expectEqual(@as(u16, 1452), s.pmtu.ceiling);
    try testing.expectEqual(@as(usize, 1452), s.send(&buf, h.now));
    // And back to IPv4: 1472 again, the old refusal forgotten.
    s.onPathChange(h.now, false, true);
    try testing.expectEqual(@as(u16, 1472), s.pmtu.ceiling);
}

test "QUIC PMTU: probes wait for the pacer" {
    const h = try Harness.init(.{}, pmtuOn);
    defer h.deinit();
    try h.run(20);
    const s = h.server.?;
    s.onPathChange(h.now, false, true);
    // An empty bucket: no probe until it has a datagram's worth.
    s.pacer.refill(h.now, &s.cc, &s.rtt);
    s.pacer.onSent(s.pacer.tokens);
    var buf: [1500]u8 = undefined;
    const sent = s.pmtu.probes_sent;
    try testing.expect(s.send(&buf, h.now) <= s.max_datagram);
    try testing.expectEqual(sent, s.pmtu.probes_sent);
    // Later, it goes.
    h.now += 50_000;
    try testing.expectEqual(@as(usize, 1472), s.send(&buf, h.now));
}

test "QUIC PMTU: an outage isn't a black hole: the size stays" {
    for ([_]u64{ 200, 700, 3000 }) |ms| {
        const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
        defer h.deinit();
        var bursts: std.ArrayList(Burst) = .empty;
        defer bursts.deinit(h.a);
        try h.runDelayed(15_000, {}, established, &bursts);
        const id = try h.client.openBidi();
        try h.client.write(id, "big 2000000", true);
        var outage: Outage = .{ .id = id, .ms = ms };
        try h.runDelayed(15_000, &outage, Outage.done, &bursts);
        try expectBody(h, id, 2_000_000);
        const s = h.server.?;
        try testing.expect(s.lost_packets > 0);
        try testing.expectEqual(@as(u32, 0), s.pmtu.black_holes);
        try testing.expectEqual(@as(u16, 1472), s.max_datagram);
    }
}

/// A path whose datagram limit changes when the download is halfway.
const MtuChange = struct {
    id: u64,
    to: usize,
    changed: bool = false,

    fn done(c: *MtuChange, h: *Harness) bool {
        if (!c.changed and halfway(c.id, h)) {
            c.changed = true;
            h.path_max = c.to;
        }
        return finishedAndSearched(c.id, h);
    }
};

test "verify PMTU: random paths, limits, losses and changes: every download completes, sizes within the path" {
    var prng = std.Random.DefaultPrng.init(0x9e3779b9);
    const r = prng.random();
    for (0..40) |seed| {
        const h = try Harness.init(.{ .seed = @intCast(seed + 1), .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
        defer h.deinit();
        h.prng = .init(seed);
        const limits = [_]usize{ 1232, 1252, 1280, 1300, 1350, 1380, 1400, 1420, 1452, 1472, 1500 };
        h.path_max = limits[r.uintLessThan(usize, limits.len)];
        const path: Path = .{
            .delay = 2_000 + r.uintLessThan(u64, 40_000),
            .jitter = if (r.boolean()) r.uintLessThan(u64, 5_000) else 0,
            .loss = if (r.boolean()) r.uintLessThan(u8, 6) else 0,
        };
        runPath(h, path, {}, established) catch |err| {
            std.debug.print("seed {d}: handshake {s} (path {any}, limit {d})\n", .{ seed, @errorName(err), path, h.path_max });
            return err;
        };
        const id = try h.client.openBidi();
        try h.client.write(id, "big 1000000", true);
        var change: MtuChange = .{ .id = id, .to = limits[r.uintLessThan(usize, limits.len)] };
        const start = h.now;
        runPath(h, path, &change, MtuChange.done) catch |err| {
            std.debug.print("seed {d}: {s} (path {any}, limit {d} -> {d}, {d} black holes, max {d})\n", .{ seed, @errorName(err), path, h.path_max, change.to, h.server.?.pmtu.black_holes, h.server.?.max_datagram });
            return err;
        };
        try expectBody(h, id, 1_000_000);
        const s = h.server.?;
        try testing.expect(s.max_datagram <= @min(h.path_max, 1472));
        try testing.expectEqual(@as(u64, s.max_datagram), s.cc.mss);
        try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
        if (h.now - start > 60 * std.time.us_per_s) {
            std.debug.print("seed {d}: {d} ms\n", .{ seed, (h.now - start) / 1000 });
            return error.TooSlow;
        }
    }
}

/// A download whose path changes at fixed points: each step at a quarter
/// more of the body, the limit changes (and, with `ku`, the client
/// initiates a key update, as soon as the last one is complete: RFC 9001
/// §6.5, which the test client doesn't track itself; with `rebind`, the
/// client's address changes).
const Flapping = struct {
    id: u64,
    total: usize,
    limits: []const usize,
    step: usize = 0,
    ku: bool = false,
    ku_pending: u32 = 0,
    key_updates: u32 = 0,
    rebind: bool = false,

    fn done(c: *Flapping, h: *Harness) bool {
        const got = h.client.readAll(c.id).len;
        while (c.step < c.limits.len and got >= c.total * (c.step + 1) / (c.limits.len + 1)) : (c.step += 1) {
            h.path_max = c.limits[c.step];
            if (c.ku) c.ku_pending += 1;
            if (c.rebind) h.server.?.onPathChange(h.now, h.ipv6, true);
        }
        const s = h.server.?;
        if (c.ku_pending > 0 and s.tx_phase == h.client.key_phase and s.tx_phase_acked) {
            c.ku_pending -= 1;
            c.key_updates += 1;
            h.client.initiateKeyUpdate();
            h.client.followKeyUpdate();
        }
        return finishedAndSearched(c.id, h);
    }
};

test "verify PMTU: a path flapping between sizes mid-download, with key updates and rebinding: completes, sizes within the path" {
    const seqs = [_][]const usize{
        &.{ 1300, 1500, 1252, 9000, 1350, 1500, 1232 },
        &.{ 1232, 1500, 1232, 1500, 1232 },
        &.{ 1472, 1471, 1300, 1299, 1500 },
    };
    for (seqs) |limits| {
        for ([_]bool{ false, true }) |ku| {
            for ([_]bool{ false, true }) |rebind| {
                for ([_]Path{ .{ .delay = 10_000 }, .{ .delay = 15_000, .jitter = 3_000, .loss = 2 } }) |path| {
                    const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
                    defer h.deinit();
                    try runPath(h, path, {}, established);
                    const id = try h.client.openBidi();
                    try h.client.write(id, "big 3000000", true);
                    var f: Flapping = .{ .id = id, .total = 3_000_000, .limits = limits, .ku = ku, .rebind = rebind };
                    const start = h.now;
                    runPath(h, path, &f, Flapping.done) catch |err| {
                        const sv = h.server.?;
                        std.debug.print("limits {any} ku {} rebind {} path {any}: {s} at step {d}, got {d}; server tx {d} rx {d} acked {} max {d} bh {d} pto {d}; client tx {d} rx {d}\n", .{ limits, ku, rebind, path, @errorName(err), f.step, h.client.readAll(id).len, sv.tx_phase, sv.rx_phase, sv.tx_phase_acked, sv.max_datagram, sv.pmtu.black_holes, sv.pto_count, h.client.key_phase, h.client.rx_phase });
                        return err;
                    };
                    try expectBody(h, id, 3_000_000);
                    if (ku) try testing.expect(f.key_updates >= 2);
                    const s = h.server.?;
                    const last = limits[limits.len - 1];
                    try testing.expect(s.max_datagram <= @min(last, 1472));
                    try testing.expectEqual(@as(u64, s.max_datagram), s.cc.mss);
                    try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
                    if (h.now - start > 60 * std.time.us_per_s) {
                        std.debug.print("limits {any} ku {} rebind {} path {any}: {d} ms\n", .{ limits, ku, rebind, path, (h.now - start) / 1000 });
                        return error.TooSlow;
                    }
                }
            }
        }
    }
}

test "verify PMTU: random loss on a path that carries every size is no black hole" {
    // Up to 10% loss in order. (Known, 2026-10-30: at 20% loss about half
    // the runs see a black hole, from two probe timeouts in a row whose
    // 1200-byte packets arrive; with 2 ms of jitter on 10 ms, reordered
    // probes declared lost fail sizes that arrive, and 10% loss finds black
    // holes too. Each costs a few bytes of datagram until the raise timer.)
    var false_positives: u32 = 0;
    var runs: u32 = 0;
    for ([_]u8{ 2, 5, 10 }) |loss| {
        for (0..6) |seed| {
            const h = try Harness.init(.{ .seed = @intCast(seed + 1), .max_stream_data = 8 << 20, .max_data = 16 << 20 }, pmtuOn);
            defer h.deinit();
            h.prng = .init(seed * 7 + loss);
            const path: Path = .{ .delay = 10_000, .jitter = 0, .loss = loss };
            try runPath(h, path, {}, established);
            const id = try h.client.openBidi();
            try h.client.write(id, "big 1500000", true);
            try runPath(h, path, id, finishedAndSearched);
            try expectBody(h, id, 1_500_000);
            const s = h.server.?;
            runs += 1;
            if (s.pmtu.black_holes > 0 or s.max_datagram != 1472) {
                false_positives += 1;
                std.debug.print("loss {d}% seed {d}: {d} black holes, max {d}, {d} probes lost\n", .{ loss, seed, s.pmtu.black_holes, s.max_datagram, s.pmtu.probes_lost });
            }
        }
    }
    try testing.expectEqual(@as(u32, 0), false_positives);
}

test "verify PMTU: a stale probe acknowledged with the current one doesn't hide the current one's acknowledgment" {
    // NAT rebinding while a probe is in flight: the search restarts and
    // sends a new probe; the client gets both and acknowledges them in
    // one ACK.
    const h = try Harness.init(.{}, pmtuOn);
    defer h.deinit();
    var bursts: std.ArrayList(Burst) = .empty;
    defer bursts.deinit(h.a);
    try h.runDelayed(10_000, {}, searchDone, &bursts);
    const s = h.server.?;
    try testing.expectEqual(@as(u16, 1472), s.max_datagram);
    var p1: [1500]u8 = undefined;
    var p2: [1500]u8 = undefined;
    s.onPathChange(h.now, h.ipv6, true);
    const n1 = s.send(&p1, h.now);
    try testing.expectEqual(@as(usize, 1472), n1);
    h.now += 1000;
    s.onPathChange(h.now, h.ipv6, true);
    const n2 = s.send(&p2, h.now);
    try testing.expectEqual(@as(usize, 1472), n2);
    try h.toClient(p1[0..n1], .not_ect);
    try h.toClient(p2[0..n2], .not_ect);
    h.now += 1000;
    var buf: [1500]u8 = undefined;
    while (true) {
        const n = try h.client.send(&buf);
        if (n == 0) break;
        try h.toServer(buf[0..n]);
    }
    // P2's acknowledgment counted: the size grew back, and nothing waits
    // for a probe that was acknowledged (else the search would hang in
    // `searching` for good: no probe, no raise timer).
    const id = try h.client.openBidi();
    try h.client.write(id, "big 300000", true);
    try h.runDelayed(10_000, id, finishedStream, &bursts);
    try expectBody(h, id, 300_000);
    if (s.pmtu.probe_pn != null) std.debug.print("search stuck: probe_pn {d} acknowledged long ago, state {s}, max_datagram {d}\n", .{ s.pmtu.probe_pn.?, @tagName(s.pmtu.state), s.max_datagram });
    try testing.expectEqual(@as(?u64, null), s.pmtu.probe_pn);
    try testing.expectEqual(@as(u16, 1472), s.max_datagram);
}

test "verify PMTU: odd client max_udp_payload_size values, IPv4 and IPv6: no datagram over them, probes included" {
    const limits = [_]u64{ 1200, 1201, 1349, 1350, 1351, 1451, 1452, 1453, 1471, 1472, 1473, 2048, 65527, 1 << 40 };
    for ([_]bool{ false, true }) |v6| {
        for ([_]usize{ std.math.maxInt(usize), 1300 }) |path_max| {
            for (limits) |limit| {
                const h = try Harness.init(.{ .max_stream_data = 8 << 20, .max_data = 16 << 20, .max_udp_payload_size = limit }, pmtuOn);
                defer h.deinit();
                h.ipv6 = v6;
                h.path_max = path_max;
                try runPath(h, .{ .delay = 10_000 }, {}, established);
                const id = try h.client.openBidi();
                try h.client.write(id, "big 400000", true);
                runPath(h, .{ .delay = 10_000 }, id, finishedAndSearched) catch |err| {
                    std.debug.print("limit {d} v6 {} path {d}: {s}\n", .{ limit, v6, path_max, @errorName(err) });
                    return err;
                };
                try expectBody(h, id, 400_000);
                const s = h.server.?;
                const ceiling: u64 = if (v6) 1452 else 1472;
                const want = @min(limit, ceiling, path_max);
                if (h.largest_to_client > limit) {
                    std.debug.print("limit {d} v6 {} path {d}: sent {d}\n", .{ limit, v6, path_max, h.largest_to_client });
                    return error.OverPeerLimit;
                }
                try testing.expect(s.max_datagram <= want);
                try testing.expect(want - s.max_datagram < pmtud.min_step);
                try testing.expectEqual(@as(u64, s.max_datagram), s.cc.mss);
                if (limit <= 1350 and path_max > 1350) try testing.expectEqual(@as(u32, 0), s.pmtu.probes_sent);
                try testing.expectEqual(liveInFlight(s), s.cc.in_flight);
            }
        }
    }
}
