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
            });
            h.first_datagram_len = dgram.len;
        }
        _ = h.server.?.recv(dgram, h.now);
        try EchoApp.run(h.server.?);
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
                    const n = s.send(&buf, h.now);
                    if (n == 0) break;
                    progress = true;
                    h.datagrams_to_client += 1;
                    h.bytes_to_client += n;
                    if (!h.dropped()) try h.client.recv(buf[0..n]);
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
                    const n = s.send(&buf, h.now);
                    if (n == 0) break;
                    bytes += s.cc.in_flight - in_flight;
                    try queue.append(h.a, .{ .at = h.now + delay, .to_server = false, .len = n, .buf = buf });
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
                if (f.to_server) try h.toServer(f.buf[0..f.len]) else try h.client.recv(f.buf[0..f.len]);
            }
            if (timer) |t| if (t <= h.now) {
                h.server.?.onTimeout(h.now);
                try EchoApp.run(h.server.?);
            };
        }
    }
};

/// A datagram on its way over a delayed path.
const Flight = struct { at: u64, to_server: bool, len: usize, buf: [1500]u8 };

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
    try testing.expectEqual(s.pacer.nextSend(s.max_datagram, &s.cc, &s.rtt).?, due);
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
