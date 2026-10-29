//! permessage-deflate (RFC 7692): negotiation, and the DEFLATE streams on
//! either side of a WebSocket, without I/O.
//!
//! What the server agrees to:
//! - It compresses each message on its own (`server_no_context_takeover`,
//!   always in the response), so one compressor per worker
//!   (`compress.Compressor`) serves all its connections and a connection
//!   holds no compression state. Back references stay within the window the
//!   client allows (`server_max_window_bits`).
//! - It keeps the client's window between messages (context takeover), at
//!   64 KiB plus 3 KiB per connection while compressed messages arrive, or,
//!   with `Options.client_no_context_takeover`, asks the client not to and
//!   keeps nothing between messages.
const std = @import("std");
const flate = std.compress.flate;
const Request = @import("../request.zig").Request;
const BufferPool = @import("../http/session.zig").BufferPool;
const compress = @import("./compress.zig");

pub const Options = struct {
    /// Messages shorter than this are sent uncompressed (DEFLATE rarely
    /// shrinks them).
    min_size: usize = 64,
    /// Ask clients to compress each message on its own, so no inflate
    /// window is kept per connection between messages, at some cost in
    /// how well clients' messages compress.
    client_no_context_takeover: bool = false,
};

/// What was negotiated for one WebSocket.
pub const Agreement = struct {
    enabled: bool = false,
    /// The client compresses each message on its own: no window is kept.
    client_no_context_takeover: bool = false,
    /// The server's window: back references reach at most 2^this bytes.
    server_window_bits: u4 = 15,
};

/// Longest response element we write.
pub const max_response_len = "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=15".len;

pub const Negotiated = struct {
    agreement: Agreement,
    /// The Sec-WebSocket-Extensions value to send back (in `buf`).
    response: []const u8,
};

/// Picks the first permessage-deflate offer in the request's
/// Sec-WebSocket-Extensions fields that can be accepted (RFC 7692 §5,
/// §7.1), and the response element accepting it. Null if there is none.
pub fn negotiate(req: *const Request, opts: Options, buf: *[max_response_len]u8) ?Negotiated {
    for (req.getHeaders()) |h| {
        if (!std.ascii.eqlIgnoreCase(h.key, "sec-websocket-extensions")) continue;
        var offers = std.mem.splitScalar(u8, h.value, ',');
        while (offers.next()) |offer| {
            if (acceptOffer(offer, opts, buf)) |n| return n;
        }
    }
    return null;
}

const Param = enum { server_no_context_takeover, client_no_context_takeover, server_max_window_bits, client_max_window_bits };

fn acceptOffer(offer: []const u8, opts: Options, buf: *[max_response_len]u8) ?Negotiated {
    var parts = std.mem.splitScalar(u8, offer, ';');
    const name = std.mem.trim(u8, parts.first(), " \t");
    if (!std.ascii.eqlIgnoreCase(name, "permessage-deflate")) return null;
    var seen: std.EnumSet(Param) = .{};
    var client_no_takeover = opts.client_no_context_takeover;
    var server_bits: ?u8 = null;
    while (parts.next()) |part| {
        const p = std.mem.trim(u8, part, " \t");
        const eq = std.mem.indexOfScalar(u8, p, '=');
        const key = std.mem.trim(u8, p[0 .. eq orelse p.len], " \t");
        var value: ?[]const u8 = if (eq) |i| std.mem.trim(u8, p[i + 1 ..], " \t") else null;
        if (value) |v| {
            // A quoted-string value (RFC 7692 §5.1 allows it).
            if (v.len >= 2 and v[0] == '"' and v[v.len - 1] == '"') value = v[1 .. v.len - 1];
        }
        const param = std.meta.stringToEnum(Param, key) orelse return null;
        if (seen.contains(param)) return null;
        seen.insert(param);
        switch (param) {
            .server_no_context_takeover => if (value != null) return null,
            .client_no_context_takeover => {
                if (value != null) return null;
                client_no_takeover = true;
            },
            .server_max_window_bits => server_bits = windowBits(value orelse return null) orelse return null,
            // Any window the client uses is one we can inflate, so the
            // response leaves it as it is.
            .client_max_window_bits => if (value) |v| {
                _ = windowBits(v) orelse return null;
            },
        }
    }
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll("permessage-deflate; server_no_context_takeover") catch unreachable;
    if (client_no_takeover) w.writeAll("; client_no_context_takeover") catch unreachable;
    if (server_bits) |b| w.print("; server_max_window_bits={d}", .{b}) catch unreachable;
    return .{
        .agreement = .{
            .enabled = true,
            .client_no_context_takeover = client_no_takeover,
            .server_window_bits = @intCast(server_bits orelse 15),
        },
        .response = w.buffered(),
    };
}

/// 8 to 15, decimal without leading zeros (RFC 7692 §7.1.2.1).
fn windowBits(v: []const u8) ?u8 {
    if (v.len == 0 or v.len > 2 or v[0] == '0') return null;
    const n = std.fmt.parseInt(u8, v, 10) catch return null;
    return if (n >= 8 and n <= 15) n else null;
}

pub const InflateError = error{ InvalidData, MessageTooBig, OutOfMemory };

/// Where the inflate stream reads when no message is being inflated.
var no_input: std.Io.Reader = .fixed(&.{});

/// The client-to-server DEFLATE stream of one connection. Its window
/// (the last 32 KiB of output) carries over from message to message unless
/// the client compresses each on its own.
pub const Inflater = struct {
    d: flate.Decompress,
    window: []u8,

    pub fn create(pool: *BufferPool) !*Inflater {
        const window = try pool.acquireLarge(flate.max_window_len);
        errdefer pool.releaseLarge(window);
        const self = try pool.allocator.create(Inflater);
        self.* = .{ .d = .init(&no_input, .raw, window), .window = window };
        return self;
    }

    pub fn destroy(self: *Inflater, pool: *BufferPool) void {
        pool.releaseLarge(self.window);
        pool.allocator.destroy(self);
    }

    /// Inflates one message's payload, which must be followed in memory by
    /// the 4 bytes 00 00 ff ff that the sender left off (`input` includes
    /// them), calling `out.append` with the output as it is produced.
    pub fn inflate(self: *Inflater, input: []const u8, out: anytype) InflateError!void {
        var in: std.Io.Reader = .fixed(input);
        const d = &self.d;
        d.input = &in;
        d.err = null;
        defer d.input = &no_input;
        const r = &d.reader;
        var ended = false;
        while (true) {
            const ready = r.buffered();
            if (ready.len > 0) {
                try out.append(ready);
                r.toss(ready.len);
            }
            if (ended) break;
            r.fillMore() catch |err| switch (err) {
                // A final block ended the stream: the next message starts a
                // new one, with an empty window.
                error.EndOfStream => ended = true,
                // Out of input where the next block would start: the empty
                // stored block that ends every message. Anything else (a
                // block cut short, bad codes) is corrupt.
                error.ReadFailed => {
                    if (d.err != @as(?flate.Decompress.Error, error.EndOfStream) or d.state != .block_header or in.bufferedLen() != 0) {
                        self.reset();
                        return error.InvalidData;
                    }
                    ended = true;
                },
            };
        }
        if (d.state == .end) self.reset();
    }

    /// Starts a new stream with an empty window.
    pub fn reset(self: *Inflater) void {
        self.d = .init(&no_input, .raw, self.window);
    }
};

/// The trailer the sender leaves off each message (RFC 7692 §7.2.1).
pub const trailer = [4]u8{ 0x00, 0x00, 0xff, 0xff };

/// A worker's compressor: every message it sends is compressed on its own,
/// so one serves all the worker's connections.
pub const Deflater = compress.Compressor;

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn testNegotiate(values: []const []const u8, opts: Options) !?Negotiated {
    var req = try Request.init(testing.allocator);
    defer req.deinit();
    for (values, 0..) |v, i| req.headers[i] = .{ .key = "Sec-WebSocket-Extensions", .value = v };
    req.headers_len = values.len;
    const S = struct {
        var buf: [max_response_len]u8 = undefined;
    };
    return negotiate(req, opts, &S.buf);
}

test "negotiation: accepted offers and the response" {
    const cases = [_]struct { offer: []const []const u8, opts: Options = .{}, response: ?[]const u8, agreement: Agreement = .{ .enabled = true } }{
        // Browsers.
        .{ .offer = &.{"permessage-deflate; client_max_window_bits"}, .response = "permessage-deflate; server_no_context_takeover" },
        .{ .offer = &.{"permessage-deflate"}, .response = "permessage-deflate; server_no_context_takeover" },
        .{
            .offer = &.{"permessage-deflate; client_no_context_takeover"},
            .response = "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            .agreement = .{ .enabled = true, .client_no_context_takeover = true },
        },
        .{
            .offer = &.{"permessage-deflate"},
            .opts = .{ .client_no_context_takeover = true },
            .response = "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            .agreement = .{ .enabled = true, .client_no_context_takeover = true },
        },
        // A smaller server window: accepted, and kept to.
        .{
            .offer = &.{"permessage-deflate; server_max_window_bits=9; client_max_window_bits=\"10\""},
            .response = "permessage-deflate; server_no_context_takeover; server_max_window_bits=9",
            .agreement = .{ .enabled = true, .server_window_bits = 9 },
        },
        .{ .offer = &.{"permessage-deflate;server_max_window_bits=15"}, .response = "permessage-deflate; server_no_context_takeover; server_max_window_bits=15" },
        // Unknown extensions and unacceptable offers are skipped.
        .{ .offer = &.{ "x-webkit-deflate-frame", "foo, permessage-deflate; server_no_context_takeover" }, .response = "permessage-deflate; server_no_context_takeover" },
        .{ .offer = &.{"permessage-deflate; bogus, permessage-deflate"}, .response = "permessage-deflate; server_no_context_takeover" },
        .{ .offer = &.{"permessage-deflate; server_max_window_bits=7, permessage-deflate; server_max_window_bits"}, .response = null },
        .{ .offer = &.{"permessage-deflate; client_no_context_takeover; client_no_context_takeover"}, .response = null },
        .{ .offer = &.{"permessage-deflate; server_no_context_takeover=1"}, .response = null },
        .{ .offer = &.{"permessage-deflate; client_max_window_bits=08"}, .response = null },
        .{ .offer = &.{"permessage-deflate; client_max_window_bits=16"}, .response = null },
        .{ .offer = &.{}, .response = null },
    };
    for (cases) |c| {
        const got = try testNegotiate(c.offer, c.opts);
        if (c.response) |want| {
            try testing.expectEqualStrings(want, got.?.response);
            try testing.expectEqual(c.agreement, got.?.agreement);
        } else {
            try testing.expect(got == null);
        }
    }
}

const TestSink = struct {
    out: std.ArrayList(u8) = .empty,
    max: usize = 1 << 20,
    pub fn append(self: *TestSink, bytes: []const u8) InflateError!void {
        if (self.out.items.len + bytes.len > self.max) return error.MessageTooBig;
        try self.out.appendSlice(testing.allocator, bytes);
    }
};

/// A client's stream with context takeover: one compressor across
/// messages, flushed after each, the empty stored block appended and its
/// last four bytes dropped (what zlib's Z_SYNC_FLUSH gives). For tests.
pub const TestClient = struct {
    c: flate.Compress,
    buf: [flate.max_window_len]u8,
    out: std.Io.Writer.Allocating,

    pub fn init(t: *TestClient) !void {
        t.out = try .initCapacity(testing.allocator, 1 << 16);
        t.c = try flate.Compress.init(&t.out.writer, &t.buf, .raw, .default);
    }

    /// One message, with the trailer still on: drop the last 4 bytes to
    /// send it. Caller frees.
    pub fn message(t: *TestClient, text: []const u8) ![]u8 {
        try t.c.writer.writeAll(text);
        try t.c.writer.flush();
        try t.out.writer.writeAll(&.{ 0, 0, 0, 0xff, 0xff });
        return t.out.toOwnedSlice();
    }
};

test "inflate: messages with context takeover, final blocks, corrupt input, size limit" {
    var pool = try BufferPool.init(testing.allocator, 1024, 1);
    defer pool.deinit();
    const inf = try Inflater.create(&pool);
    defer inf.destroy(&pool);

    var client: TestClient = undefined;
    try client.init();
    defer client.out.deinit();
    const text = "Hello, hello, hello! The same words again and again compress well. ";
    var sizes: [3]usize = undefined;
    for (0..3) |i| {
        const m = try client.message(text);
        defer testing.allocator.free(m);
        sizes[i] = m.len - 4;
        var sink: TestSink = .{};
        defer sink.out.deinit(testing.allocator);
        try inf.inflate(m, &sink);
        try testing.expectEqualStrings(text, sink.out.items);
    }
    // Later messages refer back to the first: much smaller.
    try testing.expect(sizes[1] < sizes[0] / 2);

    // A message ending in a final block (no trailer needed, but it is
    // appended anyway): inflated, then the next starts a fresh stream.
    {
        var out: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 1 << 16);
        defer out.deinit();
        var buf: [flate.max_window_len]u8 = undefined;
        var c = try flate.Compress.init(&out.writer, &buf, .raw, .default);
        try c.writer.writeAll("final");
        try c.finish();
        try out.writer.writeAll(&trailer);
        var sink: TestSink = .{};
        defer sink.out.deinit(testing.allocator);
        try inf.inflate(out.written(), &sink);
        try testing.expectEqualStrings("final", sink.out.items);
    }
    {
        var fresh: TestClient = undefined;
        try fresh.init();
        defer fresh.out.deinit();
        const m = try fresh.message("after a reset");
        defer testing.allocator.free(m);
        var sink: TestSink = .{};
        defer sink.out.deinit(testing.allocator);
        try inf.inflate(m, &sink);
        try testing.expectEqualStrings("after a reset", sink.out.items);
    }
    // Corrupt: a block type of 3, and a stored block cut short.
    {
        var sink: TestSink = .{};
        defer sink.out.deinit(testing.allocator);
        try testing.expectError(error.InvalidData, inf.inflate(&.{ 0x07, 0x00, 0x00, 0xff, 0xff }, &sink));
        try testing.expectError(error.InvalidData, inf.inflate(&.{ 0x00, 0x10, 0x00, 0xef, 0xff, 'a', 0x00, 0x00, 0xff, 0xff }, &sink));
    }
    // A bomb: a megabyte of zeros in a few hundred bytes stops at the limit.
    {
        var fresh: TestClient = undefined;
        try fresh.init();
        defer fresh.out.deinit();
        const zeros = try testing.allocator.alloc(u8, 1 << 20);
        defer testing.allocator.free(zeros);
        @memset(zeros, 0);
        const m = try fresh.message(zeros);
        defer testing.allocator.free(m);
        try testing.expect(m.len < 4096);
        inf.reset();
        var sink: TestSink = .{ .max = 64 * 1024 };
        defer sink.out.deinit(testing.allocator);
        try testing.expectError(error.MessageTooBig, inf.inflate(m, &sink));
    }
}

test "deflate: messages round-trip on their own, in small windows too, and incompressible ones are refused" {
    const d = try testing.allocator.create(Deflater);
    defer testing.allocator.destroy(d);
    d.init();
    var pool = try BufferPool.init(testing.allocator, 1024, 1);
    defer pool.deinit();
    const inf = try Inflater.create(&pool);
    defer inf.destroy(&pool);

    var big: [5000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = "abcdefgh"[i % 8] + @as(u8, @intCast(i / 1000));
    const messages = [_][]const u8{ "a message that repeats, a message that repeats, a message that repeats", &big };
    var out: [8192]u8 = undefined;
    for ([_]u4{ 15, 9 }) |bits| {
        for (messages) |m| {
            const n = d.compress(m, out[0..m.len], bits).?;
            try testing.expect(n < m.len);
            // Each message stands alone: a fresh inflater reads it.
            inf.reset();
            @memcpy(out[n..][0..4], &trailer);
            var sink: TestSink = .{};
            defer sink.out.deinit(testing.allocator);
            try inf.inflate(out[0 .. n + 4], &sink);
            try testing.expectEqualSlices(u8, m, sink.out.items);
        }
    }
    var noise: [600]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(1);
    prng.random().bytes(&noise);
    try testing.expectEqual(@as(?usize, null), d.compress(&noise, out[0..noise.len], 15));
}
