//! QUIC frames (RFC 9000 §12.4, §19): an I/O-free parser and serialisers.
//! `parse` returns one frame at a time with slices into the (decrypted)
//! payload. Every encoding rule of the frame definitions is checked here
//! and mapped to the transport error the RFC names; rules that depend on
//! connection or stream state belong to conn.zig.
const std = @import("std");
const packet = @import("./packet.zig");
const Reader = packet.Reader;
const Writer = packet.Writer;
const varintLen = packet.varintLen;

/// Transport error codes (§20.1).
pub const TransportError = enum(u64) {
    no_error = 0x0,
    internal_error = 0x1,
    connection_refused = 0x2,
    flow_control_error = 0x3,
    stream_limit_error = 0x4,
    stream_state_error = 0x5,
    final_size_error = 0x6,
    frame_encoding_error = 0x7,
    transport_parameter_error = 0x8,
    connection_id_limit_error = 0x9,
    protocol_violation = 0xa,
    invalid_token = 0xb,
    application_error = 0xc,
    crypto_buffer_exceeded = 0xd,
    key_update_error = 0xe,
    aead_limit_reached = 0xf,
    no_viable_path = 0x10,
    _,

    /// CRYPTO_ERROR carrying a TLS alert (§20.1).
    pub fn crypto(alert: u8) TransportError {
        return @fromBackingInt(0x100 | @as(u64, alert));
    }
};

pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    // 0x08-0x0f: STREAM with OFF (0x04), LEN (0x02) and FIN (0x01) bits.
    stream = 0x08,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    _,
};

pub const stream_off: u8 = 0x04;
pub const stream_len: u8 = 0x02;
pub const stream_fin: u8 = 0x01;
/// Largest stream count in MAX_STREAMS and STREAMS_BLOCKED (§19.11).
pub const max_streams_limit: u64 = 1 << 60;

pub const Ack = struct {
    largest: u64,
    /// In units of 2^ack_delay_exponent microseconds.
    delay: u64,
    first_range: u64,
    /// The encoded Gap/ACK Range pairs, already checked by `parse`.
    ranges: []const u8,
    range_count: u64,
    ecn: ?[3]u64 = null,

    /// Acknowledged ranges, largest first.
    pub fn iterator(self: *const Ack) AckIterator {
        return .{ .r = .{ .data = self.ranges }, .largest = self.largest, .len = self.first_range, .left = self.range_count, .first = true };
    }
};

pub const Range = struct { smallest: u64, largest: u64 };

pub const AckIterator = struct {
    r: Reader,
    largest: u64,
    len: u64,
    left: u64,
    first: bool,

    pub fn next(self: *AckIterator) ?Range {
        if (self.first) {
            self.first = false;
            return .{ .smallest = self.largest - self.len, .largest = self.largest };
        }
        if (self.left == 0) return null;
        self.left -= 1;
        // Validated by parse: these neither fail nor underflow.
        const gap = self.r.varint() catch unreachable;
        const len = self.r.varint() catch unreachable;
        self.largest = self.largest - self.len - gap - 2;
        self.len = len;
        return .{ .smallest = self.largest - len, .largest = self.largest };
    }
};

pub const Stream = struct {
    id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
};

pub const Frame = union(enum) {
    /// A run of PADDING frames, coalesced.
    padding,
    ping,
    ack: Ack,
    reset_stream: struct { id: u64, code: u64, final_size: u64 },
    stop_sending: struct { id: u64, code: u64 },
    crypto: struct { offset: u64, data: []const u8 },
    new_token: []const u8,
    stream: Stream,
    max_data: u64,
    max_stream_data: struct { id: u64, max: u64 },
    max_streams: struct { bidi: bool, max: u64 },
    data_blocked: u64,
    stream_data_blocked: struct { id: u64, limit: u64 },
    streams_blocked: struct { bidi: bool, limit: u64 },
    new_connection_id: struct { seq: u64, retire_prior_to: u64, cid: []const u8, reset_token: *const [16]u8 },
    retire_connection_id: u64,
    path_challenge: [8]u8,
    path_response: [8]u8,
    connection_close: struct { app: bool, code: u64, frame_type: u64, reason: []const u8 },
    handshake_done,
};

pub const Failure = struct {
    code: TransportError,
    frame_type: u64,
};

/// Parses the next frame from `r` (a packet's plaintext payload). A
/// failure is a connection error with the code to close with.
pub fn parse(r: *Reader) union(enum) { frame: Frame, failure: Failure } {
    const start = r.pos;
    const ty = r.varint() catch return fail(.frame_encoding_error, 0);
    // §12.4: frame types use the shortest encoding.
    if (r.pos - start != varintLen(ty)) return fail(.protocol_violation, ty);
    const frame = parseBody(r, ty) catch |err| return fail(switch (err) {
        error.Malformed => .frame_encoding_error,
        error.UnknownType => .frame_encoding_error,
    }, ty);
    return .{ .frame = frame };
}

fn fail(code: TransportError, ty: u64) @typeInfo(@TypeOf(parse)).@"fn".return_type.? {
    return .{ .failure = .{ .code = code, .frame_type = ty } };
}

const BodyError = packet.Error || error{UnknownType};

fn parseBody(r: *Reader, ty: u64) BodyError!Frame {
    switch (ty) {
        0x00 => {
            // Skip the rest of a padding run in one step.
            while (r.pos < r.data.len and r.data[r.pos] == 0) r.pos += 1;
            return .padding;
        },
        0x01 => return .ping,
        0x02, 0x03 => {
            var ack: Ack = .{
                .largest = try r.varint(),
                .delay = try r.varint(),
                .range_count = undefined,
                .first_range = undefined,
                .ranges = undefined,
            };
            ack.range_count = try r.varint();
            ack.first_range = try r.varint();
            if (ack.first_range > ack.largest) return error.Malformed;
            const ranges_start = r.pos;
            var smallest = ack.largest - ack.first_range;
            var i: u64 = 0;
            while (i < ack.range_count) : (i += 1) {
                const gap = try r.varint();
                const len = try r.varint();
                // The next range's largest is smallest - gap - 2.
                if (smallest < gap + 2) return error.Malformed;
                const largest = smallest - gap - 2;
                if (len > largest) return error.Malformed;
                smallest = largest - len;
            }
            ack.ranges = r.data[ranges_start..r.pos];
            if (ty == 0x03) ack.ecn = .{ try r.varint(), try r.varint(), try r.varint() };
            return .{ .ack = ack };
        },
        0x04 => return .{ .reset_stream = .{ .id = try r.varint(), .code = try r.varint(), .final_size = try r.varint() } },
        0x05 => return .{ .stop_sending = .{ .id = try r.varint(), .code = try r.varint() } },
        0x06 => {
            const offset = try r.varint();
            const data = try r.vector();
            if (offset + data.len > packet.max_varint) return error.Malformed;
            return .{ .crypto = .{ .offset = offset, .data = data } };
        },
        0x07 => {
            const token = try r.vector();
            if (token.len == 0) return error.Malformed;
            return .{ .new_token = token };
        },
        0x08...0x0f => {
            const bits: u8 = @intCast(ty & 0x07);
            const id = try r.varint();
            const offset = if (bits & stream_off != 0) try r.varint() else 0;
            const data = if (bits & stream_len != 0) try r.vector() else try r.bytes(r.left());
            if (offset + data.len > packet.max_varint) return error.Malformed;
            return .{ .stream = .{ .id = id, .offset = offset, .data = data, .fin = bits & stream_fin != 0 } };
        },
        0x10 => return .{ .max_data = try r.varint() },
        0x11 => return .{ .max_stream_data = .{ .id = try r.varint(), .max = try r.varint() } },
        0x12, 0x13 => {
            const max = try r.varint();
            if (max > max_streams_limit) return error.Malformed;
            return .{ .max_streams = .{ .bidi = ty == 0x12, .max = max } };
        },
        0x14 => return .{ .data_blocked = try r.varint() },
        0x15 => return .{ .stream_data_blocked = .{ .id = try r.varint(), .limit = try r.varint() } },
        0x16, 0x17 => {
            const limit = try r.varint();
            if (limit > max_streams_limit) return error.Malformed;
            return .{ .streams_blocked = .{ .bidi = ty == 0x16, .limit = limit } };
        },
        0x18 => {
            const seq = try r.varint();
            const retire = try r.varint();
            if (retire > seq) return error.Malformed;
            const len = try r.byte();
            if (len < 1 or len > packet.max_cid_len) return error.Malformed;
            const cid = try r.bytes(len);
            const token = try r.bytes(16);
            return .{ .new_connection_id = .{ .seq = seq, .retire_prior_to = retire, .cid = cid, .reset_token = token[0..16] } };
        },
        0x19 => return .{ .retire_connection_id = try r.varint() },
        0x1a => return .{ .path_challenge = (try r.bytes(8))[0..8].* },
        0x1b => return .{ .path_response = (try r.bytes(8))[0..8].* },
        0x1c, 0x1d => {
            const code = try r.varint();
            const frame_type = if (ty == 0x1c) try r.varint() else 0;
            const reason = try r.vector();
            return .{ .connection_close = .{ .app = ty == 0x1d, .code = code, .frame_type = frame_type, .reason = reason } };
        },
        0x1e => return .handshake_done,
        else => return error.UnknownType,
    }
}

/// Packet types a frame may appear in (§12.4, Table 3), as seen by a
/// server: Initial and Handshake carry only PADDING, PING, ACK, CRYPTO and
/// CONNECTION_CLOSE of type 0x1c; clients never send NEW_TOKEN or
/// HANDSHAKE_DONE.
pub fn allowed(f: Frame, ty: packet.PacketType) bool {
    return switch (f) {
        .padding, .ping, .ack, .crypto => ty != .zero_rtt or (f != .ack and f != .crypto),
        .connection_close => |c| ty == .one_rtt or ty == .zero_rtt or !c.app,
        .new_token, .handshake_done => false,
        .path_response => ty == .one_rtt,
        else => ty == .one_rtt or ty == .zero_rtt,
    };
}

/// Frames that don't elicit an acknowledgement (§13.2.1).
pub fn ackEliciting(f: Frame) bool {
    return switch (f) {
        .padding, .ack, .connection_close => false,
        else => true,
    };
}

// -- Serialisers --------------------------------------------------------------
// Each writes into a Writer known to have room; the *Len functions give the
// room needed.

/// An ACK frame, or ACK_ECN with `ecn` (the ECT(0), ECT(1) and ECN-CE
/// counts, §19.3.2).
pub fn writeAckFrame(w: *Writer, ranges: []const Range, delay: u64, ecn: ?[3]u64) void {
    // `ranges` are disjoint, largest first, with gaps of at least one.
    w.varint(if (ecn == null) 0x02 else 0x03);
    w.varint(ranges[0].largest);
    w.varint(delay);
    w.varint(ranges.len - 1);
    w.varint(ranges[0].largest - ranges[0].smallest);
    var prev_smallest = ranges[0].smallest;
    for (ranges[1..]) |rg| {
        w.varint(prev_smallest - rg.largest - 2);
        w.varint(rg.largest - rg.smallest);
        prev_smallest = rg.smallest;
    }
    if (ecn) |counts| for (counts) |c| w.varint(c);
}

pub fn ackFrameLen(ranges: []const Range, delay: u64, ecn: ?[3]u64) usize {
    var n = 1 + varintLen(ranges[0].largest) + varintLen(delay) + varintLen(ranges.len - 1) +
        varintLen(ranges[0].largest - ranges[0].smallest);
    var prev_smallest = ranges[0].smallest;
    for (ranges[1..]) |rg| {
        n += varintLen(prev_smallest - rg.largest - 2) + varintLen(rg.largest - rg.smallest);
        prev_smallest = rg.smallest;
    }
    if (ecn) |counts| for (counts) |c| {
        n += varintLen(c);
    };
    return n;
}

pub fn cryptoHeaderLen(offset: u64, len: usize) usize {
    return 1 + varintLen(offset) + varintLen(len);
}

pub fn writeCryptoHeader(w: *Writer, offset: u64, len: usize) void {
    w.varint(0x06);
    w.varint(offset);
    w.varint(len);
}

/// A STREAM frame header with OFF and LEN as needed. `explicit_len` false
/// omits the length: the frame runs to the end of the packet.
pub fn streamHeaderLen(id: u64, offset: u64, len: usize, explicit_len: bool) usize {
    return 1 + varintLen(id) + (if (offset > 0) varintLen(offset) else 0) + (if (explicit_len) varintLen(len) else 0);
}

pub fn writeStreamHeader(w: *Writer, id: u64, offset: u64, len: usize, fin: bool, explicit_len: bool) void {
    var ty: u8 = 0x08;
    if (offset > 0) ty |= stream_off;
    if (explicit_len) ty |= stream_len;
    if (fin) ty |= stream_fin;
    w.byte(ty);
    w.varint(id);
    if (offset > 0) w.varint(offset);
    if (explicit_len) w.varint(len);
}

pub fn writeResetStream(w: *Writer, id: u64, code: u64, final_size: u64) void {
    w.varint(0x04);
    w.varint(id);
    w.varint(code);
    w.varint(final_size);
}

pub fn writeStopSending(w: *Writer, id: u64, code: u64) void {
    w.varint(0x05);
    w.varint(id);
    w.varint(code);
}

pub fn writeMaxData(w: *Writer, max: u64) void {
    w.varint(0x10);
    w.varint(max);
}

pub fn writeMaxStreamData(w: *Writer, id: u64, max: u64) void {
    w.varint(0x11);
    w.varint(id);
    w.varint(max);
}

pub fn writeMaxStreams(w: *Writer, bidi: bool, max: u64) void {
    w.varint(if (bidi) 0x12 else 0x13);
    w.varint(max);
}

pub fn writeNewConnectionId(w: *Writer, seq: u64, retire_prior_to: u64, cid: []const u8, reset_token: *const [16]u8) void {
    w.varint(0x18);
    w.varint(seq);
    w.varint(retire_prior_to);
    w.byte(@intCast(cid.len));
    w.bytes(cid);
    w.bytes(reset_token);
}

pub fn writeNewToken(w: *Writer, token: []const u8) void {
    w.varint(0x07);
    w.varint(token.len);
    w.bytes(token);
}

pub fn writePathResponse(w: *Writer, data: [8]u8) void {
    w.varint(0x1b);
    w.bytes(&data);
}

pub fn connectionCloseLen(app: bool, reason_len: usize, code: u64, frame_type: u64) usize {
    return 1 + varintLen(code) + (if (app) 0 else varintLen(frame_type)) + varintLen(reason_len) + reason_len;
}

pub fn writeConnectionClose(w: *Writer, app: bool, code: u64, frame_type: u64, reason: []const u8) void {
    w.varint(if (app) 0x1d else 0x1c);
    w.varint(code);
    if (!app) w.varint(frame_type);
    w.varint(reason.len);
    w.bytes(reason);
}

// -- Tests ------------------------------------------------------------------

const testing = std.testing;

fn parseOne(bytes: []const u8) !Frame {
    var r: Reader = .{ .data = bytes };
    return switch (parse(&r)) {
        .frame => |f| f,
        .failure => |f| {
            std.debug.print("failure {} on 0x{x}\n", .{ f.code, f.frame_type });
            return error.TestUnexpectedResult;
        },
    };
}

fn expectFailure(code: TransportError, bytes: []const u8) !void {
    var r: Reader = .{ .data = bytes };
    switch (parse(&r)) {
        .frame => return error.TestUnexpectedResult,
        .failure => |f| try testing.expectEqual(code, f.code),
    }
}

test "ACK ranges round trip; malformed ranges fail" {
    const ranges = [_]Range{
        .{ .smallest = 95, .largest = 100 },
        .{ .smallest = 80, .largest = 90 },
        .{ .smallest = 0, .largest = 3 },
    };
    var buf: [64]u8 = undefined;
    var w: Writer = .{ .buf = &buf };
    writeAckFrame(&w, &ranges, 25, null);
    try testing.expectEqual(ackFrameLen(&ranges, 25, null), w.pos);
    const f = try parseOne(w.written());
    try testing.expectEqual(@as(u64, 25), f.ack.delay);
    var it = f.ack.iterator();
    for (ranges) |want| {
        const got = it.next().?;
        try testing.expectEqual(want, got);
    }
    try testing.expectEqual(@as(?Range, null), it.next());

    // first range larger than largest
    try expectFailure(.frame_encoding_error, &.{ 0x02, 5, 0, 0, 6 });
    // a gap that runs below zero
    try expectFailure(.frame_encoding_error, &.{ 0x02, 5, 0, 1, 2, 2, 0 });
    // a range length larger than what is left
    try expectFailure(.frame_encoding_error, &.{ 0x02, 10, 0, 1, 2, 1, 7 });
    // truncated
    try expectFailure(.frame_encoding_error, &.{ 0x02, 10, 0, 1 });
    // ECN counts
    const ecn = try parseOne(&.{ 0x03, 3, 0, 0, 0, 1, 2, 3 });
    try testing.expectEqual([3]u64{ 1, 2, 3 }, ecn.ack.ecn.?);
    // ACK_ECN round trip, counts of every size; truncated counts fail.
    const counts = [3]u64{ 63, 1 << 20, packet.max_varint };
    w = .{ .buf = &buf };
    writeAckFrame(&w, &ranges, 25, counts);
    try testing.expectEqual(ackFrameLen(&ranges, 25, counts), w.pos);
    const g = try parseOne(w.written());
    try testing.expectEqual(counts, g.ack.ecn.?);
    try testing.expectEqual(@as(u64, 100), g.ack.largest);
    try expectFailure(.frame_encoding_error, w.written()[0 .. w.pos - 1]);
    try expectFailure(.frame_encoding_error, &.{ 0x03, 3, 0, 0, 0, 1, 2 });
}

test "STREAM and CRYPTO frames" {
    var buf: [64]u8 = undefined;
    var w: Writer = .{ .buf = &buf };
    writeStreamHeader(&w, 4, 1000, 5, true, true);
    try testing.expectEqual(streamHeaderLen(4, 1000, 5, true), w.pos);
    w.bytes("hello");
    const f = try parseOne(w.written());
    try testing.expectEqual(@as(u64, 4), f.stream.id);
    try testing.expectEqual(@as(u64, 1000), f.stream.offset);
    try testing.expect(f.stream.fin);
    try testing.expectEqualSlices(u8, "hello", f.stream.data);

    // Without LEN, the data runs to the end of the packet.
    const g = try parseOne(&.{ 0x08, 0, 'a', 'b' });
    try testing.expectEqualSlices(u8, "ab", g.stream.data);
    try testing.expect(!g.stream.fin);
    // Data past 2^62 - 1.
    try expectFailure(.frame_encoding_error, &.{ 0x0e, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 'x' });

    w = .{ .buf = &buf };
    writeCryptoHeader(&w, 7, 3);
    try testing.expectEqual(cryptoHeaderLen(7, 3), w.pos);
    w.bytes("abc");
    const c = try parseOne(w.written());
    try testing.expectEqual(@as(u64, 7), c.crypto.offset);
    try testing.expectEqualSlices(u8, "abc", c.crypto.data);
    // A length past the payload.
    try expectFailure(.frame_encoding_error, &.{ 0x06, 0, 5, 'a' });
}

test "other frames and encoding rules" {
    try testing.expectEqual(Frame.padding, try parseOne(&.{ 0, 0, 0, 0 }));
    try testing.expectEqual(Frame.ping, try parseOne(&.{0x01}));
    try testing.expectEqual(@as(u64, 300), (try parseOne(&.{ 0x10, 0x41, 0x2c })).max_data);
    try expectFailure(.frame_encoding_error, &.{ 0x12, 0xd0, 0, 0, 0, 0, 0, 0, 1 }); // > 2^60 streams
    try expectFailure(.frame_encoding_error, &.{0x1f}); // unknown type
    try expectFailure(.protocol_violation, &.{ 0x40, 0x01 }); // PING in two bytes
    try expectFailure(.frame_encoding_error, &.{ 0x07, 0 }); // empty NEW_TOKEN

    var buf: [64]u8 = undefined;
    var w: Writer = .{ .buf = &buf };
    const token: [16]u8 = @splat(0xab);
    writeNewConnectionId(&w, 3, 1, &.{ 1, 2, 3, 4 }, &token);
    const n = try parseOne(w.written());
    try testing.expectEqual(@as(u64, 3), n.new_connection_id.seq);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, n.new_connection_id.cid);
    try expectFailure(.frame_encoding_error, &([_]u8{ 0x18, 1, 2, 4, 1, 2, 3, 4 } ++ token)); // retire > seq
    try expectFailure(.frame_encoding_error, &([_]u8{ 0x18, 1, 0, 0 } ++ token)); // empty CID

    w = .{ .buf = &buf };
    writeConnectionClose(&w, false, 0xa, 0x06, "bad");
    try testing.expectEqual(connectionCloseLen(false, 3, 0xa, 0x06), w.pos);
    const cc = try parseOne(w.written());
    try testing.expectEqual(@as(u64, 0xa), cc.connection_close.code);
    try testing.expectEqual(@as(u64, 0x06), cc.connection_close.frame_type);
    try testing.expectEqualSlices(u8, "bad", cc.connection_close.reason);
    const app = try parseOne(&.{ 0x1d, 0x41, 0x00, 0 });
    try testing.expect(app.connection_close.app);
    try testing.expectEqual(@as(u64, 0x100), app.connection_close.code);

    // Table 3.
    try testing.expect(allowed(.ping, .initial));
    try testing.expect(!allowed(.{ .max_data = 1 }, .handshake));
    try testing.expect(!allowed(.handshake_done, .one_rtt));
    try testing.expect(allowed(cc, .zero_rtt));
    try testing.expect(!allowed(.{ .path_response = @splat(0) }, .zero_rtt));
    try testing.expect(allowed(.{ .retire_connection_id = 0 }, .zero_rtt));
    try testing.expect(!allowed(app, .initial));
    try testing.expect(allowed(cc, .initial));
}

test "parser never reads out of bounds on truncations" {
    const frames = [_][]const u8{
        &.{ 0x02, 0x44, 0x00, 0x05, 0x01, 0x40, 0x03, 0x02, 0x01 },
        &.{ 0x0f, 0x04, 0x41, 0x00, 0x03, 'a', 'b', 'c' },
        &([_]u8{ 0x18, 0x01, 0x00, 0x04, 1, 2, 3, 4 } ++ @as([16]u8, @splat(9))),
        &.{ 0x1c, 0x01, 0x02, 0x03, 'a', 'b', 'c' },
        &.{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8 },
    };
    for (frames) |f| {
        _ = try parseOne(f);
        for (0..f.len) |n| {
            var r: Reader = .{ .data = f[0..n] };
            switch (parse(&r)) {
                .frame => |fr| {
                    // Only a STREAM frame without LEN may be cut short legally.
                    try testing.expect(fr == .stream or n == 0);
                },
                .failure => {},
            }
        }
    }
}
