//! WebSocket framing (RFC 6455) without I/O. The event loop reads into a
//! Decoder's buffer and pulls complete messages out of it; nothing here
//! touches a socket, so the whole protocol can be tested byte by byte.
//!
//! The decoder enforces the server-side rules of the RFC: client frames must
//! be masked, RSV bits must be zero, control frames must be short and
//! unfragmented, fragments must be sequenced correctly, text must be valid
//! UTF-8 and close payloads well-formed. Each violation maps to the close
//! code the server should fail the connection with.
const std = @import("std");
const BufferPool = @import("../http/session.zig").BufferPool;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,

    pub fn fromByte(byte: u8) ?Opcode {
        const op: Opcode = @enumFromInt(@as(u4, @truncate(byte)));
        return switch (op) {
            .continuation, .text, .binary, .close, .ping, .pong => op,
            _ => null,
        };
    }

    pub inline fn isControl(self: Opcode) bool {
        return @intFromEnum(self) & 0x8 != 0;
    }

    pub fn toString(self: Opcode) []const u8 {
        return switch (self) {
            .continuation => "continuation",
            .text => "text",
            .binary => "binary",
            .close => "close",
            .ping => "ping",
            .pong => "pong",
            _ => "unknown",
        };
    }
};

/// Close status codes (RFC 6455 §7.4.1).
pub const close_code = struct {
    pub const normal: u16 = 1000;
    pub const going_away: u16 = 1001;
    pub const protocol_error: u16 = 1002;
    pub const unsupported_data: u16 = 1003;
    pub const invalid_payload: u16 = 1007;
    pub const policy_violation: u16 = 1008;
    pub const message_too_big: u16 = 1009;
    pub const internal_error: u16 = 1011;
};

/// Codes a peer may send in a close frame (§7.4): defined, non-reserved
/// codes plus the library (3000-3999) and private (4000-4999) ranges.
pub fn isValidCloseCode(code: u16) bool {
    return (code >= 1000 and code <= 1003) or (code >= 1007 and code <= 1014) or
        (code >= 3000 and code <= 4999);
}

pub const Error = error{
    /// Fail with 1002.
    ProtocolError,
    /// Fail with 1007.
    InvalidUtf8,
    /// Fail with 1009.
    MessageTooBig,
    /// Fail with 1011.
    OutOfMemory,
};

pub fn closeCodeFor(err: Error) u16 {
    return switch (err) {
        error.ProtocolError => close_code.protocol_error,
        error.InvalidUtf8 => close_code.invalid_payload,
        error.MessageTooBig => close_code.message_too_big,
        error.OutOfMemory => close_code.internal_error,
    };
}

/// A complete message (fragments reassembled, payload unmasked). For text,
/// binary, ping and pong the payload is the application data; for close it
/// is the status code followed by the reason. Valid only during the handler
/// call it is passed to.
pub const Frame = struct {
    opcode: Opcode,
    payload: []const u8,

    pub fn getPayload(self: *const Frame) []const u8 {
        return self.payload;
    }

    /// The status code of a close frame, if it carries one.
    pub fn closeCode(self: *const Frame) ?u16 {
        if (self.opcode != .close or self.payload.len < 2) return null;
        return std.mem.readInt(u16, self.payload[0..2], .big);
    }

    /// The reason of a close frame (empty if none).
    pub fn closeReason(self: *const Frame) []const u8 {
        if (self.opcode != .close or self.payload.len < 2) return "";
        return self.payload[2..];
    }
};

/// Largest frame header: 2 bytes, 8 bytes of extended length, 4 of mask.
pub const max_header_len = 14;
/// Control frame payloads are at most this long (§5.5).
pub const max_control_payload = 125;

/// Writes an unmasked (server-to-client) frame header. Returns the slice of
/// `out` used.
pub fn encodeHeader(out: *[10]u8, fin: bool, opcode: Opcode, len: usize) []const u8 {
    out[0] = (if (fin) @as(u8, 0x80) else 0) | @intFromEnum(opcode);
    if (len < 126) {
        out[1] = @intCast(len);
        return out[0..2];
    }
    if (len <= 0xFFFF) {
        out[1] = 126;
        std.mem.writeInt(u16, out[2..4], @intCast(len), .big);
        return out[0..4];
    }
    out[1] = 127;
    std.mem.writeInt(u64, out[2..10], len, .big);
    return out[0..10];
}

/// Writes a whole frame, masked if a key is given (clients must mask). For
/// tests and clients; the server never masks. `out` needs
/// `max_header_len + payload.len` bytes.
pub fn encodeFrame(out: []u8, fin: bool, opcode: Opcode, payload: []const u8, mask: ?[4]u8) []u8 {
    var hdr: [10]u8 = undefined;
    const h = encodeHeader(&hdr, fin, opcode, payload.len);
    @memcpy(out[0..h.len], h);
    var n = h.len;
    if (mask) |key| {
        out[1] |= 0x80;
        out[n..][0..4].* = key;
        n += 4;
    }
    @memcpy(out[n..][0..payload.len], payload);
    if (mask) |key| applyMask(out[n..][0..payload.len], key, 0);
    return out[0 .. n + payload.len];
}

/// XORs `data` with the masking key, where `data` starts at byte `offset` of
/// the frame payload (the key rotates with the offset).
pub fn applyMask(data: []u8, key: [4]u8, offset: usize) void {
    var rotated: [4]u8 = undefined;
    for (0..4) |i| rotated[i] = key[(i + offset) & 3];
    const V = @Vector(16, u8);
    const pattern: [16]u8 = rotated ++ rotated ++ rotated ++ rotated;
    const vkey: V = pattern;
    var i: usize = 0;
    while (i + 16 <= data.len) : (i += 16) {
        const chunk: V = data[i..][0..16].*;
        data[i..][0..16].* = chunk ^ vkey;
    }
    while (i < data.len) : (i += 1) data[i] ^= rotated[i & 3];
}

const Header = struct {
    fin: bool,
    opcode: Opcode,
    key: [4]u8,
    len: usize,
    hdr_len: usize,
};

/// Parses a client frame header. Returns null if more bytes are needed.
fn parseHeader(data: []const u8) Error!?Header {
    if (data.len < 2) return null;
    const b0 = data[0];
    const b1 = data[1];
    // No extensions are negotiated, so RSV1-3 must be zero (§5.2).
    if (b0 & 0x70 != 0) return error.ProtocolError;
    const opcode = Opcode.fromByte(b0 & 0x0F) orelse return error.ProtocolError;
    const fin = b0 & 0x80 != 0;
    // Client frames must be masked (§5.1).
    if (b1 & 0x80 == 0) return error.ProtocolError;
    const len7 = b1 & 0x7F;
    // Control frames are short and never fragmented (§5.5).
    if (opcode.isControl() and (!fin or len7 > max_control_payload)) return error.ProtocolError;
    var hdr_len: usize = 2;
    var len: usize = len7;
    switch (len7) {
        126 => {
            if (data.len < 4) return null;
            len = std.mem.readInt(u16, data[2..4], .big);
            // The minimal encoding must be used (§5.2).
            if (len < 126) return error.ProtocolError;
            hdr_len = 4;
        },
        127 => {
            if (data.len < 10) return null;
            const l = std.mem.readInt(u64, data[2..10], .big);
            // The most significant bit must be 0 (§5.2).
            if (l >> 63 != 0) return error.ProtocolError;
            if (l < 65536) return error.ProtocolError;
            if (l > std.math.maxInt(usize)) return error.MessageTooBig;
            len = @intCast(l);
            hdr_len = 10;
        },
        else => {},
    }
    if (data.len < hdr_len + 4) return null;
    const key = data[hdr_len..][0..4].*;
    return .{ .fin = fin, .opcode = opcode, .key = key, .len = len, .hdr_len = hdr_len + 4 };
}

/// The payload of a close frame is empty, or a valid status code followed
/// by a UTF-8 reason (§5.5.1).
fn validateClose(payload: []const u8) Error!void {
    if (payload.len == 0) return;
    if (payload.len == 1) return error.ProtocolError;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    if (!isValidCloseCode(code)) return error.ProtocolError;
    if (!std.unicode.utf8ValidateSlice(payload[2..])) return error.InvalidUtf8;
}

/// Length of the prefix of `data` that ends on a UTF-8 sequence boundary,
/// assuming only the final sequence may be incomplete. Invalid bytes are
/// left in the prefix so that validating it fails.
fn utf8CompletePrefix(data: []const u8) usize {
    var i = data.len;
    var back: usize = 0;
    while (i > 0 and back < 4) : (back += 1) {
        const b = data[i - 1];
        if (b & 0xC0 != 0x80) {
            const seq_len = std.unicode.utf8ByteSequenceLength(b) catch return data.len;
            if (i - 1 + seq_len > data.len) return i - 1;
            return data.len;
        }
        i -= 1;
    }
    return data.len;
}

/// Reassembly buffers larger than this are freed after delivery, so one
/// large message doesn't pin memory for the life of the connection.
const msg_retain_capacity = 64 * 1024;

/// Per-connection frame decoder and message assembler. Input is buffered
/// like `Session`: the event loop reads into `readSpace`, commits, and calls
/// `next` until it returns null. A connection only holds a buffer while it
/// has unprocessed bytes.
///
/// An unfragmented message that fits in the buffer is delivered in place
/// (unmasked where it lies, no copy). Fragmented or oversized messages are
/// streamed into a growable reassembly buffer as the bytes arrive, so the
/// read buffer never needs to hold a whole frame.
pub const Decoder = struct {
    const Self = @This();

    buf: []u8 = &.{},
    start: usize = 0,
    end: usize = 0,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    state: enum(u8) { header, stream } = .header,
    /// The frame being streamed.
    fin: bool = false,
    key: [4]u8 = undefined,
    len: usize = 0,
    consumed: usize = 0,
    /// The message being reassembled, if any.
    msg: std.ArrayList(u8) = .empty,
    msg_opcode: ?Opcode = null,
    /// Prefix of `msg` already validated as UTF-8 (text messages).
    msg_valid: usize = 0,
    /// `msg` holds the message returned by the last call; reset on the next.
    msg_delivered: bool = false,

    pub fn init(allocator: std.mem.Allocator, max_message_size: usize) Self {
        return .{ .allocator = allocator, .max_message_size = max_message_size };
    }

    pub fn deinit(self: *Self, pool: *BufferPool) void {
        if (self.buf.len > 0) pool.release(self.buf);
        self.msg.deinit(self.allocator);
        self.* = .{ .allocator = self.allocator, .max_message_size = self.max_message_size };
    }

    pub inline fn buffered(self: *const Self) usize {
        return self.end - self.start;
    }

    /// Takes over a buffer (from the HTTP session after an upgrade) with
    /// its unprocessed bytes.
    pub fn adopt(self: *Self, buf: []u8, start: usize, end: usize) void {
        std.debug.assert(self.buf.len == 0);
        self.buf = buf;
        self.start = start;
        self.end = end;
    }

    /// Space to read into, acquiring or compacting the buffer as needed.
    pub fn readSpace(self: *Self, pool: *BufferPool) ![]u8 {
        if (self.buf.len == 0) {
            self.buf = try pool.acquire();
            self.start = 0;
            self.end = 0;
        }
        if (self.end == self.buf.len) {
            // Streaming consumes payload as it arrives, and a frame held
            // whole always fits the buffer, so there is always room after
            // compaction.
            if (self.start == 0) return error.BufferFull;
            const len = self.end - self.start;
            std.mem.copyForwards(u8, self.buf[0..len], self.buf[self.start..self.end]);
            self.start = 0;
            self.end = len;
        }
        return self.buf[self.end..];
    }

    pub inline fn commitRead(self: *Self, n: usize) void {
        self.end += n;
    }

    /// Returns the buffer to the pool when nothing is buffered.
    pub fn releaseIfIdle(self: *Self, pool: *BufferPool) void {
        if (self.buf.len > 0 and self.start == self.end) {
            pool.release(self.buf);
            self.buf = &.{};
            self.start = 0;
            self.end = 0;
        }
    }

    /// The next complete message, or null if more input is needed. Control
    /// frames are returned as they arrive, even in the middle of a
    /// fragmented message. The returned payload is valid until the next call
    /// to `next` or `readSpace`.
    pub fn next(self: *Self) Error!?Frame {
        if (self.msg_delivered) {
            self.msg_delivered = false;
            self.msg_opcode = null;
            self.msg_valid = 0;
            if (self.msg.capacity > msg_retain_capacity) {
                self.msg.clearAndFree(self.allocator);
            } else {
                self.msg.clearRetainingCapacity();
            }
        }
        while (true) {
            switch (self.state) {
                .header => {
                    const data = self.buf[self.start..self.end];
                    const hdr = (try parseHeader(data)) orelse return null;
                    const total = hdr.hdr_len + hdr.len;
                    const in_progress = self.msg_opcode != null;
                    if (hdr.opcode.isControl()) {
                        // At most 139 bytes: wait for all of it, handle in place.
                        if (data.len < total) return null;
                        const payload = data[hdr.hdr_len..total];
                        applyMask(payload, hdr.key, 0);
                        self.start += total;
                        if (hdr.opcode == .close) try validateClose(payload);
                        return .{ .opcode = hdr.opcode, .payload = payload };
                    }
                    // Fragment sequencing (§5.4).
                    if (hdr.opcode == .continuation) {
                        if (!in_progress) return error.ProtocolError;
                    } else if (in_progress) {
                        return error.ProtocolError;
                    }
                    const msg_len = self.msg.items.len + hdr.len;
                    if (msg_len > self.max_message_size) return error.MessageTooBig;
                    if (hdr.fin and !in_progress and total <= self.buf.len) {
                        // Whole message, fits the buffer: deliver in place.
                        if (data.len < total) return null;
                        const payload = data[hdr.hdr_len..total];
                        applyMask(payload, hdr.key, 0);
                        if (hdr.opcode == .text and !std.unicode.utf8ValidateSlice(payload)) {
                            return error.InvalidUtf8;
                        }
                        self.start += total;
                        return .{ .opcode = hdr.opcode, .payload = payload };
                    }
                    // Fragmented or larger than the buffer: stream into msg.
                    if (!in_progress) self.msg_opcode = hdr.opcode;
                    self.fin = hdr.fin;
                    self.key = hdr.key;
                    self.len = hdr.len;
                    self.consumed = 0;
                    self.start += hdr.hdr_len;
                    self.state = .stream;
                },
                .stream => {
                    const take = @min(self.end - self.start, self.len - self.consumed);
                    if (take > 0) {
                        const chunk = self.buf[self.start..][0..take];
                        applyMask(chunk, self.key, self.consumed);
                        try self.msg.appendSlice(self.allocator, chunk);
                        self.start += take;
                        self.consumed += take;
                        if (self.msg_opcode == .text) try self.validateUtf8Progress();
                    }
                    if (self.consumed < self.len) return null;
                    self.state = .header;
                    if (!self.fin) continue;
                    if (self.msg_opcode == .text and self.msg_valid != self.msg.items.len) {
                        // Ends in the middle of a sequence.
                        return error.InvalidUtf8;
                    }
                    self.msg_delivered = true;
                    return .{ .opcode = self.msg_opcode.?, .payload = self.msg.items };
                },
            }
        }
    }

    /// Validates newly appended text as far as the last complete sequence,
    /// so invalid text fails as soon as it arrives.
    fn validateUtf8Progress(self: *Self) Error!void {
        const pending = self.msg.items[self.msg_valid..];
        const upto = self.msg_valid + utf8CompletePrefix(pending);
        if (!std.unicode.utf8ValidateSlice(self.msg.items[self.msg_valid..upto])) {
            return error.InvalidUtf8;
        }
        self.msg_valid = upto;
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const TestDecoder = struct {
    pool: BufferPool,
    dec: Decoder,
    /// Collected (opcode, payload) pairs, serialised for easy comparison.
    log: std.ArrayList(u8) = .empty,
    count: usize = 0,
    err: ?Error = null,

    fn init(buf_size: usize, max_message: usize) !*TestDecoder {
        const t = try testing.allocator.create(TestDecoder);
        t.* = .{
            .pool = try BufferPool.init(testing.allocator, buf_size, 2),
            .dec = Decoder.init(testing.allocator, max_message),
        };
        return t;
    }

    fn deinit(t: *TestDecoder) void {
        t.dec.deinit(&t.pool);
        t.pool.deinit();
        t.log.deinit(testing.allocator);
        testing.allocator.destroy(t);
    }

    /// Feeds bytes as one read, draining messages after each buffer fill.
    fn feed(t: *TestDecoder, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0 and t.err == null) {
            const space = try t.dec.readSpace(&t.pool);
            const n = @min(space.len, rest.len);
            @memcpy(space[0..n], rest[0..n]);
            t.dec.commitRead(n);
            rest = rest[n..];
            t.drain();
            t.dec.releaseIfIdle(&t.pool);
        }
    }

    fn drain(t: *TestDecoder) void {
        while (true) {
            const fr = t.dec.next() catch |e| {
                t.err = e;
                return;
            } orelse return;
            t.count += 1;
            t.log.append(testing.allocator, @intFromEnum(fr.opcode)) catch unreachable;
            var len_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &len_buf, fr.payload.len, .little);
            t.log.appendSlice(testing.allocator, &len_buf) catch unreachable;
            t.log.appendSlice(testing.allocator, fr.payload) catch unreachable;
        }
    }
};

const test_key = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };

fn frame(out: []u8, fin: bool, op: Opcode, payload: []const u8) []u8 {
    return encodeFrame(out, fin, op, payload, test_key);
}

/// Decodes `bytes` in one go and returns the error, if any.
fn decodeError(bytes: []const u8) !?Error {
    const t = try TestDecoder.init(4096, 1 << 20);
    defer t.deinit();
    try t.feed(bytes);
    return t.err;
}

test "mask round trip at every offset" {
    var data: [40]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    const key = [4]u8{ 1, 2, 3, 4 };
    for (0..5) |offset| {
        var masked = data;
        applyMask(masked[offset..], key, offset);
        for (offset..data.len) |i| try testing.expectEqual(data[i] ^ key[i & 3], masked[i]);
        applyMask(masked[offset..], key, offset);
        try testing.expectEqualSlices(u8, &data, &masked);
    }
}

test "encodeHeader uses the minimal length encoding" {
    var h: [10]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x81, 5 }, encodeHeader(&h, true, .text, 5));
    try testing.expectEqualSlices(u8, &.{ 0x82, 125 }, encodeHeader(&h, true, .binary, 125));
    try testing.expectEqualSlices(u8, &.{ 0x82, 126, 0, 126 }, encodeHeader(&h, true, .binary, 126));
    try testing.expectEqualSlices(u8, &.{ 0x82, 126, 0xFF, 0xFF }, encodeHeader(&h, true, .binary, 65535));
    try testing.expectEqualSlices(u8, &.{ 0x02, 127, 0, 0, 0, 0, 0, 1, 0, 0 }, encodeHeader(&h, false, .binary, 65536));
}

test "small text frame is delivered in place" {
    const t = try TestDecoder.init(4096, 1 << 20);
    defer t.deinit();
    var out: [64]u8 = undefined;
    try t.feed(frame(&out, true, .text, "Hello"));
    try testing.expectEqual(@as(?Error, null), t.err);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 5, 0, 0, 0, 0, 0, 0, 0 } ++ "Hello".*, t.log.items);
    // The buffer went back to the pool.
    try testing.expectEqual(@as(usize, 0), t.dec.buf.len);
}

test "unmasked client frame fails with a protocol error" {
    var out: [64]u8 = undefined;
    const f = encodeFrame(&out, true, .text, "Hello", null);
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(f));
}

test "RSV bits must be zero" {
    var out: [64]u8 = undefined;
    const f = frame(&out, true, .text, "Hello");
    for ([_]u8{ 0x10, 0x20, 0x40 }) |rsv| {
        f[0] |= rsv;
        try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(f));
        f[0] &= ~rsv;
    }
}

test "reserved opcodes are rejected" {
    var out: [64]u8 = undefined;
    const f = frame(&out, true, .text, "x");
    for ([_]u8{ 3, 4, 5, 6, 7, 0xB, 0xC, 0xD, 0xE, 0xF }) |op| {
        f[0] = 0x80 | op;
        try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(f));
    }
}

test "64-bit length with the MSB set is rejected before any payload" {
    const f = [_]u8{ 0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3, 4 };
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(&f));
}

test "non-minimal length encodings are rejected" {
    // 126 form for a 5-byte payload.
    const two_byte = [_]u8{ 0x82, 0xFE, 0, 5, 1, 2, 3, 4 } ++ "hello".*;
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(&two_byte));
    // 127 form for a 300-byte payload.
    const eight_byte = [_]u8{ 0x82, 0xFF, 0, 0, 0, 0, 0, 0, 1, 44, 1, 2, 3, 4 };
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(&eight_byte));
}

test "control frames must be short and unfragmented" {
    var out: [256]u8 = undefined;
    const big: [126]u8 = @splat('p');
    // The header already says 126, so this fails before the payload arrives.
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(frame(&out, true, .ping, &big)));
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(frame(&out, false, .ping, "x")));
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(frame(&out, false, .close, "")));
    // 125 is fine.
    try testing.expectEqual(@as(?Error, null), try decodeError(frame(&out, true, .pong, big[0..125])));
}

test "fragment sequencing" {
    var out: [64]u8 = undefined;
    // Continuation without a message in progress.
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(frame(&out, true, .continuation, "x")));
    // A new data frame while a message is in progress.
    var buf: [128]u8 = undefined;
    const a = frame(buf[0..64], false, .text, "ab");
    const b = frame(buf[64..], true, .binary, "cd");
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(buf[0 .. a.len + b.len]));
}

test "continuation frames are reassembled with control frames interleaved" {
    const t = try TestDecoder.init(4096, 1 << 20);
    defer t.deinit();
    var buf: [256]u8 = undefined;
    var n: usize = 0;
    n += frame(buf[n..], false, .text, "Hel").len;
    n += frame(buf[n..], true, .ping, "p").len;
    n += frame(buf[n..], false, .continuation, "lo ").len;
    n += frame(buf[n..], true, .continuation, "World").len;
    try t.feed(buf[0..n]);
    try testing.expectEqual(@as(?Error, null), t.err);
    const expected = [_]u8{ 9, 1, 0, 0, 0, 0, 0, 0, 0 } ++ "p".* ++ [_]u8{ 1, 11, 0, 0, 0, 0, 0, 0, 0 } ++ "Hello World".*;
    try testing.expectEqualSlices(u8, &expected, t.log.items);
}

test "invalid UTF-8 in text is rejected, also across fragments and early" {
    var out: [64]u8 = undefined;
    const cases = [_][]const u8{
        "\xff",
        "\xc0\xaf", // overlong '/'
        "\xed\xa0\x80", // surrogate
        "\xf4\x90\x80\x80", // > U+10FFFF
        "abc\xe2\x82", // truncated sequence at the end
    };
    for (cases) |c| {
        try testing.expectEqual(@as(?Error, error.InvalidUtf8), try decodeError(frame(&out, true, .text, c)));
        // Binary never cares.
        try testing.expectEqual(@as(?Error, null), try decodeError(frame(&out, true, .binary, c)));
    }
    // A sequence split across fragments is fine.
    {
        const t = try TestDecoder.init(4096, 1 << 20);
        defer t.deinit();
        var buf: [128]u8 = undefined;
        var n: usize = 0;
        n += frame(buf[n..], false, .text, "\xe2\x82").len;
        n += frame(buf[n..], true, .continuation, "\xac").len;
        try t.feed(buf[0..n]);
        try testing.expectEqual(@as(?Error, null), t.err);
        try testing.expectEqualSlices(u8, "\xe2\x82\xac", t.log.items[9..]);
    }
    // A truncated sequence at the end of a message fails at fin.
    {
        const t = try TestDecoder.init(4096, 1 << 20);
        defer t.deinit();
        var buf: [128]u8 = undefined;
        var n: usize = 0;
        n += frame(buf[n..], false, .text, "ok\xe2\x82").len;
        n += frame(buf[n..], true, .continuation, "").len;
        try t.feed(buf[0..n]);
        try testing.expectEqual(@as(?Error, error.InvalidUtf8), t.err);
    }
    // Invalid bytes early in a streamed message fail before the rest arrives.
    {
        const t = try TestDecoder.init(4096, 1 << 20);
        defer t.deinit();
        var buf: [128]u8 = undefined;
        const f = frame(&buf, false, .text, "\xff and more");
        try t.feed(f[0..8]);
        try testing.expectEqual(@as(?Error, error.InvalidUtf8), t.err);
    }
}

test "messages over the limit are rejected from the header" {
    var out: [4096]u8 = undefined;
    const payload: [2000]u8 = @splat('z');
    // Whole frame.
    {
        const t = try TestDecoder.init(4096, 1000);
        defer t.deinit();
        const f = frame(&out, true, .binary, &payload);
        try t.feed(f[0..10]);
        try testing.expectEqual(@as(?Error, error.MessageTooBig), t.err);
    }
    // Fragments adding up to more than the limit.
    {
        const t = try TestDecoder.init(4096, 1000);
        defer t.deinit();
        var n: usize = 0;
        n += frame(out[n..], false, .binary, payload[0..600]).len;
        n += frame(out[n..], true, .continuation, payload[0..600]).len;
        try t.feed(out[0..n]);
        try testing.expectEqual(@as(?Error, error.MessageTooBig), t.err);
        try testing.expectEqual(@as(usize, 0), t.count);
    }
    // Exactly at the limit is fine.
    try testing.expectEqual(@as(?Error, null), try decodeError(frame(&out, true, .binary, payload[0..1000])));
}

test "close payloads are validated" {
    var out: [256]u8 = undefined;
    try testing.expectEqual(@as(?Error, null), try decodeError(frame(&out, true, .close, "")));
    try testing.expectEqual(@as(?Error, null), try decodeError(frame(&out, true, .close, "\x03\xe8")));
    try testing.expectEqual(@as(?Error, null), try decodeError(frame(&out, true, .close, "\x03\xe8bye")));
    try testing.expectEqual(@as(?Error, null), try decodeError(frame(&out, true, .close, "\x0f\xa0")));
    // One byte.
    try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(frame(&out, true, .close, "\x03")));
    // Reserved codes: 1004, 1005, 1006, 1015, 999, 2000.
    for ([_]u16{ 1004, 1005, 1006, 1015, 999, 2000, 5000 }) |code| {
        var p: [2]u8 = undefined;
        std.mem.writeInt(u16, &p, code, .big);
        try testing.expectEqual(@as(?Error, error.ProtocolError), try decodeError(frame(&out, true, .close, &p)));
    }
    // Reason must be UTF-8.
    try testing.expectEqual(@as(?Error, error.InvalidUtf8), try decodeError(frame(&out, true, .close, "\x03\xe8\xff")));
}

test "a message larger than the read buffer is streamed" {
    const t = try TestDecoder.init(512, 1 << 20);
    defer t.deinit();
    const payload = try testing.allocator.alloc(u8, 70000);
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 13);
    const out = try testing.allocator.alloc(u8, payload.len + max_header_len);
    defer testing.allocator.free(out);
    try t.feed(frame(out, true, .binary, payload));
    try testing.expectEqual(@as(?Error, null), t.err);
    try testing.expectEqual(@as(u8, 2), t.log.items[0]);
    try testing.expectEqualSlices(u8, payload, t.log.items[9..]);
    // The large reassembly buffer was freed after delivery.
    try t.feed(frame(out, true, .text, "x"));
    try testing.expectEqual(@as(usize, 0), t.dec.msg.capacity);
}

// The property from the HTTP state machine, for WebSockets: any split of
// the input, including byte by byte, produces the same messages.
test "random splits produce identical messages" {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    var big: [3000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i *% 31);
    var scratch: [4096]u8 = undefined;
    const pieces = [_]struct { fin: bool, op: Opcode, p: []const u8 }{
        .{ .fin = true, .op = .text, .p = "hello" },
        .{ .fin = true, .op = .ping, .p = "" },
        .{ .fin = false, .op = .text, .p = "fr\xe2" },
        .{ .fin = true, .op = .pong, .p = "mid" },
        .{ .fin = false, .op = .continuation, .p = "\x82\xacag" },
        .{ .fin = true, .op = .continuation, .p = "ments" },
        .{ .fin = true, .op = .binary, .p = &big },
        .{ .fin = true, .op = .binary, .p = "" },
        .{ .fin = false, .op = .binary, .p = big[0..1000] },
        .{ .fin = false, .op = .continuation, .p = "" },
        .{ .fin = true, .op = .continuation, .p = big[1000..] },
        .{ .fin = true, .op = .text, .p = "" },
        .{ .fin = true, .op = .close, .p = "\x03\xe8done" },
    };
    for (0..4) |_| {
        for (pieces) |pc| try input.appendSlice(testing.allocator, frame(&scratch, pc.fin, pc.op, pc.p));
    }

    // Reference: everything in one read, with a buffer large enough that
    // every unfragmented message takes the in-place path.
    const ref = try TestDecoder.init(8192, 1 << 20);
    defer ref.deinit();
    try ref.feed(input.items);
    try testing.expectEqual(@as(?Error, null), ref.err);
    // Per round: text, ping, reassembled text, pong, big, empty binary,
    // reassembled binary, empty text, close.
    try testing.expectEqual(@as(usize, 4 * 9), ref.count);

    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    for (0..200) |iteration| {
        // Small buffers force the streaming path for the large messages.
        const buf_size: usize = if (iteration % 2 == 0) 256 else 8192;
        const t = try TestDecoder.init(buf_size, 1 << 20);
        defer t.deinit();
        var rest: []const u8 = input.items;
        while (rest.len > 0) {
            const max_chunk: usize = if (iteration == 0) 1 else 1 + random.uintLessThan(usize, 700);
            const n = @min(rest.len, max_chunk);
            try t.feed(rest[0..n]);
            rest = rest[n..];
        }
        try testing.expectEqual(@as(?Error, null), t.err);
        try testing.expectEqualSlices(u8, ref.log.items, t.log.items);
    }
}
