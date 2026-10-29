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
const deflate = @import("./deflate.zig");
const inflate = @import("./inflate.zig");

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,

    pub fn fromByte(byte: u8) ?Opcode {
        const op: Opcode = @fromBackingInt(@intCast(@as(u4, @truncate(byte))));
        return switch (op) {
            .continuation, .text, .binary, .close, .ping, .pong => op,
            _ => null,
        };
    }

    pub inline fn isControl(self: Opcode) bool {
        return @backingInt(self) & 0x8 != 0;
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
    /// Fail with 1007: a compressed message that doesn't inflate.
    InvalidCompressedData,
    /// Fail with 1009.
    MessageTooBig,
    /// Fail with 1011.
    OutOfMemory,
};

pub fn closeCodeFor(err: Error) u16 {
    return switch (err) {
        error.ProtocolError => close_code.protocol_error,
        error.InvalidUtf8, error.InvalidCompressedData => close_code.invalid_payload,
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
    out[0] = (if (fin) @as(u8, 0x80) else 0) | @backingInt(opcode);
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
    /// RSV1: the message is compressed (permessage-deflate).
    compressed: bool,
    opcode: Opcode,
    key: [4]u8,
    len: usize,
    hdr_len: usize,
};

/// Parses a client frame header. Returns null if more bytes are needed.
/// RSV1 is allowed when permessage-deflate was negotiated (`rsv1`).
fn parseHeader(data: []const u8, rsv1: bool) Error!?Header {
    if (data.len < 2) return null;
    const b0 = data[0];
    const b1 = data[1];
    // RSV bits must be zero unless an extension defines them (§5.2).
    if (b0 & (if (rsv1) @as(u8, 0x30) else 0x70) != 0) return error.ProtocolError;
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
    return .{ .fin = fin, .compressed = b0 & 0x40 != 0, .opcode = opcode, .key = key, .len = len, .hdr_len = hdr_len + 4 };
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

/// Whether `tail`, an incomplete final sequence, can still become valid
/// UTF-8: a lead byte, then continuation bytes, the first of them in the
/// range that rules out overlong forms, surrogates and code points past
/// U+10FFFF.
fn isUtf8Prefix(tail: []const u8) bool {
    if (tail.len == 0) return true;
    const b0 = tail[0];
    if (b0 < 0xC2 or b0 > 0xF4) return false;
    if (tail.len >= 2) {
        const lo: u8, const hi: u8 = switch (b0) {
            0xE0 => .{ 0xA0, 0xBF },
            0xED => .{ 0x80, 0x9F },
            0xF0 => .{ 0x90, 0xBF },
            0xF4 => .{ 0x80, 0x8F },
            else => .{ 0x80, 0xBF },
        };
        if (tail[1] < lo or tail[1] > hi) return false;
    }
    for (tail[@min(tail.len, 2)..]) |b| if (b & 0xC0 != 0x80) return false;
    return true;
}

/// Validates text that is still arriving: `data[valid.*..]` up to the last
/// complete sequence (advancing `valid`), and that what follows can still
/// complete, so invalid text fails as soon as it arrives (fail fast,
/// RFC 6455 §8.1).
fn validateUtf8Partial(data: []const u8, valid: *usize) Error!void {
    const upto = valid.* + utf8CompletePrefix(data[valid.*..]);
    if (!std.unicode.utf8ValidateSlice(data[valid.*..upto])) return error.InvalidUtf8;
    if (!isUtf8Prefix(data[upto..])) return error.InvalidUtf8;
    valid.* = upto;
}

/// Frames up to this size are read straight into the reassembly buffer.
/// Larger ones go through the read buffer: the kernel's copy into a cold
/// megabyte cost more than its copy into the hot read buffer plus ours out
/// of it (Linux 6.12 on aarch64: 64 KiB and 256 KiB echoes 5-15% cheaper
/// read in place, 1 MiB 10-15% dearer).
const direct_read_max = 512 * 1024;

/// Per-connection frame decoder and message assembler. Input is buffered
/// like `Session`: the event loop reads into `readSpace`, commits, and calls
/// `next` until it returns null. A connection only holds a buffer while it
/// has unprocessed bytes.
///
/// An unfragmented message that fits in the buffer is delivered in place
/// (unmasked where it lies, no copy). Fragmented or oversized messages are
/// streamed into a reassembly buffer as the bytes arrive, so the read
/// buffer never needs to hold a whole frame. That buffer is sized from the
/// frame header (fragmented messages grow it), comes from the pool's cache
/// of large buffers and goes back to it once the message has been
/// delivered and no input is buffered. While more of a frame (up to
/// `direct_read_max`) is still to come than the read buffer holds,
/// `readSpace` returns the reassembly buffer itself, so the payload is read
/// straight into place.
pub const Decoder = struct {
    const Self = @This();

    buf: []u8 = &.{},
    start: usize = 0,
    end: usize = 0,
    pool: *BufferPool,
    max_message_size: usize,
    state: enum(u8) { header, stream } = .header,
    /// The frame being streamed.
    fin: bool = false,
    key: [4]u8 = undefined,
    len: usize = 0,
    consumed: usize = 0,
    /// The message being reassembled, if any: `msg_buf[0..msg_len]`.
    msg_buf: []u8 = &.{},
    msg_len: usize = 0,
    /// Payload read straight into `msg_buf` after `msg_len`, still masked.
    direct: usize = 0,
    /// The last `readSpace` returned part of `msg_buf`.
    reading_direct: bool = false,
    msg_opcode: ?Opcode = null,
    /// Prefix of the message already validated as UTF-8 (text messages).
    msg_valid: usize = 0,
    /// `msg_buf` holds the message returned by the last call; reset on the next.
    msg_delivered: bool = false,
    /// A text frame being held whole while it arrives: payload bytes
    /// unmasked so far, and the prefix of them validated.
    part_masked: usize = 0,
    part_valid: usize = 0,
    /// permessage-deflate was negotiated: messages may be compressed.
    deflate: bool = false,
    /// The client compresses each message on its own, so the inflate
    /// stream is dropped after each.
    deflate_no_takeover: bool = false,
    /// The client's window between messages (context takeover), made at
    /// the first compressed message.
    window: ?*inflate.Window = null,
    /// The message being reassembled is compressed.
    msg_compressed: bool = false,
    /// The last compressed message, inflated: `inf_buf[0..inf_len]`.
    inf_buf: []u8 = &.{},
    inf_len: usize = 0,

    pub fn init(pool: *BufferPool, max_message_size: usize) Self {
        return .{ .pool = pool, .max_message_size = max_message_size };
    }

    pub fn deinit(self: *Self) void {
        if (self.buf.len > 0) self.pool.release(self.buf);
        if (self.msg_buf.len > 0) self.pool.releaseLarge(self.msg_buf);
        if (self.inf_buf.len > 0) self.pool.releaseLarge(self.inf_buf);
        if (self.window) |w| self.pool.allocator.destroy(w);
        self.* = .{ .pool = self.pool, .max_message_size = self.max_message_size };
    }

    pub inline fn buffered(self: *const Self) usize {
        return self.end - self.start;
    }

    /// Holds part of a frame, or a buffer to read the next one into: the
    /// rest is best received straight into `readSpace` (which may be the
    /// message itself) rather than copied there.
    pub inline fn holdsPartialFrame(self: *const Self) bool {
        return self.buf.len > 0 or self.state == .stream;
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
    pub fn readSpace(self: *Self) ![]u8 {
        if (self.state == .stream and self.start == self.end and self.len <= direct_read_max) {
            // The frame continues; read what the read buffer couldn't hold
            // straight into the message (its tail comes with the next
            // header).
            const want = self.len - self.consumed - self.direct;
            if (want >= self.pool.buffer_size) {
                self.reading_direct = true;
                return self.msg_buf[self.msg_len + self.direct ..][0..want];
            }
        }
        self.reading_direct = false;
        if (self.buf.len == 0) {
            self.buf = try self.pool.acquire();
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
        if (self.reading_direct) {
            self.direct += n;
            self.reading_direct = false;
        } else {
            self.end += n;
        }
    }

    /// Returns the buffers to the pool when nothing is buffered: the read
    /// buffer, and the reassembly buffer unless a message is in progress.
    pub fn releaseIfIdle(self: *Self) void {
        if (self.buf.len > 0 and self.start == self.end) {
            self.pool.release(self.buf);
            self.buf = &.{};
            self.start = 0;
            self.end = 0;
        }
        if (self.msg_delivered or self.msg_opcode == null) {
            self.resetMessage();
            if (self.msg_buf.len > 0) self.pool.releaseLarge(self.msg_buf);
            if (self.inf_buf.len > 0) self.pool.releaseLarge(self.inf_buf);
            self.msg_buf = &.{};
            self.inf_buf = &.{};
        }
    }

    fn resetMessage(self: *Self) void {
        self.msg_delivered = false;
        self.msg_opcode = null;
        self.msg_compressed = false;
        self.msg_valid = 0;
        self.msg_len = 0;
        self.inf_len = 0;
    }

    /// Inflates a compressed message whose payload is followed by 4
    /// writable bytes (`with_room` holds both), into `inf_buf`. Returns the
    /// message.
    fn inflateMessage(self: *Self, with_room: []u8, opcode: Opcode) Error!Frame {
        const n = with_room.len - deflate.trailer.len;
        @memcpy(with_room[n..], &deflate.trailer);
        const tables = try self.pool.wsInflateTables();
        const window: ?*inflate.Window = if (self.deflate_no_takeover) null else self.window orelse blk: {
            const w = try self.pool.allocator.create(inflate.Window);
            w.* = .{};
            self.window = w;
            break :blk w;
        };
        var out: inflate.Out = .{ .buf = self.inf_buf, .max = self.max_message_size, .pool = self.pool };
        defer self.inf_buf = out.buf;
        _ = inflate.inflate(tables, window, with_room, &out) catch |err| return switch (err) {
            error.InvalidData => error.InvalidCompressedData,
            else => |e| e,
        };
        self.inf_len = out.len;
        const payload = out.buf[0..out.len];
        if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
        self.msg_delivered = true;
        return .{ .opcode = opcode, .payload = payload };
    }

    /// Room in `msg_buf` for `need` bytes, keeping what it holds. Fragments
    /// grow it geometrically (up to the message size limit).
    fn reserve(self: *Self, need: usize) Error!void {
        if (need <= self.msg_buf.len) return;
        const grown = @max(need, @min(2 * self.msg_buf.len, self.max_message_size));
        const new = try self.pool.acquireLarge(grown);
        @memcpy(new[0..self.msg_len], self.msg_buf[0..self.msg_len]);
        if (self.msg_buf.len > 0) self.pool.releaseLarge(self.msg_buf);
        self.msg_buf = new;
    }

    /// The next complete message, or null if more input is needed. Control
    /// frames are returned as they arrive, even in the middle of a
    /// fragmented message. The returned payload is valid until the next call
    /// to `next`, `readSpace` or `releaseIfIdle`.
    pub fn next(self: *Self) Error!?Frame {
        if (self.msg_delivered) self.resetMessage();
        while (true) {
            switch (self.state) {
                .header => {
                    const data = self.buf[self.start..self.end];
                    const hdr = (try parseHeader(data, self.deflate)) orelse return null;
                    const total = hdr.hdr_len + hdr.len;
                    const in_progress = self.msg_opcode != null;
                    // Only a message's first frame says it is compressed
                    // (RFC 7692 §6.1).
                    if (hdr.compressed and (hdr.opcode.isControl() or hdr.opcode == .continuation)) {
                        return error.ProtocolError;
                    }
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
                    const msg_len = self.msg_len + hdr.len;
                    if (msg_len > self.max_message_size) return error.MessageTooBig;
                    if (hdr.fin and !in_progress and total <= self.buf.len) {
                        // Whole message, fits the buffer: deliver in place.
                        // Text is unmasked and checked as it arrives.
                        const payload = data[hdr.hdr_len..@min(data.len, total)];
                        if (data.len < total) {
                            if (hdr.opcode == .text and !hdr.compressed) {
                                applyMask(payload[self.part_masked..], hdr.key, self.part_masked);
                                self.part_masked = payload.len;
                                try validateUtf8Partial(payload, &self.part_valid);
                            }
                            return null;
                        }
                        applyMask(payload[self.part_masked..], hdr.key, self.part_masked);
                        if (hdr.compressed) {
                            // Inflate where it lies: the 4 bytes after it
                            // (the next frame's, if any) are lent for the
                            // trailer. Otherwise copy it into msg.
                            const at = self.start + hdr.hdr_len;
                            self.part_masked = 0;
                            self.start += total;
                            if (at + hdr.len + 4 <= self.buf.len) {
                                const lent = self.buf[at + hdr.len ..][0..4].*;
                                defer self.buf[at + hdr.len ..][0..4].* = lent;
                                return try self.inflateMessage(self.buf[at..][0 .. hdr.len + 4], hdr.opcode);
                            }
                            try self.reserve(hdr.len + 4);
                            @memcpy(self.msg_buf[0..hdr.len], payload);
                            return try self.inflateMessage(self.msg_buf[0 .. hdr.len + 4], hdr.opcode);
                        }
                        if (hdr.opcode == .text and !std.unicode.utf8ValidateSlice(payload[self.part_valid..])) {
                            return error.InvalidUtf8;
                        }
                        self.part_masked = 0;
                        self.part_valid = 0;
                        self.start += total;
                        return .{ .opcode = hdr.opcode, .payload = payload };
                    }
                    // Fragmented or larger than the buffer: stream into msg
                    // (with room for the trailer a compressed one needs).
                    if (!in_progress) self.msg_compressed = hdr.compressed;
                    try self.reserve(msg_len + if (self.msg_compressed) deflate.trailer.len else 0);
                    if (!in_progress) self.msg_opcode = hdr.opcode;
                    self.fin = hdr.fin;
                    self.key = hdr.key;
                    self.len = hdr.len;
                    self.consumed = 0;
                    self.start += hdr.hdr_len;
                    self.state = .stream;
                },
                .stream => {
                    // Bytes read in place come first: they were read only
                    // when nothing was buffered.
                    if (self.direct > 0) {
                        applyMask(self.msg_buf[self.msg_len..][0..self.direct], self.key, self.consumed);
                        self.msg_len += self.direct;
                        self.consumed += self.direct;
                        self.direct = 0;
                        if (self.msg_opcode == .text and !self.msg_compressed) try self.validateUtf8Progress();
                    }
                    const take = @min(self.end - self.start, self.len - self.consumed);
                    if (take > 0) {
                        const chunk = self.buf[self.start..][0..take];
                        applyMask(chunk, self.key, self.consumed);
                        @memcpy(self.msg_buf[self.msg_len..][0..take], chunk);
                        self.msg_len += take;
                        self.start += take;
                        self.consumed += take;
                        if (self.msg_opcode == .text and !self.msg_compressed) try self.validateUtf8Progress();
                    }
                    if (self.consumed < self.len) return null;
                    self.state = .header;
                    if (!self.fin) continue;
                    if (self.msg_compressed) {
                        return try self.inflateMessage(self.msg_buf[0 .. self.msg_len + deflate.trailer.len], self.msg_opcode.?);
                    }
                    if (self.msg_opcode == .text and self.msg_valid != self.msg_len) {
                        // Ends in the middle of a sequence.
                        return error.InvalidUtf8;
                    }
                    self.msg_delivered = true;
                    return .{ .opcode = self.msg_opcode.?, .payload = self.msg_buf[0..self.msg_len] };
                },
            }
        }
    }

    /// Validates newly appended text as far as the last complete sequence,
    /// so invalid text fails as soon as it arrives.
    fn validateUtf8Progress(self: *Self) Error!void {
        try validateUtf8Partial(self.msg_buf[0..self.msg_len], &self.msg_valid);
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
            .dec = undefined,
        };
        t.dec = Decoder.init(&t.pool, max_message);
        return t;
    }

    fn deinit(t: *TestDecoder) void {
        t.dec.deinit();
        t.pool.deinit();
        t.log.deinit(testing.allocator);
        testing.allocator.destroy(t);
    }

    /// Feeds bytes as one read, draining messages after each buffer fill.
    fn feed(t: *TestDecoder, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0 and t.err == null) {
            const space = try t.dec.readSpace();
            const n = @min(space.len, rest.len);
            @memcpy(space[0..n], rest[0..n]);
            t.dec.commitRead(n);
            rest = rest[n..];
            t.drain();
            t.dec.releaseIfIdle();
        }
    }

    fn drain(t: *TestDecoder) void {
        while (true) {
            const fr = t.dec.next() catch |e| {
                t.err = e;
                return;
            } orelse return;
            t.count += 1;
            t.log.append(testing.allocator, @backingInt(fr.opcode)) catch unreachable;
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
    // So does an incomplete sequence that can't be completed (Autobahn
    // 6.4.2 and 6.4.4), in a fragment and in one frame still arriving.
    const doomed = [_][]const u8{ "ok\xf4\x90", "\xe0\x80", "\xed\xa0", "\xf0\x80", "\xc1", "\xf5", "\xe2\x82a" };
    for (doomed) |d| {
        for ([_]bool{ false, true }) |one_frame| {
            const t = try TestDecoder.init(4096, 1 << 20);
            defer t.deinit();
            var buf: [128]u8 = undefined;
            var payload: [64]u8 = undefined;
            @memcpy(payload[0..d.len], d);
            @memcpy(payload[d.len..][0..8], "\x80\x80tail..");
            // Header and mask, then the payload up to the doomed bytes: the
            // whole of a first fragment, or part of a longer single frame.
            const f = if (one_frame)
                frame(&buf, true, .text, payload[0 .. d.len + 8])
            else
                frame(&buf, false, .text, d);
            try t.feed(f[0 .. 6 + d.len]);
            try testing.expectEqual(@as(?Error, error.InvalidUtf8), t.err);
        }
    }
    // A valid frame arriving in pieces is unmasked and checked as it comes,
    // and delivered whole.
    {
        const t = try TestDecoder.init(4096, 1 << 20);
        defer t.deinit();
        var buf: [128]u8 = undefined;
        const text = "h\xc3\xa9llo \xe2\x82\xac \xf0\x9f\x98\x80!";
        const f = frame(&buf, true, .text, text);
        for (f, 0..) |_, i| {
            try t.feed(f[i..][0..1]);
            try testing.expectEqual(@as(?Error, null), t.err);
        }
        try testing.expectEqual(@as(usize, 1), t.count);
        try testing.expectEqualSlices(u8, text, t.log.items[9..]);
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
    // The reassembly buffer went back to the pool's cache after delivery.
    try testing.expectEqual(@as(usize, 0), t.dec.msg_buf.len);
    try testing.expectEqual(@as(usize, 1), t.pool.large_len);
    try t.feed(frame(out, true, .text, "x"));
    try testing.expectEqual(@as(usize, 1), t.pool.large_len);
}

test "the rest of a large frame is read straight into the message" {
    const t = try TestDecoder.init(512, 1 << 20);
    defer t.deinit();
    const payload = try testing.allocator.alloc(u8, 70000);
    defer testing.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 7);
    const out = try testing.allocator.alloc(u8, payload.len + max_header_len + 16);
    defer testing.allocator.free(out);
    const big = frame(out, true, .binary, payload);
    var small_buf: [16]u8 = undefined;
    const small = frame(&small_buf, true, .text, "x");
    @memcpy(out[big.len..][0..small.len], small);
    const input = out[0 .. big.len + small.len];

    // The first read fills the read buffer.
    var space = try t.dec.readSpace();
    try testing.expectEqual(@as(usize, 512), space.len);
    @memcpy(space, input[0..512]);
    t.dec.commitRead(512);
    try testing.expectEqual(@as(?Frame, null), try t.dec.next());
    // The rest of the frame goes straight into the message buffer, up to
    // a tail smaller than the read buffer.
    space = try t.dec.readSpace();
    try testing.expectEqual(big.len - 512, space.len);
    try testing.expect(space.ptr == t.dec.msg_buf.ptr + (512 - 14));
    const direct = big.len - 512 - 300;
    @memcpy(space[0..direct], input[512..][0..direct]);
    t.dec.commitRead(direct);
    try testing.expectEqual(@as(?Frame, null), try t.dec.next());
    // The tail, with the next frame, goes through the read buffer.
    space = try t.dec.readSpace();
    try testing.expect(space.ptr == t.dec.buf.ptr);
    const rest = input[512 + direct ..];
    @memcpy(space[0..rest.len], rest);
    t.dec.commitRead(rest.len);
    const msg = (try t.dec.next()).?;
    try testing.expectEqual(Opcode.binary, msg.opcode);
    try testing.expectEqualSlices(u8, payload, msg.payload);
    const text = (try t.dec.next()).?;
    try testing.expectEqualStrings("x", text.payload);
    try testing.expectEqual(@as(?Frame, null), try t.dec.next());

    // Idle: both buffers go back; the next large message reuses the cached one.
    const cached = t.dec.msg_buf.ptr;
    t.dec.releaseIfIdle();
    try testing.expectEqual(@as(usize, 0), t.dec.buf.len);
    try testing.expectEqual(@as(usize, 0), t.dec.msg_buf.len);
    try t.feed(big);
    try testing.expectEqual(@as(?Error, null), t.err);
    try testing.expectEqual(@as(usize, 1), t.pool.large_len);
    try testing.expect(t.pool.large[0].ptr == cached);
}

/// A compressed client frame (RSV1 on a first frame).
fn compressedFrame(out: []u8, fin: bool, op: Opcode, deflated: []const u8) []u8 {
    const f = frame(out, fin, op, deflated);
    f[0] |= 0x40;
    return f;
}

test "permessage-deflate: compressed messages in place, streamed and fragmented, with context takeover" {
    var client: deflate.TestClient = undefined;
    try client.init();
    defer client.out.deinit();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(testing.allocator);
    var scratch: [16384]u8 = undefined;
    var big: [6000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = "the quick brown fox "[i % 20];
    const texts = [_][]const u8{ "Hello, hello, hello, compressed world!", "Hello, hello, hello, compressed world!", &big, "\xe2\x82\xac uro" };
    for (texts, 0..) |t, i| {
        const m = try client.message(t);
        defer testing.allocator.free(m);
        const deflated = m[0 .. m.len - 4];
        if (i == 2) {
            // Fragmented: RSV1 on the first frame only, a ping between.
            const half = deflated.len / 2;
            try input.appendSlice(testing.allocator, compressedFrame(&scratch, false, .text, deflated[0..half]));
            try input.appendSlice(testing.allocator, frame(&scratch, true, .ping, "p"));
            try input.appendSlice(testing.allocator, frame(&scratch, true, .continuation, deflated[half..]));
            try fuzzLog(&expected, .ping, "p");
        } else {
            try input.appendSlice(testing.allocator, compressedFrame(&scratch, true, .text, deflated));
        }
        try fuzzLog(&expected, .text, t);
    }
    // An uncompressed message in between is fine.
    try input.appendSlice(testing.allocator, frame(&scratch, true, .binary, "plain"));
    try fuzzLog(&expected, .binary, "plain");
    // In one go (in place), and byte by byte through a small buffer
    // (streamed, read in place).
    for ([_]usize{ 8192, 256 }) |buf_size| {
        const t = try TestDecoder.init(buf_size, 1 << 20);
        defer t.deinit();
        t.dec.deflate = true;
        if (buf_size == 8192) {
            try t.feed(input.items);
        } else {
            for (input.items, 0..) |_, i| try t.feed(input.items[i..][0..1]);
        }
        try testing.expectEqual(@as(?Error, null), t.err);
        try testing.expectEqualSlices(u8, expected.items, t.log.items);
    }
}

test "permessage-deflate: RSV1 rules, corrupt data, invalid text and the size limit" {
    var out: [256]u8 = undefined;
    const Case = struct { bytes: []const u8, deflate: bool, err: Error };
    var client: deflate.TestClient = undefined;
    try client.init();
    defer client.out.deinit();
    const bad_text = try client.message("ok \xff not UTF-8");
    defer testing.allocator.free(bad_text);
    var b1: [256]u8 = undefined;
    var b2: [256]u8 = undefined;
    var b3: [256]u8 = undefined;
    var b4: [256]u8 = undefined;
    var two: [256]u8 = undefined;
    const first = frame(&two, false, .binary, "a");
    const cont = compressedFrame(two[first.len..], true, .continuation, "b");
    const cases = [_]Case{
        // Not negotiated.
        .{ .bytes = compressedFrame(&b1, true, .text, "x"), .deflate = false, .err = error.ProtocolError },
        // Control frames and continuations never carry it.
        .{ .bytes = compressedFrame(&b2, true, .ping, ""), .deflate = true, .err = error.ProtocolError },
        .{ .bytes = two[0 .. first.len + cont.len], .deflate = true, .err = error.ProtocolError },
        // RSV2 is still reserved.
        .{ .bytes = blk: {
            const f = frame(&b3, true, .text, "x");
            f[0] |= 0x20;
            break :blk f;
        }, .deflate = true, .err = error.ProtocolError },
        // A block type of 3.
        .{ .bytes = compressedFrame(&b4, true, .binary, &.{0x07}), .deflate = true, .err = error.InvalidCompressedData },
        .{ .bytes = compressedFrame(&out, true, .text, bad_text[0 .. bad_text.len - 4]), .deflate = true, .err = error.InvalidUtf8 },
    };
    for (cases) |c| {
        const t = try TestDecoder.init(4096, 1 << 20);
        defer t.deinit();
        t.dec.deflate = c.deflate;
        try t.feed(c.bytes);
        try testing.expectEqual(@as(?Error, c.err), t.err);
    }
    // Inflated past the message limit: fails, though the compressed
    // message is small.
    var zclient: deflate.TestClient = undefined;
    try zclient.init();
    defer zclient.out.deinit();
    const zeros = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(zeros);
    @memset(zeros, 0);
    const z = try zclient.message(zeros);
    defer testing.allocator.free(z);
    const zf = try testing.allocator.alloc(u8, z.len + max_header_len);
    defer testing.allocator.free(zf);
    const t = try TestDecoder.init(4096, 50_000);
    defer t.deinit();
    t.dec.deflate = true;
    try t.feed(compressedFrame(zf, true, .binary, z[0 .. z.len - 4]));
    try testing.expectEqual(@as(?Error, error.MessageTooBig), t.err);
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

// Fuzz target: a stream of client frames, decoded with a buffer that holds
// every frame whole and again with a small one, read in arbitrary pieces
// (which streams large frames and reads them in place). Both must deliver
// the same messages and fail the same way. Most inputs are valid streams,
// whose messages are also checked against what was encoded; the rest mix in
// mangled frames (bad bits, opcodes, lengths, missing masks, truncation).
// Half the streams have permessage-deflate on: their data messages are
// compressed by one client stream (context takeover), and mangled frames
// with RSV1 feed the inflater garbage.
fn fuzzDecoder(_: void, smith: *std.testing.Smith) anyerror!void {
    const a = testing.allocator;
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(a);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(a);
    const valid = smith.value(u8) & 3 != 0;
    const compressed = smith.value(u8) & 1 != 0;
    const client: ?*deflate.TestClient = if (compressed) try a.create(deflate.TestClient) else null;
    defer if (client) |c| {
        c.out.deinit();
        a.destroy(c);
    };
    if (client) |c| try c.init();
    var count: usize = 0;
    while (count < 8 and !smith.eos()) : (count += 1) {
        if (valid or smith.value(u8) & 1 == 0) {
            try fuzzMessage(smith, &input, &expected, client);
        } else {
            try fuzzMangledFrame(smith, &input);
        }
    }
    const max_message = 4096;

    const whole = try TestDecoder.init(8192, max_message);
    defer whole.deinit();
    whole.dec.deflate = compressed;
    try whole.feed(input.items);
    if (valid) {
        try testing.expectEqual(@as(?Error, null), whole.err);
        try testing.expectEqualSlices(u8, expected.items, whole.log.items);
    }

    const sizes = [_]usize{ 256, 512, 1024 };
    const split = try TestDecoder.init(sizes[smith.value(u8) % sizes.len], max_message);
    defer split.deinit();
    split.dec.deflate = compressed;
    var rest: []const u8 = input.items;
    while (rest.len > 0 and split.err == null) {
        const n = @min(rest.len, 1 + @as(usize, smith.value(u8)) * 8);
        try split.feed(rest[0..n]);
        rest = rest[n..];
    }
    try testing.expectEqualSlices(u8, whole.log.items, split.log.items);
    // Streamed text is validated as it arrives, so invalid UTF-8 in a frame
    // the input cuts short fails only there.
    // `split.err` unwrapped: see `inflateAll` in compress.zig.
    if (whole.err != null or split.err == null or split.err.? != error.InvalidUtf8) {
        try testing.expectEqual(whole.err, split.err);
    }
}

/// Appends one valid message: a ping or pong, or text or binary in up to
/// three fragments with control frames between them, and logs it as
/// `TestDecoder` does. With a `client`, data messages are compressed.
fn fuzzMessage(smith: *std.testing.Smith, input: *std.ArrayList(u8), expected: *std.ArrayList(u8), client: ?*deflate.TestClient) !void {
    const a = testing.allocator;
    var payload: [2048]u8 = undefined;
    var scratch: [4096 + max_header_len]u8 = undefined;
    var key: [4]u8 = undefined;
    smith.bytes(&key);
    if (smith.value(u8) % 4 == 0) {
        const op: Opcode = if (smith.value(u8) & 1 == 0) .ping else .pong;
        const p = payload[0..smith.slice(payload[0..max_control_payload])];
        try input.appendSlice(a, encodeFrame(&scratch, true, op, p, key));
        try fuzzLog(expected, op, p);
        return;
    }
    const text = smith.value(u8) & 1 == 0;
    var len: usize = 0;
    if (text) {
        const pieces = [_][]const u8{ "a", "hello ", "\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80", "\x00", "\xef\xbf\xbf" };
        const target = @as(usize, smith.value(u16)) % payload.len;
        while (len < target) {
            const pc = pieces[smith.value(u8) % pieces.len];
            if (len + pc.len > payload.len) break;
            @memcpy(payload[len..][0..pc.len], pc);
            len += pc.len;
        }
    } else {
        len = smith.slice(&payload);
    }
    const message = payload[0..len];
    var deflated: ?[]u8 = null;
    defer if (deflated) |d| a.free(d);
    if (client) |c| deflated = try c.message(message);
    // What goes in the frames: the message, or what it compressed to.
    const body = if (deflated) |d| d[0 .. d.len - deflate.trailer.len] else message;
    const body_len = body.len;
    // Fragment boundaries anywhere, splitting UTF-8 sequences too.
    const fragments = 1 + smith.value(u8) % 3;
    var at: usize = 0;
    for (0..fragments) |i| {
        const last = i + 1 == fragments;
        const end = if (last) body_len else at + (if (body_len - at == 0) 0 else smith.value(u16) % (body_len - at + 1));
        const op: Opcode = if (i > 0) .continuation else if (text) .text else .binary;
        const f = encodeFrame(&scratch, last, op, body[at..end], key);
        if (i == 0 and deflated != null) f[0] |= 0x40;
        try input.appendSlice(a, f);
        at = end;
        if (!last and smith.value(u8) % 4 == 0) {
            var ping: [16]u8 = undefined;
            const p = ping[0..smith.slice(&ping)];
            try input.appendSlice(a, encodeFrame(&scratch, true, .ping, p, key));
            try fuzzLog(expected, .ping, p);
        }
    }
    try fuzzLog(expected, if (text) .text else .binary, message);
}

/// Appends a frame that may break any rule, or end early.
fn fuzzMangledFrame(smith: *std.testing.Smith, input: *std.ArrayList(u8)) !void {
    const a = testing.allocator;
    var payload: [600]u8 = undefined;
    const p = payload[0..smith.slice(&payload)];
    var b0 = smith.value(u8);
    // Mostly a known opcode with RSV clear, so later checks are reached.
    if (smith.value(u8) & 3 != 0) b0 &= 0x8f;
    var b1: u8 = if (smith.value(u8) % 8 != 0) 0x80 else 0;
    var ext: [8]u8 = undefined;
    var ext_len: usize = 0;
    switch (smith.value(u8) % 4) {
        0, 1 => b1 |= @intCast(@min(p.len, 125)),
        2 => {
            b1 |= 126;
            std.mem.writeInt(u16, ext[0..2], smith.value(u16), .big);
            ext_len = 2;
        },
        else => {
            b1 |= 127;
            std.mem.writeInt(u64, &ext, smith.value(u64) >> @intCast(smith.value(u8) % 64), .big);
            ext_len = 8;
        },
    }
    try input.append(a, b0);
    try input.append(a, b1);
    try input.appendSlice(a, ext[0..ext_len]);
    if (b1 & 0x80 != 0) {
        var key: [4]u8 = undefined;
        smith.bytes(&key);
        try input.appendSlice(a, &key);
    }
    try input.appendSlice(a, p);
}

fn fuzzLog(log: *std.ArrayList(u8), op: Opcode, payload: []const u8) !void {
    const a = testing.allocator;
    try log.append(a, @backingInt(op));
    var len_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_buf, payload.len, .little);
    try log.appendSlice(a, &len_buf);
    try log.appendSlice(a, payload);
}

test "fuzz: ws decoder" {
    try std.testing.fuzz({}, fuzzDecoder, .{
        .corpus = &.{
            // A text message, a ping, a binary message in two fragments.
            &[_]u8{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00, 0x05, 0x40, 0x00 },
            // Mostly mangled frames.
            &[_]u8{ 0x00, 0x01, 0x00, 0x01, 0x81, 0x03, 0x00, 0x01, 0xff, 0xff, 0x00, 0x02, 0x03 },
            // Larger messages: streamed and read in place with the small buffer.
            &[_]u8{ 0x01, 0x07, 0xff, 0xff, 0xff, 0xff, 0x01, 0x01, 0xff, 0x07, 0x01, 0x02, 0x00, 0xf0, 0x07, 0x80, 0x03 },
        },
    });
}
