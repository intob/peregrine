//! HTTP/3 framing (RFC 9114 §7): frame and stream types, error codes,
//! SETTINGS. Frames are read from stream data incrementally: a header
//! (type and length varints) first, then the payload.
const std = @import("std");
const packet = @import("../quic/packet.zig");
const Reader = packet.Reader;
const Writer = packet.Writer;

pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    /// RFC 9218 §7.2: on the control stream, for a request stream or a
    /// push.
    priority_update_request = 0xf0700,
    priority_update_push = 0xf0701,
    _,

    /// HTTP/2 frame types with no HTTP/3 meaning (§7.2.8): an error.
    pub fn reservedH2(t: FrameType) bool {
        return switch (@backingInt(t)) {
            0x02, 0x06, 0x08, 0x09 => true,
            else => false,
        };
    }
};

pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    _,
};

/// Application error codes (RFC 9114 §8.1, RFC 9204 §6).
pub const ErrorCode = enum(u64) {
    no_error = 0x100,
    general_protocol_error = 0x101,
    internal_error = 0x102,
    stream_creation_error = 0x103,
    closed_critical_stream = 0x104,
    frame_unexpected = 0x105,
    frame_error = 0x106,
    excessive_load = 0x107,
    id_error = 0x108,
    settings_error = 0x109,
    missing_settings = 0x10a,
    request_rejected = 0x10b,
    request_cancelled = 0x10c,
    request_incomplete = 0x10d,
    message_error = 0x10e,
    connect_error = 0x10f,
    version_fallback = 0x110,
    qpack_decompression_failed = 0x200,
    qpack_encoder_stream_error = 0x201,
    qpack_decoder_stream_error = 0x202,
    _,
};

pub const SettingId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    /// RFC 9220.
    enable_connect_protocol = 0x08,
    /// RFC 9297.
    h3_datagram = 0x33,
    _,

    /// HTTP/2 settings with no HTTP/3 meaning (§7.2.4.1): an error.
    pub fn reservedH2(id: u64) bool {
        return id >= 0x02 and id <= 0x05;
    }
};

pub const Header = struct {
    type: FrameType,
    len: u64,
    /// Bytes the type and length took.
    size: usize,
};

/// The frame header at the start of `data`, or null if it isn't all there.
pub fn parseHeader(data: []const u8) ?Header {
    var r: Reader = .{ .data = data };
    const t = r.varint() catch return null;
    const len = r.varint() catch return null;
    return .{ .type = @fromBackingInt(t), .len = len, .size = r.pos };
}

pub fn writeHeader(w: *Writer, t: FrameType, len: u64) void {
    w.varint(@backingInt(t));
    w.varint(len);
}

pub fn headerLen(t: FrameType, len: u64) usize {
    return packet.varintLen(@backingInt(t)) + packet.varintLen(len);
}

pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    max_field_section_size: ?u64 = null,
    qpack_blocked_streams: u64 = 0,
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
};

/// Parses a SETTINGS payload (§7.2.4): duplicates, reserved HTTP/2 ids and
/// bad values are H3_SETTINGS_ERROR; unknown ids are ignored.
pub fn parseSettings(payload: []const u8) error{ Settings, Frame }!Settings {
    var s: Settings = .{};
    var r: Reader = .{ .data = payload };
    // Any identifier may appear once, known or not. A peer has no reason
    // to send many; past the bound the frame is refused.
    var seen: [64]u64 = undefined;
    var n: usize = 0;
    while (r.left() > 0) {
        const id = r.varint() catch return error.Frame;
        const v = r.varint() catch return error.Frame;
        if (SettingId.reservedH2(id)) return error.Settings;
        for (seen[0..n]) |x| if (x == id) return error.Settings;
        if (n == seen.len) return error.Settings;
        seen[n] = id;
        n += 1;
        switch (@as(SettingId, @fromBackingInt(id))) {
            .qpack_max_table_capacity => s.qpack_max_table_capacity = v,
            .max_field_section_size => s.max_field_section_size = v,
            .qpack_blocked_streams => s.qpack_blocked_streams = v,
            .enable_connect_protocol => {
                if (v > 1) return error.Settings;
                s.enable_connect_protocol = v == 1;
            },
            .h3_datagram => {
                if (v > 1) return error.Settings;
                s.h3_datagram = v == 1;
            },
            _ => {},
        }
    }
    return s;
}

const testing = std.testing;

test "frame headers and settings" {
    try testing.expectEqual(@as(?Header, null), parseHeader(&.{0x01}));
    const h = parseHeader(&.{ 0x01, 0x40, 0x10, 0xaa }).?;
    try testing.expectEqual(FrameType.headers, h.type);
    try testing.expectEqual(@as(u64, 16), h.len);
    try testing.expectEqual(@as(usize, 3), h.size);
    try testing.expect(@as(FrameType, @fromBackingInt(0x06)).reservedH2());

    const s = try parseSettings(&.{ 0x06, 0x44, 0x00, 0x08, 0x01, 0x21, 0x00 });
    try testing.expectEqual(@as(?u64, 0x400), s.max_field_section_size);
    try testing.expect(s.enable_connect_protocol);
    try testing.expectError(error.Settings, parseSettings(&.{ 0x02, 0x00 })); // HTTP/2's ENABLE_PUSH
    try testing.expectError(error.Settings, parseSettings(&.{ 0x06, 0x01, 0x06, 0x02 })); // duplicate
    try testing.expectError(error.Settings, parseSettings(&.{ 0x21, 0x00, 0x21, 0x01 })); // duplicate unknown
    try testing.expectError(error.Settings, parseSettings(&.{ 0x08, 0x02 }));
    try testing.expectError(error.Frame, parseSettings(&.{ 0x06, 0x40 }));
}
