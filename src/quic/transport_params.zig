//! QUIC transport parameters (RFC 9000 §7.4, §18): decoding the client's,
//! encoding ours. Carried in the TLS quic_transport_parameters extension.
const std = @import("std");
const packet = @import("./packet.zig");
const Reader = packet.Reader;
const Writer = packet.Writer;

pub const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    /// RFC 9221.
    max_datagram_frame_size = 0x20,
    /// RFC 9287.
    grease_quic_bit = 0x2ab2,
    _,
};

pub const Cid = struct {
    buf: [packet.max_cid_len]u8 = undefined,
    len: u8 = 0,

    pub fn init(bytes: []const u8) Cid {
        var c: Cid = .{ .len = @intCast(bytes.len) };
        @memcpy(c.buf[0..bytes.len], bytes);
        return c;
    }

    pub fn slice(self: *const Cid) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn eql(self: *const Cid, other: []const u8) bool {
        return std.mem.eql(u8, self.slice(), other);
    }
};

/// Defaults are the RFC's values when a parameter is absent.
pub const Params = struct {
    /// Milliseconds; 0 disables the idle timeout.
    max_idle_timeout: u64 = 0,
    max_udp_payload_size: u64 = 65527,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = 3,
    /// Milliseconds.
    max_ack_delay: u64 = 25,
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = 2,
    initial_source_connection_id: ?Cid = null,
    max_datagram_frame_size: u64 = 0,
    grease_quic_bit: bool = false,
    // Server only.
    original_destination_connection_id: ?Cid = null,
    retry_source_connection_id: ?Cid = null,
    stateless_reset_token: ?[16]u8 = null,
};

pub const Error = error{
    /// TRANSPORT_PARAMETER_ERROR (§7.4, §18.2).
    TransportParameter,
};

/// Decodes a client's parameters, rejecting server-only ones, duplicates
/// and out-of-range values (§18.2). Unknown parameters are ignored.
pub fn decodeClient(data: []const u8) Error!Params {
    var p: Params = .{};
    var r: Reader = .{ .data = data };
    var seen: [32]u64 = undefined;
    var seen_len: usize = 0;
    while (r.left() > 0) {
        const id = r.varint() catch return error.TransportParameter;
        const value = r.vector() catch return error.TransportParameter;
        // Duplicates (§7.4): tracked for every known id.
        if (id <= 0x20 or id == 0x2ab2) {
            for (seen[0..seen_len]) |s| if (s == id) return error.TransportParameter;
            if (seen_len == seen.len) return error.TransportParameter;
            seen[seen_len] = id;
            seen_len += 1;
        }
        var v: Reader = .{ .data = value };
        switch (@as(Id, @fromBackingInt(id))) {
            .original_destination_connection_id, .stateless_reset_token, .preferred_address, .retry_source_connection_id => return error.TransportParameter,
            .max_idle_timeout => p.max_idle_timeout = try int(&v),
            .max_udp_payload_size => {
                p.max_udp_payload_size = try int(&v);
                if (p.max_udp_payload_size < 1200) return error.TransportParameter;
            },
            .initial_max_data => p.initial_max_data = try int(&v),
            .initial_max_stream_data_bidi_local => p.initial_max_stream_data_bidi_local = try int(&v),
            .initial_max_stream_data_bidi_remote => p.initial_max_stream_data_bidi_remote = try int(&v),
            .initial_max_stream_data_uni => p.initial_max_stream_data_uni = try int(&v),
            .initial_max_streams_bidi => {
                p.initial_max_streams_bidi = try int(&v);
                if (p.initial_max_streams_bidi > 1 << 60) return error.TransportParameter;
            },
            .initial_max_streams_uni => {
                p.initial_max_streams_uni = try int(&v);
                if (p.initial_max_streams_uni > 1 << 60) return error.TransportParameter;
            },
            .ack_delay_exponent => {
                p.ack_delay_exponent = try int(&v);
                if (p.ack_delay_exponent > 20) return error.TransportParameter;
            },
            .max_ack_delay => {
                p.max_ack_delay = try int(&v);
                if (p.max_ack_delay >= 1 << 14) return error.TransportParameter;
            },
            .disable_active_migration => {
                if (value.len != 0) return error.TransportParameter;
                p.disable_active_migration = true;
            },
            .active_connection_id_limit => {
                p.active_connection_id_limit = try int(&v);
                if (p.active_connection_id_limit < 2) return error.TransportParameter;
            },
            .initial_source_connection_id => {
                if (value.len > packet.max_cid_len) return error.TransportParameter;
                p.initial_source_connection_id = .init(value);
            },
            .max_datagram_frame_size => p.max_datagram_frame_size = try int(&v),
            .grease_quic_bit => {
                if (value.len != 0) return error.TransportParameter;
                p.grease_quic_bit = true;
            },
            _ => {},
        }
    }
    return p;
}

/// A parameter value that is one varint, exactly.
fn int(v: *Reader) Error!u64 {
    const x = v.varint() catch return error.TransportParameter;
    if (v.left() != 0) return error.TransportParameter;
    return x;
}

/// Room `encodeServer` needs at most.
pub const max_encoded_len = 256;

/// Encodes our (server) parameters. Values equal to the defaults are
/// omitted, except those a client must see.
pub fn encodeServer(out: *[max_encoded_len]u8, p: *const Params) []const u8 {
    var w: Writer = .{ .buf = out };
    const cid = struct {
        fn put(wr: *Writer, id: Id, c: Cid) void {
            wr.varint(@backingInt(id));
            wr.varint(c.len);
            wr.bytes(c.slice());
        }
    }.put;
    const num = struct {
        fn put(wr: *Writer, id: Id, value: u64) void {
            wr.varint(@backingInt(id));
            wr.varint(packet.varintLen(value));
            wr.varint(value);
        }
    }.put;
    cid(&w, .original_destination_connection_id, p.original_destination_connection_id.?);
    cid(&w, .initial_source_connection_id, p.initial_source_connection_id.?);
    if (p.retry_source_connection_id) |c| cid(&w, .retry_source_connection_id, c);
    if (p.stateless_reset_token) |t| {
        w.varint(@backingInt(Id.stateless_reset_token));
        w.varint(16);
        w.bytes(&t);
    }
    if (p.max_idle_timeout != 0) num(&w, .max_idle_timeout, p.max_idle_timeout);
    if (p.max_udp_payload_size != 65527) num(&w, .max_udp_payload_size, p.max_udp_payload_size);
    num(&w, .initial_max_data, p.initial_max_data);
    num(&w, .initial_max_stream_data_bidi_local, p.initial_max_stream_data_bidi_local);
    num(&w, .initial_max_stream_data_bidi_remote, p.initial_max_stream_data_bidi_remote);
    num(&w, .initial_max_stream_data_uni, p.initial_max_stream_data_uni);
    num(&w, .initial_max_streams_bidi, p.initial_max_streams_bidi);
    num(&w, .initial_max_streams_uni, p.initial_max_streams_uni);
    if (p.ack_delay_exponent != 3) num(&w, .ack_delay_exponent, p.ack_delay_exponent);
    if (p.max_ack_delay != 25) num(&w, .max_ack_delay, p.max_ack_delay);
    if (p.disable_active_migration) {
        w.varint(@backingInt(Id.disable_active_migration));
        w.varint(0);
    }
    if (p.active_connection_id_limit != 2) num(&w, .active_connection_id_limit, p.active_connection_id_limit);
    if (p.max_datagram_frame_size != 0) num(&w, .max_datagram_frame_size, p.max_datagram_frame_size);
    if (p.grease_quic_bit) {
        w.varint(@backingInt(Id.grease_quic_bit));
        w.varint(0);
    }
    return w.written();
}

// -- Tests ------------------------------------------------------------------

const testing = std.testing;

test "the client parameters from RFC 9001 A.2" {
    // The extension body in the sample ClientHello.
    const ext = [_]u8{
        0x04, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80, 0x00, 0xff, 0xff,
        0x07, 0x04, 0x80, 0x00, 0xff, 0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x09,
        0x01, 0x10, 0x0f, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x06, 0x04, 0x80, 0x00,
        0xff, 0xff,
    };
    const p = try decodeClient(&ext);
    try testing.expectEqual(@as(u64, (1 << 62) - 1), p.initial_max_data);
    try testing.expectEqual(@as(u64, 65535), p.initial_max_stream_data_bidi_local);
    try testing.expectEqual(@as(u64, 65535), p.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(@as(u64, 65535), p.initial_max_stream_data_uni);
    try testing.expectEqual(@as(u64, 16), p.initial_max_streams_bidi);
    try testing.expectEqual(@as(u64, 16), p.initial_max_streams_uni);
    try testing.expectEqual(@as(u64, 30000), p.max_idle_timeout);
    try testing.expectEqualSlices(u8, &.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }, p.initial_source_connection_id.?.slice());
}

test "invalid client parameters" {
    const bad = [_][]const u8{
        &.{ 0x00, 0x01, 0xaa }, // original_destination_connection_id from a client
        &([_]u8{ 0x02, 0x10 } ++ @as([16]u8, @splat(0))), // stateless_reset_token
        &.{ 0x03, 0x02, 0x44, 0xaf }, // max_udp_payload_size 1199
        &.{ 0x0a, 0x01, 21 }, // ack_delay_exponent > 20
        &.{ 0x0b, 0x02, 0x7f, 0xff, 0x0b, 0x02, 0x7f, 0xff }, // duplicate, and too large
        &.{ 0x0e, 0x01, 0x01 }, // active_connection_id_limit < 2
        &.{ 0x0c, 0x01, 0x00 }, // disable_active_migration with a value
        &.{ 0x01, 0x02, 0x05 }, // a value shorter than its length
        &.{ 0x01, 0x02, 0x05, 0x06 }, // a value with trailing bytes
        &.{ 0x01, 0x01, 0x05, 0x01, 0x01, 0x06 }, // duplicate
        &.{ 0x08, 0x08, 0xd0, 0, 0, 0, 0, 0, 0, 1 }, // > 2^60 streams
    };
    for (bad) |b| try testing.expectError(error.TransportParameter, decodeClient(b));
    // Unknown and reserved ids are ignored, even repeated.
    _ = try decodeClient(&.{ 0x40, 0x99, 0x01, 0x00, 0x40, 0x99, 0x00 });
}

test "server parameters round trip through a client-side reading" {
    var p: Params = .{
        .original_destination_connection_id = .init(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }),
        .initial_source_connection_id = .init(&.{ 9, 9, 9, 9 }),
        .stateless_reset_token = @splat(0x5a),
        .max_idle_timeout = 30000,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 1 << 18,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 3,
        .active_connection_id_limit = 4,
    };
    var buf: [max_encoded_len]u8 = undefined;
    const enc = encodeServer(&buf, &p);
    // Read back without the client-side restrictions on server-only ids.
    var r: Reader = .{ .data = enc };
    var found: usize = 0;
    while (r.left() > 0) {
        const id: Id = @fromBackingInt(try r.varint());
        const v = try r.vector();
        var vr: Reader = .{ .data = v };
        switch (id) {
            .original_destination_connection_id => try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, v),
            .stateless_reset_token => try testing.expectEqual(@as(usize, 16), v.len),
            .initial_max_streams_bidi => try testing.expectEqual(@as(u64, 100), try vr.varint()),
            .initial_max_data => try testing.expectEqual(@as(u64, 1 << 20), try vr.varint()),
            .active_connection_id_limit => try testing.expectEqual(@as(u64, 4), try vr.varint()),
            else => {},
        }
        found += 1;
    }
    try testing.expect(found >= 10);
    p.retry_source_connection_id = .init(&@as([20]u8, @splat(1)));
    p.original_destination_connection_id = .init(&@as([20]u8, @splat(2)));
    p.initial_source_connection_id = .init(&@as([20]u8, @splat(3)));
    p.max_datagram_frame_size = 65535;
    p.grease_quic_bit = true;
    p.disable_active_migration = true;
    try testing.expect(encodeServer(&buf, &p).len <= max_encoded_len);
}
