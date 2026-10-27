//! QPACK (RFC 9204) with the static table only. We advertise a dynamic
//! table capacity of 0 (SETTINGS_QPACK_MAX_TABLE_CAPACITY), so a peer's
//! field sections may only use the static table and literals: nothing
//! blocks, the encoder and decoder streams carry no state, and our own
//! encoder never inserts. I/O-free: the decoder takes a complete field
//! section and hands each field to a sink.
const std = @import("std");
const hpack = @import("../h2/hpack.zig");

pub const Field = hpack.Field;

pub const Error = error{
    /// QPACK_DECOMPRESSION_FAILED (§6): a malformed section, or one that
    /// uses the dynamic table we never allowed.
    DecompressionFailed,
    /// The section decoded fine but its fields exceed the limit; the sink
    /// saw every field up to it.
    FieldSectionTooLarge,
};

pub const Limits = struct {
    /// Sum over fields of name + value + 32 (SETTINGS_MAX_FIELD_SECTION_SIZE).
    max_field_section_size: u32 = 16 * 1024,
    /// Longest single name or value, decoded.
    max_field_len: u32 = 8 * 1024,
};

/// RFC 9204 Appendix A.
pub const static_table = [_]Field{
    .{ .name = ":authority", .value = "" }, // 0
    .{ .name = ":path", .value = "/" }, // 1
    .{ .name = "age", .value = "0" }, // 2
    .{ .name = "content-disposition", .value = "" }, // 3
    .{ .name = "content-length", .value = "0" }, // 4
    .{ .name = "cookie", .value = "" }, // 5
    .{ .name = "date", .value = "" }, // 6
    .{ .name = "etag", .value = "" }, // 7
    .{ .name = "if-modified-since", .value = "" }, // 8
    .{ .name = "if-none-match", .value = "" }, // 9
    .{ .name = "last-modified", .value = "" }, // 10
    .{ .name = "link", .value = "" }, // 11
    .{ .name = "location", .value = "" }, // 12
    .{ .name = "referer", .value = "" }, // 13
    .{ .name = "set-cookie", .value = "" }, // 14
    .{ .name = ":method", .value = "CONNECT" }, // 15
    .{ .name = ":method", .value = "DELETE" }, // 16
    .{ .name = ":method", .value = "GET" }, // 17
    .{ .name = ":method", .value = "HEAD" }, // 18
    .{ .name = ":method", .value = "OPTIONS" }, // 19
    .{ .name = ":method", .value = "POST" }, // 20
    .{ .name = ":method", .value = "PUT" }, // 21
    .{ .name = ":scheme", .value = "http" }, // 22
    .{ .name = ":scheme", .value = "https" }, // 23
    .{ .name = ":status", .value = "103" }, // 24
    .{ .name = ":status", .value = "200" }, // 25
    .{ .name = ":status", .value = "304" }, // 26
    .{ .name = ":status", .value = "404" }, // 27
    .{ .name = ":status", .value = "503" }, // 28
    .{ .name = "accept", .value = "*/*" }, // 29
    .{ .name = "accept", .value = "application/dns-message" }, // 30
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" }, // 31
    .{ .name = "accept-ranges", .value = "bytes" }, // 32
    .{ .name = "access-control-allow-headers", .value = "cache-control" }, // 33
    .{ .name = "access-control-allow-headers", .value = "content-type" }, // 34
    .{ .name = "access-control-allow-origin", .value = "*" }, // 35
    .{ .name = "cache-control", .value = "max-age=0" }, // 36
    .{ .name = "cache-control", .value = "max-age=2592000" }, // 37
    .{ .name = "cache-control", .value = "max-age=604800" }, // 38
    .{ .name = "cache-control", .value = "no-cache" }, // 39
    .{ .name = "cache-control", .value = "no-store" }, // 40
    .{ .name = "cache-control", .value = "public, max-age=31536000" }, // 41
    .{ .name = "content-encoding", .value = "br" }, // 42
    .{ .name = "content-encoding", .value = "gzip" }, // 43
    .{ .name = "content-type", .value = "application/dns-message" }, // 44
    .{ .name = "content-type", .value = "application/javascript" }, // 45
    .{ .name = "content-type", .value = "application/json" }, // 46
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" }, // 47
    .{ .name = "content-type", .value = "image/gif" }, // 48
    .{ .name = "content-type", .value = "image/jpeg" }, // 49
    .{ .name = "content-type", .value = "image/png" }, // 50
    .{ .name = "content-type", .value = "text/css" }, // 51
    .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // 52
    .{ .name = "content-type", .value = "text/plain" }, // 53
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" }, // 54
    .{ .name = "range", .value = "bytes=0-" }, // 55
    .{ .name = "strict-transport-security", .value = "max-age=31536000" }, // 56
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" }, // 57
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" }, // 58
    .{ .name = "vary", .value = "accept-encoding" }, // 59
    .{ .name = "vary", .value = "origin" }, // 60
    .{ .name = "x-content-type-options", .value = "nosniff" }, // 61
    .{ .name = "x-xss-protection", .value = "1; mode=block" }, // 62
    .{ .name = ":status", .value = "100" }, // 63
    .{ .name = ":status", .value = "204" }, // 64
    .{ .name = ":status", .value = "206" }, // 65
    .{ .name = ":status", .value = "302" }, // 66
    .{ .name = ":status", .value = "400" }, // 67
    .{ .name = ":status", .value = "403" }, // 68
    .{ .name = ":status", .value = "421" }, // 69
    .{ .name = ":status", .value = "425" }, // 70
    .{ .name = ":status", .value = "500" }, // 71
    .{ .name = "accept-language", .value = "" }, // 72
    .{ .name = "access-control-allow-credentials", .value = "FALSE" }, // 73
    .{ .name = "access-control-allow-credentials", .value = "TRUE" }, // 74
    .{ .name = "access-control-allow-headers", .value = "*" }, // 75
    .{ .name = "access-control-allow-methods", .value = "get" }, // 76
    .{ .name = "access-control-allow-methods", .value = "get, post, options" }, // 77
    .{ .name = "access-control-allow-methods", .value = "options" }, // 78
    .{ .name = "access-control-expose-headers", .value = "content-length" }, // 79
    .{ .name = "access-control-request-headers", .value = "content-type" }, // 80
    .{ .name = "access-control-request-method", .value = "get" }, // 81
    .{ .name = "access-control-request-method", .value = "post" }, // 82
    .{ .name = "alt-svc", .value = "clear" }, // 83
    .{ .name = "authorization", .value = "" }, // 84
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" }, // 85
    .{ .name = "early-data", .value = "1" }, // 86
    .{ .name = "expect-ct", .value = "" }, // 87
    .{ .name = "forwarded", .value = "" }, // 88
    .{ .name = "if-range", .value = "" }, // 89
    .{ .name = "origin", .value = "" }, // 90
    .{ .name = "purpose", .value = "prefetch" }, // 91
    .{ .name = "server", .value = "" }, // 92
    .{ .name = "timing-allow-origin", .value = "*" }, // 93
    .{ .name = "upgrade-insecure-requests", .value = "1" }, // 94
    .{ .name = "user-agent", .value = "" }, // 95
    .{ .name = "x-forwarded-for", .value = "" }, // 96
    .{ .name = "x-frame-options", .value = "deny" }, // 97
    .{ .name = "x-frame-options", .value = "sameorigin" }, // 98
};

// -- Decoding -------------------------------------------------------------------

pub const Decoder = struct {
    const Self = @This();

    limits: Limits,
    allocator: std.mem.Allocator,
    /// Huffman-decoded name and value.
    scratch: []u8,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) !Self {
        return .{ .limits = limits, .allocator = allocator, .scratch = try allocator.alloc(u8, 2 * limits.max_field_len) };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.scratch);
    }

    /// Decodes a complete field section (a HEADERS frame's payload).
    pub fn decode(self: *Self, section: []const u8, sink: anytype) !void {
        var pos: usize = 0;
        // Encoded Required Insert Count, then the Base (§4.5.1). With no
        // dynamic table both must be zero.
        const ric = try int(section, &pos, 8);
        if (ric != 0) return error.DecompressionFailed;
        if (pos >= section.len) return error.DecompressionFailed;
        const base = try int(section, &pos, 7);
        if (base != 0) return error.DecompressionFailed;
        var total: usize = 0;
        var over = false;
        while (pos < section.len) {
            const b = section[pos];
            var name: []const u8 = undefined;
            var value: []const u8 = undefined;
            if (b & 0x80 != 0) {
                // Indexed field line (§4.5.2); T=0 is the dynamic table.
                if (b & 0x40 == 0) return error.DecompressionFailed;
                const f = try staticEntry(try int(section, &pos, 6));
                name = f.name;
                value = f.value;
            } else if (b & 0x40 != 0) {
                // Literal field line with name reference (§4.5.4).
                if (b & 0x10 == 0) return error.DecompressionFailed;
                name = (try staticEntry(try int(section, &pos, 4))).name;
                value = try self.string(section, &pos, 7, self.scratch[self.limits.max_field_len..]);
            } else if (b & 0x20 != 0) {
                // Literal field line with literal name (§4.5.6).
                name = try self.string(section, &pos, 3, self.scratch[0..self.limits.max_field_len]);
                value = try self.string(section, &pos, 7, self.scratch[self.limits.max_field_len..]);
            } else {
                // Post-base indexed and post-base name reference forms
                // (§4.5.3, §4.5.5) only refer to the dynamic table.
                return error.DecompressionFailed;
            }
            total += name.len + value.len + 32;
            if (total > self.limits.max_field_section_size) over = true;
            if (!over) try sink.header(name, value);
        }
        if (over) return error.FieldSectionTooLarge;
    }

    /// A string literal whose length prefix is `prefix` bits, with the H
    /// bit just above it.
    fn string(self: *Self, data: []const u8, pos: *usize, comptime prefix: u4, scratch: []u8) Error![]const u8 {
        if (pos.* >= data.len) return error.DecompressionFailed;
        const huffman = data[pos.*] & (@as(u8, 1) << prefix) != 0;
        const len = try int(data, pos, prefix);
        if (data.len - pos.* < len) return error.DecompressionFailed;
        const raw = data[pos.*..][0..len];
        pos.* += len;
        if (!huffman) {
            if (raw.len > self.limits.max_field_len) return error.DecompressionFailed;
            return raw;
        }
        const n = hpack.huffmanDecode(scratch, raw) catch return error.DecompressionFailed;
        return scratch[0..n];
    }
};

fn int(data: []const u8, pos: *usize, comptime prefix: u4) Error!u32 {
    if (pos.* >= data.len) return error.DecompressionFailed;
    const r = hpack.decodeInt(data[pos.*..], prefix) catch return error.DecompressionFailed;
    pos.* += r.len;
    return r.value;
}

fn staticEntry(i: u32) Error!Field {
    if (i >= static_table.len) return error.DecompressionFailed;
    return static_table[i];
}

// -- Encoding -------------------------------------------------------------------

/// The two-byte section prefix: Required Insert Count 0, Base 0.
pub const section_prefix = [2]u8{ 0, 0 };

/// Static table indices by name: the first entry with the name, and every
/// entry with it.
const name_index = blk: {
    @setEvalBranchQuota(100_000);
    var kvs: [static_table.len]struct { []const u8, []const u8 } = undefined;
    var n: usize = 0;
    for (static_table, 0..) |f, i| {
        var found = false;
        for (kvs[0..n]) |*kv| {
            if (std.mem.eql(u8, kv[0], f.name)) {
                kv[1] = kv[1] ++ [_]u8{@intCast(i)};
                found = true;
            }
        }
        if (!found) {
            kvs[n] = .{ f.name, &[_]u8{@intCast(i)} };
            n += 1;
        }
    }
    break :blk std.StaticStringMap([]const u8).initComptime(kvs[0..n]);
};

/// Writes one field line: an exact static match as an indexed line, a
/// static name as a name reference, otherwise literal (Huffman when
/// shorter). `name` must be lowercase.
pub fn encodeField(out: []u8, name: []const u8, value: []const u8) error{NoSpace}!usize {
    if (name_index.get(name)) |indices| {
        for (indices) |i| {
            if (std.mem.eql(u8, static_table[i].value, value)) {
                return hpack.encodeInt(out, 0xc0, 6, i);
            }
        }
        // Name reference, N=0, T=1 (static).
        const n = try hpack.encodeInt(out, 0x50, 4, indices[0]);
        return n + try encodeString(out[n..], 0, 7, value);
    }
    const n = try encodeString(out, 0x20, 3, name);
    return n + try encodeString(out[n..], 0, 7, value);
}

/// A string with an H bit above a `prefix`-bit length; `first` holds the
/// representation's pattern bits.
fn encodeString(out: []u8, first: u8, comptime prefix_bits: u4, s: []const u8) error{NoSpace}!usize {
    const hlen = hpack.huffmanEncodedLen(s);
    const huffman = hlen < s.len;
    const len = if (huffman) hlen else s.len;
    const h_bit: u8 = if (huffman) @as(u8, 1) << prefix_bits else 0;
    const n = try hpack.encodeInt(out, first | h_bit, prefix_bits, len);
    if (out.len - n < len) return error.NoSpace;
    if (huffman) _ = hpack.huffmanEncode(out[n..], s) else @memcpy(out[n..][0..len], s);
    return n + len;
}

/// The :status field, from the static table where it has the code.
pub fn encodeStatus(out: []u8, code: u16) error{NoSpace}!usize {
    var buf: [3]u8 = undefined;
    _ = std.fmt.printInt(&buf, code, 10, .lower, .{});
    return encodeField(out, ":status", &buf);
}

// -- Tests ----------------------------------------------------------------------

const testing = std.testing;

const LogSink = struct {
    out: std.ArrayList(u8) = .empty,

    pub fn header(self: *LogSink, name: []const u8, value: []const u8) !void {
        try self.out.print(testing.allocator, "{s}: {s}\n", .{ name, value });
    }
};

fn decodeToString(dec: *Decoder, section: []const u8) ![]u8 {
    var sink: LogSink = .{};
    errdefer sink.out.deinit(testing.allocator);
    try dec.decode(section, &sink);
    return sink.out.toOwnedSlice(testing.allocator);
}

test "static table is RFC 9204 Appendix A" {
    try testing.expectEqual(@as(usize, 99), static_table.len);
    try testing.expectEqualStrings(":authority", static_table[0].name);
    try testing.expectEqualStrings("text/plain;charset=utf-8", static_table[54].value);
    try testing.expectEqualStrings("text/html; charset=utf-8", static_table[52].value);
    try testing.expectEqualStrings("max-age=31536000; includesubdomains; preload", static_table[58].value);
    try testing.expectEqualStrings("x-frame-options", static_table[98].name);
}

test "decode: RFC 9204 B.1, every representation, and errors" {
    var dec = try Decoder.init(testing.allocator, .{});
    defer dec.deinit();
    // B.1: literal with name reference, :path /index.html.
    const b1 = [_]u8{ 0x00, 0x00, 0x51, 0x0b, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c };
    const s1 = try decodeToString(&dec, &b1);
    defer testing.allocator.free(s1);
    try testing.expectEqualStrings(":path: /index.html\n", s1);

    // Our encoder's output decodes back, Huffman and plain alike.
    var buf: [512]u8 = undefined;
    var n: usize = 2;
    @memcpy(buf[0..2], &section_prefix);
    const fields = [_]Field{
        .{ .name = ":method", .value = "GET" }, // indexed
        .{ .name = ":path", .value = "/a/b?c=d" }, // name reference
        .{ .name = "x-custom", .value = "Some Value" }, // literal name
        .{ .name = "content-type", .value = "text/plain" }, // indexed
        .{ .name = "user-agent", .value = "" }, // indexed (empty value)
        .{ .name = "x-bin", .value = "\x00\xff\x10" }, // not Huffman-shorter
    };
    for (fields) |f| n += try encodeField(buf[n..], f.name, f.value);
    const s2 = try decodeToString(&dec, buf[0..n]);
    defer testing.allocator.free(s2);
    try testing.expectEqualStrings(":method: GET\n:path: /a/b?c=d\nx-custom: Some Value\ncontent-type: text/plain\nuser-agent: \nx-bin: \x00\xff\x10\n", s2);

    const bad = [_][]const u8{
        &.{0x00}, // no Base
        &.{ 0x01, 0x00 }, // a Required Insert Count
        &.{ 0x00, 0x01 }, // a Base
        &.{ 0x00, 0x00, 0x80 }, // dynamic indexed
        &.{ 0x00, 0x00, 0xff, 0x24 }, // static index 99
        &.{ 0x00, 0x00, 0x10 }, // post-base indexed
        &.{ 0x00, 0x00, 0x40, 0x00 }, // dynamic name reference
        &.{ 0x00, 0x00, 0x00 }, // post-base name reference
        &.{ 0x00, 0x00, 0x51, 0x05, 'a' }, // truncated value
        &.{ 0x00, 0x00, 0x51, 0x81, 0xff }, // bad Huffman (EOS padding)
        &.{ 0x00, 0x00, 0x27, 0x7f }, // name length runs out
    };
    for (bad) |b| try testing.expectError(error.DecompressionFailed, decodeToString(&dec, b));
}

test "field section size limit" {
    var dec = try Decoder.init(testing.allocator, .{ .max_field_section_size = 100 });
    defer dec.deinit();
    var buf: [512]u8 = undefined;
    var n: usize = 2;
    @memcpy(buf[0..2], &section_prefix);
    for (0..5) |_| n += try encodeField(buf[n..], "x-long-header", "a value of some length");
    try testing.expectError(error.FieldSectionTooLarge, decodeToString(&dec, buf[0..n]));
}

test "encodeStatus uses the static table" {
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try encodeStatus(&buf, 200));
    try testing.expectEqual(@as(u8, 0xc0 | 25), buf[0]);
    try testing.expectEqual(@as(usize, 1), try encodeStatus(&buf, 404));
    // 201 isn't in the table: a name reference to :status (index 24).
    const n = try encodeStatus(&buf, 201);
    try testing.expect(n > 1);
    try testing.expectEqual(@as(u8, 0x50 | 0x0f), buf[0]);
}
