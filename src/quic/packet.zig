//! QUIC packet framing (RFC 9000 §12, §16, §17, RFC 8999): variable-length
//! integers, long and short headers, packet number encoding, and the
//! packets a server builds without a connection (Version Negotiation,
//! Retry). I/O-free; packet protection is in protection.zig.
const std = @import("std");

/// QUIC version 1 (RFC 9000).
pub const version_1: u32 = 0x00000001;
/// Longest connection ID in QUIC version 1 (§17.2).
pub const max_cid_len = 20;
/// Smallest UDP payload a client's Initial may arrive in (§14.1).
pub const min_initial_datagram = 1200;
pub const max_varint: u64 = (1 << 62) - 1;

pub const Error = error{
    /// Not a decodable QUIC packet: dropped (§12.2, §17).
    Malformed,
};

// -- Variable-length integers (§16) ------------------------------------------

/// Bytes needed to encode `v` (at most max_varint).
pub fn varintLen(v: u64) usize {
    if (v < 1 << 6) return 1;
    if (v < 1 << 14) return 2;
    if (v < 1 << 30) return 4;
    std.debug.assert(v <= max_varint);
    return 8;
}

/// Writes `v` in its shortest form; `out` needs `varintLen(v)` bytes.
pub fn writeVarint(out: []u8, v: u64) usize {
    return writeVarintLen(out, v, varintLen(v));
}

/// Writes `v` in exactly `len` bytes (1, 2, 4 or 8), for length fields
/// reserved before their value is known.
pub fn writeVarintLen(out: []u8, v: u64, len: usize) usize {
    switch (len) {
        1 => out[0] = @intCast(v),
        2 => std.mem.writeInt(u16, out[0..2], @as(u16, @intCast(v)) | 0x4000, .big),
        4 => std.mem.writeInt(u32, out[0..4], @as(u32, @intCast(v)) | 0x8000_0000, .big),
        8 => std.mem.writeInt(u64, out[0..8], v | 0xc000_0000_0000_0000, .big),
        else => unreachable,
    }
    return len;
}

/// A cursor over received bytes. Every read fails with Malformed past the
/// end, so a parser never reads out of bounds.
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub inline fn left(self: *const Reader) usize {
        return self.data.len - self.pos;
    }

    pub fn varint(self: *Reader) Error!u64 {
        if (self.pos >= self.data.len) return error.Malformed;
        const first = self.data[self.pos];
        const len = @as(usize, 1) << @intCast(first >> 6);
        if (self.data.len - self.pos < len) return error.Malformed;
        var v: u64 = first & 0x3f;
        for (self.data[self.pos + 1 ..][0 .. len - 1]) |b| v = v << 8 | b;
        self.pos += len;
        return v;
    }

    pub fn byte(self: *Reader) Error!u8 {
        if (self.pos >= self.data.len) return error.Malformed;
        defer self.pos += 1;
        return self.data[self.pos];
    }

    pub fn int(self: *Reader, comptime T: type) Error!T {
        const size = @divExact(@bitSizeOf(T), 8);
        const b = try self.bytes(size);
        return std.mem.readInt(T, b[0..size], .big);
    }

    pub fn bytes(self: *Reader, n: u64) Error![]const u8 {
        if (n > self.left()) return error.Malformed;
        const len: usize = @intCast(n);
        defer self.pos += len;
        return self.data[self.pos..][0..len];
    }

    /// A varint length followed by that many bytes.
    pub fn vector(self: *Reader) Error![]const u8 {
        return self.bytes(try self.varint());
    }
};

/// A cursor over a buffer known to be large enough.
pub const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    pub inline fn written(self: *const Writer) []u8 {
        return self.buf[0..self.pos];
    }

    pub inline fn left(self: *const Writer) usize {
        return self.buf.len - self.pos;
    }

    pub fn varint(self: *Writer, v: u64) void {
        self.pos += writeVarint(self.buf[self.pos..], v);
    }

    pub fn byte(self: *Writer, b: u8) void {
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    pub fn int(self: *Writer, comptime T: type, v: T) void {
        const size = @divExact(@bitSizeOf(T), 8);
        std.mem.writeInt(T, self.buf[self.pos..][0..size], v, .big);
        self.pos += size;
    }

    pub fn bytes(self: *Writer, b: []const u8) void {
        @memcpy(self.buf[self.pos..][0..b.len], b);
        self.pos += b.len;
    }
};

// -- Headers (§17) -------------------------------------------------------------

pub const PacketType = enum(u8) {
    initial,
    zero_rtt,
    handshake,
    retry,
    one_rtt,
    /// A long header with a version other than 1 (RFC 8999): only the
    /// connection IDs are known, enough to answer with Version Negotiation.
    unsupported_version,
};

pub const Header = struct {
    type: PacketType,
    version: u32 = version_1,
    dcid: []const u8,
    scid: []const u8 = &.{},
    /// Initial packets only.
    token: []const u8 = &.{},
    /// Offset of the (protected) packet number from the packet's start.
    pn_offset: usize = 0,
    /// Length of this packet within the datagram: up to the end of its
    /// Length field's extent for long headers, the rest of the datagram
    /// for short ones.
    len: usize,
};

const long_form: u8 = 0x80;
const fixed_bit: u8 = 0x40;

/// Parses the header of the first packet in `data` (a datagram or what is
/// left of it after coalesced packets). `short_dcid_len` is the length of
/// the connection IDs this endpoint issues, which short headers don't
/// encode. The packet number is still protected, so only the fields
/// before it are read.
pub fn parseHeader(data: []const u8, short_dcid_len: usize) Error!Header {
    var r: Reader = .{ .data = data };
    const first = try r.byte();
    if (first & long_form == 0) {
        // Short header (§17.3.1).
        if (first & fixed_bit == 0) return error.Malformed;
        const dcid = try r.bytes(short_dcid_len);
        return .{ .type = .one_rtt, .dcid = dcid, .pn_offset = r.pos, .len = data.len };
    }
    const version = try r.int(u32);
    // RFC 8999 §5.1: connection IDs of up to 255 bytes in other versions.
    const dcid = try r.bytes(try r.byte());
    const scid = try r.bytes(try r.byte());
    if (version != version_1) {
        // Version Negotiation (version 0) is only ever sent by servers.
        if (version == 0) return error.Malformed;
        return .{ .type = .unsupported_version, .version = version, .dcid = dcid, .scid = scid, .len = data.len };
    }
    if (dcid.len > max_cid_len or scid.len > max_cid_len) return error.Malformed;
    if (first & fixed_bit == 0) return error.Malformed;
    const ty: PacketType = switch ((first >> 4) & 3) {
        0 => .initial,
        1 => .zero_rtt,
        2 => .handshake,
        else => .retry,
    };
    // Servers never receive Retry; it has no Length field.
    if (ty == .retry) return error.Malformed;
    var h: Header = .{ .type = ty, .dcid = dcid, .scid = scid, .len = 0 };
    if (ty == .initial) h.token = try r.vector();
    const length = try r.varint();
    if (length > r.left()) return error.Malformed;
    h.pn_offset = r.pos;
    h.len = r.pos + @as(usize, @intCast(length));
    return h;
}

/// The first byte's type bits for a long header packet.
pub fn longTypeBits(ty: PacketType) u8 {
    return @as(u8, switch (ty) {
        .initial => 0,
        .zero_rtt => 1,
        .handshake => 2,
        .retry => 3,
        else => unreachable,
    }) << 4;
}

// -- Packet numbers (§17.1, Appendix A) ------------------------------------

/// Bytes to encode `pn` so the peer can decode it, given the largest
/// packet number it acknowledged (Appendix A.2).
pub fn pnLen(pn: u64, largest_acked: ?u64) usize {
    const unacked = if (largest_acked) |la| pn - la else pn + 1;
    // Twice the range, so the window covers it on both sides.
    const bits = 64 - @clz(unacked) + 1;
    return @min(4, std.math.divCeil(usize, bits, 8) catch unreachable);
}

/// Recovers a full packet number from its `len`-byte truncation, given the
/// largest packet number received so far in the space (Appendix A.3).
pub fn decodePn(largest: ?u64, truncated: u64, len: usize) u64 {
    const expected = if (largest) |l| l + 1 else 0;
    const win: u64 = @as(u64, 1) << @intCast(len * 8);
    const hwin = win / 2;
    const mask = win - 1;
    const candidate = (expected & ~mask) | truncated;
    if (candidate + hwin <= expected and candidate < (1 << 62) - win) return candidate + win;
    if (candidate > expected + hwin and candidate >= win) return candidate - win;
    return candidate;
}

// -- Packets sent without a connection ---------------------------------------

/// A Version Negotiation packet (§17.2.1) answering a long header with an
/// unsupported version: the connection IDs swapped, our versions listed.
/// `out` needs 7 + both IDs + 8 bytes. `unused` fills the first byte's
/// free bits.
pub fn writeVersionNegotiation(out: []u8, h: Header, unused: u8) usize {
    var w: Writer = .{ .buf = out };
    w.byte(long_form | (unused & 0x7f));
    w.int(u32, 0);
    w.byte(@intCast(h.scid.len));
    w.bytes(h.scid);
    w.byte(@intCast(h.dcid.len));
    w.bytes(h.dcid);
    w.int(u32, version_1);
    // A reserved version (0x?a?a?a?a, §15) keeps clients' parsers honest.
    w.int(u32, 0x1a2a3a4a);
    return w.pos;
}

// -- Tests ------------------------------------------------------------------

const testing = std.testing;

test "varints: RFC 9000 Appendix A.1 examples and round trips" {
    const cases = [_]struct { bytes: []const u8, value: u64 }{
        .{ .bytes = &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, .value = 151288809941952652 },
        .{ .bytes = &.{ 0x9d, 0x7f, 0x3e, 0x7d }, .value = 494878333 },
        .{ .bytes = &.{ 0x7b, 0xbd }, .value = 15293 },
        .{ .bytes = &.{0x25}, .value = 37 },
        .{ .bytes = &.{ 0x40, 0x25 }, .value = 37 },
    };
    for (cases) |c| {
        var r: Reader = .{ .data = c.bytes };
        try testing.expectEqual(c.value, try r.varint());
        try testing.expectEqual(c.bytes.len, r.pos);
    }
    for ([_]u64{ 0, 63, 64, 16383, 16384, (1 << 30) - 1, 1 << 30, max_varint }) |v| {
        var buf: [8]u8 = undefined;
        const n = writeVarint(&buf, v);
        try testing.expectEqual(varintLen(v), n);
        var r: Reader = .{ .data = buf[0..n] };
        try testing.expectEqual(v, try r.varint());
        // Truncated encodings fail.
        if (n > 1) {
            var short: Reader = .{ .data = buf[0 .. n - 1] };
            try testing.expectError(error.Malformed, short.varint());
        }
    }
}

test "packet numbers: RFC 9000 Appendix A.2 and A.3 examples" {
    try testing.expectEqual(@as(u64, 0xa82f9b32), decodePn(0xa82f30ea, 0x9b32, 2));
    // A.2: 0xac5c02 with 0xabe8b3 acknowledged needs 16 bits; 0xace8fe needs 24.
    try testing.expectEqual(@as(usize, 2), pnLen(0xac5c02, 0xabe8b3));
    try testing.expectEqual(@as(usize, 3), pnLen(0xace8fe, 0xabe8b3));
    try testing.expectEqual(@as(usize, 1), pnLen(0, null));
    // Exhaustive-ish: any pn within half a window of the next expected
    // one decodes from its truncation.
    var prng = std.Random.DefaultPrng.init(1);
    const random = prng.random();
    for (0..10000) |_| {
        const largest = random.int(u64) & ((1 << 40) - 1);
        const len = random.intRangeAtMost(usize, 1, 4);
        const hwin = @as(u64, 1) << @intCast(len * 8 - 1);
        const pn = largest + 1 + random.uintLessThan(u64, hwin) -% (hwin / 2);
        if (pn > largest + hwin or pn + hwin <= largest) continue;
        const mask = (@as(u64, 1) << @intCast(len * 8)) - 1;
        try testing.expectEqual(pn, decodePn(largest, pn & mask, len));
    }
}

test "headers: Initial, Handshake, short, other versions, malformed" {
    const initial = key_hex("c300000001088394c8f03e5157080000449e00000002");
    // The Length (0x449e = 1182) runs past this header-only sample.
    try testing.expectError(error.Malformed, parseHeader(&initial, 8));
    var full: [18 + 1182]u8 = undefined;
    @memcpy(full[0..22], &initial);
    const h = try parseHeader(&full, 8);
    try testing.expectEqual(PacketType.initial, h.type);
    try testing.expectEqualSlices(u8, &key_hex("8394c8f03e515708"), h.dcid);
    try testing.expectEqual(@as(usize, 0), h.scid.len);
    try testing.expectEqual(@as(usize, 0), h.token.len);
    try testing.expectEqual(@as(usize, 18), h.pn_offset);
    try testing.expectEqual(full.len, h.len);

    const short = [_]u8{ 0x41, 1, 2, 3, 4, 0xaa, 0xbb };
    const s = try parseHeader(&short, 4);
    try testing.expectEqual(PacketType.one_rtt, s.type);
    try testing.expectEqual(@as(usize, 5), s.pn_offset);
    try testing.expectError(error.Malformed, parseHeader(&[_]u8{ 0x01, 1, 2, 3, 4, 5 }, 4)); // fixed bit clear

    const other = [_]u8{ 0xc0, 0xff, 0x00, 0x00, 0x1d, 2, 9, 9, 1, 7 };
    const o = try parseHeader(&other, 8);
    try testing.expectEqual(PacketType.unsupported_version, o.type);
    var vn: [64]u8 = undefined;
    const n = writeVersionNegotiation(&vn, o, 0x15);
    try testing.expectEqualSlices(u8, &.{ 0x95, 0, 0, 0, 0, 1, 7, 2, 9, 9, 0, 0, 0, 1, 0x1a, 0x2a, 0x3a, 0x4a }, vn[0..n]);

    // A connection ID longer than 20 bytes in version 1.
    var long_cid: [7 + 21]u8 = @splat(0);
    long_cid[0] = 0xc0;
    long_cid[4] = 1;
    long_cid[5] = 21;
    try testing.expectError(error.Malformed, parseHeader(&long_cid, 8));
}

fn key_hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
