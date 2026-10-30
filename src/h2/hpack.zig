//! HPACK (RFC 7541): header compression for HTTP/2. I/O-free: the decoder
//! takes a complete header block and hands each field to a sink; the
//! encoder writes fields into a caller-supplied buffer.
//!
//! Limits are strict. The dynamic table never grows past the size this
//! side advertised, a size update above it is an error, header list size is
//! bounded (the decoder keeps decoding so that its table stays in sync with
//! the peer's, then reports the overflow), and Huffman padding is checked
//! as RFC 7541 §5.2 demands.
const std = @import("std");

pub const Error = error{
    /// A malformed block (RFC 9113 §4.3: a connection error of type
    /// COMPRESSION_ERROR).
    CompressionError,
    /// The block decoded fine, and the dynamic table is in sync, but the
    /// header list exceeds the limit (RFC 9113 §6.5.2). The sink saw every
    /// field up to the limit.
    HeaderListTooLarge,
};

/// Default SETTINGS_HEADER_TABLE_SIZE (RFC 9113 §6.5.2).
pub const default_table_size = 4096;
/// RFC 7541 §4.1: per-entry overhead in size accounting.
pub const entry_overhead = 32;

pub const Limits = struct {
    /// What this side allows the peer's encoder to use (what we advertise
    /// as SETTINGS_HEADER_TABLE_SIZE). Decoder memory is reserved for it.
    max_table_size: u32 = default_table_size,
    /// Sum over fields of name + value + 32 (SETTINGS_MAX_HEADER_LIST_SIZE).
    max_header_list_size: u32 = 16 * 1024,
    /// Longest single name or value, decoded. Bounds the scratch space.
    max_field_len: u32 = 8 * 1024,
};

// ---------------------------------------------------------------------------
// Static table (RFC 7541 Appendix A)

pub const Field = struct { name: []const u8, value: []const u8 };

pub const static_table = [_]Field{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

comptime {
    std.debug.assert(static_table.len == 61);
}

// ---------------------------------------------------------------------------
// Integer coding (RFC 7541 §5.1)

/// Writes `value` with an N-bit prefix whose high bits are `first` (the
/// representation's pattern bits). Returns the bytes written.
pub fn encodeInt(out: []u8, first: u8, comptime prefix_bits: u4, value: usize) error{NoSpace}!usize {
    const max: usize = (@as(usize, 1) << prefix_bits) - 1;
    if (out.len == 0) return error.NoSpace;
    if (value < max) {
        out[0] = first | @as(u8, @intCast(value));
        return 1;
    }
    out[0] = first | @as(u8, @intCast(max));
    var rest = value - max;
    var n: usize = 1;
    while (rest >= 128) : (rest >>= 7) {
        if (n >= out.len) return error.NoSpace;
        out[n] = @as(u8, @intCast(rest & 0x7f)) | 0x80;
        n += 1;
    }
    if (n >= out.len) return error.NoSpace;
    out[n] = @intCast(rest);
    return n + 1;
}

pub const Int = struct { value: u32, len: usize };

/// Reads an N-bit prefixed integer. Values are limited to 32 bits and the
/// continuation bytes to the minimum needed, so a decoder can't be made to
/// spin or overflow.
pub fn decodeInt(data: []const u8, comptime prefix_bits: u4) Error!Int {
    if (data.len == 0) return error.CompressionError;
    const max: u32 = (@as(u32, 1) << prefix_bits) - 1;
    var value: u32 = data[0] & @as(u8, @intCast(max));
    if (value < max) return .{ .value = value, .len = 1 };
    var shift: u5 = 0;
    var i: usize = 1;
    while (true) : (i += 1) {
        if (i >= data.len) return error.CompressionError;
        const b = data[i];
        const part: u32 = b & 0x7f;
        if (shift == 28 and part > 0xf) return error.CompressionError;
        value = std.math.add(u32, value, part << shift) catch return error.CompressionError;
        if (b & 0x80 == 0) return .{ .value = value, .len = i + 1 };
        // A fifth continuation byte can't fit in 32 bits.
        if (shift == 28) return error.CompressionError;
        shift += 7;
    }
}

// ---------------------------------------------------------------------------
// Huffman coding (RFC 7541 Appendix B)

const Code = struct { code: u32, len: u8 };

/// The code table, as printed in Appendix B.
pub const huffman_codes = [257]Code{
    .{ .code = 0x1ff8, .len = 13 },     .{ .code = 0x7fffd8, .len = 23 },   .{ .code = 0xfffffe2, .len = 28 },  .{ .code = 0xfffffe3, .len = 28 },
    .{ .code = 0xfffffe4, .len = 28 },  .{ .code = 0xfffffe5, .len = 28 },  .{ .code = 0xfffffe6, .len = 28 },  .{ .code = 0xfffffe7, .len = 28 },
    .{ .code = 0xfffffe8, .len = 28 },  .{ .code = 0xffffea, .len = 24 },   .{ .code = 0x3ffffffc, .len = 30 }, .{ .code = 0xfffffe9, .len = 28 },
    .{ .code = 0xfffffea, .len = 28 },  .{ .code = 0x3ffffffd, .len = 30 }, .{ .code = 0xfffffeb, .len = 28 },  .{ .code = 0xfffffec, .len = 28 },
    .{ .code = 0xfffffed, .len = 28 },  .{ .code = 0xfffffee, .len = 28 },  .{ .code = 0xfffffef, .len = 28 },  .{ .code = 0xffffff0, .len = 28 },
    .{ .code = 0xffffff1, .len = 28 },  .{ .code = 0xffffff2, .len = 28 },  .{ .code = 0x3ffffffe, .len = 30 }, .{ .code = 0xffffff3, .len = 28 },
    .{ .code = 0xffffff4, .len = 28 },  .{ .code = 0xffffff5, .len = 28 },  .{ .code = 0xffffff6, .len = 28 },  .{ .code = 0xffffff7, .len = 28 },
    .{ .code = 0xffffff8, .len = 28 },  .{ .code = 0xffffff9, .len = 28 },  .{ .code = 0xffffffa, .len = 28 },  .{ .code = 0xffffffb, .len = 28 },
    .{ .code = 0x14, .len = 6 },        .{ .code = 0x3f8, .len = 10 },      .{ .code = 0x3f9, .len = 10 },      .{ .code = 0xffa, .len = 12 },
    .{ .code = 0x1ff9, .len = 13 },     .{ .code = 0x15, .len = 6 },        .{ .code = 0xf8, .len = 8 },        .{ .code = 0x7fa, .len = 11 },
    .{ .code = 0x3fa, .len = 10 },      .{ .code = 0x3fb, .len = 10 },      .{ .code = 0xf9, .len = 8 },        .{ .code = 0x7fb, .len = 11 },
    .{ .code = 0xfa, .len = 8 },        .{ .code = 0x16, .len = 6 },        .{ .code = 0x17, .len = 6 },        .{ .code = 0x18, .len = 6 },
    .{ .code = 0x0, .len = 5 },         .{ .code = 0x1, .len = 5 },         .{ .code = 0x2, .len = 5 },         .{ .code = 0x19, .len = 6 },
    .{ .code = 0x1a, .len = 6 },        .{ .code = 0x1b, .len = 6 },        .{ .code = 0x1c, .len = 6 },        .{ .code = 0x1d, .len = 6 },
    .{ .code = 0x1e, .len = 6 },        .{ .code = 0x1f, .len = 6 },        .{ .code = 0x5c, .len = 7 },        .{ .code = 0xfb, .len = 8 },
    .{ .code = 0x7ffc, .len = 15 },     .{ .code = 0x20, .len = 6 },        .{ .code = 0xffb, .len = 12 },      .{ .code = 0x3fc, .len = 10 },
    .{ .code = 0x1ffa, .len = 13 },     .{ .code = 0x21, .len = 6 },        .{ .code = 0x5d, .len = 7 },        .{ .code = 0x5e, .len = 7 },
    .{ .code = 0x5f, .len = 7 },        .{ .code = 0x60, .len = 7 },        .{ .code = 0x61, .len = 7 },        .{ .code = 0x62, .len = 7 },
    .{ .code = 0x63, .len = 7 },        .{ .code = 0x64, .len = 7 },        .{ .code = 0x65, .len = 7 },        .{ .code = 0x66, .len = 7 },
    .{ .code = 0x67, .len = 7 },        .{ .code = 0x68, .len = 7 },        .{ .code = 0x69, .len = 7 },        .{ .code = 0x6a, .len = 7 },
    .{ .code = 0x6b, .len = 7 },        .{ .code = 0x6c, .len = 7 },        .{ .code = 0x6d, .len = 7 },        .{ .code = 0x6e, .len = 7 },
    .{ .code = 0x6f, .len = 7 },        .{ .code = 0x70, .len = 7 },        .{ .code = 0x71, .len = 7 },        .{ .code = 0x72, .len = 7 },
    .{ .code = 0xfc, .len = 8 },        .{ .code = 0x73, .len = 7 },        .{ .code = 0xfd, .len = 8 },        .{ .code = 0x1ffb, .len = 13 },
    .{ .code = 0x7fff0, .len = 19 },    .{ .code = 0x1ffc, .len = 13 },     .{ .code = 0x3ffc, .len = 14 },     .{ .code = 0x22, .len = 6 },
    .{ .code = 0x7ffd, .len = 15 },     .{ .code = 0x3, .len = 5 },         .{ .code = 0x23, .len = 6 },        .{ .code = 0x4, .len = 5 },
    .{ .code = 0x24, .len = 6 },        .{ .code = 0x5, .len = 5 },         .{ .code = 0x25, .len = 6 },        .{ .code = 0x26, .len = 6 },
    .{ .code = 0x27, .len = 6 },        .{ .code = 0x6, .len = 5 },         .{ .code = 0x74, .len = 7 },        .{ .code = 0x75, .len = 7 },
    .{ .code = 0x28, .len = 6 },        .{ .code = 0x29, .len = 6 },        .{ .code = 0x2a, .len = 6 },        .{ .code = 0x7, .len = 5 },
    .{ .code = 0x2b, .len = 6 },        .{ .code = 0x76, .len = 7 },        .{ .code = 0x2c, .len = 6 },        .{ .code = 0x8, .len = 5 },
    .{ .code = 0x9, .len = 5 },         .{ .code = 0x2d, .len = 6 },        .{ .code = 0x77, .len = 7 },        .{ .code = 0x78, .len = 7 },
    .{ .code = 0x79, .len = 7 },        .{ .code = 0x7a, .len = 7 },        .{ .code = 0x7b, .len = 7 },        .{ .code = 0x7ffe, .len = 15 },
    .{ .code = 0x7fc, .len = 11 },      .{ .code = 0x3ffd, .len = 14 },     .{ .code = 0x1ffd, .len = 13 },     .{ .code = 0xffffffc, .len = 28 },
    .{ .code = 0xfffe6, .len = 20 },    .{ .code = 0x3fffd2, .len = 22 },   .{ .code = 0xfffe7, .len = 20 },    .{ .code = 0xfffe8, .len = 20 },
    .{ .code = 0x3fffd3, .len = 22 },   .{ .code = 0x3fffd4, .len = 22 },   .{ .code = 0x3fffd5, .len = 22 },   .{ .code = 0x7fffd9, .len = 23 },
    .{ .code = 0x3fffd6, .len = 22 },   .{ .code = 0x7fffda, .len = 23 },   .{ .code = 0x7fffdb, .len = 23 },   .{ .code = 0x7fffdc, .len = 23 },
    .{ .code = 0x7fffdd, .len = 23 },   .{ .code = 0x7fffde, .len = 23 },   .{ .code = 0xffffeb, .len = 24 },   .{ .code = 0x7fffdf, .len = 23 },
    .{ .code = 0xffffec, .len = 24 },   .{ .code = 0xffffed, .len = 24 },   .{ .code = 0x3fffd7, .len = 22 },   .{ .code = 0x7fffe0, .len = 23 },
    .{ .code = 0xffffee, .len = 24 },   .{ .code = 0x7fffe1, .len = 23 },   .{ .code = 0x7fffe2, .len = 23 },   .{ .code = 0x7fffe3, .len = 23 },
    .{ .code = 0x7fffe4, .len = 23 },   .{ .code = 0x1fffdc, .len = 21 },   .{ .code = 0x3fffd8, .len = 22 },   .{ .code = 0x7fffe5, .len = 23 },
    .{ .code = 0x3fffd9, .len = 22 },   .{ .code = 0x7fffe6, .len = 23 },   .{ .code = 0x7fffe7, .len = 23 },   .{ .code = 0xffffef, .len = 24 },
    .{ .code = 0x3fffda, .len = 22 },   .{ .code = 0x1fffdd, .len = 21 },   .{ .code = 0xfffe9, .len = 20 },    .{ .code = 0x3fffdb, .len = 22 },
    .{ .code = 0x3fffdc, .len = 22 },   .{ .code = 0x7fffe8, .len = 23 },   .{ .code = 0x7fffe9, .len = 23 },   .{ .code = 0x1fffde, .len = 21 },
    .{ .code = 0x7fffea, .len = 23 },   .{ .code = 0x3fffdd, .len = 22 },   .{ .code = 0x3fffde, .len = 22 },   .{ .code = 0xfffff0, .len = 24 },
    .{ .code = 0x1fffdf, .len = 21 },   .{ .code = 0x3fffdf, .len = 22 },   .{ .code = 0x7fffeb, .len = 23 },   .{ .code = 0x7fffec, .len = 23 },
    .{ .code = 0x1fffe0, .len = 21 },   .{ .code = 0x1fffe1, .len = 21 },   .{ .code = 0x3fffe0, .len = 22 },   .{ .code = 0x1fffe2, .len = 21 },
    .{ .code = 0x7fffed, .len = 23 },   .{ .code = 0x3fffe1, .len = 22 },   .{ .code = 0x7fffee, .len = 23 },   .{ .code = 0x7fffef, .len = 23 },
    .{ .code = 0xfffea, .len = 20 },    .{ .code = 0x3fffe2, .len = 22 },   .{ .code = 0x3fffe3, .len = 22 },   .{ .code = 0x3fffe4, .len = 22 },
    .{ .code = 0x7ffff0, .len = 23 },   .{ .code = 0x3fffe5, .len = 22 },   .{ .code = 0x3fffe6, .len = 22 },   .{ .code = 0x7ffff1, .len = 23 },
    .{ .code = 0x3ffffe0, .len = 26 },  .{ .code = 0x3ffffe1, .len = 26 },  .{ .code = 0xfffeb, .len = 20 },    .{ .code = 0x7fff1, .len = 19 },
    .{ .code = 0x3fffe7, .len = 22 },   .{ .code = 0x7ffff2, .len = 23 },   .{ .code = 0x3fffe8, .len = 22 },   .{ .code = 0x1ffffec, .len = 25 },
    .{ .code = 0x3ffffe2, .len = 26 },  .{ .code = 0x3ffffe3, .len = 26 },  .{ .code = 0x3ffffe4, .len = 26 },  .{ .code = 0x7ffffde, .len = 27 },
    .{ .code = 0x7ffffdf, .len = 27 },  .{ .code = 0x3ffffe5, .len = 26 },  .{ .code = 0xfffff1, .len = 24 },   .{ .code = 0x1ffffed, .len = 25 },
    .{ .code = 0x7fff2, .len = 19 },    .{ .code = 0x1fffe3, .len = 21 },   .{ .code = 0x3ffffe6, .len = 26 },  .{ .code = 0x7ffffe0, .len = 27 },
    .{ .code = 0x7ffffe1, .len = 27 },  .{ .code = 0x3ffffe7, .len = 26 },  .{ .code = 0x7ffffe2, .len = 27 },  .{ .code = 0xfffff2, .len = 24 },
    .{ .code = 0x1fffe4, .len = 21 },   .{ .code = 0x1fffe5, .len = 21 },   .{ .code = 0x3ffffe8, .len = 26 },  .{ .code = 0x3ffffe9, .len = 26 },
    .{ .code = 0xffffffd, .len = 28 },  .{ .code = 0x7ffffe3, .len = 27 },  .{ .code = 0x7ffffe4, .len = 27 },  .{ .code = 0x7ffffe5, .len = 27 },
    .{ .code = 0xfffec, .len = 20 },    .{ .code = 0xfffff3, .len = 24 },   .{ .code = 0xfffed, .len = 20 },    .{ .code = 0x1fffe6, .len = 21 },
    .{ .code = 0x3fffe9, .len = 22 },   .{ .code = 0x1fffe7, .len = 21 },   .{ .code = 0x1fffe8, .len = 21 },   .{ .code = 0x7ffff3, .len = 23 },
    .{ .code = 0x3fffea, .len = 22 },   .{ .code = 0x3fffeb, .len = 22 },   .{ .code = 0x1ffffee, .len = 25 },  .{ .code = 0x1ffffef, .len = 25 },
    .{ .code = 0xfffff4, .len = 24 },   .{ .code = 0xfffff5, .len = 24 },   .{ .code = 0x3ffffea, .len = 26 },  .{ .code = 0x7ffff4, .len = 23 },
    .{ .code = 0x3ffffeb, .len = 26 },  .{ .code = 0x7ffffe6, .len = 27 },  .{ .code = 0x3ffffec, .len = 26 },  .{ .code = 0x3ffffed, .len = 26 },
    .{ .code = 0x7ffffe7, .len = 27 },  .{ .code = 0x7ffffe8, .len = 27 },  .{ .code = 0x7ffffe9, .len = 27 },  .{ .code = 0x7ffffea, .len = 27 },
    .{ .code = 0x7ffffeb, .len = 27 },  .{ .code = 0xffffffe, .len = 28 },  .{ .code = 0x7ffffec, .len = 27 },  .{ .code = 0x7ffffed, .len = 27 },
    .{ .code = 0x7ffffee, .len = 27 },  .{ .code = 0x7ffffef, .len = 27 },  .{ .code = 0x7fffff0, .len = 27 },  .{ .code = 0x3ffffee, .len = 26 },
    .{ .code = 0x3fffffff, .len = 30 },
};

const eos = 256;

/// Upper bound on the Huffman-encoded size of `s`.
pub fn huffmanEncodedLen(s: []const u8) usize {
    var bits: usize = 0;
    for (s) |b| bits += huffman_codes[b].len;
    return (bits + 7) / 8;
}

/// Writes the Huffman encoding of `s`, padded with the EOS prefix. The
/// caller sizes `out` with huffmanEncodedLen.
pub fn huffmanEncode(out: []u8, s: []const u8) usize {
    var acc: u64 = 0;
    var nbits: u6 = 0;
    var n: usize = 0;
    for (s) |b| {
        const c = huffman_codes[b];
        acc = (acc << @intCast(c.len)) | c.code;
        nbits += @intCast(c.len);
        while (nbits >= 8) {
            nbits -= 8;
            out[n] = @truncate(acc >> nbits);
            n += 1;
        }
    }
    if (nbits > 0) {
        // Pad with the high bits of EOS (all ones).
        const pad: u6 = 8 - nbits;
        acc = (acc << pad) | ((@as(u64, 1) << pad) - 1);
        out[n] = @truncate(acc);
        n += 1;
    }
    return n;
}

/// Nibble-driven decoder (the approach nghttp2 uses): the state is a node
/// of the code tree, and each 4-bit input moves to another node, possibly
/// emitting one symbol (the shortest code is 5 bits, so never two). Flags
/// say whether the string may end in this state (the bits since the last
/// symbol are a prefix of EOS, at most 7 of them) and whether it is invalid
/// (EOS itself, or 8 or more padding bits).
const Transition = packed struct(u16) {
    next: u8,
    sym: u8,
};

const Flags = packed struct(u8) {
    emit: bool = false,
    accept: bool = false,
    fail: bool = false,
    _: u5 = 0,
};

const HuffmanTables = struct {
    trans: [256][16]Transition,
    flags: [256][16]Flags,
};

const huffman = buildHuffmanTables();

fn buildHuffmanTables() HuffmanTables {
    @setEvalBranchQuota(400_000);
    // Code tree: internal nodes only, numbered from the root (0). A child
    // is either an internal node or a leaf (symbol).
    const Child = union(enum) { none, node: u8, leaf: u16 };
    var children: [256][2]Child = @splat(.{ .none, .none });
    var node_count: usize = 1;
    for (huffman_codes, 0..) |c, sym| {
        var node: usize = 0;
        var i: usize = c.len;
        while (i > 1) : (i -= 1) {
            const bit = (c.code >> @intCast(i - 1)) & 1;
            switch (children[node][bit]) {
                .none => {
                    children[node][bit] = .{ .node = @intCast(node_count) };
                    node = node_count;
                    node_count += 1;
                },
                .node => |n| node = n,
                .leaf => unreachable,
            }
        }
        const bit = c.code & 1;
        if (children[node][bit] != .none) unreachable;
        children[node][bit] = .{ .leaf = @intCast(sym) };
    }
    if (node_count != 256) unreachable;
    // Depth of each node from the root, and whether its path is all ones,
    // for the padding rule.
    var depth: [256]u8 = @splat(0);
    var ones: [256]bool = @splat(false);
    ones[0] = true;
    for (0..256) |n| {
        for (0..2) |bit| {
            if (children[n][bit] == .node) {
                const m = children[n][bit].node;
                depth[m] = depth[n] + 1;
                ones[m] = ones[n] and bit == 1;
            }
        }
    }
    var t: HuffmanTables = undefined;
    for (0..256) |state| {
        for (0..16) |nibble| {
            var node: usize = state;
            var sym: u8 = 0;
            var flags: Flags = .{};
            var b: usize = 4;
            while (b > 0) : (b -= 1) {
                const bit = (nibble >> @intCast(b - 1)) & 1;
                switch (children[node][bit]) {
                    .none => unreachable,
                    .node => |n| node = n,
                    .leaf => |s| {
                        if (s == eos) {
                            flags.fail = true;
                        } else {
                            if (flags.emit) unreachable; // two symbols per nibble
                            flags.emit = true;
                            sym = @intCast(s);
                        }
                        node = 0;
                    },
                }
            }
            flags.accept = ones[node] and depth[node] <= 7;
            t.trans[state][nibble] = .{ .next = @intCast(node), .sym = sym };
            t.flags[state][nibble] = flags;
        }
    }
    return t;
}

/// Decodes `in` into `out`, returning the decoded length. Fails on EOS in
/// the string, on padding longer than 7 bits, on padding that isn't the
/// high bits of EOS, and when `out` is too small.
pub fn huffmanDecode(out: []u8, in: []const u8) Error!usize {
    var state: u8 = 0;
    var accept = true;
    var n: usize = 0;
    for (in) |byte| {
        inline for ([2]u8{ byte >> 4, byte & 0xf }) |nibble| {
            const f = huffman.flags[state][nibble];
            const tr = huffman.trans[state][nibble];
            if (f.fail) return error.CompressionError;
            if (f.emit) {
                if (n >= out.len) return error.CompressionError;
                out[n] = tr.sym;
                n += 1;
            }
            state = tr.next;
            accept = f.accept;
        }
    }
    if (!accept) return error.CompressionError;
    return n;
}

// ---------------------------------------------------------------------------
// Dynamic table (RFC 7541 §2.3.2, §4)

/// Entries live in one byte buffer, appended at the end and evicted from
/// the start, so the live bytes are contiguous and the buffer is compacted
/// when the end is reached. No allocation after init.
pub const DynamicTable = struct {
    const Self = @This();

    const Entry = struct {
        name_off: u32,
        name_len: u32,
        value_len: u32,
    };

    allocator: std.mem.Allocator,
    bytes: []u8,
    /// Append position.
    end: usize = 0,
    entries: []Entry,
    /// Ring: `head` is the oldest entry.
    head: usize = 0,
    count: usize = 0,
    /// Sum of entry sizes (name + value + 32).
    size: u32 = 0,
    /// Current maximum, at most `bytes.len`.
    max_size: u32,

    /// `cap` bounds `max_size` for the table's lifetime.
    pub fn init(allocator: std.mem.Allocator, cap: u32) !Self {
        const bytes = try allocator.alloc(u8, cap);
        errdefer allocator.free(bytes);
        const entries = try allocator.alloc(Entry, cap / entry_overhead + 1);
        return .{
            .allocator = allocator,
            .bytes = bytes,
            .entries = entries,
            .max_size = @min(cap, default_table_size),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.entries);
    }

    pub fn capacity(self: *const Self) u32 {
        return @intCast(self.bytes.len);
    }

    /// Entry `i`, counted from the newest (1-based, as in the address space
    /// after the static table).
    pub fn get(self: *const Self, i: usize) ?Field {
        if (i == 0 or i > self.count) return null;
        const e = self.entries[(self.head + self.count - i) % self.entries.len];
        return .{
            .name = self.bytes[e.name_off..][0..e.name_len],
            .value = self.bytes[e.name_off + e.name_len ..][0..e.value_len],
        };
    }

    fn entrySize(name: []const u8, value: []const u8) u32 {
        return @intCast(name.len + value.len + entry_overhead);
    }

    /// Evicts the oldest entries until `needed` bytes fit under max_size.
    fn evictFor(self: *Self, needed: u32) void {
        while (self.count > 0 and self.size + needed > self.max_size) {
            const e = self.entries[self.head];
            self.size -= e.name_len + e.value_len + entry_overhead;
            self.head = (self.head + 1) % self.entries.len;
            self.count -= 1;
        }
        if (self.count == 0) self.end = 0;
    }

    /// Adds an entry (RFC 7541 §4.4): older entries are evicted to make
    /// room, and an entry larger than the whole table just empties it.
    pub fn add(self: *Self, name: []const u8, value: []const u8) void {
        const needed = entrySize(name, value);
        self.evictFor(needed);
        if (needed > self.max_size) return;
        const str_len = name.len + value.len;
        if (self.end + str_len > self.bytes.len) self.compact();
        const off = self.end;
        @memcpy(self.bytes[off..][0..name.len], name);
        @memcpy(self.bytes[off + name.len ..][0..value.len], value);
        self.end += str_len;
        self.entries[(self.head + self.count) % self.entries.len] = .{
            .name_off = @intCast(off),
            .name_len = @intCast(name.len),
            .value_len = @intCast(value.len),
        };
        self.count += 1;
        self.size += needed;
    }

    fn compact(self: *Self) void {
        if (self.count == 0) {
            self.end = 0;
            return;
        }
        const first = self.entries[self.head].name_off;
        const live = self.end - first;
        std.mem.copyForwards(u8, self.bytes[0..live], self.bytes[first..self.end]);
        for (0..self.count) |i| {
            self.entries[(self.head + i) % self.entries.len].name_off -= first;
        }
        self.end = live;
    }

    /// Changes the maximum size (a size update, or SETTINGS), evicting as
    /// needed. `n` must not exceed the capacity.
    pub fn setMaxSize(self: *Self, n: u32) void {
        std.debug.assert(n <= self.bytes.len);
        self.max_size = n;
        self.evictFor(0);
    }

    /// Searches newest to oldest. Returns the 1-based dynamic index of a
    /// full match, and failing that of a name match.
    pub fn find(self: *const Self, name: []const u8, value: []const u8) struct { full: ?usize, name: ?usize } {
        var name_match: ?usize = null;
        var i: usize = 1;
        while (i <= self.count) : (i += 1) {
            const f = self.get(i).?;
            if (f.name.len != name.len or !std.mem.eql(u8, f.name, name)) continue;
            if (f.value.len == value.len and std.mem.eql(u8, f.value, value)) return .{ .full = i, .name = i };
            if (name_match == null) name_match = i;
        }
        return .{ .full = null, .name = name_match };
    }
};

// ---------------------------------------------------------------------------
// Decoder (RFC 7541 §3, §6)

pub const Decoder = struct {
    const Self = @This();

    table: DynamicTable,
    limits: Limits,
    /// Decoded name then value of the field being read (`scratchLen`
    /// bytes): the decoder's own, or lent for one call (`decodeWith`).
    scratch: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) !Self {
        var self = try initShared(allocator, limits);
        errdefer self.deinit();
        self.scratch = try allocator.alloc(u8, scratchLen(limits));
        return self;
    }

    /// A decoder without scratch space of its own, for `decodeWith`: a
    /// worker's connections share one (it is only used inside a call).
    pub fn initShared(allocator: std.mem.Allocator, limits: Limits) !Self {
        const table = try DynamicTable.init(allocator, limits.max_table_size);
        return .{ .table = table, .limits = limits, .scratch = &.{}, .allocator = allocator };
    }

    /// Scratch space a decoder with these limits needs.
    pub fn scratchLen(limits: Limits) usize {
        return 2 * @as(usize, limits.max_field_len);
    }

    pub fn deinit(self: *Self) void {
        self.table.deinit();
        self.allocator.free(self.scratch);
    }

    /// `decode` with `scratch` (at least `scratchLen` bytes) lent for the
    /// call.
    pub fn decodeWith(self: *Self, scratch: []u8, block: []const u8, sink: anytype) !void {
        std.debug.assert(scratch.len >= scratchLen(self.limits));
        const own = self.scratch;
        self.scratch = scratch;
        defer self.scratch = own;
        return self.decode(block, sink);
    }

    /// Decodes one complete header block. For every field, calls
    /// `sink.header(name, value)`; the slices are valid only during the
    /// call. Fields past the header list size limit are not delivered, but
    /// decoding continues so the dynamic table stays in sync, and the
    /// result is `error.HeaderListTooLarge`.
    pub fn decode(self: *Self, block: []const u8, sink: anytype) !void {
        var pos: usize = 0;
        var list_size: u64 = 0;
        var too_large = false;
        var fields: usize = 0;
        while (pos < block.len) {
            const b = block[pos];
            if (b & 0x80 != 0) {
                // Indexed header field.
                const idx = try decodeInt(block[pos..], 7);
                pos += idx.len;
                const f = try self.lookup(idx.value);
                fields += 1;
                try self.deliver(sink, f.name, f.value, &list_size, &too_large);
            } else if (b & 0x40 != 0) {
                // Literal with incremental indexing.
                const f = try self.literal(block, &pos, 6);
                self.table.add(f.name, f.value);
                fields += 1;
                try self.deliver(sink, f.name, f.value, &list_size, &too_large);
            } else if (b & 0x20 != 0) {
                // Dynamic table size update (§6.3): only at the start of
                // a block (§4.2), and never above what we advertised.
                if (fields > 0) return error.CompressionError;
                const size = try decodeInt(block[pos..], 5);
                pos += size.len;
                if (size.value > self.table.capacity()) return error.CompressionError;
                self.table.setMaxSize(size.value);
            } else {
                // Literal without indexing (0000) or never indexed (0001).
                const f = try self.literal(block, &pos, 4);
                fields += 1;
                try self.deliver(sink, f.name, f.value, &list_size, &too_large);
            }
        }
        if (too_large) return error.HeaderListTooLarge;
    }

    fn deliver(self: *Self, sink: anytype, name: []const u8, value: []const u8, list_size: *u64, too_large: *bool) !void {
        list_size.* += name.len + value.len + entry_overhead;
        if (list_size.* > self.limits.max_header_list_size) too_large.* = true;
        if (too_large.*) return;
        try sink.header(name, value);
    }

    fn lookup(self: *const Self, index: u32) Error!Field {
        if (index == 0) return error.CompressionError;
        if (index <= static_table.len) return static_table[index - 1];
        return self.table.get(index - static_table.len) orelse error.CompressionError;
    }

    /// Reads a literal field whose name is an index (prefix N bits) or a
    /// string. The result lives in `scratch`.
    fn literal(self: *Self, block: []const u8, pos: *usize, comptime prefix_bits: u4) Error!Field {
        const idx = try decodeInt(block[pos.*..], prefix_bits);
        pos.* += idx.len;
        var name_len: usize = 0;
        if (idx.value != 0) {
            const f = try self.lookup(idx.value);
            // Fits: table entries are bounded by max_field_len on insert.
            @memcpy(self.scratch[0..f.name.len], f.name);
            name_len = f.name.len;
        } else {
            name_len = try self.string(block, pos, self.scratch[0..self.limits.max_field_len]);
        }
        const value_len = try self.string(block, pos, self.scratch[name_len..][0..self.limits.max_field_len]);
        return .{ .name = self.scratch[0..name_len], .value = self.scratch[name_len..][0..value_len] };
    }

    /// Reads a string literal (§5.2) into `out`.
    fn string(_: *Self, block: []const u8, pos: *usize, out: []u8) Error!usize {
        if (pos.* >= block.len) return error.CompressionError;
        const huff = block[pos.*] & 0x80 != 0;
        const len = try decodeInt(block[pos.*..], 7);
        pos.* += len.len;
        if (len.value > block.len - pos.*) return error.CompressionError;
        const raw = block[pos.*..][0..len.value];
        pos.* += len.value;
        if (huff) return huffmanDecode(out, raw);
        if (raw.len > out.len) return error.CompressionError;
        @memcpy(out[0..raw.len], raw);
        return raw.len;
    }
};

// ---------------------------------------------------------------------------
// Encoder

pub const Indexing = enum {
    /// Literal with incremental indexing (or an index if already present).
    index,
    /// Literal without indexing; indexed if present.
    no_index,
    /// Never indexed (§6.2.3): sensitive values, kept out of every table.
    never,
};

pub const Huffman = enum { never, always, when_shorter };

pub const EncodeOptions = struct {
    indexing: Indexing = .index,
    huffman: Huffman = .when_shorter,
};

pub const Encoder = struct {
    const Self = @This();

    table: DynamicTable,
    /// The smallest and the latest maximum since the last block, when the
    /// peer changed SETTINGS_HEADER_TABLE_SIZE (§4.2): both are signalled.
    pending_min: ?u32 = null,
    pending_final: ?u32 = null,

    /// `cap` is the most this encoder will ever use, whatever the peer
    /// allows (it bounds memory per connection).
    pub fn init(allocator: std.mem.Allocator, cap: u32) !Self {
        return .{ .table = try DynamicTable.init(allocator, cap) };
    }

    pub fn deinit(self: *Self) void {
        self.table.deinit();
    }

    /// The peer's SETTINGS_HEADER_TABLE_SIZE (after we acknowledged it).
    pub fn setPeerMaxTableSize(self: *Self, n: u32) void {
        const target = @min(n, self.table.capacity());
        if (target == self.table.max_size and self.pending_final == null) return;
        self.pending_min = @min(self.pending_min orelse target, target);
        self.pending_final = target;
    }

    /// Call at the start of every header block: writes any size updates
    /// the peer must see. Returns the bytes written.
    pub fn beginBlock(self: *Self, out: []u8) error{NoSpace}!usize {
        var n: usize = 0;
        if (self.pending_min) |min| {
            const final = self.pending_final.?;
            if (min < final) {
                n += try encodeInt(out[n..], 0x20, 5, min);
                self.table.setMaxSize(min);
            }
            if (final != self.table.max_size or min == final) {
                n += try encodeInt(out[n..], 0x20, 5, final);
                self.table.setMaxSize(final);
            }
            self.pending_min = null;
            self.pending_final = null;
        }
        return n;
    }

    /// Encodes one field. Returns the bytes written, or NoSpace with `out`
    /// untouched in effect (the table is only changed on success).
    pub fn encode(self: *Self, out: []u8, name: []const u8, value: []const u8, opts: EncodeOptions) error{NoSpace}!usize {
        var full: ?usize = null;
        var name_idx: ?usize = null;
        for (static_table, 1..) |f, i| {
            if (f.name.len != name.len or !std.mem.eql(u8, f.name, name)) continue;
            if (name_idx == null) name_idx = i;
            if (f.value.len == value.len and std.mem.eql(u8, f.value, value)) {
                full = i;
                break;
            }
        }
        if (full == null and opts.indexing != .never) {
            const d = self.table.find(name, value);
            if (d.full) |i| full = i + static_table.len;
            if (name_idx == null) {
                if (d.name) |i| name_idx = i + static_table.len;
            }
        }
        if (full) |i| return encodeInt(out, 0x80, 7, i);
        var n: usize = 0;
        switch (opts.indexing) {
            .index => n += try encodeInt(out, 0x40, 6, name_idx orelse 0),
            .no_index => n += try encodeInt(out, 0x00, 4, name_idx orelse 0),
            .never => n += try encodeInt(out, 0x10, 4, name_idx orelse 0),
        }
        if (name_idx == null) n += try encodeString(out[n..], name, opts.huffman);
        n += try encodeString(out[n..], value, opts.huffman);
        if (opts.indexing == .index) self.table.add(name, value);
        return n;
    }
};

/// Writes a string literal (§5.2).
pub fn encodeString(out: []u8, s: []const u8, huffman_mode: Huffman) error{NoSpace}!usize {
    const hlen = if (huffman_mode == .never) s.len else huffmanEncodedLen(s);
    const use_huffman = switch (huffman_mode) {
        .never => false,
        .always => true,
        .when_shorter => hlen < s.len,
    };
    const len = if (use_huffman) hlen else s.len;
    const n = try encodeInt(out, if (use_huffman) 0x80 else 0, 7, len);
    if (out.len - n < len) return error.NoSpace;
    if (use_huffman) {
        _ = huffmanEncode(out[n..], s);
    } else {
        @memcpy(out[n..][0..len], s);
    }
    return n + len;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "huffman table is canonical and complete" {
    // Kraft sum of 1: a complete prefix code. Codes of equal length are
    // consecutive in symbol order, and the first code of each length
    // follows from the previous length (a canonical code). Together these
    // mean one wrong length or code would show up here.
    var kraft: u64 = 0;
    for (huffman_codes) |c| kraft += @as(u64, 1) << @intCast(32 - c.len);
    try testing.expectEqual(@as(u64, 1) << 32, kraft);
    var code: u32 = 0;
    var last_len: u8 = 0;
    for (5..31) |len| {
        code <<= @intCast(len - last_len);
        last_len = @intCast(len);
        for (huffman_codes) |c| {
            if (c.len != len) continue;
            try testing.expectEqual(code, c.code);
            code += 1;
        }
    }
    // A few spot checks against Appendix B.
    try testing.expectEqual(Code{ .code = 0x14, .len = 6 }, huffman_codes[' ']);
    try testing.expectEqual(Code{ .code = 0x5c, .len = 7 }, huffman_codes[':']);
    try testing.expectEqual(Code{ .code = 0x7fff0, .len = 19 }, huffman_codes['\\']);
    try testing.expectEqual(Code{ .code = 0x3fffffff, .len = 30 }, huffman_codes[eos]);
}

test "huffman round trip over every byte and padding rules" {
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    var enc: [1024]u8 = undefined;
    var dec: [256]u8 = undefined;
    const n = huffmanEncode(&enc, &all);
    try testing.expectEqual(huffmanEncodedLen(&all), n);
    try testing.expectEqual(@as(usize, 256), try huffmanDecode(&dec, enc[0..n]));
    try testing.expectEqualSlices(u8, &all, &dec);
    // Empty string.
    try testing.expectEqual(@as(usize, 0), try huffmanDecode(&dec, ""));
    // RFC 7541 C.4.1: "www.example.com".
    const www = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    try testing.expectEqual(@as(usize, 15), try huffmanDecode(&dec, &www));
    try testing.expectEqualStrings("www.example.com", dec[0..15]);
    try testing.expectEqual(www.len, huffmanEncode(&enc, "www.example.com"));
    try testing.expectEqualSlices(u8, &www, enc[0..www.len]);
    // Padding that is not the EOS prefix ('0' is 00000: "a" = 00011 + 000).
    try testing.expectError(error.CompressionError, huffmanDecode(&dec, &.{0x18}));
    // Padding of 8 bits (a whole byte of ones after "a").
    try testing.expectError(error.CompressionError, huffmanDecode(&dec, &.{ 0x1f, 0xff }));
    // "aa" (00011 00011) then 6 ones of padding: fine.
    try testing.expectEqual(@as(usize, 2), try huffmanDecode(&dec, &.{ 0x18, 0xff }));
    try testing.expectEqualStrings("aa", dec[0..2]);
    // EOS inside the string.
    try testing.expectError(error.CompressionError, huffmanDecode(&dec, &.{ 0xff, 0xff, 0xff, 0xfc }));
    // The symbol for 0 (13 bits, 0x1ff8) then 3 ones: valid; then 11 ones: not.
    try testing.expectEqual(@as(usize, 1), try huffmanDecode(&dec, &.{ 0xff, 0xc7 }));
    try testing.expectEqual(@as(u8, 0), dec[0]);
    try testing.expectError(error.CompressionError, huffmanDecode(&dec, &.{ 0xff, 0xc7, 0xff }));
    // Output too small.
    try testing.expectError(error.CompressionError, huffmanDecode(dec[0..1], enc[0..n]));
}

test "integer coding (RFC 7541 C.1)" {
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try encodeInt(&buf, 0, 5, 10));
    try testing.expectEqual(@as(u8, 10), buf[0]);
    try testing.expectEqual(Int{ .value = 10, .len = 1 }, try decodeInt(&.{10}, 5));
    try testing.expectEqual(@as(usize, 3), try encodeInt(&buf, 0, 5, 1337));
    try testing.expectEqualSlices(u8, &.{ 31, 154, 10 }, buf[0..3]);
    try testing.expectEqual(Int{ .value = 1337, .len = 3 }, try decodeInt(&.{ 31, 154, 10 }, 5));
    try testing.expectEqual(@as(usize, 1), try encodeInt(&buf, 0, 8, 42));
    try testing.expectEqual(Int{ .value = 42, .len = 1 }, try decodeInt(&.{42}, 8));
    // Prefix pattern bits are preserved.
    _ = try encodeInt(&buf, 0x80, 7, 2);
    try testing.expectEqual(@as(u8, 0x82), buf[0]);
    // Truncated.
    try testing.expectError(error.CompressionError, decodeInt(&.{31}, 5));
    try testing.expectError(error.CompressionError, decodeInt(&.{ 31, 0x80 }, 5));
    try testing.expectError(error.CompressionError, decodeInt(&.{}, 5));
    // Overflow of 32 bits, and too many continuation bytes.
    try testing.expectError(error.CompressionError, decodeInt(&.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 8));
    try testing.expectError(error.CompressionError, decodeInt(&.{ 0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }, 8));
    // The largest value that fits.
    const max = try decodeInt(&.{ 0xff, 0x80, 0xfe, 0xff, 0xff, 0x0f }, 8);
    try testing.expectEqual(@as(u32, 0xffffffff), max.value);
    // Round trips.
    var prng = std.Random.DefaultPrng.init(1);
    const random = prng.random();
    for (0..2000) |_| {
        const v = random.int(u32);
        const n = try encodeInt(&buf, 0, 5, v);
        const d = try decodeInt(buf[0..n], 5);
        try testing.expectEqual(v, d.value);
        try testing.expectEqual(n, d.len);
    }
    try testing.expectError(error.NoSpace, encodeInt(buf[0..1], 0, 5, 1337));
}

/// Collects decoded fields as "name: value\n" lines.
const ListSink = struct {
    out: std.ArrayList(u8) = .empty,

    fn header(self: *ListSink, name: []const u8, value: []const u8) !void {
        try self.out.appendSlice(testing.allocator, name);
        try self.out.appendSlice(testing.allocator, ": ");
        try self.out.appendSlice(testing.allocator, value);
        try self.out.append(testing.allocator, '\n');
    }

    fn deinit(self: *ListSink) void {
        self.out.deinit(testing.allocator);
    }
};

fn hexLen(comptime s: []const u8) usize {
    var n: usize = 0;
    for (s) |c| {
        if (c != ' ') n += 1;
    }
    return n / 2;
}

fn hex(comptime s: []const u8) *const [hexLen(s)]u8 {
    const out = comptime blk: {
        var o: [hexLen(s)]u8 = undefined;
        var n: usize = 0;
        var hi: ?u8 = null;
        for (s) |c| {
            if (c == ' ') continue;
            const d = std.fmt.charToDigit(c, 16) catch unreachable;
            if (hi) |h| {
                o[n] = h * 16 + d;
                n += 1;
                hi = null;
            } else hi = d;
        }
        break :blk o;
    };
    return &out;
}

fn expectTable(table: *const DynamicTable, expected: []const Field, size: u32) !void {
    try testing.expectEqual(expected.len, table.count);
    for (expected, 1..) |f, i| {
        const got = table.get(i).?;
        try testing.expectEqualStrings(f.name, got.name);
        try testing.expectEqualStrings(f.value, got.value);
    }
    try testing.expectEqual(size, table.size);
}

/// One RFC 7541 Appendix C example: fields, their encoding, and the
/// dynamic table afterwards.
const Example = struct {
    fields: []const Field,
    bytes: []const u8,
    table: []const Field,
    size: u32,
};

fn runExamples(examples: []const Example, huffman_mode: Huffman, table_size: ?u32) !void {
    var dec = try Decoder.init(testing.allocator, .{});
    defer dec.deinit();
    var enc = try Encoder.init(testing.allocator, 4096);
    defer enc.deinit();
    if (table_size) |n| {
        dec.table.setMaxSize(n);
        enc.table.setMaxSize(n);
    }
    for (examples) |ex| {
        // Decode: the fields and the table state match.
        var sink: ListSink = .{};
        defer sink.deinit();
        try dec.decode(ex.bytes, &sink);
        var expected: std.ArrayList(u8) = .empty;
        defer expected.deinit(testing.allocator);
        for (ex.fields) |f| {
            try expected.appendSlice(testing.allocator, f.name);
            try expected.appendSlice(testing.allocator, ": ");
            try expected.appendSlice(testing.allocator, f.value);
            try expected.append(testing.allocator, '\n');
        }
        try testing.expectEqualStrings(expected.items, sink.out.items);
        try expectTable(&dec.table, ex.table, ex.size);
        // Encode: byte for byte.
        var buf: [512]u8 = undefined;
        var n: usize = 0;
        for (ex.fields) |f| {
            n += try enc.encode(buf[n..], f.name, f.value, .{ .huffman = huffman_mode });
        }
        try testing.expectEqualSlices(u8, ex.bytes, buf[0..n]);
        try expectTable(&enc.table, ex.table, ex.size);
    }
}

test "RFC 7541 C.2: literal header fields" {
    // C.2.1 Literal with indexing.
    {
        var dec = try Decoder.init(testing.allocator, .{});
        defer dec.deinit();
        var enc = try Encoder.init(testing.allocator, 4096);
        defer enc.deinit();
        const bytes = hex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572");
        var sink: ListSink = .{};
        defer sink.deinit();
        try dec.decode(bytes, &sink);
        try testing.expectEqualStrings("custom-key: custom-header\n", sink.out.items);
        try expectTable(&dec.table, &.{.{ .name = "custom-key", .value = "custom-header" }}, 55);
        var buf: [64]u8 = undefined;
        const n = try enc.encode(&buf, "custom-key", "custom-header", .{ .huffman = .never });
        try testing.expectEqualSlices(u8, bytes, buf[0..n]);
        try expectTable(&enc.table, &.{.{ .name = "custom-key", .value = "custom-header" }}, 55);
    }
    // C.2.2 Literal without indexing.
    {
        var dec = try Decoder.init(testing.allocator, .{});
        defer dec.deinit();
        var enc = try Encoder.init(testing.allocator, 4096);
        defer enc.deinit();
        const bytes = hex("040c 2f73 616d 706c 652f 7061 7468");
        var sink: ListSink = .{};
        defer sink.deinit();
        try dec.decode(bytes, &sink);
        try testing.expectEqualStrings(":path: /sample/path\n", sink.out.items);
        try expectTable(&dec.table, &.{}, 0);
        var buf: [64]u8 = undefined;
        const n = try enc.encode(&buf, ":path", "/sample/path", .{ .indexing = .no_index, .huffman = .never });
        try testing.expectEqualSlices(u8, bytes, buf[0..n]);
        try expectTable(&enc.table, &.{}, 0);
    }
    // C.2.3 Literal never indexed.
    {
        var dec = try Decoder.init(testing.allocator, .{});
        defer dec.deinit();
        var enc = try Encoder.init(testing.allocator, 4096);
        defer enc.deinit();
        const bytes = hex("1008 7061 7373 776f 7264 0673 6563 7265 74");
        var sink: ListSink = .{};
        defer sink.deinit();
        try dec.decode(bytes, &sink);
        try testing.expectEqualStrings("password: secret\n", sink.out.items);
        try expectTable(&dec.table, &.{}, 0);
        var buf: [64]u8 = undefined;
        const n = try enc.encode(&buf, "password", "secret", .{ .indexing = .never, .huffman = .never });
        try testing.expectEqualSlices(u8, bytes, buf[0..n]);
    }
    // C.2.4 Indexed.
    {
        var dec = try Decoder.init(testing.allocator, .{});
        defer dec.deinit();
        var enc = try Encoder.init(testing.allocator, 4096);
        defer enc.deinit();
        var sink: ListSink = .{};
        defer sink.deinit();
        try dec.decode(&.{0x82}, &sink);
        try testing.expectEqualStrings(":method: GET\n", sink.out.items);
        try expectTable(&dec.table, &.{}, 0);
        var buf: [64]u8 = undefined;
        const n = try enc.encode(&buf, ":method", "GET", .{});
        try testing.expectEqualSlices(u8, &.{0x82}, buf[0..n]);
    }
}

const request_examples = struct {
    const first = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    };
    const second = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "cache-control", .value = "no-cache" },
    };
    const third = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "custom-key", .value = "custom-value" },
    };
    const table1 = [_]Field{.{ .name = ":authority", .value = "www.example.com" }};
    const table2 = [_]Field{
        .{ .name = "cache-control", .value = "no-cache" },
        .{ .name = ":authority", .value = "www.example.com" },
    };
    const table3 = [_]Field{
        .{ .name = "custom-key", .value = "custom-value" },
        .{ .name = "cache-control", .value = "no-cache" },
        .{ .name = ":authority", .value = "www.example.com" },
    };
};

test "RFC 7541 C.3: request examples without Huffman coding" {
    const r = request_examples;
    try runExamples(&.{
        .{ .fields = &r.first, .bytes = hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"), .table = &r.table1, .size = 57 },
        .{ .fields = &r.second, .bytes = hex("8286 84be 5808 6e6f 2d63 6163 6865"), .table = &r.table2, .size = 110 },
        .{ .fields = &r.third, .bytes = hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"), .table = &r.table3, .size = 164 },
    }, .never, null);
}

test "RFC 7541 C.4: request examples with Huffman coding" {
    const r = request_examples;
    const examples = [_]Example{
        .{ .fields = &r.first, .bytes = hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"), .table = &r.table1, .size = 57 },
        .{ .fields = &r.second, .bytes = hex("8286 84be 5886 a8eb 1064 9cbf"), .table = &r.table2, .size = 110 },
        .{ .fields = &r.third, .bytes = hex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"), .table = &r.table3, .size = 164 },
    };
    try runExamples(&examples, .always, null);
    // Huffman is shorter for every literal here, so the default policy
    // gives the same bytes.
    try runExamples(&examples, .when_shorter, null);
}

const response_examples = struct {
    const first = [_]Field{
        .{ .name = ":status", .value = "302" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    };
    const second = [_]Field{
        .{ .name = ":status", .value = "307" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    };
    const third = [_]Field{
        .{ .name = ":status", .value = "200" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
    };
    const table1 = [_]Field{
        .{ .name = "location", .value = "https://www.example.com" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = ":status", .value = "302" },
    };
    const table2 = [_]Field{
        .{ .name = ":status", .value = "307" },
        .{ .name = "location", .value = "https://www.example.com" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "cache-control", .value = "private" },
    };
    const table3 = [_]Field{
        .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
    };
};

test "RFC 7541 C.5: response examples without Huffman coding" {
    const r = response_examples;
    try runExamples(&.{
        .{
            .fields = &r.first,
            .bytes = hex("4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"),
            .table = &r.table1,
            .size = 222,
        },
        .{ .fields = &r.second, .bytes = hex("4803 3330 37c1 c0bf"), .table = &r.table2, .size = 222 },
        .{
            .fields = &r.third,
            .bytes = hex("88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31"),
            .table = &r.table3,
            .size = 215,
        },
    }, .never, 256);
}

test "RFC 7541 C.6: response examples with Huffman coding" {
    const r = response_examples;
    const examples = [_]Example{
        .{
            .fields = &r.first,
            .bytes = hex("4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3"),
            .table = &r.table1,
            .size = 222,
        },
        .{ .fields = &r.second, .bytes = hex("4883 640e ffc1 c0bf"), .table = &r.table2, .size = 222 },
        .{
            .fields = &r.third,
            .bytes = hex("88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07"),
            .table = &r.table3,
            .size = 215,
        },
    };
    try runExamples(&examples, .always, 256);
    // The default policy differs here: "307" is 3 bytes either way, and the
    // RFC's encoder still used Huffman where ours sends it raw.
}

test "decoders sharing one scratch (a worker's connections) keep their own tables" {
    // C.3 on one decoder and C.5 on another, block by block in turn: the
    // scratch holds a field only during a call.
    const scratch = try testing.allocator.alloc(u8, Decoder.scratchLen(.{}));
    defer testing.allocator.free(scratch);
    var requests = try Decoder.initShared(testing.allocator, .{});
    defer requests.deinit();
    var responses = try Decoder.initShared(testing.allocator, .{});
    defer responses.deinit();
    responses.table.setMaxSize(256);
    const q = request_examples;
    const r = response_examples;
    const blocks = [_][2][]const u8{
        .{ hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"), hex("4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d") },
        .{ hex("8286 84be 5808 6e6f 2d63 6163 6865"), hex("4803 3330 37c1 c0bf") },
        .{ hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"), hex("88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31") },
    };
    const fields = [_][2][]const Field{ .{ &q.first, &r.first }, .{ &q.second, &r.second }, .{ &q.third, &r.third } };
    for (blocks, fields) |b, f| {
        for ([_]*Decoder{ &requests, &responses }, 0..) |dec, i| {
            var sink: ListSink = .{};
            defer sink.deinit();
            try dec.decodeWith(scratch, b[i], &sink);
            var expected: std.ArrayList(u8) = .empty;
            defer expected.deinit(testing.allocator);
            for (f[i]) |x| try expected.print(testing.allocator, "{s}: {s}\n", .{ x.name, x.value });
            try testing.expectEqualStrings(expected.items, sink.out.items);
            // Nothing of the decoder's own is left pointing at it.
            try testing.expectEqual(@as(usize, 0), dec.scratch.len);
        }
    }
    try expectTable(&requests.table, &q.table3, 164);
    try expectTable(&responses.table, &r.table3, 215);
}

test "decoder rejects malformed blocks" {
    var dec = try Decoder.init(testing.allocator, .{ .max_header_list_size = 200, .max_field_len = 64 });
    defer dec.deinit();
    var sink: ListSink = .{};
    defer sink.deinit();
    // Index 0.
    try testing.expectError(error.CompressionError, dec.decode(&.{0x80}, &sink));
    // Index past the tables (static 61, dynamic empty).
    try testing.expectError(error.CompressionError, dec.decode(&.{0xbe}, &sink));
    try testing.expectError(error.CompressionError, dec.decode(&.{ 0xff, 0x00 }, &sink));
    // Literal with a name index past the tables.
    try testing.expectError(error.CompressionError, dec.decode(&.{ 0x7f, 0x00, 0x01, 'x' }, &sink));
    // Truncated string literal, and a string length past the block.
    try testing.expectError(error.CompressionError, dec.decode(&.{ 0x40, 0x05, 'a', 'b' }, &sink));
    try testing.expectError(error.CompressionError, dec.decode(&.{ 0x40, 0x01, 'a' }, &sink));
    try testing.expectError(error.CompressionError, dec.decode(&.{0x40}, &sink));
    // A length that doesn't fit in 32 bits.
    try testing.expectError(error.CompressionError, dec.decode(&.{ 0x40, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, &sink));
    // Bad Huffman padding in a value.
    try testing.expectError(error.CompressionError, dec.decode(&.{ 0x41, 0x81, 0x18 }, &sink));
    // Size update above what we advertised (4096).
    try testing.expectError(error.CompressionError, dec.decode(&.{ 0x3f, 0xe2, 0x1f }, &sink));
    // Size update after a field.
    try testing.expectError(error.CompressionError, dec.decode(&.{ 0x82, 0x20 }, &sink));
    // Two size updates at the start are fine (RFC 7541 §4.2).
    try dec.decode(&.{ 0x20, 0x3f, 0xe1, 0x1f, 0x82 }, &sink);
    try testing.expectEqual(@as(u32, 4096), dec.table.max_size);
    // A field longer than max_field_len (64): raw and Huffman.
    const long: [65]u8 = @splat('v');
    var block: [80]u8 = undefined;
    block[0] = 0x41;
    block[1] = 65;
    @memcpy(block[2..67], &long);
    try testing.expectError(error.CompressionError, dec.decode(block[0..67], &sink));
    const hlen = huffmanEncodedLen(&long);
    block[1] = 0x80 | @as(u8, @intCast(hlen));
    _ = huffmanEncode(block[2..], &long);
    try testing.expectError(error.CompressionError, dec.decode(block[0 .. 2 + hlen], &sink));
    // 64 fits.
    block[1] = 64;
    @memcpy(block[2..66], long[0..64]);
    sink.out.clearRetainingCapacity();
    try dec.decode(block[0..66], &sink);
    try testing.expectEqualStrings(":authority: " ++ long[0..64] ++ "\n", sink.out.items);
}

test "header list limit keeps the table in sync" {
    var dec = try Decoder.init(testing.allocator, .{ .max_header_list_size = 110 });
    defer dec.deinit();
    var sink: ListSink = .{};
    defer sink.deinit();
    // Three indexed literals of 32 + 1 + 20 = 53 bytes each: the third
    // crosses the limit, so only two are delivered, but all three land in
    // the table and the next block can reference them.
    var block: [80]u8 = undefined;
    var n: usize = 0;
    for ("abc") |c| {
        block[n] = 0x40;
        block[n + 1] = 1;
        block[n + 2] = c;
        block[n + 3] = 20;
        @memset(block[n + 4 ..][0..20], c);
        n += 24;
    }
    try testing.expectError(error.HeaderListTooLarge, dec.decode(block[0..n], &sink));
    try testing.expectEqualStrings("a: aaaaaaaaaaaaaaaaaaaa\nb: bbbbbbbbbbbbbbbbbbbb\n", sink.out.items);
    try testing.expectEqual(@as(usize, 3), dec.table.count);
    sink.out.clearRetainingCapacity();
    try dec.decode(&.{ 0xbe, 0xc0 }, &sink);
    try testing.expectEqualStrings("c: cccccccccccccccccccc\na: aaaaaaaaaaaaaaaaaaaa\n", sink.out.items);
}

test "dynamic table: eviction, oversized entries, compaction, size updates" {
    var t = try DynamicTable.init(testing.allocator, 128);
    defer t.deinit();
    try testing.expectEqual(@as(u32, 128), t.max_size);
    t.add("k1", "v1"); // 36
    t.add("k2", "v2"); // 72
    t.add("k3", "v3"); // 108
    t.add("k4", "v4"); // 144 -> evicts k1 -> 108
    try expectTable(&t, &.{ .{ .name = "k4", .value = "v4" }, .{ .name = "k3", .value = "v3" }, .{ .name = "k2", .value = "v2" } }, 108);
    // An entry larger than the table empties it and is not added.
    const big: [100]u8 = @splat('b');
    t.add("name", &big);
    try expectTable(&t, &.{}, 0);
    try testing.expectEqual(@as(usize, 0), t.end);
    // Many additions wrap the byte buffer and the entry ring.
    var i: usize = 0;
    var buf: [8]u8 = undefined;
    while (i < 1000) : (i += 1) {
        const name = std.fmt.bufPrint(&buf, "n{d}", .{i}) catch unreachable;
        t.add(name, "value-with-padding");
        try testing.expect(t.size <= t.max_size);
        try testing.expect(t.end <= t.bytes.len);
        const newest = t.get(1).?;
        try testing.expectEqualStrings(name, newest.name);
        try testing.expectEqualStrings("value-with-padding", newest.value);
    }
    // Lowering the maximum evicts; raising it does not.
    t.setMaxSize(60);
    try testing.expectEqual(@as(usize, 1), t.count);
    t.setMaxSize(0);
    try expectTable(&t, &.{}, 0);
    t.setMaxSize(128);
    t.add("a", "b");
    try testing.expectEqual(@as(usize, 1), t.count);
    try testing.expectEqual(@as(?usize, 1), t.find("a", "b").full);
    try testing.expectEqual(@as(?usize, 1), t.find("a", "c").name);
    try testing.expectEqual(@as(?usize, null), t.find("a", "c").full);
    try testing.expectEqual(@as(?usize, null), t.find("x", "b").name);
}

test "encoder signals table size changes at the start of the next block" {
    var enc = try Encoder.init(testing.allocator, 4096);
    defer enc.deinit();
    var buf: [64]u8 = undefined;
    // Nothing pending.
    try testing.expectEqual(@as(usize, 0), try enc.beginBlock(&buf));
    // Peer lowers to 100: one update.
    enc.setPeerMaxTableSize(100);
    var n = try enc.beginBlock(&buf);
    try testing.expectEqualSlices(u8, &.{ 0x3f, 0x45 }, buf[0..n]);
    try testing.expectEqual(@as(u32, 100), enc.table.max_size);
    // Peer goes to 0 then 4096 before we send: both are signalled.
    enc.setPeerMaxTableSize(0);
    enc.setPeerMaxTableSize(4096);
    n = try enc.beginBlock(&buf);
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x3f, 0xe1, 0x1f }, buf[0..n]);
    try testing.expectEqual(@as(u32, 4096), enc.table.max_size);
    // Above our capacity: capped, and no change from 4096 means nothing.
    enc.setPeerMaxTableSize(65536);
    try testing.expectEqual(@as(usize, 0), try enc.beginBlock(&buf));
    // A decoder with the matching capacity accepts the block.
    var dec = try Decoder.init(testing.allocator, .{});
    defer dec.deinit();
    var sink: ListSink = .{};
    defer sink.deinit();
    try dec.decode(&.{ 0x20, 0x3f, 0xe1, 0x1f }, &sink);
    try testing.expectEqual(@as(u32, 4096), dec.table.max_size);
}

test "encoder output does not fit" {
    var enc = try Encoder.init(testing.allocator, 4096);
    defer enc.deinit();
    var buf: [8]u8 = undefined;
    try testing.expectError(error.NoSpace, enc.encode(&buf, "custom-key", "custom-header", .{}));
    try testing.expectError(error.NoSpace, enc.encode(buf[0..0], ":method", "GET", .{}));
    // The table is untouched by a failed encode.
    try testing.expectEqual(@as(usize, 0), enc.table.count);
    // never-indexed fields are not looked up in, nor added to, the table.
    var big: [64]u8 = undefined;
    const n = try enc.encode(&big, "authorization", "secret", .{ .indexing = .never, .huffman = .never });
    // Static index 23 with a 4-bit prefix: 0x1f then 23 - 15.
    try testing.expectEqualSlices(u8, &.{ 0x1f, 8, 6 }, big[0..3]);
    try testing.expectEqual(@as(usize, 3 + 6), n);
    try testing.expectEqual(@as(usize, 0), enc.table.count);
}

// Encodes random fields with random options, decodes, and checks the
// fields come back; the encoder and decoder share one table state.
test "round trip property" {
    var prng = std.Random.DefaultPrng.init(0x42);
    const random = prng.random();
    var enc = try Encoder.init(testing.allocator, 4096);
    defer enc.deinit();
    var dec = try Decoder.init(testing.allocator, .{ .max_header_list_size = 1 << 20, .max_field_len = 1024 });
    defer dec.deinit();
    const block_buf = try testing.allocator.alloc(u8, 64 * 1024);
    defer testing.allocator.free(block_buf);
    var names: [8][16]u8 = undefined;
    var values: [8][300]u8 = undefined;
    for (0..300) |iter| {
        var expected: std.ArrayList(u8) = .empty;
        defer expected.deinit(testing.allocator);
        var n: usize = 0;
        // Sometimes the peer changes the table size.
        if (random.uintLessThan(u8, 8) == 0) {
            const size = random.uintLessThan(u32, 4097);
            enc.setPeerMaxTableSize(size);
        }
        n += try enc.beginBlock(block_buf[n..]);
        const count = random.uintLessThan(usize, 8);
        for (0..count) |i| {
            const name_len = 1 + random.uintLessThan(usize, 16);
            for (names[i][0..name_len]) |*b| b.* = "abcdefgh:-"[random.uintLessThan(usize, 10)];
            const value_len = random.uintLessThan(usize, 300);
            for (values[i][0..value_len]) |*b| b.* = if (random.boolean()) random.int(u8) else "aeiou 0123456789"[random.uintLessThan(usize, 16)];
            // Static names now and then.
            const name: []const u8 = if (random.uintLessThan(u8, 4) == 0) static_table[random.uintLessThan(usize, 61)].name else names[i][0..name_len];
            const value: []const u8 = if (random.uintLessThan(u8, 8) == 0) "GET" else values[i][0..value_len];
            const opts: EncodeOptions = .{
                .indexing = random.enumValue(Indexing),
                .huffman = random.enumValue(Huffman),
            };
            n += try enc.encode(block_buf[n..], name, value, opts);
            try expected.appendSlice(testing.allocator, name);
            try expected.appendSlice(testing.allocator, ": ");
            try expected.appendSlice(testing.allocator, value);
            try expected.append(testing.allocator, '\n');
        }
        var sink: ListSink = .{};
        defer sink.deinit();
        dec.decode(block_buf[0..n], &sink) catch |err| {
            std.debug.print("iteration {d}: {s}\n", .{ iter, @errorName(err) });
            return err;
        };
        try testing.expectEqualStrings(expected.items, sink.out.items);
        try testing.expectEqual(enc.table.count, dec.table.count);
        try testing.expectEqual(enc.table.size, dec.table.size);
    }
}

/// Collects decoded fields as owned copies.
const FieldSink = struct {
    fields: std.ArrayList(Field) = .empty,

    fn header(self: *FieldSink, name: []const u8, value: []const u8) !void {
        const n = try testing.allocator.dupe(u8, name);
        errdefer testing.allocator.free(n);
        const v = try testing.allocator.dupe(u8, value);
        errdefer testing.allocator.free(v);
        try self.fields.append(testing.allocator, .{ .name = n, .value = v });
    }

    fn deinit(self: *FieldSink) void {
        for (self.fields.items) |f| {
            testing.allocator.free(f.name);
            testing.allocator.free(f.value);
        }
        self.fields.deinit(testing.allocator);
    }
};

// Fuzz target: arbitrary blocks must never crash the decoder, and
// whatever decodes must re-encode to something that decodes to the same
// fields (with a fresh pair of tables).
fn fuzzDecoder(_: void, smith: *std.testing.Smith) anyerror!void {
    var block_buf: [1024]u8 = undefined;
    const block = block_buf[0..smith.slice(&block_buf)];
    var dec = try Decoder.init(testing.allocator, .{ .max_header_list_size = 4096, .max_field_len = 512 });
    defer dec.deinit();
    var sink: FieldSink = .{};
    defer sink.deinit();
    dec.decode(block, &sink) catch |err| switch (err) {
        error.CompressionError, error.HeaderListTooLarge => return,
        else => return err,
    };
    // Re-encode what came out.
    var enc = try Encoder.init(testing.allocator, 4096);
    defer enc.deinit();
    var out: [8192]u8 = undefined;
    var n: usize = 0;
    for (sink.fields.items) |f| {
        n += try enc.encode(out[n..], f.name, f.value, .{ .huffman = if (smith.value(bool)) .always else .when_shorter });
    }
    var dec2 = try Decoder.init(testing.allocator, .{ .max_header_list_size = 4096, .max_field_len = 512 });
    defer dec2.deinit();
    var sink2: FieldSink = .{};
    defer sink2.deinit();
    try dec2.decode(out[0..n], &sink2);
    try testing.expectEqual(sink.fields.items.len, sink2.fields.items.len);
    for (sink.fields.items, sink2.fields.items) |a, b| {
        try testing.expectEqualStrings(a.name, b.name);
        try testing.expectEqualStrings(a.value, b.value);
    }
}

test "fuzz: hpack decoder" {
    try std.testing.fuzz({}, fuzzDecoder, .{ .corpus = &.{
        hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"),
        hex("8286 84be 5886 a8eb 1064 9cbf"),
        hex("4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"),
        hex("3fe1 1f82 1008 7061 7373 776f 7264 0673 6563 7265 74"),
        hex("88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab"),
    } });
}
