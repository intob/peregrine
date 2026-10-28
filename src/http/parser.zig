//! HTTP/1.1 request parsing (RFC 9112). Zero-copy: the Request's slices point
//! into the input buffer. The parser is strict where leniency enables request
//! smuggling: bare LF/CR, obs-fold, whitespace before ':', conflicting
//! framing headers and malformed chunked encoding are all rejected.
const std = @import("std");
const Request = @import("../request.zig").Request;
const request_max_headers = @import("../request.zig").MAX_HEADERS;
const Method = @import("../method.zig").Method;
const Version = @import("../version.zig").Version;
const Status = @import("../status.zig").Status;
const Header = @import("../header.zig").Header;

pub const Limits = struct {
    /// Maximum size of the request line plus headers.
    max_header_bytes: usize = 16 * 1024,
    /// Maximum size of the request line.
    max_request_line: usize = 8 * 1024,
    /// Maximum size of a (decoded) request body.
    max_body_size: usize = 1024 * 1024,
};

pub const ParseError = error{
    BadRequest,
    UriTooLong,
    HeadersTooLarge,
    PayloadTooLarge,
    UnknownMethod,
    UnsupportedVersion,
    UnsupportedTransferCoding,
    ExpectationFailed,
};

pub fn statusFor(err: ParseError) Status {
    return switch (err) {
        error.BadRequest => .bad_request,
        error.UriTooLong => .uri_too_long,
        error.HeadersTooLarge => .request_header_fields_too_large,
        error.PayloadTooLarge => .payload_too_large,
        error.UnknownMethod => .not_implemented,
        error.UnsupportedVersion => .http_version_not_supported,
        error.UnsupportedTransferCoding => .not_implemented,
        error.ExpectationFailed => .expectation_failed,
    };
}

pub const Framing = union(enum) {
    none,
    length: usize,
    chunked,
};

pub const Head = struct {
    /// Length of the request line and headers, including the final CRLFCRLF.
    len: usize,
    /// A Content-Length body is not checked against `max_body_size` here:
    /// a handler may stream it (see the session).
    framing: Framing,
    expect_continue: bool,
};

const vec_len = std.simd.suggestVectorLength(u8) orelse 16;
const V = @Vector(vec_len, u8);
const Mask = @Int(.unsigned, vec_len);

/// Searches for the end of the head (CRLFCRLF). Every LF must be preceded by
/// CR. `scan_from` is a resume offset: bytes before it were already checked
/// and are not scanned again. Returns the head length, or null if more data
/// is needed.
pub fn findHeadEnd(data: []const u8, scan_from: *usize, limits: Limits) ParseError!?usize {
    var i = scan_from.*;
    while (i + vec_len <= data.len) : (i += vec_len) {
        const chunk: V = data[i..][0..vec_len].*;
        var mask: Mask = @bitCast(chunk == @as(V, @splat('\n')));
        while (mask != 0) : (mask &= mask - 1) {
            if (try checkLf(data, i + @ctz(mask))) |end| return end;
        }
    }
    while (i < data.len) : (i += 1) {
        if (data[i] == '\n') {
            if (try checkLf(data, i)) |end| return end;
        }
    }
    scan_from.* = data.len;
    if (data.len > limits.max_request_line and
        std.mem.indexOfScalar(u8, data[0..limits.max_request_line], '\n') == null)
    {
        return error.UriTooLong;
    }
    if (data.len >= limits.max_header_bytes) return error.HeadersTooLarge;
    return null;
}

inline fn checkLf(data: []const u8, i: usize) ParseError!?usize {
    if (i == 0 or data[i - 1] != '\r') return error.BadRequest; // bare LF
    if (i >= 3 and data[i - 2] == '\n') return i + 1;
    return null;
}

/// Parses a complete head (as delimited by findHeadEnd) into `req`.
pub fn parseHead(head: []const u8, req: *Request, limits: Limits) ParseError!Head {
    req.reset();
    // Request line
    const line_end = std.mem.indexOfScalar(u8, head, '\r') orelse return error.BadRequest;
    if (line_end > limits.max_request_line) return error.UriTooLong;
    const line = head[0..line_end];
    if (line.len == 0) return error.BadRequest;
    const method_end = std.mem.indexOfScalar(u8, line[0..@min(line.len, 16)], ' ') orelse {
        return if (isToken(line[0..@min(line.len, 16)])) error.UnknownMethod else error.BadRequest;
    };
    const method_token = line[0..method_end];
    if (method_token.len == 0 or !isToken(method_token)) return error.BadRequest;
    req.method = try Method.parse(method_token);
    const target_start = method_end + 1;
    const target_end = target_start + targetLength(line[target_start..]);
    if (target_end == target_start or target_end >= line.len or line[target_end] != ' ') {
        return error.BadRequest;
    }
    req.path_and_query = line[target_start..target_end];
    req.version = Version.parse(line[target_end + 1 ..]) catch |err| switch (err) {
        error.InvalidVersion => return error.BadRequest,
        error.UnsupportedVersion => return error.UnsupportedVersion,
    };

    // Header fields
    var host_count: u8 = 0;
    var content_length: ?usize = null;
    var chunked = false;
    var has_transfer_encoding = false;
    var conn_close = false;
    var conn_keep_alive = false;
    var expect_continue = false;
    var pos = line_end + 2;
    const fields_end = head.len - 2; // final CRLF
    while (pos < fields_end) {
        const cr = std.mem.indexOfScalarPos(u8, head, pos, '\r') orelse return error.BadRequest;
        const field = head[pos..cr];
        pos = cr + 2;
        if (head[cr + 1] != '\n') return error.BadRequest; // bare CR
        if (req.headers_len == request_max_headers) return error.HeadersTooLarge;
        const h = try parseField(field);
        req.headers[req.headers_len] = h;
        req.headers_len += 1;
        switch (h.key.len) {
            4 => if (std.ascii.eqlIgnoreCase(h.key, "host")) {
                host_count +|= 1;
            },
            6 => if (std.ascii.eqlIgnoreCase(h.key, "expect")) {
                if (!std.ascii.eqlIgnoreCase(h.value, "100-continue")) return error.ExpectationFailed;
                expect_continue = true;
            },
            10 => if (std.ascii.eqlIgnoreCase(h.key, "connection")) {
                var it = std.mem.tokenizeAny(u8, h.value, ", \t");
                while (it.next()) |tok| {
                    if (std.ascii.eqlIgnoreCase(tok, "close")) conn_close = true;
                    if (std.ascii.eqlIgnoreCase(tok, "keep-alive")) conn_keep_alive = true;
                }
            },
            14 => if (std.ascii.eqlIgnoreCase(h.key, "content-length")) {
                if (content_length != null) return error.BadRequest;
                content_length = try parseContentLength(h.value);
            },
            17 => if (std.ascii.eqlIgnoreCase(h.key, "transfer-encoding")) {
                if (has_transfer_encoding) return error.BadRequest;
                has_transfer_encoding = true;
                if (!std.ascii.eqlIgnoreCase(h.value, "chunked")) return error.UnsupportedTransferCoding;
                chunked = true;
            },
            else => {},
        }
    }
    if (has_transfer_encoding) {
        // RFC 9112 §6.1: HTTP/1.0 with Transfer-Encoding is faulty framing.
        if (req.version == .@"HTTP/1.0") return error.BadRequest;
        // RFC 9112 §6.3: both present is a smuggling vector; reject.
        if (content_length != null) return error.BadRequest;
    }
    // RFC 9112 §3.2: exactly one Host in HTTP/1.1, at most one otherwise.
    if (host_count > 1 or (req.version == .@"HTTP/1.1" and host_count == 0)) {
        return error.BadRequest;
    }
    req.keep_alive = switch (req.version) {
        .@"HTTP/1.1" => !conn_close,
        .@"HTTP/1.0" => conn_keep_alive and !conn_close,
    };
    const framing: Framing = if (chunked)
        .chunked
    else if (content_length) |n|
        (if (n == 0) .none else .{ .length = n })
    else
        .none;
    return .{
        .len = head.len,
        .framing = framing,
        .expect_continue = expect_continue and framing != .none,
    };
}

fn parseField(field: []const u8) ParseError!Header {
    const colon = std.mem.indexOfScalar(u8, field, ':') orelse return error.BadRequest;
    const name = field[0..colon];
    // Rejects empty names, obs-fold (leading SP/HT) and whitespace before ':'.
    if (name.len == 0 or !isToken(name)) return error.BadRequest;
    var value = field[colon + 1 ..];
    while (value.len > 0 and (value[0] == ' ' or value[0] == '\t')) value = value[1..];
    while (value.len > 0 and (value[value.len - 1] == ' ' or value[value.len - 1] == '\t')) {
        value = value[0 .. value.len - 1];
    }
    if (!isFieldValue(value)) return error.BadRequest;
    return .{ .key = name, .value = value };
}

fn parseContentLength(value: []const u8) ParseError!usize {
    if (value.len == 0) return error.BadRequest;
    var n: usize = 0;
    for (value) |c| {
        if (c < '0' or c > '9') return error.BadRequest;
        n = std.math.mul(usize, n, 10) catch return error.PayloadTooLarge;
        n = std.math.add(usize, n, c - '0') catch return error.PayloadTooLarge;
    }
    return n;
}

/// RFC 9110 §5.6.2 tchar
const token_table: [256]bool = blk: {
    var t: [256]bool = @splat(false);
    for ("!#$%&'*+-.^_`|~") |c| t[c] = true;
    for ('0'..'9' + 1) |c| t[c] = true;
    for ('a'..'z' + 1) |c| t[c] = true;
    for ('A'..'Z' + 1) |c| t[c] = true;
    break :blk t;
};

inline fn isToken(s: []const u8) bool {
    for (s) |c| if (!token_table[c]) return false;
    return true;
}

/// Length of the request target: bytes up to the first SP or control byte.
/// Bytes >= 0x80 are accepted (raw UTF-8 paths are common in the wild).
inline fn targetLength(s: []const u8) usize {
    var i: usize = 0;
    while (i + vec_len <= s.len) : (i += vec_len) {
        const chunk: V = s[i..][0..vec_len].*;
        const stop = (chunk <= @as(V, @splat(' '))) | (chunk == @as(V, @splat(0x7f)));
        const mask: Mask = @bitCast(stop);
        if (mask != 0) return i + @ctz(mask);
    }
    while (i < s.len) : (i += 1) {
        if (s[i] <= ' ' or s[i] == 0x7f) return i;
    }
    return i;
}

/// field-value: VCHAR, SP, HTAB and obs-text. No other control bytes.
inline fn isFieldValue(s: []const u8) bool {
    var i: usize = 0;
    while (i + vec_len <= s.len) : (i += vec_len) {
        const chunk: V = s[i..][0..vec_len].*;
        const bad = ((chunk < @as(V, @splat(' '))) & (chunk != @as(V, @splat('\t')))) |
            (chunk == @as(V, @splat(0x7f)));
        if (@reduce(.Or, bad)) return false;
    }
    while (i < s.len) : (i += 1) {
        if ((s[i] < ' ' and s[i] != '\t') or s[i] == 0x7f) return false;
    }
    return true;
}

/// Incremental validator for a chunked body (RFC 9112 §7.1). It doesn't
/// modify the input, so it can resume as more data arrives. Once complete,
/// decodeChunked removes the framing in place. For a body handed to the
/// handler as it arrives, `next` decodes it piece by piece instead.
pub const ChunkedScanner = struct {
    const State = enum {
        size_first,
        size,
        ext_ws,
        ext,
        size_lf,
        data,
        data_cr,
        data_lf,
        trailer_start,
        trailer,
        trailer_lf,
        final_lf,
        done,
    };

    /// Longest chunk-size line (size and extensions).
    const max_line = 4096;

    state: State = .size_first,
    /// Bytes of raw (encoded) body consumed so far.
    pos: usize = 0,
    /// Chunk size being parsed, or chunk data remaining.
    n: u64 = 0,
    decoded: u64 = 0,
    /// Bytes of the current chunk-size line.
    line: u32 = 0,
    /// Where the trailer section starts in the raw body, once the last
    /// chunk has been seen.
    trailer_at: usize = 0,

    /// Returns true once the whole chunked body (including trailers) has been
    /// seen; `pos` is then its encoded length.
    pub fn scan(self: *ChunkedScanner, raw: []const u8, max_body: usize) ParseError!bool {
        // Bound framing overhead too (e.g. a flood of 1-byte chunks).
        const max_raw = max_body * 2 + 4096;
        while (self.pos < raw.len) {
            if (self.pos >= max_raw) return error.PayloadTooLarge;
            if (self.state == .data) {
                const take = @min(self.n, raw.len - self.pos);
                self.pos += @intCast(take);
                self.n -= take;
                if (self.n == 0) self.state = .data_cr;
                continue;
            }
            if (self.state == .done) return true;
            try self.step(raw[self.pos], max_body);
            self.pos += 1;
        }
        return self.state == .done;
    }

    /// What `next` found.
    pub const Piece = struct {
        /// Bytes at the start of `raw` the caller is done with (framing,
        /// and `data`): drop them before the next call.
        consumed: usize = 0,
        /// Body bytes, within raw[0..consumed].
        data: []const u8 = "",
        /// The body ended; `trailers` is its trailer section (field lines,
        /// each ending in CRLF), within raw[0..consumed].
        done: bool = false,
        trailers: []const u8 = "",
    };

    /// Decodes a body as it arrives: `raw` holds the bytes after those
    /// already consumed. Returns at the end of each run of data so the
    /// caller can hand it on. The body has no size limit; the trailer
    /// section is kept in `raw` until it is complete, up to `max_trailer`
    /// bytes.
    pub fn next(self: *ChunkedScanner, raw: []const u8, max_trailer: usize) ParseError!Piece {
        while (self.pos < raw.len) {
            switch (self.state) {
                .data => {
                    const take: usize = @intCast(@min(self.n, raw.len - self.pos));
                    const data = raw[self.pos..][0..take];
                    self.n -= take;
                    if (self.n == 0) self.state = .data_cr;
                    const consumed = self.pos + take;
                    self.pos = 0;
                    return .{ .consumed = consumed, .data = data };
                },
                .trailer_start, .trailer, .trailer_lf, .final_lf => {
                    if (self.pos - self.trailer_at >= max_trailer) return error.HeadersTooLarge;
                },
                .done => break,
                else => {},
            }
            try self.step(raw[self.pos], std.math.maxInt(u64));
            self.pos += 1;
            if (self.state == .done) {
                const consumed = self.pos;
                const section = raw[self.trailer_at .. consumed - 2];
                self.pos = 0;
                self.trailer_at = 0;
                return .{ .consumed = consumed, .done = true, .trailers = section };
            }
        }
        // Framing seen so far can go, except a trailer section in progress.
        const keep = switch (self.state) {
            .trailer_start, .trailer, .trailer_lf, .final_lf => self.trailer_at,
            else => self.pos,
        };
        self.pos -= keep;
        self.trailer_at = 0;
        return .{ .consumed = keep };
    }

    /// One byte of framing (any state but `data` and `done`).
    fn step(self: *ChunkedScanner, c: u8, max_body: u64) ParseError!void {
        switch (self.state) {
            .size_first, .size, .ext_ws, .ext => {
                self.line += 1;
                if (self.line > max_line) return error.BadRequest;
            },
            else => {},
        }
        switch (self.state) {
            .size_first, .size => {
                if (hexValue(c)) |d| {
                    if (self.n > (max_body >> 4)) return error.PayloadTooLarge;
                    self.n = (self.n << 4) | d;
                    self.state = .size;
                } else if (self.state == .size_first) {
                    return error.BadRequest;
                } else switch (c) {
                    '\r' => self.state = .size_lf,
                    ';' => self.state = .ext,
                    ' ', '\t' => self.state = .ext_ws,
                    else => return error.BadRequest,
                }
            },
            .ext_ws => switch (c) {
                ' ', '\t' => {},
                ';' => self.state = .ext,
                else => return error.BadRequest,
            },
            .ext => switch (c) {
                '\r' => self.state = .size_lf,
                '\n' => return error.BadRequest,
                else => if (c < ' ' and c != '\t' or c == 0x7f) return error.BadRequest,
            },
            .size_lf => {
                if (c != '\n') return error.BadRequest;
                self.line = 0;
                if (self.n == 0) {
                    self.state = .trailer_start;
                    self.trailer_at = self.pos + 1;
                } else {
                    self.decoded +|= self.n;
                    if (self.decoded > max_body) return error.PayloadTooLarge;
                    self.state = .data;
                }
            },
            .data_cr => {
                if (c != '\r') return error.BadRequest;
                self.state = .data_lf;
            },
            .data_lf => {
                if (c != '\n') return error.BadRequest;
                self.state = .size_first;
            },
            .trailer_start => switch (c) {
                '\r' => self.state = .final_lf,
                '\n' => return error.BadRequest,
                else => self.state = .trailer,
            },
            .trailer => switch (c) {
                '\r' => self.state = .trailer_lf,
                '\n' => return error.BadRequest,
                else => if (c < ' ' and c != '\t' or c == 0x7f) return error.BadRequest,
            },
            .trailer_lf => {
                if (c != '\n') return error.BadRequest;
                self.state = .trailer_start;
            },
            .final_lf => {
                if (c != '\n') return error.BadRequest;
                self.state = .done;
            },
            .data, .done => unreachable,
        }
    }

    /// The trailer section of a body `scan` found complete (field lines,
    /// each ending in CRLF).
    pub fn trailers(self: *const ChunkedScanner, raw: []const u8) []const u8 {
        return raw[self.trailer_at .. self.pos - 2];
    }

    inline fn hexValue(c: u8) ?u4 {
        return switch (c) {
            '0'...'9' => @intCast(c - '0'),
            'a'...'f' => @intCast(c - 'a' + 10),
            'A'...'F' => @intCast(c - 'A' + 10),
            else => null,
        };
    }
};

/// Parses a trailer section (field lines, each ending in CRLF, as the
/// chunked scanner delimits it) into `out`. Fields beyond `out.len` are
/// dropped. Returns how many were stored.
pub fn parseTrailers(section: []const u8, out: []Header) ParseError!usize {
    var n: usize = 0;
    var rest = section;
    while (rest.len > 0) {
        const cr = std.mem.indexOfScalar(u8, rest, '\r') orelse return error.BadRequest;
        const h = try parseField(rest[0..cr]);
        rest = rest[cr + 2 ..];
        if (n < out.len) {
            out[n] = h;
            n += 1;
        }
    }
    return n;
}

/// Removes chunked framing in place. `raw` must be a complete chunked body
/// already validated by ChunkedScanner. Returns the decoded length.
pub fn decodeChunked(raw: []u8) usize {
    var r: usize = 0;
    var w: usize = 0;
    while (true) {
        var size: usize = 0;
        while (ChunkedScanner.hexValue(raw[r])) |d| : (r += 1) size = (size << 4) | d;
        r = std.mem.indexOfScalarPos(u8, raw, r, '\n').? + 1;
        if (size == 0) return w;
        std.mem.copyForwards(u8, raw[w..][0..size], raw[r..][0..size]);
        w += size;
        r += size + 2;
    }
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

/// Comptime string repetition (0.17 removed the `**` operator).
pub fn repeat(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
    return comptime blk: {
        @setEvalBranchQuota(n * 10 + 1000);
        var out: [s.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
        const final = out;
        break :blk &final;
    };
}

fn testParse(raw: []const u8) !struct { *Request, Head } {
    const req = try testing.allocator.create(Request);
    req.* = .{ .allocator = testing.allocator, .query = .init(testing.allocator) };
    errdefer testing.allocator.destroy(req);
    var scan: usize = 0;
    const len = (try findHeadEnd(raw, &scan, .{})) orelse return error.BadRequest;
    const head = try parseHead(raw[0..len], req, .{});
    return .{ req, head };
}

fn expectParseError(expected: ParseError, raw: []const u8) !void {
    if (testParse(raw)) |res| {
        testing.allocator.destroy(res[0]);
        std.debug.print("expected {s} for {any}\n", .{ @errorName(expected), raw });
        return error.TestExpectedError;
    } else |err| try testing.expectEqual(@as(anyerror, expected), err);
}

test "parse GET request" {
    const req, const head = try testParse(
        "GET /path/to/resource?x=1 HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "User-Agent: test-client\r\n" ++
            "Accept:*/*\r\n" ++
            "X-Spaces: \t padded value \t\r\n" ++
            "Connection: keep-alive\r\n\r\n",
    );
    defer testing.allocator.destroy(req);
    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/path/to/resource?x=1", req.path_and_query);
    try testing.expectEqualStrings("/path/to/resource", req.getPath());
    try testing.expectEqual(Version.@"HTTP/1.1", req.version);
    try testing.expectEqual(5, req.headers_len);
    try testing.expectEqualStrings("Host", req.headers[0].key);
    try testing.expectEqualStrings("example.com", req.headers[0].value);
    try testing.expectEqualStrings("*/*", req.findHeader("accept").?);
    try testing.expectEqualStrings("padded value", req.findHeader("x-spaces").?);
    try testing.expect(req.keep_alive);
    try testing.expectEqual(Framing.none, head.framing);
}

test "keep-alive semantics" {
    {
        const req, _ = try testParse("GET / HTTP/1.1\r\nHost: a\r\nConnection: Close\r\n\r\n");
        defer testing.allocator.destroy(req);
        try testing.expect(!req.keep_alive);
    }
    {
        const req, _ = try testParse("GET / HTTP/1.1\r\nHost: a\r\nConnection: Upgrade, close\r\n\r\n");
        defer testing.allocator.destroy(req);
        try testing.expect(!req.keep_alive);
    }
    {
        const req, _ = try testParse("GET / HTTP/1.0\r\n\r\n");
        defer testing.allocator.destroy(req);
        try testing.expect(!req.keep_alive);
    }
    {
        const req, _ = try testParse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        defer testing.allocator.destroy(req);
        try testing.expect(req.keep_alive);
    }
}

test "framing" {
    {
        const req, const head = try testParse("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n");
        defer testing.allocator.destroy(req);
        try testing.expectEqual(Framing{ .length = 12 }, head.framing);
    }
    {
        const req, const head = try testParse("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked\r\n\r\n");
        defer testing.allocator.destroy(req);
        try testing.expectEqual(Framing.chunked, head.framing);
    }
    {
        const req, const head = try testParse("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n");
        defer testing.allocator.destroy(req);
        try testing.expect(head.expect_continue);
    }
}

test "malformed and smuggling requests are rejected" {
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\nHost: a\r\nabc :x\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\nHost: a\nX: b\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\nHost: a\r\nX: \x00\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\nHost: a\r\nnovalue\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\nHost: a\r\n: v\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\n\r\n"); // missing Host
    try expectParseError(error.BadRequest, "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
    try expectParseError(error.BadRequest, "GET  / HTTP/1.1\r\nHost: a\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTP/1.1 \r\nHost: a\r\n\r\n");
    try expectParseError(error.BadRequest, "GET /a\x01b HTTP/1.1\r\nHost: a\r\n\r\n");
    try expectParseError(error.BadRequest, "GET / HTTX/1.1\r\nHost: a\r\n\r\n");
    try expectParseError(error.BadRequest, "\nGET / HTTP/1.1\r\nHost: a\r\n\r\n");
    try expectParseError(error.UnsupportedVersion, "GET / HTTP/2.0\r\nHost: a\r\n\r\n");
    try expectParseError(error.UnknownMethod, "PROPFIND / HTTP/1.1\r\nHost: a\r\n\r\n");
    try expectParseError(error.UnknownMethod, "GARBAGE / HTTP/1.1\r\nHost: a\r\n\r\n");
    // Framing conflicts
    try expectParseError(error.BadRequest, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n");
    try expectParseError(error.BadRequest, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n");
    try expectParseError(error.BadRequest, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +1\r\n\r\n");
    try expectParseError(error.BadRequest, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 1\r\n\r\n");
    try expectParseError(error.BadRequest, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length:\r\n\r\n");
    try expectParseError(error.BadRequest, "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n");
    try expectParseError(error.BadRequest, "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n");
    try expectParseError(error.UnsupportedTransferCoding, "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n");
    try expectParseError(error.PayloadTooLarge, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999999\r\n\r\n");
    try expectParseError(error.ExpectationFailed, "POST / HTTP/1.1\r\nHost: a\r\nExpect: something\r\n\r\n");
}

test "empty header value is valid" {
    // Regression: "abc:" crashed the old header parser (integer underflow).
    const req, _ = try testParse("GET / HTTP/1.1\r\nHost: a\r\nabc:\r\nx:  \r\n\r\n");
    defer testing.allocator.destroy(req);
    try testing.expectEqualStrings("", req.findHeader("abc").?);
    try testing.expectEqualStrings("", req.findHeader("x").?);
}

test "long header values are accepted" {
    const cookie = "c=" ++ repeat("x", 4000);
    const req, _ = try testParse("GET / HTTP/1.1\r\nHost: a\r\nCookie: " ++ cookie ++ "\r\n\r\n");
    defer testing.allocator.destroy(req);
    try testing.expectEqualStrings(cookie, req.findHeader("cookie").?);
}

test "too many headers" {
    const line = "X-H: v\r\n";
    try expectParseError(error.HeadersTooLarge, "GET / HTTP/1.1\r\nHost: a\r\n" ++ repeat(line, request_max_headers) ++ "\r\n");
}

test "findHeadEnd resumes and enforces limits" {
    const raw = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    var scan: usize = 0;
    // Feed one byte at a time.
    for (1..raw.len) |n| {
        try testing.expectEqual(@as(?usize, null), try findHeadEnd(raw[0..n], &scan, .{}));
    }
    try testing.expectEqual(@as(?usize, raw.len), try findHeadEnd(raw, &scan, .{}));

    var big: [20 * 1024]u8 = @splat('a');
    scan = 0;
    try testing.expectError(error.UriTooLong, findHeadEnd(&big, &scan, .{}));
    @memcpy(big[0..16], "GET / HTTP/1.1\r\n");
    scan = 0;
    try testing.expectError(error.HeadersTooLarge, findHeadEnd(&big, &scan, .{}));
}

test "chunked decoding" {
    var raw = "4\r\nWiki\r\n5;ext=1\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nTrailer: x\r\n\r\nNEXT".*;
    var s: ChunkedScanner = .{};
    // Byte-by-byte to exercise resumption.
    const body_len = raw.len - "NEXT".len;
    for (1..body_len) |n| try testing.expect(!try s.scan(raw[0..n], 1024));
    try testing.expect(try s.scan(raw[0..], 1024));
    try testing.expectEqual(body_len, s.pos);
    const n = decodeChunked(raw[0..s.pos]);
    try testing.expectEqualStrings("Wikipedia in\r\n\r\nchunks.", raw[0..n]);
}

test "malformed chunked bodies are rejected" {
    const cases = [_][]const u8{
        "x\r\n",
        "\r\n",
        "4\nWiki\r\n0\r\n\r\n", // bare LF after size
        "4\r\nWikiX\r\n0\r\n\r\n", // data longer than size
        "4\r\nWiki\n0\r\n\r\n",
        "4;a\nb\r\nWiki\r\n0\r\n\r\n", // bare LF in extension
        "4 x\r\nWiki\r\n0\r\n\r\n",
        "0\r\nTrailer: x\n\r\n",
        "0\r\n\n",
    };
    for (cases) |raw| {
        var s: ChunkedScanner = .{};
        try testing.expectError(error.BadRequest, s.scan(raw, 1024));
    }
    var s: ChunkedScanner = .{};
    try testing.expectError(error.PayloadTooLarge, s.scan("FFFFFFFFFFFFFFFFFFFF\r\n", 1024));
    s = .{};
    try testing.expectError(error.PayloadTooLarge, s.scan("401\r\n", 1024));
}

test "chunked trailers" {
    const raw = "3\r\nabc\r\n0\r\nX-Sum: 1\r\nOther:\tv \r\n\r\n";
    var s: ChunkedScanner = .{};
    try testing.expect(try s.scan(raw, 1024));
    var out: [4]Header = undefined;
    const n = try parseTrailers(s.trailers(raw), &out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("X-Sum", out[0].key);
    try testing.expectEqualStrings("1", out[0].value);
    try testing.expectEqualStrings("v", out[1].value);
    // Fields beyond the room given are dropped; malformed ones rejected.
    try testing.expectEqual(@as(usize, 1), try parseTrailers("A: 1\r\nB: 2\r\n", out[0..1]));
    try testing.expectError(error.BadRequest, parseTrailers("no colon\r\n", &out));
    try testing.expectError(error.BadRequest, parseTrailers("A : 1\r\n", &out));
    // No trailers.
    s = .{};
    try testing.expect(try s.scan("0\r\n\r\n", 1024));
    try testing.expectEqual(@as(usize, 0), s.trailers("0\r\n\r\n").len);
}

/// Decodes `raw` with `next`, fed in pieces of at most `max_piece` bytes
/// the way a session would (dropping consumed bytes, keeping the rest).
fn decodeStreaming(raw: []const u8, max_piece: usize, body: *std.ArrayList(u8), trailers: *std.ArrayList(u8)) !usize {
    var s: ChunkedScanner = .{};
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var fed: usize = 0;
    while (true) {
        const piece = try s.next(buf.items, 1024);
        try body.appendSlice(testing.allocator, piece.data);
        if (piece.done) {
            try trailers.appendSlice(testing.allocator, piece.trailers);
            return fed - (buf.items.len - piece.consumed);
        }
        std.mem.copyForwards(u8, buf.items[0 .. buf.items.len - piece.consumed], buf.items[piece.consumed..]);
        buf.items.len -= piece.consumed;
        if (piece.data.len > 0) continue;
        if (fed == raw.len) return error.EndOfStream;
        const n = @min(max_piece, raw.len - fed);
        try buf.appendSlice(testing.allocator, raw[fed..][0..n]);
        fed += n;
    }
}

test "streaming chunked decode: any split gives the same body and trailers" {
    const raw = "4\r\nWiki\r\n5;ext=1\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nT: x\r\nU: y\r\n\r\nNEXT";
    for ([_]usize{ 1, 2, 3, 7, 64, 1000 }) |max_piece| {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(testing.allocator);
        var trailers: std.ArrayList(u8) = .empty;
        defer trailers.deinit(testing.allocator);
        const used = try decodeStreaming(raw, max_piece, &body, &trailers);
        try testing.expectEqualStrings("Wikipedia in\r\n\r\nchunks.", body.items);
        try testing.expectEqualStrings("T: x\r\nU: y\r\n", trailers.items);
        try testing.expectEqual(raw.len - "NEXT".len, used);
    }
}

test "streaming chunked decode: errors and limits" {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    var trailers: std.ArrayList(u8) = .empty;
    defer trailers.deinit(testing.allocator);
    try testing.expectError(error.BadRequest, decodeStreaming("4\r\nWikiX\r\n0\r\n\r\n", 3, &body, &trailers));
    // No body limit, but chunk-size lines and trailers are bounded.
    const big = "FFFFFFFFFFFF\r\n";
    var s: ChunkedScanner = .{};
    const p = try s.next(big, 1024);
    try testing.expectEqual(big.len, p.consumed);
    try testing.expectEqual(@as(u64, 0xFFFFFFFFFFFF), s.n);
    s = .{};
    const ext = "1;" ++ repeat("e", 5000);
    try testing.expectError(error.BadRequest, s.next(ext, 1024));
    s = .{};
    const long_trailer = "0\r\nX: " ++ repeat("t", 2000) ++ "\r\n\r\n";
    try testing.expectError(error.HeadersTooLarge, s.next(long_trailer, 1024));
}
