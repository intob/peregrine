//! Request fields decoded from HPACK or QPACK, validated as RFC 9113 §8.2
//! and §8.3 (HTTP/2) and RFC 9114 §4.2 and §4.3 (HTTP/3) require, and
//! stored for the handler: names and values back to back in one buffer,
//! then the body, then any trailers.
const std = @import("std");
const Request = @import("../request.zig").Request;
const Header = @import("../header.zig").Header;
const Method = @import("../method.zig").Method;
const MAX_HEADERS = @import("../request.zig").MAX_HEADERS;

pub const HeaderRef = struct { name_off: u32, name_len: u32, value_len: u32 };

pub const Fault = enum(u8) {
    /// A malformed request: a stream error (h2 PROTOCOL_ERROR, h3
    /// H3_MESSAGE_ERROR).
    protocol,
    /// Too many or too large headers: 431.
    headers_too_large,
    /// Unknown method, or a CONNECT that isn't extended: 501.
    not_implemented,
    /// Body over the limit: 413.
    body_too_large,
};

pub const Fields = struct {
    const Self = @This();

    buf: std.ArrayList(u8) = .empty,
    hdr: [MAX_HEADERS]HeaderRef = undefined,
    hdr_count: u16 = 0,
    method: ?HeaderRef = null,
    path: ?HeaderRef = null,
    scheme: ?HeaderRef = null,
    authority: ?HeaderRef = null,
    /// Extended CONNECT (RFC 8441, RFC 9220), when the sink allowed it.
    protocol: ?HeaderRef = null,
    has_host: bool = false,
    regular_seen: bool = false,
    body_start: usize = 0,
    content_length: ?u64 = null,
    body_received: u64 = 0,
    fault: ?Fault = null,
    /// Trailers: names and values from `trl_off` in `buf`, references
    /// after the headers' in `hdr`.
    trl_off: usize = 0,
    trl_count: u16 = 0,

    pub fn clear(self: *Self) void {
        self.buf.clearRetainingCapacity();
        self.* = .{ .buf = self.buf };
    }

    pub fn deinit(self: *Self, a: std.mem.Allocator) void {
        self.buf.deinit(a);
    }

    pub fn value(self: *const Self, ref: HeaderRef) []const u8 {
        return self.buf.items[ref.name_off + ref.name_len ..][0..ref.value_len];
    }

    pub fn body(self: *const Self) []const u8 {
        return self.buf.items[self.body_start..if (self.trl_count > 0) self.trl_off else self.buf.items.len];
    }

    /// A sink for the trailer section, stored after the body.
    pub fn trailerSink(self: *Self, a: std.mem.Allocator) TrailerStore {
        self.trl_off = self.buf.items.len;
        return .{ .buf = &self.buf, .allocator = a, .refs = self.hdr[self.hdr_count..], .count = &self.trl_count };
    }

    /// The trailers as headers, written into `out` (valid as long as
    /// `buf` is unchanged).
    pub fn trailers(self: *const Self, out: []Header) []const Header {
        return resolve(self.buf.items, self.hdr[self.hdr_count..][0..self.trl_count], out);
    }

    pub fn sink(self: *Self, a: std.mem.Allocator) RequestSink {
        return .{ .fields = self, .allocator = a };
    }

    /// The field section is complete: synthesise `host` from :authority
    /// for handlers written for HTTP/1.1 and check the pseudo-header
    /// fields. The declared body size is checked by `limitBody`, unless
    /// the handler streams the body.
    pub fn endHead(self: *Self, a: std.mem.Allocator) std.mem.Allocator.Error!void {
        if (self.fault == null and !self.has_host and self.authority != null and self.hdr_count < MAX_HEADERS) {
            const auth = self.value(self.authority.?);
            const off = self.buf.items.len;
            try self.buf.ensureUnusedCapacity(a, 4 + auth.len);
            self.buf.appendSliceAssumeCapacity("host");
            self.buf.appendSliceAssumeCapacity(self.value(self.authority.?));
            self.hdr[self.hdr_count] = .{ .name_off = @intCast(off), .name_len = 4, .value_len = @intCast(auth.len) };
            self.hdr_count += 1;
        }
        self.body_start = self.buf.items.len;
        if (self.fault == null) self.validate();
    }

    /// A body to be buffered: a declared length over `max` is a fault.
    pub fn limitBody(self: *Self, max: usize) void {
        if (self.fault != null) return;
        if (self.content_length) |cl| {
            if (cl > max) self.fault = .body_too_large;
        }
    }

    /// A valid extended CONNECT: the stream carries the protocol named
    /// by :protocol once the handler accepts it.
    pub fn isExtendedConnect(self: *const Self) bool {
        return self.protocol != null and self.fault == null;
    }

    /// The required pseudo-header fields (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
    fn validate(self: *Self) void {
        const method = self.method orelse {
            self.fault = .protocol;
            return;
        };
        const connect = std.mem.eql(u8, self.value(method), "CONNECT");
        if (self.protocol != null) {
            // Extended CONNECT (RFC 8441 §4, RFC 9220 §3): only on
            // CONNECT, which then has :scheme and :path like any request.
            if (!connect) {
                self.fault = .protocol;
                return;
            }
        } else if (connect) {
            // No :scheme or :path. A proxy's CONNECT: not supported.
            self.fault = if (self.scheme != null or self.path != null) .protocol else .not_implemented;
            return;
        }
        const path = self.path orelse {
            self.fault = .protocol;
            return;
        };
        const scheme = self.scheme orelse {
            self.fault = .protocol;
            return;
        };
        if (path.value_len == 0) self.fault = .protocol;
        // http and https URIs have an authority: the request names it in
        // :authority or Host (RFC 9113 §8.3.1, RFC 9114 §4.3.1).
        const s = self.value(scheme);
        if ((std.mem.eql(u8, s, "https") or std.mem.eql(u8, s, "http")) and self.authority == null and !self.has_host)
            self.fault = .protocol;
    }

    /// Appends request body bytes, up to `max` in all (then body_too_large).
    pub fn appendBody(self: *Self, a: std.mem.Allocator, data: []const u8, max: usize) std.mem.Allocator.Error!void {
        self.body_received += data.len;
        if (self.fault != null) return;
        if (self.body().len + data.len > max) {
            self.fault = .body_too_large;
            return;
        }
        try self.buf.appendSlice(a, data);
    }

    /// The received body matches a declared content-length.
    pub fn lengthMatches(self: *const Self) bool {
        return if (self.content_length) |cl| self.body_received == cl else true;
    }

    /// Fills the worker's Request. Returns false for an unknown method.
    pub fn fill(self: *const Self, req: *Request) bool {
        req.reset();
        req.version = .@"HTTP/1.1";
        req.method = Method.parse(self.value(self.method.?)) catch return false;
        req.path_and_query = self.value(self.path.?);
        req.protocol = if (self.protocol) |p| self.value(p) else null;
        for (self.hdr[0..self.hdr_count], 0..) |h, i| {
            req.headers[i] = .{
                .key = self.buf.items[h.name_off..][0..h.name_len],
                .value = self.buf.items[h.name_off + h.name_len ..][0..h.value_len],
            };
        }
        req.headers_len = self.hdr_count;
        req.body = self.body();
        req.trailers = self.trailers(req.headers[self.hdr_count..]);
        return true;
    }
};

/// Takes decoded fields one at a time (the HPACK and QPACK decoders' sink).
pub const RequestSink = struct {
    fields: *Fields,
    allocator: std.mem.Allocator,
    /// Accept :protocol (we sent SETTINGS_ENABLE_CONNECT_PROTOCOL);
    /// otherwise it is an unknown pseudo-header field.
    allow_protocol: bool = false,

    pub fn header(self: *RequestSink, name: []const u8, val: []const u8) !void {
        const s = self.fields;
        if (s.fault != null) return;
        if (name.len == 0) {
            s.fault = .protocol;
            return;
        }
        // Field values must not contain NUL, CR or LF, nor start or end
        // with whitespace.
        for (val) |c| {
            if (c == 0 or c == '\r' or c == '\n') {
                s.fault = .protocol;
                return;
            }
        }
        if (val.len > 0 and (val[0] == ' ' or val[0] == '\t' or val[val.len - 1] == ' ' or val[val.len - 1] == '\t')) {
            s.fault = .protocol;
            return;
        }
        if (name[0] == ':') {
            // Pseudo-header fields come first, each at most once, only the
            // request ones.
            if (s.regular_seen) {
                s.fault = .protocol;
                return;
            }
            const ref = try self.store(name, val);
            const target: *?HeaderRef = if (std.mem.eql(u8, name, ":method"))
                &s.method
            else if (std.mem.eql(u8, name, ":path"))
                &s.path
            else if (std.mem.eql(u8, name, ":scheme"))
                &s.scheme
            else if (std.mem.eql(u8, name, ":authority"))
                &s.authority
            else if (self.allow_protocol and std.mem.eql(u8, name, ":protocol"))
                &s.protocol
            else {
                s.fault = .protocol;
                return;
            };
            if (target.* != null) {
                s.fault = .protocol;
                return;
            }
            target.* = ref;
            return;
        }
        s.regular_seen = true;
        for (name) |c| {
            // Lowercase token characters only.
            if (c >= 'A' and c <= 'Z' or !isTokenChar(c)) {
                s.fault = .protocol;
                return;
            }
        }
        // Connection-specific fields are forbidden; TE only "trailers".
        if (std.mem.eql(u8, name, "connection") or std.mem.eql(u8, name, "keep-alive") or
            std.mem.eql(u8, name, "proxy-connection") or std.mem.eql(u8, name, "transfer-encoding") or
            std.mem.eql(u8, name, "upgrade"))
        {
            s.fault = .protocol;
            return;
        }
        if (std.mem.eql(u8, name, "te") and !std.mem.eql(u8, val, "trailers")) {
            s.fault = .protocol;
            return;
        }
        if (std.mem.eql(u8, name, "content-length")) {
            const n = std.fmt.parseInt(u64, val, 10) catch {
                s.fault = .protocol;
                return;
            };
            if (val.len == 0 or val[0] == '+' or val[0] == '-' or (s.content_length != null and s.content_length.? != n)) {
                s.fault = .protocol;
                return;
            }
            s.content_length = n;
        }
        if (std.mem.eql(u8, name, "host")) s.has_host = true;
        if (s.hdr_count >= MAX_HEADERS) {
            s.fault = .headers_too_large;
            return;
        }
        s.hdr[s.hdr_count] = try self.store(name, val);
        s.hdr_count += 1;
    }

    fn store(self: *RequestSink, name: []const u8, val: []const u8) !HeaderRef {
        const s = self.fields;
        const off = s.buf.items.len;
        try s.buf.ensureUnusedCapacity(self.allocator, name.len + val.len);
        s.buf.appendSliceAssumeCapacity(name);
        s.buf.appendSliceAssumeCapacity(val);
        return .{ .name_off = @intCast(off), .name_len = @intCast(name.len), .value_len = @intCast(val.len) };
    }
};

/// Validates trailer fields as RequestSink does regular ones (no
/// pseudo-header fields) and stores them: names and values appended to
/// `buf`, references in `refs`. Fields beyond `refs.len` are dropped.
pub const TrailerStore = struct {
    buf: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    refs: []HeaderRef,
    count: *u16,
    fault: bool = false,

    pub fn header(self: *TrailerStore, name: []const u8, val: []const u8) !void {
        if (name.len == 0 or name[0] == ':') self.fault = true;
        for (name) |c| {
            if (c >= 'A' and c <= 'Z' or !isTokenChar(c)) self.fault = true;
        }
        for (val) |c| {
            if (c == 0 or c == '\r' or c == '\n') self.fault = true;
        }
        if (val.len > 0 and (val[0] == ' ' or val[0] == '\t' or val[val.len - 1] == ' ' or val[val.len - 1] == '\t')) self.fault = true;
        if (self.fault or self.count.* >= self.refs.len) return;
        const off = self.buf.items.len;
        try self.buf.ensureUnusedCapacity(self.allocator, name.len + val.len);
        self.buf.appendSliceAssumeCapacity(name);
        self.buf.appendSliceAssumeCapacity(val);
        self.refs[self.count.*] = .{ .name_off = @intCast(off), .name_len = @intCast(name.len), .value_len = @intCast(val.len) };
        self.count.* += 1;
    }
};

/// Headers for stored references, written into `out`.
pub fn resolve(buf: []const u8, refs: []const HeaderRef, out: []Header) []const Header {
    const n = @min(refs.len, out.len);
    for (refs[0..n], out[0..n]) |r, *h| {
        h.* = .{ .key = buf[r.name_off..][0..r.name_len], .value = buf[r.name_off + r.name_len ..][0..r.value_len] };
    }
    return out[0..n];
}

pub const DiscardSink = struct {
    pub fn header(_: *DiscardSink, _: []const u8, _: []const u8) !void {}
};

pub fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// Calls `encode(name, value)` for each "Name: value\r\n" line of a
/// response head, with the name lowercased in place (HTTP/2 and HTTP/3
/// field names are lowercase).
pub fn forEachLine(lines: []const u8, ctx: anytype, comptime encode: anytype) !void {
    var rest = lines;
    while (rest.len > 0) {
        const eol = std.mem.indexOf(u8, rest, "\r\n") orelse break;
        const line = rest[0..eol];
        rest = rest[eol + 2 ..];
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = @constCast(line[0..colon]);
        for (name) |*c| c.* = std.ascii.toLower(c.*);
        try encode(ctx, name, std.mem.trim(u8, line[colon + 1 ..], " \t"));
    }
}

const testing = std.testing;

test "request fields: valid, malformed, host synthesis" {
    const a = testing.allocator;
    var f: Fields = .{};
    defer f.deinit(a);
    var s = f.sink(a);
    try s.header(":method", "GET");
    try s.header(":scheme", "https");
    try s.header(":authority", "example.com");
    try s.header(":path", "/x?y");
    try s.header("accept", "*/*");
    try f.endHead(a);
    f.limitBody(1024);
    try testing.expectEqual(@as(?Fault, null), f.fault);
    try testing.expectEqual(@as(u16, 2), f.hdr_count);
    var req = try Request.init(a);
    defer req.deinit();
    try testing.expect(f.fill(req));
    try testing.expectEqualStrings("/x?y", req.path_and_query);
    try testing.expectEqualStrings("example.com", req.findHeader("Host").?);

    const cases = [_][]const [2][]const u8{
        &.{ .{ ":method", "GET" }, .{ ":path", "/" } }, // no :scheme
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" } }, // no :path
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ ":path", "/" } },
        &.{ .{ ":method", "GET" }, .{ "a", "b" }, .{ ":scheme", "https" }, .{ ":path", "/" } },
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ "Upper", "x" } },
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ "connection", "close" } },
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ "te", "gzip" } },
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ "x", " lead" } },
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ "content-length", "+5" } },
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ ":status", "200" } },
        &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" } }, // no authority or host
    };
    for (cases) |c| {
        f.clear();
        s = f.sink(a);
        for (c) |kv| try s.header(kv[0], kv[1]);
        try f.endHead(a);
        try testing.expectEqual(@as(?Fault, .protocol), f.fault);
    }
    f.clear();
    s = f.sink(a);
    try s.header(":method", "POST");
    try s.header(":scheme", "https");
    try s.header(":authority", "example.com");
    try s.header(":path", "/");
    try s.header("content-length", "5000");
    try f.endHead(a);
    try testing.expectEqual(@as(?Fault, null), f.fault);
    f.limitBody(1024);
    try testing.expectEqual(@as(?Fault, .body_too_large), f.fault);
}

test "extended CONNECT: :protocol only when allowed, only on CONNECT, with :scheme and :path" {
    const a = testing.allocator;
    var f: Fields = .{};
    defer f.deinit(a);
    var req = try Request.init(a);
    defer req.deinit();
    const ok = [_][2][]const u8{ .{ ":method", "CONNECT" }, .{ ":protocol", "websocket" }, .{ ":scheme", "https" }, .{ ":path", "/chat" }, .{ ":authority", "example.com" } };
    var s = f.sink(a);
    s.allow_protocol = true;
    for (ok) |kv| try s.header(kv[0], kv[1]);
    try f.endHead(a);
    try testing.expect(f.isExtendedConnect());
    try testing.expect(f.fill(req));
    try testing.expectEqual(.CONNECT, req.method);
    try testing.expectEqualStrings("websocket", req.protocol.?);
    try testing.expectEqualStrings("/chat", req.path_and_query);
    // Not allowed: an unknown pseudo-header field.
    f.clear();
    s = f.sink(a);
    for (ok) |kv| try s.header(kv[0], kv[1]);
    try f.endHead(a);
    try testing.expectEqual(@as(?Fault, .protocol), f.fault);
    const bad = [_][]const [2][]const u8{
        &.{ .{ ":method", "GET" }, .{ ":protocol", "websocket" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ ":authority", "a" } },
        &.{ .{ ":method", "CONNECT" }, .{ ":protocol", "websocket" }, .{ ":scheme", "https" }, .{ ":authority", "a" } },
        &.{ .{ ":method", "CONNECT" }, .{ ":protocol", "websocket" }, .{ ":path", "/" }, .{ ":authority", "a" } },
        &.{ .{ ":method", "CONNECT" }, .{ ":protocol", "websocket" }, .{ ":protocol", "websocket" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ ":authority", "a" } },
    };
    for (bad) |c| {
        f.clear();
        s = f.sink(a);
        s.allow_protocol = true;
        for (c) |kv| try s.header(kv[0], kv[1]);
        try f.endHead(a);
        try testing.expectEqual(@as(?Fault, .protocol), f.fault);
        try testing.expect(!f.isExtendedConnect());
    }
    // A plain CONNECT is still 501, and leaves req.protocol null.
    f.clear();
    s = f.sink(a);
    s.allow_protocol = true;
    try s.header(":method", "CONNECT");
    try s.header(":authority", "example.com:443");
    try f.endHead(a);
    try testing.expectEqual(@as(?Fault, .not_implemented), f.fault);
}

test "trailers: stored after the body, validated, extra ones dropped" {
    const a = testing.allocator;
    var f: Fields = .{};
    defer f.deinit(a);
    var s = f.sink(a);
    try s.header(":method", "POST");
    try s.header(":scheme", "https");
    try s.header(":authority", "example.com");
    try s.header(":path", "/");
    try f.endHead(a);
    try f.appendBody(a, "body", 1024);
    var t = f.trailerSink(a);
    try t.header("x-sum", "4");
    try t.header("x-b", "two");
    try testing.expect(!t.fault);
    var req = try Request.init(a);
    defer req.deinit();
    try testing.expect(f.fill(req));
    try testing.expectEqualStrings("body", req.body);
    try testing.expectEqual(@as(usize, 2), req.trailers.len);
    try testing.expectEqualStrings("x-sum", req.trailers[0].key);
    try testing.expectEqualStrings("two", req.trailers[1].value);
    for ([_][2][]const u8{ .{ ":path", "/" }, .{ "Upper", "x" }, .{ "x", " lead" }, .{ "x", "a\nb" } }) |kv| {
        var bad = f.trailerSink(a);
        try bad.header(kv[0], kv[1]);
        try testing.expect(bad.fault);
    }
}
