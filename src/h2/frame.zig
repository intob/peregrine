//! HTTP/2 framing (RFC 9113 §4, §6): an I/O-free parser and serialiser.
//! The Reader buffers input like the HTTP/1.1 Session: a pooled buffer
//! held only while bytes are unprocessed, grown for a frame larger than a
//! pool buffer. `next` returns one frame at a time, with payload slices
//! into the buffer that are valid until the next call. Every length, flag,
//! padding and stream identifier rule of the frame definitions is checked
//! here and mapped to the error the RFC names; rules that depend on
//! connection or stream state belong to conn.zig.
const std = @import("std");
const BufferPool = @import("../http/session.zig").BufferPool;

pub const header_len = 9;
/// The client connection preface (§3.4).
pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// SETTINGS_MAX_FRAME_SIZE bounds (§6.5.2).
pub const min_max_frame_size: u32 = 1 << 14;
pub const max_max_frame_size: u32 = (1 << 24) - 1;
pub const max_window_size: u32 = (1 << 31) - 1;

pub const FrameType = enum(u8) {
    data = 0,
    headers = 1,
    priority = 2,
    rst_stream = 3,
    settings = 4,
    push_promise = 5,
    ping = 6,
    goaway = 7,
    window_update = 8,
    continuation = 9,
    _,
};

pub const ErrorCode = enum(u32) {
    no_error = 0,
    protocol_error = 1,
    internal_error = 2,
    flow_control_error = 3,
    settings_timeout = 4,
    stream_closed = 5,
    frame_size_error = 6,
    refused_stream = 7,
    cancel = 8,
    compression_error = 9,
    connect_error = 10,
    enhance_your_calm = 11,
    inadequate_security = 12,
    http_1_1_required = 13,
    _,
};

pub const flag = struct {
    pub const end_stream: u8 = 0x1;
    pub const ack: u8 = 0x1;
    pub const end_headers: u8 = 0x4;
    pub const padded: u8 = 0x8;
    pub const priority: u8 = 0x20;
};

pub const SettingId = enum(u16) {
    header_table_size = 1,
    enable_push = 2,
    max_concurrent_streams = 3,
    initial_window_size = 4,
    max_frame_size = 5,
    max_header_list_size = 6,
    _,
};

pub const Setting = struct { id: SettingId, value: u32 };

/// A frame-level violation, consumed when it is a stream error (the
/// stream is reset and parsing continues) and final when it is a
/// connection error.
pub const Failure = struct {
    code: ErrorCode,
    /// 0 for a connection error.
    stream_id: u31,

    fn connection(code: ErrorCode) Failure {
        return .{ .code = code, .stream_id = 0 };
    }
};

pub const Frame = union(enum) {
    data: struct {
        stream_id: u31,
        end_stream: bool,
        data: []const u8,
        /// The whole payload, padding included: what flow control counts.
        flow_len: u32,
    },
    headers: struct {
        stream_id: u31,
        end_stream: bool,
        end_headers: bool,
        fragment: []const u8,
    },
    /// Priority signals are ignored (RFC 9113 §5.3.1), but still validated.
    priority: struct { stream_id: u31 },
    rst_stream: struct { stream_id: u31, code: ErrorCode },
    settings: SettingsFrame,
    ping: struct { ack: bool, data: *const [8]u8 },
    goaway: struct { last_stream_id: u31, code: ErrorCode, debug: []const u8 },
    window_update: struct { stream_id: u31, increment: u31 },
    continuation: struct { stream_id: u31, end_headers: bool, fragment: []const u8 },
    /// A type this implementation doesn't know, including RFC 9218
    /// PRIORITY_UPDATE: ignored (§4.1), unless it interrupts a field block.
    unknown: struct { type: u8, stream_id: u31 },
};

pub const SettingsFrame = struct {
    ack: bool,
    /// Validated 6-byte settings, in order (later values win).
    raw: []const u8,

    pub const Iterator = struct {
        raw: []const u8,

        pub fn next(self: *Iterator) ?Setting {
            if (self.raw.len == 0) return null;
            const s: Setting = .{
                .id = @fromBackingInt(std.mem.readInt(u16, self.raw[0..2], .big)),
                .value = std.mem.readInt(u32, self.raw[2..6], .big),
            };
            self.raw = self.raw[6..];
            return s;
        }
    };

    pub fn iterator(self: SettingsFrame) Iterator {
        return .{ .raw = self.raw };
    }
};

pub const Result = union(enum) {
    need_more,
    frame: Frame,
    failure: Failure,
};

pub const Options = struct {
    /// What we advertised as SETTINGS_MAX_FRAME_SIZE.
    max_frame_size: u32 = min_max_frame_size,
};

pub const Reader = struct {
    const Self = @This();

    buf: []u8 = &.{},
    start: usize = 0,
    end: usize = 0,
    /// The buffer is from the allocator, not the pool (grown for a large
    /// frame).
    grown: bool = false,

    pub inline fn buffered(self: *const Self) usize {
        return self.end - self.start;
    }

    /// Returns space to read into, acquiring, compacting or growing the
    /// buffer as needed. A frame up to max_frame_size always fits.
    pub fn readSpace(self: *Self, pool: *BufferPool, opts: Options) ![]u8 {
        if (self.buf.len == 0) {
            self.buf = try pool.acquire();
            self.start = 0;
            self.end = 0;
        }
        if (self.end == self.buf.len) {
            if (self.start > 0) {
                self.compact();
            } else {
                const need = @as(usize, opts.max_frame_size) + header_len;
                if (self.buf.len >= need) return error.BufferFull;
                const new_buf = try pool.allocator.alloc(u8, need);
                @memcpy(new_buf[0..self.end], self.buf[0..self.end]);
                self.releaseBuf(pool);
                self.buf = new_buf;
                self.grown = true;
            }
        }
        return self.buf[self.end..];
    }

    pub inline fn commitRead(self: *Self, n: usize) void {
        self.end += n;
    }

    fn compact(self: *Self) void {
        const len = self.end - self.start;
        std.mem.copyForwards(u8, self.buf[0..len], self.buf[self.start..self.end]);
        self.start = 0;
        self.end = len;
    }

    fn releaseBuf(self: *Self, pool: *BufferPool) void {
        if (self.grown) pool.allocator.free(self.buf) else pool.release(self.buf);
        self.buf = &.{};
        self.grown = false;
    }

    /// Returns the buffer when nothing is buffered.
    pub fn releaseIfIdle(self: *Self, pool: *BufferPool) void {
        if (self.buf.len > 0 and self.start == self.end) {
            self.releaseBuf(pool);
            self.start = 0;
            self.end = 0;
        }
    }

    pub fn deinit(self: *Self, pool: *BufferPool) void {
        if (self.buf.len > 0) self.releaseBuf(pool);
        self.* = .{};
    }

    /// Parses the next frame. Slices in the result point into the buffer
    /// and are valid until the next call of `next` or `readSpace`.
    pub fn next(self: *Self, opts: Options) Result {
        const data = self.buf[self.start..self.end];
        if (data.len < header_len) return .need_more;
        const len: u32 = (@as(u32, data[0]) << 16) | (@as(u32, data[1]) << 8) | data[2];
        if (len > opts.max_frame_size) return .{ .failure = Failure.connection(.frame_size_error) };
        if (data.len < header_len + len) return .need_more;
        const ty = data[3];
        const flags = data[4];
        const stream_id: u31 = @truncate(std.mem.readInt(u32, data[5..9], .big));
        const payload = data[header_len..][0..len];
        self.start += header_len + len;
        return parse(ty, flags, stream_id, payload);
    }
};

fn parse(ty: u8, flags: u8, stream_id: u31, payload: []const u8) Result {
    const conn_err = struct {
        fn f(code: ErrorCode) Result {
            return .{ .failure = Failure.connection(code) };
        }
    }.f;
    switch (@as(FrameType, @fromBackingInt(ty))) {
        .data => {
            if (stream_id == 0) return conn_err(.protocol_error);
            const body = unpad(flags, payload) orelse return conn_err(.protocol_error);
            return .{ .frame = .{ .data = .{
                .stream_id = stream_id,
                .end_stream = flags & flag.end_stream != 0,
                .data = body,
                .flow_len = @intCast(payload.len),
            } } };
        },
        .headers => {
            if (stream_id == 0) return conn_err(.protocol_error);
            var body = unpad(flags, payload) orelse return conn_err(.protocol_error);
            if (flags & flag.priority != 0) {
                // Carries a field block: a short frame is a connection
                // error (§4.2).
                if (body.len < 5) return conn_err(.frame_size_error);
                const dep: u31 = @truncate(std.mem.readInt(u32, body[0..4], .big));
                // §5.3.1 (RFC 7540): a stream cannot depend on itself.
                if (dep == stream_id) return .{ .failure = .{ .code = .protocol_error, .stream_id = stream_id } };
                body = body[5..];
            }
            return .{ .frame = .{ .headers = .{
                .stream_id = stream_id,
                .end_stream = flags & flag.end_stream != 0,
                .end_headers = flags & flag.end_headers != 0,
                .fragment = body,
            } } };
        },
        .priority => {
            if (stream_id == 0) return conn_err(.protocol_error);
            if (payload.len != 5) return .{ .failure = .{ .code = .frame_size_error, .stream_id = stream_id } };
            const dep: u31 = @truncate(std.mem.readInt(u32, payload[0..4], .big));
            if (dep == stream_id) return .{ .failure = .{ .code = .protocol_error, .stream_id = stream_id } };
            return .{ .frame = .{ .priority = .{ .stream_id = stream_id } } };
        },
        .rst_stream => {
            if (stream_id == 0) return conn_err(.protocol_error);
            if (payload.len != 4) return conn_err(.frame_size_error);
            return .{ .frame = .{ .rst_stream = .{
                .stream_id = stream_id,
                .code = @fromBackingInt(std.mem.readInt(u32, payload[0..4], .big)),
            } } };
        },
        .settings => {
            if (stream_id != 0) return conn_err(.protocol_error);
            const ack = flags & flag.ack != 0;
            if (ack and payload.len != 0) return conn_err(.frame_size_error);
            if (payload.len % 6 != 0) return conn_err(.frame_size_error);
            var i: usize = 0;
            while (i < payload.len) : (i += 6) {
                const id: SettingId = @fromBackingInt(std.mem.readInt(u16, payload[i..][0..2], .big));
                const value = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
                switch (id) {
                    .enable_push => if (value > 1) return conn_err(.protocol_error),
                    .initial_window_size => if (value > max_window_size) return conn_err(.flow_control_error),
                    .max_frame_size => if (value < min_max_frame_size or value > max_max_frame_size) return conn_err(.protocol_error),
                    else => {},
                }
            }
            return .{ .frame = .{ .settings = .{ .ack = ack, .raw = payload } } };
        },
        // §8.4: clients cannot push, so a server never receives one.
        .push_promise => return conn_err(.protocol_error),
        .ping => {
            if (stream_id != 0) return conn_err(.protocol_error);
            if (payload.len != 8) return conn_err(.frame_size_error);
            return .{ .frame = .{ .ping = .{ .ack = flags & flag.ack != 0, .data = payload[0..8] } } };
        },
        .goaway => {
            if (stream_id != 0) return conn_err(.protocol_error);
            if (payload.len < 8) return conn_err(.frame_size_error);
            return .{ .frame = .{ .goaway = .{
                .last_stream_id = @truncate(std.mem.readInt(u32, payload[0..4], .big)),
                .code = @fromBackingInt(std.mem.readInt(u32, payload[4..8], .big)),
                .debug = payload[8..],
            } } };
        },
        .window_update => {
            if (payload.len != 4) return conn_err(.frame_size_error);
            const inc: u31 = @truncate(std.mem.readInt(u32, payload[0..4], .big));
            // §6.9: a zero increment is a stream error, or a connection
            // error on stream 0.
            if (inc == 0) return .{ .failure = .{ .code = .protocol_error, .stream_id = stream_id } };
            return .{ .frame = .{ .window_update = .{ .stream_id = stream_id, .increment = inc } } };
        },
        .continuation => {
            if (stream_id == 0) return conn_err(.protocol_error);
            return .{ .frame = .{ .continuation = .{
                .stream_id = stream_id,
                .end_headers = flags & flag.end_headers != 0,
                .fragment = payload,
            } } };
        },
        _ => return .{ .frame = .{ .unknown = .{ .type = ty, .stream_id = stream_id } } },
    }
}

/// Strips padding (§6.1, §6.2). Null if the padding is longer than the
/// payload allows.
fn unpad(flags: u8, payload: []const u8) ?[]const u8 {
    if (flags & flag.padded == 0) return payload;
    if (payload.len == 0) return null;
    const pad = payload[0];
    if (pad >= payload.len) return null;
    return payload[1 .. payload.len - pad];
}

// ---------------------------------------------------------------------------
// Serialising

pub fn writeHeader(out: *[header_len]u8, len: u32, ty: FrameType, flags: u8, stream_id: u31) void {
    std.debug.assert(len <= max_max_frame_size);
    out[0] = @truncate(len >> 16);
    out[1] = @truncate(len >> 8);
    out[2] = @truncate(len);
    out[3] = @backingInt(ty);
    out[4] = flags;
    std.mem.writeInt(u32, out[5..9], stream_id, .big);
}

fn reserve(out: []u8, n: usize) error{NoSpace}![]u8 {
    if (out.len < n) return error.NoSpace;
    return out[0..n];
}

pub fn writeSettings(out: []u8, settings: []const Setting) error{NoSpace}!usize {
    const n = header_len + 6 * settings.len;
    const o = try reserve(out, n);
    writeHeader(o[0..header_len], @intCast(6 * settings.len), .settings, 0, 0);
    for (settings, 0..) |s, i| {
        const p = o[header_len + 6 * i ..];
        std.mem.writeInt(u16, p[0..2], @backingInt(s.id), .big);
        std.mem.writeInt(u32, p[2..6], s.value, .big);
    }
    return n;
}

pub fn writeSettingsAck(out: []u8) error{NoSpace}!usize {
    const o = try reserve(out, header_len);
    writeHeader(o[0..header_len], 0, .settings, flag.ack, 0);
    return header_len;
}

pub fn writePing(out: []u8, ack: bool, data: *const [8]u8) error{NoSpace}!usize {
    const o = try reserve(out, header_len + 8);
    writeHeader(o[0..header_len], 8, .ping, if (ack) flag.ack else 0, 0);
    o[header_len..][0..8].* = data.*;
    return header_len + 8;
}

pub fn writeGoaway(out: []u8, last_stream_id: u31, code: ErrorCode, debug: []const u8) error{NoSpace}!usize {
    const n = header_len + 8 + debug.len;
    const o = try reserve(out, n);
    writeHeader(o[0..header_len], @intCast(8 + debug.len), .goaway, 0, 0);
    std.mem.writeInt(u32, o[header_len..][0..4], last_stream_id, .big);
    std.mem.writeInt(u32, o[header_len + 4 ..][0..4], @backingInt(code), .big);
    @memcpy(o[header_len + 8 ..][0..debug.len], debug);
    return n;
}

pub fn writeRstStream(out: []u8, stream_id: u31, code: ErrorCode) error{NoSpace}!usize {
    const o = try reserve(out, header_len + 4);
    writeHeader(o[0..header_len], 4, .rst_stream, 0, stream_id);
    std.mem.writeInt(u32, o[header_len..][0..4], @backingInt(code), .big);
    return header_len + 4;
}

pub fn writeWindowUpdate(out: []u8, stream_id: u31, increment: u31) error{NoSpace}!usize {
    std.debug.assert(increment > 0);
    const o = try reserve(out, header_len + 4);
    writeHeader(o[0..header_len], 4, .window_update, 0, stream_id);
    std.mem.writeInt(u32, o[header_len..][0..4], increment, .big);
    return header_len + 4;
}

/// A DATA frame with a copied payload (the connection layer writes large
/// bodies by reference).
pub fn writeData(out: []u8, stream_id: u31, end_stream: bool, data: []const u8) error{NoSpace}!usize {
    const n = header_len + data.len;
    const o = try reserve(out, n);
    writeHeader(o[0..header_len], @intCast(data.len), .data, if (end_stream) flag.end_stream else 0, stream_id);
    @memcpy(o[header_len..][0..data.len], data);
    return n;
}

/// A HEADERS (or CONTINUATION) frame around an already encoded fragment.
pub fn writeHeaders(out: []u8, stream_id: u31, flags: u8, fragment: []const u8) error{NoSpace}!usize {
    const n = header_len + fragment.len;
    const o = try reserve(out, n);
    writeHeader(o[0..header_len], @intCast(fragment.len), .headers, flags, stream_id);
    @memcpy(o[header_len..][0..fragment.len], fragment);
    return n;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

/// Feeds bytes through a Reader and records what comes out, as text.
const Harness = struct {
    pool: BufferPool,
    reader: Reader = .{},
    log: std.ArrayList(u8) = .empty,
    opts: Options = .{},
    failed: bool = false,

    fn init(buf_size: usize) !*Harness {
        const h = try testing.allocator.create(Harness);
        h.* = .{ .pool = try BufferPool.init(testing.allocator, buf_size, 2) };
        return h;
    }

    fn deinit(h: *Harness) void {
        h.reader.deinit(&h.pool);
        h.pool.deinit();
        h.log.deinit(testing.allocator);
        testing.allocator.destroy(h);
    }

    fn feed(h: *Harness, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0 and !h.failed) {
            const space = try h.reader.readSpace(&h.pool, h.opts);
            const n = @min(space.len, rest.len);
            @memcpy(space[0..n], rest[0..n]);
            h.reader.commitRead(n);
            rest = rest[n..];
            try h.drain();
        }
    }

    fn drain(h: *Harness) !void {
        const a = testing.allocator;
        while (!h.failed) {
            switch (h.reader.next(h.opts)) {
                .need_more => break,
                .failure => |f| {
                    try h.log.print(a, "fail {s} on {d}\n", .{ @tagName(f.code), f.stream_id });
                    if (f.stream_id == 0) h.failed = true;
                },
                .frame => |fr| switch (fr) {
                    .data => |d| try h.log.print(a, "data {d} end={} flow={d} '{s}'\n", .{ d.stream_id, d.end_stream, d.flow_len, d.data }),
                    .headers => |x| try h.log.print(a, "headers {d} end={} eh={} '{s}'\n", .{ x.stream_id, x.end_stream, x.end_headers, x.fragment }),
                    .priority => |p| try h.log.print(a, "priority {d}\n", .{p.stream_id}),
                    .rst_stream => |r| try h.log.print(a, "rst {d} {s}\n", .{ r.stream_id, @tagName(r.code) }),
                    .settings => |s| {
                        try h.log.print(a, "settings ack={}", .{s.ack});
                        var it = s.iterator();
                        while (it.next()) |st| try h.log.print(a, " {d}={d}", .{ @backingInt(st.id), st.value });
                        try h.log.append(a, '\n');
                    },
                    .ping => |p| try h.log.print(a, "ping ack={} {x}\n", .{ p.ack, @as([]const u8, p.data) }),
                    .goaway => |g| try h.log.print(a, "goaway last={d} {s} '{s}'\n", .{ g.last_stream_id, @tagName(g.code), g.debug }),
                    .window_update => |w| try h.log.print(a, "window {d} +{d}\n", .{ w.stream_id, w.increment }),
                    .continuation => |c| try h.log.print(a, "continuation {d} eh={} '{s}'\n", .{ c.stream_id, c.end_headers, c.fragment }),
                    .unknown => |u| try h.log.print(a, "unknown type {d} on {d}\n", .{ u.type, u.stream_id }),
                },
            }
        }
        h.reader.releaseIfIdle(&h.pool);
    }
};

fn raw(comptime len: u24, ty: u8, flags: u8, stream_id: u32, payload: []const u8) [header_len + len]u8 {
    var out: [header_len + len]u8 = undefined;
    out[0] = @truncate(len >> 16);
    out[1] = @truncate(len >> 8);
    out[2] = @truncate(len);
    out[3] = ty;
    out[4] = flags;
    std.mem.writeInt(u32, out[5..9], stream_id, .big);
    @memcpy(out[9..], payload[0..len]);
    return out;
}

test "every frame type parses, with padding and flags" {
    const h = try Harness.init(4096);
    defer h.deinit();
    try h.feed(&raw(5, 0, flag.end_stream, 1, "hello"));
    try h.feed(&raw(8, 0, flag.padded, 3, "\x02hello\x00\x00"));
    try h.feed(&raw(3, 0, flag.padded, 3, "\x02\x00\x00")); // all padding, no data
    try h.feed(&raw(3, 1, flag.end_headers | flag.end_stream, 5, "abc"));
    // PADDED and PRIORITY: pad length 1, 5 priority bytes, "xy", 1 pad.
    try h.feed(&raw(9, 1, flag.padded | flag.priority, 7, "\x01\x00\x00\x00\x03\x10xy\x00"));
    try h.feed(&raw(5, 2, 0, 9, "\x00\x00\x00\x01\x20"));
    try h.feed(&raw(4, 3, 0, 1, "\x00\x00\x00\x08"));
    try h.feed(&raw(12, 4, 0, 0, "\x00\x03\x00\x00\x00\x64\x00\x04\x00\x01\x00\x00"));
    try h.feed(&raw(0, 4, flag.ack, 0, ""));
    try h.feed(&raw(8, 6, 0, 0, "12345678"));
    try h.feed(&raw(8, 6, flag.ack, 0, "12345678"));
    try h.feed(&raw(11, 7, 0, 0, "\x00\x00\x00\x07\x00\x00\x00\x00bye"));
    try h.feed(&raw(4, 8, 0, 0, "\x00\x01\x00\x00"));
    try h.feed(&raw(4, 8, 0, 3, "\x80\x00\x00\x01")); // reserved bit ignored
    try h.feed(&raw(2, 9, flag.end_headers, 7, "zz"));
    try h.feed(&raw(3, 0x10, 0, 0, "u=3")); // PRIORITY_UPDATE
    try h.feed(&raw(1, 0xfe, 0xff, 99, "?"));
    try testing.expectEqualStrings(
        \\data 1 end=true flow=5 'hello'
        \\data 3 end=false flow=8 'hello'
        \\data 3 end=false flow=3 ''
        \\headers 5 end=true eh=true 'abc'
        \\headers 7 end=false eh=false 'xy'
        \\priority 9
        \\rst 1 cancel
        \\settings ack=false 3=100 4=65536
        \\settings ack=true
        \\ping ack=false 3132333435363738
        \\ping ack=true 3132333435363738
        \\goaway last=7 no_error 'bye'
        \\window 0 +65536
        \\window 3 +1
        \\continuation 7 eh=true 'zz'
        \\unknown type 16 on 0
        \\unknown type 254 on 99
        \\
    , h.log.items);
    try testing.expectEqual(@as(usize, 0), h.reader.buf.len);
}

test "malformed frames map to the RFC's error codes" {
    const cases = [_]struct { bytes: []const u8, expect: []const u8 }{
        // §4.2: over SETTINGS_MAX_FRAME_SIZE.
        .{ .bytes = &.{ 0x00, 0x40, 0x01, 0, 0, 0, 0, 0, 1 }, .expect = "fail frame_size_error on 0\n" },
        // §6.1 DATA on stream 0; padding too long (equal and over).
        .{ .bytes = &raw(1, 0, 0, 0, "x"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(3, 0, flag.padded, 1, "\x03xx"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(3, 0, flag.padded, 1, "\x05xx"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(0, 0, flag.padded, 1, ""), .expect = "fail protocol_error on 0\n" },
        // §6.2 HEADERS on stream 0; padding; too short for PRIORITY; self-dependency.
        .{ .bytes = &raw(1, 1, flag.end_headers, 0, "x"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(2, 1, flag.padded, 1, "\x02x"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(4, 1, flag.priority, 1, "\x00\x00\x00\x00"), .expect = "fail frame_size_error on 0\n" },
        .{ .bytes = &raw(5, 1, flag.priority | flag.end_headers, 1, "\x00\x00\x00\x01\x00"), .expect = "fail protocol_error on 1\n" },
        // §6.3 PRIORITY on stream 0; wrong length (stream error); self-dependency.
        .{ .bytes = &raw(5, 2, 0, 0, "\x00\x00\x00\x01\x00"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(4, 2, 0, 3, "\x00\x00\x00\x01"), .expect = "fail frame_size_error on 3\n" },
        .{ .bytes = &raw(5, 2, 0, 3, "\x00\x00\x00\x03\x00"), .expect = "fail protocol_error on 3\n" },
        // §6.4 RST_STREAM on stream 0; wrong length.
        .{ .bytes = &raw(4, 3, 0, 0, "\x00\x00\x00\x00"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(3, 3, 0, 1, "\x00\x00\x00"), .expect = "fail frame_size_error on 0\n" },
        // §6.5 SETTINGS on a stream; ACK with payload; length not a multiple of 6;
        // ENABLE_PUSH 2; INITIAL_WINDOW_SIZE 2^31; MAX_FRAME_SIZE too small and too large.
        .{ .bytes = &raw(0, 4, 0, 1, ""), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(6, 4, flag.ack, 0, "\x00\x01\x00\x00\x10\x00"), .expect = "fail frame_size_error on 0\n" },
        .{ .bytes = &raw(5, 4, 0, 0, "\x00\x01\x00\x00\x10"), .expect = "fail frame_size_error on 0\n" },
        .{ .bytes = &raw(6, 4, 0, 0, "\x00\x02\x00\x00\x00\x02"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(6, 4, 0, 0, "\x00\x04\x80\x00\x00\x00"), .expect = "fail flow_control_error on 0\n" },
        .{ .bytes = &raw(6, 4, 0, 0, "\x00\x05\x00\x00\x3f\xff"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(6, 4, 0, 0, "\x00\x05\x01\x00\x00\x00"), .expect = "fail protocol_error on 0\n" },
        // §8.4 PUSH_PROMISE from a client.
        .{ .bytes = &raw(4, 5, flag.end_headers, 1, "\x00\x00\x00\x02"), .expect = "fail protocol_error on 0\n" },
        // §6.7 PING on a stream; wrong length.
        .{ .bytes = &raw(8, 6, 0, 1, "12345678"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(7, 6, 0, 0, "1234567"), .expect = "fail frame_size_error on 0\n" },
        // §6.8 GOAWAY on a stream; too short.
        .{ .bytes = &raw(8, 7, 0, 1, "\x00\x00\x00\x00\x00\x00\x00\x00"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(7, 7, 0, 0, "\x00\x00\x00\x00\x00\x00\x00"), .expect = "fail frame_size_error on 0\n" },
        // §6.9 WINDOW_UPDATE wrong length; zero increment on the connection and on a stream.
        .{ .bytes = &raw(3, 8, 0, 1, "\x00\x00\x01"), .expect = "fail frame_size_error on 0\n" },
        .{ .bytes = &raw(4, 8, 0, 0, "\x00\x00\x00\x00"), .expect = "fail protocol_error on 0\n" },
        .{ .bytes = &raw(4, 8, 0, 5, "\x80\x00\x00\x00"), .expect = "fail protocol_error on 5\n" },
        // §6.10 CONTINUATION on stream 0.
        .{ .bytes = &raw(1, 9, flag.end_headers, 0, "x"), .expect = "fail protocol_error on 0\n" },
    };
    for (cases) |case| {
        const h = try Harness.init(4096);
        defer h.deinit();
        try h.feed(case.bytes);
        try testing.expectEqualStrings(case.expect, h.log.items);
        // Stream errors consume the frame, so what follows still parses.
        if (!h.failed) {
            try h.feed(&raw(8, 6, 0, 0, "12345678"));
            try testing.expect(std.mem.endsWith(u8, h.log.items, "ping ack=false 3132333435363738\n"));
        }
    }
}

test "a frame larger than the pool buffer grows the buffer, then it goes back" {
    const h = try Harness.init(64);
    defer h.deinit();
    const payload: [1000]u8 = @splat('p');
    try h.feed(&raw(1000, 0, 0, 1, &payload));
    try testing.expect(std.mem.startsWith(u8, h.log.items, "data 1 end=false flow=1000 'ppp"));
    try testing.expectEqual(@as(usize, 0), h.reader.buf.len);
    try testing.expect(!h.reader.grown);
    // A frame of exactly the maximum size fits too.
    const big = try testing.allocator.alloc(u8, header_len + min_max_frame_size);
    defer testing.allocator.free(big);
    writeHeader(big[0..header_len], min_max_frame_size, .data, 0, 1);
    @memset(big[header_len..], 'b');
    h.log.clearRetainingCapacity();
    try h.feed(big);
    try testing.expect(std.mem.startsWith(u8, h.log.items, "data 1 end=false flow=16384 'bbb"));
    // One byte more is rejected before any buffer grows.
    h.log.clearRetainingCapacity();
    try h.feed(&.{ 0x00, 0x40, 0x01, 0, 0, 0, 0, 0, 1 });
    try testing.expectEqualStrings("fail frame_size_error on 0\n", h.log.items);
}

test "serialisers round-trip through the parser" {
    const h = try Harness.init(4096);
    defer h.deinit();
    var buf: [256]u8 = undefined;
    var n: usize = 0;
    n += try writeSettings(buf[n..], &.{ .{ .id = .max_concurrent_streams, .value = 100 }, .{ .id = .initial_window_size, .value = 65535 } });
    n += try writeSettingsAck(buf[n..]);
    n += try writePing(buf[n..], true, "pingdata");
    n += try writeGoaway(buf[n..], 5, .enhance_your_calm, "calm");
    n += try writeRstStream(buf[n..], 3, .cancel);
    n += try writeWindowUpdate(buf[n..], 0, 1 << 20);
    n += try writeData(buf[n..], 1, true, "body");
    n += try writeHeaders(buf[n..], 1, flag.end_headers, "frag");
    try h.feed(buf[0..n]);
    try testing.expectEqualStrings(
        \\settings ack=false 3=100 4=65535
        \\settings ack=true
        \\ping ack=true 70696e6764617461
        \\goaway last=5 enhance_your_calm 'calm'
        \\rst 3 cancel
        \\window 0 +1048576
        \\data 1 end=true flow=4 'body'
        \\headers 1 end=false eh=true 'frag'
        \\
    , h.log.items);
    try testing.expectError(error.NoSpace, writePing(buf[0..10], false, "pingdata"));
    try testing.expectError(error.NoSpace, writeGoaway(buf[0..16], 0, .no_error, ""));
}

// Any split of the same bytes gives the same frames and failures.
test "split invariance" {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    const a = testing.allocator;
    var buf: [600]u8 = undefined;
    for (0..20) |i| {
        var n: usize = 0;
        n += try writeSettings(buf[n..], &.{.{ .id = .header_table_size, .value = @intCast(i) }});
        n += try writePing(buf[n..], i % 2 == 0, "12345678");
        var payload: [400]u8 = undefined;
        for (&payload, 0..) |*b, j| b.* = @truncate(i * 31 + j);
        n += try writeData(buf[n..], @intCast(2 * i + 1), i % 3 == 0, payload[0 .. 17 * i]);
        n += try writeHeaders(buf[n..], @intCast(2 * i + 1), flag.end_headers | flag.padded, "\x03frag\x00\x00\x00");
        n += try writeWindowUpdate(buf[n..], 0, 1);
        n += try writeRstStream(buf[n..], 9, .cancel);
        // One stream error in the middle: a zero increment on stream 7.
        if (i == 10) {
            n += try writeWindowUpdate(buf[n..], 7, 1);
            buf[n - 1] = 0;
        }
        try input.appendSlice(a, buf[0..n]);
    }
    try input.appendSlice(a, &raw(1, 9, flag.end_headers, 0, "x")); // connection error at the end

    const ref = try Harness.init(128);
    defer ref.deinit();
    try ref.feed(input.items);
    try testing.expect(ref.failed);
    try testing.expect(std.mem.indexOf(u8, ref.log.items, "fail protocol_error on 7\n") != null);

    var prng = std.Random.DefaultPrng.init(7);
    const random = prng.random();
    for (0..100) |iteration| {
        const h = try Harness.init(if (iteration % 2 == 0) 128 else 4096);
        defer h.deinit();
        var rest: []const u8 = input.items;
        while (rest.len > 0 and !h.failed) {
            const max_chunk: usize = if (iteration == 0) 1 else 1 + random.uintLessThan(usize, 500);
            const n = @min(rest.len, max_chunk);
            try h.feed(rest[0..n]);
            rest = rest[n..];
        }
        try testing.expectEqualStrings(ref.log.items, h.log.items);
    }
}

fn fuzzFrames(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [4096]u8 = undefined;
    const input = input_buf[0..smith.slice(&input_buf)];
    const whole = try Harness.init(128);
    defer whole.deinit();
    try whole.feed(input);
    const split = try Harness.init(128);
    defer split.deinit();
    var rest: []const u8 = input;
    while (rest.len > 0 and !split.failed) {
        const n = @min(rest.len, @as(usize, smith.value(u8)) + 1);
        try split.feed(rest[0..n]);
        rest = rest[n..];
    }
    try testing.expectEqual(whole.failed, split.failed);
    try testing.expectEqualStrings(whole.log.items, split.log.items);
}

test "fuzz: h2 frames" {
    try std.testing.fuzz({}, fuzzFrames, .{ .corpus = &.{
        &raw(5, 0, flag.end_stream, 1, "hello"),
        &raw(9, 1, flag.padded | flag.priority, 7, "\x01\x00\x00\x00\x03\x10xy\x00"),
        &raw(12, 4, 0, 0, "\x00\x03\x00\x00\x00\x64\x00\x04\x00\x01\x00\x00"),
        &raw(11, 7, 0, 0, "\x00\x00\x00\x07\x00\x00\x00\x00bye"),
        &raw(4, 8, 0, 3, "\x80\x00\x00\x01"),
    } });
}
