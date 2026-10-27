const std = @import("std");
const Header = @import("./header.zig").Header;
const Status = @import("./status.zig").Status;
const exchange = @import("./http/exchange.zig");
pub const Exchange = exchange.Exchange;

pub const Mode = enum(u8) {
    /// The response is complete when handleRequest returns.
    sync,
    /// `later()`: nothing is sent until `ex.respond` or `ex.startStream`.
    later,
    /// `stream()`: the head is sent now, the body through `ex.write`.
    stream,
};

/// This response is reused for every request on a worker. The server resets
/// it before calling handleRequest.
///
/// Headers are serialised as they are added, so their values are copied and
/// may be freed as soon as addHeader returns. The server adds Content-Length,
/// Date and Connection itself.
pub const Response = struct {
    const Self = @This();

    status: Status = .ok,
    /// Close the connection after this response is sent.
    close: bool = false,
    is_ws_upgrade: bool = false,
    /// Serialised "key: value\r\n" lines.
    header_buf: []u8,
    header_len: usize = 0,
    /// The body to send. Set it with setBody (copies) or setBodyBorrowed.
    body: []const u8 = "",
    body_buf: []u8,
    allocator: std.mem.Allocator,
    /// Set by later() and stream(); checked by the session once.
    mode: Mode = .sync,
    /// The exchange taken by later() or stream().
    exchange: Exchange = undefined,
    /// For stream(): send a Content-Length body instead of chunked.
    content_length: ?usize = null,
    /// The worker's exchange slab and clock; null in handlers run
    /// without a worker (tests, benchmarks), where later()/stream() fail.
    exchanges: ?*exchange.Slab = null,
    now: *const u32 = &zero_now,

    pub fn init(allocator: std.mem.Allocator, body_size: usize, header_size: usize) !*Self {
        const resp = try allocator.create(Self);
        errdefer allocator.destroy(resp);
        const body_buf = try allocator.alloc(u8, body_size);
        errdefer allocator.free(body_buf);
        resp.* = .{
            .allocator = allocator,
            .body_buf = body_buf,
            .header_buf = try allocator.alloc(u8, header_size),
        };
        return resp;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.body_buf);
        self.allocator.free(self.header_buf);
        self.allocator.destroy(self);
    }

    /// Add a header. Prefer addNewHeader, which rejects server-managed
    /// headers at compile time.
    pub fn addHeader(self: *Self, header: Header) !void {
        // Reject CR/LF to prevent response splitting.
        if (std.mem.indexOfAny(u8, header.key, "\r\n:") != null or header.key.len == 0) {
            return error.InvalidHeader;
        }
        if (std.mem.indexOfAny(u8, header.value, "\r\n") != null) return error.InvalidHeader;
        const needed = header.key.len + 2 + header.value.len + 2;
        if (self.header_len + needed > self.header_buf.len) return error.HeadersFull;
        var buf = self.header_buf[self.header_len..];
        @memcpy(buf[0..header.key.len], header.key);
        buf = buf[header.key.len..];
        buf[0..2].* = ": ".*;
        @memcpy(buf[2..][0..header.value.len], header.value);
        buf[2 + header.value.len ..][0..2].* = "\r\n".*;
        self.header_len += needed;
    }

    pub fn addNewHeader(self: *Self, comptime key: []const u8, value: []const u8) !void {
        try self.addHeader(Header.init(key, value));
    }

    /// Copies `buf` into the worker's response buffer.
    pub fn setBody(self: *Self, buf: []const u8) !usize {
        if (buf.len > self.body_buf.len) {
            return error.ResponseBodyBufferTooSmall;
        }
        @memcpy(self.body_buf[0..buf.len], buf);
        self.body = self.body_buf[0..buf.len];
        return buf.len;
    }

    /// Sends `buf` without copying it. It must stay valid and unchanged until
    /// the response is sent, which happens before this worker calls
    /// handleRequest again. Use it for static or cached content.
    pub fn setBodyBorrowed(self: *Self, buf: []const u8) void {
        self.body = buf;
    }

    /// Returns a slice of the response buffer to write a body into directly.
    /// Call commitBody with the number of bytes written.
    pub fn bodyWriteBuffer(self: *Self) []u8 {
        return self.body_buf;
    }

    pub fn commitBody(self: *Self, len: usize) void {
        self.body = self.body_buf[0..len];
    }

    pub fn headerBytes(self: *const Self) []const u8 {
        return self.header_buf[0..self.header_len];
    }

    /// Sends the status and the headers added so far now, and the body
    /// later through the returned exchange: `ex.write`, `ex.finish`. The
    /// body is chunked unless setContentLength was called. Call it last;
    /// the body set on `resp` is ignored.
    pub fn stream(self: *Self) error{ TooManyExchanges, NoWorker, AlreadyTaken }!Exchange {
        const ex = try self.take();
        self.mode = .stream;
        // Writes may start right away, before the worker binds the
        // exchange to the connection.
        self.exchanges.?.beginStream(ex.slot, self.content_length);
        return ex;
    }

    /// Sends nothing now. Later, from any thread, `ex.respond` sends a
    /// complete response or `ex.startStream` begins a streamed one. The
    /// connection waits (further pipelined requests queue behind it).
    pub fn later(self: *Self) error{ TooManyExchanges, NoWorker, AlreadyTaken }!Exchange {
        const ex = try self.take();
        self.mode = .later;
        return ex;
    }

    fn take(self: *Self) error{ TooManyExchanges, NoWorker, AlreadyTaken }!Exchange {
        if (self.mode != .sync) return error.AlreadyTaken;
        const slab = self.exchanges orelse return error.NoWorker;
        self.exchange = try slab.create(self.now.*);
        return self.exchange;
    }

    /// With stream(): the body length, so the response uses
    /// Content-Length framing. `write` then fails past this many bytes
    /// and `finish` fails short of it. Call it before stream().
    pub fn setContentLength(self: *Self, n: usize) void {
        self.content_length = n;
    }

    pub inline fn reset(self: *Self) void {
        self.status = .ok;
        self.close = false;
        self.is_ws_upgrade = false;
        self.header_len = 0;
        self.body = "";
        self.mode = .sync;
        self.content_length = null;
    }
};

const zero_now: u32 = 0;

test "headers are serialised on add" {
    var r = try Response.init(std.testing.allocator, 16, 128);
    defer r.deinit();
    try r.addNewHeader("Content-Type", "text/plain");
    try r.addNewHeader("X-A", "b");
    try std.testing.expectEqualStrings("Content-Type: text/plain\r\nX-A: b\r\n", r.headerBytes());
}

test "header injection is rejected" {
    var r = try Response.init(std.testing.allocator, 16, 128);
    defer r.deinit();
    try std.testing.expectError(error.InvalidHeader, r.addNewHeader("X", "a\r\nSet-Cookie: x"));
    try std.testing.expectError(error.InvalidHeader, r.addHeader(.{ .key = "X\r\n", .value = "a" }));
}

test "header buffer overflow" {
    var r = try Response.init(std.testing.allocator, 16, 8);
    defer r.deinit();
    try std.testing.expectError(error.HeadersFull, r.addNewHeader("Key", "value"));
}
