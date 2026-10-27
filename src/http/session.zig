//! The HTTP/1.1 connection state machine, independent of the I/O model.
//! The event loop reads into a Session's buffer, calls `process`, and writes
//! whatever ends up in the Out buffer. No syscalls happen here, which keeps
//! it testable byte-by-byte and reusable by different backends.
const std = @import("std");
const parser = @import("./parser.zig");
const date = @import("./date.zig");
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const Status = @import("../status.zig").Status;
const iovec_const = std.posix.iovec_const;

/// Fixed-size read buffers shared by a worker's connections. A connection
/// only holds one while it has unprocessed bytes, so idle keep-alive
/// connections cost no buffer memory.
pub const BufferPool = struct {
    const Self = @This();

    buffer_size: usize,
    free: [][]u8,
    free_len: usize = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize, count: usize) !Self {
        var self: Self = .{
            .allocator = allocator,
            .buffer_size = buffer_size,
            .free = try allocator.alloc([]u8, count),
        };
        errdefer self.deinit();
        while (self.free_len < count) : (self.free_len += 1) {
            self.free[self.free_len] = try allocator.alloc(u8, buffer_size);
        }
        return self;
    }

    pub fn deinit(self: *Self) void {
        for (self.free[0..self.free_len]) |b| self.allocator.free(b);
        self.allocator.free(self.free);
    }

    pub fn acquire(self: *Self) ![]u8 {
        if (self.free_len > 0) {
            self.free_len -= 1;
            return self.free[self.free_len];
        }
        // Pool exhausted: overflow to the heap.
        return self.allocator.alloc(u8, self.buffer_size);
    }

    pub fn release(self: *Self, buf: []u8) void {
        if (buf.len == self.buffer_size and self.free_len < self.free.len) {
            self.free[self.free_len] = buf;
            self.free_len += 1;
        } else {
            self.allocator.free(buf);
        }
    }
};

/// Serialised output waiting to be written: `buf[0..len]`, then `body`,
/// then `tail`.
pub const Out = struct {
    buf: []u8,
    len: usize = 0,
    /// An uncopied response body sent after buf[0..len].
    body: []const u8 = "",
    /// Sent after the body: the CRLF that ends a chunk of a streamed
    /// response whose bytes are borrowed.
    tail: []const u8 = "",

    pub inline fn isEmpty(self: *const Out) bool {
        return self.len == 0 and self.body.len == 0;
    }

    pub inline fn clear(self: *Out) void {
        self.len = 0;
        self.body = "";
        self.tail = "";
    }

    pub inline fn totalLen(self: *const Out) usize {
        return self.len + self.body.len + self.tail.len;
    }

    pub fn iovecs(self: *const Out, iov: *[3]iovec_const) []iovec_const {
        var n: usize = 0;
        if (self.len > 0) {
            iov[n] = .{ .base = self.buf.ptr, .len = self.len };
            n += 1;
        }
        if (self.body.len > 0) {
            iov[n] = .{ .base = self.body.ptr, .len = self.body.len };
            n += 1;
        }
        if (self.tail.len > 0) {
            iov[n] = .{ .base = self.tail.ptr, .len = self.tail.len };
            n += 1;
        }
        return iov[0..n];
    }

    pub inline fn free(self: *const Out) usize {
        return self.buf.len - self.len;
    }

    pub inline fn append(self: *Out, bytes: []const u8) void {
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }
};

pub const Action = enum {
    /// Every complete request was handled. Flush Out, then read more.
    need_more,
    /// Flush Out completely, then call process again.
    flush,
    /// Flush Out, then close the connection.
    close,
    /// Flush Out, then hand the connection and any remaining buffered
    /// bytes to the WebSocket side.
    upgrade,
    /// Flush Out; the response (or the rest of it) comes through the
    /// exchange the handler took (`resp.exchange`). Don't call process
    /// again until it ends: responses go out in request order.
    wait,
};

pub const Options = struct {
    limits: parser.Limits = .{},
    /// 0 means unlimited.
    max_requests_per_connection: u32 = 0,
};

pub const Session = struct {
    const Self = @This();

    buf: []u8 = &.{},
    start: usize = 0,
    end: usize = 0,
    /// Resume offset for findHeadEnd, relative to start.
    head_scan: usize = 0,
    chunked: parser.ChunkedScanner = .{},
    /// Total bytes the current request needs in the buffer, if known.
    need: usize = 0,
    sent_continue: bool = false,
    requests: u32 = 0,
    /// Closing after an error, possibly with request bytes still arriving.
    /// The event loop should drain input before closing (lingering close),
    /// or the kernel may reset the connection and destroy the response.
    linger: bool = false,
    /// An exchange is pending on this connection: parsing is paused.
    waiting: bool = false,
    /// What the pending exchange's response needs to know about its
    /// request, for the worker to bind.
    wait_keep_alive: bool = true,
    wait_is_head: bool = false,
    wait_http10: bool = false,

    pub inline fn buffered(self: *const Self) usize {
        return self.end - self.start;
    }

    /// Whether a request is partially received.
    pub inline fn inRequest(self: *const Self) bool {
        return self.end > self.start;
    }

    /// Returns space to read into, acquiring, compacting or growing the
    /// buffer as needed.
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
                // A full buffer with a request at its start: only a body can
                // need more room (findHeadEnd limits the head).
                const max = opts.limits.max_header_bytes + opts.limits.max_body_size * 2 + 4096;
                const wanted = if (self.need > self.buf.len) self.need else self.buf.len * 2;
                const new_len = @min(wanted, max);
                if (new_len <= self.buf.len) return error.BufferFull;
                const new_buf = try pool.allocator.alloc(u8, new_len);
                @memcpy(new_buf[0..self.end], self.buf[0..self.end]);
                pool.release(self.buf);
                self.buf = new_buf;
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

    /// Return the buffer to the pool when nothing is buffered.
    pub fn releaseIfIdle(self: *Self, pool: *BufferPool) void {
        if (self.buf.len > 0 and self.start == self.end) {
            pool.release(self.buf);
            self.buf = &.{};
            self.start = 0;
            self.end = 0;
        }
    }

    pub fn deinit(self: *Self, pool: *BufferPool) void {
        if (self.buf.len > 0) pool.release(self.buf);
        self.* = .{};
    }

    fn resetRequestState(self: *Self) void {
        self.head_scan = 0;
        self.chunked = .{};
        self.need = 0;
        self.sent_continue = false;
    }
};

/// Everything `process` needs besides the session.
pub fn Context(comptime Handler: type) type {
    return struct {
        handler: *Handler,
        req: *Request,
        resp: *Response,
        /// The current "date: ...\r\n" line, refreshed once per second.
        date: *const [date.header_len]u8,
        opts: Options,
    };
}

/// Longest status line + server-managed headers.
const fixed_head_overhead = "HTTP/1.1 ".len + 48 + "content-length: ".len + 20 + 2 +
    date.header_len + "connection: keep-alive\r\n".len + 2;

/// Out must be at least this large.
pub fn headRoom(resp: *const Response) usize {
    return fixed_head_overhead + resp.header_buf.len;
}

pub fn process(comptime Handler: type, s: *Session, ctx: *const Context(Handler), out: *Out) Action {
    const opts = ctx.opts;
    if (s.waiting) return .wait;
    while (true) {
        // A borrowed body must be written before the response is reused,
        // and Out must have room for the largest possible response head.
        // Checked before parsing: chunked bodies are decoded in place, so a
        // request must not be parsed twice.
        if (out.body.len > 0) return .flush;
        if (out.len > 0 and out.free() < headRoom(ctx.resp)) return .flush;
        var data = s.buf[s.start..s.end];
        if (s.head_scan == 0) {
            // RFC 9112 §2.2: ignore empty lines before a request line.
            while (data.len >= 2 and data[0] == '\r' and data[1] == '\n') {
                s.start += 2;
                data = data[2..];
            }
            // A lone CR may be the start of another empty line; don't let
            // findHeadEnd scan past it.
            if (data.len == 1 and data[0] == '\r') return .need_more;
        }
        if (data.len == 0) return .need_more;
        const head_len = (parser.findHeadEnd(data, &s.head_scan, opts.limits) catch |err| {
            return errorResponse(s, ctx, out, err);
        }) orelse return .need_more;
        const head = parser.parseHead(data[0..head_len], ctx.req, opts.limits) catch |err| {
            return errorResponse(s, ctx, out, err);
        };
        var total: usize = head_len;
        switch (head.framing) {
            .none => {},
            .length => |n| {
                total += n;
                if (data.len < total) {
                    s.need = total;
                    return awaitBody(s, ctx, out, head);
                }
                ctx.req.body = data[head_len..total];
            },
            .chunked => {
                const complete = s.chunked.scan(data[head_len..], opts.limits.max_body_size) catch |err| {
                    return errorResponse(s, ctx, out, err);
                };
                if (!complete) return awaitBody(s, ctx, out, head);
                const raw = s.buf[s.start + head_len ..][0..s.chunked.pos];
                ctx.req.body = raw[0..parser.decodeChunked(raw)];
                total += s.chunked.pos;
            },
        }

        ctx.resp.reset();
        ctx.handler.handleRequest(ctx.req, ctx.resp);

        s.requests +|= 1;
        var keep_alive = ctx.req.keep_alive and !ctx.resp.close and
            (opts.max_requests_per_connection == 0 or s.requests < opts.max_requests_per_connection);
        s.start += total;
        s.resetRequestState();
        if (ctx.resp.mode != .sync) {
            // The response comes through the exchange. A streamed body
            // without a length to an HTTP/1.0 client is close-delimited.
            const http10 = ctx.req.version == .@"HTTP/1.0";
            if (ctx.resp.mode == .stream and http10 and ctx.resp.content_length == null) keep_alive = false;
            s.waiting = true;
            s.wait_keep_alive = keep_alive;
            s.wait_is_head = ctx.req.method == .HEAD;
            s.wait_http10 = http10;
            if (ctx.resp.mode == .stream) writeStreamHead(ctx.req, ctx.resp, ctx.date, out, keep_alive);
            return .wait;
        }
        const more = s.start < s.end;
        writeResponse(ctx.req, ctx.resp, ctx.date, out, keep_alive, more);
        if (ctx.resp.is_ws_upgrade) {
            // Anything after the request is the first WebSocket frames; the
            // event loop hands the buffer to the WebSocket side.
            return .upgrade;
        }
        if (!keep_alive) {
            s.start = s.end;
            return .close;
        }
    }
}

fn awaitBody(s: *Session, ctx: anytype, out: *Out, head: parser.Head) Action {
    if (head.expect_continue and !s.sent_continue) {
        // RFC 9110 §10.1.1: tell the client to send the body.
        const line = "HTTP/1.1 100 Continue\r\n\r\n";
        if (out.free() < line.len) return .flush;
        out.append(line);
        s.sent_continue = true;
    }
    _ = ctx;
    return .need_more;
}

fn errorResponse(s: *Session, ctx: anytype, out: *Out, err: parser.ParseError) Action {
    const status = parser.statusFor(err);
    const reason = status.toString();
    const needed = 9 + reason.len + 2 + "content-length: 0\r\n".len + date.header_len +
        "connection: close\r\n\r\n".len;
    if (out.free() < needed) {
        if (out.len > 0) return .flush;
        return .close;
    }
    out.append("HTTP/1.1 ");
    out.append(reason);
    out.append("\r\ncontent-length: 0\r\n");
    out.append(ctx.date);
    out.append("connection: close\r\n\r\n");
    s.start = s.end;
    s.linger = true;
    return .close;
}

/// The head of a `resp.stream()` response: chunked unless the handler set
/// a Content-Length (or the client is HTTP/1.0, which gets no framing).
fn writeStreamHead(
    req: *const Request,
    resp: *Response,
    date_line: *const [date.header_len]u8,
    out: *Out,
    keep_alive: bool,
) void {
    out.append("HTTP/1.1 ");
    out.append(resp.status.toString());
    out.append("\r\n");
    out.append(resp.headerBytes());
    if (resp.status.allowsContentLength()) {
        if (resp.content_length) |n| {
            out.append("content-length: ");
            out.len += std.fmt.printInt(out.buf[out.len..], n, 10, .lower, .{});
            out.append("\r\n");
        } else if (req.version != .@"HTTP/1.0") {
            out.append("transfer-encoding: chunked\r\n");
        }
    }
    out.append(date_line);
    if (!keep_alive) {
        out.append("connection: close\r\n");
    } else if (req.version == .@"HTTP/1.0") {
        out.append("connection: keep-alive\r\n");
    }
    out.append("\r\n");
}

fn writeResponse(
    req: *const Request,
    resp: *Response,
    date_line: *const [date.header_len]u8,
    out: *Out,
    keep_alive: bool,
    more: bool,
) void {
    const reason = resp.status.toString();
    out.append("HTTP/1.1 ");
    out.append(reason);
    out.append("\r\n");
    out.append(resp.headerBytes());
    const code = @backingInt(resp.status);
    const send_body = req.method != .HEAD and code >= 200 and code != 204 and code != 304;
    if (resp.status.allowsContentLength() and !resp.is_ws_upgrade) {
        out.append("content-length: ");
        out.len += std.fmt.printInt(out.buf[out.len..], resp.body.len, 10, .lower, .{});
        out.append("\r\n");
    }
    out.append(date_line);
    if (resp.is_ws_upgrade) {
        out.append("connection: upgrade\r\n");
    } else if (!keep_alive) {
        out.append("connection: close\r\n");
    } else if (req.version == .@"HTTP/1.0") {
        out.append("connection: keep-alive\r\n");
    }
    out.append("\r\n");
    if (!send_body or resp.body.len == 0) return;
    if (more and resp.body.len <= out.free()) {
        // More pipelined requests follow and the response object will be
        // reused, so copy small bodies to batch them into one write.
        out.append(resp.body);
    } else {
        out.body = resp.body;
    }
}

// ---------------------------------------------------------------------------
// Tests: drive the state machine without sockets.

const testing = std.testing;

const EchoHandler = struct {
    calls: usize = 0,

    pub fn handleRequest(self: *EchoHandler, req: *Request, resp: *Response) void {
        self.calls += 1;
        resp.addNewHeader("x-path", req.path_and_query) catch {};
        if (std.mem.eql(u8, req.getPath(), "/close")) resp.close = true;
        if (std.mem.eql(u8, req.getPath(), "/big")) {
            const big = resp.bodyWriteBuffer();
            @memset(big[0..3000], 'b');
            resp.commitBody(3000);
            return;
        }
        _ = resp.setBody(req.body) catch {};
    }
};

const Harness = struct {
    pool: BufferPool,
    session: Session = .{},
    handler: EchoHandler = .{},
    req: *Request,
    resp: *Response,
    out_buf: []u8,
    out: Out,
    written: std.ArrayList(u8) = .empty,
    date_line: [date.header_len]u8 = undefined,
    opts: Options,
    closed: bool = false,

    fn init(opts: Options, pool_buf: usize, out_size: usize) !*Harness {
        const h = try testing.allocator.create(Harness);
        const out_buf = try testing.allocator.alloc(u8, out_size);
        h.* = .{
            .pool = try BufferPool.init(testing.allocator, pool_buf, 2),
            .req = try Request.init(testing.allocator),
            .resp = try Response.init(testing.allocator, 8192, 1024),
            .out_buf = out_buf,
            .out = .{ .buf = out_buf },
            .opts = opts,
        };
        date.formatHeader(&h.date_line, 784111777);
        return h;
    }

    fn deinit(h: *Harness) void {
        h.session.deinit(&h.pool);
        h.pool.deinit();
        h.req.deinit();
        h.resp.deinit();
        h.written.deinit(testing.allocator);
        testing.allocator.free(h.out_buf);
        testing.allocator.destroy(h);
    }

    fn flush(h: *Harness) !void {
        try h.written.appendSlice(testing.allocator, h.out.buf[0..h.out.len]);
        try h.written.appendSlice(testing.allocator, h.out.body);
        h.out.clear();
    }

    /// Feed bytes as if they arrived in one read, then run the loop the way
    /// the worker does.
    fn feed(h: *Harness, bytes: []const u8) !void {
        var rest = bytes;
        while (rest.len > 0) {
            const space = try h.session.readSpace(&h.pool, h.opts);
            const n = @min(space.len, rest.len);
            @memcpy(space[0..n], rest[0..n]);
            h.session.commitRead(n);
            rest = rest[n..];
            try h.run();
            if (h.closed) return;
        }
    }

    fn run(h: *Harness) !void {
        const ctx: Context(EchoHandler) = .{
            .handler = &h.handler,
            .req = h.req,
            .resp = h.resp,
            .date = &h.date_line,
            .opts = h.opts,
        };
        while (true) {
            const action = process(EchoHandler, &h.session, &ctx, &h.out);
            try h.flush();
            switch (action) {
                .flush => continue,
                .need_more => break,
                .close, .upgrade => {
                    h.closed = true;
                    break;
                },
                .wait => break,
            }
        }
        h.session.releaseIfIdle(&h.pool);
    }
};

const DATE = "date: Sun, 06 Nov 1994 08:49:37 GMT\r\n";

test "single request" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nx-path: /a\r\ncontent-length: 0\r\n" ++ DATE ++ "\r\n", h.written.items);
    // The buffer went back to the pool.
    try testing.expectEqual(@as(usize, 0), h.session.buf.len);
}

test "HTTP/1.0 and close semantics" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("GET /a HTTP/1.0\r\n\r\nGET /ignored HTTP/1.0\r\n\r\n");
    try testing.expect(h.closed);
    try testing.expectEqual(@as(usize, 1), h.handler.calls);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nx-path: /a\r\ncontent-length: 0\r\n" ++ DATE ++ "connection: close\r\n\r\n", h.written.items);
}

test "HEAD omits the body but keeps its length" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("HEAD /big HTTP/1.1\r\nHost: x\r\n\r\n");
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nx-path: /big\r\ncontent-length: 3000\r\n" ++ DATE ++ "\r\n", h.written.items);
}

test "errors get a response and close" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("GET / HTTP/1.1\r\n\r\n");
    try testing.expect(h.closed);
    try testing.expectEqualStrings("HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n" ++ DATE ++ "connection: close\r\n\r\n", h.written.items);
}

test "expect 100-continue" {
    const h = try Harness.init(.{}, 4096, 4096);
    defer h.deinit();
    try h.feed("POST /e HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", h.written.items);
    try h.feed("hello");
    try testing.expect(std.mem.endsWith(u8, h.written.items, "\r\n\r\nhello"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, h.written.items, "100 Continue"));
}

test "body larger than the pool buffer grows the buffer" {
    const h = try Harness.init(.{}, 256, 4096);
    defer h.deinit();
    const body = parser.repeat("z", 2000);
    try h.feed(std.fmt.comptimePrint("POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{body.len}) ++ body);
    try testing.expect(std.mem.endsWith(u8, h.written.items, "\r\n\r\n" ++ body));
}

test "oversized body is rejected" {
    const h = try Harness.init(.{ .limits = .{ .max_body_size = 10 } }, 4096, 4096);
    defer h.deinit();
    try h.feed("POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n");
    try testing.expect(h.closed);
    try testing.expect(std.mem.startsWith(u8, h.written.items, "HTTP/1.1 413 "));
}

// The property from PLAN.md Phase 2: any split of the input, including
// byte-by-byte, and any amount of pipelining gives identical output.
test "random splits and pipelining produce identical output" {
    const requests = [_][]const u8{
        "GET /1 HTTP/1.1\r\nHost: x\r\n\r\n",
        "POST /2 HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world",
        "\r\nGET /3?q=1 HTTP/1.1\r\nHost: x\r\nCookie: " ++ parser.repeat("c", 600) ++ "\r\n\r\n",
        "POST /4 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;e=1\r\n world\r\n0\r\nT: v\r\n\r\n",
        "GET /big HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /6 HTTP/1.1\r\nHost: x\r\n\r\n",
    };
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    for (0..16) |i| try input.appendSlice(testing.allocator, requests[i % requests.len]);
    try input.appendSlice(testing.allocator, "GET /close HTTP/1.1\r\nHost: x\r\n\r\n");

    // Reference: everything in one read.
    const ref = try Harness.init(.{}, 512, 2048);
    defer ref.deinit();
    try ref.feed(input.items);
    try testing.expect(ref.closed);
    try testing.expectEqual(@as(usize, 17), ref.handler.calls);

    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    for (0..200) |iteration| {
        const h = try Harness.init(.{}, 512, 2048);
        defer h.deinit();
        var rest = input.items;
        while (rest.len > 0 and !h.closed) {
            const max_chunk: usize = if (iteration == 0) 1 else 1 + random.uintLessThan(usize, 300);
            const n = @min(rest.len, max_chunk);
            try h.feed(rest[0..n]);
            rest = rest[n..];
        }
        try testing.expect(h.closed);
        try testing.expectEqualStrings(ref.written.items, h.written.items);
    }
}

// Fuzz target: arbitrary bytes, split arbitrarily. The state machine must not
// crash or leak, and the split must never change the output. Without --fuzz
// this runs over the corpus as a regression test.
fn fuzzSplitInvariance(_: void, smith: *std.testing.Smith) anyerror!void {
    var input_buf: [2048]u8 = undefined;
    const input = input_buf[0..smith.slice(&input_buf)];

    const whole = try Harness.init(.{ .limits = .{ .max_header_bytes = 1024, .max_body_size = 512 } }, 128, 2048);
    defer whole.deinit();
    try whole.feed(input);

    const split = try Harness.init(whole.opts, 128, 2048);
    defer split.deinit();
    var rest: []const u8 = input;
    while (rest.len > 0 and !split.closed) {
        const n = @min(rest.len, @as(usize, smith.value(u8)) + 1);
        try split.feed(rest[0..n]);
        rest = rest[n..];
    }
    try testing.expectEqual(whole.closed, split.closed);
    try testing.expectEqualStrings(whole.written.items, split.written.items);
}

test "fuzz: split invariance" {
    try std.testing.fuzz({}, fuzzSplitInvariance, .{ .corpus = &.{
        "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n",
        "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
        "POST /p HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3;e\r\nabc\r\n0\r\nT: v\r\n\r\n",
        "POST /p HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc",
        "\r\n\r\nGET /close HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
        "HEAD /big HTTP/1.1\r\nHost: x\r\n\r\n",
    } });
}
