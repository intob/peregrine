//! h3/conn.zig over quic/conn.zig, driven by the QUIC test client speaking
//! HTTP/3: requests and responses, bodies, exchanges, trailers, control
//! and QPACK stream rules, GOAWAY, malformed requests.
const std = @import("std");
const quic = @import("../quic/conn.zig");
const packet = @import("../quic/packet.zig");
const test_client = @import("../quic/test_client.zig");
const h3 = @import("./conn.zig");
const frame = @import("./frame.zig");
const qpack = @import("./qpack.zig");
const credentials = @import("../tls/credentials.zig");
const handshake = @import("../tls/handshake.zig");
const exchange = @import("../http/exchange.zig");
const date = @import("../http/date.zig");
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const Header = @import("../header.zig").Header;
const Mailbox = @import("../mailbox.zig").Mailbox;
const BufferPool = @import("../http/session.zig").BufferPool;
const ws = @import("../ws/conn.zig");
const ws_protocol = @import("../ws/protocol.zig");
const ws_upgrader = @import("../ws/upgrader.zig");
const qframe = @import("../quic/frame.zig");
const sys = @import("../sys.zig");
const Client = test_client.Client;
const testing = std.testing;

const server_cid = [8]u8{ 0x5e, 0x5e, 1, 2, 3, 4, 5, 6 };

const TestHandler = struct {
    log: std.ArrayList(u8) = .empty,
    exchanges: std.ArrayList(exchange.Exchange) = .empty,
    aborts: usize = 0,
    big: []const u8 = "",
    /// Streamed bodies (paths under /up): calls, bytes, and the ends.
    bodies: std.ArrayList(u8) = .empty,
    chunks: usize = 0,
    received: usize = 0,
    /// handleBody pauses after each chunk.
    pause: bool = false,
    /// WebSockets: the last one opened, and what the hooks saw.
    ws_conn: ?*ws.Conn = null,
    ws_log: std.ArrayList(u8) = .empty,

    pub fn handleWSConn(self: *TestHandler, conn: *ws.Conn) void {
        self.ws_conn = conn;
        self.ws_log.appendSlice(testing.allocator, "open;") catch unreachable;
    }

    pub fn handleWSDisconn(self: *TestHandler, conn: *ws.Conn) void {
        if (self.ws_conn == conn) self.ws_conn = null;
        self.ws_log.appendSlice(testing.allocator, "gone;") catch unreachable;
    }

    /// Echoes text and binary; "close-me" starts the close handshake,
    /// "flood" sends 200 binary messages of 1000 bytes.
    pub fn handleWSFrame(self: *TestHandler, conn: *ws.Conn, fr: *ws.Frame) void {
        const p = fr.getPayload();
        self.ws_log.print(testing.allocator, "{s}:{s};", .{ fr.opcode.toString(), p[0..@min(p.len, 16)] }) catch unreachable;
        switch (fr.opcode) {
            .text, .binary => {},
            else => return,
        }
        if (std.mem.eql(u8, p, "close-me")) {
            conn.close(1000, "bye") catch unreachable;
        } else if (std.mem.eql(u8, p, "flood")) {
            for (0..200) |i| conn.sendBinary(&(@as([1000]u8, @splat(@truncate(i))))) catch unreachable;
        } else {
            conn.send(p, fr.opcode == .binary) catch unreachable;
        }
    }

    pub fn handleHead(_: *TestHandler, req: *Request, resp: *Response) exchange.BodyMode {
        const path = req.getPath();
        if (std.mem.eql(u8, path, "/reject")) {
            resp.status = .forbidden;
            resp.setBodyBorrowed("no");
            return .reject;
        }
        return if (std.mem.startsWith(u8, path, "/up")) .stream else .buffer;
    }

    pub fn handleBody(self: *TestHandler, ex: exchange.Exchange, chunk: []const u8, end: ?[]const Header) exchange.BodyAction {
        const a = testing.allocator;
        self.chunks += 1;
        self.received += chunk.len;
        if (end) |trailers| {
            self.bodies.print(a, "END n={d}", .{self.received}) catch unreachable;
            for (trailers) |t| self.bodies.print(a, " [{s}={s}]", .{ t.key, t.value }) catch unreachable;
            self.bodies.append(a, '\n') catch unreachable;
            var buf: [32]u8 = undefined;
            ex.respond(.{}, std.fmt.bufPrint(&buf, "got {d}", .{self.received}) catch unreachable) catch unreachable;
            self.received = 0;
            return .more;
        }
        return if (self.pause) .pause else .more;
    }

    pub fn handleRequest(self: *TestHandler, req: *Request, resp: *Response) void {
        const a = testing.allocator;
        self.log.print(a, "{s} {s}", .{ @tagName(req.method), req.path_and_query }) catch unreachable;
        for (req.getHeaders()) |h| {
            if (std.mem.startsWith(u8, h.key, "x-") or std.mem.eql(u8, h.key, "host")) {
                self.log.print(a, " [{s}={s}]", .{ h.key, h.value }) catch unreachable;
            }
        }
        if (req.body.len > 0) self.log.print(a, " body={d}", .{req.body.len}) catch unreachable;
        for (req.trailers) |t| self.log.print(a, " trailer[{s}={s}]", .{ t.key, t.value }) catch unreachable;
        self.log.append(a, '\n') catch unreachable;
        const path = req.getPath();
        if (std.mem.eql(u8, path, "/up-sync")) {
            resp.setBodyBorrowed("early");
            return;
        }
        if (std.mem.startsWith(u8, path, "/up")) {
            self.exchanges.append(a, resp.later() catch unreachable) catch unreachable;
            return;
        }
        if (std.mem.eql(u8, path, "/ws")) {
            ws_upgrader.handleUpgrade(undefined, req, resp) catch {
                resp.status = .bad_request;
            };
            return;
        }
        resp.addNewHeader("Content-Type", "text/plain") catch {};
        if (std.mem.eql(u8, path, "/later") or std.mem.eql(u8, path, "/stream")) {
            const ex = if (path[1] == 'l') resp.later() catch unreachable else resp.stream() catch unreachable;
            self.exchanges.append(a, ex) catch unreachable;
            return;
        }
        if (std.mem.eql(u8, path, "/big")) {
            resp.setBodyBorrowed(self.big);
            return;
        }
        if (std.mem.eql(u8, path, "/echo")) {
            _ = resp.setBody(req.body) catch {};
            return;
        }
        resp.setBodyBorrowed("Hello, World!");
    }

    pub fn handleAbort(self: *TestHandler, _: exchange.Exchange) void {
        self.aborts += 1;
    }
};

const Parsed = struct {
    status: ?[]const u8 = null,
    headers: std.ArrayList(u8) = .empty,
    body: std.ArrayList(u8) = .empty,
    trailers: std.ArrayList(u8) = .empty,
    frames: usize = 0,

    fn deinit(p: *Parsed) void {
        p.headers.deinit(testing.allocator);
        p.body.deinit(testing.allocator);
        p.trailers.deinit(testing.allocator);
        if (p.status) |st| testing.allocator.free(st);
    }
};

const Harness = struct {
    a: std.mem.Allocator,
    creds: credentials.Credentials,
    tls_cfg: handshake.Config,
    cfg: quic.Config,
    server: ?*quic.Conn = null,
    h3c: ?*h3.Conn = null,
    client: *Client,
    handler: TestHandler = .{},
    req: *Request,
    resp: *Response,
    mailbox: Mailbox,
    slab: exchange.Slab,
    date_line: [date.header_len]u8 = undefined,
    now_us: u64 = 1_000_000,
    now: u32 = 1000,
    qdec: qpack.Decoder,
    h3_opts: h3.Options = .{},
    pool: BufferPool,
    /// The client's control stream (after `startClient`).
    control: u64 = 0,

    fn init() !*Harness {
        const a = testing.allocator;
        const h = try a.create(Harness);
        errdefer a.destroy(h);
        const td = credentials.testdata;
        h.* = .{
            .a = a,
            .creds = try .fromPem(a, td.p256_cert, td.p256_key),
            .tls_cfg = undefined,
            .cfg = undefined,
            .client = try Client.init(a, .{ .max_stream_data = 8 << 20 }),
            .req = try Request.init(a),
            .resp = try Response.init(a, 64 * 1024, 2048),
            .mailbox = try Mailbox.init(a, 16, try sys.Waker.init()),
            .slab = undefined,
            .qdec = try qpack.Decoder.init(a, .{}),
            .pool = try BufferPool.init(a, 1024, 2),
        };
        h.mailbox.bind();
        h.slab = try exchange.Slab.init(a, 8, &h.mailbox, .{});
        h.resp.exchanges = &h.slab;
        h.resp.now = &h.now;
        h.tls_cfg = .{ .credentials = &h.creds, .alpn = &.{"h3"}, .quic = true, .groups = &.{.x25519} };
        h.cfg = .{ .tls = &h.tls_cfg };
        date.formatHeader(&h.date_line, 784111777);
        return h;
    }

    fn deinit(h: *Harness) void {
        if (h.h3c) |c| {
            c.abortAll(&h.ctx());
            c.deinit();
        }
        if (h.server) |s| s.deinit();
        h.client.deinit();
        h.creds.deinit();
        h.slab.deinit();
        h.mailbox.waker.deinit();
        h.mailbox.deinit();
        h.req.deinit();
        h.resp.deinit();
        h.qdec.deinit();
        h.pool.deinit();
        h.handler.log.deinit(h.a);
        h.handler.bodies.deinit(h.a);
        h.handler.exchanges.deinit(h.a);
        h.handler.ws_log.deinit(h.a);
        h.a.destroy(h);
    }

    fn ctx(h: *Harness) h3.Context(TestHandler) {
        return .{
            .handler = &h.handler,
            .req = h.req,
            .resp = h.resp,
            .date = &h.date_line,
            .now = h.now,
            .now_us = h.now_us,
            .exchanges = &h.slab,
            .conn_slot = 3,
            .conn_gen = 7,
            .pool = &h.pool,
        };
    }

    fn toServer(h: *Harness, dgram: []u8) !void {
        if (h.server == null) {
            const hdr = try packet.parseHeader(dgram, 8);
            var entropy: [handshake.entropy_len]u8 = @splat(9);
            h.server = try quic.Conn.init(h.a, &h.cfg, .{
                .odcid = hdr.dcid,
                .client_scid = hdr.scid,
                .scid = &server_cid,
                .reset_token = @splat(0xee),
                .entropy = &entropy,
                .now = h.now_us,
            });
            h.h3c = try h3.Conn.init(h.a, h.h3_opts, h.server.?);
        }
        _ = h.server.?.recv(dgram, h.now_us);
        h.serverProcess();
    }

    fn serverProcess(h: *Harness) void {
        const c = ctx(h);
        h.h3c.?.process(TestHandler, &c);
    }

    fn drainMailbox(h: *Harness) void {
        var entries: [16]@import("../mailbox.zig").Entry = undefined;
        while (true) {
            const n = h.mailbox.drain(&entries);
            if (n == 0) break;
            for (entries[0..n]) |e| {
                const c = ctx(h);
                h.h3c.?.onExchangePosted(TestHandler, &c, e.slot);
            }
        }
    }

    fn run(h: *Harness, rounds: usize) !void {
        var buf: [1500]u8 = undefined;
        for (0..rounds) |_| {
            var progress = false;
            while (true) {
                const n = try h.client.send(&buf);
                if (n == 0) break;
                progress = true;
                try h.toServer(buf[0..n]);
            }
            if (h.server) |s| {
                h.drainMailbox();
                h.serverProcess();
                while (true) {
                    const n = s.send(&buf, h.now_us);
                    if (n == 0) break;
                    progress = true;
                    try h.client.recv(buf[0..n]);
                }
                if (s.isClosed()) return;
            }
            h.now_us += 1000;
            if (!progress) {
                if (h.server) |s| {
                    if (s.deadline()) |d| if (d < h.now_us + 2 * std.time.us_per_s) {
                        if (d > h.now_us) h.now_us = d;
                        s.onTimeout(h.now_us);
                        h.serverProcess();
                    };
                }
                try h.client.retransmit();
            }
        }
    }

    /// Opens the client's control and QPACK streams with SETTINGS.
    fn startClient(h: *Harness) !void {
        try h.run(10);
        const control = try h.client.openUni();
        h.control = control;
        try h.client.write(control, &.{ 0x00, 0x04, 0x03, 0x06, 0x50, 0x00 }, false);
        const enc = try h.client.openUni();
        try h.client.write(enc, &.{0x02}, false);
        const dec = try h.client.openUni();
        try h.client.write(dec, &.{0x03}, false);
    }

    fn request(h: *Harness, method: []const u8, path: []const u8, extra: []const qpack.Field, body: []const u8) !u64 {
        const id = try h.client.openBidi();
        try h.writeHeaders(id, &([_]qpack.Field{
            .{ .name = ":method", .value = method },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "example.com" },
            .{ .name = ":path", .value = path },
        }), extra, false);
        if (body.len > 0) {
            var hdr: [16]u8 = undefined;
            var w: packet.Writer = .{ .buf = &hdr };
            frame.writeHeader(&w, .data, body.len);
            try h.client.write(id, w.written(), false);
            try h.client.write(id, body, false);
        }
        try h.client.write(id, "", true);
        return id;
    }

    fn writeHeaders(h: *Harness, id: u64, pseudo: []const qpack.Field, extra: []const qpack.Field, fin: bool) !void {
        var section: [2048]u8 = undefined;
        var n: usize = 2;
        @memcpy(section[0..2], &qpack.section_prefix);
        for (pseudo) |f| n += try qpack.encodeField(section[n..], f.name, f.value);
        for (extra) |f| n += try qpack.encodeField(section[n..], f.name, f.value);
        var hdr: [16]u8 = undefined;
        var w: packet.Writer = .{ .buf = &hdr };
        frame.writeHeader(&w, .headers, n);
        try h.client.write(id, w.written(), false);
        try h.client.write(id, section[0..n], fin);
    }

    /// Parses a response stream's frames.
    fn response(h: *Harness, id: u64) !Parsed {
        var p: Parsed = .{};
        errdefer p.deinit();
        var data = h.client.readAll(id);
        var headers_seen = false;
        while (data.len > 0) {
            const fh = frame.parseHeader(data) orelse return error.Truncated;
            if (data.len < fh.size + fh.len) return error.Truncated;
            const payload = data[fh.size..][0..@intCast(fh.len)];
            data = data[fh.size + payload.len ..];
            p.frames += 1;
            switch (fh.type) {
                .headers => {
                    const Sink = struct {
                        p: *Parsed,
                        trailers: bool,
                        pub fn header(self: *@This(), name: []const u8, value: []const u8) !void {
                            if (std.mem.eql(u8, name, ":status")) {
                                self.p.status = try testing.allocator.dupe(u8, value);
                                return;
                            }
                            const list = if (self.trailers) &self.p.trailers else &self.p.headers;
                            try list.print(testing.allocator, "{s}={s};", .{ name, value });
                        }
                    };
                    var sink: Sink = .{ .p = &p, .trailers = headers_seen };
                    try h.qdec.decode(payload, &sink);
                    headers_seen = true;
                },
                .data => try p.body.appendSlice(testing.allocator, payload),
                else => {},
            }
        }
        return p;
    }

    fn serverStreamData(h: *Harness, id: u64) []const u8 {
        return h.client.readAll(id);
    }
};

test "HTTP/3: GET, POST with a body, HEAD, 404-style paths, many at once" {
    const h = try Harness.init();
    defer h.deinit();
    try h.startClient();
    const get = try h.request("GET", "/hello", &.{.{ .name = "x-trace", .value = "abc" }}, "");
    const post = try h.request("POST", "/echo", &.{}, "ping pong body");
    const head = try h.request("HEAD", "/hello", &.{}, "");
    try h.run(30);

    var r = try h.response(get);
    defer r.deinit();
    try testing.expectEqualStrings("200", r.status.?);
    try testing.expectEqualStrings("Hello, World!", r.body.items);
    try testing.expect(std.mem.indexOf(u8, r.headers.items, "content-type=text/plain;") != null);
    try testing.expect(std.mem.indexOf(u8, r.headers.items, "content-length=13;") != null);
    try testing.expect(std.mem.indexOf(u8, r.headers.items, "date=") != null);
    try testing.expect(h.client.finished(get));

    var p = try h.response(post);
    defer p.deinit();
    try testing.expectEqualStrings("ping pong body", p.body.items);

    var hd = try h.response(head);
    defer hd.deinit();
    try testing.expectEqualStrings("200", hd.status.?);
    try testing.expectEqual(@as(usize, 0), hd.body.items.len);
    try testing.expect(std.mem.indexOf(u8, hd.headers.items, "content-length=13;") != null);

    try testing.expect(std.mem.indexOf(u8, h.handler.log.items, "GET /hello [x-trace=abc] [host=example.com]\n") != null);
    try testing.expect(std.mem.indexOf(u8, h.handler.log.items, "POST /echo [host=example.com] body=14\n") != null);

    // Many requests at once.
    var ids: [60]u64 = undefined;
    for (&ids) |*id| id.* = try h.request("GET", "/", &.{}, "");
    try h.run(60);
    for (ids) |id| {
        var x = try h.response(id);
        defer x.deinit();
        try testing.expectEqualStrings("Hello, World!", x.body.items);
    }
    try testing.expectEqual(@as(u32, 0), h.h3c.?.activeRequests());
}

test "HTTP/3: a 3 MB response and a 2 MB upload" {
    const h = try Harness.init();
    defer h.deinit();
    h.h3_opts.limits.max_body_size = 4 << 20;
    const big = try testing.allocator.alloc(u8, 3 * 1024 * 1024);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i * 31);
    h.handler.big = big;
    try h.startClient();
    const id = try h.request("GET", "/big", &.{}, "");
    try h.run(5000);
    var r = try h.response(id);
    defer r.deinit();
    try testing.expectEqual(big.len, r.body.items.len);
    try testing.expectEqualSlices(u8, big, r.body.items);

    const up = try testing.allocator.alloc(u8, 2 * 1024 * 1024);
    defer testing.allocator.free(up);
    for (up, 0..) |*b, i| b.* = @truncate(i * 7);
    h.handler.log.clearRetainingCapacity();
    const id2 = try h.request("POST", "/hello", &.{}, up);
    try h.run(5000);
    var r2 = try h.response(id2);
    defer r2.deinit();
    try testing.expectEqualStrings("Hello, World!", r2.body.items);
    try testing.expectEqualStrings("POST /hello [host=example.com] body=2097152\n", h.handler.log.items);
}

test "HTTP/3: a body over the limit gets 413 and STOP_SENDING" {
    const h = try Harness.init();
    defer h.deinit();
    h.h3_opts.limits.max_body_size = 1000;
    try h.startClient();
    const up: [5000]u8 = @splat('u');
    const id = try h.request("POST", "/echo", &.{}, &up);
    try h.run(100);
    var r = try h.response(id);
    defer r.deinit();
    try testing.expectEqualStrings("413", r.status.?);
    try testing.expectEqual(@as(?u64, 0x100), (try h.client.getStream(id)).stop_code);
    try testing.expectEqualStrings("", h.handler.log.items);
    // The connection carries on.
    const ok = try h.request("GET", "/", &.{}, "");
    try h.run(20);
    var r2 = try h.response(ok);
    defer r2.deinit();
    try testing.expectEqualStrings("Hello, World!", r2.body.items);
}

/// A request with a body in one DATA frame, then trailers.
fn requestWithTrailers(h: *Harness, path: []const u8, body: []const u8, trailers: []const qpack.Field) !u64 {
    const id = try h.client.openBidi();
    try h.writeHeaders(id, &([_]qpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = path },
    }), &.{}, false);
    var hdr: [16]u8 = undefined;
    var w: packet.Writer = .{ .buf = &hdr };
    frame.writeHeader(&w, .data, body.len);
    try h.client.write(id, w.written(), false);
    try h.client.write(id, body, false);
    try h.writeHeaders(id, &.{}, trailers, true);
    return id;
}

test "HTTP/3: handleHead reject and stream, trailers, an early answer" {
    const h = try Harness.init();
    defer h.deinit();
    h.h3_opts.limits.max_body_size = 1000;
    try h.startClient();
    const up: [3000]u8 = @splat('u');
    // Rejected: without a body the request just ends; with one (more than
    // a packet, so not all in yet), the rest is refused with
    // STOP_SENDING(H3_NO_ERROR).
    const rej = try h.request("GET", "/reject", &.{}, "");
    const rej_body = try h.request("POST", "/reject", &.{}, &up);
    // Streamed beyond max_body_size, with trailers; answered at once.
    const streamed = try requestWithTrailers(h, "/up", &up, &.{.{ .name = "x-sum", .value = "3000" }});
    const early = try h.request("POST", "/up-sync", &.{}, &up);
    // Buffered trailers reach the request.
    const buffered = try requestWithTrailers(h, "/echo", "abc", &.{.{ .name = "x-t", .value = "1" }});
    try h.run(100);
    inline for (.{ rej, rej_body }) |id| {
        var r = try h.response(id);
        defer r.deinit();
        try testing.expectEqualStrings("403", r.status.?);
        try testing.expectEqualStrings("no", r.body.items);
    }
    try testing.expectEqual(@as(?u64, null), (try h.client.getStream(rej)).stop_code);
    try testing.expectEqual(@as(?u64, 0x100), (try h.client.getStream(rej_body)).stop_code);
    var s = try h.response(streamed);
    defer s.deinit();
    try testing.expectEqualStrings("got 3000", s.body.items);
    try testing.expectEqualStrings("END n=3000 [x-sum=3000]\n", h.handler.bodies.items);
    var e = try h.response(early);
    defer e.deinit();
    try testing.expectEqualStrings("early", e.body.items);
    try testing.expectEqual(@as(?u64, 0x100), (try h.client.getStream(early)).stop_code);
    var b = try h.response(buffered);
    defer b.deinit();
    try testing.expectEqualStrings("abc", b.body.items);
    try testing.expect(std.mem.indexOf(u8, h.handler.log.items, "POST /echo [host=example.com] body=3 trailer[x-t=1]\n") != null);
    try testing.expectEqual(@as(u32, 0), h.h3c.?.activeRequests());
}

test "HTTP/3: a paused body holds MAX_STREAM_DATA back until resumed" {
    const h = try Harness.init();
    defer h.deinit();
    try h.startClient();
    h.handler.pause = true;
    const up = try testing.allocator.alloc(u8, 3 * 1024 * 1024);
    defer testing.allocator.free(up);
    @memset(up, 'p');
    const id = try h.request("POST", "/up", &.{}, up);
    try h.run(400);
    // One chunk was delivered; the rest waits in the stream, and the
    // client is held at the first window (1 MiB).
    try testing.expectEqual(@as(usize, 1), h.handler.chunks);
    const st = try h.client.getStream(id);
    try testing.expectEqual(@as(u64, 1 << 20), st.send.max_data);
    try testing.expect(st.send.blocked());
    try testing.expectEqualStrings("", h.handler.bodies.items);
    // Resumed: everything else arrives.
    h.handler.pause = false;
    try h.handler.exchanges.items[0].resumeBody();
    try h.run(5000);
    var r = try h.response(id);
    defer r.deinit();
    try testing.expectEqualStrings("got 3145728", r.body.items);
    try testing.expectEqualStrings("END n=3145728\n", h.handler.bodies.items);
}

test "HTTP/3: later() and stream() exchanges with trailers" {
    const h = try Harness.init();
    defer h.deinit();
    try h.startClient();
    const later = try h.request("GET", "/later", &.{}, "");
    const streamed = try h.request("GET", "/stream", &.{}, "");
    try h.run(20);
    try testing.expectEqual(@as(usize, 2), h.handler.exchanges.items.len);
    const ex_later = h.handler.exchanges.items[0];
    const ex_stream = h.handler.exchanges.items[1];
    try ex_stream.write("part one, ");
    try h.run(10);
    try ex_later.respond(.{ .status = .accepted, .headers = &.{.{ .key = "X-Later", .value = "yes" }} }, "done later");
    try ex_stream.write("part two");
    try ex_stream.finish(&.{.{ .key = "X-Checksum", .value = "42" }});
    try h.run(20);

    var a = try h.response(later);
    defer a.deinit();
    try testing.expectEqualStrings("202", a.status.?);
    try testing.expectEqualStrings("done later", a.body.items);
    try testing.expect(std.mem.indexOf(u8, a.headers.items, "x-later=yes;") != null);
    var b = try h.response(streamed);
    defer b.deinit();
    try testing.expectEqualStrings("200", b.status.?);
    try testing.expectEqualStrings("part one, part two", b.body.items);
    try testing.expectEqualStrings("x-checksum=42;", b.trailers.items);
    try testing.expect(h.client.finished(streamed));
}

test "HTTP/3: malformed and incomplete requests are stream errors" {
    const h = try Harness.init();
    defer h.deinit();
    try h.startClient();
    // An uppercase field name.
    const bad = try h.request("GET", "/", &.{.{ .name = "X-Upper", .value = "1" }}, "");
    // No :path.
    const id2 = try h.client.openBidi();
    try h.writeHeaders(id2, &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" } }, &.{}, true);
    // A FIN in the middle of HEADERS.
    const id3 = try h.client.openBidi();
    try h.client.write(id3, &.{ 0x01, 0x10, 0x00 }, true);
    // A content-length that doesn't match the body.
    const id4 = try h.request("POST", "/echo", &.{.{ .name = "content-length", .value = "3" }}, "four");
    // DATA before HEADERS: a connection error, tested separately below.
    const good = try h.request("GET", "/", &.{}, "");
    try h.run(30);
    try testing.expectEqual(@as(?u64, 0x10e), (try h.client.getStream(bad)).reset_code);
    try testing.expectEqual(@as(?u64, 0x10e), (try h.client.getStream(id2)).reset_code);
    try testing.expectEqual(@as(?u64, 0x10d), (try h.client.getStream(id3)).reset_code);
    try testing.expectEqual(@as(?u64, 0x10e), (try h.client.getStream(id4)).reset_code);
    var r = try h.response(good);
    defer r.deinit();
    try testing.expectEqualStrings("Hello, World!", r.body.items);
    try testing.expect(h.client.closed == null);
}

fn expectConnectionError(code: u64, setup: anytype) !void {
    const h = try Harness.init();
    defer h.deinit();
    try h.run(10);
    try setup(h);
    try h.run(30);
    const closed = h.client.closed orelse return error.TestExpectedClose;
    try testing.expect(closed.app);
    try testing.expectEqual(code, closed.code);
}

fn connectWs(h: *Harness, path: []const u8) !u64 {
    const id = try h.client.openBidi();
    try h.writeHeaders(id, &([_]qpack.Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = path },
    }), &.{.{ .name = "sec-websocket-version", .value = "13" }}, false);
    return id;
}

/// One masked WebSocket frame in a DATA frame.
fn wsSend(h: *Harness, id: u64, op: ws_protocol.Opcode, payload: []const u8, fin: bool) !void {
    var buf: [2048]u8 = undefined;
    const f = ws_protocol.encodeFrame(&buf, true, op, payload, .{ 1, 2, 3, 4 });
    var hdr: [16]u8 = undefined;
    var w: packet.Writer = .{ .buf = &hdr };
    frame.writeHeader(&w, .data, f.len);
    try h.client.write(id, w.written(), false);
    try h.client.write(id, f, fin);
}

/// The server's SETTINGS, from its control stream (stream 3).
fn serverSettings(h: *Harness) !frame.Settings {
    const data = h.client.readAll(3);
    if (data.len < 1 or data[0] != 0x00) return error.NoControlStream;
    const fh = frame.parseHeader(data[1..]) orelse return error.Truncated;
    return frame.parseSettings(data[1 + fh.size ..][0..@intCast(fh.len)]);
}

test "WebSocket over HTTP/3 (RFC 9220): the setting, validation, echo, close both ways, FIN, STOP_SENDING" {
    {
        // Not advertised: :protocol is malformed.
        const off = try Harness.init();
        defer off.deinit();
        try off.startClient();
        const id = try connectWs(off, "/ws");
        try off.run(30);
        try testing.expect(!(try serverSettings(off)).enable_connect_protocol);
        try testing.expectEqual(@as(?u64, @backingInt(frame.ErrorCode.message_error)), (try off.client.getStream(id)).reset_code);
        try testing.expectEqualStrings("", off.handler.ws_log.items);
    }
    const h = try Harness.init();
    defer h.deinit();
    h.h3_opts.enable_connect_protocol = true;
    try h.startClient();
    const id = try connectWs(h, "/ws");
    try h.run(30);
    try testing.expect((try serverSettings(h)).enable_connect_protocol);
    {
        var r = try h.response(id);
        defer r.deinit();
        try testing.expectEqualStrings("200", r.status.?);
        try testing.expect(std.mem.indexOf(u8, r.headers.items, "content-length") == null);
    }
    try wsSend(h, id, .text, "hello", false);
    try wsSend(h, id, .ping, "p", false);
    try h.run(30);
    {
        var r = try h.response(id);
        defer r.deinit();
        try testing.expectEqualSlices(u8, "\x81\x05hello\x8a\x01p", r.body.items);
        try testing.expect(!h.client.finished(id));
    }
    // The client's close is echoed, then FIN and STOP_SENDING(H3_NO_ERROR)
    // for the client's side, still open.
    try wsSend(h, id, .close, "\x03\xe8", false);
    try h.run(30);
    {
        var r = try h.response(id);
        defer r.deinit();
        try testing.expect(std.mem.endsWith(u8, r.body.items, "\x88\x02\x03\xe8"));
        try testing.expect(h.client.finished(id));
        try testing.expectEqual(@as(?u64, 0x100), (try h.client.getStream(id)).stop_code);
    }
    try testing.expectEqualStrings("open;text:hello;ping:p;close:\x03\xe8;gone;", h.handler.ws_log.items);
    try testing.expect(std.mem.indexOf(u8, h.handler.log.items, "CONNECT /ws [host=example.com]\n") != null);
    h.handler.ws_log.clearRetainingCapacity();

    // Our close waits for the client's; the client's close with FIN ends it.
    const ours = try connectWs(h, "/ws");
    try wsSend(h, ours, .text, "close-me", false);
    try h.run(30);
    {
        var r = try h.response(ours);
        defer r.deinit();
        try testing.expectEqualSlices(u8, "\x88\x05\x03\xe8bye", r.body.items);
        try testing.expect(!h.client.finished(ours));
    }
    try wsSend(h, ours, .text, "late", false);
    try wsSend(h, ours, .close, "\x03\xe8", true);
    try h.run(30);
    try testing.expect(h.client.finished(ours));
    try testing.expectEqual(@as(?u64, null), (try h.client.getStream(ours)).stop_code);
    try testing.expectEqualStrings("open;text:close-me;close:\x03\xe8;gone;", h.handler.ws_log.items);
    h.handler.ws_log.clearRetainingCapacity();

    // FIN without a close frame is a TCP FIN; STOP_SENDING drops it; a
    // protocol violation fails it with 1002.
    const fin = try connectWs(h, "/ws");
    try h.client.write(fin, "", true);
    const stop = try connectWs(h, "/ws");
    const bad = try connectWs(h, "/ws");
    var hdr: [16]u8 = undefined;
    var w: packet.Writer = .{ .buf = &hdr };
    frame.writeHeader(&w, .data, 3);
    try h.client.write(bad, w.written(), false);
    try h.client.write(bad, &.{ 0x81, 0x01, 'x' }, false);
    try h.run(30);
    var sw: packet.Writer = .{ .buf = &hdr };
    qframe.writeStopSending(&sw, stop, 0x10c);
    try h.client.injectFrames(sw.written());
    try h.run(30);
    try testing.expect(h.client.finished(fin));
    {
        var r = try h.response(bad);
        defer r.deinit();
        try testing.expectEqualSlices(u8, "\x88\x02\x03\xea", r.body.items);
        try testing.expect(h.client.finished(bad));
    }
    try testing.expect((try h.client.getStream(stop)).reset_code != null);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, h.handler.ws_log.items, "open;"));
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, h.handler.ws_log.items, "gone;"));

    // A handler that doesn't take the WebSocket answers as usual.
    const other = try connectWs(h, "/other");
    try wsSend(h, other, .text, "ignored", false);
    try h.run(30);
    {
        var r = try h.response(other);
        defer r.deinit();
        try testing.expectEqualStrings("Hello, World!", r.body.items);
        try testing.expectEqual(@as(?u64, 0x100), (try h.client.getStream(other)).stop_code);
    }
    try testing.expectEqual(@as(u32, 0), h.h3c.?.activeRequests());
    try testing.expectEqual(@as(usize, 0), h.slab.active_count);
}

test "WebSocket over HTTP/3: output beyond the stream buffer, sends from another thread" {
    const h = try Harness.init();
    defer h.deinit();
    h.h3_opts.enable_connect_protocol = true;
    // 200 KB of output through a 16 KB window of unacknowledged data.
    h.h3_opts.stream_buffer = 16 * 1024;
    try h.startClient();
    const id = try connectWs(h, "/ws");
    try wsSend(h, id, .text, "flood", false);
    try wsSend(h, id, .text, "after", false);
    try h.run(400);
    const t = try std.Thread.spawn(.{}, struct {
        fn run(c: *ws.Conn) void {
            c.sendText("from elsewhere") catch unreachable;
        }
    }.run, .{h.handler.ws_conn.?});
    t.join();
    try h.run(30);
    var r = try h.response(id);
    defer r.deinit();
    // 200 binary frames of 1004 bytes, the echo, the other thread's.
    try testing.expectEqual(@as(usize, 200 * 1004 + 7 + 16), r.body.items.len);
    for (0..200) |i| {
        const f = r.body.items[i * 1004 ..][0..1004];
        try testing.expectEqualSlices(u8, &.{ 0x82, 0x7e, 0x03, 0xe8 }, f[0..4]);
        try testing.expect(std.mem.allEqual(u8, f[4..], @truncate(i)));
    }
    try testing.expectEqualSlices(u8, "\x81\x05after\x81\x0efrom elsewhere", r.body.items[200 * 1004 ..]);
    try testing.expectEqualStrings("open;text:flood;text:after;", h.handler.ws_log.items);
}

test "HTTP/3: control and QPACK stream rules" {
    // DATA on the control stream.
    try expectConnectionError(0x105, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x00, 0x04, 0x00, 0x00, 0x00 }, false);
        }
    }.f);
    // A first frame other than SETTINGS.
    try expectConnectionError(0x10a, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x00, 0x07, 0x01, 0x00 }, false);
        }
    }.f);
    // Two control streams.
    try expectConnectionError(0x103, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x00, 0x04, 0x00 }, false);
            const d = try h.client.openUni();
            try h.client.write(d, &.{ 0x00, 0x04, 0x00 }, false);
        }
    }.f);
    // The control stream closed.
    try expectConnectionError(0x104, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x00, 0x04, 0x00 }, true);
        }
    }.f);
    // HTTP/2's SETTINGS_ENABLE_PUSH.
    try expectConnectionError(0x109, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x00, 0x04, 0x02, 0x02, 0x00 }, false);
        }
    }.f);
    // An insert on the QPACK encoder stream (we allow no table).
    try expectConnectionError(0x201, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x02, 0xc1, 0x01, 'x' }, false);
        }
    }.f);
    // The encoder stream ended inside an instruction.
    try expectConnectionError(0x104, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x02, 0x3f }, true);
        }
    }.f);
    // A table capacity too large to decode, terminated and not.
    try expectConnectionError(0x201, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x02, 0x3f, 0xff, 0xff, 0xff, 0xff, 0x7f }, false);
        }
    }.f);
    try expectConnectionError(0x201, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x02, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff }, false);
        }
    }.f);
    // An Insert Count Increment too large to decode.
    try expectConnectionError(0x202, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x03, 0x7f, 0xff, 0xff, 0xff, 0xff, 0x7f }, false);
        }
    }.f);
    // A Section Acknowledgment on the decoder stream.
    try expectConnectionError(0x202, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x03, 0x80 }, false);
        }
    }.f);
    // A push stream from a client.
    try expectConnectionError(0x103, struct {
        fn f(h: *Harness) !void {
            const c = try h.client.openUni();
            try h.client.write(c, &.{ 0x01, 0x00 }, false);
        }
    }.f);
    // DATA before HEADERS on a request stream.
    try expectConnectionError(0x105, struct {
        fn f(h: *Harness) !void {
            const id = try h.client.openBidi();
            try h.client.write(id, &.{ 0x00, 0x01, 'x' }, true);
        }
    }.f);
    // A dynamic table reference in a request.
    try expectConnectionError(0x200, struct {
        fn f(h: *Harness) !void {
            const id = try h.client.openBidi();
            try h.client.write(id, &.{ 0x01, 0x03, 0x00, 0x00, 0x80 }, true);
        }
    }.f);
}

test "HTTP/3: unknown stream types and frame types are ignored" {
    const h = try Harness.init();
    defer h.deinit();
    try h.startClient();
    // A reserved stream type (0x1f * 3 + 0x21 = 0x80) is stopped.
    const g = try h.client.openUni();
    try h.client.write(g, &.{ 0x40, 0x80, 1, 2, 3 }, false);
    // A reserved frame type on a request stream, before HEADERS.
    const id = try h.client.openBidi();
    try h.client.write(id, &.{ 0x21, 0x02, 0xaa, 0xbb }, false);
    try h.writeHeaders(id, &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":authority", .value = "a" }, .{ .name = ":path", .value = "/" } }, &.{}, true);
    try h.run(30);
    try testing.expectEqual(@as(?u64, 0x103), (try h.client.getStream(g)).stop_code);
    var r = try h.response(id);
    defer r.deinit();
    try testing.expectEqualStrings("Hello, World!", r.body.items);
    try testing.expect(h.client.closed == null);
}

/// A PRIORITY_UPDATE frame (RFC 9218 §7.2), for the control stream.
fn priorityUpdate(buf: []u8, t: frame.FrameType, id: u64, value: []const u8) []const u8 {
    var w: packet.Writer = .{ .buf = buf };
    frame.writeHeader(&w, t, packet.varintLen(id) + value.len);
    w.varint(id);
    w.bytes(value);
    return w.written();
}

fn serverUrgency(h: *Harness, id: u64) struct { u3, bool } {
    const s = &h.server.?.streams[h.server.?.stream_map.get(id).?];
    return .{ s.urgency, s.incremental };
}

test "HTTP/3 priorities (RFC 9218): urgency first, incremental streams share" {
    const h = try Harness.init();
    defer h.deinit();
    const big = try testing.allocator.alloc(u8, 200_000);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    h.handler.big = big;
    try h.startClient();
    try h.run(10);
    // All dispatched before the server sends: the congestion window then
    // limits each round, and QUIC picks what goes in each packet.
    const lazy = try h.request("GET", "/big", &.{.{ .name = "priority", .value = "u=7" }}, "");
    const first = try h.request("GET", "/big", &.{.{ .name = "priority", .value = "u=0" }}, "");
    const normal = try h.request("GET", "/big", &.{}, "");
    const inc1 = try h.request("GET", "/big", &.{.{ .name = "priority", .value = "u=1, i" }}, "");
    const inc2 = try h.request("GET", "/big", &.{.{ .name = "priority", .value = "u=1, i" }}, "");
    var shared = false;
    for (0..2000) |_| {
        try h.run(1);
        const got = struct {
            fn f(c: *Client, id: u64) usize {
                return c.readAll(id).len;
            }
        }.f;
        const done = struct {
            fn f(c: *Client, id: u64) bool {
                return c.finished(id);
            }
        }.f;
        // Nothing for a stream while a more urgent one is unfinished.
        if (!done(h.client, first)) try testing.expectEqual(@as(usize, 0), got(h.client, inc1) + got(h.client, inc2) + got(h.client, normal) + got(h.client, lazy));
        if (!done(h.client, inc1) or !done(h.client, inc2)) try testing.expectEqual(@as(usize, 0), got(h.client, normal) + got(h.client, lazy));
        if (!done(h.client, normal)) try testing.expectEqual(@as(usize, 0), got(h.client, lazy));
        // The incremental pair is part-sent together at some point.
        if (got(h.client, inc1) > 0 and got(h.client, inc2) > 0 and !done(h.client, inc1) and !done(h.client, inc2)) shared = true;
        if (done(h.client, lazy)) break;
    }
    try testing.expect(shared);
    for ([_]u64{ lazy, first, normal, inc1, inc2 }) |id| {
        var r = try h.response(id);
        defer r.deinit();
        try testing.expectEqual(big.len, r.body.items.len);
    }
}

test "HTTP/3 priorities: PRIORITY_UPDATE before and after the request, header parsing" {
    const h = try Harness.init();
    defer h.deinit();
    try h.startClient();
    try h.run(10);
    var buf: [64]u8 = undefined;
    // For idle stream 4 (stream 0 comes first): it wins over the header.
    try h.client.write(h.control, priorityUpdate(&buf, .priority_update_request, 4, "u=6, i"), false);
    try h.client.write(h.control, priorityUpdate(&buf, .priority_update_request, 4, "u=5, i"), false);
    try h.client.write(h.control, priorityUpdate(&buf, .priority_update_request, 4, "u=x="), false); // ignored
    try h.run(10);
    const a = try h.request("GET", "/later", &.{.{ .name = "priority", .value = "u=2" }}, "");
    const b = try h.request("GET", "/later", &.{.{ .name = "priority", .value = "u=0" }}, "");
    const c = try h.request("GET", "/later", &.{ .{ .name = "priority", .value = "u=1" }, .{ .name = "priority", .value = "i" } }, "");
    const d = try h.request("GET", "/later", &.{.{ .name = "priority", .value = "u=1;" }}, "");
    try h.run(10);
    try testing.expectEqual(.{ 2, false }, serverUrgency(h, a));
    try testing.expectEqual(.{ 5, true }, serverUrgency(h, b));
    try testing.expectEqual(.{ 1, true }, serverUrgency(h, c));
    try testing.expectEqual(.{ 3, false }, serverUrgency(h, d));
    // An open stream.
    try h.client.write(h.control, priorityUpdate(&buf, .priority_update_request, a, "u=0"), false);
    try h.run(10);
    try testing.expectEqual(.{ 0, false }, serverUrgency(h, a));
    try testing.expect(h.client.closed == null);
}

test "HTTP/3 priorities: PRIORITY_UPDATE errors" {
    // A push ID: we never push.
    try expectConnectionError(0x108, struct {
        fn f(h: *Harness) !void {
            try h.startClient();
            var buf: [32]u8 = undefined;
            try h.client.write(h.control, priorityUpdate(&buf, .priority_update_push, 0, "u=1"), false);
        }
    }.f);
    // Not a request stream.
    try expectConnectionError(0x108, struct {
        fn f(h: *Harness) !void {
            try h.startClient();
            var buf: [32]u8 = undefined;
            try h.client.write(h.control, priorityUpdate(&buf, .priority_update_request, 2, "u=1"), false);
        }
    }.f);
    // Beyond the stream limit.
    try expectConnectionError(0x108, struct {
        fn f(h: *Harness) !void {
            try h.startClient();
            var buf: [32]u8 = undefined;
            try h.client.write(h.control, priorityUpdate(&buf, .priority_update_request, 4 * 1000, "u=1"), false);
        }
    }.f);
    // On a request stream.
    try expectConnectionError(0x105, struct {
        fn f(h: *Harness) !void {
            try h.startClient();
            var buf: [32]u8 = undefined;
            const id = try h.client.openBidi();
            try h.client.write(id, priorityUpdate(&buf, .priority_update_request, id, "u=1"), false);
        }
    }.f);
    // Before SETTINGS.
    try expectConnectionError(0x10a, struct {
        fn f(h: *Harness) !void {
            var buf: [32]u8 = undefined;
            const c = try h.client.openUni();
            try h.client.write(c, &.{0x00}, false);
            try h.client.write(c, priorityUpdate(&buf, .priority_update_request, 0, "u=1"), false);
        }
    }.f);
}

test "HTTP/3 priorities: an exchange waiting behind other streams doesn't time out" {
    const h = try Harness.init();
    defer h.deinit();
    const big = try testing.allocator.alloc(u8, 500_000);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    h.handler.big = big;
    try h.startClient();
    try h.run(10);
    _ = try h.request("GET", "/big", &.{.{ .name = "priority", .value = "u=0" }}, "");
    const waiting = try h.request("GET", "/stream", &.{.{ .name = "priority", .value = "u=7" }}, "");
    try h.run(1);
    const ex = h.handler.exchanges.items[0];
    try ex.write("behind");
    h.drainMailbox();
    const c = h.ctx();
    h.h3c.?.onExchangeTimeout(TestHandler, &c, ex.slot);
    try testing.expect(ex.isOpen());
    try testing.expectEqual(h.now + 11, h.slab.entry(ex.slot).deadline);
    try h.run(400);
    var r = try h.response(waiting);
    defer r.deinit();
    try testing.expectEqualStrings("behind", r.body.items);
}

test "HTTP/3: GOAWAY finishes requests in flight, then closes" {
    const h = try Harness.init();
    defer h.deinit();
    try h.startClient();
    const id = try h.request("GET", "/later", &.{}, "");
    try h.run(20);
    h.h3c.?.shutdown(h.now_us);
    try h.run(5);
    // The control stream carries SETTINGS, then GOAWAY naming stream 4.
    const control = h.client.readAll(3);
    try testing.expect(std.mem.indexOf(u8, control, &.{ 0x07, 0x01, 0x04 }) != null);
    try testing.expect(h.client.closed == null);
    try h.handler.exchanges.items[0].respond(.{ .status = .ok }, "late");
    try h.run(20);
    var r = try h.response(id);
    defer r.deinit();
    try testing.expectEqualStrings("late", r.body.items);
    try testing.expectEqual(@as(u64, 0x100), h.client.closed.?.code);
}

// -- Fuzzing ----------------------------------------------------------------------

/// A completed handshake with the client's control stream open, then a
/// fuzzer-chosen mix of raw QUIC frames in 1-RTT packets, bytes on request
/// and unidirectional streams (with or without FIN), and lost datagrams.
/// Checked: no crash, leak or out-of-bounds access; a connection that
/// closes does so with a transport or HTTP/3 error code; every response
/// the client sees parses as HTTP/3 frames.
fn fuzzH3(_: void, smith: *std.testing.Smith) anyerror!void {
    const h = try Harness.init();
    defer h.deinit();
    h.h3_opts.limits.max_body_size = 4096;
    h.h3_opts.enable_connect_protocol = true;
    h.h3_opts.websocket = .{ .max_message_size = 2048, .max_send_queue_bytes = 8192 };
    try h.startClient();
    var ids: [4]u64 = undefined;
    var nids: usize = 0;
    var data: [512]u8 = undefined;
    var ops: usize = 0;
    while (ops < 24 and !smith.eos()) : (ops += 1) {
        const op = smith.value(u8);
        const n = smith.slice(data[0..@min(data.len, 1 + @as(usize, smith.value(u8)) * 2)]);
        const bytes = data[0..n];
        switch (op % 7) {
            0 => try h.client.injectFrames(bytes),
            1 => {
                if (nids < ids.len) {
                    ids[nids] = try h.client.openBidi();
                    nids += 1;
                }
                // With every slot used, the last stream may have ended.
                if ((try h.client.getStream(ids[nids - 1])).send.fin) continue;
                try h.client.write(ids[nids - 1], bytes, op & 0x80 != 0);
            },
            2 => {
                if (nids == 0) continue;
                const id = ids[smith.value(u8) % nids];
                const s = try h.client.getStream(id);
                if (s.send.fin) continue;
                try h.client.write(id, bytes, op & 0x80 != 0);
            },
            3 => {
                const id = try h.client.openUni();
                try h.client.write(id, bytes, op & 0x80 != 0);
            },
            4 => {
                // A well-formed request, or a WebSocket.
                if (nids < ids.len) {
                    ids[nids] = if (op & 0x40 != 0) try connectWs(h, "/ws") else try h.request("GET", "/", &.{.{ .name = "priority", .value = bytes[0..@min(bytes.len, 32)] }}, "");
                    nids += 1;
                }
            },
            5 => {
                // A WebSocket frame (any opcode) in a DATA frame.
                if (nids == 0) continue;
                const id = ids[smith.value(u8) % nids];
                if ((try h.client.getStream(id)).send.fin) continue;
                try wsSend(h, id, @fromBackingInt(@as(u4, @truncate(op >> 3))), bytes, op & 0x80 != 0);
            },
            6 => {
                // PRIORITY_UPDATE for one of our streams, or any ID.
                const id = if (nids > 0 and op & 0x80 != 0) ids[smith.value(u8) % nids] else smith.value(u16);
                var buf: [600]u8 = undefined;
                try h.client.write(h.control, priorityUpdate(&buf, if (op & 0x40 != 0) .priority_update_push else .priority_update_request, id, bytes), false);
            },
            else => {},
        }
        try h.run(3);
        if (h.server.?.isClosed() or h.client.closed != null) break;
    }
    try h.run(20);
    if (h.client.closed) |c| {
        const ok = if (c.app) (c.code >= 0x100 and c.code <= 0x110) or (c.code >= 0x200 and c.code <= 0x202) else c.code <= 0x1ff;
        try testing.expect(ok);
    }
    for (ids[0..nids]) |id| {
        var r = h.response(id) catch |err| switch (err) {
            error.Truncated => continue, // still arriving, or reset
            else => return err,
        };
        r.deinit();
    }
}

test "fuzz: h3 connection" {
    try std.testing.fuzz({}, fuzzH3, .{
        .corpus = &.{
            // A request through raw STREAM frames; MAX_DATA; PING.
            &[_]u8{ 0x04, 0x00, 0x00, 0x10, 0x01, 0x01 },
            // HEADERS on a request stream, then DATA.
            &[_]u8{ 0x01, 0x10, 0x01, 0x0b, 0x00, 0x00, 0xd1, 0xd7, 0x51, 0x01, '/', 0xc4, 0x00, 0x01, 'x', 0x81, 0x00 },
            // A control stream with a GOAWAY, an encoder stream.
            &[_]u8{ 0x03, 0x04, 0x00, 0x07, 0x01, 0x00, 0x03, 0x01, 0x02 },
        },
    });
}
