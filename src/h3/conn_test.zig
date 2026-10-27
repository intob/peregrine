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
const Mailbox = @import("../mailbox.zig").Mailbox;
const sys = @import("../sys.zig");
const Client = test_client.Client;
const testing = std.testing;

const server_cid = [8]u8{ 0x5e, 0x5e, 1, 2, 3, 4, 5, 6 };

const TestHandler = struct {
    log: std.ArrayList(u8) = .empty,
    exchanges: std.ArrayList(exchange.Exchange) = .empty,
    aborts: usize = 0,
    big: []const u8 = "",

    pub fn handleRequest(self: *TestHandler, req: *Request, resp: *Response) void {
        const a = testing.allocator;
        self.log.print(a, "{s} {s}", .{ @tagName(req.method), req.path_and_query }) catch unreachable;
        for (req.getHeaders()) |h| {
            if (std.mem.startsWith(u8, h.key, "x-") or std.mem.eql(u8, h.key, "host")) {
                self.log.print(a, " [{s}={s}]", .{ h.key, h.value }) catch unreachable;
            }
        }
        if (req.body.len > 0) self.log.print(a, " body={d}", .{req.body.len}) catch unreachable;
        self.log.append(a, '\n') catch unreachable;
        const path = req.getPath();
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
        h.handler.log.deinit(h.a);
        h.handler.exchanges.deinit(h.a);
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
    try h.writeHeaders(id, &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" } }, &.{}, true);
    try h.run(30);
    try testing.expectEqual(@as(?u64, 0x103), (try h.client.getStream(g)).stop_code);
    var r = try h.response(id);
    defer r.deinit();
    try testing.expectEqualStrings("Hello, World!", r.body.items);
    try testing.expect(h.client.closed == null);
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
