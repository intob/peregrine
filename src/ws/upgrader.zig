const std = @import("std");
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const deflate = @import("./deflate.zig");

const MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn isWebsocketUpgrade(req: *Request) bool {
    if (req.findHeader("upgrade")) |upgrade_header| {
        if (std.ascii.eqlIgnoreCase(upgrade_header, "websocket")) {
            return true;
        }
    }
    return false;
}

/// An extended CONNECT for a WebSocket: HTTP/2 (RFC 8441) or HTTP/3 (RFC
/// 9220).
fn isExtendedConnect(req: *const Request) bool {
    const protocol = req.protocol orelse return false;
    return req.method == .CONNECT and std.ascii.eqlIgnoreCase(protocol, "websocket");
}

/// Whether the request asks for a WebSocket: an HTTP/1.1 Upgrade, or an
/// extended CONNECT on HTTP/2 or HTTP/3.
pub fn isUpgrade(req: *Request) bool {
    return isExtendedConnect(req) or isWebsocketUpgrade(req);
}

/// Accepts a WebSocket request in `handleRequest`: HTTP/1.1 gets 101 with
/// Sec-WebSocket-Accept, HTTP/2 and HTTP/3 get 200 (no key exchange, RFC
/// 8441 §5). The connection, or the stream, then carries the WebSocket and
/// the handler's `handleWSConn` is called. Add Sec-WebSocket-Protocol to
/// `resp` yourself if you negotiate a subprotocol. permessage-deflate is
/// negotiated here when the server enables it (`Config.websocket_deflate`).
pub fn handleUpgrade(allocator: std.mem.Allocator, req: *Request, resp: *Response) !void {
    _ = allocator;
    if (isExtendedConnect(req)) {
        try negotiateDeflate(req, resp);
        resp.is_ws_upgrade = true;
        resp.status = .ok;
        return;
    }
    if (!isWebsocketUpgrade(req)) {
        resp.status = .bad_request;
        return error.NoValidUpgradeHeader;
    }
    // Get key header
    var key: []const u8 = undefined;
    if (req.findHeader("sec-websocket-key")) |k| {
        key = k;
    } else return error.NoKeyHeader;
    var hash = std.crypto.hash.Sha1.init(.{});
    // Maybe concatenate these before calling update once (benchmark and test it)
    hash.update(key);
    hash.update(MAGIC_KEY);
    const result = hash.finalResult();
    var encoded_buf: [std.base64.standard.Encoder.calcSize(20)]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&encoded_buf, result[0..]);
    // Headers are copied when added, so a stack buffer is fine.
    try resp.addNewHeader("sec-websocket-accept", encoded);
    try resp.addNewHeader("upgrade", "websocket");
    try negotiateDeflate(req, resp);
    resp.is_ws_upgrade = true; // the server sets "connection: upgrade"
    resp.status = .switching_protocols;
}

fn negotiateDeflate(req: *const Request, resp: *Response) !void {
    const opts = resp.ws_deflate_options orelse return;
    var buf: [deflate.max_response_len]u8 = undefined;
    const n = deflate.negotiate(req, opts, &buf) orelse return;
    try resp.addNewHeader("sec-websocket-extensions", n.response);
    resp.ws_deflate = n.agreement;
}

test "extended CONNECT gets 200 without the HTTP/1.1 handshake headers" {
    const testing = std.testing;
    var req = try Request.init(testing.allocator);
    defer req.deinit();
    const resp = try Response.init(testing.allocator, 1024, 1024);
    defer resp.deinit();
    req.method = .CONNECT;
    req.protocol = "websocket";
    try testing.expect(isUpgrade(req));
    try handleUpgrade(undefined, req, resp);
    try testing.expect(resp.is_ws_upgrade);
    try testing.expectEqual(.ok, resp.status);
    try testing.expectEqualStrings("", resp.headerBytes());
    // Another protocol is not a WebSocket.
    resp.reset();
    req.protocol = "connect-udp";
    try testing.expect(!isUpgrade(req));
    try testing.expectError(error.NoValidUpgradeHeader, handleUpgrade(undefined, req, resp));
}
