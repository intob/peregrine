const std = @import("std");
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;

const MAGIC_KEY = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn isWebsocketUpgrade(req: *Request) bool {
    if (req.findHeader("upgrade")) |upgrade_header| {
        if (std.ascii.eqlIgnoreCase(upgrade_header, "websocket")) {
            return true;
        }
    }
    return false;
}

pub fn handleUpgrade(allocator: std.mem.Allocator, req: *Request, resp: *Response) !void {
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
    _ = allocator;
    var encoded_buf: [std.base64.standard.Encoder.calcSize(20)]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&encoded_buf, result[0..]);
    // Headers are copied when added, so a stack buffer is fine.
    try resp.addNewHeader("sec-websocket-accept", encoded);
    try resp.addNewHeader("upgrade", "websocket");
    resp.is_ws_upgrade = true; // the server sets "connection: upgrade"
    resp.status = .switching_protocols;
}
