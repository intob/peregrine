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
    const encoded_size = std.base64.standard.Encoder.calcSize(result.len);
    // TODO: consider using a fixed size buffer on the stack so we don't need
    // to provide an allocator. It's less than 30B.
    var encoded_buf = try allocator.alloc(u8, encoded_size);
    defer allocator.free(encoded_buf);
    _ = &encoded_buf;
    _ = std.base64.standard.Encoder.encode(encoded_buf, result[0..]);
    try resp.addNewHeader("sec-websocket-accept", encoded_buf);
    try resp.addNewHeader("upgrade", "websocket");
    resp.is_ws_upgrade = true; // worker will set header "connection: upgrade"
    resp.status = .switching_protocols;
}
