const std = @import("std");
const parser = @import("./parser.zig");

pub const ServerHelloParams = struct {
    cs: parser.CipherSuite,
    ks: parser.KeyShare,
    legacy_session_id: ?[32]u8,
};

// ServerHello contains:
// - server random data (used later in the handshake)
// - a selected cipher suite
// - a public key for key exchange
// - the negotiated protocol version (TLS 1.3)
// TODO: optimise this by modifying and returning the appropriate pre-computed template slice.
// This will involve creating a template slice for each supported combination of
// input parameters.
pub fn buildServerHello(allocator: std.mem.Allocator, params: ServerHelloParams) !*std.ArrayList(u8) {
    var result = try allocator.create(std.ArrayList(u8));
    result.* = std.ArrayList(u8).init(allocator);

    try result.append(@intFromEnum(parser.RecordType.handshake));
    try result.appendSlice(&[_]u8{ 0x03, 0x03 }); // Legacy version TLS 1.2

    // Record length follows, so we need an intermediate slice
    var record = std.ArrayList(u8).init(allocator);
    try record.append(@intFromEnum(parser.HandshakeType.server_hello));

    // Message length follows, so we need another intermediate slice
    var message = std.ArrayList(u8).init(allocator);
    try message.appendSlice(&[_]u8{ 0x03, 0x03 }); // Legacy version TLS 1.2

    // TODO: must we store this, and therefore provide it in params?
    var random: [32]u8 = undefined;
    std.crypto.random.bytes(random[0..]);
    try message.appendSlice(random[0..]);

    if (params.legacy_session_id == null) {
        try message.append(@intCast(0));
    } else {
        try message.append(@intCast(32));
        try message.appendSlice(params.legacy_session_id.?[0..]);
    }

    var cs_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, cs_bytes[0..], @intFromEnum(params.cs), .big);
    try message.appendSlice(cs_bytes[0..]);

    try message.append(0x00); // Legacy compression method (null)

    var extensions = std.ArrayList(u8).init(allocator);

    try extensions.appendSlice(&[_]u8{
        0x00, 0x2b, // Supported versions extension
        0x00, 0x02, // 2 bytes follow
        0x03, 0x04, // TLS 1.3
    });

    try extensions.appendSlice(&[_]u8{ 0x00, 0x33 }); // Key share extension
    switch (params.ks.group) {
        .x25519 => {
            try extensions.appendSlice(&[_]u8{
                0x00, 0x24, // 36 bytes follow
                0x00, 0x1d, // x25519 key exchange
                0x00, 0x20, // 32 bytes follow
            });
            try extensions.appendSlice(params.ks.key_exchange);
        },
        else => return error.SerialiseKSGroupNotImplemented,
    }

    var extensions_len: [2]u8 = undefined;
    std.mem.writeInt(u16, extensions_len[0..], @intCast(extensions.items.len), .big);
    try message.appendSlice(extensions_len[0..]);
    try message.appendSlice(extensions.items);

    var message_len: [3]u8 = undefined; // Oh TLS, you're naughty
    std.mem.writeInt(u24, message_len[0..], @intCast(message.items.len), .big);
    try record.appendSlice(message_len[0..]);
    try record.appendSlice(message.items);

    var record_len: [2]u8 = undefined;
    std.mem.writeInt(u16, record_len[0..], @intCast(record.items.len), .big);
    try result.appendSlice(record_len[0..]);
    try result.appendSlice(record.items);

    return result; // What a ball-ache that was...
}
