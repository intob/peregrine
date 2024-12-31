const std = @import("std");
const posix = std.posix;

pub fn writeMessage(fd: posix.socket_t, data: []const u8, is_binary: bool) !void {
    // Create header bytes
    var header: [14]u8 = undefined;
    var header_len: usize = 2; // minimum header size

    // Set FIN bit and opcode (0x1 for text, 0x2 for binary)
    const opcode: u8 = if (is_binary) 0x02 else 0x01;
    // Then combine with the FIN bit
    header[0] = 0x80 | opcode;

    // Set payload length and masking bit (server messages are not masked)
    if (data.len < 126) {
        header[1] = @intCast(data.len);
    } else if (data.len <= 65535) {
        header[1] = 126;
        header[2] = @intCast((data.len >> 8) & 0xFF);
        header[3] = @intCast(data.len & 0xFF);
        header_len = 4;
    } else {
        header[1] = 127;
        var len = data.len;
        var i: usize = 9;
        while (i > 1) : (i -= 1) {
            header[i] = @intCast(len & 0xFF);
            len >>= 8;
        }
        header_len = 10;
    }

    // Write header
    var pos: usize = 0;
    while (pos < header_len) {
        const written = try posix.write(fd, header[pos..header_len]);
        if (written == 0) return error.ConnectionClosed;
        pos += written;
    }

    // Write payload
    pos = 0;
    while (pos < data.len) {
        const written = try posix.write(fd, data[pos..]);
        if (written == 0) return error.ConnectionClosed;
        pos += written;
    }
}
