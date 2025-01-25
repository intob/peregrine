pub fn hkdfExpandLabel(
    comptime hkdf_t: type,
    comptime len: u8,
    out: *[len]u8,
    secret: [hkdf_t.prk_length]u8,
    label: []const u8,
    context: []const u8,
) void {
    const tls13_label = "tls13 ";
    var hkdf_label: [512]u8 = undefined;
    hkdf_label[0] = 0;
    hkdf_label[1] = len;
    hkdf_label[2] = @intCast(tls13_label.len + label.len);
    @memcpy(hkdf_label[3..][0..tls13_label.len], tls13_label);
    @memcpy(hkdf_label[3 + tls13_label.len ..][0..label.len], label);
    hkdf_label[3 + tls13_label.len + label.len] = @intCast(context.len);
    @memcpy(hkdf_label[4 + tls13_label.len + label.len ..][0..context.len], context);
    const total_len = 4 + tls13_label.len + label.len + context.len;
    hkdf_t.expand(out, hkdf_label[0..total_len], secret);
}
