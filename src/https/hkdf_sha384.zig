const std = @import("std");
const Sha384 = std.crypto.hash.sha2.Sha384;
const Hmac = std.crypto.auth.hmac.Hmac;

pub const HkdfSha384 = struct {
    const Self = @This();
    const mac = Hmac(Sha384);

    pub fn extract(salt: []const u8, ikm: []const u8) [48]u8 {
        var out: [48]u8 = undefined;
        var ctx = mac.init(salt);
        ctx.update(ikm);
        ctx.final(&out);
        return out;
    }

    pub fn expand(out: []u8, info: []const u8, prk: [48]u8) void {
        var ctx = mac.init(prk[0..]);
        var counter: u8 = 1;
        var prev_buf: [Sha384.digest_length]u8 = undefined;

        var pos: usize = 0;
        while (pos < out.len) {
            if (counter > 1) {
                ctx.update(&prev_buf);
            }
            ctx.update(info);
            ctx.update(&[_]u8{counter});
            ctx.final(&prev_buf);

            const remain = out.len - pos;
            const to_copy = @min(remain, Sha384.digest_length);
            @memcpy(out[pos..][0..to_copy], prev_buf[0..to_copy]);

            pos += to_copy;
            counter += 1;
        }
    }
};
