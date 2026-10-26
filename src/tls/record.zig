//! TLS 1.3 record protection (RFC 8446 §5): one direction's AEAD state.
//! Framing (finding record boundaries in a byte stream) is up to the caller.
const std = @import("std");
const tls = std.crypto.tls;
const key_schedule = @import("./key_schedule.zig");
const errors = @import("./errors.zig");

pub const ContentType = tls.ContentType;

pub const header_len = tls.record_header_len;
pub const max_plaintext = 1 << 14;
/// Largest allowed record body (ciphertext): plaintext + content type +
/// padding + tag is capped at 2^14 + 256.
pub const max_ciphertext = max_plaintext + 256;
pub const max_record = header_len + max_ciphertext;
pub const tag_len = 16;
/// Bytes a sealed record adds to its plaintext.
pub const overhead = header_len + 1 + tag_len;

pub const Suite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,

    pub fn Aead(comptime s: Suite) type {
        return switch (s) {
            .aes_128_gcm_sha256 => std.crypto.aead.aes_gcm.Aes128Gcm,
            .aes_256_gcm_sha384 => std.crypto.aead.aes_gcm.Aes256Gcm,
            .chacha20_poly1305_sha256 => std.crypto.aead.chacha_poly.ChaCha20Poly1305,
        };
    }

    pub fn Schedule(comptime s: Suite) type {
        return switch (s) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => key_schedule.Sha256,
            .aes_256_gcm_sha384 => key_schedule.Sha384,
        };
    }

    pub fn hashLen(s: Suite) usize {
        return switch (s) {
            inline else => |c| c.Schedule().hash_len,
        };
    }
};

pub const max_hash_len = 48;
const max_key_len = 32;

/// AES-GCM with the AES key schedule, H and GHASH's powers of H computed
/// once per key instead of once per record (std's AEAD API takes a raw
/// key). Output is identical to std.crypto.aead.aes_gcm (see the tests).
fn AesGcmKey(comptime Aes: type) type {
    return struct {
        const Self = @This();
        const Ghash = std.crypto.onetimeauth.Ghash;

        aes: std.crypto.core.aes.AesEncryptCtx(Aes),
        /// A fresh GHASH state keyed with H; copied for each record.
        ghash: Ghash,

        fn init(key: [Aes.key_bits / 8]u8) Self {
            const aes = Aes.initEnc(key);
            var h: [16]u8 = undefined;
            aes.encrypt(&h, &@splat(0));
            defer std.crypto.secureZero(u8, &h);
            return .{ .aes = aes, .ghash = .init(&h) };
        }

        /// The tag over `ad` and ciphertext `c`, for counter block `j`.
        fn tag(self: *const Self, ad: []const u8, c: []const u8, j: [16]u8) [tag_len]u8 {
            var mac = self.ghash;
            mac.update(ad);
            mac.pad();
            mac.update(c);
            mac.pad();
            var lengths: [16]u8 = undefined;
            std.mem.writeInt(u64, lengths[0..8], @as(u64, ad.len) * 8, .big);
            std.mem.writeInt(u64, lengths[8..16], @as(u64, c.len) * 8, .big);
            mac.update(&lengths);
            var out: [tag_len]u8 = undefined;
            mac.final(&out);
            var t: [16]u8 = undefined;
            self.aes.encrypt(&t, &j);
            for (&out, t) |*o, x| o.* ^= x;
            return out;
        }

        fn counter(npub: [12]u8, n: u32) [16]u8 {
            var j: [16]u8 = undefined;
            j[0..12].* = npub;
            std.mem.writeInt(u32, j[12..16], n, .big);
            return j;
        }

        fn encrypt(self: *const Self, c: []u8, tag_out: *[tag_len]u8, m: []const u8, ad: []const u8, npub: [12]u8) void {
            std.debug.assert(c.len == m.len);
            std.crypto.core.modes.ctr(@TypeOf(self.aes), self.aes, c, m, counter(npub, 2), .big);
            tag_out.* = self.tag(ad, c, counter(npub, 1));
        }

        /// Verifies before decrypting, so `m` never holds unauthenticated
        /// plaintext. `m` may alias `c`.
        fn decrypt(self: *const Self, m: []u8, c: []const u8, tag_in: [tag_len]u8, ad: []const u8, npub: [12]u8) error{AuthenticationFailed}!void {
            std.debug.assert(c.len == m.len);
            var computed = self.tag(ad, c, counter(npub, 1));
            defer std.crypto.secureZero(u8, &computed);
            if (!std.crypto.timing_safe.eql([tag_len]u8, computed, tag_in)) return error.AuthenticationFailed;
            std.crypto.core.modes.ctr(@TypeOf(self.aes), self.aes, m, c, counter(npub, 2), .big);
        }
    };
}

const Aes128GcmKey = AesGcmKey(std.crypto.core.aes.Aes128);
const Aes256GcmKey = AesGcmKey(std.crypto.core.aes.Aes256);
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const Opened = struct {
    content_type: ContentType,
    data: []u8,
};

/// AEAD state for one direction of a connection at one encryption level.
pub const Protection = struct {
    const Self = @This();

    suite: Suite,
    key: [max_key_len]u8,
    iv: [12]u8,
    seq: u64 = 0,
    /// The traffic secret the key came from, kept for KeyUpdate.
    secret: [max_hash_len]u8,
    /// The expanded key for AES-GCM suites (ChaCha20 has no key schedule).
    expanded: union { aes128: Aes128GcmKey, aes256: Aes256GcmKey, none: void } = .{ .none = {} },

    pub fn init(suite: Suite, secret: []const u8) Self {
        var self: Self = .{ .suite = suite, .key = undefined, .iv = undefined, .secret = @splat(0) };
        @memcpy(self.secret[0..secret.len], secret);
        self.derive();
        return self;
    }

    fn derive(self: *Self) void {
        switch (self.suite) {
            inline else => |s| {
                const ks = s.Schedule();
                const secret = self.secret[0..ks.hash_len].*;
                const key_len = s.Aead().key_length;
                self.key = @splat(0);
                self.key[0..key_len].* = ks.trafficKey(key_len, secret);
                self.iv = ks.trafficIv(secret);
            },
        }
        self.expanded = switch (self.suite) {
            .aes_128_gcm_sha256 => .{ .aes128 = .init(self.key[0..16].*) },
            .aes_256_gcm_sha384 => .{ .aes256 = .init(self.key) },
            .chacha20_poly1305_sha256 => .{ .none = {} },
        };
        self.seq = 0;
    }

    /// Move to the next application traffic secret (KeyUpdate).
    pub fn update(self: *Self) void {
        switch (self.suite) {
            inline else => |s| {
                const ks = s.Schedule();
                self.secret[0..ks.hash_len].* = ks.nextTrafficSecret(self.secret[0..ks.hash_len].*);
            },
        }
        self.derive();
    }

    pub fn wipe(self: *Self) void {
        std.crypto.secureZero(u8, &self.key);
        std.crypto.secureZero(u8, &self.secret);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.expanded));
    }

    fn encrypt(self: *const Self, c: []u8, tag: *[tag_len]u8, m: []const u8, ad: []const u8) void {
        const n = self.nonce();
        switch (self.suite) {
            .aes_128_gcm_sha256 => self.expanded.aes128.encrypt(c, tag, m, ad, n),
            .aes_256_gcm_sha384 => self.expanded.aes256.encrypt(c, tag, m, ad, n),
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.encrypt(c, tag, m, ad, n, self.key),
        }
    }

    fn decrypt(self: *const Self, m: []u8, c: []const u8, tag: [tag_len]u8, ad: []const u8) error{AuthenticationFailed}!void {
        const n = self.nonce();
        return switch (self.suite) {
            .aes_128_gcm_sha256 => self.expanded.aes128.decrypt(m, c, tag, ad, n),
            .aes_256_gcm_sha384 => self.expanded.aes256.decrypt(m, c, tag, ad, n),
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.decrypt(m, c, tag, ad, n, self.key),
        };
    }

    fn nonce(self: *const Self) [12]u8 {
        var n = self.iv;
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, self.seq, .big);
        for (n[4..], seq_bytes) |*b, s| b.* ^= s;
        return n;
    }

    /// Seals `data` as one record into `out`, which needs room for
    /// `data.len + overhead` bytes. `data` may already sit at
    /// `out[header_len..]` (encryption is then in place). Returns the record
    /// length.
    pub fn seal(self: *Self, out: []u8, content_type: ContentType, data: []const u8) usize {
        std.debug.assert(data.len <= max_plaintext);
        const inner_len = data.len + 1;
        const body_len = inner_len + tag_len;
        std.debug.assert(out.len >= header_len + body_len);
        out[0] = @backingInt(ContentType.application_data);
        out[1] = 0x03;
        out[2] = 0x03;
        std.mem.writeInt(u16, out[3..5], @intCast(body_len), .big);
        const inner = out[header_len..][0..inner_len];
        if (data.len > 0 and inner.ptr != data.ptr) @memcpy(inner[0..data.len], data);
        inner[data.len] = @backingInt(content_type);
        self.encrypt(inner, out[header_len + inner_len ..][0..tag_len], inner, out[0..header_len]);
        self.seq += 1;
        return header_len + body_len;
    }

    /// Decrypts a complete record (header included) in place. The returned
    /// data points into `record`.
    pub fn open(self: *Self, record: []u8) errors.Error!Opened {
        const len = (try ciphertext(record)).len;
        return self.openTo(record, record[header_len..][0..len]);
    }

    /// The size of a record's inner plaintext (content, type, padding):
    /// what `openInto` needs. Records too short or too long fail anyway.
    pub fn innerLen(record: []const u8) usize {
        return record.len -| (header_len + tag_len);
    }

    /// Decrypts a complete record into `out`, which needs `innerLen(record)`
    /// bytes, leaving the record as it is. The returned data points into
    /// `out`.
    pub fn openInto(self: *Self, record: []const u8, out: []u8) errors.Error!Opened {
        const ct = try ciphertext(record);
        return self.openTo(record, out[0..ct.len]);
    }

    fn ciphertext(record: []const u8) errors.Error![]const u8 {
        const body = record[header_len..];
        if (body.len > max_ciphertext) return error.RecordOverflow;
        if (body.len < tag_len) return error.BadRecordMac;
        return body[0 .. body.len - tag_len];
    }

    fn openTo(self: *Self, record: []const u8, out: []u8) errors.Error!Opened {
        const ct = record[header_len..][0..out.len];
        const tag = record[header_len + ct.len ..][0..tag_len].*;
        self.decrypt(out, ct, tag, record[0..header_len]) catch return error.BadRecordMac;
        self.seq += 1;
        return unpad(out);
    }

    fn unpad(ct: []u8) errors.Error!Opened {
        // The inner plaintext, padding included, is at most 2^14 + 1 bytes
        // (§5.4). Checked after decryption so rejected 0-RTT data still
        // fails as bad_record_mac and is skipped.
        if (ct.len > max_plaintext + 1) return error.RecordOverflow;
        // Strip padding: the content type is the last non-zero byte.
        var end = ct.len;
        while (end > 0 and ct[end - 1] == 0) end -= 1;
        if (end == 0) return error.UnexpectedMessage;
        const inner_len = end - 1;
        return .{ .content_type = @fromBackingInt(ct[inner_len]), .data = ct[0..inner_len] };
    }
};

const testHex = key_schedule.testHex;

// RFC 8448 §3: the server's encrypted handshake flight and the client's
// Finished, both under handshake traffic keys.
const rfc8448_server_flight = testHex(
    \\08 00 00 24 00 22 00 0a 00 14 00 12 00 1d
    \\00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c 00 02 40
    \\01 00 00 00 00 0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30
    \\82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48 86 f7 0d
    \\01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61
    \\30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36
    \\30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06 03 55 04
    \\03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01
    \\01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30
    \\3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a
    \\24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e
    \\aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01
    \\8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80 30 53
    \\0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab
    \\9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01
    \\a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55 1d
    \\0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05
    \\00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17
    \\06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5
    \\8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72
    \\60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63
    \\a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84
    \\e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29
    \\ac 91 87 b4 2b 4d e1 00 00 0f 00 00 84 08 04 00 80 5a 74 7c 5d
    \\88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a b3
    \\ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07 86
    \\53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b be
    \\8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c
    \\9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d
    \\a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3 14 00
    \\00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c
    \\30 95 72 cb 7f ff ee 54 54 b7 8f 07 18
);

const rfc8448_server_flight_record = testHex(
    \\17 03 03 02 a2 d1 ff 33 4a 56 f5 bf
    \\f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df
    \\78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45
    \\cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3
    \\89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b
    \\d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9
    \\b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf
    \\51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d
    \\2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55
    \\cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f
    \\d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6
    \\86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac
    \\66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea
    \\52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e
    \\a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6
    \\54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb
    \\31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59
    \\62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e
    \\92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af
    \\36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37
    \\8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c
    \\f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88
    \\2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80
    \\f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69
    \\18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99
    \\2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11
    \\c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51
    \\56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42
    \\f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f
    \\60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd
    \\d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af
    \\93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da
    \\bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b
);

const rfc8448_s_hs_traffic = testHex("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38");
const rfc8448_c_hs_traffic = testHex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21");

test "seal matches RFC 8448" {
    var p = Protection.init(.aes_128_gcm_sha256, &rfc8448_s_hs_traffic);
    var out: [rfc8448_server_flight.len + overhead]u8 = undefined;
    const n = p.seal(&out, .handshake, &rfc8448_server_flight);
    try std.testing.expectEqualSlices(u8, &rfc8448_server_flight_record, out[0..n]);
    try std.testing.expectEqual(1, p.seq);
}

test "open matches RFC 8448" {
    var record = testHex(
        \\17 03 03 00 35 75 ec 4d c2 38 cc e6
        \\0b 29 80 44 a7 1e 21 9c 56 cc 77 b0 51 7f e9 b9 3c 7a 4b fc 44
        \\d8 7f 38 f8 03 38 ac 98 fc 46 de b3 84 bd 1c ae ac ab 68 67 d7
        \\26 c4 05 46
    );
    var p = Protection.init(.aes_128_gcm_sha256, &rfc8448_c_hs_traffic);
    const opened = try p.open(&record);
    try std.testing.expectEqual(ContentType.handshake, opened.content_type);
    try std.testing.expectEqualSlices(u8, &testHex(
        \\14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a c1
        \\fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61
    ), opened.data);
}

test "round trip, in place, every suite and KeyUpdate" {
    inline for (.{ Suite.aes_128_gcm_sha256, Suite.aes_256_gcm_sha384, Suite.chacha20_poly1305_sha256 }) |suite| {
        const secret: [48]u8 = @splat(7);
        var tx = Protection.init(suite, secret[0..suite.hashLen()]);
        var rx = Protection.init(suite, secret[0..suite.hashLen()]);
        var buf: [max_plaintext + overhead]u8 = undefined;
        for ([_]usize{ 0, 1, 100, max_plaintext }, 0..) |len, i| {
            if (i == 2) {
                tx.update();
                rx.update();
            }
            // Plaintext placed where seal expects it: encrypted in place.
            for (buf[header_len..][0..len], 0..) |*b, j| b.* = @truncate(j);
            const n = tx.seal(&buf, .application_data, buf[header_len..][0..len]);
            try std.testing.expectEqual(len + overhead, n);
            const opened = try rx.open(buf[0..n]);
            try std.testing.expectEqual(ContentType.application_data, opened.content_type);
            try std.testing.expectEqual(len, opened.data.len);
            for (opened.data, 0..) |b, j| try std.testing.expectEqual(@as(u8, @truncate(j)), b);
        }
    }
}

test "open rejects tampering, replays and empty inner plaintext" {
    const secret: [32]u8 = @splat(1);
    var tx = Protection.init(.aes_128_gcm_sha256, &secret);
    var rx = Protection.init(.aes_128_gcm_sha256, &secret);
    var buf: [64]u8 = undefined;
    var n = tx.seal(&buf, .application_data, "hello");
    var copy = buf;
    copy[header_len + 2] ^= 1;
    try std.testing.expectError(error.BadRecordMac, rx.open(copy[0..n]));
    // A failed open doesn't consume a sequence number; the original opens.
    copy = buf;
    _ = try rx.open(copy[0..n]);
    // Replaying it fails: the sequence number moved on.
    try std.testing.expectError(error.BadRecordMac, rx.open(buf[0..n]));

    // All-zero inner plaintext (padding only, no content type).
    var tx2 = Protection.init(.aes_128_gcm_sha256, &secret);
    var rx2 = Protection.init(.aes_128_gcm_sha256, &secret);
    var zeros: [4]u8 = @splat(0);
    n = tx2.seal(&buf, .invalid, &zeros);
    try std.testing.expectError(error.UnexpectedMessage, rx2.open(buf[0..n]));
}

test "expanded AES-GCM matches std's AEAD" {
    var prng = std.Random.DefaultPrng.init(0xae5);
    const random = prng.random();
    var m: [3 * max_plaintext]u8 = undefined;
    var c1: [m.len]u8 = undefined;
    var c2: [m.len]u8 = undefined;
    var back: [m.len]u8 = undefined;
    // Lengths around block and GHASH aggregation boundaries, and records.
    const lens = [_]usize{ 0, 1, 15, 16, 17, 63, 64, 65, 351, 352, 1343, 1344, 5247, 5248, max_plaintext + 1, m.len };
    inline for (.{ std.crypto.aead.aes_gcm.Aes128Gcm, std.crypto.aead.aes_gcm.Aes256Gcm }, .{ Aes128GcmKey, Aes256GcmKey }) |Std, Ours| {
        for (0..8) |round| for (lens) |len| {
            var key: [Std.key_length]u8 = undefined;
            var npub: [12]u8 = undefined;
            var ad: [5]u8 = undefined;
            random.bytes(&key);
            random.bytes(&npub);
            random.bytes(&ad);
            random.bytes(m[0..len]);
            const ours = Ours.init(key);
            var t1: [tag_len]u8 = undefined;
            var t2: [tag_len]u8 = undefined;
            Std.encrypt(c1[0..len], &t1, m[0..len], &ad, npub, key);
            ours.encrypt(c2[0..len], &t2, m[0..len], &ad, npub);
            try std.testing.expectEqualSlices(u8, c1[0..len], c2[0..len]);
            try std.testing.expectEqualSlices(u8, &t1, &t2);
            try ours.decrypt(back[0..len], c1[0..len], t1, &ad, npub);
            try std.testing.expectEqualSlices(u8, m[0..len], back[0..len]);
            // In place, and a tampered tag.
            try ours.decrypt(c2[0..len], c2[0..len], t2, &ad, npub);
            try std.testing.expectEqualSlices(u8, m[0..len], c2[0..len]);
            t1[round % tag_len] ^= 1;
            try std.testing.expectError(error.AuthenticationFailed, ours.decrypt(back[0..len], c1[0..len], t1, &ad, npub));
        };
    }
}

test "openInto decrypts into another buffer and leaves the record" {
    inline for (.{ Suite.aes_128_gcm_sha256, Suite.aes_256_gcm_sha384, Suite.chacha20_poly1305_sha256 }) |suite| {
        const secret: [48]u8 = @splat(9);
        var tx = Protection.init(suite, secret[0..suite.hashLen()]);
        var rx = Protection.init(suite, secret[0..suite.hashLen()]);
        var buf: [256]u8 = undefined;
        const n = tx.seal(&buf, .application_data, "direct");
        const sealed = buf;
        var out: [64]u8 = undefined;
        try std.testing.expectEqual(7, Protection.innerLen(buf[0..n]));
        const opened = try rx.openInto(buf[0..n], &out);
        try std.testing.expectEqualStrings("direct", opened.data);
        try std.testing.expect(opened.data.ptr == &out);
        try std.testing.expectEqualSlices(u8, sealed[0..n], buf[0..n]);
    }
}

/// Seals an arbitrary inner plaintext (content, type and padding), which
/// `seal` can't produce when it is malformed.
fn sealInner(p: *Protection, out: []u8, inner: []const u8) []u8 {
    const rec = out[0 .. header_len + inner.len + tag_len];
    rec[0..5].* = .{ 23, 3, 3, 0, 0 };
    std.mem.writeInt(u16, rec[3..5], @intCast(inner.len + tag_len), .big);
    @memcpy(rec[header_len..][0..inner.len], inner);
    const A = Suite.aes_128_gcm_sha256.Aead();
    A.encrypt(rec[header_len..][0..inner.len], rec[header_len + inner.len ..][0..tag_len], rec[header_len..][0..inner.len], rec[0..header_len], p.nonce(), p.key[0..A.key_length].*);
    p.seq += 1;
    return rec;
}

test "open: a record holding only the tag has no content type" {
    // Found by the tls.Conn fuzz harness: an empty inner plaintext
    // authenticates, so it is unexpected_message (§5.4), not bad_record_mac.
    const secret: [32]u8 = @splat(3);
    var tx = Protection.init(.aes_128_gcm_sha256, &secret);
    var rx = Protection.init(.aes_128_gcm_sha256, &secret);
    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.UnexpectedMessage, rx.open(sealInner(&tx, &buf, "")));
    // Shorter than a tag can't have come from the AEAD at all.
    var short: [header_len + tag_len - 1]u8 = .{ 23, 3, 3, 0, tag_len - 1 } ++ @as([tag_len - 1]u8, @splat(0));
    try std.testing.expectError(error.BadRecordMac, rx.open(&short));
}

test "open: inner plaintext over 2^14 + 1 bytes is record_overflow, padding included" {
    // Found by the tls.Conn fuzz harness: padding could take the inner
    // plaintext past 2^14 + 1 bytes (§5.4) as long as the content itself
    // stayed within 2^14.
    const secret: [32]u8 = @splat(4);
    var tx = Protection.init(.aes_128_gcm_sha256, &secret);
    var rx = Protection.init(.aes_128_gcm_sha256, &secret);
    var buf: [max_record]u8 = undefined;
    var inner: [max_plaintext + 2]u8 = @splat(0);
    // The limit itself: 2^14 bytes of content and the type.
    @memset(inner[0..max_plaintext], 'a');
    inner[max_plaintext] = @backingInt(ContentType.application_data);
    const ok = try rx.open(sealInner(&tx, &buf, inner[0 .. max_plaintext + 1]));
    try std.testing.expectEqual(max_plaintext, ok.data.len);
    // One byte of padding over it.
    try std.testing.expectError(error.RecordOverflow, rx.open(sealInner(&tx, &buf, &inner)));
    // A short content with padding over it.
    var tx2 = Protection.init(.aes_128_gcm_sha256, &secret);
    var rx2 = Protection.init(.aes_128_gcm_sha256, &secret);
    @memset(&inner, 0);
    inner[0] = 'b';
    inner[1] = @backingInt(ContentType.application_data);
    try std.testing.expectError(error.RecordOverflow, rx2.open(sealInner(&tx2, &buf, &inner)));
}
