//! QUIC packet protection (RFC 9001 §5): Initial secrets, packet and
//! header protection keys derived from TLS traffic secrets, sealing and
//! opening packets in place, key updates and Retry integrity tags.
const std = @import("std");
const tls = std.crypto.tls;
const record = @import("../tls/record.zig");
const key_schedule = @import("../tls/key_schedule.zig");
const packet = @import("./packet.zig");

pub const Suite = record.Suite;
pub const tag_len = record.tag_len;
pub const max_hash_len = record.max_hash_len;
/// Bytes of ciphertext sampled for header protection (§5.4.2).
pub const sample_len = 16;

const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;
const ChaCha20 = std.crypto.stream.chacha.ChaCha20IETF;
const Sha256Schedule = key_schedule.Sha256;

/// RFC 9001 §5.2.
const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub const Error = error{
    /// The packet is too short or doesn't authenticate: dropped.
    Undecryptable,
};

/// Initial secrets for a connection, from the client's first Destination
/// Connection ID (§5.2). Initial packets always use AES-128-GCM.
pub fn initialSecrets(dcid: []const u8) struct { client: [32]u8, server: [32]u8 } {
    const Hkdf = Sha256Schedule.Hkdf;
    var initial = Hkdf.extract(&initial_salt_v1, dcid);
    defer std.crypto.secureZero(u8, &initial);
    return .{
        .client = tls.hkdfExpandLabel(Hkdf, initial, "client in", "", 32),
        .server = tls.hkdfExpandLabel(Hkdf, initial, "server in", "", 32),
    };
}

fn expand(suite: Suite, secret: []const u8, comptime label: []const u8, comptime len: usize) [len]u8 {
    switch (suite) {
        inline else => |s| {
            const ks = s.Schedule();
            return tls.hkdfExpandLabel(ks.Hkdf, secret[0..ks.hash_len].*, label, "", len);
        },
    }
}

fn keyLen(suite: Suite) usize {
    return switch (suite) {
        inline else => |s| s.Aead().key_length,
    };
}

/// The secret for the next key phase (§6.1): "quic ku".
pub fn nextSecret(suite: Suite, secret: []const u8) [max_hash_len]u8 {
    var out: [max_hash_len]u8 = @splat(0);
    switch (suite) {
        inline else => |s| {
            const ks = s.Schedule();
            out[0..ks.hash_len].* = tls.hkdfExpandLabel(ks.Hkdf, secret[0..ks.hash_len].*, "quic ku", "", ks.hash_len);
        },
    }
    return out;
}

/// Packet payload protection for one direction and key phase.
pub const PacketKey = struct {
    aead: record.Aead,
    iv: [12]u8,

    pub fn init(suite: Suite, secret: []const u8) PacketKey {
        var key_buf: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &key_buf);
        const key_len = keyLen(suite);
        switch (suite) {
            inline else => |s| {
                const n = comptime s.Aead().key_length;
                key_buf[0..n].* = expand(s, secret, "quic key", n);
            },
        }
        return .{ .aead = .init(suite, key_buf[0..key_len]), .iv = expand(suite, secret, "quic iv", 12) };
    }

    pub fn wipe(self: *PacketKey) void {
        self.aead.wipe();
    }

    fn nonce(self: *const PacketKey, pn: u64) [12]u8 {
        var n = self.iv;
        var pn_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &pn_bytes, pn, .big);
        for (n[4..], pn_bytes) |*b, p| b.* ^= p;
        return n;
    }

    /// Encrypts `pkt[header_len .. pkt.len - tag_len]` in place with the
    /// header as associated data and writes the tag into the last bytes.
    pub fn seal(self: *const PacketKey, pkt: []u8, header_len: usize, pn: u64) void {
        const payload = pkt[header_len .. pkt.len - tag_len];
        self.aead.encrypt(payload, pkt[pkt.len - tag_len ..][0..tag_len], payload, pkt[0..header_len], self.nonce(pn));
    }

    /// Decrypts in place; returns the plaintext payload, a slice of `pkt`.
    pub fn open(self: *const PacketKey, pkt: []u8, header_len: usize, pn: u64) Error![]u8 {
        if (pkt.len < header_len + tag_len) return error.Undecryptable;
        const payload = pkt[header_len .. pkt.len - tag_len];
        const tag = pkt[pkt.len - tag_len ..][0..tag_len].*;
        self.aead.decrypt(payload, payload, tag, pkt[0..header_len], self.nonce(pn)) catch return error.Undecryptable;
        return payload;
    }
};

/// Header protection (§5.4), which stays the same across key updates.
pub const HeaderKey = union(enum) {
    aes128: std.crypto.core.aes.AesEncryptCtx(Aes128),
    aes256: std.crypto.core.aes.AesEncryptCtx(Aes256),
    chacha20: [32]u8,

    pub fn init(suite: Suite, secret: []const u8) HeaderKey {
        return switch (suite) {
            .aes_128_gcm_sha256 => blk: {
                var k = expand(suite, secret, "quic hp", 16);
                defer std.crypto.secureZero(u8, &k);
                break :blk .{ .aes128 = Aes128.initEnc(k) };
            },
            .aes_256_gcm_sha384 => blk: {
                var k = expand(suite, secret, "quic hp", 32);
                defer std.crypto.secureZero(u8, &k);
                break :blk .{ .aes256 = Aes256.initEnc(k) };
            },
            .chacha20_poly1305_sha256 => .{ .chacha20 = expand(suite, secret, "quic hp", 32) },
        };
    }

    pub fn wipe(self: *HeaderKey) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    pub fn mask(self: *const HeaderKey, sample: *const [sample_len]u8) [5]u8 {
        var out: [16]u8 = undefined;
        switch (self.*) {
            .aes128 => |*ctx| ctx.encrypt(&out, sample),
            .aes256 => |*ctx| ctx.encrypt(&out, sample),
            .chacha20 => |key| {
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                const zeros: [5]u8 = @splat(0);
                ChaCha20.xor(out[0..5], &zeros, counter, key, sample[4..16].*);
            },
        }
        return out[0..5].*;
    }

    /// Applies header protection to a sealed packet whose packet number of
    /// `pn_len` bytes starts at `pn_offset`. The ciphertext must reach 4
    /// bytes past the packet number's start plus the sample (§5.4.2).
    pub fn protect(self: *const HeaderKey, pkt: []u8, pn_offset: usize, pn_len: usize) void {
        const m = self.mask(pkt[pn_offset + 4 ..][0..sample_len]);
        pkt[0] ^= m[0] & firstByteMask(pkt[0]);
        for (pkt[pn_offset..][0..pn_len], m[1..][0..pn_len]) |*b, x| b.* ^= x;
    }

    /// Removes header protection in place. Returns the packet number's
    /// length and truncated value; the reserved and key phase bits of the
    /// first byte are readable afterwards.
    pub fn unprotect(self: *const HeaderKey, pkt: []u8, pn_offset: usize) Error!struct { len: usize, truncated: u32 } {
        if (pkt.len < pn_offset + 4 + sample_len) return error.Undecryptable;
        const m = self.mask(pkt[pn_offset + 4 ..][0..sample_len]);
        pkt[0] ^= m[0] & firstByteMask(pkt[0]);
        const len: usize = (pkt[0] & 3) + 1;
        var pn: u32 = 0;
        for (pkt[pn_offset..][0..len], m[1..][0..len]) |*b, x| {
            b.* ^= x;
            pn = pn << 8 | b.*;
        }
        return .{ .len = len, .truncated = pn };
    }

    fn firstByteMask(first: u8) u8 {
        return if (first & 0x80 != 0) 0x0f else 0x1f;
    }
};

/// Both keys of one direction at one encryption level.
pub const Keys = struct {
    packet: PacketKey,
    header: HeaderKey,

    pub fn init(suite: Suite, secret: []const u8) Keys {
        return .{ .packet = .init(suite, secret), .header = .init(suite, secret) };
    }

    pub fn wipe(self: *Keys) void {
        self.packet.wipe();
        self.header.wipe();
    }

    /// Seals and header-protects `pkt`: the header ends with a `pn_len`-byte
    /// packet number at `pn_offset`, followed by the plaintext payload and
    /// `tag_len` bytes of room.
    pub fn protect(self: *const Keys, pkt: []u8, pn_offset: usize, pn_len: usize, pn: u64) void {
        self.packet.seal(pkt, pn_offset + pn_len, pn);
        self.header.protect(pkt, pn_offset, pn_len);
    }
};

// -- Retry (§5.8) -------------------------------------------------------------

const retry_key = [16]u8{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const retry_nonce = [12]u8{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

/// A Retry packet (RFC 9000 §17.2.5) to a client whose Initial had
/// connection IDs `client_dcid` (the original destination) and
/// `client_scid`. `out` needs 7 + both IDs + the token + 16 bytes.
pub fn writeRetry(out: []u8, client_dcid: []const u8, client_scid: []const u8, new_scid: []const u8, token: []const u8, unused: u8) usize {
    var w: packet.Writer = .{ .buf = out };
    w.byte(0xf0 | (unused & 0x0f));
    w.int(u32, packet.version_1);
    w.byte(@intCast(client_scid.len));
    w.bytes(client_scid);
    w.byte(@intCast(new_scid.len));
    w.bytes(new_scid);
    w.bytes(token);
    const tag = retryTag(client_dcid, w.written());
    w.bytes(&tag);
    return w.pos;
}

fn retryTag(odcid: []const u8, retry_without_tag: []const u8) [tag_len]u8 {
    // The Retry pseudo-packet: the original DCID, then the packet.
    var ad_buf: [1 + packet.max_cid_len + 512]u8 = undefined;
    std.debug.assert(1 + odcid.len + retry_without_tag.len <= ad_buf.len);
    ad_buf[0] = @intCast(odcid.len);
    @memcpy(ad_buf[1..][0..odcid.len], odcid);
    @memcpy(ad_buf[1 + odcid.len ..][0..retry_without_tag.len], retry_without_tag);
    var tag: [tag_len]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(&.{}, &tag, &.{}, ad_buf[0 .. 1 + odcid.len + retry_without_tag.len], retry_nonce, retry_key);
    return tag;
}

// -- Tests: RFC 9001 Appendix A -----------------------------------------------

const testing = std.testing;
const testHex = key_schedule.testHex;
const test_dcid = testHex("8394c8f03e515708");

test "Initial secrets and keys (RFC 9001 A.1)" {
    const s = initialSecrets(&test_dcid);
    try testing.expectEqualSlices(u8, &testHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"), &s.client);
    try testing.expectEqualSlices(u8, &testHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"), &s.server);
    const suite: Suite = .aes_128_gcm_sha256;
    try testing.expectEqualSlices(u8, &testHex("1f369613dd76d5467730efcbe3b1a22d"), &expand(suite, &s.client, "quic key", 16));
    try testing.expectEqualSlices(u8, &testHex("fa044b2f42a3fd3b46fb255c"), &expand(suite, &s.client, "quic iv", 12));
    try testing.expectEqualSlices(u8, &testHex("9f50449e04a0e810283a1e9933adedd2"), &expand(suite, &s.client, "quic hp", 16));
    try testing.expectEqualSlices(u8, &testHex("cf3a5331653c364c88f0f379b6067e37"), &expand(suite, &s.server, "quic key", 16));
    try testing.expectEqualSlices(u8, &testHex("0ac1493ca1905853b0bba03e"), &expand(suite, &s.server, "quic iv", 12));
    try testing.expectEqualSlices(u8, &testHex("c206b8d9b9f0f37644430b490eeaa314"), &expand(suite, &s.server, "quic hp", 16));
}

const client_crypto_frame = testHex(
    \\060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
    \\04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
    \\616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
    \\04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
    \\baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
    \\0d0010000e0403050306030203080408 050806002d00020101001c0002400100
    \\3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
    \\75300901100f088394c8f03e51570806 048000ffff
);

const client_initial_protected = testHex(
    \\c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
    \\d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
    \\1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
    \\8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
    \\30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
    \\457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
    \\4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
    \\4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
    \\485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
    \\059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
    \\7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
    \\9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
    \\be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
    \\68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
    \\c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
    \\f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
    \\291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
    \\25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
    \\14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
    \\ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
    \\e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
    \\c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
    \\203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
    \\cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
    \\fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
    \\a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
    \\90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
    \\162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
    \\40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
    \\6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
    \\8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
    \\be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
    \\54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
    \\760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
    \\f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
    \\056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
    \\7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
    \\e221af44860018ab0856972e194cd934
);

test "client Initial: protect and open (RFC 9001 A.2)" {
    const secrets = initialSecrets(&test_dcid);
    const keys: Keys = .init(.aes_128_gcm_sha256, &secrets.client);
    const header = testHex("c300000001088394c8f03e5157080000449e00000002");

    // Protect: header, CRYPTO frame, PADDING to 1162 bytes, tag.
    var pkt: [client_initial_protected.len]u8 = @splat(0);
    @memcpy(pkt[0..header.len], &header);
    @memcpy(pkt[header.len..][0..client_crypto_frame.len], &client_crypto_frame);
    keys.protect(&pkt, 18, 4, 2);
    try testing.expectEqualSlices(u8, &client_initial_protected, &pkt);

    // Open, the way a server sees it.
    var rx = client_initial_protected;
    const h = try packet.parseHeader(&rx, 8);
    try testing.expectEqual(rx.len, h.len);
    const pn = try keys.header.unprotect(&rx, h.pn_offset);
    try testing.expectEqual(@as(usize, 4), pn.len);
    try testing.expectEqual(@as(u32, 2), pn.truncated);
    const payload = try keys.packet.open(&rx, h.pn_offset + pn.len, packet.decodePn(null, pn.truncated, pn.len));
    try testing.expectEqual(@as(usize, 1162), payload.len);
    try testing.expectEqualSlices(u8, &client_crypto_frame, payload[0..client_crypto_frame.len]);
    for (payload[client_crypto_frame.len..]) |b| try testing.expectEqual(@as(u8, 0), b);

    // Any flipped bit fails authentication.
    var bad = client_initial_protected;
    bad[600] ^= 1;
    const pn2 = try keys.header.unprotect(&bad, 18);
    try testing.expectError(error.Undecryptable, keys.packet.open(&bad, 18 + pn2.len, 2));
}

test "server Initial (RFC 9001 A.3)" {
    const secrets = initialSecrets(&test_dcid);
    const keys: Keys = .init(.aes_128_gcm_sha256, &secrets.server);
    const header = testHex("c1000000010008f067a5502a4262b50040750001");
    const payload = testHex(
        \\02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
        \\88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
        \\0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
        \\020304
    );
    const expected = testHex(
        \\cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
        \\5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
        \\dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
        \\022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4
        \\2158407dd074ee
    );
    var pkt: [expected.len]u8 = undefined;
    @memcpy(pkt[0..header.len], &header);
    @memcpy(pkt[header.len..][0..payload.len], &payload);
    keys.protect(&pkt, header.len - 2, 2, 1);
    try testing.expectEqualSlices(u8, &expected, &pkt);
}

test "Retry integrity tag (RFC 9001 A.4)" {
    var out: [64]u8 = undefined;
    const n = writeRetry(&out, &test_dcid, &.{}, &testHex("f067a5502a4262b5"), "token", 0x0f);
    try testing.expectEqualSlices(u8, &testHex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"), out[0..n]);
}

test "ChaCha20-Poly1305 short header packet (RFC 9001 A.5)" {
    const suite: Suite = .chacha20_poly1305_sha256;
    const secret = testHex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    try testing.expectEqualSlices(u8, &testHex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"), &expand(suite, &secret, "quic key", 32));
    try testing.expectEqualSlices(u8, &testHex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"), &expand(suite, &secret, "quic hp", 32));
    try testing.expectEqualSlices(u8, &testHex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"), nextSecret(suite, &secret)[0..32]);
    const keys: Keys = .init(suite, &secret);
    const pn: u64 = 654360564;
    try testing.expectEqualSlices(u8, &testHex("e0459b3474bdd0e46d417eb0"), &keys.packet.nonce(pn));
    var pkt = testHex("4200bff4" ++ "01" ++ "00000000000000000000000000000000");
    keys.protect(&pkt, 1, 3, pn);
    try testing.expectEqualSlices(u8, &testHex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"), &pkt);

    // And back.
    const h = try packet.parseHeader(&pkt, 0);
    const p = try keys.header.unprotect(&pkt, h.pn_offset);
    try testing.expectEqual(@as(usize, 3), p.len);
    const full = packet.decodePn(pn - 1, p.truncated, p.len);
    try testing.expectEqual(pn, full);
    const payload = try keys.packet.open(&pkt, h.pn_offset + p.len, full);
    try testing.expectEqualSlices(u8, &.{0x01}, payload);
}

test "AES-256-GCM round trip with a key update" {
    const suite: Suite = .aes_256_gcm_sha384;
    var secret: [48]u8 = undefined;
    for (&secret, 0..) |*b, i| b.* = @intCast(i);
    const next = nextSecret(suite, &secret);
    const a: Keys = .init(suite, &secret);
    // After a key update the packet key changes and the header key stays.
    const b: Keys = .{ .packet = .init(suite, &next), .header = a.header };
    for ([_]Keys{ a, b }) |k| {
        var pkt: [1 + 8 + 2 + 30 + tag_len]u8 = undefined;
        pkt[0] = 0x41;
        @memset(pkt[1..9], 7);
        pkt[9] = 0x12;
        pkt[10] = 0x34;
        for (pkt[11..41], 0..) |*x, i| x.* = @intCast(i);
        k.protect(&pkt, 9, 2, 0x1234);
        const p = try k.header.unprotect(&pkt, 9);
        try testing.expectEqual(@as(u32, 0x1234), p.truncated);
        const payload = try k.packet.open(&pkt, 11, 0x1234);
        try testing.expectEqual(@as(u8, 29), payload[29]);
    }
    var pkt: [1 + 8 + 2 + 30 + tag_len]u8 = @splat(0);
    pkt[0] = 0x41;
    a.protect(&pkt, 9, 2, 5);
    _ = try b.header.unprotect(&pkt, 9);
    try testing.expectError(error.Undecryptable, b.packet.open(&pkt, 11, 5));
}
