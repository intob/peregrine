//! TLS 1.3 key schedule (RFC 8446 §7.1), generic over the transcript hash.
//! Secrets are exposed rather than only keys so QUIC (RFC 9001) can derive
//! its packet protection keys from the same traffic secrets.
const std = @import("std");
const tls = std.crypto.tls;

pub fn KeySchedule(comptime HashType: type) type {
    return struct {
        pub const Hash = HashType;
        pub const Hmac = std.crypto.auth.hmac.Hmac(Hash);
        pub const Hkdf = std.crypto.kdf.hkdf.Hkdf(Hmac);
        pub const hash_len = Hash.digest_length;
        pub const Secret = [hash_len]u8;

        const zeros: Secret = @splat(0);
        const empty_hash: Secret = blk: {
            @setEvalBranchQuota(10_000);
            break :blk tls.emptyHash(Hash);
        };

        /// Derive-Secret(secret, label, transcript_hash)
        pub fn deriveSecret(secret: Secret, label: []const u8, transcript_hash: []const u8) Secret {
            return tls.hkdfExpandLabel(Hkdf, secret, label, transcript_hash, hash_len);
        }

        /// Early secret without a PSK.
        pub fn earlySecret() Secret {
            return Hkdf.extract(&.{0}, &zeros);
        }

        pub fn handshakeSecret(early: Secret, shared_secret: []const u8) Secret {
            return Hkdf.extract(&deriveSecret(early, "derived", &empty_hash), shared_secret);
        }

        pub fn masterSecret(handshake: Secret) Secret {
            return Hkdf.extract(&deriveSecret(handshake, "derived", &empty_hash), &zeros);
        }

        /// verify_data for a Finished message sent under `traffic_secret`.
        pub fn finishedVerifyData(traffic_secret: Secret, transcript_hash: []const u8) Secret {
            const key = tls.hkdfExpandLabel(Hkdf, traffic_secret, "finished", "", Hmac.key_length);
            var out: Secret = undefined;
            Hmac.create(&out, transcript_hash, &key);
            return out;
        }

        /// application_traffic_secret_N+1 (KeyUpdate).
        pub fn nextTrafficSecret(secret: Secret) Secret {
            return tls.hkdfExpandLabel(Hkdf, secret, "traffic upd", "", hash_len);
        }

        pub fn trafficKey(comptime key_len: usize, secret: Secret) [key_len]u8 {
            return tls.hkdfExpandLabel(Hkdf, secret, "key", "", key_len);
        }

        pub fn trafficIv(secret: Secret) [12]u8 {
            return tls.hkdfExpandLabel(Hkdf, secret, "iv", "", 12);
        }
    };
}

pub const Sha256 = KeySchedule(std.crypto.hash.sha2.Sha256);
pub const Sha384 = KeySchedule(std.crypto.hash.sha2.Sha384);

/// Hex in RFC 8448 style ("33 ad 0a ..."), whitespace ignored.
pub fn testHex(comptime s: []const u8) [countHex(s) / 2]u8 {
    @setEvalBranchQuota(1_000_000);
    var out: [countHex(s) / 2]u8 = undefined;
    var n: usize = 0;
    var hi: ?u8 = null;
    for (s) |c| {
        const v: u8 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => continue,
        };
        if (hi) |h| {
            out[n] = h << 4 | v;
            n += 1;
            hi = null;
        } else hi = v;
    }
    return out;
}

fn countHex(comptime s: []const u8) usize {
    @setEvalBranchQuota(1_000_000);
    var n: usize = 0;
    for (s) |c| switch (c) {
        '0'...'9', 'a'...'f', 'A'...'F' => n += 1,
        else => {},
    };
    return n;
}

// RFC 8448 §3: simple 1-RTT handshake, TLS_AES_128_GCM_SHA256 over x25519.
test "key schedule matches RFC 8448" {
    const ks = Sha256;
    const expectEqual = std.testing.expectEqualSlices;

    const early = ks.earlySecret();
    try expectEqual(u8, &testHex("33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"), &early);

    const shared = testHex("8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d");
    const hs = ks.handshakeSecret(early, &shared);
    try expectEqual(u8, &testHex("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"), &hs);

    // Transcript hash of ClientHello..ServerHello.
    const hello_hash = testHex("86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8");
    const c_hs = ks.deriveSecret(hs, "c hs traffic", &hello_hash);
    const s_hs = ks.deriveSecret(hs, "s hs traffic", &hello_hash);
    try expectEqual(u8, &testHex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"), &c_hs);
    try expectEqual(u8, &testHex("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"), &s_hs);

    try expectEqual(u8, &testHex("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc"), &ks.trafficKey(16, s_hs));
    try expectEqual(u8, &testHex("5d 31 3e b2 67 12 76 ee 13 00 0b 30"), &ks.trafficIv(s_hs));
    try expectEqual(u8, &testHex("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01"), &ks.trafficKey(16, c_hs));
    try expectEqual(u8, &testHex("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f"), &ks.trafficIv(c_hs));

    const master = ks.masterSecret(hs);
    try expectEqual(u8, &testHex("18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19"), &master);

    // Transcript hash of ClientHello..server Finished.
    const server_fin_hash = testHex("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
    const c_ap = ks.deriveSecret(master, "c ap traffic", &server_fin_hash);
    const s_ap = ks.deriveSecret(master, "s ap traffic", &server_fin_hash);
    try expectEqual(u8, &testHex("9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5"), &c_ap);
    try expectEqual(u8, &testHex("a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43"), &s_ap);
    try expectEqual(u8, &testHex("9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56"), &ks.trafficKey(16, s_ap));
    try expectEqual(u8, &testHex("cf 78 2b 88 dd 83 54 9a ad f1 e9 84"), &ks.trafficIv(s_ap));
    try expectEqual(u8, &testHex("17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51"), &ks.trafficKey(16, c_ap));
    try expectEqual(u8, &testHex("5b 78 92 3d ee 08 57 90 33 e5 23 d9"), &ks.trafficIv(c_ap));
}

test "Finished verify_data matches RFC 8448" {
    const ks = Sha256;
    // The server's Finished covers ClientHello..CertificateVerify; the RFC
    // gives only the result, so check the client's, whose transcript hash
    // (ClientHello..server Finished) appears above.
    const c_hs = testHex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21");
    const server_fin_hash = testHex("96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13");
    try std.testing.expectEqualSlices(
        u8,
        &testHex("a8 ec 43 6d 67 76 34 ae 52 5a c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61"),
        &ks.finishedVerifyData(c_hs, &server_fin_hash),
    );
}
