//! Fuzz target over `tls.Conn`: the record layer and the handshake together.
//!
//! Each input drives a scripted client. It starts from a real session (std's
//! TLS client against this server, recorded once per process): it takes that
//! ClientHello apart, swaps in key shares this harness holds the private keys
//! for, and mutates it (lengths, extensions, key shares, PSK placement, the
//! answer to a HelloRetryRequest). It then follows the server's replies the
//! way a client would, deriving the real handshake and application keys, and
//! sends a scripted mix of valid and invalid records: Finished variants,
//! application data, KeyUpdate, alerts, padding, corrupted, oversized and
//! early-data records. Mode 0 instead replays the recorded session itself
//! with only its ClientHello mutated.
//!
//! The client's bytes are then replayed into fresh connections with other
//! read splits and record boundaries. Checked:
//! - no crash, leak or out-of-bounds access (runtime safety is on);
//! - the server's output is a well-formed record stream; once the harness
//!   knows the keys, every record decrypts and the handshake verifies;
//! - every failure ends the output with a fatal alert, and nothing else ends
//!   with one; where RFC 8446 names the alert, it is that alert;
//! - read splits never change the output, and neither do record boundaries
//!   inside handshake messages and application data;
//! - a script without faults completes, and its plaintext arrives intact.
const std = @import("std");
const tls = std.crypto.tls;
const conn_mod = @import("./conn.zig");
const record = @import("./record.zig");
const handshake = @import("./handshake.zig");
const credentials = @import("./credentials.zig");
const Conn = conn_mod.Conn;
const Protection = record.Protection;
const Suite = record.Suite;
const Description = tls.Alert.Description;
const X25519 = std.crypto.dh.X25519;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Smith = testing.Smith;

const group_x25519: u16 = 0x001d;
const group_p256: u16 = 0x0017;
const group_hybrid: u16 = 0x11ec;

const ext_server_name: u16 = 0;
const ext_supported_groups: u16 = 10;
const ext_signature_algorithms: u16 = 13;
const ext_alpn: u16 = 16;
const ext_padding: u16 = 21;
const ext_pre_shared_key: u16 = 41;
const ext_early_data: u16 = 42;
const ext_supported_versions: u16 = 43;
const ext_psk_modes: u16 = 45;
const ext_key_share: u16 = 51;

const ct_ccs: u8 = 20;
const ct_alert: u8 = 21;
const ct_handshake: u8 = 22;
const ct_app: u8 = 23;

/// Early data the server skips; mirrors `max_skipped_early_data` in conn.zig.
const early_budget = 64 * 1024;

// -- Fixtures -----------------------------------------------------------------

const Fixtures = struct {
    creds: [3]credentials.Credentials,
    /// Every byte std's client sent in the recorded session.
    session: []const u8,
    /// The recorded ClientHello message (inside the first record).
    hello: []const u8,
    x25519: X25519.KeyPair,
    p256: P256.KeyPair,
    mlkem: MLKem768.KeyPair,
    p256_share: [65]u8,
    hybrid_share: [MLKem768.PublicKey.encoded_length + 32]u8,

    fn share(self: *const Fixtures, group: u16) ?[]const u8 {
        return switch (group) {
            group_x25519 => &self.x25519.public_key,
            group_p256 => &self.p256_share,
            group_hybrid => &self.hybrid_share,
            else => null,
        };
    }

    /// The client's side of the key exchange with the server's share.
    fn sharedSecret(self: *const Fixtures, group: u16, server: []const u8, out: *[64]u8) ![]const u8 {
        switch (group) {
            group_x25519 => {
                if (server.len != 32) return error.BadServerShare;
                out[0..32].* = try X25519.scalarmult(self.x25519.secret_key, server[0..32].*);
                return out[0..32];
            },
            group_p256 => {
                const pk = try P256.PublicKey.fromSec1(server);
                out[0..32].* = (try pk.p.mulPublic(self.p256.secret_key.bytes, .big)).affineCoordinates().x.toBytes(.big);
                return out[0..32];
            },
            group_hybrid => {
                const ct_len = MLKem768.ciphertext_length;
                if (server.len != ct_len + 32) return error.BadServerShare;
                out[0..32].* = try self.mlkem.secret_key.decaps(server[0..ct_len]);
                out[32..64].* = try X25519.scalarmult(self.x25519.secret_key, server[ct_len..][0..32].*);
                return out[0..64];
            },
            else => return error.BadServerShare,
        }
    }
};

var fixtures_storage: Fixtures = undefined;
var fixtures_ready = false;

/// Built once per process and never freed (page allocator, so the leak
/// checker doesn't count it against the first input).
fn fixtures() !*const Fixtures {
    if (fixtures_ready) return &fixtures_storage;
    const a = std.heap.page_allocator;
    const td = credentials.testdata;
    const f = &fixtures_storage;
    f.creds = .{
        try .fromPem(a, td.p256_cert, td.p256_key),
        try .fromPem(a, td.p384_cert, td.p384_key),
        try .fromPem(a, td.ed25519_cert, td.ed25519_key),
    };
    {
        var server: conn_mod.TestServer = undefined;
        try server.init(td.p256_cert, td.p256_key);
        defer server.deinit();
        var transcript: std.ArrayList(u8) = .empty;
        defer transcript.deinit(testing.allocator);
        try conn_mod.runAgainstStdClient(&server, recorded_request, &transcript);
        f.session = try a.dupe(u8, transcript.items);
    }
    if (f.session.len < 9 or f.session[0] != ct_handshake) return error.BadRecording;
    const first_len = std.mem.readInt(u16, f.session[3..5], .big);
    f.hello = f.session[5..][0..first_len];
    if (f.hello[0] != 1 or std.mem.readInt(u24, f.hello[1..4], .big) + 4 != f.hello.len) return error.BadRecording;
    f.x25519 = X25519.KeyPair.generateDeterministic(@splat(11));
    f.p256 = try P256.KeyPair.generateDeterministic(@splat(12));
    f.mlkem = try MLKem768.KeyPair.generateDeterministic(@splat(13));
    f.p256_share = f.p256.public_key.toUncompressedSec1();
    const ek = f.mlkem.public_key.toBytes();
    @memcpy(f.hybrid_share[0..ek.len], &ek);
    @memcpy(f.hybrid_share[ek.len..], &f.x25519.public_key);
    fixtures_ready = true;
    return f;
}

const recorded_request = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";

// -- Byte helpers -------------------------------------------------------------

const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    fn take(r: *Reader, n: usize) ![]const u8 {
        if (r.data.len - r.pos < n) return error.Truncated;
        defer r.pos += n;
        return r.data[r.pos..][0..n];
    }

    fn int(r: *Reader, comptime T: type) !T {
        const n = @divExact(@bitSizeOf(T), 8);
        return std.mem.readInt(T, (try r.take(n))[0..n], .big);
    }

    fn vec(r: *Reader, comptime T: type) ![]const u8 {
        return r.take(try r.int(T));
    }

    fn done(r: *const Reader) bool {
        return r.pos == r.data.len;
    }
};

fn putInt(list: *std.ArrayList(u8), a: Allocator, comptime T: type, v: T) !void {
    var b: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .big);
    try list.appendSlice(a, &b);
}

/// A length, off by `delta` and truncated to the field's width (mutations
/// need lengths that lie).
fn lieLen(comptime T: type, len: usize, delta: i32) T {
    return @truncate(@as(u64, @bitCast(@as(i64, @intCast(len)) + delta)));
}

fn putVec(list: *std.ArrayList(u8), a: Allocator, comptime T: type, bytes: []const u8, delta: i32) !void {
    try putInt(list, a, T, lieLen(T, bytes.len, delta));
    try list.appendSlice(a, bytes);
}

fn listHas(list: []const u8, v: u16) bool {
    var i: usize = 0;
    while (i + 2 <= list.len) : (i += 2) {
        if (std.mem.readInt(u16, list[i..][0..2], .big) == v) return true;
    }
    return false;
}

// -- ClientHello --------------------------------------------------------------

const HelloExt = struct {
    type: u16,
    body: []const u8,
    len_delta: i32 = 0,
};

const KeyShare = struct { group: u16, kx: []const u8 };

const Hello = struct {
    legacy_version: u16,
    random: [32]u8,
    session_id: []const u8,
    suites: []const u8,
    compression: []const u8,
    exts: std.ArrayList(HelloExt) = .empty,
    sid_delta: i32 = 0,
    exts_delta: i32 = 0,
    msg_delta: i32 = 0,
    /// Bytes after the extensions, inside the message.
    trailing: []const u8 = "",
    /// Bytes cut from the end of the body (the length still matches).
    cut: u32 = 0,

    fn parse(a: Allocator, msg: []const u8) !Hello {
        var r: Reader = .{ .data = msg[4..] };
        var h: Hello = .{
            .legacy_version = try r.int(u16),
            .random = (try r.take(32))[0..32].*,
            .session_id = try r.vec(u8),
            .suites = try r.vec(u16),
            .compression = try r.vec(u8),
        };
        var e: Reader = .{ .data = try r.vec(u16) };
        while (!e.done()) try h.exts.append(a, .{ .type = try e.int(u16), .body = try e.vec(u16) });
        return h;
    }

    fn encode(h: *const Hello, a: Allocator) ![]u8 {
        var w: std.ArrayList(u8) = .empty;
        try w.appendSlice(a, &.{ 1, 0, 0, 0 });
        try putInt(&w, a, u16, h.legacy_version);
        try w.appendSlice(a, &h.random);
        try putVec(&w, a, u8, h.session_id, h.sid_delta);
        try putVec(&w, a, u16, h.suites, 0);
        try putVec(&w, a, u8, h.compression, 0);
        const exts_at = w.items.len;
        try putInt(&w, a, u16, 0);
        for (h.exts.items) |e| {
            try putInt(&w, a, u16, e.type);
            try putVec(&w, a, u16, e.body, e.len_delta);
        }
        std.mem.writeInt(u16, w.items[exts_at..][0..2], lieLen(u16, w.items.len - exts_at - 2, h.exts_delta), .big);
        try w.appendSlice(a, h.trailing);
        w.shrinkRetainingCapacity(w.items.len - @min(h.cut, w.items.len - 4));
        std.mem.writeInt(u24, w.items[1..4], lieLen(u24, w.items.len - 4, h.msg_delta), .big);
        return w.items;
    }

    fn find(h: *const Hello, t: u16) ?usize {
        for (h.exts.items, 0..) |e, i| if (e.type == t) return i;
        return null;
    }

    fn ext(h: *const Hello, t: u16) ?[]const u8 {
        return if (h.find(t)) |i| h.exts.items[i].body else null;
    }

    fn setExt(h: *Hello, a: Allocator, t: u16, body: []const u8) !void {
        if (h.find(t)) |i| {
            h.exts.items[i].body = body;
        } else {
            // Before pre_shared_key, which must stay last.
            const at = h.find(ext_pre_shared_key) orelse h.exts.items.len;
            try h.exts.insert(a, at, .{ .type = t, .body = body });
        }
    }

    fn shares(h: *const Hello, out: []KeyShare) usize {
        const body = h.ext(ext_key_share) orelse return 0;
        var r: Reader = .{ .data = body };
        var list: Reader = .{ .data = r.vec(u16) catch return 0 };
        var n: usize = 0;
        while (!list.done() and n < out.len) {
            const g = list.int(u16) catch break;
            const kx = list.vec(u16) catch break;
            out[n] = .{ .group = g, .kx = kx };
            n += 1;
        }
        return n;
    }

    /// The key_share body for `list` (vector of KeyShareEntry).
    fn sharesBody(a: Allocator, list: []const KeyShare) ![]u8 {
        var w: std.ArrayList(u8) = .empty;
        try putInt(&w, a, u16, 0);
        for (list) |s| {
            try putInt(&w, a, u16, s.group);
            try putVec(&w, a, u16, s.kx, 0);
        }
        std.mem.writeInt(u16, w.items[0..2], @intCast(w.items.len - 2), .big);
        return w.items;
    }

    fn u16List(a: Allocator, comptime T: type, values: []const u16) ![]u8 {
        var w: std.ArrayList(u8) = .empty;
        try putInt(&w, a, T, @intCast(values.len * 2));
        for (values) |v| try putInt(&w, a, u16, v);
        return w.items;
    }
};

/// Replaces each key share for a group this harness supports with its own.
fn substituteShares(a: Allocator, fx: *const Fixtures, h: *Hello) !void {
    var list: [16]KeyShare = undefined;
    const n = h.shares(&list);
    if (n == 0) return;
    for (list[0..n]) |*s| {
        if (fx.share(s.group)) |mine| s.kx = mine;
    }
    try h.setExt(a, ext_key_share, try Hello.sharesBody(a, list[0..n]));
}

const Mutation = enum(u8) {
    flip_byte,
    ext_len,
    drop_ext,
    dup_ext,
    swap_exts,
    add_psk,
    add_early_data,
    add_unknown,
    add_padding,
    share_only,
    share_none,
    share_dup,
    share_bad_len,
    share_low_order,
    share_bad_point,
    share_unlisted,
    share_empty,
    groups,
    versions,
    suites,
    session_id,
    compression,
    msg_len,
    exts_len,
    trailing,
    cut,
    alpn,
    sig_algs,
    legacy_version,
};

const MutationResult = struct {
    /// Every mutation left a valid ClientHello.
    benign: bool = true,
    /// The message length still frames the message (record boundaries
    /// inside it must not matter).
    framed: bool = true,
    early_data: bool = false,
};

/// Byte content comes from a PRNG seeded by one value, so every Smith
/// read is an integer. (Replaying a corpus, Smith reads each integer from 8
/// input bytes; raw byte reads in between would misalign the rest.)
fn fill(smith: *Smith, buf: []u8) void {
    var prng = std.Random.DefaultPrng.init(smith.value(u64));
    prng.random().bytes(buf);
}

fn randomBytes(a: Allocator, smith: *Smith, max: u16) ![]u8 {
    const buf = try a.alloc(u8, smith.valueRangeAtMost(u16, 0, max));
    fill(smith, buf);
    return buf;
}

fn pickGroup(smith: *Smith) u16 {
    return switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => group_x25519,
        1 => group_p256,
        else => group_hybrid,
    };
}

fn mutateHello(a: Allocator, smith: *Smith, fx: *const Fixtures, h: *Hello, res: *MutationResult, count: u8) !void {
    for (0..count) |_| {
        const m = smith.valueRangeAtMost(u8, 0, @typeInfo(Mutation).@"enum".field_names.len - 1);
        if (trace) std.debug.print("mutation {s}\n", .{@tagName(@as(Mutation, @fromBackingInt(m)))});
        const exts = h.exts.items;
        switch (@as(Mutation, @fromBackingInt(m))) {
            .flip_byte => {
                if (exts.len == 0) continue;
                const i = smith.index(exts.len);
                if (exts[i].body.len == 0) continue;
                const body = try a.dupe(u8, exts[i].body);
                body[smith.index(body.len)] ^= smith.valueRangeAtMost(u8, 1, 255);
                exts[i].body = body;
                res.benign = false;
            },
            .ext_len => {
                if (exts.len == 0) continue;
                exts[smith.index(exts.len)].len_delta = smith.valueRangeAtMost(i32, -4, 4);
                res.benign = false;
            },
            .drop_ext => {
                if (exts.len == 0) continue;
                const i = smith.index(exts.len);
                switch (exts[i].type) {
                    ext_supported_groups, ext_signature_algorithms, ext_supported_versions, ext_key_share => res.benign = false,
                    else => {},
                }
                _ = h.exts.orderedRemove(i);
            },
            .dup_ext => {
                if (exts.len == 0) continue;
                const e = exts[smith.index(exts.len)];
                try h.exts.insert(a, smith.index(exts.len + 1), e);
                res.benign = false;
            },
            .swap_exts => {
                if (exts.len < 2) continue;
                const i = smith.index(exts.len);
                const j = smith.index(exts.len);
                if (exts[i].type == ext_pre_shared_key or exts[j].type == ext_pre_shared_key) res.benign = false;
                std.mem.swap(HelloExt, &exts[i], &exts[j]);
            },
            .add_psk => {
                // identities<7..>: identity<1..2^16-1>, obfuscated_ticket_age;
                // binders<33..>: a 32-byte binder. Last or not.
                var w: std.ArrayList(u8) = .empty;
                const identity = try randomBytes(a, smith, 64);
                try putInt(&w, a, u16, @intCast(identity.len + 6));
                try putVec(&w, a, u16, identity, 0);
                try putInt(&w, a, u32, smith.value(u32));
                try putInt(&w, a, u16, 33);
                try w.append(a, 32);
                try w.appendNTimes(a, smith.value(u8), 32);
                const last = smith.boolWeighted(1, 3);
                try h.exts.insert(a, if (last) exts.len else smith.index(exts.len + 1), .{ .type = ext_pre_shared_key, .body = w.items });
                if (!last or identity.len == 0 or h.find(ext_psk_modes) == null) res.benign = false;
            },
            .add_early_data => {
                try h.setExt(a, ext_early_data, "");
                res.early_data = true;
            },
            .add_unknown => {
                // A type no TLS 1.3 server acts on.
                const t = 0x7a00 | @as(u16, smith.value(u8));
                if (h.find(t) != null) continue;
                try h.setExt(a, t, try randomBytes(a, smith, 300));
            },
            .add_padding => {
                if (h.find(ext_padding) != null) continue;
                const body = try a.alloc(u8, smith.valueRangeAtMost(u16, 0, 1024));
                @memset(body, 0);
                try h.setExt(a, ext_padding, body);
            },
            .share_only => {
                const g = pickGroup(smith);
                try h.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = fx.share(g).? }}));
            },
            .share_none => try h.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{})),
            .share_dup => {
                const g = pickGroup(smith);
                const s: KeyShare = .{ .group = g, .kx = fx.share(g).? };
                try h.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{ s, s }));
                res.benign = false;
            },
            .share_bad_len => {
                const g = pickGroup(smith);
                const good = fx.share(g).?;
                const len = if (smith.boolWeighted(1, 1)) good.len - 1 else good.len + 1;
                const kx = try a.alloc(u8, len);
                @memcpy(kx[0..@min(len, good.len)], good[0..@min(len, good.len)]);
                if (len > good.len) kx[good.len] = 0;
                try h.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = kx }}));
                res.benign = false;
            },
            .share_low_order => {
                // X25519 points of small order give an all-zero secret.
                const kx = try a.alloc(u8, 32);
                @memset(kx, 0);
                if (smith.boolWeighted(1, 1)) kx[0] = 1;
                try h.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = group_x25519, .kx = kx }}));
                res.benign = false;
            },
            .share_bad_point => {
                const g: u16 = if (smith.boolWeighted(1, 1)) group_p256 else group_hybrid;
                const kx = try a.alloc(u8, fx.share(g).?.len);
                fill(smith, kx);
                if (g == group_p256) kx[0] = if (smith.boolWeighted(3, 1)) 4 else 2;
                try h.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = kx }}));
                res.benign = false;
            },
            .share_unlisted => {
                // A share for a group missing from supported_groups.
                const g = pickGroup(smith);
                var others: [2]u16 = undefined;
                var n: usize = 0;
                for ([_]u16{ group_x25519, group_p256, group_hybrid }) |x| {
                    if (x == g) continue;
                    others[n] = x;
                    n += 1;
                }
                try h.setExt(a, ext_supported_groups, try Hello.u16List(a, u16, &others));
                try h.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = fx.share(g).? }}));
                res.benign = false;
            },
            .share_empty => {
                try h.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = pickGroup(smith), .kx = "" }}));
                res.benign = false;
            },
            .groups => {
                var list: [8]u16 = undefined;
                const n = smith.valueRangeAtMost(u8, 0, list.len);
                for (list[0..n]) |*g| g.* = if (smith.boolWeighted(1, 1)) pickGroup(smith) else smith.value(u16);
                try h.setExt(a, ext_supported_groups, try Hello.u16List(a, u16, list[0..n]));
                res.benign = false;
            },
            .versions => {
                var list: [4]u16 = undefined;
                const n = smith.valueRangeAtMost(u8, 0, list.len);
                for (list[0..n]) |*v| v.* = if (smith.boolWeighted(1, 1)) 0x0303 + @as(u16, smith.valueRangeAtMost(u8, 0, 2)) else smith.value(u16);
                try h.setExt(a, ext_supported_versions, try Hello.u16List(a, u8, list[0..n]));
                res.benign = false;
            },
            .suites => {
                var list: [6]u16 = undefined;
                const n = smith.valueRangeAtMost(u8, 0, list.len);
                for (list[0..n]) |*s| s.* = if (smith.boolWeighted(1, 1)) 0x1301 + @as(u16, smith.valueRangeAtMost(u8, 0, 3)) else smith.value(u16);
                h.suites = (try Hello.u16List(a, u16, list[0..n]))[2..];
                res.benign = false;
            },
            .session_id => {
                h.session_id = try randomBytes(a, smith, 40);
                if (smith.boolWeighted(3, 1)) h.sid_delta = smith.valueRangeAtMost(i32, -2, 2);
                if (h.session_id.len > 32 or h.sid_delta != 0) res.benign = false;
            },
            .compression => {
                h.compression = try randomBytes(a, smith, 3);
                res.benign = false;
            },
            .msg_len => {
                h.msg_delta = smith.valueRangeAtMost(i32, -3, 3);
                if (h.msg_delta != 0) {
                    res.benign = false;
                    res.framed = false;
                }
            },
            .exts_len => {
                h.exts_delta = smith.valueRangeAtMost(i32, -3, 3);
                res.benign = false;
            },
            .trailing => {
                h.trailing = try randomBytes(a, smith, 8);
                res.benign = false;
            },
            .cut => {
                h.cut = smith.valueRangeAtMost(u32, 1, 64);
                res.benign = false;
            },
            .alpn => {
                const offers = [_][]const u8{ "\x08http/1.1", "\x02h2", "\x02h2\x08http/1.1", "\x03foo", "", "\x00", "\x05short" };
                var w: std.ArrayList(u8) = .empty;
                try putVec(&w, a, u16, offers[smith.index(offers.len)], 0);
                try h.setExt(a, ext_alpn, w.items);
                res.benign = false;
            },
            .sig_algs => {
                var list: [6]u16 = undefined;
                const n = smith.valueRangeAtMost(u8, 0, list.len);
                const known = [_]u16{ 0x0403, 0x0503, 0x0807, 0x0804, 0x0603 };
                for (list[0..n]) |*s| s.* = if (smith.boolWeighted(1, 2)) smith.value(u16) else known[smith.index(known.len)];
                try h.setExt(a, ext_signature_algorithms, try Hello.u16List(a, u16, list[0..n]));
                res.benign = false;
            },
            .legacy_version => {
                // Ignored when supported_versions is present (§4.2.1).
                h.legacy_version = smith.value(u16);
            },
        }
    }
}

// -- Client records -----------------------------------------------------------

/// One record (or, with `frags`, several) the client sends.
const Rec = struct {
    kind: enum { plain, sealed, raw },
    /// Outer type for plain records, inner type for sealed ones.
    ct: u8 = ct_app,
    /// Sealed records: 0 = handshake keys, n = application keys after n-1
    /// KeyUpdates.
    epoch: u32 = 0,
    data: []const u8,
    padding: u16 = 0,
    /// The whole inner plaintext, for malformed sealed records.
    inner: ?[]const u8 = null,
    corrupt: bool = false,
    legacy_version: u16 = 0x0303,
    /// Fragment sizes for the fragmented serialisation. Only set where
    /// record boundaries must not matter.
    frags: []const u16 = &.{},
};

const Keys = struct {
    suite: Suite,
    c_hs: [record.max_hash_len]u8 = undefined,
    c_ap: [record.max_hash_len]u8 = undefined,
    have_ap: bool = false,
};

/// Turns records into bytes, tracking the client's sequence numbers.
const Serializer = struct {
    keys: *const ?Keys,
    hs: ?Protection = null,
    ap: ?Protection = null,
    ap_epoch: u32 = 0,

    fn protection(self: *Serializer, epoch: u32) *Protection {
        const keys = self.keys.*.?;
        if (epoch == 0) {
            if (self.hs == null) self.hs = .init(keys.suite, keys.c_hs[0..keys.suite.hashLen()]);
            return &self.hs.?;
        }
        std.debug.assert(keys.have_ap);
        if (self.ap == null) {
            self.ap = .init(keys.suite, keys.c_ap[0..keys.suite.hashLen()]);
            self.ap_epoch = 1;
        }
        std.debug.assert(epoch >= self.ap_epoch);
        while (self.ap_epoch < epoch) : (self.ap_epoch += 1) self.ap.?.update();
        return &self.ap.?;
    }

    fn write(self: *Serializer, a: Allocator, out: *std.ArrayList(u8), rec: Rec, fragmented: bool) !void {
        if (rec.kind == .raw) return out.appendSlice(a, rec.data);
        var rest = rec.data;
        var fi: usize = 0;
        while (true) {
            var n = rest.len;
            if (fragmented and rec.frags.len > 0 and rest.len > 1) {
                n = @min(rest.len, @max(1, rec.frags[fi % rec.frags.len]));
                fi += 1;
            }
            const piece = rest[0..n];
            rest = rest[n..];
            const last = rest.len == 0;
            switch (rec.kind) {
                .plain => {
                    try out.append(a, rec.ct);
                    try putInt(out, a, u16, rec.legacy_version);
                    try putVec(out, a, u16, piece, 0);
                },
                .sealed => {
                    const inner = rec.inner orelse blk: {
                        const buf = try a.alloc(u8, piece.len + 1 + if (last) rec.padding else 0);
                        @memcpy(buf[0..piece.len], piece);
                        buf[piece.len] = rec.ct;
                        @memset(buf[piece.len + 1 ..], 0);
                        break :blk buf;
                    };
                    try seal(self.protection(rec.epoch), a, out, inner, rec.corrupt);
                },
                .raw => unreachable,
            }
            if (last) break;
        }
    }
};

/// Seals any inner plaintext (record.Protection.seal only builds valid ones).
fn seal(p: *Protection, a: Allocator, out: *std.ArrayList(u8), inner: []const u8, corrupt: bool) !void {
    const start = out.items.len;
    try out.append(a, ct_app);
    try out.appendSlice(a, &.{ 3, 3 });
    try putInt(out, a, u16, @intCast(inner.len + record.tag_len));
    try out.appendSlice(a, inner);
    try out.appendNTimes(a, 0, record.tag_len);
    const rec = out.items[start..];
    var nonce = p.iv;
    var seq: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq, p.seq, .big);
    for (nonce[4..], seq) |*b, s| b.* ^= s;
    const body = rec[record.header_len..];
    switch (p.suite) {
        inline else => |s| {
            const A = s.Aead();
            A.encrypt(body[0..inner.len], body[inner.len..][0..record.tag_len], body[0..inner.len], rec[0..record.header_len], nonce, p.key[0..A.key_length].*);
        },
    }
    p.seq += 1;
    if (corrupt) body[body.len - 1] ^= 0x80;
}

// -- The client's view of the server's output ---------------------------------

/// Parses and checks everything the server sends, as a client would: the
/// record stream, ServerHello/HelloRetryRequest against what was offered,
/// the encrypted flight and its Finished, KeyUpdates and the final alert.
const View = struct {
    fx: *const Fixtures,
    a: Allocator,
    pos: usize = 0,
    state: enum { start, hrr, flight, connected, opaque_keys } = .start,
    suite: ?Suite = null,
    transcript: std.ArrayList(u8) = .empty,
    hs_in: std.ArrayList(u8) = .empty,
    read: ?Protection = null,
    keys: ?Keys = null,
    hs_secret: [record.max_hash_len]u8 = undefined,
    s_hs: [record.max_hash_len]u8 = undefined,
    /// The latest ClientHello sent.
    hello: ?Hello = null,
    hrr_group: ?u16 = null,
    ccs_seen: bool = false,
    client_finished: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    alert: ?[2]u8 = null,
    ku_received: u32 = 0,

    fn sentHello(v: *View, msg: []const u8) !void {
        try v.transcript.appendSlice(v.a, msg);
        v.hello = Hello.parse(v.a, msg) catch null;
    }

    fn hash(v: *const View, out: *[record.max_hash_len]u8) []const u8 {
        switch (v.suite.?) {
            inline else => |s| {
                const H = s.Schedule().Hash;
                H.hash(v.transcript.items, out[0..H.digest_length], .{});
                return out[0..H.digest_length];
            },
        }
    }

    /// Processes every complete record from where the last call stopped.
    fn pump(v: *View, wire: []const u8) !void {
        while (wire.len - v.pos >= record.header_len) {
            const len = std.mem.readInt(u16, wire[v.pos + 3 ..][0..2], .big);
            if (wire.len - v.pos < record.header_len + len) return error.PartialServerRecord;
            const rec = wire[v.pos..][0 .. record.header_len + len];
            v.pos += rec.len;
            if (v.alert != null) return error.RecordAfterAlert;
            if (rec[1] != 3 or rec[2] != 3) return error.BadServerRecordVersion;
            try v.onRecord(rec);
        }
        if (v.pos != wire.len) return error.PartialServerRecord;
    }

    fn onRecord(v: *View, rec: []const u8) !void {
        const body = rec[record.header_len..];
        switch (rec[0]) {
            ct_handshake => {
                if (v.state != .start and v.state != .hrr) return error.PlaintextHandshakeAfterKeys;
                if (body.len == 0 or body.len > record.max_plaintext) return error.BadServerRecord;
                try v.hs_in.appendSlice(v.a, body);
                try v.onHandshake();
            },
            ct_ccs => {
                if (v.ccs_seen or v.state == .connected or !std.mem.eql(u8, body, "\x01")) return error.BadServerCcs;
                v.ccs_seen = true;
            },
            ct_alert => {
                // Only before the server has keys.
                if (v.state != .start and v.state != .hrr) return error.PlaintextAlertAfterKeys;
                if (body.len != 2) return error.BadServerAlert;
                v.alert = body[0..2].*;
            },
            ct_app => {
                if (v.state == .opaque_keys) {
                    // Keys unknown: an alert is the only record of its size.
                    if (body.len == 2 + 1 + record.tag_len) v.alert = .{ 2, 0 };
                    return;
                }
                var p = &(v.read orelse return error.EncryptedBeforeServerHello);
                var copy: [record.max_record]u8 = undefined;
                if (rec.len > copy.len) return error.BadServerRecord;
                @memcpy(copy[0..rec.len], rec);
                const opened = p.open(copy[0..rec.len]) catch return error.UndecryptableServerRecord;
                switch (opened.content_type) {
                    .handshake => {
                        try v.hs_in.appendSlice(v.a, opened.data);
                        try v.onHandshake();
                    },
                    .alert => {
                        if (opened.data.len != 2) return error.BadServerAlert;
                        v.alert = opened.data[0..2].*;
                    },
                    else => return error.UnexpectedServerContent,
                }
            },
            else => return error.BadServerRecordType,
        }
    }

    fn onHandshake(v: *View) !void {
        while (v.hs_in.items.len >= 4) {
            const len = std.mem.readInt(u24, v.hs_in.items[1..4], .big);
            if (v.hs_in.items.len < 4 + len) return;
            const msg = try v.a.dupe(u8, v.hs_in.items[0 .. 4 + len]);
            const left = v.hs_in.items.len - msg.len;
            std.mem.copyForwards(u8, v.hs_in.items[0..left], v.hs_in.items[msg.len..]);
            v.hs_in.shrinkRetainingCapacity(left);
            try v.onMessage(msg);
        }
    }

    fn onMessage(v: *View, msg: []const u8) !void {
        switch (v.state) {
            .start, .hrr => {
                if (msg[0] != 2) return error.ExpectedServerHello;
                try v.onServerHello(msg);
            },
            .flight => try v.onFlight(msg),
            .connected => {
                // Only a KeyUpdate answering ours, never requesting one.
                if (!std.mem.eql(u8, msg, &.{ 24, 0, 0, 1, 0 })) return error.UnexpectedPostHandshake;
                v.ku_received += 1;
                v.read.?.update();
            },
            .opaque_keys => {},
        }
    }

    fn onServerHello(v: *View, msg: []const u8) !void {
        var r: Reader = .{ .data = msg[4..] };
        if (try r.int(u16) != 0x0303) return error.BadServerHello;
        const random = try r.take(32);
        const sid = try r.vec(u8);
        const suite_v = try r.int(u16);
        if (try r.int(u8) != 0) return error.BadServerHello;
        var e: Reader = .{ .data = try r.vec(u16) };
        if (!r.done()) return error.BadServerHello;
        var group: ?u16 = null;
        var share: []const u8 = "";
        var version_ok = false;
        while (!e.done()) {
            const t = try e.int(u16);
            var b: Reader = .{ .data = try e.vec(u16) };
            switch (t) {
                ext_supported_versions => version_ok = try b.int(u16) == 0x0304,
                ext_key_share => {
                    group = try b.int(u16);
                    if (!b.done()) share = try b.vec(u16);
                },
                else => return error.UnexpectedServerHelloExtension,
            }
            if (!b.done()) return error.BadServerHello;
        }
        if (!version_ok or group == null) return error.BadServerHello;
        const suite: Suite = switch (suite_v) {
            0x1301, 0x1302, 0x1303 => @fromBackingInt(suite_v),
            else => return error.BadServerSuite,
        };
        const is_hrr = std.mem.eql(u8, random, &tls.hello_retry_request_sequence);

        // Checks against what the client offered, when it can parse that.
        if (v.hello) |h| {
            if (!std.mem.eql(u8, sid, h.session_id)) return error.SessionIdNotEchoed;
            if (!listHas(h.suites, suite_v)) return error.SuiteNotOffered;
            var list: [16]KeyShare = undefined;
            const n = h.shares(&list);
            const sent = for (list[0..n]) |s| {
                if (s.group == group.?) break s.kx;
            } else null;
            if (is_hrr) {
                if (sent != null) return error.RetryForSentGroup;
                if (h.ext(ext_supported_groups)) |g| {
                    if (g.len < 2 or !listHas(g[2..], group.?)) return error.RetryForUnofferedGroup;
                }
            } else if (sent == null) return error.ServerHelloWithoutShare;
        }
        if (v.suite) |s| if (s != suite) return error.SuiteChangedAfterRetry;
        v.suite = suite;

        if (is_hrr) {
            if (v.state == .hrr or share.len != 0) return error.BadHelloRetryRequest;
            // §4.4.1: ClientHello1 becomes message_hash(ClientHello1).
            var h: [record.max_hash_len]u8 = undefined;
            const ch1 = v.hash(&h);
            v.transcript.clearRetainingCapacity();
            try v.transcript.appendSlice(v.a, &.{ 254, 0, 0, @intCast(ch1.len) });
            try v.transcript.appendSlice(v.a, ch1);
            try v.transcript.appendSlice(v.a, msg);
            v.hrr_group = group;
            v.state = .hrr;
            return;
        }
        if (v.hrr_group) |g| if (g != group.?) return error.GroupChangedAfterRetry;
        try v.transcript.appendSlice(v.a, msg);

        // Derive keys if the share the server used is ours.
        var list: [16]KeyShare = undefined;
        const n = if (v.hello) |h| h.shares(&list) else 0;
        const ours = for (list[0..n]) |s| {
            if (s.group == group.?) break if (v.fx.share(s.group)) |mine| std.mem.eql(u8, mine, s.kx) else false;
        } else false;
        if (!ours) {
            v.state = .opaque_keys;
            return;
        }
        var shared_buf: [64]u8 = undefined;
        const shared = try v.fx.sharedSecret(group.?, share, &shared_buf);
        var h: [record.max_hash_len]u8 = undefined;
        const hello_hash = v.hash(&h);
        v.keys = .{ .suite = suite };
        switch (suite) {
            inline else => |s| {
                const ks = s.Schedule();
                const hs = ks.handshakeSecret(ks.earlySecret(), shared);
                v.hs_secret[0..ks.hash_len].* = hs;
                v.s_hs[0..ks.hash_len].* = ks.deriveSecret(hs, "s hs traffic", hello_hash);
                v.keys.?.c_hs[0..ks.hash_len].* = ks.deriveSecret(hs, "c hs traffic", hello_hash);
                v.read = .init(suite, v.s_hs[0..ks.hash_len]);
            },
        }
        v.state = .flight;
    }

    fn onFlight(v: *View, msg: []const u8) !void {
        const suite = v.suite.?;
        switch (msg[0]) {
            8 => {
                var r: Reader = .{ .data = msg[4..] };
                var e: Reader = .{ .data = try r.vec(u16) };
                while (!e.done()) {
                    const t = try e.int(u16);
                    var b: Reader = .{ .data = try e.vec(u16) };
                    if (t != ext_alpn) return error.UnexpectedEncryptedExtension;
                    var list: Reader = .{ .data = try b.vec(u16) };
                    v.alpn = try list.vec(u8);
                    if (!list.done() or !b.done()) return error.BadAlpn;
                }
            },
            11, 15 => {},
            20 => {
                var h: [record.max_hash_len]u8 = undefined;
                switch (suite) {
                    inline else => |s| {
                        const ks = s.Schedule();
                        const expected = ks.finishedVerifyData(v.s_hs[0..ks.hash_len].*, v.hash(&h));
                        if (!std.mem.eql(u8, msg[4..], &expected)) return error.BadServerFinished;
                        try v.transcript.appendSlice(v.a, msg);
                        const fin_hash = v.hash(&h);
                        const master = ks.masterSecret(v.hs_secret[0..ks.hash_len].*);
                        const s_ap = ks.deriveSecret(master, "s ap traffic", fin_hash);
                        v.keys.?.c_ap[0..ks.hash_len].* = ks.deriveSecret(master, "c ap traffic", fin_hash);
                        v.keys.?.have_ap = true;
                        const fin = try v.a.alloc(u8, 4 + ks.hash_len);
                        fin[0..4].* = .{ 20, 0, 0, ks.hash_len };
                        fin[4..][0..ks.hash_len].* = ks.finishedVerifyData(v.keys.?.c_hs[0..ks.hash_len].*, fin_hash);
                        v.client_finished = fin;
                        v.read = .init(suite, &s_ap);
                    },
                }
                v.state = .connected;
                return;
            },
            else => return error.UnexpectedFlightMessage,
        }
        try v.transcript.appendSlice(v.a, msg);
    }
};

// -- Expected outcome ---------------------------------------------------------

const Expect = struct {
    /// The model below applies (the server took the ClientHello and the
    /// harness knows the keys).
    exact: bool = false,
    /// The first invalid input the server must fail on, and the alert it
    /// must send (null: any fatal alert).
    fault: ?struct { alert: ?Description, line: u32 } = null,
    /// The client sent close_notify or a fatal alert first.
    closed: bool = false,
    finished: bool = false,
    app: std.ArrayList(u8) = .empty,
    ku_requested: u32 = 0,
    /// Rejected 0-RTT data the server will still skip.
    early_left: usize = early_budget,

    fn live(e: *const Expect) bool {
        return e.fault == null and !e.closed;
    }

    /// `line`: where the script sent it, for failure reports.
    fn fail(e: *Expect, line: u32, alert: ?Description) void {
        if (e.live()) e.fault = .{ .alert = alert, .line = line };
    }
};

// -- One run of the server ----------------------------------------------------

const Result = struct {
    wire: std.ArrayList(u8) = .empty,
    plain: std.ArrayList(u8) = .empty,
    failed: bool = false,
    peer_closed: bool = false,
    established: bool = false,
    alpn: ?[]const u8 = null,

    fn deinit(r: *Result) void {
        r.wire.deinit(testing.allocator);
        r.plain.deinit(testing.allocator);
    }

    fn expectEqual(r: *const Result, other: *const Result, what: []const u8) !void {
        if (!std.mem.eql(u8, r.wire.items, other.wire.items) or !std.mem.eql(u8, r.plain.items, other.plain.items) or
            r.failed != other.failed or r.peer_closed != other.peer_closed or r.established != other.established or
            !std.mem.eql(u8, r.alpn orelse "", other.alpn orelse ""))
        {
            std.debug.print("{s} changed the output: wire {d} vs {d} bytes, plain {d} vs {d}, failed {} vs {}, closed {} vs {}\n", .{
                what,     r.wire.items.len, other.wire.items.len, r.plain.items.len, other.plain.items.len,
                r.failed, other.failed,     r.peer_closed,        other.peer_closed,
            });
            return error.SplitChangedOutput;
        }
    }
};

const Run = struct {
    conn: Conn,
    result: Result = .{},
    plain_buf_len: usize,

    fn init(pools: *conn_mod.Pools, config: *const conn_mod.Config, plain_buf_len: usize) !Run {
        return .{ .conn = try Conn.init(testing.allocator, pools, config, &conn_mod.testEntropy(5)), .plain_buf_len = plain_buf_len };
    }

    fn deinit(r: *Run) void {
        r.conn.deinit();
        r.result.deinit();
    }

    fn stopped(r: *const Run) bool {
        return r.conn.failed or r.conn.peer_closed;
    }

    /// Feeds bytes as reads of the given sizes (cycled), or as large reads
    /// as fit. Stops at failure or close, like the worker does.
    fn feed(r: *Run, bytes: []const u8, read_sizes: []const u16) !void {
        var rest = bytes;
        var i: usize = 0;
        while (rest.len > 0 and !r.stopped()) {
            const space = try r.conn.readSpace();
            if (space.len == 0) return error.NoReadSpace;
            var n = @min(space.len, rest.len);
            if (read_sizes.len > 0) n = @min(n, @max(1, read_sizes[i % read_sizes.len]));
            i += 1;
            @memcpy(space[0..n], rest[0..n]);
            r.conn.commitRead(n);
            rest = rest[n..];
            try r.drain();
        }
    }

    fn drain(r: *Run) !void {
        var buf: [record.max_plaintext]u8 = undefined;
        while (true) {
            const k = r.conn.readPlain(buf[0..r.plain_buf_len]);
            if (k == 0) break;
            if (r.conn.hs != null) return error.PlaintextBeforeHandshake;
            try r.result.plain.appendSlice(testing.allocator, buf[0..k]);
        }
        if (r.conn.failed and r.conn.hasBufferedInput()) return error.InputAfterFailure;
        const w = r.conn.wireBytes();
        try r.result.wire.appendSlice(testing.allocator, w);
        r.conn.advance(w.len);
        r.conn.releaseIfIdle();
    }

    fn finish(r: *Run) Result {
        r.result.failed = r.conn.failed;
        r.result.peer_closed = r.conn.peer_closed;
        r.result.established = r.conn.isEstablished();
        r.result.alpn = r.conn.alpn;
        const res = r.result;
        r.result = .{};
        return res;
    }
};

/// Every server output is a sequence of records; a failure, and only a
/// failure, ends it with a fatal alert.
fn checkStructure(res: *const Result) !void {
    var pos: usize = 0;
    var last_alert = false;
    var alerts: usize = 0;
    const w = res.wire.items;
    while (pos < w.len) {
        if (w.len - pos < record.header_len) return error.PartialServerRecord;
        const len = std.mem.readInt(u16, w[pos + 3 ..][0..2], .big);
        if (w.len - pos - record.header_len < len) return error.PartialServerRecord;
        const body = w[pos + record.header_len ..][0..len];
        last_alert = switch (w[pos]) {
            ct_alert => len == 2 and body[0] == 2,
            ct_app => len == 2 + 1 + record.tag_len,
            ct_handshake, ct_ccs => false,
            else => return error.BadServerRecordType,
        };
        if (last_alert) alerts += 1;
        pos += record.header_len + len;
    }
    if (res.failed and !last_alert) return error.FailureWithoutAlert;
    // No close() in the harness, so no close_notify either.
    if (!res.failed and alerts > 0 and res.established) return error.AlertWithoutFailure;
    if (!res.failed and w.len > 0 and w[0] == ct_alert) return error.AlertWithoutFailure;
}

// -- The fuzz target ----------------------------------------------------------

const Script = struct {
    a: Allocator,
    recs: std.ArrayList(Rec) = .empty,
    stream: std.ArrayList(u8) = .empty,
    ser: Serializer,
    probe: *Run,
    view: *View,

    fn send(s: *Script, rec: Rec) !void {
        if (trace) std.debug.print("send {s} ct {d} epoch {d} len {d} pad {d} -> state {s} failed {} alert {any}\n", .{ @tagName(rec.kind), rec.ct, rec.epoch, rec.data.len, rec.padding, @tagName(s.view.state), s.probe.conn.failed, s.view.alert });
        try s.recs.append(s.a, rec);
        const start = s.stream.items.len;
        try s.ser.write(s.a, &s.stream, rec, false);
        try s.probe.feed(s.stream.items[start..], &.{});
        try s.view.pump(s.probe.result.wire.items);
    }
};

fn fragSizes(a: Allocator, smith: *Smith) ![]const u16 {
    if (smith.boolWeighted(1, 1)) return &.{};
    const sizes = try a.alloc(u16, smith.valueRangeAtMost(u8, 1, 4));
    for (sizes) |*s| s.* = if (smith.boolWeighted(3, 1)) smith.valueRangeAtMost(u16, 1, 64) else smith.valueRangeAtMost(u16, 1, 4096);
    return sizes;
}

fn appBytes(a: Allocator, len: usize, seed: usize) ![]u8 {
    const b = try a.alloc(u8, len);
    for (b, 0..) |*x, i| x.* = @truncate((seed + i) *% 131 +% 7);
    return b;
}

fn fuzzOne(_: void, smith: *Smith) anyerror!void {
    const fx = try fixtures();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Mode 0 replays the recording (often under the configuration it was
    // recorded with); the others script a client.
    const scripted = smith.valueRangeAtMost(u8, 0, 7) != 0;
    const as_recorded = !scripted and smith.boolWeighted(1, 1);

    // Server configuration.
    const all_suites = [_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 };
    const all_groups = [_]tls.NamedGroup{ .x25519_ml_kem768, .x25519, .secp256r1 };
    const alpn_choices = [_][]const []const u8{ &.{}, &.{"http/1.1"}, &.{ "h2", "http/1.1" }, &.{"x"} };
    var suites_buf: [3]Suite = undefined;
    var groups_buf: [3]tls.NamedGroup = undefined;
    const n_suites = if (as_recorded) 0 else smith.valueRangeAtMost(u8, 0, 3);
    const n_groups = if (as_recorded) 0 else smith.valueRangeAtMost(u8, 0, 3);
    for (suites_buf[0..n_suites]) |*s| s.* = all_suites[smith.index(3)];
    for (groups_buf[0..n_groups]) |*g| g.* = all_groups[smith.index(3)];
    const creds = &fx.creds[if (as_recorded) 0 else smith.valueRangeAtMost(u8, 0, 2)];
    const config: conn_mod.Config = .{
        .credentials = creds,
        .suites = if (n_suites == 0) handshake.default_suites else suites_buf[0..n_suites],
        .groups = if (n_groups == 0) &all_groups else groups_buf[0..n_groups],
        .alpn = alpn_choices[if (as_recorded) 1 else smith.valueRangeAtMost(u8, 0, 3)],
    };

    var pools = try conn_mod.Pools.init(testing.allocator, 2);
    defer pools.deinit();

    var probe = try Run.init(&pools, &config, record.max_plaintext);
    defer probe.deinit();
    var view: View = .{ .fx = fx, .a = a };
    var exp: Expect = .{};
    var script: Script = .{ .a = a, .ser = .{ .keys = &view.keys }, .probe = &probe, .view = &view };

    var hello = try Hello.parse(a, fx.hello);
    if (scripted) {
        try substituteShares(a, fx, &hello);
        // std's client sends a share for every group it offers, so ask for
        // a HelloRetryRequest often: no shares, or one for a random group.
        switch (smith.valueRangeAtMost(u8, 0, 3)) {
            2 => try hello.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{})),
            3 => {
                const g = pickGroup(smith);
                try hello.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = fx.share(g).? }}));
            },
            else => {},
        }
        // Offer 0-RTT (rejected) in a quarter of the scripts.
        if (smith.boolWeighted(3, 1)) try hello.setExt(a, ext_early_data, "");
    }
    var mres: MutationResult = .{};
    try mutateHello(a, smith, fx, &hello, &mres, smith.valueRangeAtMost(u8, 0, if (scripted) 3 else 6));
    const ch1 = try hello.encode(a);
    try view.sentHello(ch1);
    try script.send(.{ .kind = .plain, .ct = ct_handshake, .data = ch1, .legacy_version = 0x0301, .frags = if (mres.framed) try fragSizes(a, smith) else &.{} });

    // The scheme our certificate signs with must be on offer, or the
    // handshake can't complete whatever else the client does.
    const scheme_ok = if (hello.ext(ext_signature_algorithms)) |b| b.len >= 2 and listHas(b[2..], @backingInt(creds.key.scheme())) else false;
    if (mres.benign and scheme_ok and view.alert != null) return error.ValidHelloRejected;

    if (!scripted) {
        // The rest of the recorded session, as it was sent.
        try script.send(.{ .kind = .raw, .data = fx.session[5 + fx.hello.len ..] });
    } else {
        try runScript(a, smith, fx, &script, &view, &exp, &hello, &mres, scheme_ok);
    }

    // Validate everything the server sent, then compare other splits.
    try view.pump(probe.result.wire.items);
    var ref = probe.finish();
    defer ref.deinit();
    try checkStructure(&ref);
    if (as_recorded and std.mem.eql(u8, ch1, fx.hello)) {
        // The unmodified recording: a complete, valid session.
        if (ref.failed or !ref.peer_closed or !std.mem.eql(u8, ref.plain.items, recorded_request)) return error.RecordedSessionFailed;
    }
    if (exp.exact) try checkExpect(&exp, &ref, &view);

    // The same bytes in different reads.
    var read_sizes: [8]u16 = undefined;
    const n_sizes = smith.valueRangeAtMost(u8, 1, read_sizes.len);
    for (read_sizes[0..n_sizes]) |*s| s.* = if (smith.boolWeighted(1, 1)) smith.valueRangeAtMost(u16, 1, 32) else smith.valueRangeAtMost(u16, 1, 20000);
    {
        var run = try Run.init(&pools, &config, smith.valueRangeAtMost(u16, 1, record.max_plaintext));
        defer run.deinit();
        try run.feed(script.stream.items, read_sizes[0..n_sizes]);
        var res = run.finish();
        defer res.deinit();
        try ref.expectEqual(&res, "read split");
    }
    // Different record boundaries inside handshake messages and
    // application data, delivered a byte at a time.
    {
        var frag_stream: std.ArrayList(u8) = .empty;
        var ser: Serializer = .{ .keys = &view.keys };
        for (script.recs.items) |rec| try ser.write(a, &frag_stream, rec, true);
        var run = try Run.init(&pools, &config, 1 + smith.valueRangeAtMost(u16, 0, 15));
        defer run.deinit();
        try run.feed(frag_stream.items, &.{1});
        var res = run.finish();
        defer res.deinit();
        try ref.expectEqual(&res, "record boundaries");
    }
}

fn checkExpect(exp: *const Expect, res: *const Result, view: *const View) !void {
    errdefer std.debug.print("expected: fault {any} closed {any} finished {any} app {d} ku {d}; got: failed {any} closed {any} established {any} plain {d} ku {d} alert {any}\n", .{
        exp.fault,  exp.closed,      exp.finished,    exp.app.items.len,   exp.ku_requested,
        res.failed, res.peer_closed, res.established, res.plain.items.len, view.ku_received,
        view.alert,
    });
    if (exp.fault) |f| {
        if (!res.failed) return error.FaultAccepted;
        const alert = view.alert orelse return error.FailureWithoutAlert;
        if (alert[0] != 2) return error.AlertNotFatal;
        if (f.alert) |d| if (alert[1] != @backingInt(d)) return error.WrongAlert;
    } else if (exp.closed) {
        if (res.failed or !res.peer_closed) return error.CloseNotHonoured;
    } else {
        if (res.failed or res.peer_closed) return error.ValidScriptFailed;
        if (res.established != exp.finished) return error.WrongHandshakeState;
    }
    if (!std.mem.eql(u8, res.plain.items, exp.app.items)) return error.PlaintextMismatch;
    if (view.ku_received != exp.ku_requested) return error.KeyUpdateMismatch;
}

/// After the first ClientHello: answer a HelloRetryRequest, then send the
/// Finished and a script of records, tracking what the server must do.
fn runScript(
    a: Allocator,
    smith: *Smith,
    fx: *const Fixtures,
    s: *Script,
    view: *View,
    exp: *Expect,
    hello: *Hello,
    mres: *MutationResult,
    scheme_ok: bool,
) !void {
    // Early data straight after ClientHello1: skipped if 0-RTT was offered
    // (rejected, §4.2.10), whether or not a HelloRetryRequest follows.
    const offered_early = view.hello != null and view.hello.?.find(ext_early_data) != null;
    var early_records: u8 = 0;
    if (smith.boolWeighted(3, 1)) early_records = smith.valueRangeAtMost(u8, 1, 3);

    if (view.state == .hrr) {
        if (smith.boolWeighted(1, 1)) try s.send(.{ .kind = .plain, .ct = ct_ccs, .data = "\x01" });
        for (0..early_records) |_| try sendEarly(a, smith, s, exp, offered_early, true);
        var h2 = hello.*;
        h2.exts = try hello.exts.clone(a);
        // ClientHello2 drops early_data (§4.1.2).
        if (h2.find(ext_early_data)) |i| _ = h2.exts.orderedRemove(i);
        const g = view.hrr_group.?;
        var retry_fault: ?Description = null;
        switch (smith.valueRangeAtMost(u8, 0, 11)) {
            0...5 => try h2.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = fx.share(g) orelse "" }})),
            6 => retry_fault = .illegal_parameter, // the same shares again
            7 => {
                const other: u16 = if (g == group_x25519) group_p256 else group_x25519;
                try h2.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{ .{ .group = g, .kx = fx.share(g).? }, .{ .group = other, .kx = fx.share(other).? } }));
                retry_fault = .illegal_parameter;
            },
            8 => {
                try h2.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = fx.share(g).? }}));
                const sid = try a.dupe(u8, if (h2.session_id.len > 0) h2.session_id else "x");
                sid[0] ^= 1;
                h2.session_id = sid;
                retry_fault = .illegal_parameter;
            },
            9 => {
                try h2.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = fx.share(g).? }}));
                try h2.setExt(a, ext_early_data, "");
                retry_fault = .illegal_parameter;
            },
            10 => {
                try h2.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = fx.share(g).? }}));
                // Drop the suite the server chose.
                var list: std.ArrayList(u8) = .empty;
                var i: usize = 0;
                while (i + 2 <= h2.suites.len) : (i += 2) {
                    if (std.mem.readInt(u16, h2.suites[i..][0..2], .big) != @backingInt(view.suite.?)) try list.appendSlice(a, h2.suites[i..][0..2]);
                }
                if (list.items.len == 0) try list.appendSlice(a, "\x13\x99");
                h2.suites = list.items;
                retry_fault = .illegal_parameter;
            },
            else => {
                try h2.setExt(a, ext_key_share, try Hello.sharesBody(a, &.{.{ .group = g, .kx = fx.share(g).? }}));
                var r2: MutationResult = .{};
                try mutateHello(a, smith, fx, &h2, &r2, 1);
                // After a HelloRetryRequest the only valid share list is the
                // one requested.
                var list: [2]KeyShare = undefined;
                const n = h2.shares(&list);
                const requested = n == 1 and list[0].group == g and std.mem.eql(u8, list[0].kx, fx.share(g).?);
                if (!r2.benign or r2.early_data or !requested) mres.benign = false;
                if (!r2.framed) mres.framed = false;
            },
        }
        if (retry_fault) |d| {
            mres.benign = false;
            exp.fail(@src().line, d);
        }
        const ch2 = try h2.encode(a);
        try view.sentHello(ch2);
        hello.* = h2;
        try s.send(.{ .kind = .plain, .ct = ct_handshake, .data = ch2, .frags = if (mres.framed) try fragSizes(a, smith) else &.{} });
        if (trace) std.debug.print("retry for group {x}: alert {any}\n", .{ g, view.alert });
        if (mres.benign and scheme_ok and exp.live() and view.alert != null) return error.ValidHelloRejected;
    } else if (view.state == .connected) {
        for (0..early_records) |_| try sendEarly(a, smith, s, exp, offered_early, false);
    }

    if (view.state != .connected) {
        if (view.state == .flight) return error.FlightIncomplete;
        // A fault so far must have been answered with its alert.
        if (exp.fault) |f| {
            errdefer std.debug.print("pre-handshake fault {any}, state {s}, alert {any}\n", .{ f, @tagName(view.state), view.alert });
            const alert = view.alert orelse return error.FaultAccepted;
            if (f.alert) |d| if (alert[1] != @backingInt(d)) return error.WrongAlert;
        }
        // Otherwise rejected, or keys unknown: a little more input,
        // structural checks only.
        if (smith.boolWeighted(1, 1)) try s.send(.{ .kind = .raw, .data = try randomBytes(a, smith, 64) });
        return;
    }
    exp.exact = mres.framed;

    // Before Finished.
    var hs_decrypted = false;
    var ops: u8 = smith.valueRangeAtMost(u8, 0, 3);
    while (ops > 0) : (ops -= 1) {
        switch (smith.valueRangeAtMost(u8, 0, 5)) {
            0 => try s.send(.{ .kind = .plain, .ct = ct_ccs, .data = "\x01" }),
            1 => {
                try s.send(.{ .kind = .plain, .ct = ct_ccs, .data = if (smith.boolWeighted(1, 1)) "\x02" else "\x01\x01" });
                exp.fail(@src().line, .unexpected_message);
            },
            // After a HelloRetryRequest, early data ended with ClientHello2.
            2 => try sendEarly(a, smith, s, exp, offered_early and view.hrr_group == null and !hs_decrypted, false),
            3 => {
                const desc = smith.value(u8);
                try s.send(.{ .kind = .plain, .ct = ct_alert, .data = try a.dupe(u8, &.{ smith.valueRangeAtMost(u8, 1, 2), desc }) });
                if (desc != @backingInt(Description.user_canceled) and exp.live()) exp.closed = true;
            },
            4 => {
                try s.send(.{ .kind = .sealed, .ct = ct_app, .epoch = 0, .data = "early?" });
                hs_decrypted = true;
                exp.fail(@src().line, .unexpected_message);
            },
            else => {
                // A handshake message other than Finished.
                try s.send(.{ .kind = .sealed, .ct = ct_handshake, .epoch = 0, .data = &.{ 11, 0, 0, 4, 0, 0, 0, 0 } });
                hs_decrypted = true;
                exp.fail(@src().line, .unexpected_message);
            },
        }
    }

    // Finished.
    const fin = view.client_finished.?;
    var finished = true;
    switch (smith.valueRangeAtMost(u8, 0, 11)) {
        0...6 => try s.send(.{ .kind = .sealed, .ct = ct_handshake, .data = fin, .frags = try fragSizes(a, smith) }),
        7 => {
            const bad = try a.dupe(u8, fin);
            bad[4 + smith.index(fin.len - 4)] ^= 1;
            try s.send(.{ .kind = .sealed, .ct = ct_handshake, .data = bad, .frags = try fragSizes(a, smith) });
            exp.fail(@src().line, .decrypt_error);
            finished = false;
        },
        8 => {
            const bad = try a.alloc(u8, fin.len + 1);
            @memcpy(bad[0..fin.len], fin);
            bad[fin.len] = 0;
            bad[3] += 1;
            try s.send(.{ .kind = .sealed, .ct = ct_handshake, .data = bad });
            exp.fail(@src().line, .decode_error);
            finished = false;
        },
        9 => {
            const both = try a.alloc(u8, fin.len + 5);
            @memcpy(both[0..fin.len], fin);
            @memcpy(both[fin.len..], &[_]u8{ 24, 0, 0, 1, 0 });
            try s.send(.{ .kind = .sealed, .ct = ct_handshake, .data = both });
            exp.fail(@src().line, .unexpected_message);
            finished = false;
        },
        10 => {
            try s.send(.{ .kind = .plain, .ct = ct_handshake, .data = fin });
            exp.fail(@src().line, .unexpected_message);
            finished = false;
        },
        else => {
            // No Finished: what follows is under keys the server doesn't
            // have yet, so the model gives up.
            exp.exact = false;
            finished = false;
        },
    }
    if (finished and exp.live()) exp.finished = true;

    // Application phase.
    var epoch: u32 = 1;
    var seed: usize = 0;
    for (0..smith.valueRangeAtMost(u8, 0, 24)) |_| {
        switch (smith.valueRangeAtMost(u8, 0, 21)) {
            0...5, 19 => {
                const len: usize = switch (smith.valueRangeAtMost(u8, 0, 9)) {
                    0...6 => smith.valueRangeAtMost(u16, 0, 64),
                    7, 8 => smith.valueRangeAtMost(u16, 65, 2000),
                    else => smith.valueRangeAtMost(u16, 2001, record.max_plaintext),
                };
                const data = try appBytes(a, len, seed);
                seed += len;
                // Padding up to the 2^14 + 1 inner plaintext limit.
                const pad_max: u16 = @intCast(record.max_plaintext - len);
                const padding = if (smith.boolWeighted(3, 1)) 0 else smith.valueRangeAtMost(u16, 0, pad_max);
                try s.send(.{ .kind = .sealed, .ct = ct_app, .epoch = epoch, .data = data, .padding = padding, .frags = if (padding == 0) try fragSizes(a, smith) else &.{} });
                if (exp.live()) try exp.app.appendSlice(a, data);
            },
            6, 7 => {
                const requested = smith.boolWeighted(1, 1);
                try s.send(.{ .kind = .sealed, .ct = ct_handshake, .epoch = epoch, .data = if (requested) &.{ 24, 0, 0, 1, 1 } else &.{ 24, 0, 0, 1, 0 } });
                epoch += 1;
                if (requested and exp.live()) exp.ku_requested += 1;
            },
            8 => {
                try s.send(.{ .kind = .sealed, .ct = ct_handshake, .epoch = epoch, .data = try a.dupe(u8, &.{ 24, 0, 0, 1, smith.valueRangeAtMost(u8, 2, 255) }) });
                exp.fail(@src().line, .illegal_parameter);
            },
            9 => {
                // KeyUpdate with a bad length, or not ending its record.
                const v = smith.valueRangeAtMost(u8, 0, 2);
                const data: []const u8 = switch (v) {
                    0 => &.{ 24, 0, 0, 2, 0, 0 },
                    1 => &.{ 24, 0, 0, 0 },
                    else => &.{ 24, 0, 0, 1, 0, 24, 0, 0, 1, 0 },
                };
                try s.send(.{ .kind = .sealed, .ct = ct_handshake, .epoch = epoch, .data = data });
                exp.fail(@src().line, if (v == 2) .unexpected_message else null);
            },
            10 => {
                // Post-handshake messages a server never accepts.
                const types = [_]u8{ 4, 13, 1, 20, 2, 8 };
                try s.send(.{ .kind = .sealed, .ct = ct_handshake, .epoch = epoch, .data = try a.dupe(u8, &.{ types[smith.index(types.len)], 0, 0, 0 }) });
                exp.fail(@src().line, .unexpected_message);
            },
            11 => {
                const desc: u8 = switch (smith.valueRangeAtMost(u8, 0, 3)) {
                    0 => 0, // close_notify
                    1 => 90, // user_canceled
                    else => smith.value(u8),
                };
                try s.send(.{ .kind = .sealed, .ct = ct_alert, .epoch = epoch, .data = try a.dupe(u8, &.{ smith.valueRangeAtMost(u8, 1, 2), desc }) });
                if (desc != 90 and exp.live()) exp.closed = true;
            },
            12 => {
                try s.send(.{ .kind = .sealed, .ct = ct_alert, .epoch = epoch, .data = if (smith.boolWeighted(1, 1)) "\x01" else "\x01\x00\x00" });
                exp.fail(@src().line, .decode_error);
            },
            13 => {
                // change_cipher_spec, or plaintext handshake, after the handshake.
                if (smith.boolWeighted(1, 1)) {
                    try s.send(.{ .kind = .plain, .ct = ct_ccs, .data = "\x01" });
                } else {
                    try s.send(.{ .kind = .plain, .ct = ct_handshake, .data = &.{ 24, 0, 0, 1, 0 } });
                }
                exp.fail(@src().line, .unexpected_message);
            },
            14 => {
                try s.send(.{ .kind = .sealed, .ct = ct_app, .epoch = epoch, .data = "corrupt", .corrupt = true });
                exp.fail(@src().line, .bad_record_mac);
            },
            15 => {
                // Inner plaintext with no content type, or an unknown one,
                // or an empty handshake fragment.
                const inner: []const u8 = switch (smith.valueRangeAtMost(u8, 0, 2)) {
                    0 => blk: {
                        const zeros = try a.alloc(u8, smith.valueRangeAtMost(u16, 0, 32));
                        @memset(zeros, 0);
                        break :blk zeros;
                    },
                    1 => try a.dupe(u8, &.{ 'x', smith.valueRangeAtMost(u8, 24, 255) }),
                    else => &.{ct_handshake},
                };
                try s.send(.{ .kind = .sealed, .epoch = epoch, .data = "", .inner = inner });
                exp.fail(@src().line, .unexpected_message);
            },
            16 => {
                // Inner plaintext over 2^14 + 1 bytes: too much content,
                // or padding (§5.2, §5.4).
                const extra = smith.valueRangeAtMost(u16, 1, record.max_ciphertext - record.tag_len - record.max_plaintext - 1);
                const inner = try a.alloc(u8, record.max_plaintext + 1 + extra);
                @memset(inner, 0);
                const content: usize = if (smith.boolWeighted(1, 1)) record.max_plaintext + extra else smith.valueRangeAtMost(u16, 0, record.max_plaintext);
                for (inner[0..content], 0..) |*b, i| b.* = @truncate(i | 1);
                inner[content] = ct_app;
                try s.send(.{ .kind = .sealed, .epoch = epoch, .data = "", .inner = inner });
                exp.fail(@src().line, .record_overflow);
            },
            17 => {
                // A record header claiming more than 2^14 + 256 bytes.
                var hdr: [5]u8 = .{ ct_app, 3, 3, 0, 0 };
                std.mem.writeInt(u16, hdr[3..5], smith.valueRangeAtMost(u16, record.max_ciphertext + 1, 0xffff), .big);
                try s.send(.{ .kind = .raw, .data = try a.dupe(u8, &hdr) });
                exp.fail(@src().line, .record_overflow);
            },
            18 => {
                try s.send(.{ .kind = .sealed, .ct = ct_app, .epoch = epoch, .data = "" });
            },
            20 => {
                // Garbage that starts with a byte that is no record type.
                const junk = try a.alloc(u8, smith.valueRangeAtMost(u16, 5, 64));
                fill(smith, junk);
                if (junk[0] >= ct_ccs and junk[0] <= ct_app) junk[0] = 0;
                try s.send(.{ .kind = .raw, .data = junk });
                exp.fail(@src().line, .unexpected_message);
            },
            else => {
                // Records under a key the server doesn't have yet (one
                // KeyUpdate ahead) or no longer has.
                try s.send(.{ .kind = .sealed, .ct = ct_app, .epoch = epoch + 1, .data = "ahead" });
                exp.fail(@src().line, .bad_record_mac);
                epoch += 1;
            },
        }
        if (s.probe.stopped()) {
            if (smith.boolWeighted(3, 1)) break;
        }
    }
}

/// An undecryptable 0-RTT record. Skipped while the server may still be
/// receiving rejected early data, a fault otherwise.
fn sendEarly(a: Allocator, smith: *Smith, s: *Script, exp: *Expect, skippable: bool, before_keys: bool) !void {
    const len = smith.valueRangeAtMost(u16, 1, 300);
    const rec = try a.alloc(u8, 5 + len);
    rec[0..5].* = .{ ct_app, 3, 3, 0, 0 };
    std.mem.writeInt(u16, rec[3..5], len, .big);
    fill(smith, rec[5..]);
    try s.send(.{ .kind = .raw, .data = rec });
    if (skippable and exp.early_left >= len) {
        exp.early_left -= len;
    } else {
        exp.fail(@src().line, if (before_keys) .unexpected_message else .bad_record_mac);
    }
}

/// Prints the script as it runs; set it while replaying a crash input
/// (add the file to `corpus` and run `zig build test`).
var trace = false;

/// Inputs that once failed, replayed by every `zig build test`. Saved by
/// the fuzzer as .zig-cache/f/crash.
const corpus = [_][]const u8{
    // Harness: a ClientHello2 mutation dropped the requested key share.
    @embedFile("testdata/fuzz/hrr-1.bin"),
};

test "fuzz: tls.Conn handshake and record mutations" {
    try std.testing.fuzz({}, fuzzOne, .{ .corpus = &corpus });
}

test "tls fuzz harness over pseudo-random inputs" {
    // The harness with inputs from a PRNG, so a plain `zig build test`
    // exercises every script path too.
    var prng = std.Random.DefaultPrng.init(0x7115);
    const random = prng.random();
    var input: [256]u64 = undefined;
    for (0..64) |i| {
        // Mostly small values: they land inside most ranges asked for
        // (anything outside one reads as its minimum).
        for (&input) |*v| v.* = std.mem.nativeToLittle(u64, switch (random.uintLessThan(u8, 20)) {
            0...7 => random.uintLessThan(u64, 2),
            8...13 => random.uintLessThan(u64, 8),
            14...16 => random.uintLessThan(u64, 32),
            17, 18 => random.uintLessThan(u64, 1024),
            else => random.int(u16),
        });
        var smith: Smith = .{ .in = std.mem.sliceAsBytes(&input) };
        fuzzOne({}, &smith) catch |err| {
            std.debug.print("input {d} failed: {s}\n", .{ i, @errorName(err) });
            return err;
        };
    }
}
