//! Session tickets (RFC 8446 §4.6.1): the server keeps no session cache.
//! A ticket is the resumption state (suite, PSK, issue time, age offset)
//! sealed with AES-256-GCM under a key only the server has, so any
//! worker, or any server sharing the master key, can resume it.
//!
//! Keys rotate: the key for a period of `lifetime_s` is derived from the
//! master key and the period's number, and a ticket sealed in the current
//! or previous period is accepted (if it is younger than `lifetime_s`).
//! Whoever holds the master key can open every ticket, so for forward
//! secrecy of resumed sessions keep it in memory only (the default: random
//! per process).
//!
//! 0-RTT (RFC 8446 §4.2.10, §8): a ticket issued with early data on
//! carries the issuing process's `instance`, and early data is accepted
//! only by that process, whose `ReplayGuard` admits each ClientHello once.
//! Servers sharing a master key resume each other's tickets, but only
//! with a full round trip.
const std = @import("std");
const sys = @import("../sys.zig");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const max_psk_len = 48;
/// The largest ticket `seal` makes.
pub const max_len = header_len + plain_max + Aes256Gcm.tag_length;

const version: u8 = 2;
const header_len = 1 + 8 + Aes256Gcm.nonce_length;
const plain_fixed = 2 + 8 + 4 + 1 + 1 + 1 + 8 + 1;
const plain_max = plain_fixed + max_psk_len;

pub const State = struct {
    /// The cipher suite of the session; resumption needs one with the
    /// same hash.
    suite: u16,
    /// Seconds (realtime).
    issued: i64,
    /// The client adds this to the ticket age it reports.
    age_add: u32,
    /// Issued over QUIC: used only there (and a TCP ticket only on TCP).
    quic: bool,
    /// 0-RTT allowed: by the process `instance` names, with the ALPN
    /// protocol `alpn` (an index into the server's list, plus one; 0 for
    /// none).
    early: bool = false,
    instance: u64 = 0,
    alpn: u8 = 0,
    psk_len: u8,
    psk: [max_psk_len]u8,

    pub fn pskSlice(self: *const State) []const u8 {
        return self.psk[0..self.psk_len];
    }
};

pub const Keys = struct {
    master: [32]u8,
    /// Ticket lifetime, sent to clients, and the key rotation period.
    /// At most 7 days (RFC 8446 §4.6.1).
    lifetime_s: u32 = 24 * 3600,
    /// The clock (tests set a fixed one).
    now: *const fn () i64 = sys.realtimeSeconds,
    /// This process, in tickets that allow 0-RTT (random per process).
    instance: u64 = 0,

    pub fn init(master: [32]u8) Keys {
        return .{ .master = master };
    }

    /// A master key from the OS.
    pub fn random() Keys {
        var master: [32]u8 = undefined;
        sys.randomBytes(&master);
        return init(master);
    }

    /// A random `instance`, so 0-RTT tickets from another process (or an
    /// earlier run of this one) aren't accepted with early data.
    pub fn newInstance(self: *Keys) void {
        var b: [8]u8 = undefined;
        sys.randomBytes(&b);
        self.instance = std.mem.readInt(u64, &b, .little);
    }

    fn period(self: *const Keys, t: i64) u64 {
        return @intCast(@divFloor(@max(t, 0), self.lifetime_s));
    }

    fn key(self: *const Keys, p: u64) [Aes256Gcm.key_length]u8 {
        var info: [24]u8 = undefined;
        @memcpy(info[0..16], "peregrine ticket");
        std.mem.writeInt(u64, info[16..24], p, .big);
        var out: [Aes256Gcm.key_length]u8 = undefined;
        HkdfSha256.expand(&out, &info, self.master);
        return out;
    }

    /// Seals `state` into `out` (at least `max_len` bytes).
    pub fn seal(self: *const Keys, state: *const State, nonce: [Aes256Gcm.nonce_length]u8, out: []u8) []const u8 {
        const p = self.period(state.issued);
        out[0] = version;
        std.mem.writeInt(u64, out[1..9], p, .big);
        out[9..header_len].* = nonce;
        var plain: [plain_max]u8 = undefined;
        std.mem.writeInt(u16, plain[0..2], state.suite, .big);
        std.mem.writeInt(i64, plain[2..10], state.issued, .big);
        std.mem.writeInt(u32, plain[10..14], state.age_add, .big);
        plain[14] = @intFromBool(state.quic);
        plain[15] = @intFromBool(state.early);
        std.mem.writeInt(u64, plain[16..24], state.instance, .big);
        plain[24] = state.alpn;
        plain[25] = state.psk_len;
        @memcpy(plain[plain_fixed..][0..state.psk_len], state.pskSlice());
        const len = plain_fixed + @as(usize, state.psk_len);
        defer std.crypto.secureZero(u8, &plain);
        var k = self.key(p);
        defer std.crypto.secureZero(u8, &k);
        const ct = out[header_len..][0..len];
        const tag = out[header_len + len ..][0..Aes256Gcm.tag_length];
        Aes256Gcm.encrypt(ct, tag, plain[0..len], out[0..header_len], nonce, k);
        return out[0 .. header_len + len + Aes256Gcm.tag_length];
    }

    /// The state in a ticket this server sealed and that is still valid;
    /// null for anything else (another server's ticket, an old key,
    /// tampering, expiry).
    pub fn open(self: *const Keys, ticket: []const u8) ?State {
        if (ticket.len < header_len + plain_fixed + Aes256Gcm.tag_length or ticket.len > max_len) return null;
        if (ticket[0] != version) return null;
        const p = std.mem.readInt(u64, ticket[1..9], .big);
        const now = self.now();
        const current = self.period(now);
        if (p != current and p + 1 != current) return null;
        const len = ticket.len - header_len - Aes256Gcm.tag_length;
        var plain: [plain_max]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain);
        var k = self.key(p);
        defer std.crypto.secureZero(u8, &k);
        Aes256Gcm.decrypt(
            plain[0..len],
            ticket[header_len..][0..len],
            ticket[ticket.len - Aes256Gcm.tag_length ..][0..Aes256Gcm.tag_length].*,
            ticket[0..header_len],
            ticket[9..header_len].*,
            k,
        ) catch return null;
        var state: State = .{
            .suite = std.mem.readInt(u16, plain[0..2], .big),
            .issued = std.mem.readInt(i64, plain[2..10], .big),
            .age_add = std.mem.readInt(u32, plain[10..14], .big),
            .quic = plain[14] == 1,
            .early = plain[15] == 1,
            .instance = std.mem.readInt(u64, plain[16..24], .big),
            .alpn = plain[24],
            .psk_len = plain[25],
            .psk = @splat(0),
        };
        if (state.psk_len != len - plain_fixed) return null;
        @memcpy(state.psk[0..state.psk_len], plain[plain_fixed..len]);
        if (state.issued > now or now - state.issued > self.lifetime_s) return null;
        return state;
    }
};

/// Admits each 0-RTT ClientHello once (RFC 8446 §8.2), by its first
/// binder: unique to the ClientHello and unpredictable without the PSK.
/// Shared by the workers of a process. A ClientHello is only acceptable
/// with early data within `max_age_skew_s` of the ticket age it claims, so
/// an entry is needed for twice that (plus the clock's resolution); after
/// that, a replay fails the age check. When the table is full, 0-RTT is
/// refused (the handshake goes on without it), never let through.
pub const ReplayGuard = struct {
    /// Probed slots per lookup.
    const probes = 8;
    /// How far the client's ticket age may differ from ours.
    pub const max_age_skew_s = 10;
    const keep_s = 2 * max_age_skew_s + 2;

    const Entry = struct {
        fingerprint: u128 = 0,
        /// Seconds (realtime); 0 for a free slot.
        expires: i64 = 0,
    };

    mutex: sys.Mutex = .{},
    entries: []Entry,
    allocator: std.mem.Allocator,

    /// `capacity` (a power of two) ClientHellos within `keep_s` seconds.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) !ReplayGuard {
        std.debug.assert(std.math.isPowerOfTwo(capacity) and capacity >= probes);
        const entries = try allocator.alloc(Entry, capacity);
        @memset(entries, .{});
        return .{ .entries = entries, .allocator = allocator };
    }

    pub fn deinit(self: *ReplayGuard) void {
        self.allocator.free(self.entries);
    }

    /// True the first time `binder` is seen (and remembered); false for a
    /// replay, or when there is no room to remember it.
    pub fn admit(self: *ReplayGuard, binder: []const u8, now: i64) bool {
        std.debug.assert(binder.len >= 16);
        const fp = std.mem.readInt(u128, binder[0..16], .little);
        const mask = self.entries.len - 1;
        const start: usize = @truncate(fp);
        self.mutex.lock();
        defer self.mutex.unlock();
        var free: ?*Entry = null;
        for (0..probes) |i| {
            const e = &self.entries[(start + i) & mask];
            if (e.expires <= now) {
                if (free == null) free = e;
            } else if (e.fingerprint == fp) {
                return false;
            }
        }
        const e = free orelse return false;
        e.* = .{ .fingerprint = fp, .expires = now + keep_s };
        return true;
    }
};

var test_now: i64 = 1_000_000;

fn testClock() i64 {
    return test_now;
}

test "ticket: seal, open, expiry, rotation, tampering, other keys" {
    const testing = std.testing;
    var keys = Keys.init(@splat(7));
    keys.now = testClock;
    keys.lifetime_s = 1000;
    test_now = 1_000_500;
    var state: State = .{ .suite = 0x1302, .issued = test_now, .age_add = 0xdeadbeef, .quic = true, .early = true, .instance = 0x0102030405060708, .alpn = 3, .psk_len = 48, .psk = undefined };
    for (&state.psk, 0..) |*b, i| b.* = @truncate(i);
    var buf: [max_len]u8 = undefined;
    const ticket = keys.seal(&state, @splat(3), &buf);
    const got = keys.open(ticket).?;
    try testing.expectEqual(state.suite, got.suite);
    try testing.expectEqual(state.issued, got.issued);
    try testing.expectEqual(state.age_add, got.age_add);
    try testing.expect(got.quic);
    try testing.expect(got.early);
    try testing.expectEqual(state.instance, got.instance);
    try testing.expectEqual(state.alpn, got.alpn);
    try testing.expectEqualSlices(u8, state.pskSlice(), got.pskSlice());
    // Still valid in the next period, until it is lifetime_s old.
    test_now = 1_001_400;
    try testing.expect(keys.open(ticket) != null);
    test_now = 1_001_501;
    try testing.expect(keys.open(ticket) == null);
    test_now = 1_000_500;
    // Tampering, truncation, another master key.
    for (0..ticket.len) |i| {
        var bad = buf;
        bad[i] ^= 0x40;
        try testing.expect(keys.open(bad[0..ticket.len]) == null);
    }
    try testing.expect(keys.open(ticket[0 .. ticket.len - 1]) == null);
    var other = keys;
    other.master[0] ^= 1;
    try testing.expect(other.open(ticket) == null);
}

test "replay guard: once each, forgotten after keep_s, refuses when full" {
    const testing = std.testing;
    var guard = try ReplayGuard.init(testing.allocator, 16);
    defer guard.deinit();
    var a: [32]u8 = @splat(1);
    try testing.expect(guard.admit(&a, 100));
    try testing.expect(!guard.admit(&a, 100));
    try testing.expect(!guard.admit(&a, 100 + ReplayGuard.keep_s - 1));
    // Long enough that the ticket age check refuses it anyway.
    try testing.expect(guard.admit(&a, 100 + ReplayGuard.keep_s));
    // Eight binders landing on the same slots fill them; a ninth is
    // refused until they expire.
    var binders: [9][32]u8 = undefined;
    for (&binders, 0..) |*b, i| {
        b.* = @splat(0);
        b[0] = 5; // the same start slot
        b[8] = @intCast(i + 1);
    }
    for (binders[0..8]) |*b| try testing.expect(guard.admit(b, 200));
    try testing.expect(!guard.admit(&binders[8], 200));
    try testing.expect(guard.admit(&binders[8], 200 + ReplayGuard.keep_s));
}
