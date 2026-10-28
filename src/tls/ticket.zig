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
const std = @import("std");
const sys = @import("../sys.zig");
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const max_psk_len = 48;
/// The largest ticket `seal` makes.
pub const max_len = header_len + plain_max + Aes256Gcm.tag_length;

const version: u8 = 1;
const header_len = 1 + 8 + Aes256Gcm.nonce_length;
const plain_max = 2 + 8 + 4 + 1 + 1 + max_psk_len;

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

    pub fn init(master: [32]u8) Keys {
        return .{ .master = master };
    }

    /// A master key from the OS.
    pub fn random() Keys {
        var master: [32]u8 = undefined;
        sys.randomBytes(&master);
        return init(master);
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
        plain[15] = state.psk_len;
        @memcpy(plain[16..][0..state.psk_len], state.pskSlice());
        const len = 16 + @as(usize, state.psk_len);
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
        if (ticket.len < header_len + 16 + Aes256Gcm.tag_length or ticket.len > max_len) return null;
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
            .psk_len = plain[15],
            .psk = @splat(0),
        };
        if (state.psk_len != len - 16) return null;
        @memcpy(state.psk[0..state.psk_len], plain[16..len]);
        if (state.issued > now or now - state.issued > self.lifetime_s) return null;
        return state;
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
    var state: State = .{ .suite = 0x1302, .issued = test_now, .age_add = 0xdeadbeef, .quic = true, .psk_len = 48, .psk = undefined };
    for (&state.psk, 0..) |*b, i| b.* = @truncate(i);
    var buf: [max_len]u8 = undefined;
    const ticket = keys.seal(&state, @splat(3), &buf);
    const got = keys.open(ticket).?;
    try testing.expectEqual(state.suite, got.suite);
    try testing.expectEqual(state.issued, got.issued);
    try testing.expectEqual(state.age_add, got.age_add);
    try testing.expect(got.quic);
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
