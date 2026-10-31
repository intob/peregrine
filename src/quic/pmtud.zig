//! Datagram Packetization Layer PMTU Discovery (RFC 8899, RFC 9000 §14.3)
//! for one path: which probe to send next, and what the acknowledgment
//! or loss of each probe, and of full-sized packets, says about the path.
//! I/O-free like the rest; conn.zig sends the probes (PING and PADDING,
//! one in flight at a time) and reports their fate, and the PLPMTU is
//! its maximum datagram size.
//!
//! States (RFC 8899 §5.2): `disabled` until the handshake is confirmed
//! (§14.3.1: QUIC is an acknowledged PL, and the handshake has confirmed
//! BASE_PLPMTU, 1200 bytes, the client's Initials being at least that),
//! then `searching`, then `complete`. Searching sends the ceiling first
//! (most paths carry a full Ethernet frame, so one probe usually ends the
//! search), then halves the range between the PLPMTU and the largest
//! size not known to fail, until it is under `min_step`. A size fails
//! when `max_probes` probes of it in a row are lost, or at once when the
//! local interface refuses it (EMSGSIZE). After `raise_interval_us` in
//! `complete` below the ceiling, the search runs again (PMTU_RAISE_TIMER).
//!
//! Black holes (§4.3, the third indicator: loss of data sent at one
//! size): full-sized packets (the PLPMTU's size) lost `black_hole_packets`
//! times in a row over at least a probe timeout, with none of that size
//! acknowledged since, while smaller ones sent after the first of them
//! are acknowledged and none of BASE_PLPMTU's size or less is lost (an
//! outage loses both). The PLPMTU goes back to BASE_PLPMTU at once, and
//! the search runs again from the size that failed: probed first, as a
//! confirmation (an outage that looked like a black hole costs one probe,
//! not 600 s below the size), then bisected below it. (conn.zig sends its
//! probe timeouts' packets at BASE_PLPMTU after two in a row, so a bulk
//! sender whose every packet is full-sized still has small ones
//! acknowledged.) A datagram the local interface refuses (EMSGSIZE) takes
//! the PLPMTU to BASE_PLPMTU and the ceiling below its size at once.
const std = @import("std");

/// BASE_PLPMTU and MIN_PLPMTU (RFC 9000 §14.3): QUIC's smallest maximum
/// datagram size.
pub const base: u16 = 1200;
/// MAX_PROBES (RFC 8899 §5.1.2).
pub const max_probes = 3;
/// PMTU_RAISE_TIMER (RFC 8899 §5.1.1).
pub const raise_interval_us: u64 = 600 * std.time.us_per_s;
/// The search ends when the range left is smaller than this (§5.3.2: not
/// every size is worth a probe).
pub const min_step: u16 = 16;
/// Full-sized packets lost in a row before a black hole is suspected.
pub const black_hole_packets = 3;

/// UDP and IP headers: what a datagram of an MTU-sized IP packet loses.
pub const ipv4_overhead: u16 = 20 + 8;
pub const ipv6_overhead: u16 = 40 + 8;

pub const State = enum(u8) { disabled, searching, complete };

pub const Search = struct {
    const Self = @This();

    state: State = .disabled,
    /// The PLPMTU: the maximum datagram size in use.
    current: u16,
    /// MAX_PLPMTU: the configured ceiling, the peer's max_udp_payload_size
    /// and what the local interface took.
    ceiling: u16,
    /// Below the smallest size the local interface refused (EMSGSIZE): our
    /// route's limit, which a new peer port on the same address keeps.
    local_max: u16 = std.math.maxInt(u16),
    /// The largest size not known to fail, in this search.
    high: u16 = 0,
    /// PROBED_SIZE: the next probe's size (or the one in flight).
    probe: u16 = 0,
    /// The probe in flight, by packet number (its acknowledgment or loss
    /// is matched by it, so a probe from before a restart counts nothing).
    probe_pn: ?u64 = null,
    /// PROBE_COUNT: probes of `probe`'s size lost in a row.
    lost: u8 = 0,
    /// `probe` was cut to what the sender could send (`limit`): once it
    /// is acknowledged the top of the range is tried again, not halved.
    clamped: bool = false,
    /// When `complete` searches again.
    raise_at: u64 = 0,

    // Black hole detection.
    /// Full-sized packets lost in a row (none acknowledged since), and
    /// when the first and last of them were sent.
    full_lost: u32 = 0,
    full_lost_first: u64 = 0,
    full_lost_last: u64 = 0,
    /// The newest send time of a full-sized packet acknowledged, and of a
    /// smaller one.
    full_acked: u64 = 0,
    small_acked: u64 = 0,

    // Counters, for tests and stats.
    probes_sent: u32 = 0,
    probes_lost: u32 = 0,
    black_holes: u32 = 0,

    /// `current` is the size the connection starts with, no larger than
    /// `ceiling`; a ceiling at it: nothing to search for (black holes are
    /// still detected).
    pub fn init(current: u16, ceiling: u16) Self {
        const c = @max(ceiling, base);
        return .{ .current = @min(current, c), .ceiling = c };
    }

    /// The handshake is confirmed: probing may begin.
    pub fn start(self: *Self, now: u64) void {
        if (self.state != .disabled) return;
        self.search(self.ceiling, now);
    }

    /// Searches from `current` up to `high`, sending `high` first.
    fn search(self: *Self, high: u16, now: u64) void {
        self.high = high;
        self.lost = 0;
        self.clamped = false;
        self.probe_pn = null;
        if (high <= self.current) return self.finish(now);
        self.state = .searching;
        self.probe = high;
    }

    fn finish(self: *Self, now: u64) void {
        self.state = .complete;
        self.probe = 0;
        self.probe_pn = null;
        self.raise_at = now +| raise_interval_us;
    }

    /// The next probe's size, between `current` and `high` (or ends the
    /// search when the range is too small).
    fn bisect(self: *Self, now: u64) void {
        self.lost = 0;
        if (self.high <= self.current or self.high - self.current < min_step) return self.finish(now);
        self.probe = self.current + (self.high - self.current + 1) / 2;
    }

    /// The size of a probe to send now, if one is due.
    pub fn due(self: *Self, now: u64) ?u16 {
        switch (self.state) {
            .disabled => return null,
            .complete => {
                if (self.current >= self.ceiling or now < self.raise_at) return null;
                self.search(self.ceiling, now);
                if (self.state != .searching) return null;
            },
            .searching => {},
        }
        if (self.probe_pn != null) return null;
        return self.probe;
    }

    /// The sender can't send more than `max` bytes at once now (its
    /// congestion window, or its pacer's bucket): the probe due goes at
    /// most at that size (the range above it is still searched once the
    /// window allows, which a larger PLPMTU's floor of two datagrams
    /// helps), or waits while that wouldn't be a step up. Returns the
    /// probe's size, or null if none is worth sending now.
    pub fn limit(self: *Self, max: u16) ?u16 {
        if (self.state != .searching or self.probe <= max) return self.probe;
        if (max <= self.current or max - self.current < min_step) return null;
        // Another size: its losses so far don't count against it.
        self.probe = max;
        self.lost = 0;
        self.clamped = true;
        return max;
    }

    pub fn onProbeSent(self: *Self, pn: u64) void {
        self.probe_pn = pn;
        self.probes_sent += 1;
    }

    /// A probe was acknowledged: the path carries `size`. Returns the new
    /// PLPMTU if it grew.
    pub fn onProbeAcked(self: *Self, pn: u64, size: u16, now: u64) ?u16 {
        if (self.probe_pn != pn) return null;
        self.probe_pn = null;
        const grew = size > self.current;
        if (grew) {
            self.current = size;
            // A new size: the black hole record starts again at it.
            self.full_lost = 0;
        }
        if (self.clamped) {
            // The size the sender allowed, not the middle of the range:
            // the top of it next (the sender may allow it now).
            self.clamped = false;
            self.lost = 0;
            if (self.high <= self.current or self.high - self.current < min_step) {
                self.finish(now);
            } else self.probe = self.high;
        } else self.bisect(now);
        return if (grew) size else null;
    }

    /// A probe was declared lost.
    pub fn onProbeLost(self: *Self, pn: u64, now: u64) void {
        if (self.probe_pn != pn) return;
        self.probe_pn = null;
        self.probes_lost += 1;
        self.lost += 1;
        if (self.lost < max_probes) return;
        self.fail(self.probe, now);
    }

    /// The local interface refused the probe (EMSGSIZE): that size fails
    /// at once, and the ceiling comes down for good.
    pub fn onProbeTooBig(self: *Self, now: u64) void {
        if (self.state != .searching or self.probe_pn == null) return;
        self.probe_pn = null;
        self.probes_lost += 1;
        self.local_max = @min(self.local_max, self.probe - 1);
        self.ceiling = @max(self.probe - 1, base);
        self.fail(self.probe, now);
    }

    fn fail(self: *Self, size: u16, now: u64) void {
        self.clamped = false;
        self.high = @min(self.high, size - 1);
        self.bisect(now);
    }

    /// A packet other than a probe was acknowledged.
    pub fn onPacketAcked(self: *Self, size: u32, time_sent: u64) void {
        if (size >= self.current) {
            self.full_acked = @max(self.full_acked, time_sent);
            self.full_lost = 0;
        } else {
            self.small_acked = @max(self.small_acked, time_sent);
        }
    }

    /// An ack-eliciting packet other than a probe was declared lost.
    pub fn onPacketLost(self: *Self, size: u32, time_sent: u64) void {
        if (size < self.current) {
            // A packet the fallback size carries, lost too, sent after the
            // run began: the path lost everything for a while (an outage),
            // not only what was too large. (Sizes in between say nothing:
            // the path may have shrunk below them.)
            if (size <= base and self.full_lost > 0 and time_sent > self.full_lost_first) self.full_lost = 0;
            return;
        }
        // Only full-sized ones sent after the last full-sized one that
        // arrived say anything about the size.
        if (self.current <= base or time_sent <= self.full_acked) return;
        if (self.full_lost == 0) {
            self.full_lost_first = time_sent;
            self.full_lost_last = time_sent;
        }
        self.full_lost += 1;
        self.full_lost_first = @min(self.full_lost_first, time_sent);
        self.full_lost_last = @max(self.full_lost_last, time_sent);
    }

    /// Whether the losses so far look like a black hole: `span` is the
    /// shortest time they must cover (a probe timeout).
    pub fn blackHole(self: *const Self, span: u64) bool {
        return self.current > base and self.full_lost >= black_hole_packets and
            self.full_lost_last - self.full_lost_first >= span and
            self.small_acked > self.full_lost_first;
    }

    /// A black hole: back to BASE_PLPMTU, and the search runs again from
    /// the size that stopped arriving, probed first (MAX_PROBES losses of
    /// it confirm the black hole; an outage mistaken for one ends with
    /// that probe acknowledged). Returns the new PLPMTU.
    pub fn onBlackHole(self: *Self, now: u64) u16 {
        const failed = @min(self.current, self.ceiling);
        self.black_holes += 1;
        self.fallBack();
        if (self.state != .disabled) self.search(failed, now);
        return base;
    }

    /// The local interface refused a datagram of `size` (EMSGSIZE): the
    /// ceiling goes below it for good and the PLPMTU to BASE_PLPMTU, and
    /// the search runs again (its probes find the interface's size by
    /// EMSGSIZE). Returns the new PLPMTU, or null if it can't go lower.
    pub fn onLocalTooBig(self: *Self, size: u16, now: u64) ?u16 {
        if (self.current <= base) return null;
        self.local_max = @min(self.local_max, size -| 1);
        self.ceiling = @max(@min(self.ceiling, size -| 1), base);
        self.fallBack();
        if (self.state != .disabled) self.search(self.ceiling, now);
        return base;
    }

    fn fallBack(self: *Self) void {
        self.current = base;
        self.full_lost = 0;
        self.full_acked = 0;
        self.small_acked = 0;
    }

    /// The peer moved to a new address: a new path with its own `ceiling`,
    /// searched afresh from `current` (what the connection started with).
    /// `same_route`: only its port changed (NAT rebinding), so what the
    /// local interface refused still holds; otherwise the route may be
    /// another interface's, and is learnt again.
    pub fn restart(self: *Self, current: u16, ceiling: u16, same_route: bool, now: u64) void {
        const old = self.*;
        const local_max = if (same_route) old.local_max else std.math.maxInt(u16);
        self.* = .init(current, @min(ceiling, local_max));
        self.local_max = local_max;
        self.probes_sent = old.probes_sent;
        self.probes_lost = old.probes_lost;
        self.black_holes = old.black_holes;
        if (old.state != .disabled) self.search(self.ceiling, now);
    }
};

const testing = std.testing;

/// Runs a search against a path carrying datagrams up to `mtu` bytes:
/// every probe larger is lost, every other acknowledged. Returns the
/// probes sent.
fn converge(s: *Search, path: u16, now: *u64) !u32 {
    var pn: u64 = 0;
    var sent: u32 = 0;
    while (s.due(now.*)) |size| {
        try testing.expect(size > s.current and size <= s.ceiling);
        s.onProbeSent(pn);
        sent += 1;
        if (size <= path) {
            _ = s.onProbeAcked(pn, size, now.*);
        } else s.onProbeLost(pn, now.*);
        pn += 1;
        now.* += 10_000;
        if (sent > 100) return error.NoEnd;
    }
    return sent;
}

test "the search: the ceiling at once, or bisection to within a step of the path" {
    var now: u64 = 1_000_000;
    // Nothing before the handshake is confirmed.
    var s: Search = .init(1350, 1472);
    try testing.expectEqual(@as(?u16, null), s.due(now));
    s.start(now);
    // A path carrying the ceiling: one probe.
    try testing.expectEqual(@as(u32, 1), try converge(&s, 1500, &now));
    try testing.expectEqual(@as(u16, 1472), s.current);
    try testing.expectEqual(State.complete, s.state);
    // Paths below it (a WireGuard tunnel's 1420 MTU over IPv4: 1392; the
    // IPv6 minimum's 1232 under a start of 1350 never probes below it).
    for ([_]u16{ 1392, 1452, 1400, 1351, 1471 }) |path| {
        s = .init(1350, 1472);
        s.start(now);
        _ = try converge(&s, path, &now);
        try testing.expect(s.current <= path);
        try testing.expect(path - s.current < min_step);
        try testing.expectEqual(State.complete, s.state);
    }
    // No room: complete at once.
    s = .init(1350, 1300);
    s.start(now);
    try testing.expectEqual(State.complete, s.state);
    try testing.expectEqual(@as(?u16, null), s.due(now));
}

test "the search: isolated probe losses don't fail a size; MAX_PROBES do" {
    const now: u64 = 0;
    var s: Search = .init(1350, 1472);
    s.start(now);
    for (0..max_probes - 1) |i| {
        try testing.expectEqual(@as(?u16, 1472), s.due(now));
        s.onProbeSent(i);
        // One probe at a time.
        try testing.expectEqual(@as(?u16, null), s.due(now));
        s.onProbeLost(i, now);
    }
    s.onProbeSent(10);
    try testing.expectEqual(@as(?u16, 1472), s.onProbeAcked(10, 1472, now).?);
    // A stale probe's fate counts nothing.
    s = .init(1350, 1472);
    s.start(now);
    s.onProbeSent(20);
    s.onProbeLost(19, now);
    try testing.expectEqual(@as(?u16, null), s.onProbeAcked(21, 1472, now));
    try testing.expectEqual(@as(u8, 0), s.lost);
    // Three in a row: the size fails and the search halves the range.
    for (0..max_probes) |i| {
        if (i > 0) s.onProbeSent(20 + i);
        s.onProbeLost(20 + i, now);
    }
    try testing.expectEqual(@as(u16, 1471), s.high);
    try testing.expectEqual(@as(?u16, 1350 + (1471 - 1350 + 1) / 2), s.due(now));
}

test "the search: EMSGSIZE fails a size at once and lowers the ceiling; the raise timer searches again" {
    const now: u64 = 0;
    var s: Search = .init(1350, 65507);
    s.start(now);
    s.onProbeSent(1);
    s.onProbeTooBig(now);
    try testing.expectEqual(@as(u16, 65506), s.ceiling);
    // An interface of 16384 (macOS loopback) and a path that carries it.
    var pn: u64 = 2;
    while (s.due(now)) |size| : (pn += 1) {
        s.onProbeSent(pn);
        if (size > 16384 - ipv4_overhead) s.onProbeTooBig(now) else _ = s.onProbeAcked(pn, size, now);
    }
    try testing.expect(s.current <= 16384 - ipv4_overhead and 16384 - ipv4_overhead - s.current < min_step);
    try testing.expectEqual(State.complete, s.state);
    // The raise timer: after 600 s, the ceiling (lowered by the
    // refusals, so not far past the interface) is tried again.
    try testing.expectEqual(@as(?u16, null), s.due(now + raise_interval_us - 1));
    try testing.expectEqual(s.ceiling, s.due(now + raise_interval_us).?);
    try testing.expect(s.ceiling < 16384);
}

test "black holes: full-sized losses over a PTO while smaller packets arrive" {
    var s: Search = .init(1350, 1472);
    s.start(0);
    s.onProbeSent(0);
    _ = s.onProbeAcked(0, 1472, 0);
    const pto: u64 = 30_000;
    // Losses alone, or a short run, aren't one.
    s.onPacketAcked(1472, 100);
    s.onPacketLost(1472, 1000);
    s.onPacketLost(1472, 2000);
    s.onPacketLost(1472, 40_000);
    try testing.expect(!s.blackHole(pto));
    // A smaller packet sent before the run arrived: no evidence either.
    s.onPacketAcked(300, 500);
    try testing.expect(!s.blackHole(pto));
    // One sent after the run's start: a black hole.
    s.onPacketAcked(1200, 41_000);
    try testing.expect(s.blackHole(pto));
    // Unless a full-sized one arrives: the run is over.
    s.onPacketAcked(1472, 41_500);
    try testing.expect(!s.blackHole(pto));
    // Losses of packets older than a full-sized arrival don't count.
    s.onPacketLost(1472, 41_000);
    s.onPacketLost(1472, 40_000);
    s.onPacketLost(1472, 1_000);
    try testing.expect(!s.blackHole(pto));
    // Smaller packets' losses don't make a run (nor, over the fallback
    // size, end one: the path may have shrunk below them).
    for (0..10) |i| s.onPacketLost(1300, 42_000 + i * 100);
    try testing.expect(!s.blackHole(pto));
    for (0..3) |i| s.onPacketLost(1472, 50_000 + i * 20_000);
    s.onPacketAcked(80, 100_000);
    try testing.expect(s.blackHole(pto));
    // An outage: a smaller packet sent during the run was lost as well.
    var outage = s;
    outage.onPacketLost(1200, 60_000);
    try testing.expect(!outage.blackHole(pto));
    // (One sent before the run began says nothing, and one between the
    // fallback size and the full size doesn't end it.)
    outage = s;
    outage.onPacketLost(1200, 49_000);
    outage.onPacketLost(1300, 60_000);
    try testing.expect(outage.blackHole(pto));
    var confirmed = s;
    try testing.expectEqual(base, s.onBlackHole(200_000));
    try testing.expectEqual(@as(u16, base), s.current);
    // The size that failed is probed again first: a confirmation.
    try testing.expectEqual(@as(?u16, 1472), s.due(200_000));
    var now: u64 = 200_000;
    _ = try converge(&s, 1400, &now);
    try testing.expect(s.current <= 1400 and 1400 - s.current < min_step);
    // An outage taken for a black hole: the first probe of the old size
    // is acknowledged and the size is back.
    _ = confirmed.onBlackHole(200_000);
    confirmed.onProbeSent(99);
    try testing.expectEqual(@as(?u16, 1472), confirmed.onProbeAcked(99, 1472, 210_000));
    try testing.expectEqual(State.complete, confirmed.state);
    // At BASE_PLPMTU, nothing is a black hole.
    s = .init(1200, 1200);
    for (0..10) |i| s.onPacketLost(1200, i * 100_000);
    s.onPacketAcked(50, 2_000_000);
    try testing.expect(!s.blackHole(pto));
}

test "a restart (new path) forgets the probe in flight; the local interface's refusals only with the route" {
    var s: Search = .init(1350, 1472);
    s.start(0);
    s.onProbeSent(5);
    // A refusal on the old route had lowered the ceiling; the new path
    // has its own (here an IPv6 one).
    s.onProbeTooBig(5);
    try testing.expectEqual(@as(u16, 1471), s.ceiling);
    s.onProbeSent(6);
    s.restart(1350, 1452, false, 10);
    try testing.expectEqual(@as(?u16, null), s.onProbeAcked(6, 1472, 20));
    try testing.expectEqual(@as(u16, 1350), s.current);
    try testing.expectEqual(@as(?u16, 1452), s.due(20));
    try testing.expectEqual(@as(u32, 2), s.probes_sent);
    // An interface of 1300 refused a datagram and a probe; the peer's
    // port changes (the same route): the start and the ceiling stay under
    // it, and nothing is searched for.
    s = .init(1350, 1472);
    try testing.expectEqual(@as(?u16, base), s.onLocalTooBig(1350, 0));
    s.start(0);
    while (s.due(0)) |size| {
        s.onProbeSent(size);
        if (size > 1300) s.onProbeTooBig(0) else _ = s.onProbeAcked(size, size, 0);
    }
    try testing.expect(s.local_max >= 1300 and s.local_max < 1300 + min_step);
    s.restart(1350, 1472, true, 0);
    try testing.expectEqual(s.local_max, s.ceiling);
    try testing.expectEqual(s.local_max, s.current);
    try testing.expectEqual(State.complete, s.state);
    // Another address forgets it.
    s.restart(1350, 1472, false, 0);
    try testing.expectEqual(@as(u16, 1350), s.current);
    try testing.expectEqual(@as(?u16, 1472), s.due(0));
    // Before the handshake, a restart doesn't start the search.
    s = .init(1350, 1472);
    s.restart(1350, 1472, false, 0);
    try testing.expectEqual(@as(?u16, null), s.due(0));
}

test "the start size is clamped to the ceiling; a local refusal lowers both at once" {
    // max_mtu 1300 over IPv4: a 1272 ceiling under a 1350 start.
    var s: Search = .init(1350, 1272);
    try testing.expectEqual(@as(u16, 1272), s.current);
    s.start(0);
    try testing.expectEqual(State.complete, s.state);
    // After a black hole the confirmation probe stays within the ceiling.
    _ = s.onBlackHole(0);
    try testing.expectEqual(@as(?u16, 1272), s.due(0));
    // An ordinary datagram of 1272 refused by the interface (before the
    // handshake: no search yet).
    s = .init(1350, 1472);
    try testing.expectEqual(@as(?u16, base), s.onLocalTooBig(1350, 0));
    try testing.expectEqual(@as(u16, 1349), s.ceiling);
    try testing.expectEqual(@as(?u16, null), s.due(0));
    s.start(0);
    try testing.expectEqual(@as(?u16, 1349), s.due(0));
    // At BASE_PLPMTU there is nowhere lower to go.
    s = .init(1200, 1472);
    try testing.expectEqual(@as(?u16, null), s.onLocalTooBig(1200, 0));
}

test "the search under a sender that can't send the probe at once: what it can, then the top again" {
    var s: Search = .init(1350, 65507);
    s.start(0);
    try testing.expectEqual(@as(?u16, 65507), s.due(0));
    // A 13500-byte window: that, and when it is acknowledged the ceiling
    // again (the window's floor is now two of the new size).
    try testing.expectEqual(@as(?u16, 13500), s.limit(13500));
    s.onProbeSent(1);
    try testing.expectEqual(@as(?u16, 13500), s.onProbeAcked(1, 13500, 0));
    try testing.expectEqual(@as(?u16, 65507), s.due(0));
    try testing.expectEqual(@as(?u16, 27000), s.limit(27000));
    s.onProbeSent(2);
    _ = s.onProbeAcked(2, 27000, 0);
    try testing.expectEqual(@as(?u16, 65507), s.limit(std.math.maxInt(u16)));
    s.onProbeSent(3);
    _ = s.onProbeAcked(3, 65507, 0);
    try testing.expectEqual(@as(u16, 65507), s.current);
    try testing.expectEqual(State.complete, s.state);
    // Nothing worth a probe within a step of the current size: wait.
    s = .init(1350, 65507);
    s.start(0);
    _ = s.due(0);
    try testing.expectEqual(@as(?u16, null), s.limit(1360));
    try testing.expectEqual(State.searching, s.state);
    // A cut probe lost MAX_PROBES times fails its size: bisection below it.
    try testing.expectEqual(@as(?u16, 9000), s.limit(9000));
    for (0..max_probes) |i| {
        s.onProbeSent(10 + i);
        s.onProbeLost(10 + i, 0);
    }
    try testing.expectEqual(@as(u16, 8999), s.high);
    try testing.expectEqual(@as(?u16, 1350 + (8999 - 1350 + 1) / 2), s.due(0));
}
