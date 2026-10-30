//! Loss detection and congestion control (RFC 9002, RFC 9438): the RTT
//! estimator, the loss and probe timeouts' arithmetic, CUBIC with a
//! NewReno fallback, and the pacer. Times are microseconds; sizes are
//! bytes. Which packets are in flight is tracked by sent.zig and conn.zig.
const std = @import("std");

pub const granularity: u64 = 1000;
pub const initial_rtt: u64 = 333_000;
/// kPacketThreshold (§6.1.1).
pub const packet_threshold: u64 = 3;
/// kPersistentCongestionThreshold (§7.6.1).
pub const persistent_congestion_threshold: u64 = 3;

pub const Rtt = struct {
    latest: u64 = 0,
    min: u64 = 0,
    smoothed: u64 = initial_rtt,
    variance: u64 = initial_rtt / 2,
    has_sample: bool = false,

    /// §5.3. `ack_delay` is the peer's reported delay, already capped at
    /// max_ack_delay by the caller once the handshake is confirmed.
    pub fn update(self: *Rtt, latest_rtt: u64, ack_delay: u64) void {
        self.latest = latest_rtt;
        if (!self.has_sample) {
            self.has_sample = true;
            self.min = latest_rtt;
            self.smoothed = latest_rtt;
            self.variance = latest_rtt / 2;
            return;
        }
        self.min = @min(self.min, latest_rtt);
        // Subtract the ack delay only if that leaves at least min_rtt.
        var adjusted = latest_rtt;
        if (latest_rtt >= self.min + ack_delay) adjusted = latest_rtt - ack_delay;
        const diff = if (self.smoothed > adjusted) self.smoothed - adjusted else adjusted - self.smoothed;
        self.variance = (3 * self.variance + diff) / 4;
        self.smoothed = (7 * self.smoothed + adjusted) / 8;
    }

    /// The probe timeout's base (§6.2.1), before backoff. `max_ack_delay`
    /// is 0 for the Initial and Handshake spaces.
    pub fn pto(self: *const Rtt, max_ack_delay: u64) u64 {
        return self.smoothed + @max(4 * self.variance, granularity) + max_ack_delay;
    }

    /// The time threshold for declaring a packet lost (§6.1.2).
    pub fn lossDelay(self: *const Rtt) u64 {
        const base = @max(self.latest, self.smoothed);
        return @max(base + base / 8, granularity);
    }
};

pub const Algorithm = enum { cubic, new_reno };

/// Congestion control over bytes in flight (§7), CUBIC in congestion
/// avoidance (RFC 9438) or NewReno.
pub const Congestion = struct {
    const Self = @This();

    algorithm: Algorithm = .cubic,
    mss: u64,
    window: u64,
    ssthresh: u64 = std.math.maxInt(u64),
    in_flight: u64 = 0,
    /// Packets sent before this time don't start a new congestion event.
    recovery_start: ?u64 = null,
    /// NewReno: bytes acknowledged towards the next window increase.
    acked_bytes: u64 = 0,
    // CUBIC state, in bytes and microseconds.
    w_max: f64 = 0,
    k: f64 = 0,
    epoch: ?u64 = null,
    w_est: f64 = 0,

    const cubic_c = 0.4;
    const cubic_beta = 0.7;
    const reno_beta = 0.5;

    pub fn init(mss: u64, algorithm: Algorithm) Self {
        return .{ .algorithm = algorithm, .mss = mss, .window = initialWindow(mss) };
    }

    /// §7.2: ten datagrams, within 14720 bytes and at least two datagrams.
    pub fn initialWindow(mss: u64) u64 {
        return @min(10 * mss, @max(14720, 2 * mss));
    }

    pub fn minWindow(self: *const Self) u64 {
        return 2 * self.mss;
    }

    pub fn available(self: *const Self) u64 {
        return self.window -| self.in_flight;
    }

    pub fn onSent(self: *Self, bytes: u64) void {
        self.in_flight += bytes;
    }

    /// A packet sent at `time_sent` belongs to the current recovery period
    /// (a congestion event for it would be the same one).
    pub fn inRecovery(self: *const Self, time_sent: u64) bool {
        return if (self.recovery_start) |r| time_sent <= r else false;
    }

    /// An in-flight packet was acknowledged. `in_flight_before` is the
    /// bytes in flight before this ACK was processed: a sender that
    /// wasn't using half its window is application-limited and doesn't
    /// grow it (§7.8).
    pub fn onAcked(self: *Self, bytes: u64, time_sent: u64, now: u64, rtt: *const Rtt, in_flight_before: u64) void {
        self.in_flight -|= bytes;
        if (self.inRecovery(time_sent)) return;
        if (in_flight_before < self.window / 2) return;
        if (self.window < self.ssthresh) {
            self.window += bytes;
            return;
        }
        switch (self.algorithm) {
            .new_reno => {
                self.acked_bytes += bytes;
                if (self.acked_bytes >= self.window) {
                    self.acked_bytes -= self.window;
                    self.window += self.mss;
                }
            },
            .cubic => self.cubicAck(bytes, now, rtt),
        }
    }

    fn cubicAck(self: *Self, bytes: u64, now: u64, rtt: *const Rtt) void {
        const mss: f64 = @floatFromInt(self.mss);
        const cwnd: f64 = @floatFromInt(self.window);
        if (self.epoch == null) {
            // First ACK in congestion avoidance (after slow start ended
            // without a loss event, or a reset): start a new epoch here.
            self.epoch = now;
            self.w_max = cwnd;
            self.k = 0;
            self.w_est = cwnd;
        }
        const t: f64 = @as(f64, @floatFromInt(now - self.epoch.?)) / 1e6;
        const rtt_s: f64 = @as(f64, @floatFromInt(rtt.smoothed)) / 1e6;
        // Reno-friendly estimate (RFC 9438 §4.3).
        const alpha = 3.0 * (1.0 - cubic_beta) / (1.0 + cubic_beta);
        self.w_est += alpha * mss * @as(f64, @floatFromInt(bytes)) / cwnd;
        const target = std.math.clamp(self.wCubic(t + rtt_s), cwnd, 1.5 * cwnd);
        var next = cwnd;
        if (self.wCubic(t) < self.w_est) {
            next = self.w_est;
        } else {
            next = cwnd + (target - cwnd) * @as(f64, @floatFromInt(bytes)) / cwnd;
        }
        self.window = @max(self.window, @as(u64, @intFromFloat(next)));
    }

    /// W_cubic(t) in bytes (RFC 9438 §4.2), with C scaled to bytes.
    fn wCubic(self: *const Self, t: f64) f64 {
        const mss: f64 = @floatFromInt(self.mss);
        const d = t - self.k;
        return cubic_c * mss * d * d * d + self.w_max;
    }

    /// Lost packets leave the flight.
    pub fn onLost(self: *Self, bytes: u64) void {
        self.in_flight -|= bytes;
    }

    /// Packets that won't be acknowledged or declared lost (their space was
    /// discarded) leave the flight without a congestion signal.
    pub fn onDiscarded(self: *Self, bytes: u64) void {
        self.in_flight -|= bytes;
    }

    /// A loss (or ECN-CE) whose newest packet was sent at `time_sent`.
    pub fn onCongestionEvent(self: *Self, time_sent: u64, now: u64) void {
        if (self.inRecovery(time_sent)) return;
        self.recovery_start = now;
        const cwnd: f64 = @floatFromInt(self.window);
        switch (self.algorithm) {
            .new_reno => {
                self.ssthresh = @max(@as(u64, @intFromFloat(cwnd * reno_beta)), self.minWindow());
                self.acked_bytes = 0;
            },
            .cubic => {
                // Fast convergence (§4.7).
                self.w_max = if (cwnd < self.w_max) cwnd * (1.0 + cubic_beta) / 2.0 else cwnd;
                self.ssthresh = @max(@as(u64, @intFromFloat(cwnd * cubic_beta)), self.minWindow());
                const mss: f64 = @floatFromInt(self.mss);
                const reduced: f64 = @floatFromInt(self.ssthresh);
                self.k = std.math.cbrt((self.w_max - reduced) / (cubic_c * mss));
                self.epoch = now;
                self.w_est = reduced;
            },
        }
        self.window = self.ssthresh;
    }

    /// §7.6.2: back to the minimum window, slow start again.
    pub fn onPersistentCongestion(self: *Self) void {
        self.window = self.minWindow();
        self.recovery_start = null;
        self.epoch = null;
        self.w_max = 0;
        self.acked_bytes = 0;
    }
};

/// Pacing (RFC 9002 §7.7): a token bucket filled at N · cwnd /
/// smoothed_rtt (N = 1.25) holding at most `burst_us` of that rate, and
/// never less than ten datagrams (the initial window, the burst §7.7
/// allows). Packets in flight take their size from it as they are sent;
/// a datagram waits while fewer tokens than its size are left. ACK-only
/// packets take nothing and don't wait; probes take tokens but don't wait.
///
/// Once the bucket runs dry, the next send is due when it is half full
/// again (or holds what the window has room for, if less) rather than
/// when one datagram's worth is back: a wait releases a
/// burst that GSO sends at once, costs one timer per burst instead of one
/// per packet, and keeps the full rate behind an event loop whose timers
/// have millisecond resolution (half of 2 ms of the rate is back after
/// 1 ms, and a late wake-up still finds room in the bucket). On paths with a
/// smoothed RTT under `burst_us` the bucket holds more than a window, so
/// the congestion window, not the pacer, is what limits.
///
/// Bursts may exceed the initial window, which §7.7 says senders SHOULD
/// keep to unless they know the path absorbs more: a wait releases 1 ms of
/// the rate, 2 ms after idle (12 and 25 datagrams of 1200 bytes at a
/// window of 1.2 MB over 100 ms; on paths under 2 ms, a window). That is
/// the timer's resolution: the event loops wake in whole milliseconds, and
/// ten datagrams per wake-up would cap a connection that ACKs don't clock
/// at 13.5 MB/s (108 Mbit/s). Linux's TCP pacing makes the same trade
/// (about 1 ms of the rate per TSO burst).
pub const Pacer = struct {
    const Self = @This();

    /// Bytes that may be sent now.
    tokens: u64,
    /// When `tokens` was last brought up to date.
    last: u64 = 0,
    /// What is left of a byte since then, in units of 1 / (rate_den ·
    /// smoothed_rtt): frequent refills at low rates would lose it each time.
    frac: u64 = 0,
    burst_us: u64,

    /// N in N · cwnd / smoothed_rtt, as a fraction.
    const rate_num = 5;
    const rate_den = 4;
    pub const min_burst_packets = 10;
    pub const default_burst_us = 2000;

    pub fn init(mss: u64, burst_us: u64) Self {
        return .{ .tokens = min_burst_packets * mss, .burst_us = burst_us };
    }

    /// The bucket's size for the current window and RTT.
    pub fn capacity(self: *const Self, cc: *const Congestion, rtt: *const Rtt) u64 {
        const burst = mulDiv(rateNum(cc), self.burst_us, rateDen(rtt));
        return @max(min_burst_packets *| cc.mss, burst);
    }

    /// The rate is rateNum / rateDen bytes per microsecond.
    fn rateNum(cc: *const Congestion) u64 {
        return @max(cc.window, 1) *| rate_num;
    }

    fn rateDen(rtt: *const Rtt) u64 {
        return @max(rtt.smoothed, 1) *| rate_den;
    }

    const Level = struct { tokens: u64, frac: u64 };

    /// The tokens (and what is left of a byte) at `now`.
    fn level(self: *const Self, now: u64, cc: *const Congestion, rtt: *const Rtt) Level {
        const cap = self.capacity(cc, rtt);
        if (now <= self.last) return .{ .tokens = @min(self.tokens, cap), .frac = self.frac };
        const num = rateNum(cc);
        const den = rateDen(rtt);
        var add: u64 = undefined;
        var frac: u64 = undefined;
        const p = @mulWithOverflow(now - self.last, num);
        if (p[1] == 0) {
            const t = p[0] +| self.frac;
            add = t / den;
            frac = t % den;
        } else {
            const t = @as(u128, now - self.last) * num + self.frac;
            add = @intCast(@min(t / den, std.math.maxInt(u64)));
            frac = @intCast(t % den);
        }
        const tokens = self.tokens +| add;
        if (tokens >= cap) return .{ .tokens = cap, .frac = 0 };
        return .{ .tokens = tokens, .frac = frac };
    }

    /// The tokens at `now` (not before `last`).
    pub fn available(self: *const Self, now: u64, cc: *const Congestion, rtt: *const Rtt) u64 {
        return self.level(now, cc, rtt).tokens;
    }

    /// Brings the tokens up to `now`.
    pub fn refill(self: *Self, now: u64, cc: *const Congestion, rtt: *const Rtt) void {
        const l = self.level(now, cc, rtt);
        self.tokens = l.tokens;
        self.frac = l.frac;
        self.last = @max(self.last, now);
    }

    pub fn onSent(self: *Self, bytes: u64) void {
        self.tokens -|= bytes;
    }

    /// When a held-back datagram of `size` bytes is due, as of the last
    /// `refill`: null if it may go now. `room` is what the congestion
    /// window has left: no point waiting for more tokens than that.
    pub fn nextSend(self: *const Self, size: u64, room: u64, cc: *const Congestion, rtt: *const Rtt) ?u64 {
        if (self.tokens >= size) return null;
        const want = @max(@min(self.capacity(cc, rtt) / 2, room), size);
        // (want - tokens - frac) / rate, rounded up. Rare: 128 bits.
        const num = rateNum(cc);
        const need = (@as(u128, want - self.tokens) * rateDen(rtt)) -| self.frac;
        const wait = (need + num - 1) / num;
        return self.last +| @as(u64, @intCast(@min(wait, std.math.maxInt(u64))));
    }

    /// a · b / c, saturating; 64-bit arithmetic unless a · b overflows
    /// (it runs for every datagram sent).
    fn mulDiv(a: u64, b: u64, c: u64) u64 {
        const p = @mulWithOverflow(a, b);
        if (p[1] == 0) return p[0] / c;
        return @intCast(@min(@as(u128, a) * b / c, std.math.maxInt(u64)));
    }
};

const testing = std.testing;

test "RTT estimator follows RFC 9002 §5.3" {
    var r: Rtt = .{};
    try testing.expectEqual(@as(u64, 333_000 + 4 * 166_500), r.pto(0));
    r.update(100_000, 0);
    try testing.expectEqual(@as(u64, 100_000), r.smoothed);
    try testing.expectEqual(@as(u64, 50_000), r.variance);
    // An ack delay is subtracted only while the result stays above min_rtt.
    r.update(120_000, 10_000);
    try testing.expectEqual(@as(u64, (7 * 100_000 + 110_000) / 8), r.smoothed);
    r.update(90_000, 50_000);
    try testing.expectEqual(@as(u64, 90_000), r.min);
    try testing.expect(r.lossDelay() >= r.smoothed);
    try testing.expectEqual(r.smoothed + 4 * r.variance + 25_000, r.pto(25_000));
}

test "slow start, a loss, recovery, then growth again" {
    for ([_]Algorithm{ .cubic, .new_reno }) |alg| {
        var c = Congestion.init(1200, alg);
        var rtt: Rtt = .{};
        rtt.update(10_000, 0);
        try testing.expectEqual(@as(u64, 12000), c.window);
        var now: u64 = 0;
        // Slow start doubles per round trip of full windows.
        c.onSent(12000);
        now += 10_000;
        c.onAcked(12000, 0, now, &rtt, 12000);
        try testing.expectEqual(@as(u64, 24000), c.window);
        // An application-limited sender doesn't grow.
        c.onSent(1200);
        c.onAcked(1200, now, now + 10_000, &rtt, 1200);
        try testing.expectEqual(@as(u64, 24000), c.window);
        // Loss: the window shrinks once per recovery period.
        c.onSent(24000);
        c.onLost(1200);
        c.onCongestionEvent(now, now + 5000);
        const reduced = c.window;
        try testing.expect(reduced < 24000 and reduced >= c.minWindow());
        c.onCongestionEvent(now, now + 6000);
        try testing.expectEqual(reduced, c.window);
        // Acks of packets sent before recovery began don't grow it.
        c.onAcked(1200, now, now + 7000, &rtt, c.window);
        try testing.expectEqual(reduced, c.window);
        // Congestion avoidance grows it slowly afterwards.
        now += 20_000;
        var t = now;
        for (0..200) |_| {
            c.onSent(1200);
            t += 1000;
            c.onAcked(1200, t, t + 10_000, &rtt, c.window);
        }
        try testing.expect(c.window > reduced);
        try testing.expect(c.window < 3 * reduced);
        c.onPersistentCongestion();
        try testing.expectEqual(c.minWindow(), c.window);
    }
}

test "pacer: burst allowance, then the paced rate" {
    var cc = Congestion.init(1200, .cubic);
    var rtt: Rtt = .{};
    rtt.update(100_000, 0);
    var p = Pacer.init(1200, Pacer.default_burst_us);
    // The bucket starts with ten datagrams (2 ms of the rate is less).
    try testing.expectEqual(@as(u64, 12000), p.capacity(&cc, &rtt));
    p.refill(1_000_000, &cc, &rtt);
    for (0..10) |_| {
        try testing.expectEqual(@as(?u64, null), p.nextSend(1200, std.math.maxInt(u64), &cc, &rtt));
        p.onSent(1200);
    }
    // Empty: due once half the bucket is back. The rate is
    // 1.25 · 12000 / 100 ms = 0.15 bytes/µs, so 6000 bytes take 40 ms.
    try testing.expectEqual(@as(?u64, 1_000_000 + 40_000), p.nextSend(1200, std.math.maxInt(u64), &cc, &rtt));
    // With room for only two datagrams in the window, only that long; for
    // less than one, a datagram's worth.
    try testing.expectEqual(@as(?u64, 1_000_000 + 16_000), p.nextSend(1200, 2400, &cc, &rtt));
    try testing.expectEqual(@as(?u64, 1_000_000 + 8_000), p.nextSend(1200, 100, &cc, &rtt));
    try testing.expectEqual(@as(u64, 1200), p.available(1_008_000, &cc, &rtt));
    try testing.expectEqual(@as(u64, 6000), p.available(1_040_000, &cc, &rtt));
    // Idle time refills it to the burst, no further.
    try testing.expectEqual(@as(u64, 12000), p.available(5_000_000, &cc, &rtt));
    // A partly used bucket waits only for what is missing.
    p.refill(1_020_000, &cc, &rtt);
    try testing.expectEqual(@as(u64, 3000), p.tokens);
    p.onSent(2400);
    try testing.expectEqual(@as(?u64, 1_020_000 + 36_000), p.nextSend(1200, std.math.maxInt(u64), &cc, &rtt));
}

test "pacer: frequent refills at a low rate keep the rate" {
    // The minimum window over 100 ms: 1.25 · 2400 / 100 ms = 0.03 bytes/µs,
    // with an upload's datagrams (or a stream of ACKs) refilling every 10 µs.
    var cc = Congestion.init(1200, .cubic);
    cc.onPersistentCongestion();
    var rtt: Rtt = .{};
    rtt.update(100_000, 0);
    var p = Pacer.init(1200, Pacer.default_burst_us);
    p.refill(1_000_000, &cc, &rtt);
    p.onSent(p.tokens);
    var t: u64 = 1_000_000;
    while (t < 1_200_000) {
        t += 10;
        p.refill(t, &cc, &rtt);
    }
    // 200 ms of the rate: 6000 bytes, as if refilled once.
    try testing.expectEqual(@as(u64, 6000), p.tokens);
    // At an irregular rate too: 1.25 · 2400 / 70 ms is 3/70 bytes per µs.
    rtt = .{};
    rtt.update(70_000, 0);
    p.onSent(p.tokens);
    const start = t;
    var step: u64 = 1;
    while (t < start + 70_000) {
        t += step;
        step = step % 13 + 1;
        p.refill(t, &cc, &rtt);
    }
    try testing.expectEqual(@as(u64, 3 * (t - start) / 70), p.tokens);
}

test "pacer: no overflow at absurd windows and RTTs" {
    var cc = Congestion.init(1200, .cubic);
    var rtt: Rtt = .{};
    rtt.update(std.math.maxInt(u64) / 2, 0);
    var p = Pacer.init(1200, Pacer.default_burst_us);
    cc.window = std.math.maxInt(u64);
    p.refill(std.math.maxInt(u64) - 1, &cc, &rtt);
    p.onSent(p.tokens);
    _ = p.nextSend(1200, std.math.maxInt(u64), &cc, &rtt);
    _ = p.available(std.math.maxInt(u64), &cc, &rtt);
    rtt.smoothed = 0;
    cc.window = 0;
    _ = p.capacity(&cc, &rtt);
    _ = p.nextSend(1200, 0, &cc, &rtt);
}

test "pacer: the rate follows the window and the RTT" {
    var cc = Congestion.init(1200, .cubic);
    var rtt: Rtt = .{};
    rtt.update(100_000, 0);
    var p = Pacer.init(1200, Pacer.default_burst_us);
    cc.window = 1_200_000;
    // 1.25 · 1.2 MB / 100 ms is 15 bytes/µs: 2 ms of it is 30000 bytes.
    try testing.expectEqual(@as(u64, 30000), p.capacity(&cc, &rtt));
    p.refill(0, &cc, &rtt);
    p.onSent(p.tokens);
    try testing.expectEqual(@as(u64, 3000), p.available(200, &cc, &rtt));
    // Half the bucket, 15000 bytes, is back in 1 ms.
    try testing.expectEqual(@as(?u64, 1000), p.nextSend(1200, std.math.maxInt(u64), &cc, &rtt));
    // Twice the window: twice the rate (and twice the bucket).
    cc.window = 2_400_000;
    try testing.expectEqual(@as(u64, 6000), p.available(200, &cc, &rtt));
    try testing.expectEqual(@as(?u64, 1000), p.nextSend(1200, std.math.maxInt(u64), &cc, &rtt));
    // Twice the RTT: half the rate.
    cc.window = 1_200_000;
    rtt = .{};
    rtt.update(200_000, 0);
    try testing.expectEqual(@as(u64, 15000), p.capacity(&cc, &rtt));
    try testing.expectEqual(@as(u64, 1500), p.available(200, &cc, &rtt));
    // A window shrunk by a loss shrinks the bucket at once (to its floor
    // of ten datagrams here).
    p.refill(10_000, &cc, &rtt);
    try testing.expectEqual(@as(u64, 15000), p.tokens);
    cc.onCongestionEvent(0, 10_000);
    try testing.expectEqual(@as(u64, 12000), p.available(10_000, &cc, &rtt));
    // A tiny RTT (loopback): the bucket holds more than the window.
    rtt = .{};
    rtt.update(100, 0);
    try testing.expect(p.capacity(&cc, &rtt) > cc.window);
}
