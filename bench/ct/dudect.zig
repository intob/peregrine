//! dudect-style timing test (Reparaz, Balasch, Verbauwhede 2017) of the
//! constant-time code in src/tls: P-256 (`p256.zig`), X25519
//! (`x25519.zig`) and RSA's private operation (`rsa.zig` over `mont.zig`,
//! RSA-2048: the base is what varies, the key is fixed; a tenth of the
//! samples, at about 0.5 ms each). Two classes of secret inputs are interleaved at random
//! (class 0 a fixed secret, class 1 random or another fixed secret), and
//! Welch's t compares their cycle counts, over all samples and below a
//! ladder of percentiles (dudect's crops). |t| > 4.5 means the classes are
//! told apart. Also the binary whose disassembly `bench/ct/branches.py`
//! scans (it calls every operation on secrets). Run by
//! `bench/scripts/ct-check.sh`.
//! Usage: dudect N [case name substring...]
const std = @import("std");
const builtin = @import("builtin");
const per = @import("peregrine");
const p256 = per.internal.tls_p256;
const x25519 = per.internal.tls_x25519;
const rsa = per.internal.tls_rsa;
const rsa_verify = per.internal.tls_rsa_verify;
const P256 = std.crypto.ecc.P256;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const n = P256.scalar.field_order;

inline fn ticks() u64 {
    return switch (builtin.cpu.arch) {
        .aarch64 => asm volatile (
            \\isb
            \\mrs %[r], cntvct_el0
            \\isb
            : [r] "=r" (-> u64),
            :
            : .{ .memory = true }),
        .x86_64 => blk: {
            var lo: u32 = undefined;
            var hi: u32 = undefined;
            asm volatile ("lfence; rdtsc; lfence"
                : [lo] "={eax}" (lo),
                  [hi] "={edx}" (hi),
            );
            break :blk (@as(u64, hi) << 32) | lo;
        },
        else => @compileError("dudect: aarch64 and x86_64 only"),
    };
}

const Welch = struct {
    n: [2]f64 = .{ 0, 0 },
    mean: [2]f64 = .{ 0, 0 },
    m2: [2]f64 = .{ 0, 0 },

    fn push(w: *Welch, c: u1, x: f64) void {
        w.n[c] += 1;
        const d = x - w.mean[c];
        w.mean[c] += d / w.n[c];
        w.m2[c] += d * (x - w.mean[c]);
    }

    fn t(w: Welch) f64 {
        const v0 = w.m2[0] / (w.n[0] - 1);
        const v1 = w.m2[1] / (w.n[1] - 1);
        return (w.mean[0] - w.mean[1]) / @sqrt(v0 / w.n[0] + v1 / w.n[1]);
    }
};

fn be(v: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, v, .big);
    return out;
}

const Kind = enum { shared, keyshare, sign, public, x_shared, x_public, rsa };

const Case = struct {
    name: []const u8,
    kind: Kind,
    /// Class 0's secret.
    fixed: u256,
    /// Class 1's secret when it is fixed too (else random).
    other: ?u256 = null,
};

const cases = [_]Case{
    .{ .name = "p256 sharedSecret s=1 vs random", .kind = .shared, .fixed = 1 },
    .{ .name = "p256 sharedSecret s=n-2 vs random", .kind = .shared, .fixed = n - 2 },
    .{ .name = "p256 sharedSecret s=0x88.. vs random", .kind = .shared, .fixed = 0x8888888888888888888888888888888888888888888888888888888888888888 },
    .{ .name = "p256 sharedSecret low-HW (2^255+1) vs high-HW (n-1)", .kind = .shared, .fixed = (1 << 255) + 1, .other = n - 1 },
    .{ .name = "p256 sharedSecret fixed vs random", .kind = .shared, .fixed = 0x3c1f7a92d0e5b8146a2f9c3e7d5b1a08f6e4c2a0193b5d7f8e6c4a2b0d9f7e5c },
    .{ .name = "p256 keyShare fixed seed vs random seed", .kind = .keyshare, .fixed = 7 },
    .{ .name = "p256 publicKey s=1 vs random", .kind = .public, .fixed = 1 },
    .{ .name = "p256 publicKey s=0x77.. vs random", .kind = .public, .fixed = 0x7777777777777777777777777777777777777777777777777777777777777777 },
    .{ .name = "p256 sign fixed noise vs random noise", .kind = .sign, .fixed = 7 },
    .{ .name = "x25519 sharedSecret sk=0 vs random", .kind = .x_shared, .fixed = 0 },
    .{ .name = "x25519 sharedSecret sk=0xff.. vs random", .kind = .x_shared, .fixed = (1 << 256) - 1 },
    .{ .name = "x25519 sharedSecret fixed vs random", .kind = .x_shared, .fixed = 0x3c1f7a92d0e5b8146a2f9c3e7d5b1a08f6e4c2a0193b5d7f8e6c4a2b0d9f7e5c },
    .{ .name = "x25519 publicKey sk=0 vs random", .kind = .x_public, .fixed = 0 },
    .{ .name = "x25519 publicKey sk=0x88.. vs random", .kind = .x_public, .fixed = 0x8888888888888888888888888888888888888888888888888888888888888888 },
    // The base m (256 bytes): `fixed` as its last 32 bytes, the rest 0
    // (so 0 and 1 are themselves), or 2^2032 + fixed; class 1 random below 2^2040.
    .{ .name = "rsa2048 privateOp m=0 vs random", .kind = .rsa, .fixed = 0 },
    .{ .name = "rsa2048 privateOp m=1 vs random", .kind = .rsa, .fixed = 1 },
    .{ .name = "rsa2048 privateOp fixed vs random", .kind = .rsa, .fixed = 0x3c1f7a92d0e5b8146a2f9c3e7d5b1a08f6e4c2a0193b5d7f8e6c4a2b0d9f7e5c },
};

/// dP and dQ patterns for the exponent cases.
const ExpPattern = enum { zeros, ones, runs, top_only, random };

const exp_cases = [_]struct { name: []const u8, a: ExpPattern, b: ExpPattern }{
    .{ .name = "rsa2048 privateOp dP,dQ=0 vs random", .a = .zeros, .b = .random },
    .{ .name = "rsa2048 privateOp dP,dQ=0xff.. vs random", .a = .ones, .b = .random },
    .{ .name = "rsa2048 privateOp dP,dQ runs of 64 zero/one bytes vs random", .a = .runs, .b = .random },
    .{ .name = "rsa2048 privateOp dP,dQ=0x80 00.. vs random", .a = .top_only, .b = .random },
    .{ .name = "rsa2048 privateOp dP,dQ=0 vs 0xff..", .a = .zeros, .b = .ones },
};

fn fillExp(e: []u8, pat: ExpPattern, r: std.Random) void {
    switch (pat) {
        .zeros => @memset(e, 0),
        .ones => @memset(e, 0xff),
        .runs => for (e, 0..) |*b, i| {
            b.* = if ((i / 64) % 2 == 0) 0 else 0xff;
        },
        .top_only => {
            @memset(e, 0);
            e[0] = 0x80;
        },
        .random => r.bytes(e),
    }
}

fn lessThan(_: void, a: u64, b: u64) bool {
    return a < b;
}

const Peers = struct {
    p256: [65]u8,
    x25519: [32]u8,
    kp: Ecdsa.KeyPair,
    rsa: rsa.PrivateKey,
};

inline fn run(kind: Kind, in: [32]u8, m: *const [256]u8, peers: *const Peers) void {
    const msg = "a CertificateVerify's content";
    switch (kind) {
        .shared => std.mem.doNotOptimizeAway(p256.sharedSecret(in, &peers.p256)),
        .keyshare => std.mem.doNotOptimizeAway(p256.keyShare(in, &peers.p256)),
        .public => std.mem.doNotOptimizeAway(p256.publicKey(in)),
        .sign => std.mem.doNotOptimizeAway(p256.sign(peers.kp, msg, in)),
        .x_shared => std.mem.doNotOptimizeAway(x25519.sharedSecret(in, peers.x25519)),
        .x_public => std.mem.doNotOptimizeAway(x25519.publicKey(in)),
        .rsa => {
            var s: [256]u8 = undefined;
            peers.rsa.privateOp(m, &s) catch unreachable;
            std.mem.doNotOptimizeAway(&s);
        },
    }
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const count: usize = if (args.len > 1) try std.fmt.parseInt(usize, args[1], 10) else 200_000;
    // Welch's t needs samples in both classes; RSA takes a tenth of them.
    if (count < 20) {
        std.debug.print("dudect: N must be at least 20\n", .{});
        std.process.exit(2);
    }
    const gpa = init.gpa;
    var prng = std.Random.DefaultPrng.init(@truncate(@as(u96, @bitCast(std.Io.Clock.awake.now(init.io).nanoseconds))));
    const r = prng.random();
    var peers: Peers = .{
        .p256 = (P256.basePoint.mul(be(0x1234567890abcdef1234567890abcdef), .big) catch unreachable).toUncompressedSec1(),
        .x25519 = x25519.publicKey(@splat(0x42)),
        .kp = try Ecdsa.KeyPair.generateDeterministic(@splat(3)),
        .rsa = undefined,
    };
    var der_buf: [4096]u8 = undefined;
    peers.rsa = try rsa.PrivateKey.fromPkcs1(try rsa_verify.pemToPkcs1(&der_buf, per.internal.tls_credentials.testdata.rsa2048_key));

    const class = try gpa.alloc(u1, count);
    defer gpa.free(class);
    const inputs = try gpa.alloc([32]u8, count);
    defer gpa.free(inputs);
    const ms = try gpa.alloc([256]u8, count / 10);
    defer gpa.free(ms);
    const times = try gpa.alloc(u64, count);
    defer gpa.free(times);
    const sorted = try gpa.alloc(u64, count);
    defer gpa.free(sorted);

    var worst_all: f64 = 0;
    for (cases) |cs| {
        if (args.len > 2) {
            var want = false;
            for (args[2..]) |a| {
                if (std.mem.indexOf(u8, cs.name, a) != null) want = true;
            }
            if (!want) continue;
        }
        const samples = if (cs.kind == .rsa) ms.len else count;
        for (class[0..samples], inputs[0..samples], 0..) |*c, *in, i| {
            c.* = r.int(u1);
            if (c.* == 0) in.* = be(cs.fixed) else if (cs.other) |o| in.* = be(o) else r.bytes(in);
            if (cs.kind == .rsa) {
                ms[i] = @splat(0);
                if (c.* == 0) ms[i][224..].* = in.* else r.bytes(ms[i][1..]);
                if (c.* == 0 and cs.fixed > 1) ms[i][1] = 1;
            }
        }
        // Warm up (the base-point tables, caches).
        for (inputs[0..@min(200, samples)], 0..) |in, i| run(cs.kind, in, &ms[i % @max(1, ms.len)], &peers);
        for (inputs[0..samples], times[0..samples], 0..) |in, *t, i| {
            const m = &ms[if (cs.kind == .rsa) i else 0];
            const t0 = ticks();
            run(cs.kind, in, m, &peers);
            t.* = ticks() - t0;
        }
        @memcpy(sorted[0..samples], times[0..samples]);
        std.mem.sort(u64, sorted[0..samples], {}, lessThan);
        const pcts = [_]f64{ 1.0, 0.99, 0.95, 0.9, 0.75, 0.5, 0.25, 0.1 };
        var worst: f64 = 0;
        var line: [512]u8 = undefined;
        var w = std.Io.Writer.fixed(&line);
        for (pcts) |pc| {
            const idx = @min(samples - 1, @as(usize, @intFromFloat(pc * @as(f64, @floatFromInt(samples - 1)))));
            const cut = sorted[idx];
            var welch: Welch = .{};
            for (class[0..samples], times[0..samples]) |c, t| {
                if (t <= cut) welch.push(c, @floatFromInt(t));
            }
            const t = welch.t();
            if (@abs(t) > @abs(worst)) worst = t;
            try w.print(" p{d:.0}:{d:.2}", .{ pc * 100, t });
        }
        worst_all = @max(worst_all, @abs(worst));
        std.debug.print("{s}: N={} median={} ticks, max|t|={d:.2} [{s}]\n", .{ cs.name, samples, sorted[samples / 2], @abs(worst), w.buffered() });
    }
    // RSA with the exponents varying (the base fixed): dP and dQ of each
    // class written into the key before every sample (outside the timed
    // part), so long runs of zero or one bits, a lone top bit and all
    // zeros (every window selects table entry 0) meet random exponents.
    for (exp_cases) |cs| {
        if (args.len > 2) {
            var want = false;
            for (args[2..]) |a| {
                if (std.mem.indexOf(u8, cs.name, a) != null) want = true;
            }
            if (!want) continue;
        }
        const samples = ms.len;
        var key = peers.rsa;
        var m: [256]u8 = undefined;
        r.bytes(&m);
        m[0] = 0;
        for (class[0..samples]) |*c| c.* = r.int(u1);
        for (0..@min(20, samples)) |_| key.privateOp(&m, &ms[0]) catch unreachable;
        for (class[0..samples], times[0..samples]) |c, *t| {
            fillExp(key.dp[0..key.p_len], if (c == 0) cs.a else cs.b, r);
            fillExp(key.dq[0..key.q_len], if (c == 0) cs.a else cs.b, r);
            var s: [256]u8 = undefined;
            const t0 = ticks();
            key.privateOp(&m, &s) catch unreachable;
            t.* = ticks() - t0;
            std.mem.doNotOptimizeAway(&s);
        }
        @memcpy(sorted[0..samples], times[0..samples]);
        std.mem.sort(u64, sorted[0..samples], {}, lessThan);
        const pcts = [_]f64{ 1.0, 0.99, 0.95, 0.9, 0.75, 0.5, 0.25, 0.1 };
        var worst: f64 = 0;
        var line: [512]u8 = undefined;
        var w = std.Io.Writer.fixed(&line);
        for (pcts) |pc| {
            const idx = @min(samples - 1, @as(usize, @intFromFloat(pc * @as(f64, @floatFromInt(samples - 1)))));
            const cut = sorted[idx];
            var welch: Welch = .{};
            for (class[0..samples], times[0..samples]) |c, t| {
                if (t <= cut) welch.push(c, @floatFromInt(t));
            }
            const t = welch.t();
            if (@abs(t) > @abs(worst)) worst = t;
            try w.print(" p{d:.0}:{d:.2}", .{ pc * 100, t });
        }
        worst_all = @max(worst_all, @abs(worst));
        std.debug.print("{s}: N={} median={} ticks, max|t|={d:.2} [{s}]\n", .{ cs.name, samples, sorted[samples / 2], @abs(worst), w.buffered() });
    }
    std.debug.print("max |t| over the cases: {d:.2}{s}\n", .{ worst_all, if (worst_all > 4.5) " (> 4.5: LEAK?)" else "" });
    if (worst_all > 4.5) std.process.exit(1);
}
