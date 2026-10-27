//! Micro-benchmarks for TLS record protection. Run with `zig build bench-tls`
//! (always built with -O fast).
//!
//! "std AEAD" seals and opens each record the way record.zig did before it
//! kept expanded keys: std's AEAD API with the raw key, which expands the
//! AES key schedule and GHASH's powers of H on every call.
const std = @import("std");
const per = @import("peregrine");
const record = per.internal.tls_record;
const sys = per.internal.sys;
const Protection = record.Protection;

fn report(name: []const u8, size: usize, iterations: usize, ns: u64) void {
    const per_op = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(iterations));
    const gbps = @as(f64, @floatFromInt(size * iterations)) / @as(f64, @floatFromInt(ns));
    std.debug.print("{s:<44} {d:>6} B  {d:>8.1} ns/record  {d:>6.2} GB/s\n", .{ name, size, per_op, gbps });
}

/// What record.zig's seal did before: std's AEAD with a raw key.
fn stdSeal(comptime A: type, p: *Protection, out: []u8, data_len: usize) usize {
    const inner_len = data_len + 1;
    out[0..5].* = .{ 23, 3, 3, 0, 0 };
    std.mem.writeInt(u16, out[3..5], @intCast(inner_len + record.tag_len), .big);
    const inner = out[record.header_len..][0..inner_len];
    inner[data_len] = 23;
    A.encrypt(inner, out[record.header_len + inner_len ..][0..record.tag_len], inner, out[0..record.header_len], nonce(p), p.aead.key[0..A.key_length].*);
    p.seq += 1;
    return record.header_len + inner_len + record.tag_len;
}

fn stdOpen(comptime A: type, p: *Protection, rec: []u8) !void {
    const body = rec[record.header_len..];
    const ct = body[0 .. body.len - record.tag_len];
    try A.decrypt(ct, ct, body[ct.len..][0..record.tag_len].*, rec[0..record.header_len], nonce(p), p.aead.key[0..A.key_length].*);
    p.seq += 1;
}

fn nonce(p: *const Protection) [12]u8 {
    var n = p.iv;
    var seq: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq, p.seq, .big);
    for (n[4..], seq) |*b, s| b.* ^= s;
    return n;
}

pub fn main() !void {
    var buf: [record.max_record]u8 = undefined;
    var out: [record.max_plaintext + 1]u8 = undefined;
    const secret: [48]u8 = @splat(7);
    inline for (.{ record.Suite.aes_128_gcm_sha256, record.Suite.aes_256_gcm_sha384 }) |suite| {
        const A = suite.Aead();
        for ([_]usize{ 32, 256, 1024, 4096, record.max_plaintext }) |size| {
            const iterations: usize = @max(20_000, 400_000_000 / (size + 200));
            @memset(buf[record.header_len..][0..size], 'a');
            // Seal then open: one record each way, as a server does per
            // request/response pair.
            {
                var tx: Protection = .init(suite, secret[0..suite.hashLen()]);
                var rx: Protection = .init(suite, secret[0..suite.hashLen()]);
                const start = sys.nanoTimestamp();
                for (0..iterations) |_| {
                    const n = stdSeal(A, &tx, &buf, size);
                    try stdOpen(A, &rx, buf[0..n]);
                }
                report(@tagName(suite) ++ " std AEAD, seal+open", size, iterations, sys.nanoTimestamp() - start);
            }
            {
                var tx: Protection = .init(suite, secret[0..suite.hashLen()]);
                var rx: Protection = .init(suite, secret[0..suite.hashLen()]);
                const start = sys.nanoTimestamp();
                for (0..iterations) |_| {
                    const n = tx.seal(&buf, .application_data, buf[record.header_len..][0..size]);
                    _ = try rx.open(buf[0..n]);
                }
                report(@tagName(suite) ++ " expanded key, seal+open", size, iterations, sys.nanoTimestamp() - start);
            }
            {
                // Open into another buffer, as readPlain does when the
                // plaintext fits, against open in place plus a copy.
                var tx: Protection = .init(suite, secret[0..suite.hashLen()]);
                var rx: Protection = .init(suite, secret[0..suite.hashLen()]);
                var rx2: Protection = .init(suite, secret[0..suite.hashLen()]);
                var t_copy: u64 = 0;
                var t_into: u64 = 0;
                for (0..iterations) |_| {
                    const n = tx.seal(&buf, .application_data, buf[record.header_len..][0..size]);
                    var copy: [record.max_record]u8 = undefined;
                    @memcpy(copy[0..n], buf[0..n]);
                    var start = sys.nanoTimestamp();
                    const opened = try rx.open(buf[0..n]);
                    @memcpy(out[0..opened.data.len], opened.data);
                    t_copy += sys.nanoTimestamp() - start;
                    start = sys.nanoTimestamp();
                    std.mem.doNotOptimizeAway(try rx2.openInto(copy[0..n], &out));
                    t_into += sys.nanoTimestamp() - start;
                }
                report(@tagName(suite) ++ " open in place + copy", size, iterations, t_copy);
                report(@tagName(suite) ++ " openInto", size, iterations, t_into);
            }
        }
    }
}
