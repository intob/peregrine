//! A DEFLATE compressor (RFC 1951) for whole WebSocket messages, each
//! compressed on its own (permessage-deflate with server_no_context_takeover).
//!
//! std's compressor is built for long streams: per message it clears a
//! 64 KiB hash table and builds Huffman tables in ways that cost more than
//! compressing a small message. This one keeps what a message needs cheap:
//! - matching is greedy over a short hash chain (up to `max_chain` earlier
//!   positions with the same 4-byte hash, as zlib's fastest levels); the
//!   tables hold positions plus a running base, so entries from earlier
//!   messages are recognised as stale and nothing is cleared per message;
//! - each block (up to `max_tokens` tokens) gets the cheapest of dynamic
//!   Huffman codes, the fixed codes or stored, computed from its symbol
//!   counts, with code lengths from the in-place minimum-redundancy
//!   algorithm (Moffat and Katajainen) and a length limit fixed up after;
//! - distances never exceed the window the client allows
//!   (server_max_window_bits).
//! Output ends on a byte boundary with an empty stored block's header bits:
//! the 00 00 ff ff that would follow are left off (RFC 7692 §7.2.1).
const std = @import("std");

const hash_bits = 14;
const min_match = 4;
const max_match = 258;
/// Candidates tried per position, and a match long enough to stop at.
const max_chain = 4;
const nice_match = 64;
const chain_bits = 15;
/// Tokens per block: their counts decide the block's codes.
pub const max_tokens = 16 * 1024;

/// A literal byte, or a match: length - 3 in bits 0-7, distance - 1 in bits
/// 8-22, bit 31 set.
const Token = u32;
const match_bit: u32 = 1 << 31;

pub const Compressor = struct {
    /// Position of the last 4 bytes with each hash, plus `base`.
    table: [1 << hash_bits]u32,
    /// For each position (modulo 2^chain_bits), the one before it with the
    /// same hash, plus `base`.
    prev: [1 << chain_bits]u32,
    /// Added to positions in the current message; entries below it are
    /// from earlier ones.
    base: u32,
    tokens: [max_tokens]Token,
    lit_freq: [286]u32,
    dist_freq: [30]u32,

    pub fn init(self: *Compressor) void {
        self.base = 1;
        @memset(&self.table, 0);
        @memset(&self.prev, 0);
    }

    inline fn insert(self: *Compressor, base: u32, i: usize, h: u32) u32 {
        const head = self.table[h];
        const at = base + @as(u32, @intCast(i));
        self.prev[at & ((1 << chain_bits) - 1)] = head;
        self.table[h] = at;
        return head;
    }

    /// Compresses `input` into `out` as one message whose back references
    /// reach at most 2^`window_bits` bytes. Returns the length, or null if
    /// it doesn't fit (pass `out` no longer than the input to keep only
    /// output that is smaller).
    pub fn compress(self: *Compressor, input: []const u8, out: []u8, window_bits: u4) ?usize {
        // Positions in the table must stay below 2^32.
        if (input.len > std.math.maxInt(u32) / 2) return null;
        if (self.base > std.math.maxInt(u32) - @as(u32, @intCast(input.len)) - 1) self.init();
        var w: BitWriter = .{ .out = out };
        const max_dist: usize = @as(usize, 1) << window_bits;
        const base = self.base;
        self.base += @intCast(input.len + 1);

        var block_start: usize = 0;
        var n_tokens: usize = 0;
        @memset(&self.lit_freq, 0);
        @memset(&self.dist_freq, 0);
        var i: usize = 0;
        var anchor: usize = 0;
        var misses: usize = 0;
        while (i + min_match <= input.len) {
            const v = std.mem.readInt(u32, input[i..][0..4], .little);
            var cand = self.insert(base, i, hash(v));
            const limit = @min(max_match, input.len - i);
            var len: usize = 0;
            var pos: usize = 0;
            var tries: usize = max_chain;
            while (tries > 0 and cand >= base and i - (cand - base) <= max_dist) : (tries -= 1) {
                const p = cand - base;
                if (std.mem.readInt(u32, input[p..][0..4], .little) == v and input[p + len] == input[i + len]) {
                    const l = matchLen(input, p, i, limit);
                    if (l > len) {
                        len = l;
                        pos = p;
                        if (l >= nice_match or l == limit) break;
                    }
                }
                const older = self.prev[cand & ((1 << chain_bits) - 1)];
                // Slots are reused every 2^chain_bits positions: stop at one
                // that no longer leads further back.
                if (older >= cand) break;
                cand = older;
            }
            if (len >= min_match) {
                {
                    // Literals before it, then the match.
                    self.literals(&w, input, &block_start, &n_tokens, anchor, i);
                    if (n_tokens == max_tokens) {
                        self.writeBlock(&w, input[block_start..i], n_tokens);
                        block_start = i;
                        n_tokens = 0;
                    }
                    const dist = i - pos;
                    self.tokens[n_tokens] = match_bit | @as(u32, @intCast(len - 3)) | @as(u32, @intCast(dist - 1)) << 8;
                    self.lit_freq[257 + @as(usize, len_code[len - 3])] += 1;
                    self.dist_freq[distCode(@intCast(dist - 1))] += 1;
                    n_tokens += 1;
                    // Short matches: chain every position in them, so what
                    // follows can match into them; long ones, just the end.
                    const end = i + len;
                    var e = i + 1;
                    if (len > 16) e = end - 2;
                    while (e < end and e + min_match <= input.len) : (e += 1) {
                        _ = self.insert(base, e, hash(std.mem.readInt(u32, input[e..][0..4], .little)));
                    }
                    i += len;
                    anchor = i;
                    misses = 0;
                    continue;
                }
            }
            // Step faster through data that doesn't repeat.
            misses += 1;
            i += 1 + (misses >> 6);
        }
        self.literals(&w, input, &block_start, &n_tokens, anchor, input.len);
        if (n_tokens > 0) self.writeBlock(&w, input[block_start..], n_tokens);
        // An empty stored block, not final: its header, then padding to a
        // byte; LEN and NLEN (00 00 ff ff) are left off.
        w.put(0, 3);
        w.alignByte();
        return if (w.overflow) null else w.pos;
    }

    /// Adds `input[from..to]` as literals, writing out blocks as the token
    /// buffer fills.
    fn literals(self: *Compressor, w: *BitWriter, input: []const u8, block_start: *usize, n_tokens: *usize, from: usize, to: usize) void {
        var p = from;
        while (p < to) {
            if (n_tokens.* == max_tokens) {
                self.writeBlock(w, input[block_start.*..p], n_tokens.*);
                block_start.* = p;
                n_tokens.* = 0;
            }
            const k = @min(to - p, max_tokens - n_tokens.*);
            for (input[p..][0..k], self.tokens[n_tokens.*..][0..k]) |b, *t| {
                t.* = b;
                self.lit_freq[b] += 1;
            }
            n_tokens.* += k;
            p += k;
        }
    }

    /// Writes one block (not final) holding `n` tokens, which encode `raw`.
    fn writeBlock(self: *Compressor, w: *BitWriter, raw: []const u8, n: usize) void {
        if (w.overflow) return;
        self.lit_freq[256] = 1;
        defer {
            @memset(&self.lit_freq, 0);
            @memset(&self.dist_freq, 0);
        }
        var lit_len: [286]u8 = undefined;
        var dist_len: [30]u8 = undefined;
        buildLengths(&self.lit_freq, &lit_len, 15);
        // A decoder needs a complete distance code: at least two lengths.
        var dist_used: usize = 0;
        for (self.dist_freq) |f| dist_used += @intFromBool(f != 0);
        var dist_freq = self.dist_freq;
        if (dist_used < 2) {
            if (dist_freq[0] == 0) dist_freq[0] = 1;
            if (dist_freq[1] == 0) dist_freq[1] = 1;
        }
        buildLengths(&dist_freq, &dist_len, 15);

        var hlit: usize = 286;
        while (hlit > 257 and lit_len[hlit - 1] == 0) hlit -= 1;
        var hdist: usize = 30;
        while (hdist > 1 and dist_len[hdist - 1] == 0) hdist -= 1;

        // The code lengths, run-length coded (codes 16, 17, 18).
        var all: [286 + 30]u8 = undefined;
        @memcpy(all[0..hlit], lit_len[0..hlit]);
        @memcpy(all[hlit..][0..hdist], dist_len[0..hdist]);
        var rle: [286 + 30]u16 = undefined;
        const n_rle = runLengths(all[0 .. hlit + hdist], &rle);
        var cl_freq: [19]u32 = @splat(0);
        for (rle[0..n_rle]) |r| cl_freq[r & 0x1f] += 1;
        // zlib rejects an incomplete code-length code: use two symbols.
        var cl_used: usize = 0;
        for (cl_freq) |f| cl_used += @intFromBool(f != 0);
        var cl_build = cl_freq;
        if (cl_used < 2) {
            if (cl_build[0] == 0) cl_build[0] = 1 else cl_build[8] = 1;
        }
        var cl_len: [19]u8 = undefined;
        buildLengths(&cl_build, &cl_len, 7);
        var hclen: usize = 19;
        while (hclen > 4 and cl_len[codegen_order[hclen - 1]] == 0) hclen -= 1;

        // Bits each way.
        var data_dynamic: u64 = 0;
        var data_fixed: u64 = 0;
        var extra: u64 = 0;
        for (self.lit_freq[0..286], 0..) |f, s| {
            data_dynamic += @as(u64, f) * lit_len[s];
            data_fixed += @as(u64, f) * fixedLitLen(s);
            if (s >= 257) extra += @as(u64, f) * len_extra_bits[s - 257];
        }
        for (self.dist_freq, 0..) |f, s| {
            data_dynamic += @as(u64, f) * dist_len[s];
            data_fixed += @as(u64, f) * 5;
            extra += @as(u64, f) * dist_extra_bits[s];
        }
        var header: u64 = 5 + 5 + 4 + 3 * @as(u64, hclen);
        for (rle[0..n_rle]) |r| header += cl_len[r & 0x1f] + rle_extra_bits[r & 0x1f];
        const dynamic_bits = 3 + header + data_dynamic + extra;
        const fixed_bits = 3 + data_fixed + extra;
        const stored_bits = (raw.len + 5 * (raw.len / 65535 + 1)) * 8 + 8;

        if (stored_bits < dynamic_bits and stored_bits < fixed_bits) return writeStored(w, raw);
        var lit_code: [286]u16 = undefined;
        var dist_code: [30]u16 = undefined;
        if (fixed_bits <= dynamic_bits) {
            w.put(0b010, 3); // not final, fixed codes
            for (0..286) |s| lit_len[s] = fixedLitLen(s);
            @memset(&dist_len, 5);
            lit_code = fixed_lit_code;
        } else {
            w.put(0b100, 3); // not final, dynamic codes
            w.put(hlit - 257, 5);
            w.put(hdist - 1, 5);
            w.put(hclen - 4, 4);
            for (codegen_order[0..hclen]) |s| w.put(cl_len[s], 3);
            var cl_code: [19]u16 = undefined;
            canonicalCodes(&cl_len, &cl_code);
            for (rle[0..n_rle]) |r| {
                const s = r & 0x1f;
                w.put(cl_code[s], @intCast(cl_len[s]));
                if (rle_extra_bits[s] > 0) w.put(r >> 5, @intCast(rle_extra_bits[s]));
            }
        }
        // Fixed codes come from all 288 lengths (RFC 1951 §3.2.6), so
        // they are precomputed; 286 lengths would shift every 9-bit code.
        if (fixed_bits > dynamic_bits) canonicalCodes(&lit_len, &lit_code);
        canonicalCodes(&dist_len, &dist_code);
        for (self.tokens[0..n]) |t| {
            if (t & match_bit == 0) {
                w.put(lit_code[t], @intCast(lit_len[t]));
                continue;
            }
            const l = t & 0xff;
            const lc: usize = len_code[l];
            w.put(lit_code[257 + lc], @intCast(lit_len[257 + lc]));
            if (len_extra_bits[lc] > 0) w.put(l - len_base[lc], @intCast(len_extra_bits[lc]));
            const d = (t >> 8) & 0x7fff;
            const dc = distCode(d);
            w.put(dist_code[dc], @intCast(dist_len[dc]));
            if (dist_extra_bits[dc] > 0) w.put(d - dist_base[dc], @intCast(dist_extra_bits[dc]));
        }
        w.put(lit_code[256], @intCast(lit_len[256]));
    }
};

fn writeStored(w: *BitWriter, raw: []const u8) void {
    var rest = raw;
    while (true) {
        const k = @min(rest.len, 65535);
        w.put(0b000, 3); // not final, stored
        w.alignByte();
        w.put(k, 16);
        w.put(~k & 0xffff, 16);
        w.bytes(rest[0..k]);
        rest = rest[k..];
        if (rest.len == 0) break;
    }
}

inline fn hash(v: u32) u32 {
    return (v *% 0x9E3779B1) >> (32 - hash_bits);
}

fn matchLen(input: []const u8, pos: usize, i: usize, max: usize) usize {
    var len: usize = min_match;
    while (len + 8 <= max) {
        const a = std.mem.readInt(u64, input[pos + len ..][0..8], .little);
        const b = std.mem.readInt(u64, input[i + len ..][0..8], .little);
        if (a != b) return len + @ctz(a ^ b) / 8;
        len += 8;
    }
    while (len < max and input[pos + len] == input[i + len]) len += 1;
    return len;
}

/// Writes bits least significant first, as DEFLATE packs them.
const BitWriter = struct {
    out: []u8,
    pos: usize = 0,
    bits: u64 = 0,
    nbits: u7 = 0,
    overflow: bool = false,

    /// Codes are stored bit-reversed, so they can be put like other fields.
    inline fn put(w: *BitWriter, v: anytype, n: u6) void {
        w.bits |= @as(u64, @intCast(v)) << @intCast(w.nbits);
        w.nbits += n;
        if (w.nbits >= 32) {
            if (w.pos + 4 > w.out.len) {
                w.overflow = true;
                w.pos = 0;
            } else {
                std.mem.writeInt(u32, w.out[w.pos..][0..4], @truncate(w.bits), .little);
                w.pos += 4;
            }
            w.bits >>= 32;
            w.nbits -= 32;
        }
    }

    fn alignByte(w: *BitWriter) void {
        while (w.nbits > 0) {
            if (w.pos >= w.out.len) {
                w.overflow = true;
                w.pos = 0;
            } else {
                w.out[w.pos] = @truncate(w.bits);
                w.pos += 1;
            }
            w.bits >>= 8;
            w.nbits -|= 8;
        }
        w.bits = 0;
    }

    /// Bytes on a byte boundary.
    fn bytes(w: *BitWriter, b: []const u8) void {
        w.alignByte();
        if (w.pos + b.len > w.out.len) {
            w.overflow = true;
            w.pos = 0;
            return;
        }
        @memcpy(w.out[w.pos..][0..b.len], b);
        w.pos += b.len;
    }
};

/// Code lengths for `freq` (0 for unused symbols), at most `limit` bits:
/// minimum-redundancy lengths computed in place over the used symbols sorted
/// by count, then lengths over the limit folded back as zlib and miniz do.
fn buildLengths(freq: []const u32, lens: []u8, limit: u5) void {
    @memset(lens, 0);
    var syms: [286]u16 = undefined;
    var n: usize = 0;
    for (freq, 0..) |f, s| {
        if (f != 0) {
            syms[n] = @intCast(s);
            n += 1;
        }
    }
    if (n == 0) return;
    if (n == 1) {
        lens[syms[0]] = 1;
        return;
    }
    const Ctx = struct {
        freq: []const u32,
        fn less(ctx: @This(), a: u16, b: u16) bool {
            return ctx.freq[a] < ctx.freq[b] or (ctx.freq[a] == ctx.freq[b] and a < b);
        }
    };
    std.sort.pdq(u16, syms[0..n], Ctx{ .freq = freq }, Ctx.less);
    var a: [286]u32 = undefined;
    for (syms[0..n], 0..) |s, i| a[i] = freq[s];
    minimumRedundancy(a[0..n]);
    // a[i] is now the length of the i-th rarest symbol (non-increasing).
    var count: [33]u32 = @splat(0);
    for (a[0..n]) |l| count[@min(l, 32)] += 1;
    if (a[0] > limit) {
        for (limit + 1..33) |l| {
            count[limit] += count[l];
            count[l] = 0;
        }
        var total: u64 = 0;
        var l: usize = limit;
        while (l > 0) : (l -= 1) total += @as(u64, count[l]) << @intCast(limit - l);
        const full = @as(u64, 1) << limit;
        while (total > full) {
            count[limit] -= 1;
            var k: usize = limit - 1;
            while (k > 0) : (k -= 1) {
                if (count[k] != 0) {
                    count[k] -= 1;
                    count[k + 1] += 2;
                    break;
                }
            }
            total -= 1;
        }
    }
    // Longest codes to the rarest symbols.
    var i: usize = 0;
    var l: usize = 32;
    while (l > 0) : (l -= 1) {
        var c = count[l];
        while (c > 0) : (c -= 1) {
            lens[syms[i]] = @intCast(l);
            i += 1;
        }
    }
}

/// In place: `a` holds counts in non-decreasing order and gets the code
/// length of each (Moffat and Katajainen, "In-Place Calculation of
/// Minimum-Redundancy Codes", 1995). At least two entries.
fn minimumRedundancy(a: []u32) void {
    const n = a.len;
    a[0] += a[1];
    var root: usize = 0;
    var leaf: usize = 2;
    var next: usize = 1;
    while (next < n - 1) : (next += 1) {
        if (leaf >= n or a[root] < a[leaf]) {
            a[next] = a[root];
            a[root] = @intCast(next);
            root += 1;
        } else {
            a[next] = a[leaf];
            leaf += 1;
        }
        if (leaf >= n or (root < next and a[root] < a[leaf])) {
            a[next] += a[root];
            a[root] = @intCast(next);
            root += 1;
        } else {
            a[next] += a[leaf];
            leaf += 1;
        }
    }
    a[n - 2] = 0;
    var j: usize = n - 2;
    while (j > 0) {
        j -= 1;
        a[j] = a[a[j]] + 1;
    }
    var avail: usize = 1;
    var used: usize = 0;
    var depth: u32 = 0;
    var r: isize = @as(isize, @intCast(n)) - 2;
    var nxt: isize = @as(isize, @intCast(n)) - 1;
    while (avail > 0) {
        while (r >= 0 and a[@intCast(r)] == depth) {
            used += 1;
            r -= 1;
        }
        while (avail > used) {
            a[@intCast(nxt)] = depth;
            nxt -= 1;
            avail -= 1;
        }
        avail = 2 * used;
        depth += 1;
        used = 0;
    }
}

/// Canonical codes from lengths, bit-reversed for writing LSB first.
fn canonicalCodes(lens: []const u8, codes: []u16) void {
    var count: [16]u16 = @splat(0);
    for (lens) |l| count[l] += 1;
    count[0] = 0;
    var next: [16]u16 = undefined;
    var code: u16 = 0;
    for (1..16) |b| {
        code = (code + count[b - 1]) << 1;
        next[b] = code;
    }
    for (lens, 0..) |l, s| {
        if (l == 0) continue;
        const c = next[l];
        next[l] += 1;
        codes[s] = @bitReverse(c) >> @intCast(16 - @as(u5, @intCast(l)));
    }
}

/// Code lengths as code-length symbols: bits 0-4 the symbol, bits 5+ its
/// extra value. Returns how many.
fn runLengths(lens: []const u8, out: []u16) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < lens.len) {
        const l = lens[i];
        var run: usize = 1;
        while (i + run < lens.len and lens[i + run] == l) run += 1;
        i += run;
        if (l == 0) {
            while (run >= 11) {
                const k = @min(run, 138);
                out[n] = 18 | @as(u16, @intCast(k - 11)) << 5;
                n += 1;
                run -= k;
            }
            if (run >= 3) {
                out[n] = 17 | @as(u16, @intCast(run - 3)) << 5;
                n += 1;
                run = 0;
            }
        } else {
            out[n] = l;
            n += 1;
            run -= 1;
            while (run >= 3) {
                const k = @min(run, 6);
                out[n] = 16 | @as(u16, @intCast(k - 3)) << 5;
                n += 1;
                run -= k;
            }
        }
        while (run > 0) : (run -= 1) {
            out[n] = l;
            n += 1;
        }
    }
    return n;
}

const codegen_order = [19]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
const rle_extra_bits = blk: {
    var t: [19]u8 = @splat(0);
    t[16] = 2;
    t[17] = 3;
    t[18] = 7;
    break :blk t;
};

fn fixedLitLen(s: usize) u8 {
    return if (s < 144) 8 else if (s < 256) 9 else if (s < 280) 7 else 8;
}

const fixed_lit_code = blk: {
    @setEvalBranchQuota(20_000);
    var lens: [288]u8 = undefined;
    for (&lens, 0..) |*l, s| l.* = fixedLitLen(s);
    var codes: [288]u16 = undefined;
    canonicalCodes(&lens, &codes);
    break :blk codes[0..286].*;
};

const len_base = [29]u16{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 255 };
const len_extra_bits = [29]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
/// Length - 3 to its length code (0-28).
const len_code = blk: {
    @setEvalBranchQuota(10_000);
    var t: [256]u8 = undefined;
    for (0..256) |l| {
        var c: usize = 28;
        while (len_base[c] > l) c -= 1;
        t[l] = c;
    }
    break :blk t;
};

const dist_base = [30]u16{ 0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576 };
const dist_extra_bits = [30]u8{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

/// Distance - 1 to its distance code (0-29).
inline fn distCode(d: u32) u5 {
    if (d < 4) return @intCast(d);
    const bits: u5 = @intCast(31 - @clz(d)); // floor(log2 d), 2..14
    return @intCast(2 * @as(u32, bits) + ((d >> (bits - 1)) & 1));
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const flate = std.compress.flate;

fn inflateAll(deflated: []const u8, out: *std.ArrayList(u8)) !void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    try input.appendSlice(testing.allocator, deflated);
    try input.appendSlice(testing.allocator, &.{ 0, 0, 0xff, 0xff });
    var in: std.Io.Reader = .fixed(input.items);
    var window: [flate.max_window_len]u8 = undefined;
    var d: flate.Decompress = .init(&in, .raw, &window);
    while (true) {
        const ready = d.reader.buffered();
        try out.appendSlice(testing.allocator, ready);
        d.reader.toss(ready.len);
        d.reader.fillMore() catch |err| switch (err) {
            error.EndOfStream => return error.UnexpectedFinal,
            error.ReadFailed => {
                // Unwrapped, not `d.err != @as(?flate.Decompress.Error,
                // error.EndOfStream)`: Zig 0.17's own x86_64 backend (Debug
                // builds) compares two optional error sets as if each had a
                // null flag after it, and reads stack garbage for both.
                if ((d.err orelse return error.Corrupt) != error.EndOfStream or d.state != .block_header or in.bufferedLen() != 0) return error.Corrupt;
                const rest = d.reader.buffered();
                try out.appendSlice(testing.allocator, rest);
                return;
            },
        };
    }
}

fn roundTrip(c: *Compressor, input: []const u8, window_bits: u4) !?usize {
    const out = try testing.allocator.alloc(u8, input.len + input.len / 8 + 64);
    defer testing.allocator.free(out);
    const n = c.compress(input, out, window_bits) orelse return null;
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    try inflateAll(out[0..n], &got);
    try testing.expectEqualSlices(u8, input, got.items);
    return n;
}

test "the test inflater accepts a clean end and rejects a cut-off one" {
    const c = try testing.allocator.create(Compressor);
    defer testing.allocator.destroy(c);
    c.init();
    // Noise, a short repeat and longer text (stored, fixed and dynamic
    // blocks), each followed by the empty stored block's header.
    var long: [3000]u8 = undefined;
    for (&long, 0..) |*b, i| b.* = "the quick brown fox "[i % 20] +% @as(u8, @intCast(i % 7));
    var noise: [300]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(1);
    prng.random().bytes(&noise);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    for ([_][]const u8{ &noise, "hello, hello, hello", &long }) |m| {
        var out: [4000]u8 = undefined;
        const n = c.compress(m, &out, 15).?;
        got.clearRetainingCapacity();
        try inflateAll(out[0..n], &got);
        try testing.expectEqualSlices(u8, m, got.items);
    }
    // A stored block of 10 bytes holding 3: with the 00 00 ff ff appended,
    // the input runs out inside it.
    got.clearRetainingCapacity();
    try testing.expectError(error.Corrupt, inflateAll(&.{ 0x00, 0x0a, 0x00, 0xf5, 0xff, 'a', 'b', 'c' }, &got));
    // A fixed block, then a dynamic header std rejects (an oversubscribed
    // code) with every byte taken, still in the block-header state: only the
    // error check catches it.
    got.clearRetainingCapacity();
    try testing.expectError(error.Corrupt, inflateAll(&.{ 0x02, 0x94, 0xd1, 0x4d, 0xb1 }, &got));
}

test "distance and length codes" {
    for (0..32768) |d| {
        const c = distCode(@intCast(d));
        try testing.expect(d >= dist_base[c]);
        try testing.expect(d - dist_base[c] < @as(u32, 1) << @intCast(dist_extra_bits[c]));
    }
    for (0..256) |l| {
        const c = len_code[l];
        try testing.expect(l >= len_base[c]);
        try testing.expect(l - len_base[c] < @as(u32, 1) << @intCast(len_extra_bits[c]));
    }
}

test "code lengths are complete, optimal for small cases and within the limit" {
    var lens: [286]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 3 }, blk: {
        buildLengths(&.{ 8, 4, 2, 1 }, lens[0..4], 15);
        break :blk lens[0..4];
    });
    // Fibonacci counts force deep trees; the limit folds them.
    var freq: [286]u32 = @splat(0);
    var f0: u32 = 1;
    var f1: u32 = 1;
    for (0..30) |s| {
        freq[s] = f0;
        const t = f0 + f1;
        f0 = f1;
        f1 = t;
    }
    for ([_]u5{ 15, 7 }) |limit| {
        buildLengths(&freq, &lens, limit);
        var kraft: u64 = 0;
        for (lens) |l| {
            try testing.expect(l <= limit);
            if (l > 0) kraft += @as(u64, 1) << @intCast(limit - l);
        }
        try testing.expectEqual(@as(u64, 1) << limit, kraft);
    }
}

test "messages round-trip through std's decompressor: text, repeats, noise, empty, many blocks, small windows" {
    const c = try testing.allocator.create(Compressor);
    defer testing.allocator.destroy(c);
    c.init();
    const json = "{\"userId\":12345,\"action\":\"purchase\",\"items\":[{\"id\":\"A1B2C3\",\"name\":\"Wireless Mouse\",\"price\":25.99}]} ";
    var big: [200_000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = json[i % json.len] +% @as(u8, @intCast((i / 7919) % 3));
    var noise: [5000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(42);
    prng.random().bytes(&noise);
    var zeros: [70_000]u8 = @splat(0);
    _ = &zeros;
    const json10 = comptime blk: {
        var t: [json.len * 10]u8 = undefined;
        for (0..10) |k| @memcpy(t[k * json.len ..][0..json.len], json);
        break :blk t;
    };
    const cases = [_][]const u8{ "", "a", "abcabcabcabcabcabc", json, &json10, big[0..1000], &big, &noise, &zeros };
    for (cases) |m| {
        for ([_]u4{ 15, 12, 9, 8 }) |wb| {
            const n = (try roundTrip(c, m, wb)).?;
            if (m.len >= 1000 and wb == 15 and m.ptr != &noise) try testing.expect(n < m.len / 3);
        }
    }
    // Noise doesn't shrink: refused when the output may only be smaller.
    var out: [5000]u8 = undefined;
    try testing.expectEqual(@as(?usize, null), c.compress(&noise, &out, 15));
}

test "fixed codes: every literal and length, high bytes included" {
    const c = try testing.allocator.create(Compressor);
    defer testing.allocator.destroy(c);
    c.init();
    // Short messages where fixed codes beat a dynamic header and stored.
    var m: [96]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(9);
    var fixed: usize = 0;
    for (0..2000) |_| {
        const n = 8 + prng.random().uintLessThan(usize, m.len - 8);
        prng.random().bytes(m[0..n]);
        // Some repeats, so matches mix in.
        if (n > 40) @memcpy(m[n - 16 .. n], m[4..20]);
        var out: [256]u8 = undefined;
        const k = c.compress(m[0..n], &out, 15).?;
        if ((out[0] >> 1) & 3 == 1) fixed += 1;
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(testing.allocator);
        try inflateAll(out[0..k], &got);
        try testing.expectEqualSlices(u8, m[0..n], got.items);
    }
    try testing.expect(fixed > 100);
    // Against RFC 1951's table: 0 is 00110000, 144 is 110010000, 256 is
    // 0000000, 280 is 11000000 (written bit-reversed).
    try testing.expectEqual(@bitReverse(@as(u16, 0b00110000)) >> 8, fixed_lit_code[0]);
    try testing.expectEqual(@bitReverse(@as(u16, 0b110010000)) >> 7, fixed_lit_code[144]);
    try testing.expectEqual(@as(u16, 0), fixed_lit_code[256]);
    try testing.expectEqual(@bitReverse(@as(u16, 0b11000000)) >> 8, fixed_lit_code[280]);
}

// Fuzz target: any message, any window, round-trips.
fn fuzzCompress(_: void, smith: *std.testing.Smith) anyerror!void {
    const c = try testing.allocator.create(Compressor);
    defer testing.allocator.destroy(c);
    c.init();
    var buf: [40_000]u8 = undefined;
    var len: usize = 0;
    // Pieces of random bytes and repeats of earlier output, so matches of
    // every length and distance come up.
    while (len < buf.len and !smith.eos()) {
        const kind = smith.value(u8);
        const n = @min(buf.len - len, 1 + @as(usize, smith.value(u16)) % 600);
        if (kind & 1 == 0 or len == 0) {
            smith.bytes(buf[len..][0..n]);
        } else {
            const from = smith.value(u16) % len;
            for (0..n) |k| buf[len + k] = buf[from + k % (len - from)];
        }
        len += n;
    }
    const wb: u4 = @intCast(8 + smith.value(u8) % 8);
    _ = try roundTrip(c, buf[0..len], wb);
    // And a second message after it, with the table holding the first.
    _ = try roundTrip(c, buf[0 .. len / 2], wb);
}

test "fuzz: ws compress" {
    try std.testing.fuzz({}, fuzzCompress, .{ .corpus = &.{
        &[_]u8{ 0x00, 0x20, 0x00, 'a', 'b', 'c', 0x01, 0x10, 0x00, 0x05, 0x01, 0x07 },
    } });
}
