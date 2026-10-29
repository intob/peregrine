//! A DEFLATE decompressor (RFC 1951) for whole permessage-deflate messages.
//!
//! A message's compressed payload is in memory in one piece (with the
//! 00 00 ff ff the sender left off appended), and every message ends at a
//! block boundary (the sync flush), so between messages a connection keeps
//! only its window: the last 32 KiB of output, in a ring (`Window`), for
//! back references when the client uses context takeover. Huffman tables
//! are rebuilt for each block in scratch shared by a worker's connections
//! (`Tables`): two-level lookups, 9 bits then the rest for literals and
//! lengths, 8 then the rest for distances. Bits are read 64 at a time.
//! Output goes straight into the message buffer (`Out`), bounded by the
//! message size limit.
const std = @import("std");
const BufferPool = @import("../http/session.zig").BufferPool;

pub const Error = error{ InvalidData, MessageTooBig, OutOfMemory };

pub const window_size = 32 * 1024;

/// The last `window_size` bytes of a connection's output.
pub const Window = struct {
    buf: [window_size]u8 = undefined,
    /// Where the next byte goes.
    end: usize = 0,
    /// Bytes that are valid (up to `window_size`).
    len: usize = 0,

    fn append(w: *Window, data: []const u8) void {
        const d = data[data.len - @min(data.len, window_size) ..];
        const first = @min(d.len, window_size - w.end);
        @memcpy(w.buf[w.end..][0..first], d[0..first]);
        @memcpy(w.buf[0 .. d.len - first], d[first..]);
        w.end = (w.end + d.len) % window_size;
        w.len = @min(window_size, w.len + d.len);
    }
};

/// The message being inflated: `buf[0..len]`, grown from the pool's cache
/// of large buffers, at most `max` bytes.
pub const Out = struct {
    buf: []u8,
    len: usize = 0,
    max: usize,
    pool: *BufferPool,

    /// Room for `n` more bytes, plus 8 for copies that overshoot.
    fn reserve(o: *Out, n: usize) Error!void {
        if (o.len + n > o.max) return error.MessageTooBig;
        if (o.len + n + 8 > o.buf.len) try o.grow(o.len + n + 8);
    }

    fn grow(o: *Out, need: usize) Error!void {
        const size = @max(need, @min(2 * o.buf.len, o.max + 8), 16 * 1024);
        const new = try o.pool.acquireLarge(size);
        @memcpy(new[0..o.len], o.buf[0..o.len]);
        if (o.buf.len > 0) o.pool.releaseLarge(o.buf);
        o.buf = new;
    }
};

const lit_root = 9;
const dist_root = 8;
const cl_root = 7;
/// Root tables plus a subtable of 2^(15 - root) entries per code longer
/// than the root (an upper bound).
const lit_cap = (1 << lit_root) + 286 * (1 << (15 - lit_root));
const dist_cap = (1 << dist_root) + 30 * (1 << (15 - dist_root));

/// Decoding tables: a worker's scratch, rebuilt for each dynamic block;
/// the fixed codes' are built once.
pub const Tables = struct {
    lit: [lit_cap]u32,
    dist: [dist_cap]u32,
    cl: [1 << cl_root]u32,
    fixed_lit: [1 << lit_root]u32,
    fixed_dist: [1 << dist_root]u32,

    pub fn init(t: *Tables) void {
        var lens: [288]u8 = undefined;
        for (&lens, 0..) |*l, s| l.* = if (s < 144) 8 else if (s < 256) 9 else if (s < 280) 7 else 8;
        build(&t.fixed_lit, &lens, lit_root) catch unreachable;
        const dl: [30]u8 = @splat(5);
        build(&t.fixed_dist, &dl, dist_root) catch unreachable;
    }
};

// A table entry: symbol in bits 0-15 and code length in bits 16-19 (0:
// no code); or, with bit 31, a subtable at the offset in bits 0-15 indexed
// by the next (bits 20-23) bits.
const sub_flag: u32 = 1 << 31;

/// Builds a lookup table for canonical codes of `lens`. Over-subscribed
/// lengths are invalid; an incomplete code leaves entries that fail to
/// decode.
fn build(table: []u32, lens: []const u8, root: u5) Error!void {
    var count: [16]u16 = @splat(0);
    for (lens) |l| count[l] += 1;
    return buildCounted(table, lens, count, root);
}

/// `build` with the lengths already counted (a dynamic header counts them
/// as it decodes them, in runs: counting 286 entries one by one is a chain
/// of dependent increments).
fn buildCounted(table: []u32, lens: []const u8, counted: [16]u16, root: u5) Error!void {
    var count = counted;
    count[0] = 0;
    var left: i32 = 1;
    var max_len: u5 = 0;
    for (1..16) |l| {
        left = (left << 1) - count[l];
        if (left < 0) return error.InvalidData;
        if (count[l] != 0) max_len = @intCast(l);
    }
    // Symbols in canonical order: by length, then value.
    var offs: [16]u16 = undefined;
    offs[1] = 0;
    for (1..15) |l| offs[l + 1] = offs[l] + count[l];
    var sorted: [288]u16 = undefined;
    for (lens, 0..) |l, sym| {
        if (l == 0) continue;
        sorted[offs[l]] = @intCast(sym);
        offs[l] += 1;
    }
    const root_size = @as(usize, 1) << root;
    // A complete code fills every root entry (a code or a subtable);
    // otherwise entries left over from the last table must read as no code.
    if (left != 0) @memset(table[0..root_size], 0);
    const sub_bits: u5 = if (max_len > root) max_len - root else 0;
    var next_sub: usize = root_size;
    // Long codes come last in canonical order, their root prefixes
    // ascending: a new prefix starts a new subtable.
    var prefix: usize = std.math.maxInt(usize);
    var code: u32 = 0;
    var k: usize = 0;
    for (1..16) |l| {
        for (0..count[l]) |_| {
            const sym = sorted[k];
            k += 1;
            const rev: usize = @bitReverse(@as(u16, @intCast(code))) >> @intCast(16 - l);
            code += 1;
            const entry = @as(u32, sym) | @as(u32, @intCast(l)) << 16;
            if (l <= root) {
                var i = rev;
                while (i < root_size) : (i += @as(usize, 1) << @intCast(l)) table[i] = entry;
                continue;
            }
            const p = rev & (root_size - 1);
            if (p != prefix) {
                prefix = p;
                table[p] = sub_flag | @as(u32, @intCast(next_sub)) | @as(u32, sub_bits) << 20;
                if (left != 0) @memset(table[next_sub..][0 .. @as(usize, 1) << sub_bits], 0);
                next_sub += @as(usize, 1) << sub_bits;
            }
            const base: usize = table[p] & 0xffff;
            var i = rev >> root;
            while (i < @as(usize, 1) << sub_bits) : (i += @as(usize, 1) << @intCast(l - root)) table[base + i] = entry;
        }
        code <<= 1;
    }
}

const BitReader = struct {
    in: []const u8,
    pos: usize = 0,
    bits: u64 = 0,
    n: u7 = 0,
    /// Zero bytes read past the end of the input.
    over: usize = 0,

    /// At least 56 bits, unless the input (and 8 bytes of zeros past it)
    /// has run out.
    inline fn refill(r: *BitReader) Error!void {
        if (r.pos + 8 <= r.in.len) {
            r.bits |= std.mem.readInt(u64, r.in[r.pos..][0..8], .little) << @intCast(r.n);
            const k = (63 - @as(usize, r.n)) >> 3;
            r.pos += k;
            r.n += @intCast(k * 8);
            return;
        }
        while (r.n <= 56) {
            var b: u64 = 0;
            if (r.pos < r.in.len) {
                b = r.in[r.pos];
            } else {
                // The buffer holds 8 bytes: a ninth of padding means bits
                // past the end were used.
                if (r.over == 8) return error.InvalidData;
                r.over += 1;
            }
            r.pos += 1;
            r.bits |= b << @intCast(r.n);
            r.n += 8;
        }
    }

    inline fn take(r: *BitReader, k: u6) u32 {
        const v: u32 = @intCast(r.bits & ((@as(u64, 1) << k) - 1));
        r.bits >>= k;
        r.n -= k;
        return v;
    }

    /// Whether bits past the end of the input have been used.
    fn overrun(r: *const BitReader) bool {
        return r.n < r.over * 8;
    }

    inline fn decode(r: *BitReader, table: []const u32, root: u5) Error!u32 {
        var e = table[@intCast(r.bits & ((@as(u64, 1) << root) - 1))];
        if (e & sub_flag != 0) {
            const sb: u6 = @intCast((e >> 20) & 0xf);
            e = table[(e & 0xffff) + @as(usize, @intCast((r.bits >> root) & ((@as(u64, 1) << sb) - 1)))];
        }
        const l: u6 = @intCast((e >> 16) & 0xf);
        if (l == 0) return error.InvalidData;
        r.bits >>= l;
        r.n -= l;
        return e & 0xffff;
    }
};

/// Inflates one message: `input` is the payload with 00 00 ff ff after
/// it. Back references may reach into `window` (null: the client
/// compresses each message on its own). Returns whether the stream ended
/// with a final block (the next message starts a new one: reset the
/// window). The window is updated with the output.
pub fn inflate(t: *Tables, window: ?*Window, input: []const u8, out: *Out) Error!bool {
    var r: BitReader = .{ .in = input };
    const history: usize = if (window) |w| w.len else 0;
    var final = false;
    while (true) {
        try r.refill();
        if (r.overrun()) return error.InvalidData;
        final = r.take(1) == 1;
        switch (r.take(2)) {
            0 => {
                // Stored: whole bytes from the input, after the header's.
                _ = r.take(@intCast(r.n % 8));
                // Give back the whole bytes the reader holds; read on from
                // the input.
                r.pos -= r.n / 8;
                r.bits = 0;
                r.n = 0;
                if (r.pos > input.len) return error.InvalidData;
                r.over = 0;
                if (r.pos + 4 > input.len) return error.InvalidData;
                const len = std.mem.readInt(u16, input[r.pos..][0..2], .little);
                const nlen = std.mem.readInt(u16, input[r.pos + 2 ..][0..2], .little);
                if (len != ~nlen) return error.InvalidData;
                r.pos += 4;
                if (r.pos + len > input.len) return error.InvalidData;
                try out.reserve(len);
                @memcpy(out.buf[out.len..][0..len], input[r.pos..][0..len]);
                out.len += len;
                r.pos += len;
            },
            1 => try codes(&r, &t.fixed_lit, &t.fixed_dist, window, history, out),
            2 => {
                try dynamicHeader(t, &r);
                try codes(&r, &t.lit, &t.dist, window, history, out);
            },
            else => return error.InvalidData,
        }
        if (r.overrun()) return error.InvalidData;
        // The empty stored block that ends a message leaves nothing.
        const left_bits = (input.len - @min(input.len, r.pos)) * 8 + @as(usize, r.n) - r.over * 8;
        if (final or left_bits < 8) break;
    }
    if (window) |w| {
        if (final) {
            w.len = 0;
            w.end = 0;
        } else {
            w.append(out.buf[0..out.len]);
        }
    }
    return final;
}

fn dynamicHeader(t: *Tables, r: *BitReader) Error!void {
    try r.refill();
    const hlit = r.take(5) + 257;
    const hdist = r.take(5) + 1;
    const hclen = r.take(4) + 4;
    if (hlit > 286 or hdist > 30) return error.InvalidData;
    const order = [19]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    var cl_lens: [19]u8 = @splat(0);
    for (order[0..hclen]) |s| {
        try r.refill();
        cl_lens[s] = @intCast(r.take(3));
    }
    try build(&t.cl, &cl_lens, cl_root);
    var lens: [286 + 30]u8 = undefined;
    var lit_count: [16]u16 = @splat(0);
    var dist_count: [16]u16 = @splat(0);
    var i: usize = 0;
    const total = hlit + hdist;
    while (i < total) {
        try r.refill();
        const sym = try r.decode(&t.cl, cl_root);
        if (sym < 16) {
            lens[i] = @intCast(sym);
            if (i < hlit) lit_count[sym] += 1 else dist_count[sym] += 1;
            i += 1;
            continue;
        }
        const rep: usize, const value: u8 = switch (sym) {
            16 => blk: {
                if (i == 0) return error.InvalidData;
                break :blk .{ 3 + r.take(2), lens[i - 1] };
            },
            17 => .{ 3 + r.take(3), 0 },
            else => .{ 11 + r.take(7), 0 },
        };
        if (i + rep > total) return error.InvalidData;
        @memset(lens[i..][0..rep], value);
        // A run may cross from literal lengths into distance lengths.
        const in_lit = @min(rep, hlit -| i);
        lit_count[value] += @intCast(in_lit);
        dist_count[value] += @intCast(rep - in_lit);
        i += rep;
    }
    if (r.overrun()) return error.InvalidData;
    // A block needs its end code.
    if (lens[256] == 0) return error.InvalidData;
    try buildCounted(&t.lit, lens[0..hlit], lit_count, lit_root);
    try buildCounted(&t.dist, lens[hlit..][0..hdist], dist_count, dist_root);
}

const len_base = [29]u16{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
const len_extra = [29]u6{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
const dist_base = [30]u16{ 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
const dist_extra = [30]u6{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

/// One block's codes, up to its end code. The reader's and the output's
/// state live in locals here: stores into the output could otherwise alias
/// them and force reloads on every symbol.
fn codes(r: *BitReader, lit: []const u32, dist: []const u32, window: ?*Window, history: usize, out: *Out) Error!void {
    var br = r.*;
    defer r.* = br;
    var buf = out.buf;
    var len = out.len;
    defer out.len = len;
    const max = out.max;
    while (true) {
        try br.refill();
        if (br.over > 0 and br.overrun()) return error.InvalidData;
        const sym = try br.decode(lit, lit_root);
        if (sym < 256) {
            if (len + 9 > buf.len) {
                if (len + 1 > max) return error.MessageTooBig;
                out.len = len;
                try out.grow(len + 9);
                buf = out.buf;
            }
            buf[len] = @intCast(sym);
            len += 1;
            continue;
        }
        if (sym == 256) return;
        const lc = sym - 257;
        if (lc >= 29) return error.InvalidData;
        const n: usize = len_base[lc] + br.take(len_extra[lc]);
        const dc = try br.decode(dist, dist_root);
        if (dc >= 30) return error.InvalidData;
        const d: usize = dist_base[dc] + br.take(dist_extra[dc]);
        if (d > len + history) return error.InvalidData;
        if (len + n + 8 > buf.len) {
            if (len + n > max) return error.MessageTooBig;
            out.len = len;
            try out.grow(len + n + 8);
            buf = out.buf;
        }
        var o = len;
        var rest = n;
        if (d > o) {
            // From the window, then on in the output.
            const w = window.?;
            const back = d - o;
            const k = @min(rest, back);
            const start = (w.end + window_size - back) % window_size;
            const first = @min(k, window_size - start);
            @memcpy(buf[o..][0..first], w.buf[start..][0..first]);
            @memcpy(buf[o + first ..][0 .. k - first], w.buf[0 .. k - first]);
            o += k;
            rest -= k;
        }
        if (rest > 0) copyBack(buf, o, d, rest);
        len += n;
    }
}

/// Copies `n` bytes to `buf[o..]` from `d` back, overlapping as LZ77
/// does. May write up to 8 bytes past the end.
inline fn copyBack(buf: []u8, o: usize, d: usize, n: usize) void {
    var src = o - d;
    var dst = o;
    const end = o + n;
    if (d >= 8) {
        while (dst < end) {
            buf[dst..][0..8].* = buf[src..][0..8].*;
            dst += 8;
            src += 8;
        }
    } else if (d == 1) {
        @memset(buf[dst..end], buf[src]);
    } else {
        while (dst < end) {
            buf[dst] = buf[src];
            dst += 1;
            src += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const flate = std.compress.flate;
const compress = @import("./compress.zig");

/// Inflates a message (trailer included) with std's decompressor: the
/// reference. Clean ends only: the end of a final block within the message,
/// or input running out where a block would start, and then only if a final
/// empty fixed block appended (03 00) is read as one, with the output
/// unchanged (std reads a stored block's LEN and NLEN in its block-header
/// state, so a header cut short also runs out there; appending more than
/// that to every message would let a final block cut short read on into it).
fn stdInflate(message: []const u8, out: *std.ArrayList(u8)) !void {
    const window = try testing.allocator.alloc(u8, flate.max_window_len);
    defer testing.allocator.free(window);
    if (try stdRun(window, message, out)) return;
    const n = out.items.len;
    out.clearRetainingCapacity();
    const extended = try std.mem.concat(testing.allocator, u8, &.{ message, &.{ 0x03, 0x00 } });
    defer testing.allocator.free(extended);
    if (!try stdRun(window, extended, out) or out.items.len != n) return error.Corrupt;
}

/// True: a final block ended the stream. False: input ran out in the
/// block-header state.
fn stdRun(window: []u8, input: []const u8, out: *std.ArrayList(u8)) !bool {
    var in: std.Io.Reader = .fixed(input);
    var d: flate.Decompress = .init(&in, .raw, window);
    while (true) {
        const ready = d.reader.buffered();
        try out.appendSlice(testing.allocator, ready);
        d.reader.toss(ready.len);
        d.reader.fillMore() catch |err| switch (err) {
            error.EndOfStream => return true,
            error.ReadFailed => {
                if (d.err != @as(?flate.Decompress.Error, error.EndOfStream) or d.state != .block_header) return error.Corrupt;
                const rest = d.reader.buffered();
                try out.appendSlice(testing.allocator, rest);
                return false;
            },
        };
    }
}

const Harness = struct {
    pool: BufferPool,
    tables: *Tables,
    window: *Window,

    fn init() !Harness {
        const t = try testing.allocator.create(Tables);
        t.init();
        const w = try testing.allocator.create(Window);
        w.* = .{};
        return .{ .pool = try BufferPool.init(testing.allocator, 1024, 1), .tables = t, .window = w };
    }

    fn deinit(h: *Harness) void {
        testing.allocator.destroy(h.tables);
        testing.allocator.destroy(h.window);
        h.pool.deinit();
    }

    /// Inflates `deflated` (trailer appended here) into a new list.
    fn run(h: *Harness, deflated: []const u8, max: usize, takeover: bool) ![]u8 {
        const input = try std.mem.concat(testing.allocator, u8, &.{ deflated, &.{ 0, 0, 0xff, 0xff } });
        defer testing.allocator.free(input);
        var out: Out = .{ .buf = &.{}, .max = max, .pool = &h.pool };
        defer if (out.buf.len > 0) h.pool.releaseLarge(out.buf);
        _ = try inflate(h.tables, if (takeover) h.window else null, input, &out);
        return testing.allocator.dupe(u8, out.buf[0..out.len]);
    }
};

test "messages from std's compressor at every level, ours, and a stream with context takeover" {
    var h = try Harness.init();
    defer h.deinit();
    const json = "{\"userId\":12345,\"action\":\"purchase\",\"items\":[{\"id\":\"A1B2C3\",\"name\":\"Wireless Mouse\",\"price\":25.99}]} ";
    var big: [100_000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(5);
    for (&big, 0..) |*b, i| b.* = json[i % json.len];
    var k: usize = 0;
    while (k < big.len) : (k += 31) big[k] = prng.random().int(u8);
    var noise: [3000]u8 = undefined;
    prng.random().bytes(&noise);
    const messages = [_][]const u8{ "", "x", json, big[0..5000], &big, &noise };
    const c = try testing.allocator.create(compress.Compressor);
    defer testing.allocator.destroy(c);
    c.init();
    for (messages) |m| {
        // Ours.
        const buf = try testing.allocator.alloc(u8, m.len + m.len / 8 + 64);
        defer testing.allocator.free(buf);
        const n = c.compress(m, buf, 15).?;
        const got = try h.run(buf[0..n], 1 << 20, false);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, m, got);
        // std's, each level (dynamic, fixed and stored blocks).
        for ([_]flate.Compress.Options{ .level_1, .level_4, .level_9 }) |lvl| {
            var o: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 1 << 16);
            defer o.deinit();
            const window = try testing.allocator.alloc(u8, flate.max_window_len);
            defer testing.allocator.free(window);
            const sc = try testing.allocator.create(flate.Compress);
            defer testing.allocator.destroy(sc);
            sc.* = try .init(&o.writer, window, .raw, lvl);
            try sc.writer.writeAll(m);
            try sc.writer.flush();
            try o.writer.writeByte(0);
            const g = try h.run(o.written(), 1 << 20, false);
            defer testing.allocator.free(g);
            try testing.expectEqualSlices(u8, m, g);
        }
    }
    // Context takeover: later messages refer into earlier ones, across the
    // window ring's wrap.
    var client: @import("./deflate.zig").TestClient = undefined;
    try client.init();
    defer client.out.deinit();
    for (0..12) |i| {
        const m = big[i * 7000 ..][0..7000];
        const deflated = try client.message(m);
        defer testing.allocator.free(deflated);
        const got = try h.run(deflated[0 .. deflated.len - 4], 1 << 20, true);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, m, got);
    }
}

test "a final block ends the stream: the next message starts with an empty window" {
    var h = try Harness.init();
    defer h.deinit();
    var o: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 1 << 16);
    defer o.deinit();
    const window = try testing.allocator.alloc(u8, flate.max_window_len);
    defer testing.allocator.free(window);
    const sc = try testing.allocator.create(flate.Compress);
    defer testing.allocator.destroy(sc);
    sc.* = try .init(&o.writer, window, .raw, .default);
    try sc.writer.writeAll("final, final, final");
    try sc.finish();
    const got = try h.run(o.written(), 1 << 20, true);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("final, final, final", got);
    try testing.expectEqual(@as(usize, 0), h.window.len);
    var client: @import("./deflate.zig").TestClient = undefined;
    try client.init();
    defer client.out.deinit();
    const m = try client.message("a new stream");
    defer testing.allocator.free(m);
    const again = try h.run(m[0 .. m.len - 4], 1 << 20, true);
    defer testing.allocator.free(again);
    try testing.expectEqualStrings("a new stream", again);
}

test "corrupt input, distances too far, truncation and the size limit fail" {
    var h = try Harness.init();
    defer h.deinit();
    const cases = [_][]const u8{
        &.{0x07}, // block type 3
        &.{ 0x00, 0x05, 0x00, 0x00, 0x00 }, // stored LEN and NLEN disagree
        &.{ 0x00, 0x10, 0x00, 0xef, 0xff, 'a' }, // stored block cut short
    };
    for (cases) |cs| try testing.expectError(error.InvalidData, h.run(cs, 1 << 20, false));
    // Over-subscribed code lengths.
    var table: [lit_cap]u32 = undefined;
    try testing.expectError(error.InvalidData, build(&table, &.{ 1, 1, 1 }, lit_root));
    // A message that refers back into one this connection never had: the
    // second of a context-takeover stream, inflated without the first.
    var client: @import("./deflate.zig").TestClient = undefined;
    try client.init();
    defer client.out.deinit();
    const text = "repeated words, repeated words, repeated words";
    const first = try client.message(text);
    defer testing.allocator.free(first);
    const second = try client.message(text);
    defer testing.allocator.free(second);
    try testing.expectError(error.InvalidData, h.run(second[0 .. second.len - 4], 1 << 20, true));
    // A megabyte of zeros stops at the limit.
    const c = try testing.allocator.create(compress.Compressor);
    defer testing.allocator.destroy(c);
    c.init();
    const zeros = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(zeros);
    @memset(zeros, 0);
    var buf: [8192]u8 = undefined;
    const n = c.compress(zeros, &buf, 15).?;
    try testing.expectError(error.MessageTooBig, h.run(buf[0..n], 64 * 1024, false));
}

// Fuzz target, differential: bytes as a compressed message, and messages
// from std's compressor cut or flipped. Whatever std's decompressor
// accepts, this must give the same output for; nothing may crash or run
// past the size limit.
fn fuzzInflate(_: void, smith: *std.testing.Smith) anyerror!void {
    var h = try Harness.init();
    defer h.deinit();
    var raw: [4096]u8 = undefined;
    var input: []const u8 = raw[0..smith.slice(&raw)];
    var owned: ?[]u8 = null;
    defer if (owned) |o| testing.allocator.free(o);
    if (smith.value(u8) & 1 == 0 and input.len > 0) {
        // Compress it with std, then damage it a little.
        var o: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 1 << 13);
        defer o.deinit();
        const window = try testing.allocator.alloc(u8, flate.max_window_len);
        defer testing.allocator.free(window);
        const sc = try testing.allocator.create(flate.Compress);
        defer testing.allocator.destroy(sc);
        sc.* = try .init(&o.writer, window, .raw, .level_4);
        try sc.writer.writeAll(input);
        try sc.writer.flush();
        try o.writer.writeByte(0);
        const d = try o.toOwnedSlice();
        owned = d;
        switch (smith.value(u8) % 4) {
            0 => {},
            1 => d[smith.value(u16) % d.len] ^= @as(u8, 1) << @intCast(smith.value(u8) % 8),
            2 => owned = try testing.allocator.realloc(d, smith.value(u16) % d.len + 1),
            else => d[smith.value(u16) % d.len] = smith.value(u8),
        }
        input = owned.?;
    }
    const with_trailer = try std.mem.concat(testing.allocator, u8, &.{ input, &.{ 0, 0, 0xff, 0xff } });
    defer testing.allocator.free(with_trailer);

    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(testing.allocator);
    const std_ok = if (stdInflate(with_trailer, &want)) true else |_| false;

    var out: Out = .{ .buf = &.{}, .max = 256 * 1024, .pool = &h.pool };
    defer if (out.buf.len > 0) h.pool.releaseLarge(out.buf);
    const ours = inflate(h.tables, h.window, with_trailer, &out);
    if (std_ok and want.items.len <= out.max) {
        _ = try ours;
        try testing.expectEqualSlices(u8, want.items, out.buf[0..out.len]);
    }
    try testing.expect(out.len <= out.max);
}

test "fuzz: ws inflate" {
    try std.testing.fuzz({}, fuzzInflate, .{
        .corpus = &.{
            &[_]u8{ 0x00, 0x10, 'h', 'e', 'l', 'l', 'o', ' ', 'h', 'e', 'l', 'l', 'o', ' ', 'h', 'e', 'l', 'l', 'o' },
            &[_]u8{ 0x05, 0x00, 0x01, 0xe0, 0xff, 0xff },
            // Found by the fuzzer, where the reference took a message cut
            // short for a clean end: a stored header after a fixed block,
            // and a final block.
            &[_]u8{ 0x02, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            &[_]u8{ 0x05, 0x00, 0x00, 0x00, 0xdb, 0x63, 0x57, 0x36, 0x7d, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        },
    });
}
