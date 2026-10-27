//! AES-GCM for TLS records on aarch64 with the AES and PMULL instructions.
//! Counter mode and GHASH run in one pass over the data, eight blocks at a
//! time, with one GHASH reduction per eight blocks. std's AES-GCM makes two
//! passes, and its AES rounds run `aese` with a zero key and XOR each round
//! key separately; here the round key goes into `aese` itself, so each round
//! is an `aese`/`aesmc` pair the CPU fuses.
//!
//! GHASH follows std's representation (ghash_polyval.zig): blocks are read
//! as big-endian 128-bit integers, H is pre-shifted by one bit, and products
//! are reduced with the same two folding multiplications. Output is
//! identical to std.crypto.aead.aes_gcm (see the tests in record.zig).
const std = @import("std");
const builtin = @import("builtin");

/// Whether this implementation is available for the target. Elsewhere,
/// record.zig keeps using std's AES and GHASH.
pub const supported = builtin.cpu.arch == .aarch64 and
    builtin.cpu.has(.aarch64, .aes) and
    builtin.zig_backend != .stage2_c;

pub const tag_len = 16;

/// Blocks per iteration of the main loop: GHASH's aggregation width.
const width = 8;

/// A block as bytes, for AES.
const B = @Vector(16, u8);
/// A block as a 128-bit integer (lane 0 is the low half), for GHASH.
const U = @Vector(2, u64);

/// One AES round: AddRoundKey(k), SubBytes, ShiftRows, MixColumns.
inline fn round(b: B, k: B) B {
    return asm (
        \\ aese %[b].16b, %[k].16b
        \\ aesmc %[b].16b, %[b].16b
        : [b] "=w" (-> B),
        : [_] "0" (b),
          [k] "w" (k),
    );
}

/// The last round's AddRoundKey(k), SubBytes and ShiftRows (no MixColumns;
/// the caller XORs the final round key).
inline fn roundLast(b: B, k: B) B {
    return asm (
        \\ aese %[b].16b, %[k].16b
        : [b] "=w" (-> B),
        : [_] "0" (b),
          [k] "w" (k),
    );
}

/// Carry-less product of the low halves.
inline fn pmull(a: U, b: U) U {
    return asm (
        \\ pmull %[r].1q, %[a].1d, %[b].1d
        : [r] "=w" (-> U),
        : [a] "w" (a),
          [b] "w" (b),
    );
}

/// Carry-less product of the high halves.
inline fn pmull2(a: U, b: U) U {
    return asm (
        \\ pmull2 %[r].1q, %[a].2d, %[b].2d
        : [r] "=w" (-> U),
        : [a] "w" (a),
          [b] "w" (b),
    );
}

inline fn load(p: *const [16]u8) B {
    return @as(*align(1) const B, @ptrCast(p)).*;
}

inline fn store(p: *[16]u8, b: B) void {
    @as(*align(1) B, @ptrCast(p)).* = b;
}

/// A counter block as four big-endian 32-bit words, so incrementing the
/// last word (GCM's inc32) is a vector add.
const Counter = @Vector(4, u32);

inline fn counterBlock(c: Counter) B {
    return @bitCast(@byteSwap(c));
}

const reverse = [16]i32{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

/// A block's bytes as a big-endian 128-bit integer, and back.
inline fn toU(b: B) U {
    return @bitCast(@shuffle(u8, b, undefined, reverse));
}

inline fn toB(u: U) B {
    return @shuffle(u8, @as(B, @bitCast(u)), undefined, reverse);
}

inline fn swap(u: U) U {
    return @shuffle(u64, u, undefined, [2]i32{ 1, 0 });
}

/// An unreduced 256-bit product, as std's I256: lo + mid·2^64 + hi·2^128.
const Product = struct {
    lo: U = @splat(0),
    mid: U = @splat(0),
    hi: U = @splat(0),

    /// Adds x·h, where `hs` is `h` with its halves swapped.
    inline fn add(p: *Product, x: U, h: U, hs: U) void {
        p.lo ^= pmull(x, h);
        p.hi ^= pmull2(x, h);
        p.mid ^= pmull(x, hs) ^ pmull2(x, hs);
    }

    /// Reduces modulo x^128 + x^127 + x^126 + x^121 + 1, as std's `reduce`.
    inline fn reduce(p: Product) U {
        const zero: U = @splat(0);
        const hi = p.hi ^ @shuffle(u64, p.mid, zero, [2]i32{ 1, -1 });
        const lo = p.lo ^ @shuffle(u64, zero, p.mid, [2]i32{ 0, -1 });
        const poly: U = .{ 0xc200000000000000, 0 };
        const b = swap(lo) ^ pmull(lo, poly);
        return swap(b) ^ pmull(b, poly) ^ hi;
    }
};

pub fn Key(comptime Aes: type) type {
    return struct {
        const Self = @This();
        const rounds = Aes.rounds;

        /// Round keys 0..rounds.
        rk: [rounds + 1]B,
        /// H^1..H^8 (h[i] = H^(i+1)), and the same with halves swapped.
        h: [width]U,
        hs: [width]U,

        pub fn init(key: [Aes.key_bits / 8]u8) Self {
            var ctx = Aes.initEnc(key);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&ctx));
            var self: Self = undefined;
            for (&self.rk, ctx.key_schedule.round_keys) |*r, k| r.* = @bitCast(k.repr);
            const h_bytes = self.block(@splat(0));
            // Shift H by one bit, reducing for GCM, as std's Ghash.init.
            var h: u128 = @bitCast(toU(h_bytes));
            const carry = ((@as(u128, 0xc2) << 120) | 1) & (@as(u128, 0) -% (h >> 127));
            h = (h << 1) ^ carry;
            self.h[0] = @bitCast(h);
            self.hs[0] = swap(self.h[0]);
            for (1..width) |i| {
                var p: Product = .{};
                p.add(self.h[i - 1], self.h[0], self.hs[0]);
                self.h[i] = p.reduce();
                self.hs[i] = swap(self.h[i]);
            }
            return self;
        }

        inline fn block(self: *const Self, in: B) B {
            var b = in;
            inline for (self.rk[0 .. rounds - 1]) |k| b = round(b, k);
            return roundLast(b, self.rk[rounds - 1]) ^ self.rk[rounds];
        }

        /// The keystream for `n` counter blocks from `ctr`.
        inline fn keystream(self: *const Self, comptime n: usize, ctr: Counter) [n]B {
            var b: [n]B = undefined;
            inline for (&b, 0..) |*x, i| x.* = counterBlock(ctr +% Counter{ 0, 0, 0, i });
            inline for (self.rk[0 .. rounds - 1]) |k| {
                inline for (&b) |*x| x.* = round(x.*, k);
            }
            inline for (&b) |*x| x.* = roundLast(x.*, self.rk[rounds - 1]) ^ self.rk[rounds];
            return b;
        }

        /// Folds `n` (1..width) blocks into the GHASH accumulator.
        inline fn ghash(self: *const Self, acc: U, x: *const [width]B, n: usize) U {
            var p: Product = .{};
            for (0..n) |i| {
                var u = toU(x[i]);
                if (i == 0) u ^= acc;
                p.add(u, self.h[n - 1 - i], self.hs[n - 1 - i]);
            }
            return p.reduce();
        }

        /// GHASH over `data`, zero-padded to whole blocks.
        fn ghashPadded(self: *const Self, acc_in: U, data: []const u8) U {
            var acc = acc_in;
            var i: usize = 0;
            while (i < data.len) {
                const chunk = @min(data.len - i, width * 16);
                var x: [width]B = @splat(@splat(0));
                @memcpy(std.mem.sliceAsBytes(&x)[0..chunk], data[i..][0..chunk]);
                acc = self.ghash(acc, &x, std.math.divCeil(usize, chunk, 16) catch unreachable);
                i += chunk;
            }
            return acc;
        }

        /// Counter mode from block 2 over `in` into `out`, with GHASH over
        /// the ciphertext (`out` when encrypting, `in` when decrypting).
        /// `out` may alias `in`. Returns the tag.
        inline fn crypt(self: *const Self, comptime encrypting: bool, out: []u8, in: []const u8, ad: []const u8, npub: [12]u8) [tag_len]u8 {
            std.debug.assert(out.len == in.len);
            const j0: Counter = @byteSwap(@as(Counter, @bitCast(npub ++ [4]u8{ 0, 0, 0, 1 })));
            var acc = self.ghashPadded(@splat(0), ad);
            var ctr = j0 +% Counter{ 0, 0, 0, 1 };
            var i: usize = 0;
            while (i + width * 16 <= in.len) : (i += width * 16) {
                // One slice per chunk: one bounds check in safe builds.
                const src = in[i..][0 .. width * 16];
                const dst = out[i..][0 .. width * 16];
                var x: [width]B = undefined;
                inline for (&x, 0..) |*b, k| b.* = load(src[16 * k ..][0..16]);
                const ks = self.keystream(width, ctr);
                ctr +%= Counter{ 0, 0, 0, width };
                inline for (&x, ks, 0..) |*b, s, k| {
                    const y = b.* ^ s;
                    store(dst[16 * k ..][0..16], y);
                    if (encrypting) b.* = y;
                }
                acc = self.ghash(acc, &x, width);
            }
            if (i < in.len) {
                const rest = in.len - i;
                var x: [width]B = @splat(@splat(0));
                @memcpy(std.mem.sliceAsBytes(&x)[0..rest], in[i..]);
                // Short records need only a few blocks of keystream.
                var ks: [width]B = undefined;
                if (rest <= width * 8) {
                    ks[0 .. width / 2].* = self.keystream(width / 2, ctr);
                } else {
                    ks = self.keystream(width, ctr);
                }
                var y: [width]B = undefined;
                for (&y, x, ks) |*d, b, s| d.* = b ^ s;
                const y_bytes = std.mem.sliceAsBytes(&y);
                @memcpy(out[i..], y_bytes[0..rest]);
                if (encrypting) {
                    @memset(y_bytes[rest..], 0);
                    x = y;
                }
                acc = self.ghash(acc, &x, std.math.divCeil(usize, rest, 16) catch unreachable);
            }
            var lengths: [width]B = undefined;
            lengths[0] = toB(.{ @as(u64, in.len) * 8, @as(u64, ad.len) * 8 });
            acc = self.ghash(acc, &lengths, 1);
            return toB(acc) ^ self.block(counterBlock(j0));
        }

        pub fn encrypt(self: *const Self, c: []u8, tag: *[tag_len]u8, m: []const u8, ad: []const u8, npub: [12]u8) void {
            tag.* = self.crypt(true, c, m, ad, npub);
        }

        /// Decrypts while authenticating, so on failure `m` is zeroed
        /// rather than left holding unauthenticated plaintext. `m` may alias
        /// `c`.
        pub fn decrypt(self: *const Self, m: []u8, c: []const u8, tag: [tag_len]u8, ad: []const u8, npub: [12]u8) error{AuthenticationFailed}!void {
            var computed = self.crypt(false, m, c, ad, npub);
            defer std.crypto.secureZero(u8, &computed);
            if (!std.crypto.timing_safe.eql([tag_len]u8, computed, tag)) {
                std.crypto.secureZero(u8, m);
                return error.AuthenticationFailed;
            }
        }
    };
}
