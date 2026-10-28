//! TLS 1.3 over TCP for one connection, independent of the I/O model.
//!
//! The event loop reads ciphertext into `readSpace`, then takes decrypted
//! application data with `readPlain`; it hands application output to
//! `encrypt` and writes `wireBytes`. Handshake messages, alerts and
//! KeyUpdate responses also end up in the wire buffer. Like `Session`, the
//! connection holds a pooled input buffer only while it has unprocessed
//! bytes, and a pooled output buffer only while it has unsent bytes.
const std = @import("std");
const tls = std.crypto.tls;
const record = @import("./record.zig");
const handshake = @import("./handshake.zig");
const errors = @import("./errors.zig");
const BufferPool = @import("../http/session.zig").BufferPool;
const Protection = record.Protection;
const ContentType = record.ContentType;
const Level = handshake.Level;
const Suite = record.Suite;

pub const Config = handshake.Config;
pub const entropy_len = handshake.entropy_len;

/// Input buffers hold one maximum-size record.
pub const in_buffer_size = 17 * 1024;
/// Output buffers hold several records, so a large body goes out in fewer
/// writes.
pub const out_buffer_size = 4 * (record.max_plaintext + record.overhead);

comptime {
    std.debug.assert(in_buffer_size >= record.max_record);
}

/// Per-worker buffer pools shared by its TLS connections.
pub const Pools = struct {
    in: BufferPool,
    out: BufferPool,

    pub fn init(allocator: std.mem.Allocator, count: usize) !Pools {
        var in = try BufferPool.init(allocator, in_buffer_size, count);
        errdefer in.deinit();
        return .{ .in = in, .out = try BufferPool.init(allocator, out_buffer_size, count) };
    }

    pub fn deinit(self: *Pools) void {
        self.in.deinit();
        self.out.deinit();
    }
};

/// 0-RTT data the server rejects is skipped, up to this many bytes.
const max_skipped_early_data = 64 * 1024;

/// Records we seal under one key before sending KeyUpdate and switching.
/// RFC 8446 §5.5 allows AES-GCM about 2^24.5 full-size records per key;
/// this stays a power of two below. ChaCha20-Poly1305 has no such limit
/// (its sequence number would wrap first), but one rule for every suite is
/// simpler and costs one small record per 2^24.
pub const key_update_after = 1 << 24;

const key_update_not_requested = [_]u8{ @backingInt(tls.HandshakeType.key_update), 0, 0, 1, 0 };

pub const Conn = struct {
    const Self = @This();

    pools: *Pools,
    hs: ?*handshake.Handshake,
    read: ?Protection = null,
    write: ?Protection = null,
    read_level: Level = .initial,

    in_buf: []u8 = &.{},
    in_start: usize = 0,
    in_end: usize = 0,
    /// `in_buf` is the caller's (see `borrowInput`), not the pool's.
    borrowed: bool = false,
    /// Decrypted application data not yet taken (points into in_buf).
    plain: []u8 = &.{},

    wire_buf: []u8 = &.{},
    wire_start: usize = 0,
    wire_end: usize = 0,

    early_data_left: usize = 0,
    /// Negotiated ALPN protocol (points into the config), once established.
    alpn: ?[]const u8 = null,
    /// A fatal alert was queued: flush the wire, then close.
    failed: bool = false,
    /// The peer sent close_notify or an alert: no more input will come.
    peer_closed: bool = false,
    close_sent: bool = false,
    /// See `key_update_after`; lowered by tests.
    key_update_limit: u64 = key_update_after,

    pub fn init(allocator: std.mem.Allocator, pools: *Pools, config: *const Config, entropy: *const [entropy_len]u8) !Self {
        const hs = try allocator.create(handshake.Handshake);
        hs.* = .init(allocator, config, entropy);
        return .{ .pools = pools, .hs = hs };
    }

    pub fn deinit(self: *Self) void {
        self.freeHandshake();
        if (self.read) |*p| p.wipe();
        if (self.write) |*p| p.wipe();
        if (self.in_buf.len > 0 and !self.borrowed) self.pools.in.release(self.in_buf);
        if (self.wire_buf.len > 0) self.pools.out.release(self.wire_buf);
        self.* = undefined;
    }

    fn freeHandshake(self: *Self) void {
        if (self.hs) |hs| {
            const allocator = hs.allocator;
            hs.deinit();
            allocator.destroy(hs);
            self.hs = null;
        }
    }

    pub fn isEstablished(self: *const Self) bool {
        return self.hs == null and !self.failed;
    }

    pub fn isHandshaking(self: *const Self) bool {
        return self.hs != null;
    }

    // -- Input --------------------------------------------------------------

    /// Space to read ciphertext into. Empty while the buffer is full of
    /// decrypted data not yet taken with `readPlain`.
    pub fn readSpace(self: *Self) ![]u8 {
        std.debug.assert(!self.borrowed);
        if (self.in_buf.len == 0) {
            self.in_buf = try self.pools.in.acquire();
            self.in_start = 0;
            self.in_end = 0;
        }
        if (self.in_end == self.in_buf.len and self.plain.len == 0) self.compact();
        return self.in_buf[self.in_end..];
    }

    pub fn commitRead(self: *Self, n: usize) void {
        self.in_end += n;
    }

    /// Bytes to read before the buffered input ends on a record boundary
    /// (the header first, then the rest of the record), or 0 when nothing
    /// is buffered. Reading no more than this into `readSpace` lets the
    /// rest of a chunk go through `borrowInput`.
    pub fn partialRecordNeed(self: *const Self) usize {
        const avail = self.in_end - self.in_start;
        if (avail == 0 or self.failed or self.peer_closed) return 0;
        if (avail < record.header_len) return record.header_len - avail;
        const header = self.in_buf[self.in_start..][0..record.header_len];
        const len = std.mem.readInt(u16, header[3..5], .big);
        return (record.header_len + len) -| avail;
    }

    /// Whether `borrowInput` may be called: nothing is buffered.
    pub fn canBorrow(self: *const Self) bool {
        return self.in_start == self.in_end and self.plain.len == 0;
    }

    /// Processes ciphertext from `data` without copying it into the input
    /// buffer: records are decrypted in place or straight into `readPlain`'s
    /// destination. For a buffer the caller gets back (say, a kernel recv
    /// buffer): call `endBorrow` before `data` is reused.
    pub fn borrowInput(self: *Self, data: []u8) void {
        std.debug.assert(self.canBorrow() and !self.borrowed);
        if (self.in_buf.len > 0) self.pools.in.release(self.in_buf);
        self.in_buf = data;
        self.in_start = 0;
        self.in_end = data.len;
        self.borrowed = true;
    }

    /// Copies what is left of borrowed input (a partial record, or records
    /// not yet processed) into a pooled buffer. Dropped after a failure or
    /// the peer's close, since it would never be read.
    pub fn endBorrow(self: *Self) !void {
        std.debug.assert(self.borrowed);
        const plain = self.plain;
        const rest = self.in_buf[self.in_start..self.in_end];
        self.borrowed = false;
        self.in_buf = &.{};
        self.in_start = 0;
        self.in_end = 0;
        self.plain = &.{};
        if (self.failed or self.peer_closed or plain.len + rest.len == 0) return;
        if (plain.len + rest.len > in_buffer_size) return error.BufferFull;
        self.in_buf = try self.pools.in.acquire();
        @memcpy(self.in_buf[0..plain.len], plain);
        self.plain = self.in_buf[0..plain.len];
        @memcpy(self.in_buf[plain.len..][0..rest.len], rest);
        self.in_start = plain.len;
        self.in_end = plain.len + rest.len;
    }

    fn compact(self: *Self) void {
        const len = self.in_end - self.in_start;
        std.mem.copyForwards(u8, self.in_buf[0..len], self.in_buf[self.in_start..self.in_end]);
        self.in_start = 0;
        self.in_end = len;
    }

    /// Whether `readPlain` has work to do without another read: decrypted
    /// data, a complete record, or a header that is already invalid.
    pub fn hasBufferedInput(self: *const Self) bool {
        if (self.plain.len > 0) return true;
        const avail = self.in_end - self.in_start;
        if (avail < record.header_len or self.failed or self.peer_closed) return false;
        const header = self.in_buf[self.in_start..][0..record.header_len];
        const len = std.mem.readInt(u16, header[3..5], .big);
        return avail >= record.header_len + len or !headerValid(header);
    }

    fn headerValid(header: *const [record.header_len]u8) bool {
        const len = std.mem.readInt(u16, header[3..5], .big);
        return switch (@as(ContentType, @fromBackingInt(header[0]))) {
            .application_data => len <= record.max_ciphertext,
            .change_cipher_spec, .alert, .handshake => len <= record.max_plaintext,
            else => false,
        };
    }

    /// Moves decrypted application data into `out`, processing records
    /// (handshake, alerts, KeyUpdate) as needed. A record whose plaintext
    /// fits is decrypted straight into `out`; others are decrypted in place
    /// and copied. Returns 0 when more input is needed, or when `failed` or
    /// `peer_closed` is set.
    pub fn readPlain(self: *Self, out: []u8) usize {
        var n: usize = 0;
        while (n < out.len) {
            if (self.plain.len > 0) {
                const k = @min(self.plain.len, out.len - n);
                @memcpy(out[n..][0..k], self.plain[0..k]);
                self.plain = self.plain[k..];
                n += k;
                continue;
            }
            n += (self.nextRecord(out[n..]) catch |err| {
                self.fail(err);
                break;
            }) orelse break;
        }
        return n;
    }

    /// Return the input buffer to the pool when nothing is buffered.
    pub fn releaseIfIdle(self: *Self) void {
        if (self.in_buf.len > 0 and !self.borrowed and self.in_start == self.in_end and self.plain.len == 0) {
            self.pools.in.release(self.in_buf);
            self.in_buf = &.{};
            self.in_start = 0;
            self.in_end = 0;
        }
        if (self.wire_buf.len > 0 and self.wire_start == self.wire_end) {
            self.pools.out.release(self.wire_buf);
            self.wire_buf = &.{};
            self.wire_start = 0;
            self.wire_end = 0;
        }
    }

    /// Processes one record. Returns null if none is complete, else the
    /// number of application data bytes decrypted into `dst` (which may be
    /// clobbered beyond them).
    fn nextRecord(self: *Self, dst: []u8) (errors.Error || error{OutOfMemory})!?usize {
        if (self.failed or self.peer_closed) return null;
        const avail = self.in_end - self.in_start;
        if (avail < record.header_len) return null;
        const header = self.in_buf[self.in_start..][0..record.header_len];
        const content_type: ContentType = @fromBackingInt(header[0]);
        const len = std.mem.readInt(u16, header[3..5], .big);
        // Reject garbage (say, plaintext HTTP) without waiting for a
        // "record" of whatever length its bytes happen to encode.
        if (!headerValid(header)) return switch (content_type) {
            .change_cipher_spec, .alert, .handshake, .application_data => error.RecordOverflow,
            else => error.UnexpectedMessage,
        };
        if (avail < record.header_len + len) {
            // Make room for the rest of the record.
            if (!self.borrowed and self.in_start > 0 and self.in_start + record.header_len + len > self.in_buf.len) self.compact();
            return null;
        }
        const rec = self.in_buf[self.in_start..][0 .. record.header_len + len];
        self.in_start += rec.len;
        const body = rec[record.header_len..];

        switch (content_type) {
            .change_cipher_spec => {
                // Compatibility mode: one byte, 0x01, dropped while handshaking.
                if (self.hs == null or len != 1 or body[0] != 1) return error.UnexpectedMessage;
            },
            .alert => {
                // Plaintext alerts only make sense before keys exist, but a
                // client that failed to process the ServerHello sends one.
                if (self.hs == null) return error.UnexpectedMessage;
                try self.handleAlert(body);
            },
            .handshake => {
                if (self.read != null or len == 0) return error.UnexpectedMessage;
                try self.feedHandshake(.initial, body);
            },
            .application_data => {
                var p = &(self.read orelse {
                    // 0-RTT data sent with ClientHello1, arriving after our
                    // HelloRetryRequest: no keys at all yet.
                    if (self.early_data_left >= len) {
                        self.early_data_left -= len;
                        return 0;
                    }
                    return error.UnexpectedMessage;
                });
                const direct = dst.len >= Protection.innerLen(rec);
                const opened = (if (direct) p.openInto(rec, dst) else p.open(rec)) catch |err| {
                    // Rejected 0-RTT data is encrypted under keys we never
                    // derived: skip it (RFC 8446 §4.2.10).
                    if (err == error.BadRecordMac and self.early_data_left >= len) {
                        self.early_data_left -= len;
                        return 0;
                    }
                    return err;
                };
                self.early_data_left = 0;
                switch (opened.content_type) {
                    .application_data => {
                        if (self.hs != null) return error.UnexpectedMessage;
                        if (direct) return opened.data.len;
                        self.plain = opened.data;
                    },
                    .handshake => {
                        if (opened.data.len == 0) return error.UnexpectedMessage;
                        if (self.hs != null) {
                            try self.feedHandshake(self.read_level, opened.data);
                        } else {
                            try self.handlePostHandshake(opened.data);
                        }
                    },
                    .alert => try self.handleAlert(opened.data),
                    else => return error.UnexpectedMessage,
                }
            },
            else => return error.UnexpectedMessage,
        }
        return 0;
    }

    fn feedHandshake(self: *Self, level: Level, data: []const u8) !void {
        const hs = self.hs.?;
        const retrying = hs.isRetrying();
        var sink: Sink = .{ .conn = self };
        hs.feed(level, data, &sink) catch |err| switch (err) {
            error.OutOfMemory => return error.InternalError,
            else => |e| return e,
        };
        if (level == .initial) {
            // Rejected 0-RTT data is skipped (§4.2.10) from ClientHello1
            // until the first record that decrypts, or, after a
            // HelloRetryRequest, until ClientHello2 starts.
            self.early_data_left = if (hs.early_data_offered and !retrying) max_skipped_early_data else 0;
        }
        if (hs.isDone()) {
            self.alpn = hs.alpn;
            self.freeHandshake();
        }
    }

    fn handleAlert(self: *Self, body: []const u8) !void {
        if (body.len != 2) return error.DecodeError;
        const description: tls.Alert.Description = @fromBackingInt(body[1]);
        switch (description) {
            // Followed by close_notify; nothing to do.
            .user_canceled => {},
            // close_notify, or a fatal alert: either way no more input.
            else => self.peer_closed = true,
        }
    }

    /// After the handshake the client may only send KeyUpdate.
    fn handlePostHandshake(self: *Self, data: []const u8) !void {
        // KeyUpdate precedes a key change, so it must end its record and
        // can't be split across records.
        if (data.len != 5 or data[0] != @backingInt(tls.HandshakeType.key_update)) return error.UnexpectedMessage;
        if (std.mem.readInt(u24, data[1..4], .big) != 1) return error.DecodeError;
        const request: tls.KeyUpdateRequest = @fromBackingInt(data[4]);
        switch (request) {
            .update_not_requested => {},
            .update_requested => {
                // Answer under the current key, then switch (§4.6.3).
                try self.sendRecords(.handshake, &key_update_not_requested);
                self.write.?.update();
            },
            _ => return error.IllegalParameter,
        }
        self.read.?.update();
    }

    fn fail(self: *Self, err: (errors.Error || error{OutOfMemory})) void {
        const e: errors.Error = switch (err) {
            error.OutOfMemory => error.InternalError,
            else => |e| e,
        };
        self.failed = true;
        self.sendAlert(.fatal, errors.alertFor(e));
        self.freeHandshake();
    }

    fn sendAlert(self: *Self, level: tls.Alert.Level, description: tls.Alert.Description) void {
        if (self.close_sent) return;
        self.close_sent = true;
        // Best effort: if there is no memory for the alert, just close.
        self.sendRecords(.alert, &.{ @backingInt(level), @backingInt(description) }) catch {};
    }

    /// Queues close_notify: no more output after this.
    pub fn close(self: *Self) void {
        if (self.hs != null) return;
        self.sendAlert(.warning, .close_notify);
    }

    // -- Output -------------------------------------------------------------

    pub fn wireBytes(self: *const Self) []const u8 {
        return self.wire_buf[self.wire_start..self.wire_end];
    }

    pub fn hasWire(self: *const Self) bool {
        return self.wire_end > self.wire_start;
    }

    pub fn advance(self: *Self, n: usize) void {
        self.wire_start += n;
        if (self.wire_start == self.wire_end) {
            self.wire_start = 0;
            self.wire_end = 0;
        }
    }

    /// Free space at the end of the wire buffer, at least `min` bytes.
    fn reserve(self: *Self, min: usize) ![]u8 {
        if (self.wire_buf.len == 0) {
            self.wire_buf = try self.pools.out.acquire();
            self.wire_start = 0;
            self.wire_end = 0;
        }
        if (self.wire_buf.len - self.wire_end >= min) return self.wire_buf[self.wire_end..];
        const len = self.wire_end - self.wire_start;
        if (self.wire_buf.len - len >= min) {
            std.mem.copyForwards(u8, self.wire_buf[0..len], self.wire_buf[self.wire_start..self.wire_end]);
        } else {
            // Rare: a handshake flight larger than the buffer (a long
            // certificate chain).
            const new_buf = try self.pools.out.allocator.alloc(u8, len + min);
            @memcpy(new_buf[0..len], self.wire_buf[self.wire_start..self.wire_end]);
            self.pools.out.release(self.wire_buf);
            self.wire_buf = new_buf;
        }
        self.wire_start = 0;
        self.wire_end = len;
        return self.wire_buf[self.wire_end..];
    }

    /// Writes `data` as records of the given type, encrypted once keys
    /// exist.
    fn sendRecords(self: *Self, content_type: ContentType, data: []const u8) !void {
        var rest = data;
        while (true) {
            const chunk = rest[0..@min(rest.len, record.max_plaintext)];
            const out = try self.reserve(chunk.len + record.overhead);
            if (self.write) |*p| {
                self.wire_end += p.seal(out, content_type, chunk);
            } else {
                out[0] = @backingInt(content_type);
                out[1..3].* = .{ 3, 3 };
                std.mem.writeInt(u16, out[3..5], @intCast(chunk.len), .big);
                @memcpy(out[record.header_len..][0..chunk.len], chunk);
                self.wire_end += record.header_len + chunk.len;
            }
            rest = rest[chunk.len..];
            if (rest.len == 0) break;
        }
    }

    /// Encrypts as much of `parts` (taken in order, as one stream) as fits
    /// in the wire buffer. Returns the number of plaintext bytes consumed.
    pub fn encrypt(self: *Self, parts: []const []const u8) !usize {
        std.debug.assert(self.isEstablished());
        var total: usize = 0;
        for (parts) |p| total += p.len;
        var consumed: usize = 0;
        var part: usize = 0;
        var part_off: usize = 0;
        while (consumed < total) {
            if (self.write.?.seq >= self.key_update_limit) {
                // Only with room for it and some data after it: never grow
                // the buffer for this, the next call will do.
                const room = if (self.wire_buf.len == 0) out_buffer_size else self.wire_buf.len - (self.wire_end - self.wire_start);
                if (room < 2 * record.overhead + key_update_not_requested.len + 1) break;
                self.sendRecords(.handshake, &key_update_not_requested) catch |err| {
                    if (consumed > 0) break;
                    return err;
                };
                self.write.?.update();
            }
            const out = self.reserve(record.overhead + 1) catch |err| {
                if (consumed > 0) break;
                return err;
            };
            if (out.len < record.overhead + 1) break;
            const n = @min(total - consumed, record.max_plaintext, out.len - record.overhead);
            // Gather the plaintext where seal expects it, then seal in place.
            const dst = out[record.header_len..][0..n];
            var filled: usize = 0;
            while (filled < n) {
                const src = parts[part][part_off..];
                const k = @min(src.len, n - filled);
                @memcpy(dst[filled..][0..k], src[0..k]);
                filled += k;
                part_off += k;
                if (part_off == parts[part].len) {
                    part += 1;
                    part_off = 0;
                }
            }
            self.wire_end += self.write.?.seal(out, .application_data, dst);
            consumed += n;
            // Fill the buffer, but don't grow it for application data.
            if (self.wire_buf.len - self.wire_end < record.overhead + 1) break;
        }
        return consumed;
    }

    const Sink = struct {
        conn: *Self,
        pub const Error = error{OutOfMemory};

        pub fn handshakeData(self: *Sink, _: Level, bytes: []const u8) Error!void {
            try self.conn.sendRecords(.handshake, bytes);
        }

        pub fn changeCipherSpec(self: *Sink) Error!void {
            const out = try self.conn.reserve(6);
            out[0..6].* = .{ @backingInt(ContentType.change_cipher_spec), 3, 3, 0, 1, 1 };
            self.conn.wire_end += 6;
        }

        pub fn writeSecret(self: *Sink, _: Level, suite: Suite, secret: []const u8) Error!void {
            if (self.conn.write) |*p| p.wipe();
            self.conn.write = Protection.init(suite, secret);
        }

        pub fn readSecret(self: *Sink, level: Level, suite: Suite, secret: []const u8) Error!void {
            if (self.conn.read) |*p| p.wipe();
            self.conn.read = Protection.init(suite, secret);
            self.conn.read_level = level;
        }
    };
};

// -- Tests ----------------------------------------------------------------

const sys = @import("../sys.zig");
const credentials = @import("./credentials.zig");
const testing = std.testing;

pub const TestServer = struct {
    creds: credentials.Credentials,
    config: Config,
    pools: Pools,
    key_update_limit: u64 = key_update_after,
    /// Records sealed under the server's last key in the last session.
    last_write_seq: u64 = 0,

    pub fn init(self: *TestServer, cert: []const u8, key: []const u8) !void {
        self.key_update_limit = key_update_after;
        self.last_write_seq = 0;
        self.creds = try .fromPem(testing.allocator, cert, key);
        self.config = .{ .credentials = &self.creds, .alpn = &.{"http/1.1"} };
        self.pools = try .init(testing.allocator, 4);
    }

    pub fn deinit(self: *TestServer) void {
        self.pools.deinit();
        self.creds.deinit();
    }
};

pub fn testEntropy(seed: u8) [entropy_len]u8 {
    var e: [entropy_len]u8 = undefined;
    for (&e, 0..) |*b, i| b.* = @truncate(i *% 13 +% seed);
    return e;
}

/// std's TLS client: handshake, send `msg`, expect it echoed, close_notify.
fn stdClient(fd: sys.fd_t, msg: []const u8, seed: u8, result: *?anyerror) void {
    stdClientInner(fd, msg, seed) catch |err| {
        result.* = err;
    };
    sys.shutdownWrite(fd);
}

fn stdClientInner(fd: sys.fd_t, msg: []const u8, seed: u8) !void {
    const io = testing.io;
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    var in_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var out_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var reader = file.readerStreaming(io, &in_buf);
    var writer = file.writerStreaming(io, &out_buf);
    var read_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var write_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @truncate(i *% 7 +% seed);
    var client = try tls.Client.init(&reader.interface, &writer.interface, .{
        .host = .{ .explicit = "localhost" },
        .ca = .self_signed,
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = .{ .nanoseconds = @as(i96, sys.realtimeSeconds()) * std.time.ns_per_s },
    });
    try client.writer.writeAll(msg);
    try client.writer.flush();
    try writer.interface.flush();
    const echo = try testing.allocator.alloc(u8, msg.len);
    defer testing.allocator.free(echo);
    try client.reader.readSliceAll(echo);
    if (!std.mem.eql(u8, echo, msg)) return error.EchoMismatch;
    try client.end();
    try writer.interface.flush();
}

/// Serves one connection on a blocking socket: once `expect_len` bytes of
/// application data have arrived, sends them back (not before, or both
/// sides could block writing), then waits for close_notify.
fn echoServer(conn: *Conn, fd: sys.fd_t, expect_len: usize, transcript: ?*std.ArrayList(u8)) !void {
    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(testing.allocator);
    var plain: [8192]u8 = undefined;
    var echoed = false;
    while (true) {
        const space = try conn.readSpace();
        const n = try sys.read(fd, space);
        if (n == 0) return error.UnexpectedEof;
        if (transcript) |t| try t.appendSlice(testing.allocator, space[0..n]);
        conn.commitRead(n);
        while (true) {
            const k = conn.readPlain(&plain);
            if (k == 0) break;
            try received.appendSlice(testing.allocator, plain[0..k]);
        }
        try flushBlocking(conn, fd);
        if (conn.failed) return error.TlsFailed;
        if (!echoed and received.items.len == expect_len) {
            echoed = true;
            var sent: usize = 0;
            while (sent < received.items.len) {
                sent += try conn.encrypt(&.{received.items[sent..]});
                try flushBlocking(conn, fd);
            }
        }
        if (conn.peer_closed) {
            if (!echoed) return error.ShortMessage;
            conn.close();
            try flushBlocking(conn, fd);
            return;
        }
        conn.releaseIfIdle();
    }
}

fn flushBlocking(conn: *Conn, fd: sys.fd_t) !void {
    while (conn.hasWire()) conn.advance(try sys.write(fd, conn.wireBytes()));
}

pub fn runAgainstStdClient(server: *TestServer, msg: []const u8, transcript: ?*std.ArrayList(u8)) !void {
    const fds = try sys.socketPair();
    defer sys.close(fds[0]);
    var client_err: ?anyerror = null;
    const t = try std.Thread.spawn(.{}, stdClient, .{ fds[1], msg, 1, &client_err });
    var conn = try Conn.init(testing.allocator, &server.pools, &server.config, &testEntropy(5));
    defer conn.deinit();
    conn.key_update_limit = server.key_update_limit;
    const result = echoServer(&conn, fds[0], msg.len, transcript);
    // Unblock the client if the server gave up.
    sys.shutdownWrite(fds[0]);
    t.join();
    sys.close(fds[1]);
    if (client_err) |err| return err;
    try result;
    try testing.expectEqualStrings("http/1.1", conn.alpn orelse "http/1.1");
    server.last_write_seq = if (conn.write) |w| w.seq else 0;
}

test "handshake and echo with std's TLS client, every suite, group and key type" {
    const td = credentials.testdata;
    // std's client can't verify an Ed25519 CertificateVerify (its scheme
    // check has no Ed25519 case), so Ed25519 is checked with OpenSSL.
    const keys = [_][2][]const u8{
        .{ td.p256_cert, td.p256_key },
        .{ td.p384_cert, td.p384_key },
        .{ td.rsa2048_cert, td.rsa2048_key },
        .{ td.rsa4096_cert, td.rsa4096_key },
    };
    const suites = [_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 };
    const groups = [_]tls.NamedGroup{ .x25519_ml_kem768, .x25519, .secp256r1 };
    // A message larger than a record, so the echo spans several.
    var big: [40_000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);
    for (keys) |kc| for (suites) |suite| for (groups) |group| {
        var server: TestServer = undefined;
        try server.init(kc[0], kc[1]);
        defer server.deinit();
        server.config.suites = &.{suite};
        server.config.groups = &.{group};
        runAgainstStdClient(&server, &big, null) catch |err| {
            std.debug.print("suite {s} group {s}: {s}\n", .{ @tagName(suite), @tagName(group), @errorName(err) });
            return err;
        };
    };
}

test "std's TLS client follows our KeyUpdates" {
    const td = credentials.testdata;
    // 100 KB echoed as 7 records: a KeyUpdate after every 2.
    const big = try testing.allocator.alloc(u8, 100_000);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 3);
    for ([_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        var server: TestServer = undefined;
        try server.init(td.p256_cert, td.p256_key);
        defer server.deinit();
        server.config.suites = &.{suite};
        server.key_update_limit = 2;
        runAgainstStdClient(&server, big, null) catch |err| {
            std.debug.print("suite {s}: {s}\n", .{ @tagName(suite), @errorName(err) });
            return err;
        };
        // Without the KeyUpdates: 7 records and close_notify.
        try testing.expect(server.last_write_seq <= 3);
    }
}

test "split invariance: any split of the client's bytes gives identical output, copied or borrowed" {
    const td = credentials.testdata;
    var server: TestServer = undefined;
    try server.init(td.p256_cert, td.p256_key);
    defer server.deinit();

    // Record a real session (client entropy and server entropy are fixed,
    // so it is deterministic), then replay the client's bytes in pieces.
    var transcript: std.ArrayList(u8) = .empty;
    defer transcript.deinit(testing.allocator);
    // Long enough that its record outgrows `readPlain`'s buffer below.
    const msg = "GET / HTTP/1.1\r\nHost: x\r\nX-Pad: " ++ &@as([600]u8, @splat('a')) ++ "\r\n\r\n";
    try runAgainstStdClient(&server, msg, &transcript);
    const input = transcript.items;

    const Replay = struct {
        const Mode = enum {
            copy,
            /// As the io_uring worker does: each chunk sits in a buffer
            /// that is reused afterwards (poisoned here), and is borrowed
            /// once nothing is buffered.
            borrow,
            /// Borrow, but take only one piece of plaintext before the
            /// chunk ends, so the rest is kept by `endBorrow`.
            borrow_partial,
        };

        fn run(srv: *TestServer, bytes: []const u8, splits: []const usize, mode: Mode, wire: *std.ArrayList(u8), plain_out: *std.ArrayList(u8)) !void {
            var conn = try Conn.init(testing.allocator, &srv.pools, &srv.config, &testEntropy(5));
            defer conn.deinit();
            var pos: usize = 0;
            var si: usize = 0;
            var kernel: [2048]u8 = undefined;
            while (pos < bytes.len) {
                const want = if (si < splits.len) splits[si] else bytes.len - pos;
                si += 1;
                const len = @min(bytes.len - pos, want, kernel.len);
                @memcpy(kernel[0..len], bytes[pos..][0..len]);
                pos += len;
                var chunk = kernel[0..len];
                while (chunk.len > 0) {
                    if (mode != .copy and conn.canBorrow()) {
                        conn.borrowInput(chunk);
                        try drain(&conn, if (mode == .borrow) null else 1, wire, plain_out);
                        try conn.endBorrow();
                        @memset(&kernel, 0xaa);
                        break;
                    }
                    const space = try conn.readSpace();
                    const need = if (mode == .copy) 0 else conn.partialRecordNeed();
                    const k = @min(space.len, chunk.len, if (need > 0) need else chunk.len);
                    @memcpy(space[0..k], chunk[0..k]);
                    conn.commitRead(k);
                    chunk = chunk[k..];
                    try drain(&conn, null, wire, plain_out);
                }
            }
            try drain(&conn, null, wire, plain_out);
            try testing.expect(conn.peer_closed);
        }

        /// Echoes decrypted data (at most `limit` pieces of it).
        fn drain(conn: *Conn, limit: ?usize, wire: *std.ArrayList(u8), plain_out: *std.ArrayList(u8)) !void {
            var buf: [100]u8 = undefined;
            var pieces: usize = 0;
            while (limit == null or pieces < limit.?) : (pieces += 1) {
                const n = conn.readPlain(&buf);
                if (n == 0) break;
                try plain_out.appendSlice(testing.allocator, buf[0..n]);
                var sent: usize = 0;
                while (sent < n) sent += try conn.encrypt(&.{buf[sent..n]});
            }
            try wire.appendSlice(testing.allocator, conn.wireBytes());
            conn.advance(conn.wireBytes().len);
            try testing.expect(!conn.failed);
        }
    };

    var ref_wire: std.ArrayList(u8) = .empty;
    defer ref_wire.deinit(testing.allocator);
    var ref_plain: std.ArrayList(u8) = .empty;
    defer ref_plain.deinit(testing.allocator);
    try Replay.run(&server, input, &.{}, .copy, &ref_wire, &ref_plain);
    try testing.expectEqualStrings(msg, ref_plain.items);

    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    var splits: [4096]usize = undefined;
    for (0..300) |i| {
        const round = i / 3;
        const modes = [_]Replay.Mode{ .copy, .borrow, .borrow_partial };
        const mode = modes[i % 3];
        var n: usize = 0;
        var covered: usize = 0;
        while (covered < input.len and n < splits.len) : (n += 1) {
            splits[n] = if (round == 0) 1 else random.intRangeAtMost(usize, 1, 1500);
            covered += splits[n];
        }
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(testing.allocator);
        var plain: std.ArrayList(u8) = .empty;
        defer plain.deinit(testing.allocator);
        try Replay.run(&server, input, splits[0..n], mode, &wire, &plain);
        // Record boundaries in the output may differ (application data is
        // encrypted as it arrives), so compare the decrypted streams.
        try testing.expectEqualSlices(u8, ref_plain.items, plain.items);
        try testing.expectEqualSlices(u8, ref_wire.items[0..handshakeLen(ref_wire.items)], wire.items[0..handshakeLen(wire.items)]);
    }
}

/// Length of the server's handshake flight: everything before the first
/// record sealed under application keys. Records up to and including the
/// last handshake-key record are identical across splits.
fn handshakeLen(wire: []const u8) usize {
    // ServerHello, CCS, then one encrypted record holding the flight.
    var pos: usize = 0;
    for (0..3) |_| pos += record.header_len + std.mem.readInt(u16, wire[pos + 3 ..][0..2], .big);
    return pos;
}

fn expectAlert(input: []const u8, description: tls.Alert.Description) !void {
    const td = credentials.testdata;
    var server: TestServer = undefined;
    try server.init(td.p256_cert, td.p256_key);
    defer server.deinit();
    var conn = try Conn.init(testing.allocator, &server.pools, &server.config, &testEntropy(5));
    defer conn.deinit();
    const space = try conn.readSpace();
    @memcpy(space[0..input.len], input);
    conn.commitRead(input.len);
    var buf: [64]u8 = undefined;
    try testing.expectEqual(0, conn.readPlain(&buf));
    try testing.expect(conn.failed);
    const wire = conn.wireBytes();
    // Before any keys exist the alert is in plaintext.
    try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, @backingInt(description) }, wire);
}

test "malformed records get the right alert" {
    // Oversized plaintext record.
    try expectAlert(&.{ 22, 3, 1, 0x40, 0x01 }, .record_overflow);
    // Unknown content type.
    try expectAlert(&.{ 99, 3, 3, 0, 1, 0 }, .unexpected_message);
    // Application data before keys.
    try expectAlert(&.{ 23, 3, 3, 0, 1, 0 }, .unexpected_message);
    // Empty handshake record.
    try expectAlert(&.{ 22, 3, 1, 0, 0 }, .unexpected_message);
    // change_cipher_spec with the wrong value.
    try expectAlert(&.{ 20, 3, 3, 0, 1, 2 }, .unexpected_message);
    // A message other than ClientHello first.
    try expectAlert(&.{ 22, 3, 1, 0, 4, 20, 0, 0, 0 }, .unexpected_message);
    // A ClientHello claiming more than the limit.
    try expectAlert(&.{ 22, 3, 1, 0, 4, 1, 0xff, 0xff, 0xff }, .decode_error);
}

test "KeyUpdate in both directions" {
    const td = credentials.testdata;
    var server: TestServer = undefined;
    try server.init(td.p256_cert, td.p256_key);
    defer server.deinit();
    var conn = try Conn.init(testing.allocator, &server.pools, &server.config, &testEntropy(5));
    defer conn.deinit();
    // Pretend the handshake finished with known secrets.
    conn.freeHandshake();
    const c_secret: [32]u8 = @splat(1);
    const s_secret: [32]u8 = @splat(2);
    conn.read = .init(.aes_128_gcm_sha256, &c_secret);
    conn.write = .init(.aes_128_gcm_sha256, &s_secret);
    var client_tx: Protection = .init(.aes_128_gcm_sha256, &c_secret);
    var client_rx: Protection = .init(.aes_128_gcm_sha256, &s_secret);

    // KeyUpdate(update_requested), then data under the next key.
    const space = try conn.readSpace();
    var n = client_tx.seal(space, .handshake, &.{ 24, 0, 0, 1, 1 });
    client_tx.update();
    n += client_tx.seal(space[n..], .application_data, "after");
    conn.commitRead(n);
    var buf: [16]u8 = undefined;
    try testing.expectEqual(5, conn.readPlain(&buf));
    try testing.expectEqualStrings("after", buf[0..5]);

    // The server answered under its old key, then switched.
    try testing.expectEqual(5, try conn.encrypt(&.{"reply"}));
    var wire: [256]u8 = undefined;
    const w = conn.wireBytes();
    @memcpy(wire[0..w.len], w);
    const first_len = record.header_len + std.mem.readInt(u16, wire[3..5], .big);
    const ku = try client_rx.open(wire[0..first_len]);
    try testing.expectEqual(ContentType.handshake, ku.content_type);
    try testing.expectEqualSlices(u8, &.{ 24, 0, 0, 1, 0 }, ku.data);
    client_rx.update();
    const reply = try client_rx.open(wire[first_len..w.len]);
    try testing.expectEqualStrings("reply", reply.data);

    // A KeyUpdate with an invalid request value is fatal.
    const space2 = try conn.readSpace();
    n = client_tx.seal(space2, .handshake, &.{ 24, 0, 0, 1, 7 });
    conn.commitRead(n);
    try testing.expectEqual(0, conn.readPlain(&buf));
    try testing.expect(conn.failed);
}

/// Appends a plaintext handshake record holding `msg`.
fn plainRecord(out: []u8, msg: []const u8) []u8 {
    out[0..5].* = .{ 22, 3, 1, 0, 0 };
    std.mem.writeInt(u16, out[3..5], @intCast(msg.len), .big);
    @memcpy(out[5..][0..msg.len], msg);
    return out[0 .. 5 + msg.len];
}

fn feedConn(conn: *Conn, bytes: []const u8) !void {
    const space = try conn.readSpace();
    @memcpy(space[0..bytes.len], bytes);
    conn.commitRead(bytes.len);
    var buf: [64]u8 = undefined;
    try testing.expectEqual(0, conn.readPlain(&buf));
}

test "0-RTT data after a HelloRetryRequest is skipped until ClientHello2" {
    // Found by the tls.Conn fuzz harness: a client offering 0-RTT sends
    // early data right after ClientHello1. If the server answers with a
    // HelloRetryRequest, that data arrives before ClientHello2, with no
    // keys yet, and must be skipped (RFC 8446 §4.2.10), not rejected.
    const td = credentials.testdata;
    var server: TestServer = undefined;
    try server.init(td.p256_cert, td.p256_key);
    defer server.deinit();
    server.config.groups = &.{.x25519};
    var conn = try Conn.init(testing.allocator, &server.pools, &server.config, &testEntropy(5));
    defer conn.deinit();

    var hello_buf: [2048]u8 = undefined;
    var rec: [2048]u8 = undefined;
    const early_data_ext = "\x00\x2a\x00\x00";
    // No key share: HelloRetryRequest.
    const ch1 = handshake.buildClientHello(&hello_buf, .{ .groups = &.{.x25519}, .extra = early_data_ext });
    try feedConn(&conn, plainRecord(&rec, ch1));
    try testing.expect(!conn.failed and conn.hasWire());
    conn.advance(conn.wireBytes().len);

    // 0-RTT records under keys the server never derived.
    var early: [5 + 40]u8 = @splat(0xa5);
    early[0..5].* = .{ 23, 3, 3, 0, 40 };
    try feedConn(&conn, &early);
    try feedConn(&conn, &early);
    try testing.expect(!conn.failed);

    const x = std.crypto.dh.X25519.recoverPublicKey(@splat(5));
    const ch2 = handshake.buildClientHello(&hello_buf, .{ .groups = &.{.x25519}, .shares = &.{.{ .group = .x25519, .key_exchange = &x }} });
    try feedConn(&conn, plainRecord(&rec, ch2));
    try testing.expect(!conn.failed and conn.hasWire());
    conn.advance(conn.wireBytes().len);

    // Early data ends with ClientHello2: an undecryptable record now fails.
    try feedConn(&conn, &early);
    try testing.expect(conn.failed);
}

test "KeyUpdate before the record limit of a key" {
    const td = credentials.testdata;
    var server: TestServer = undefined;
    try server.init(td.p256_cert, td.p256_key);
    defer server.deinit();
    inline for (.{ Suite.aes_128_gcm_sha256, Suite.aes_256_gcm_sha384, Suite.chacha20_poly1305_sha256 }) |suite| {
        var conn = try Conn.init(testing.allocator, &server.pools, &server.config, &testEntropy(5));
        defer conn.deinit();
        conn.freeHandshake();
        const secret: [48]u8 = @splat(2);
        conn.write = .init(suite, secret[0..suite.hashLen()]);
        conn.read = .init(suite, secret[0..suite.hashLen()]);
        conn.key_update_limit = 3;
        var client_rx: Protection = .init(suite, secret[0..suite.hashLen()]);

        // 20 full records' worth, written as the buffer drains.
        const data = try testing.allocator.alloc(u8, 20 * record.max_plaintext);
        defer testing.allocator.free(data);
        for (data, 0..) |*b, i| b.* = @truncate(i *% 7);
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(testing.allocator);
        var sent: usize = 0;
        while (sent < data.len) {
            sent += try conn.encrypt(&.{data[sent..]});
            try wire.appendSlice(testing.allocator, conn.wireBytes());
            conn.advance(conn.wireBytes().len);
        }

        // A KeyUpdate (not requesting one back) after every 3 records under
        // a key; the client follows them and gets all the data.
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(testing.allocator);
        var pos: usize = 0;
        var since_update: usize = 0;
        var updates: usize = 0;
        while (pos < wire.items.len) {
            const len = record.header_len + std.mem.readInt(u16, wire.items[pos + 3 ..][0..2], .big);
            const opened = try client_rx.open(wire.items[pos..][0..len]);
            pos += len;
            since_update += 1;
            switch (opened.content_type) {
                .application_data => try got.appendSlice(testing.allocator, opened.data),
                .handshake => {
                    try testing.expectEqualSlices(u8, &key_update_not_requested, opened.data);
                    try testing.expectEqual(4, since_update);
                    client_rx.update();
                    since_update = 0;
                    updates += 1;
                },
                else => return error.UnexpectedRecord,
            }
        }
        try testing.expectEqualSlices(u8, data, got.items);
        try testing.expectEqual(6, updates);
    }
}

test "close_notify from the peer ends input" {
    const td = credentials.testdata;
    var server: TestServer = undefined;
    try server.init(td.p256_cert, td.p256_key);
    defer server.deinit();
    var conn = try Conn.init(testing.allocator, &server.pools, &server.config, &testEntropy(5));
    defer conn.deinit();
    conn.freeHandshake();
    const secret: [32]u8 = @splat(1);
    conn.read = .init(.aes_128_gcm_sha256, &secret);
    conn.write = .init(.aes_128_gcm_sha256, &secret);
    var client_tx: Protection = .init(.aes_128_gcm_sha256, &secret);
    const space = try conn.readSpace();
    var n = client_tx.seal(space, .application_data, "last");
    n += client_tx.seal(space[n..], .alert, &.{ 1, 0 });
    // Anything after close_notify is ignored.
    n += client_tx.seal(space[n..], .application_data, "ignored");
    conn.commitRead(n);
    var buf: [16]u8 = undefined;
    try testing.expectEqual(4, conn.readPlain(&buf));
    try testing.expectEqual(0, conn.readPlain(&buf));
    try testing.expect(conn.peer_closed);
    try testing.expect(!conn.failed);
    conn.close();
    try testing.expect(conn.hasWire());
}
