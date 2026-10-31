//! OCSP responses from files (`TlsOptions.ocsp_response_path`,
//! `TlsCertificate.ocsp_response_path`): read when the server starts, then
//! every `ocsp_reload_interval_s` by a thread of their own, which hands a
//! response that changed to the handshakes through the certificate's
//! `ocsp.Staple`. Workers never touch the files.
//!
//! Each round reads every file whole and compares it with what was last
//! decided on: the files are small and the rounds far apart, and a
//! modification time can miss a rewrite (coarse timestamps). Files are
//! opened without blocking and must be regular files (a FIFO with no
//! writer would hold the thread, and server init, forever).
//!
//! A response is stapled only if `ocsp.check` passes for the certificate's
//! chain (successful, for this certificate, signed by the issuer or a
//! responder it delegated to, good, current); otherwise it is logged and
//! skipped. A file that can't be read or doesn't pass leaves the last
//! good response in place: it is stapled until it expires (checked at
//! each handshake), which keeps a half-written file or a failed fetch from
//! removing a response that is still valid. The exception is news: a
//! current response, properly signed, saying the certificate is revoked
//! stops stapling altogether, logged as an error (unknown doesn't: it is
//! often a responder's passing trouble). A response older than the newest
//! verified one isn't stapled (a cached good response must not undo a
//! revocation). A verified response the time refuses (expired, not valid
//! yet, the responder's certificate not current) is checked against the
//! clock again each round, without parsing it again. Each problem is
//! logged once (until it changes), and expiry once.
//!
//! Fetching responses from the CA's responder is left to a job that
//! writes the file (for example `openssl ocsp -issuer ... -cert ... -url
//! ... -respout`, run well before nextUpdate), ideally by writing a
//! temporary file and renaming it over the old one.
const std = @import("std");
const sys = @import("./sys.zig");
const ocsp = @import("./tls/ocsp.zig");
const Credentials = @import("./tls/credentials.zig").Credentials;

const log = std.log.scoped(.peregrine);

pub const Source = struct {
    /// Its `ocsp` is set to the watcher's staple for it.
    credentials: *Credentials,
    path: []const u8,
};

pub const Watcher = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    entries: []Entry,
    interval_ms: i32,
    /// Ends the thread promptly at `deinit`.
    waker: sys.Waker,
    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    /// Synchronous file I/O only (no thread pool, no signal handlers).
    threaded: std.Io.Threaded = .init_single_threaded,
    /// The clock (tests set a fixed one).
    now: *const fn () i64 = sys.realtimeSeconds,
    /// Responses parsed and verified (for tests: unchanged bytes aren't).
    verified: u64 = 0,

    const Entry = struct {
        path: [:0]u8,
        chain: []const []const u8,
        staple: ocsp.Staple,
        /// The file's contents as last read and verified (or refused): the
        /// same bytes again aren't parsed or verified again.
        last: ?[]u8 = null,
        /// What `ocsp.verify` found in `last`, while the time may still
        /// change the answer (a response not valid yet, expired, its
        /// responder's certificate not current): `ocsp.evaluate` is run
        /// again each round. Null once decided for good.
        pending: ?ocsp.Verified = null,
        /// The largest thisUpdate of a current, verified response (good,
        /// revoked or unknown): an older one doesn't replace it (a cached
        /// good response must not undo a revocation).
        newest: i64 = std.math.minInt(i64),
        /// The last problem logged (logged again only when it changes).
        warning: [256]u8 = undefined,
        warning_len: usize = 0,
        scratch: [256]u8 = undefined,
        /// The expiry of the current response was logged.
        expiry_logged: bool = false,

        fn deinit(e: *Entry, allocator: std.mem.Allocator) void {
            e.staple.deinit();
            if (e.last) |l| allocator.free(l);
            allocator.free(e.path);
        }
    };

    /// Reads every file once (logging and skipping what doesn't pass),
    /// points each certificate at its staple, and with `interval_s` > 0
    /// starts the thread that rereads them.
    pub fn init(allocator: std.mem.Allocator, sources: []const Source, interval_s: u32) !*Self {
        const entries = try allocator.alloc(Entry, sources.len);
        errdefer allocator.free(entries);
        var made: usize = 0;
        errdefer for (entries[0..made]) |*e| e.deinit(allocator);
        for (sources, entries) |src, *e| {
            e.* = .{
                .path = try allocator.dupeSentinel(u8, src.path, 0),
                .chain = src.credentials.chain,
                .staple = .init(allocator),
            };
            made += 1;
        }
        const waker: sys.Waker = try .init();
        errdefer waker.deinit();
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .entries = entries,
            .interval_ms = @intCast(@min(@as(u64, interval_s) * 1000, std.math.maxInt(i32))),
            .waker = waker,
        };
        self.checkAll();
        if (interval_s > 0) self.thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, run, .{self});
        // Only once nothing can fail: a failed init leaves the
        // credentials as they were.
        for (sources, self.entries) |src, *e| src.credentials.ocsp = &e.staple;
        return self;
    }

    /// Stops the thread. No handshake may be using the staples any more.
    pub fn deinit(self: *Self) void {
        self.stop.store(true, .release);
        self.waker.wake();
        if (self.thread) |t| t.join();
        self.waker.deinit();
        for (self.entries) |*e| e.deinit(self.allocator);
        self.allocator.free(self.entries);
        self.allocator.destroy(self);
    }

    fn run(self: *Self) void {
        while (true) {
            var fds = [_]std.posix.pollfd{.{ .fd = self.waker.read_fd, .events = std.posix.POLL.IN, .revents = 0 }};
            _ = std.posix.poll(&fds, self.interval_ms) catch {};
            if (self.stop.load(.acquire)) return;
            self.checkAll();
        }
    }

    /// One round: every file is read, and checked if it changed.
    pub fn checkAll(self: *Self) void {
        for (self.entries) |*e| self.checkOne(e);
    }

    fn warn(e: *Entry, comptime fmt: []const u8, args: anytype) void {
        report(e, .warn, fmt, args);
    }

    /// Logs a problem unless it is the one logged last (cut to 256 bytes).
    fn report(e: *Entry, comptime level: std.log.Level, comptime fmt: []const u8, args: anytype) void {
        var w: std.Io.Writer = .fixed(&e.scratch);
        w.print(fmt, args) catch {};
        const msg = w.buffered();
        if (std.mem.eql(u8, msg, e.warning[0..e.warning_len])) return;
        @memcpy(e.warning[0..msg.len], msg);
        e.warning_len = msg.len;
        switch (level) {
            // The test runner fails a test that logs an error.
            .err => if (@import("builtin").is_test) log.warn("OCSP response {s}: {s}", .{ e.path, msg }) else log.err("OCSP response {s}: {s}", .{ e.path, msg }),
            else => log.warn("OCSP response {s}: {s}", .{ e.path, msg }),
        }
    }

    fn checkOne(self: *Self, e: *Entry) void {
        const io = self.threaded.io();
        const now = self.now();
        if (e.staple.expiry()) |t| {
            if (now >= t and !e.expiry_logged) {
                log.warn("OCSP response {s}: expired, no longer stapled", .{e.path});
                e.expiry_logged = true;
            }
        }
        const fd = sys.openReadNonBlocking(e.path) catch |err| {
            warn(e, "can't open ({t}); keeping the last good one, if any", .{err});
            return;
        };
        const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
        defer file.close(io);
        const st = file.stat(io) catch |err| {
            warn(e, "stat failed ({t})", .{err});
            return;
        };
        if (st.kind != .file) {
            warn(e, "not a regular file ({t}); keeping the last good one, if any", .{st.kind});
            return;
        }
        if (st.size > ocsp.max_response_len) {
            warn(e, "{d} bytes, more than {d}; not stapled", .{ st.size, ocsp.max_response_len });
            return;
        }
        // One byte more than it should hold, to see it grew.
        const buf = self.allocator.alloc(u8, @intCast(st.size + 1)) catch {
            warn(e, "out of memory", .{});
            return;
        };
        defer self.allocator.free(buf);
        const n = file.readPositionalAll(io, buf, 0) catch |err| {
            warn(e, "read failed ({t})", .{err});
            return;
        };
        // Its size changed while it was read: being written.
        if (n != st.size) return;
        const data = buf[0..n];
        if (e.last) |l| if (std.mem.eql(u8, l, data)) {
            // Unchanged: only the time can change the answer.
            if (e.pending != null) decide(e, now);
            return;
        };
        const copy = self.allocator.dupe(u8, data) catch {
            warn(e, "out of memory", .{});
            return;
        };
        if (e.last) |l| self.allocator.free(l);
        e.last = copy;
        self.verified += 1;
        e.pending = ocsp.verify(copy, e.chain) catch |err| {
            warn(e, "{s} (SHA-256 {x}...); not stapled", .{ describe(err), fingerprint(copy) });
            e.pending = null;
            return;
        };
        decide(e, now);
    }

    /// What `e.pending` (a verified response, `e.last`) means at `now`.
    fn decide(e: *Entry, now: i64) void {
        const v = e.pending.?;
        const data = e.last.?;
        if (v.this_update < e.newest) {
            warn(e, "older than the last response (thisUpdate {d} s before it) (SHA-256 {x}...); not stapled", .{ e.newest - v.this_update, fingerprint(data) });
            e.pending = null;
            return;
        }
        const checked = ocsp.evaluate(v, now) catch |err| {
            switch (err) {
                // A current, verified revocation: stop stapling the last
                // good response, which clients would trust for days more.
                error.Revoked => {
                    e.staple.clear();
                    report(e, .err, "{s} (SHA-256 {x}...); no longer stapling any response", .{ describe(err), fingerprint(data) });
                },
                // Unknown is often a responder's passing trouble: the last
                // good response stays (Must-Staple clients need one).
                error.StatusUnknown => warn(e, "{s} (SHA-256 {x}...); keeping the last good one, if any", .{ describe(err), fingerprint(data) }),
                // The time may change the answer: kept pending, checked
                // again each round.
                else => {
                    warn(e, "{s} (SHA-256 {x}...); not stapled", .{ describe(err), fingerprint(data) });
                    return;
                },
            }
            e.newest = @max(e.newest, v.this_update);
            e.pending = null;
            return;
        };
        e.staple.set(data, checked.expires) catch |err| {
            warn(e, "{t}; not stapled", .{err});
            return;
        };
        e.newest = @max(e.newest, v.this_update);
        e.pending = null;
        e.warning_len = 0;
        e.expiry_logged = false;
    }

    fn fingerprint(data: []const u8) [6]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        return digest[0..6].*;
    }
};

fn describe(err: ocsp.Error) []const u8 {
    return switch (err) {
        error.Malformed => "not a DER OCSPResponse",
        error.NotSuccessful => "the responder's status is not successful",
        error.NotBasic => "not a basic OCSP response",
        error.NoIssuer => "the certificate chain has no issuer for the leaf (needed to match the CertID and check the signature)",
        error.NotForCertificate => "not for this certificate",
        error.NoSha1CertId => "its CertID for this certificate uses SHA-2, and OpenSSL clients look for a SHA-1 one (fetch it with SHA-1, openssl ocsp's default)",
        error.InvalidCertificate => "the certificate itself doesn't parse strictly, so no response can be matched to it",
        error.UnauthorizedResponder => "signed by a responder that may not sign for the issuer",
        error.ResponderNotCurrent => "the responder's certificate isn't valid now",
        error.BadSignature => "the signature doesn't verify",
        error.UnsupportedAlgorithm => "an unsupported signature algorithm or key",
        error.Revoked => "the certificate is revoked",
        error.StatusUnknown => "the responder doesn't know the certificate",
        error.Expired => "expired (nextUpdate has passed)",
        error.NotYetValid => "not valid yet (thisUpdate or producedAt is ahead of our clock)",
        error.TooLarge => "too large",
    };
}

// -- Tests ------------------------------------------------------------

const testing = std.testing;

/// A temporary directory for tests (`std.testing.tmpDir`), with paths to
/// put in a config and files replaced the way a fetching job should
/// (written aside, renamed over).
pub const TestDir = struct {
    tmp: std.testing.TmpDir,
    path_buf: [64]u8,
    path: []const u8,

    pub fn init(self: *TestDir) void {
        self.tmp = std.testing.tmpDir(.{});
        self.path = std.fmt.bufPrint(&self.path_buf, "{s}/{s}", .{ std.testing.TmpDir.parent_dir_path, self.tmp.sub_path }) catch unreachable;
    }

    pub fn deinit(self: *TestDir) void {
        self.tmp.cleanup();
    }

    /// `name`'s path from the working directory.
    pub fn file(self: *const TestDir, buf: []u8, name: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}", .{ self.path, name }) catch unreachable;
    }

    /// Replaces `name` atomically.
    pub fn write(self: *const TestDir, name: []const u8, data: []const u8) !void {
        try self.tmp.dir.writeFile(testing.io, .{ .sub_path = "tmp", .data = data });
        try self.tmp.dir.rename("tmp", self.tmp.dir, name, testing.io);
    }

    /// Overwrites `name` where it is.
    pub fn writeInPlace(self: *const TestDir, name: []const u8, data: []const u8) !void {
        try self.tmp.dir.writeFile(testing.io, .{ .sub_path = name, .data = data });
    }

    pub fn delete(self: *const TestDir, name: []const u8) !void {
        try self.tmp.dir.deleteFile(testing.io, name);
    }
};

var watcher_test_now: i64 = ocsp.testdata.this_update + 3600;

fn watcherTestClock() i64 {
    return watcher_test_now;
}

fn stapled(c: *const Credentials) ?[]const u8 {
    const s = c.ocsp orelse return null;
    const r = s.acquire() orelse return null;
    defer r.release();
    return r.bytes[8..];
}

/// The test allocator, failing while `fail` is set.
const FlakyAllocator = struct {
    fail: bool = false,

    fn allocator(self: *FlakyAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *FlakyAllocator = @ptrCast(@alignCast(ctx));
        if (self.fail) return null;
        return testing.allocator.rawAlloc(len, alignment, ra);
    }

    fn resize(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        return testing.allocator.rawResize(memory, alignment, new_len, ra);
    }

    fn remap(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        return testing.allocator.rawRemap(memory, alignment, new_len, ra);
    }

    fn free(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        testing.allocator.rawFree(memory, alignment, ra);
    }
};

test "Watcher: loads at init, rereads a file that changed, keeps the last good response, logs and skips the rest" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var sni = try Credentials.fromPem(testing.allocator, otd.sni_chain, otd.sni_key);
    defer sni.deinit();
    try dir.write("leaf.der", otd.leaf_good);
    var b1: [192]u8 = undefined;
    var b2: [192]u8 = undefined;
    // No thread: the test runs the rounds.
    const w = try Watcher.init(testing.allocator, &.{
        .{ .credentials = &leaf, .path = dir.file(&b1, "leaf.der") },
        .{ .credentials = &sni, .path = dir.file(&b2, "missing.der") },
    }, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    for (w.entries) |*e| e.staple.now = watcherTestClock;
    watcher_test_now = otd.this_update + 3600;
    try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    try testing.expectEqual(null, stapled(&sni));

    // Replaced by one that doesn't pass: the last good one stays.
    for ([_][]const u8{ otd.sni_good, otd.leaf_good_noeku, otd.leaf_good_rogue, otd.leaf_good_forged, "garbage", otd.leaf_good[0..100] }) |bad| {
        try dir.write("leaf.der", bad);
        w.checkAll();
        try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    }
    // A SHA-2 CertID only: OpenSSL clients wouldn't find it.
    try dir.write("leaf.der", otd.leaf_good_sha256);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    // A good one replaces it; so does one written in place.
    try dir.write("leaf.der", otd.leaf_good_ca384);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good_ca384, stapled(&leaf).?);
    try dir.writeInPlace("leaf.der", otd.both_good);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.both_good, stapled(&leaf).?);
    // The file that was missing appears.
    try dir.write("missing.der", otd.sni_good);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.sni_good, stapled(&sni).?);
    // Deleted: the last good one stays until it expires.
    try dir.delete("missing.der");
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.sni_good, stapled(&sni).?);
    watcher_test_now = otd.next_update;
    w.checkAll();
    try testing.expectEqual(null, stapled(&sni));
    try testing.expectEqual(null, stapled(&leaf));
    // An expired file isn't loaded.
    watcher_test_now = otd.this_update + 3600;
    try dir.write("leaf.der", otd.short);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.both_good, stapled(&leaf).?);
}

test "Watcher: a file that couldn't be read, or isn't valid yet, is tried again unchanged" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var flaky: FlakyAllocator = .{};
    var b1: [192]u8 = undefined;
    // Nothing at first; then a file whose read fails (out of memory).
    const w = try Watcher.init(flaky.allocator(), &.{.{ .credentials = &leaf, .path = dir.file(&b1, "leaf.der") }}, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    w.entries[0].staple.now = watcherTestClock;
    watcher_test_now = otd.this_update + 3600;
    try dir.write("leaf.der", otd.leaf_good);
    flaky.fail = true;
    w.checkAll();
    flaky.fail = false;
    try testing.expectEqual(null, stapled(&leaf));
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    // thisUpdate more than 300 s ahead of our clock: not stapled, the
    // last good one stays, and once the clock is near enough the same
    // file is.
    try dir.write("leaf.der", otd.leaf_good_ca384);
    watcher_test_now = otd.this_update - 400;
    const verified = w.verified;
    for (0..3) |_| {
        w.checkAll();
        try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    }
    watcher_test_now = otd.this_update;
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good_ca384, stapled(&leaf).?);
    // Parsed and verified once: later rounds only ask the clock.
    try testing.expectEqual(verified + 1, w.verified);
}

test "Watcher: a current, signed revocation stops stapling; unknown keeps the last good response; a new good one staples again" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    try dir.write("leaf.der", otd.leaf_good);
    const w = try Watcher.init(testing.allocator, &.{.{ .credentials = &leaf, .path = dir.file(&b1, "leaf.der") }}, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    w.entries[0].staple.now = watcherTestClock;
    watcher_test_now = otd.this_update + 3600;
    try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    // Unknown: often passing trouble at the responder.
    try dir.write("leaf.der", otd.leaf_unknown);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    // Revoked: stapling stops, and stays stopped while the file stays.
    try dir.write("leaf.der", otd.leaf_revoked);
    w.checkAll();
    try testing.expectEqual(null, stapled(&leaf));
    w.checkAll();
    try testing.expectEqual(null, stapled(&leaf));
    try dir.write("leaf.der", otd.leaf_good_ca384);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good_ca384, stapled(&leaf).?);
}

test "Watcher: a response older than the newest verified one isn't stapled (a cached good one doesn't undo a revocation)" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    const w = try Watcher.init(testing.allocator, &.{.{ .credentials = &leaf, .path = dir.file(&b1, "leaf.der") }}, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    w.entries[0].staple.now = watcherTestClock;
    watcher_test_now = otd.this_update + 3600;
    // A revocation 100 s after leaf-good.der's thisUpdate, and a good
    // response 200 s after (both signed by the CA).
    const revoked_later = try ocsp.craft.retimed(a, otd.leaf_revoked, "20261031182646Z", "21261007182506Z");
    const good_later = try ocsp.craft.retimed(a, otd.leaf_good, "20261031182826Z", "21261007182506Z");
    try dir.write("leaf.der", otd.leaf_good);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    try dir.write("leaf.der", revoked_later);
    w.checkAll();
    try testing.expectEqual(null, stapled(&leaf));
    // The older good response again (from a cache, say): refused.
    try dir.write("leaf.der", otd.leaf_good);
    w.checkAll();
    try testing.expectEqual(null, stapled(&leaf));
    try dir.write("leaf.der", good_later);
    w.checkAll();
    try testing.expectEqualSlices(u8, good_later, stapled(&leaf).?);
}

test "Watcher: a refusal the clock can lift is checked again: expired, or the responder's certificate not current, until the clock is corrected" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    const w = try Watcher.init(testing.allocator, &.{.{ .credentials = &leaf, .path = dir.file(&b1, "leaf.der") }}, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    w.entries[0].staple.now = watcherTestClock;
    // The clock jumped a century (nextUpdate passed), then two days (the
    // responder's certificate expired): refused; corrected: stapled.
    for ([_]struct { file: []const u8, wrong: i64 }{
        .{ .file = otd.leaf_good, .wrong = otd.next_update },
        .{ .file = otd.leaf_good_shortlived, .wrong = otd.this_update + 2 * 86400 },
    }) |case| {
        w.entries[0].staple.clear();
        try dir.write("leaf.der", case.file);
        watcher_test_now = case.wrong;
        w.checkAll();
        try testing.expectEqual(null, stapled(&leaf));
        watcher_test_now = otd.this_update + 3600;
        w.checkAll();
        try testing.expectEqualSlices(u8, case.file, stapled(&leaf).?);
    }
}

test "Watcher: the thread rereads a changed file within the interval, and stops at deinit" {
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    try dir.write("leaf.der", otd.leaf_good);
    const w = try Watcher.init(testing.allocator, &.{.{ .credentials = &leaf, .path = dir.file(&b1, "leaf.der") }}, 1);
    defer w.deinit();
    try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    try dir.write("leaf.der", otd.both_good);
    const began = sys.nanoTimestamp();
    while (!std.mem.eql(u8, stapled(&leaf).?, otd.both_good)) {
        if (sys.nanoTimestamp() - began > 5 * std.time.ns_per_s) return error.Timeout;
        std.Io.sleep(testing.io, .fromMilliseconds(50), .awake) catch {};
    }
}

test "Watcher: init failing part way frees everything and leaves the credentials alone" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    const sources: []const Source = &.{ .{ .credentials = &leaf, .path = "a" }, .{ .credentials = &leaf, .path = "b" } };
    try std.testing.checkAllAllocationFailures(testing.allocator, struct {
        fn f(a: std.mem.Allocator, src: []const Source, c: *Credentials) !void {
            const w = try Watcher.init(a, src, 0);
            w.deinit();
            c.ocsp = null;
        }
    }.f, .{ sources, &leaf });
    try testing.expectEqual(null, leaf.ocsp);
}

// -- Adversarial verification -------------------------------------------

const builtin = @import("builtin");
extern "c" fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;

fn makeFifo(path: []const u8) !void {
    var z: [256]u8 = undefined;
    const p = try std.fmt.bufPrintSentinel(&z, "{s}", .{path}, 0);
    if (builtin.os.tag == .linux) {
        const rc = std.os.linux.mknod(p, std.os.linux.S.IFIFO | 0o600, 0);
        if (std.os.linux.errno(rc) != .SUCCESS) return error.MkfifoFailed;
    } else {
        if (mkfifo(p, 0o600) != 0) return error.MkfifoFailed;
    }
}

test "verify: Watcher: a FIFO at the path doesn't block init (or the thread)" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    const path = dir.file(&b1, "fifo.der");
    try makeFifo(path);
    const Init = struct {
        fn run(c: *Credentials, p: []const u8, out: *?*Watcher, done: *std.atomic.Value(bool)) void {
            out.* = Watcher.init(testing.allocator, &.{.{ .credentials = c, .path = p }}, 0) catch null;
            done.store(true, .release);
        }
    };
    var w: ?*Watcher = null;
    var done: std.atomic.Value(bool) = .init(false);
    const t = try std.Thread.spawn(.{}, Init.run, .{ &leaf, path, &w, &done });
    const began = sys.nanoTimestamp();
    while (!done.load(.acquire) and sys.nanoTimestamp() - began < 3 * std.time.ns_per_s) {
        std.Io.sleep(testing.io, .fromMilliseconds(20), .awake) catch {};
    }
    const blocked = !done.load(.acquire);
    if (blocked) {
        // Unblock it: a writer opens and closes the FIFO.
        var z: [256]u8 = undefined;
        const zp = try std.fmt.bufPrintSentinel(&z, "{s}", .{path}, 0);
        const flags: std.posix.O = .{ .ACCMODE = .WRONLY, .NONBLOCK = true };
        if (builtin.os.tag == .linux) {
            const fd = std.os.linux.open(zp, flags, 0);
            _ = std.os.linux.close(@intCast(fd));
        } else {
            const fd = std.c.open(zp, flags, @as(c_uint, 0));
            _ = std.c.close(fd);
        }
    }
    t.join();
    if (w) |x| x.deinit();
    try testing.expect(!blocked);
}

test "verify: Watcher: a directory, then a symlink swapped to another file" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    const path = dir.file(&b1, "leaf.der");
    try dir.tmp.dir.createDirPath(testing.io, "leaf.der");
    const w = try Watcher.init(testing.allocator, &.{.{ .credentials = &leaf, .path = path }}, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    for (w.entries) |*e| e.staple.now = watcherTestClock;
    watcher_test_now = otd.this_update + 3600;
    try testing.expectEqual(null, stapled(&leaf));
    // The directory goes; a symlink to a good response takes its place.
    try dir.tmp.dir.deleteTree(testing.io, "leaf.der");
    try dir.write("a.der", otd.leaf_good);
    try dir.write("b.der", otd.both_good);
    try dir.tmp.dir.symLink(testing.io, "a.der", "leaf.der", .{});
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good, stapled(&leaf).?);
    // Swapped (a new symlink renamed over it) to the other file.
    try dir.tmp.dir.symLink(testing.io, "b.der", "link.tmp", .{});
    try dir.tmp.dir.rename("link.tmp", dir.tmp.dir, "leaf.der", testing.io);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.both_good, stapled(&leaf).?);
    // Dangling: the last good one stays.
    try dir.delete("b.der");
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.both_good, stapled(&leaf).?);
    // A directory again: still the last good one.
    try dir.delete("leaf.der");
    try dir.tmp.dir.createDirPath(testing.io, "leaf.der");
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.both_good, stapled(&leaf).?);
}

// Failed on Linux while files were reread on a changed inode, size or
// time (ext4/overlayfs timestamps are coarse: 189 of 200 rewrites missed
// in Docker); every round compares the bytes now.
test "verify: Watcher: a file rewritten in place with the same size is reread" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    const path = dir.file(&b1, "leaf.der");
    // A response the same size as leaf_good that doesn't pass (a bit of
    // the serial flipped), written in place, then leaf_good in place
    // again at once: the second write must not be missed for having the
    // same inode and size and (coarse) times.
    var bad: [otd.leaf_good.len]u8 = otd.leaf_good.*;
    const at = std.mem.indexOf(u8, &bad, &.{ 0x02, 0x02, 0x10, 0x01 }).? + 3;
    bad[at] ^= 1;
    try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = path, .data = &bad });
    const w = try Watcher.init(testing.allocator, &.{.{ .credentials = &leaf, .path = path }}, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    for (w.entries) |*e| e.staple.now = watcherTestClock;
    watcher_test_now = otd.this_update + 3600;
    try testing.expectEqual(null, stapled(&leaf));
    var misses: usize = 0;
    for (0..200) |_| {
        try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = path, .data = &bad });
        w.checkAll();
        try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = path, .data = otd.leaf_good });
        w.checkAll();
        if (stapled(&leaf) == null) misses += 1;
        w.entries[0].staple.clear();
    }
    try testing.expectEqual(@as(usize, 0), misses);
}

test "verify: Watcher: a delegated responder's response isn't stapled past the responder certificate's notAfter" {
    // leaf-good-shortlived.der: nextUpdate in 100 years, its responder's
    // certificate valid for a day. Stapled at first, check refuses it two
    // days on, and so do clients (openssl ocsp -attime: "certificate has
    // expired"), but the file is unchanged, so it isn't checked again and
    // its expiry is nextUpdate: it stays stapled for a century.
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    const w = try Watcher.init(testing.allocator, &.{.{ .credentials = &leaf, .path = dir.file(&b1, "leaf.der") }}, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    w.entries[0].staple.now = watcherTestClock;
    watcher_test_now = otd.this_update + 3600;
    try dir.write("leaf.der", otd.leaf_good_shortlived);
    w.checkAll();
    try testing.expectEqualSlices(u8, otd.leaf_good_shortlived, stapled(&leaf).?);
    watcher_test_now = otd.this_update + 2 * 86400;
    try testing.expectError(error.ResponderNotCurrent, ocsp.check(otd.leaf_good_shortlived, leaf.chain, watcher_test_now));
    w.checkAll();
    try testing.expect(stapled(&leaf) == null);
}

test "verify: Watcher: a response whose responder certificate isn't valid yet is tried again unchanged" {
    // Like thisUpdate ahead of our clock: a responder certificate whose
    // notBefore is ahead (a CA clock ahead of ours, a response fetched
    // right after the responder's certificate was renewed) is refused for
    // good, and the same file is never checked again, though it passes
    // once the clock gets there (and OpenSSL accepts it then).
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    const resp = @embedFile("tls/testdata/ocsp/verify/responder-not-yet-valid.der");
    var dir: TestDir = undefined;
    dir.init();
    defer dir.deinit();
    var leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
    defer leaf.deinit();
    var b1: [192]u8 = undefined;
    const w = try Watcher.init(testing.allocator, &.{.{ .credentials = &leaf, .path = dir.file(&b1, "leaf.der") }}, 0);
    defer w.deinit();
    w.now = watcherTestClock;
    w.entries[0].staple.now = watcherTestClock;
    // Its responder certificate is valid from a day and a minute after
    // thisUpdate.
    watcher_test_now = otd.this_update + 3600;
    try dir.write("leaf.der", resp);
    w.checkAll();
    try testing.expect(stapled(&leaf) == null);
    watcher_test_now = otd.this_update + 2 * 86400;
    _ = try ocsp.check(resp, leaf.chain, watcher_test_now);
    w.checkAll();
    try testing.expect(std.mem.eql(u8, resp, stapled(&leaf) orelse ""));
}

// -- Adversarial verification, third round --------------------------------

/// A response for the leaf, status from `like` (leaf-good or
/// leaf-revoked/unknown), with these thisUpdate and nextUpdate, signed by
/// the test CA.
fn verify3Response(a: std.mem.Allocator, like: []const u8, this_update: []const u8, next_update: []const u8) ![]u8 {
    const p = try ocsp.craft.split(like);
    return ocsp.craft.join(a, p, &.{try ocsp.singleWithTimes(a, p.singles[0], this_update, next_update)}, "");
}

const Verify3Watch = struct {
    dir: TestDir,
    leaf: Credentials,
    w: *Watcher,
    b1: [192]u8,

    fn init(self: *Verify3Watch) !void {
        const otd = ocsp.testdata;
        self.dir.init();
        self.leaf = try Credentials.fromPem(testing.allocator, otd.leaf_chain, otd.leaf_key);
        self.w = try Watcher.init(testing.allocator, &.{.{ .credentials = &self.leaf, .path = self.dir.file(&self.b1, "leaf.der") }}, 0);
        self.w.now = watcherTestClock;
        self.w.entries[0].staple.now = watcherTestClock;
        watcher_test_now = otd.this_update + 3600;
    }

    fn deinit(self: *Verify3Watch) void {
        self.w.deinit();
        self.leaf.deinit();
        self.dir.deinit();
    }

    fn put(self: *Verify3Watch, data: []const u8) !?[]const u8 {
        try self.dir.write("leaf.der", data);
        self.w.checkAll();
        return stapled(&self.leaf);
    }
};

test "verify: Watcher: a revocation from a responder that may not sign, a stale one, or for another serial doesn't stop stapling" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const otd = ocsp.testdata;
    var v: Verify3Watch = undefined;
    try v.init();
    defer v.deinit();
    watcher_test_now = otd.this_update + 60;
    const d = "tls/testdata/ocsp/verify3/";
    for ([_][]const u8{
        @embedFile(d ++ "revoked-by-noeku.der"),
        @embedFile(d ++ "revoked-by-other-ca-same-name.der"),
        @embedFile(d ++ "revoked-by-self-signed.der"),
        @embedFile(d ++ "revoked-by-expired-responder.der"),
        @embedFile(d ++ "unknown-by-noeku.der"),
        @embedFile(d ++ "revoked-other-serial.der"),
        // Signed by the CA: nextUpdate passed a second ago, thisUpdate
        // 301 s ahead (the next round checks it again).
        try verify3Response(a, otd.leaf_revoked, "20261030182506Z", "20261031182605Z"),
        try verify3Response(a, otd.leaf_revoked, "20261031183107Z", "20261107182506Z"),
    }) |news| {
        try testing.expectEqualSlices(u8, otd.leaf_good, (try v.put(otd.leaf_good)).?);
        try testing.expectEqualSlices(u8, otd.leaf_good, (try v.put(news)).?);
    }
    // The one from the future, once the clock gets there: stapling stops.
    const future = try verify3Response(a, otd.leaf_revoked, "20261031183107Z", "20261107182506Z");
    try testing.expectEqualSlices(u8, otd.leaf_good, (try v.put(otd.leaf_good)).?);
    try testing.expectEqualSlices(u8, otd.leaf_good, (try v.put(future)).?);
    watcher_test_now = otd.this_update + 361;
    v.w.checkAll();
    try testing.expectEqual(null, stapled(&v.leaf));
}

test "Watcher: a revocation signed by a responder whose keyUsage lacks digitalSignature stops stapling (as OpenSSL clients would take it)" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    const otd = ocsp.testdata;
    var v: Verify3Watch = undefined;
    try v.init();
    defer v.deinit();
    watcher_test_now = otd.this_update + 60;
    try testing.expectEqualSlices(u8, otd.leaf_good, (try v.put(otd.leaf_good)).?);
    try testing.expectEqual(null, try v.put(@embedFile("tls/testdata/ocsp/verify3/revoked-by-ku-no-ds.der")));
}
test "verify: Watcher: after a signed revocation, an older good response (still current) isn't stapled again" {
    // The fetching job alternates between a CDN node with a cached good
    // response and one with the newer revocation (or an attacker on its
    // plain-HTTP fetch replays the good one): the revocation the watcher
    // verified must not be undone by a response from before it.
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const otd = ocsp.testdata;
    var v: Verify3Watch = undefined;
    try v.init();
    defer v.deinit();
    // Good at thisUpdate, revoked 10 minutes later; both current an hour on.
    const good = try verify3Response(a, otd.leaf_good, "20261031182506Z", "20261107182506Z");
    const revoked = try verify3Response(a, otd.leaf_revoked, "20261031183506Z", "20261107183506Z");
    try testing.expect((try v.put(good)) != null);
    try testing.expect((try v.put(revoked)) == null);
    try testing.expect((try v.put(good)) == null);
}

test "verify: Watcher: an unknown response older than the stapled good one doesn't stop stapling" {
    // A response cached from just after issuance ("unknown": the CA's
    // responder hadn't heard of the certificate yet) is still current
    // when a newer good one is stapled; a Must-Staple certificate then
    // fails in Firefox.
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const otd = ocsp.testdata;
    var v: Verify3Watch = undefined;
    try v.init();
    defer v.deinit();
    const unknown = try verify3Response(a, otd.leaf_unknown, "20261031182506Z", "20261107182506Z");
    const good = try verify3Response(a, otd.leaf_good, "20261031183506Z", "20261107183506Z");
    try testing.expect((try v.put(good)) != null);
    try testing.expect((try v.put(unknown)) != null);
}

test "verify: Watcher: an older good response doesn't replace a newer one" {
    const saved_level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = saved_level;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const otd = ocsp.testdata;
    var v: Verify3Watch = undefined;
    try v.init();
    defer v.deinit();
    const older = try verify3Response(a, otd.leaf_good, "20261031182506Z", "20261107182506Z");
    const newer = try verify3Response(a, otd.leaf_good, "20261031183506Z", "20261107183506Z");
    try testing.expectEqualSlices(u8, newer, (try v.put(newer)).?);
    try testing.expectEqualSlices(u8, newer, (try v.put(older)).?);
}
