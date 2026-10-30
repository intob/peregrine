//! Thin wrappers over raw syscalls. On Linux these go straight to the kernel
//! (no libc). On Darwin/BSD they go through libc, which is the only stable
//! syscall interface on those systems.
const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const system = posix.system;
const linux = std.os.linux;

pub const fd_t = posix.fd_t;
pub const iovec_const = posix.iovec_const;
pub const E = posix.E;

pub const is_linux = native_os == .linux;
pub const is_bsd = switch (native_os) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

comptime {
    if (!is_linux and !is_bsd) @compileError("Unsupported OS");
}

pub const IoError = error{
    WouldBlock,
    /// Peer reset, broken pipe, or otherwise unusable connection.
    ConnectionClosed,
    Unexpected,
};

fn unexpected(e: E) error{Unexpected} {
    if (@import("builtin").mode == .debug) {
        std.debug.print("unexpected errno: {s}\n", .{@tagName(e)});
    }
    return error.Unexpected;
}

pub fn read(fd: fd_t, buf: []u8) IoError!usize {
    while (true) {
        const rc = system.read(fd, buf.ptr, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET, .PIPE, .TIMEDOUT, .NOTCONN, .BADF => return error.ConnectionClosed,
            else => |e| return unexpected(e),
        }
    }
}

/// iovecs for `parts` (one stream) in `iov`, from byte `skip` on and at
/// most `max` bytes; empty pieces are left out.
pub fn iovecsOf(iov: []iovec_const, parts: []const []const u8, skip: usize, max: usize) []iovec_const {
    var n: usize = 0;
    var skipping = skip;
    var taken: usize = 0;
    for (parts) |p| {
        const rest = p[@min(skipping, p.len)..];
        skipping -|= p.len;
        const take = @min(rest.len, max - taken);
        if (take == 0) continue;
        iov[n] = .{ .base = rest.ptr, .len = take };
        n += 1;
        taken += take;
    }
    return iov[0..n];
}

test iovecsOf {
    var iov: [3]iovec_const = undefined;
    const parts = [_][]const u8{ "head", "", "body", "tail" };
    const a = iovecsOf(&iov, &parts, 2, 7);
    try std.testing.expectEqual(3, a.len);
    try std.testing.expectEqualStrings("ad", a[0].base[0..a[0].len]);
    try std.testing.expectEqualStrings("body", a[1].base[0..a[1].len]);
    try std.testing.expectEqualStrings("t", a[2].base[0..a[2].len]);
    const b = iovecsOf(&iov, &parts, 9, 100);
    try std.testing.expectEqual(1, b.len);
    try std.testing.expectEqualStrings("ail", b[0].base[0..b[0].len]);
    try std.testing.expectEqual(0, iovecsOf(&iov, &parts, 12, 100).len);
}

pub fn writev(fd: fd_t, iov: []const iovec_const) IoError!usize {
    while (true) {
        const rc = system.writev(fd, iov.ptr, @intCast(iov.len));
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET, .PIPE, .TIMEDOUT, .NOTCONN, .BADF => return error.ConnectionClosed,
            else => |e| return unexpected(e),
        }
    }
}

pub fn write(fd: fd_t, buf: []const u8) IoError!usize {
    while (true) {
        const rc = system.write(fd, buf.ptr, buf.len);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNRESET, .PIPE, .TIMEDOUT, .NOTCONN, .BADF => return error.ConnectionClosed,
            else => |e| return unexpected(e),
        }
    }
}

pub const SendfileError = IoError || error{
    /// This system or this file can't be sent with sendfile: read and
    /// write it instead.
    Unsupported,
    /// The file ended before `count` bytes (it was truncated).
    FileTruncated,
};

/// Tests set this to exercise the read-and-write fallback.
pub var sendfile_disabled = false;

/// Sends up to `count` bytes of `file` from `offset` to the socket `sock`
/// without copying them through user space. Returns the bytes sent;
/// error.WouldBlock only if none were.
pub fn sendfile(sock: fd_t, file: fd_t, offset: u64, count: usize) SendfileError!usize {
    if (count == 0) return 0;
    if (sendfile_disabled) return error.Unsupported;
    if (is_linux) {
        while (true) {
            var off: i64 = @intCast(offset);
            const rc = linux.sendfile(sock, file, &off, count);
            switch (posix.errno(rc)) {
                .SUCCESS => return if (rc == 0) error.FileTruncated else rc,
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .CONNRESET, .PIPE, .TIMEDOUT, .NOTCONN => return error.ConnectionClosed,
                .INVAL, .NOSYS, .OPNOTSUPP => return error.Unsupported,
                else => |e| return unexpected(e),
            }
        }
    }
    switch (native_os) {
        .macos => while (true) {
            var len: std.c.off_t = @intCast(count);
            const rc = std.c.sendfile(file, sock, @intCast(offset), &len, null, 0);
            const sent: usize = @intCast(len);
            switch (posix.errno(rc)) {
                .SUCCESS => return if (sent == 0) error.FileTruncated else sent,
                // Partial sends report what went out.
                .INTR => if (sent > 0) return sent else continue,
                .AGAIN => return if (sent > 0) sent else error.WouldBlock,
                .CONNRESET, .PIPE, .TIMEDOUT, .NOTCONN => return error.ConnectionClosed,
                .INVAL, .OPNOTSUPP, .NOTSOCK => return error.Unsupported,
                else => |e| return unexpected(e),
            }
        },
        .freebsd => while (true) {
            var sbytes: std.c.off_t = 0;
            const rc = std.c.sendfile(file, sock, @intCast(offset), count, null, &sbytes, 0);
            const sent: usize = @intCast(sbytes);
            switch (posix.errno(rc)) {
                .SUCCESS => return if (sent == 0) error.FileTruncated else sent,
                .INTR, .BUSY => if (sent > 0) return sent else continue,
                .AGAIN => return if (sent > 0) sent else error.WouldBlock,
                .CONNRESET, .PIPE, .TIMEDOUT, .NOTCONN => return error.ConnectionClosed,
                .INVAL, .OPNOTSUPP, .NOTSOCK => return error.Unsupported,
                else => |e| return unexpected(e),
            }
        },
        else => return error.Unsupported,
    }
}

/// Kernel TLS (Linux): the kernel encrypts what is written to the socket
/// into TLS records, so plain writes and sendfile work on a TLS connection.
/// Only the sending side is used here.
pub const ktls = struct {
    pub const Error = error{
        /// No kernel TLS here (no tls module): no use trying again.
        NoModule,
        /// Not for this cipher or this socket.
        Unsupported,
        Unexpected,
    };

    const tls_tx = 1;
    const tls_set_record_type = 1;

    pub const version_1_3: u16 = 0x0304;
    pub const cipher_aes_gcm_128: u16 = 51;
    pub const cipher_aes_gcm_256: u16 = 52;
    pub const cipher_chacha20_poly1305: u16 = 54;

    /// Hands the sending side of a connected TCP socket to the kernel.
    /// `info` is a `tls12_crypto_info_*` structure (see linux/tls.h).
    pub fn enableTx(fd: fd_t, info: []const u8) Error!void {
        if (!is_linux) return error.NoModule;
        const ulp = "tls";
        switch (posix.errno(linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.ULP, ulp, ulp.len))) {
            .SUCCESS, .EXIST => {},
            .NOENT, .NOPROTOOPT, .PERM => return error.NoModule,
            .OPNOTSUPP, .NOTCONN => return error.Unsupported,
            else => |e| return unexpected(e),
        }
        return setTx(fd, info);
    }

    /// New keys for the sending side (TLS 1.3 KeyUpdate). Kernels before
    /// TLS 1.3 rekey support refuse (error.Unsupported).
    pub fn rekeyTx(fd: fd_t, info: []const u8) Error!void {
        if (!is_linux) return error.Unsupported;
        return setTx(fd, info);
    }

    fn setTx(fd: fd_t, info: []const u8) Error!void {
        switch (posix.errno(linux.setsockopt(fd, linux.SOL.TLS, tls_tx, info.ptr, @intCast(info.len)))) {
            .SUCCESS => {},
            .INVAL, .BUSY, .OPNOTSUPP, .NOENT, .NOPROTOOPT, .NOMEM => return error.Unsupported,
            else => |e| return unexpected(e),
        }
    }

    /// Writes `data` as one record of `content_type` (an alert, or a
    /// handshake message such as KeyUpdate); application data needs no
    /// call, a plain write is one.
    pub fn sendRecord(fd: fd_t, content_type: u8, data: []const u8) IoError!usize {
        if (!is_linux) return error.Unexpected;
        var control: [@sizeOf(linux.cmsghdr) + linux.cmsg_align]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
        const hdr: *linux.cmsghdr = @ptrCast(&control);
        hdr.* = .{ .len = @sizeOf(linux.cmsghdr) + 1, .level = linux.SOL.TLS, .type = tls_set_record_type };
        control[@sizeOf(linux.cmsghdr)] = content_type;
        const iov = [_]iovec_const{.{ .base = data.ptr, .len = data.len }};
        const msg: linux.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &control,
            .controllen = control.len,
            .flags = 0,
        };
        while (true) {
            const rc = linux.sendmsg(fd, &msg, linux.MSG.NOSIGNAL);
            switch (posix.errno(rc)) {
                .SUCCESS => return rc,
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .CONNRESET, .PIPE, .TIMEDOUT, .NOTCONN => return error.ConnectionClosed,
                else => |e| return unexpected(e),
            }
        }
    }
};

pub const PreadError = error{ FileTruncated, Unexpected };

/// Reads `buf.len` bytes of `file` at `offset` (fewer only at the end of
/// the file, which is error.FileTruncated if nothing is left).
pub fn pread(file: fd_t, buf: []u8, offset: u64) PreadError!usize {
    if (buf.len == 0) return 0;
    var done: usize = 0;
    while (done < buf.len) {
        const rc = system.pread(file, buf[done..].ptr, buf.len - done, @intCast(offset + done));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return if (done == 0) error.FileTruncated else done;
                done += @intCast(rc);
            },
            .INTR => continue,
            else => |e| return unexpected(e),
        }
    }
    return done;
}

pub fn close(fd: fd_t) void {
    _ = system.close(fd);
}

/// Half-close: send FIN after any queued output.
pub fn shutdownWrite(fd: fd_t) void {
    _ = system.shutdown(fd, posix.SHUT.WR);
}

/// Upper bound on input discarded during a lingering close.
pub const max_linger_bytes = 1024 * 1024;

pub const AcceptError = error{
    WouldBlock,
    /// Process or system fd limit reached.
    FdLimit,
    /// A connection was aborted before it was accepted. Try again.
    Aborted,
    Unexpected,
};

/// Returns a non-blocking, close-on-exec socket.
pub fn accept(listener: fd_t) AcceptError!fd_t {
    while (true) {
        const rc = if (is_linux)
            linux.accept4(listener, null, null, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC)
        else
            // BSD sockets inherit O_NONBLOCK from the listener.
            system.accept(listener, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNABORTED, .PROTO, .PERM => return error.Aborted,
            .MFILE, .NFILE, .NOBUFS, .NOMEM => return error.FdLimit,
            else => |e| return unexpected(e),
        }
    }
}

pub fn setNonBlocking(fd: fd_t) !void {
    const flags = system.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (posix.errno(flags) != .SUCCESS) return error.Unexpected;
    const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    const arg = @as(u32, @intCast(flags)) | nonblock;
    const rc = system.fcntl(fd, posix.F.SETFL, if (is_linux) @as(usize, arg) else @as(c_int, @bitCast(arg)));
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
}

pub fn isNonBlocking(fd: fd_t) bool {
    const flags = system.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    return (@as(u32, @intCast(flags)) & nonblock) != 0;
}

pub fn setsockoptInt(fd: fd_t, level: i32, opt: u32, value: c_int) !void {
    try posix.setsockopt(fd, level, opt, std.mem.asBytes(&value));
}

pub fn getsockoptInt(fd: fd_t, level: i32, opt: u32) !c_int {
    var value: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    const rc = system.getsockopt(fd, level, opt, @ptrCast(&value), &len);
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
    return value;
}

/// TCP_NODELAY is 1 on every supported platform.
pub const TCP_NODELAY: u32 = 1;

pub const ListenOptions = struct {
    /// One listener per worker, load-balanced by the kernel.
    reuse_port: bool,
    backlog: u31 = 4096,
};

pub fn listenTcp(address: std.Io.net.IpAddress, opts: ListenOptions) !fd_t {
    var storage: Sockaddr = undefined;
    const addr_len = toSockaddr(address, &storage);
    const family: u32 = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const sock_type: u32 = if (is_linux)
        posix.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC
    else
        posix.SOCK.STREAM;
    const rc = system.socket(family, sock_type, posix.IPPROTO.TCP);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: fd_t = @intCast(rc);
    errdefer close(fd);
    if (!is_linux) try setNonBlocking(fd);
    try setsockoptInt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, 1);
    if (opts.reuse_port) {
        if (@hasDecl(posix.SO, "REUSEPORT_LB")) {
            try setsockoptInt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT_LB, 1);
        } else {
            try setsockoptInt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, 1);
        }
    }
    // Accepted sockets inherit TCP_NODELAY from the listener on Linux, macOS
    // and FreeBSD, which saves a syscall per accepted connection. This is
    // verified by a test in server.zig.
    try setsockoptInt(fd, posix.IPPROTO.TCP, TCP_NODELAY, 1);
    if (posix.errno(system.bind(fd, @ptrCast(&storage), addr_len)) != .SUCCESS) {
        return error.AddressInUse;
    }
    if (posix.errno(system.listen(fd, opts.backlog)) != .SUCCESS) return error.ListenFailed;
    return fd;
}

/// Returns the port a listener is bound to (useful when binding port 0).
pub fn localPort(fd: fd_t) !u16 {
    var storage: Sockaddr = undefined;
    var len: posix.socklen_t = @sizeOf(Sockaddr);
    if (posix.errno(system.getsockname(fd, @ptrCast(&storage), &len)) != .SUCCESS) {
        return error.Unexpected;
    }
    return std.mem.bigToNative(u16, storage.in.port);
}

const Sockaddr = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

fn toSockaddr(address: std.Io.net.IpAddress, out: *Sockaddr) posix.socklen_t {
    switch (address) {
        .ip4 => |a| {
            out.* = .{ .in = std.mem.zeroes(posix.sockaddr.in) };
            out.in.family = posix.AF.INET;
            out.in.port = std.mem.nativeToBig(u16, a.port);
            out.in.addr = @bitCast(a.bytes);
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |a| {
            out.* = .{ .in6 = std.mem.zeroes(posix.sockaddr.in6) };
            out.in6.family = posix.AF.INET6;
            out.in6.port = std.mem.nativeToBig(u16, a.port);
            out.in6.addr = a.bytes;
            return @sizeOf(posix.sockaddr.in6);
        },
    }
}

/// Seconds from a monotonic clock.
pub fn monotonicSeconds() u32 {
    var ts: posix.timespec = undefined;
    _ = system.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @truncate(@as(u64, @intCast(ts.sec)));
}

/// Seconds since the Unix epoch.
pub fn realtimeSeconds() i64 {
    var ts: posix.timespec = undefined;
    _ = system.clock_gettime(posix.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

pub fn nanoTimestamp() u64 {
    var ts: posix.timespec = undefined;
    _ = system.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Fills `buf` with cryptographically secure random bytes from the OS.
pub fn randomBytes(buf: []u8) void {
    if (is_linux) {
        var filled: usize = 0;
        while (filled < buf.len) {
            const rc = linux.getrandom(buf[filled..].ptr, buf.len - filled, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => filled += rc,
                .INTR => continue,
                // getrandom only fails on bad arguments or before the pool
                // is seeded (not with flags = 0); there is no safe fallback.
                else => @panic("getrandom failed"),
            }
        }
    } else {
        std.c.arc4random_buf(buf.ptr, buf.len);
    }
}

/// A connected pair of blocking stream sockets (for tests).
pub fn socketPair() ![2]fd_t {
    var fds: [2]fd_t = undefined;
    const rc = system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
    return fds;
}

/// A pipe (BSD) or eventfd (Linux) that wakes a poller from another thread
/// or a signal handler. Writing uses write(2), which is async-signal-safe.
pub const Waker = struct {
    read_fd: fd_t,
    write_fd: fd_t,

    pub fn init() !Waker {
        if (is_linux) {
            const rc = linux.eventfd(0, linux.EFD.NONBLOCK | linux.EFD.CLOEXEC);
            if (posix.errno(rc) != .SUCCESS) return error.Unexpected;
            const fd: fd_t = @intCast(rc);
            return .{ .read_fd = fd, .write_fd = fd };
        }
        var fds: [2]fd_t = undefined;
        if (posix.errno(system.pipe(&fds)) != .SUCCESS) return error.Unexpected;
        try setNonBlocking(fds[0]);
        try setNonBlocking(fds[1]);
        return .{ .read_fd = fds[0], .write_fd = fds[1] };
    }

    pub fn deinit(self: Waker) void {
        close(self.read_fd);
        if (self.write_fd != self.read_fd) close(self.write_fd);
    }

    pub fn wake(self: Waker) void {
        const one: u64 = 1;
        _ = system.write(self.write_fd, std.mem.asBytes(&one), if (is_linux) 8 else 1);
    }
};

/// Pin the calling thread to one CPU (Linux only; a no-op elsewhere).
/// `index` selects among the CPUs this process is allowed to run on.
pub fn pinToCpu(index: usize) void {
    if (!is_linux) return;
    var allowed: linux.cpu_set_t = std.mem.zeroes(linux.cpu_set_t);
    if (posix.errno(linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &allowed)) != .SUCCESS) return;
    const count: usize = @intCast(linux.CPU_COUNT(allowed));
    if (count == 0) return;
    var target = index % count;
    const bits = @bitSizeOf(usize);
    for (allowed, 0..) |word, w| {
        var bitset = word;
        while (bitset != 0) {
            const b = @ctz(bitset);
            if (target == 0) {
                var set: linux.cpu_set_t = std.mem.zeroes(linux.cpu_set_t);
                set[w] = @as(usize, 1) << @intCast(b);
                linux.sched_setaffinity(0, &set) catch {};
                return;
            }
            target -= 1;
            bitset &= bitset - 1;
        }
        _ = bits;
    }
}

/// A futex-based mutex (Linux futex, Darwin __ulock; other BSDs spin and
/// yield). std.Thread.Mutex is gone in 0.17 and std.Io.Mutex needs an Io.
/// Uncontended lock and unlock are one atomic operation each.
pub const Mutex = struct {
    const State = enum(u32) { unlocked, locked, contended };

    state: std.atomic.Value(State) = .init(.unlocked),

    pub fn tryLock(m: *Mutex) bool {
        return m.state.cmpxchgStrong(.unlocked, .locked, .acquire, .monotonic) == null;
    }

    pub fn lock(m: *Mutex) void {
        if (m.state.cmpxchgWeak(.unlocked, .locked, .acquire, .monotonic) == null) return;
        m.lockSlow();
    }

    fn lockSlow(m: *Mutex) void {
        @branchHint(.cold);
        // Spin briefly: critical sections here are short.
        for (0..64) |_| {
            if (m.state.load(.monotonic) == .unlocked and m.tryLock()) return;
            std.atomic.spinLoopHint();
        }
        while (m.state.swap(.contended, .acquire) != .unlocked) {
            futexWait(@ptrCast(&m.state.raw), @backingInt(State.contended));
        }
    }

    pub fn unlock(m: *Mutex) void {
        if (m.state.swap(.unlocked, .release) == .contended) {
            futexWake(@ptrCast(&m.state.raw), 1);
        }
    }
};

fn futexWait(ptr: *const u32, expect: u32) void {
    switch (native_os) {
        .linux => _ = linux.futex(ptr, .{ .cmd = .WAIT, .private = true }, expect, .{ .timeout = null }, null, 0),
        .macos, .ios, .tvos, .watchos, .visionos => {
            const c = std.c;
            const flags: c.UL = .{ .op = .COMPARE_AND_WAIT, .NO_ERRNO = true };
            _ = c.__ulock_wait2(flags, ptr, expect, 0, 0);
        },
        else => _ = system.sched_yield(),
    }
}

fn futexWake(ptr: *const u32, max_waiters: u32) void {
    switch (native_os) {
        .linux => _ = linux.futex_3arg(ptr, .{ .cmd = .WAKE, .private = true }, max_waiters),
        .macos, .ios, .tvos, .watchos, .visionos => {
            const c = std.c;
            const flags: c.UL = .{ .op = .COMPARE_AND_WAIT, .NO_ERRNO = true, .WAKE_ALL = max_waiters > 1 };
            while (true) {
                const status = c.__ulock_wake(flags, ptr, 0);
                if (status >= 0) return;
                switch (@as(c.E, @fromBackingInt(@intCast(@as(u16, @intCast(-status)))))) {
                    .INTR => continue,
                    else => return,
                }
            }
        },
        else => {},
    }
}

test "mutex serialises counters across threads" {
    const Shared = struct {
        mutex: Mutex = .{},
        counter: usize = 0,

        fn bump(s: *@This()) void {
            for (0..10000) |_| {
                s.mutex.lock();
                s.counter += 1;
                s.mutex.unlock();
            }
        }
    };
    var shared: Shared = .{};
    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Shared.bump, .{&shared});
    for (threads) |t| t.join();
    try std.testing.expectEqual(@as(usize, 40000), shared.counter);
    try std.testing.expect(shared.mutex.tryLock());
    try std.testing.expect(!shared.mutex.tryLock());
    shared.mutex.unlock();
}
