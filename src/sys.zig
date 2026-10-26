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
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
    const rc = system.fcntl(fd, posix.F.SETFL, @as(c_int, @intCast(flags)) | nonblock);
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
