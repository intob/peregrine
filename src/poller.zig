const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const sys = @import("./sys.zig");

pub const Poller = if (sys.is_linux) Epoll else Kqueue;

pub const Interest = enum {
    /// Edge-triggered read + write readiness. Registered once per connection,
    /// so no syscall is needed to toggle write interest.
    connection,
    /// Level-triggered read readiness (listeners, wakers).
    level_read,
};

const Epoll = struct {
    const Self = @This();
    pub const Event = linux.epoll_event;

    epfd: i32,

    pub fn init() !Self {
        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (posix.errno(rc) != .SUCCESS) return error.PollerInitFailed;
        return .{ .epfd = @intCast(rc) };
    }

    pub fn deinit(self: *Self) void {
        sys.close(self.epfd);
    }

    pub fn add(self: *Self, fd: sys.fd_t, token_value: u64, interest: Interest) !void {
        var ev = linux.epoll_event{
            .events = switch (interest) {
                .connection => linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.RDHUP | linux.EPOLL.ET,
                .level_read => linux.EPOLL.IN,
            },
            .data = .{ .u64 = token_value },
        };
        if (posix.errno(linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, fd, &ev)) != .SUCCESS) {
            return error.PollerAddFailed;
        }
    }

    pub fn remove(self: *Self, fd: sys.fd_t) void {
        _ = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_DEL, fd, null);
    }

    /// `timeout_ms` < 0 blocks indefinitely.
    pub fn wait(self: *Self, events: []Event, timeout_ms: i32) usize {
        const rc = linux.epoll_wait(self.epfd, events.ptr, @intCast(events.len), timeout_ms);
        return switch (posix.errno(rc)) {
            .SUCCESS => rc,
            else => 0, // EINTR
        };
    }

    pub inline fn token(ev: Event) u64 {
        return ev.data.u64;
    }

    pub inline fn readable(ev: Event) bool {
        return ev.events & (linux.EPOLL.IN | linux.EPOLL.RDHUP | linux.EPOLL.HUP | linux.EPOLL.ERR) != 0;
    }

    pub inline fn writable(ev: Event) bool {
        return ev.events & (linux.EPOLL.OUT | linux.EPOLL.HUP | linux.EPOLL.ERR) != 0;
    }
};

const Kqueue = struct {
    const Self = @This();
    const EVFILT = posix.system.EVFILT;
    const EV = posix.system.EV;
    pub const Event = posix.Kevent;

    kfd: i32,

    pub fn init() !Self {
        const rc = posix.system.kqueue();
        if (posix.errno(rc) != .SUCCESS) return error.PollerInitFailed;
        return .{ .kfd = rc };
    }

    pub fn deinit(self: *Self) void {
        sys.close(self.kfd);
    }

    fn change(fd: sys.fd_t, filter: @FieldType(Event, "filter"), flags: @FieldType(Event, "flags"), token_value: u64) Event {
        return .{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = @intCast(token_value),
        };
    }

    pub fn add(self: *Self, fd: sys.fd_t, token_value: u64, interest: Interest) !void {
        var changes: [2]Event = undefined;
        const n: usize = switch (interest) {
            .connection => blk: {
                changes[0] = change(fd, EVFILT.READ, EV.ADD | EV.CLEAR, token_value);
                changes[1] = change(fd, EVFILT.WRITE, EV.ADD | EV.CLEAR, token_value);
                break :blk 2;
            },
            .level_read => blk: {
                changes[0] = change(fd, EVFILT.READ, EV.ADD, token_value);
                break :blk 1;
            },
        };
        const rc = posix.system.kevent(self.kfd, &changes, @intCast(n), &changes, 0, null);
        if (posix.errno(rc) != .SUCCESS) return error.PollerAddFailed;
    }

    pub fn remove(self: *Self, fd: sys.fd_t) void {
        // Delete each filter separately: a combined call stops at the first
        // filter that isn't registered.
        var changes = [_]Event{change(fd, EVFILT.READ, EV.DELETE, 0)};
        _ = posix.system.kevent(self.kfd, &changes, 1, &changes, 0, null);
        changes[0] = change(fd, EVFILT.WRITE, EV.DELETE, 0);
        _ = posix.system.kevent(self.kfd, &changes, 1, &changes, 0, null);
    }

    pub fn wait(self: *Self, events: []Event, timeout_ms: i32) usize {
        var ts: posix.timespec = .{
            .sec = @divTrunc(timeout_ms, 1000),
            .nsec = @rem(timeout_ms, 1000) * std.time.ns_per_ms,
        };
        const rc = posix.system.kevent(
            self.kfd,
            &.{},
            0,
            events.ptr,
            @intCast(events.len),
            if (timeout_ms < 0) null else &ts,
        );
        return switch (posix.errno(rc)) {
            .SUCCESS => @intCast(rc),
            else => 0, // EINTR
        };
    }

    pub inline fn token(ev: Event) u64 {
        return @intCast(ev.udata);
    }

    pub inline fn readable(ev: Event) bool {
        return ev.filter == EVFILT.READ or ev.flags & EV.EOF != 0;
    }

    pub inline fn writable(ev: Event) bool {
        return ev.filter == EVFILT.WRITE;
    }
};

test "poller wakes on waker" {
    var p = try Poller.init();
    defer p.deinit();
    const w = try sys.Waker.init();
    defer w.deinit();
    try p.add(w.read_fd, 42, .level_read);
    var events: [4]Poller.Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), p.wait(&events, 0));
    w.wake();
    const n = p.wait(&events, 1000);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u64, 42), Poller.token(events[0]));
    try std.testing.expect(Poller.readable(events[0]));
}
