const native_os = @import("builtin").os.tag;
const posix = @import("std").posix;
const linux = @import("std").os.linux;

pub const IOHandler = switch (native_os) {
    .freebsd, .netbsd, .openbsd, .dragonfly, .macos => KqueueHandler,
    .linux => EpollHandler,
    else => @compileError("Unsupported OS"),
};

pub const KqueueHandler = struct {
    const Self = @This();

    kfd: i32,
    timeout: posix.timespec,

    pub fn init() !Self {
        return .{
            .kfd = try posix.kqueue(),
            .timeout = posix.timespec{ .sec = 0, .nsec = 50_000_000 },
        };
    }

    pub fn addSocket(self: *Self, fd: posix.socket_t) !void {
        const event = posix.Kevent{
            .ident = @intCast(fd),
            .filter = posix.system.EVFILT.READ,
            .flags = posix.system.EV.ADD | posix.system.EV.CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = @intCast(fd),
        };
        _ = try posix.kevent(self.kfd, &[_]posix.Kevent{event}, &.{}, null);
    }

    pub fn removeSocket(self: *Self, fd: posix.socket_t) !void {
        const event = posix.Kevent{
            .ident = @intCast(fd),
            .filter = posix.system.EVFILT.READ,
            .flags = posix.system.EV.DELETE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        _ = try posix.kevent(self.kfd, &[_]posix.Kevent{event}, &.{}, null);
    }

    pub fn wait(self: *Self, events: []posix.Kevent) !usize {
        return try posix.kevent(self.kfd, &.{}, events, &self.timeout);
    }

    pub fn deinit(self: *Self) void {
        posix.close(self.kfd);
    }
};

pub const EpollHandler = struct {
    epfd: i32,

    const Self = @This();

    pub fn init() !Self {
        const epfd = try posix.epoll_create1(0);
        return .{ .epfd = epfd };
    }

    pub fn addSocket(self: *Self, fd: posix.socket_t) !void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.IN | linux.EPOLL.ET,
            .data = .{ .fd = fd },
        };
        try posix.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, fd, &event);
    }

    pub fn removeSocket(self: *Self, fd: posix.socket_t) !void {
        try posix.epoll_ctl(self.epfd, linux.EPOLL.CTL_DEL, fd, null);
    }

    pub fn wait(self: *Self, events: []linux.epoll_event) !usize {
        return posix.epoll_wait(self.epfd, events, 50); // 50ms timeout
    }

    pub fn deinit(self: *Self) void {
        posix.close(self.epfd);
    }
};
