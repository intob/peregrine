//! UDP sockets for QUIC: binding, batched receive (recvmmsg on Linux),
//! sends with generic segmentation offload (one sendmsg for many datagrams
//! of one size, UDP_SEGMENT), and SO_REUSEPORT steering by connection ID so
//! each worker gets the packets of the connections it owns.
const std = @import("std");
const builtin = @import("builtin");
const sys = @import("../sys.zig");
const posix = std.posix;
const linux = std.os.linux;
const system = posix.system;

pub const fd_t = sys.fd_t;

/// A peer address: IPv4 or IPv6, kept as the sockaddr the kernel gave.
pub const Addr = extern struct {
    storage: posix.sockaddr.in6 = std.mem.zeroes(posix.sockaddr.in6),
    len: posix.socklen_t = 0,

    pub fn eql(a: *const Addr, b: *const Addr) bool {
        return a.len == b.len and std.mem.eql(u8, std.mem.asBytes(&a.storage)[0..a.len], std.mem.asBytes(&b.storage)[0..b.len]);
    }

    pub fn sockaddr(a: *const Addr) *const posix.sockaddr {
        return @ptrCast(&a.storage);
    }

    /// Address bytes and port, for tokens and logs.
    pub fn bytes(a: *const Addr) []const u8 {
        return std.mem.asBytes(&a.storage)[0..a.len];
    }
};

pub fn bind(address: std.Io.net.IpAddress, reuse_port: bool) !fd_t {
    const family: u32 = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const sock_type: u32 = if (sys.is_linux)
        posix.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC
    else
        posix.SOCK.DGRAM;
    const rc = system.socket(family, sock_type, posix.IPPROTO.UDP);
    if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: fd_t = @intCast(rc);
    errdefer sys.close(fd);
    if (!sys.is_linux) try sys.setNonBlocking(fd);
    try sys.setsockoptInt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, 1);
    if (reuse_port) try sys.setsockoptInt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, 1);
    // Bursts of datagrams between event loop turns: big kernel buffers.
    sys.setsockoptInt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, 4 << 20) catch {};
    sys.setsockoptInt(fd, posix.SOL.SOCKET, posix.SO.SNDBUF, 4 << 20) catch {};
    var storage: Addr = .{};
    switch (address) {
        .ip4 => |a| {
            const in: *posix.sockaddr.in = @ptrCast(&storage.storage);
            in.* = std.mem.zeroes(posix.sockaddr.in);
            in.family = posix.AF.INET;
            in.port = std.mem.nativeToBig(u16, a.port);
            in.addr = @bitCast(a.bytes);
            storage.len = @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |a| {
            storage.storage.family = posix.AF.INET6;
            storage.storage.port = std.mem.nativeToBig(u16, a.port);
            storage.storage.addr = a.bytes;
            storage.len = @sizeOf(posix.sockaddr.in6);
        },
    }
    if (posix.errno(system.bind(fd, storage.sockaddr(), storage.len)) != .SUCCESS) return error.AddressInUse;
    return fd;
}

// -- Steering (Linux) ----------------------------------------------------------

const SockFilter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
const SockFprog = extern struct { len: u16, filter: [*]const SockFilter };

/// Attaches a classic BPF program to a SO_REUSEPORT group (call it on one
/// socket of the group) that picks the socket by the first byte of the
/// Destination Connection ID, modulo the group size. Our connection IDs
/// start with the owning worker's index, so a connection's packets reach
/// its worker; a client's first Initial (a random DCID) lands on any
/// worker, which then issues IDs naming itself.
pub fn attachSteering(fd: fd_t, workers: u32) !void {
    if (!sys.is_linux) return;
    const B = struct {
        const ld_b_abs: u16 = 0x30; // BPF_LD | BPF_B | BPF_ABS
        const jset_k: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
        const ja: u16 = 0x05; // BPF_JMP | BPF_JA
        const mod_k: u16 = 0x94; // BPF_ALU | BPF_MOD | BPF_K
        const ret_a: u16 = 0x16; // BPF_RET | BPF_A
    };
    // The program sees the UDP payload (the kernel pulls the UDP header).
    const prog = [_]SockFilter{
        .{ .code = B.ld_b_abs, .jt = 0, .jf = 0, .k = 0 }, // A = first byte
        .{ .code = B.jset_k, .jt = 2, .jf = 0, .k = 0x80 }, // long header?
        .{ .code = B.ld_b_abs, .jt = 0, .jf = 0, .k = 1 }, // short: DCID at 1
        .{ .code = B.ja, .jt = 0, .jf = 0, .k = 1 },
        .{ .code = B.ld_b_abs, .jt = 0, .jf = 0, .k = 6 }, // long: DCID at 6
        .{ .code = B.mod_k, .jt = 0, .jf = 0, .k = workers },
        .{ .code = B.ret_a, .jt = 0, .jf = 0, .k = 0 },
    };
    const fprog: SockFprog = .{ .len = prog.len, .filter = &prog };
    const rc = linux.setsockopt(fd, posix.SOL.SOCKET, linux.SO.ATTACH_REUSEPORT_CBPF, @ptrCast(&fprog), @sizeOf(SockFprog));
    if (posix.errno(rc) != .SUCCESS) return error.SteeringFailed;
}

// -- Receiving -----------------------------------------------------------------

pub const Datagram = struct { data: []u8, from: Addr };

/// A batch of receive buffers.
pub fn RecvBatch(comptime n: usize, comptime size: usize) type {
    return struct {
        const Self = @This();

        bufs: [n][size]u8 = undefined,
        addrs: [n]Addr = undefined,
        iovs: [n]posix.iovec = undefined,
        msgs: if (sys.is_linux) [n]linux.mmsghdr else void = undefined,
        lens: [n]usize = undefined,

        /// Receives up to n datagrams; 0 when none are waiting.
        pub fn recv(self: *Self, fd: fd_t) usize {
            if (sys.is_linux) {
                for (0..n) |i| {
                    self.iovs[i] = .{ .base = &self.bufs[i], .len = size };
                    self.msgs[i] = .{
                        .hdr = .{
                            .name = @ptrCast(&self.addrs[i].storage),
                            .namelen = @sizeOf(posix.sockaddr.in6),
                            .iov = @ptrCast(&self.iovs[i]),
                            .iovlen = 1,
                            .control = null,
                            .controllen = 0,
                            .flags = 0,
                        },
                        .len = 0,
                    };
                }
                while (true) {
                    const rc = linux.recvmmsg(fd, &self.msgs, n, 0, null);
                    switch (posix.errno(rc)) {
                        .SUCCESS => {
                            for (0..rc) |i| {
                                self.addrs[i].len = self.msgs[i].hdr.namelen;
                                self.lens[i] = self.msgs[i].len;
                            }
                            return rc;
                        },
                        .INTR => continue,
                        else => return 0,
                    }
                }
            }
            var count: usize = 0;
            while (count < n) {
                var len: posix.socklen_t = @sizeOf(posix.sockaddr.in6);
                const rc = std.c.recvfrom(fd, &self.bufs[count], size, 0, @ptrCast(&self.addrs[count].storage), &len);
                if (rc < 0) break;
                self.addrs[count].len = len;
                self.lens[count] = @intCast(rc);
                count += 1;
            }
            return count;
        }

        pub fn get(self: *Self, i: usize) Datagram {
            return .{ .data = self.bufs[i][0..self.lens[i]], .from = self.addrs[i] };
        }
    };
}

// -- Sending -------------------------------------------------------------------

const SOL_UDP = 17;
const UDP_SEGMENT = 103;

pub const SendError = error{ WouldBlock, Unexpected };

/// Sends `data` to `to`: one datagram, or (Linux, `segment` set) several
/// datagrams of `segment` bytes each, the last possibly shorter.
pub fn send(fd: fd_t, to: *const Addr, data: []const u8, segment: ?u16) SendError!void {
    if (sys.is_linux) {
        var iov = [1]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
        var control: [linux.cmsg_align * 2 + @sizeOf(linux.cmsghdr)]u8 align(@alignOf(linux.cmsghdr)) = @splat(0);
        var msg: linux.msghdr_const = .{
            .name = to.sockaddr(),
            .namelen = to.len,
            .iov = &iov,
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        if (segment) |seg| {
            if (data.len > seg) {
                const hdr: *linux.cmsghdr = @ptrCast(&control);
                hdr.* = .{ .len = @sizeOf(linux.cmsghdr) + @sizeOf(u16), .level = SOL_UDP, .type = UDP_SEGMENT };
                std.mem.writeInt(u16, control[@sizeOf(linux.cmsghdr)..][0..2], seg, builtin.cpu.arch.endian());
                msg.control = &control;
                msg.controllen = std.mem.alignForward(usize, @sizeOf(linux.cmsghdr) + @sizeOf(u16), linux.cmsg_align);
            }
        }
        while (true) {
            const rc = linux.sendmsg(fd, &msg, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                // EIO: GSO unsupported by the device; ECONNREFUSED and
                // friends: ICMP errors from earlier sends. Drop.
                else => return error.Unexpected,
            }
        }
    }
    // Elsewhere: datagram by datagram.
    var rest = data;
    const seg = segment orelse data.len;
    while (rest.len > 0) {
        const n = @min(rest.len, seg);
        const rc = std.c.sendto(fd, rest.ptr, n, 0, to.sockaddr(), to.len);
        if (rc < 0) {
            return switch (posix.errno(rc)) {
                .AGAIN => error.WouldBlock,
                else => error.Unexpected,
            };
        }
        rest = rest[n..];
    }
}

/// Whether the kernel supports UDP_SEGMENT on this socket.
pub fn gsoSupported(fd: fd_t) bool {
    if (!sys.is_linux) return false;
    var v: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    return posix.errno(linux.getsockopt(fd, SOL_UDP, UDP_SEGMENT, @ptrCast(&v), &len)) == .SUCCESS;
}

pub fn localPort(fd: fd_t) !u16 {
    return sys.localPort(fd);
}
