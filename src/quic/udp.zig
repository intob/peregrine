//! UDP sockets for QUIC: binding, batched receive (recvmmsg on Linux),
//! sends with generic segmentation offload (one sendmsg for many datagrams
//! of one size, UDP_SEGMENT), and SO_REUSEPORT steering by connection ID so
//! each worker gets the packets of the connections it owns.
//!
//! ECN (RFC 9000 §13.4): `enableEcn` asks the kernel for each datagram's
//! TOS byte or Traffic Class (IP_RECVTOS, IPV6_RECVTCLASS), which arrives
//! as a control message beside it; sends set the codepoint per sendmsg
//! (IP_TOS or IPV6_TCLASS control message), so connections that mark and
//! connections that don't share the socket. One GSO send has one codepoint.
const std = @import("std");
const builtin = @import("builtin");
const sys = @import("../sys.zig");
const Ecn = @import("./packet.zig").Ecn;
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

// -- ECN ----------------------------------------------------------------------

/// The IP_TOS control message's type when received: Linux reports it as
/// IP_TOS, the BSDs as IP_RECVTOS.
const ip_tos_recv: i32 = if (sys.is_linux) posix.IP.TOS else posix.IP.RECVTOS;

/// Asks for each datagram's ECN codepoint (best effort: a kernel that
/// won't say leaves every datagram Not-ECT). An IPv6 socket also takes
/// IPv4-mapped traffic, whose codepoint comes as IP_TOS.
pub fn enableEcn(fd: fd_t, ipv6: bool) void {
    if (ipv6) sys.setsockoptInt(fd, posix.IPPROTO.IPV6, posix.IPV6.RECVTCLASS, 1) catch {};
    sys.setsockoptInt(fd, posix.IPPROTO.IP, posix.IP.RECVTOS, 1) catch {};
}

/// A control buffer's room for one TOS or Traffic Class message (an int at
/// most), aligned as the kernel's cmsghdr.
const cmsg_hdr_len = if (sys.is_linux) @sizeOf(linux.cmsghdr) else std.mem.alignForward(usize, @sizeOf(std.c.cmsghdr), 4);
const cmsg_align = if (sys.is_linux) linux.cmsg_align else 4;
const cmsg_space = cmsg_hdr_len + std.mem.alignForward(usize, @sizeOf(c_int), cmsg_align);
const CmsgHdr = if (sys.is_linux) linux.cmsghdr else std.c.cmsghdr;

/// The ECN codepoint in a received datagram's control messages.
fn ecnFromControl(control: []const u8) Ecn {
    var pos: usize = 0;
    while (pos + cmsg_hdr_len <= control.len) {
        const hdr: *align(1) const CmsgHdr = @ptrCast(control[pos..].ptr);
        const len: usize = @intCast(hdr.len);
        if (len < cmsg_hdr_len or pos + len > control.len) break;
        const data = control[pos + cmsg_hdr_len .. pos + len];
        const tos = (hdr.level == posix.IPPROTO.IP and (hdr.type == ip_tos_recv or hdr.type == posix.IP.TOS)) or
            (hdr.level == posix.IPPROTO.IPV6 and hdr.type == posix.IPV6.TCLASS);
        // One byte (IP_TOS) or an int (IPV6_TCLASS); ECN is in the low bits.
        if (tos and data.len > 0) return @fromBackingInt(@as(u2, @truncate(if (data.len >= 4) std.mem.readInt(u32, data[0..4], builtin.cpu.arch.endian()) else data[0])));
        pos += std.mem.alignForward(usize, len, cmsg_align);
    }
    return .not_ect;
}

// -- Receiving -----------------------------------------------------------------

pub const Datagram = struct { data: []u8, from: Addr, ecn: Ecn };

/// A batch of receive buffers, each with room for its ECN control message.
pub fn RecvBatch(comptime n: usize, comptime size: usize) type {
    return struct {
        const Self = @This();

        bufs: [n][size]u8 = undefined,
        addrs: [n]Addr = undefined,
        iovs: [n]posix.iovec = undefined,
        msgs: if (sys.is_linux) [n]linux.mmsghdr else void = undefined,
        control: [n][cmsg_space]u8 align(@alignOf(CmsgHdr)) = undefined,
        lens: [n]usize = undefined,
        ecns: [n]Ecn = undefined,

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
                            .control = &self.control[i],
                            .controllen = cmsg_space,
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
                                const hdr = &self.msgs[i].hdr;
                                self.addrs[i].len = hdr.namelen;
                                self.lens[i] = self.msgs[i].len;
                                self.ecns[i] = if (hdr.controllen == 0) .not_ect else ecnFromControl(self.control[i][0..@min(hdr.controllen, cmsg_space)]);
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
                self.iovs[count] = .{ .base = &self.bufs[count], .len = size };
                var msg: std.c.msghdr = .{
                    .name = @ptrCast(&self.addrs[count].storage),
                    .namelen = @sizeOf(posix.sockaddr.in6),
                    .iov = @ptrCast(&self.iovs[count]),
                    .iovlen = 1,
                    .control = &self.control[count],
                    .controllen = cmsg_space,
                    .flags = 0,
                };
                const rc = std.c.recvmsg(fd, &msg, 0);
                if (rc < 0) break;
                self.addrs[count].len = msg.namelen;
                self.lens[count] = @intCast(rc);
                self.ecns[count] = if (msg.controllen == 0) .not_ect else ecnFromControl(self.control[count][0..@min(msg.controllen, cmsg_space)]);
                count += 1;
            }
            return count;
        }

        pub fn get(self: *Self, i: usize) Datagram {
            return .{ .data = self.bufs[i][0..self.lens[i]], .from = self.addrs[i], .ecn = self.ecns[i] };
        }
    };
}

// -- Sending -------------------------------------------------------------------

const SOL_UDP = 17;
const UDP_SEGMENT = 103;

pub const SendError = error{ WouldBlock, Unexpected };

/// A kernel refused a TOS control message on send (EINVAL): send unmarked
/// from then on. ECN validation then fails on every connection, which
/// stops asking.
var tos_refused: std.atomic.Value(bool) = .init(false);

/// The control message that sets a send's codepoint: IP_TOS for IPv4
/// (on Linux, IPv4-mapped addresses on an IPv6 socket too), else
/// IPV6_TCLASS.
fn tosLevelType(to: *const Addr) struct { i32, i32 } {
    const v4 = to.storage.family == posix.AF.INET or
        (sys.is_linux and std.mem.eql(u8, to.storage.addr[0..12], &[12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }));
    return if (v4) .{ posix.IPPROTO.IP, posix.IP.TOS } else .{ posix.IPPROTO.IPV6, posix.IPV6.TCLASS };
}

/// Appends a control message with an int (or u16) payload at `pos`;
/// returns the new length.
fn putCmsg(control: []u8, pos: usize, level: i32, ty: i32, comptime T: type, value: T) usize {
    const hdr: *align(1) CmsgHdr = @ptrCast(control[pos..].ptr);
    hdr.* = std.mem.zeroes(CmsgHdr);
    hdr.len = @intCast(cmsg_hdr_len + @sizeOf(T));
    hdr.level = level;
    hdr.type = ty;
    std.mem.writeInt(T, control[pos + cmsg_hdr_len ..][0..@sizeOf(T)], value, builtin.cpu.arch.endian());
    return pos + std.mem.alignForward(usize, cmsg_hdr_len + @sizeOf(T), cmsg_align);
}

/// Sends `data` to `to`: one datagram, or (Linux, `segment` set) several
/// datagrams of `segment` bytes each, the last possibly shorter, all with
/// the ECN codepoint `ecn`.
pub fn send(fd: fd_t, to: *const Addr, data: []const u8, segment: ?u16, ecn: Ecn) SendError!void {
    var control: [2 * cmsg_space]u8 align(@alignOf(CmsgHdr)) = @splat(0);
    var tos_len: usize = 0;
    if (ecn != .not_ect and !tos_refused.load(.monotonic)) {
        const lt = tosLevelType(to);
        tos_len = putCmsg(&control, 0, lt[0], lt[1], c_int, @backingInt(ecn));
    }
    if (sys.is_linux) {
        var iov = [1]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
        var len = tos_len;
        if (segment) |seg| {
            if (data.len > seg) len = putCmsg(&control, len, SOL_UDP, UDP_SEGMENT, u16, seg);
        }
        var msg: linux.msghdr_const = .{
            .name = to.sockaddr(),
            .namelen = to.len,
            .iov = &iov,
            .iovlen = 1,
            .control = if (len > 0) &control else null,
            .controllen = len,
            .flags = 0,
        };
        while (true) {
            const rc = linux.sendmsg(fd, &msg, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .INVAL => {
                    if (tos_len == 0) return error.Unexpected;
                    // No TOS control messages here: send unmarked.
                    tos_refused.store(true, .monotonic);
                    std.mem.copyForwards(u8, control[0 .. len - tos_len], control[tos_len..len]);
                    len -= tos_len;
                    tos_len = 0;
                    msg.control = if (len > 0) &control else null;
                    msg.controllen = len;
                },
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
        var iov = [1]posix.iovec_const{.{ .base = rest.ptr, .len = n }};
        var msg: std.c.msghdr_const = .{
            .name = to.sockaddr(),
            .namelen = to.len,
            .iov = &iov,
            .iovlen = 1,
            .control = if (tos_len > 0) &control else null,
            .controllen = @intCast(tos_len),
            .flags = 0,
        };
        const rc = std.c.sendmsg(fd, &msg, 0);
        if (rc < 0) {
            switch (posix.errno(rc)) {
                .AGAIN => return error.WouldBlock,
                .INVAL => if (tos_len > 0) {
                    tos_refused.store(true, .monotonic);
                    tos_len = 0;
                    continue;
                } else return error.Unexpected,
                else => return error.Unexpected,
            }
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

const testing = std.testing;

test "ECN codepoint from control messages" {
    var control: [3 * cmsg_space]u8 align(@alignOf(CmsgHdr)) = @splat(0);
    // IP_TOS as one byte (Linux), DSCP bits above the ECN field.
    var len = putCmsg(&control, 0, posix.IPPROTO.IP, ip_tos_recv, u8, 0xb8 | 3);
    try testing.expectEqual(Ecn.ce, ecnFromControl(control[0..len]));
    // IPV6_TCLASS as an int, after a message of another kind.
    len = putCmsg(&control, 0, posix.SOL.SOCKET, 1, c_int, 7);
    len = putCmsg(&control, len, posix.IPPROTO.IPV6, posix.IPV6.TCLASS, c_int, 0x22);
    try testing.expectEqual(Ecn.ect0, ecnFromControl(control[0..len]));
    // Nothing, a cut header, a length beyond the buffer or under a header.
    try testing.expectEqual(Ecn.not_ect, ecnFromControl(control[0..0]));
    try testing.expectEqual(Ecn.not_ect, ecnFromControl(control[0 .. cmsg_hdr_len - 1]));
    len = putCmsg(&control, 0, posix.IPPROTO.IP, ip_tos_recv, c_int, 1);
    try testing.expectEqual(Ecn.ect1, ecnFromControl(control[0..len]));
    try testing.expectEqual(Ecn.not_ect, ecnFromControl(control[0 .. len - cmsg_align]));
    const hdr: *align(1) CmsgHdr = @ptrCast(&control);
    hdr.len = 2;
    try testing.expectEqual(Ecn.not_ect, ecnFromControl(control[0..len]));
}

test "ECN codepoints set per send come back on loopback (GSO sends too)" {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    const fd = try bind(addr, false);
    defer sys.close(fd);
    enableEcn(fd, false);
    addr.setPort(try localPort(fd));
    var to: Addr = .{};
    const in: *posix.sockaddr.in = @ptrCast(&to.storage);
    in.* = std.mem.zeroes(posix.sockaddr.in);
    in.family = posix.AF.INET;
    in.port = std.mem.nativeToBig(u16, addr.ip4.port);
    in.addr = @bitCast(addr.ip4.bytes);
    to.len = @sizeOf(posix.sockaddr.in);
    const batch = try testing.allocator.create(RecvBatch(8, 2048));
    defer testing.allocator.destroy(batch);
    const data: [3000]u8 = @splat(0x5a);
    for ([_]Ecn{ .ect0, .ce, .not_ect, .ect1 }) |ecn| {
        // Three datagrams of 1000 bytes: one GSO send where there is GSO.
        try send(fd, &to, &data, 1000, ecn);
        var got: usize = 0;
        var tries: usize = 0;
        while (got < 3 and tries < 100_000) : (tries += 1) {
            const n = batch.recv(fd);
            for (0..n) |i| {
                const d = batch.get(i);
                try testing.expectEqual(@as(usize, 1000), d.data.len);
                try testing.expectEqual(ecn, d.ecn);
            }
            got += n;
        }
        try testing.expectEqual(@as(usize, 3), got);
    }
}
