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
//!
//! Datagram size (RFC 9000 §14): `setDontFragment` sets DF, so a datagram
//! too large for the path is dropped rather than fragmented; PMTU
//! discovery (pmtud.zig) finds the size that arrives. A send larger than
//! the local interface takes fails with `error.MessageTooBig`.
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

    /// The port (the same place in IPv4 and IPv6 sockaddrs).
    pub fn port(a: *const Addr) u16 {
        return std.mem.bigToNative(u16, a.storage.port);
    }

    pub fn fromIp(address: std.Io.net.IpAddress) Addr {
        var a: Addr = .{};
        switch (address) {
            .ip4 => |v| {
                const in: *posix.sockaddr.in = @ptrCast(&a.storage);
                in.* = std.mem.zeroes(posix.sockaddr.in);
                in.family = posix.AF.INET;
                in.port = std.mem.nativeToBig(u16, v.port);
                in.addr = @bitCast(v.bytes);
                a.len = @sizeOf(posix.sockaddr.in);
            },
            .ip6 => |v| {
                a.storage.family = posix.AF.INET6;
                a.storage.port = std.mem.nativeToBig(u16, v.port);
                a.storage.addr = v.bytes;
                a.len = @sizeOf(posix.sockaddr.in6);
            },
        }
        // BSD sockaddrs start with their length.
        if (!sys.is_linux) std.mem.asBytes(&a.storage)[0] = @intCast(a.len);
        return a;
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
    const storage: Addr = .fromIp(address);
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

// -- Fragmentation --------------------------------------------------------------

/// Sets DF on our datagrams (RFC 9000 §14: "the Don't Fragment (DF) bit
/// MUST be set if possible"), best effort. Linux: IP_PMTUDISC_PROBE, which
/// sets DF and ignores the kernel's path MTU cache (learnt from ICMP, which
/// DPLPMTUD needn't trust: RFC 9000 §14.2.1), so a probe goes at any size
/// up to the interface's and larger ones fail with EMSGSIZE; on an IPv6
/// socket for both families (IPv4-mapped traffic follows the IP option).
/// macOS: IP_DONTFRAG or IPV6_DONTFRAG (it refuses IP-level options on an
/// IPv6 socket, as with ECN). Whether every option took.
pub fn setDontFragment(fd: fd_t, ipv6: bool) bool {
    var ok = true;
    if (sys.is_linux) {
        if (ipv6) ok = sys.trySetsockoptInt(fd, posix.IPPROTO.IPV6, linux.IPV6.MTU_DISCOVER, linux.IPV6.PMTUDISC_PROBE) and ok;
        ok = sys.trySetsockoptInt(fd, posix.IPPROTO.IP, linux.IP.MTU_DISCOVER, linux.IP.PMTUDISC_PROBE) and ok;
        return ok;
    }
    if (ipv6) {
        if (!@hasDecl(posix.IPV6, "DONTFRAG")) return false;
        return sys.trySetsockoptInt(fd, posix.IPPROTO.IPV6, posix.IPV6.DONTFRAG, 1);
    }
    if (!@hasDecl(posix.IP, "DONTFRAG")) return false;
    return sys.trySetsockoptInt(fd, posix.IPPROTO.IP, posix.IP.DONTFRAG, 1);
}

// -- ECN ----------------------------------------------------------------------

/// The IP_TOS control message's type when received: Linux reports it as
/// IP_TOS, the BSDs as IP_RECVTOS.
const ip_tos_recv: i32 = if (sys.is_linux) posix.IP.TOS else posix.IP.RECVTOS;

/// Asks for each datagram's ECN codepoint (best effort: a kernel that
/// won't say leaves every datagram Not-ECT). On Linux an IPv6 socket's
/// IPv4-mapped traffic reports IP_TOS, asked for with an IP-level option
/// that macOS refuses on IPv6 sockets.
pub fn enableEcn(fd: fd_t, ipv6: bool) void {
    if (ipv6) _ = sys.trySetsockoptInt(fd, posix.IPPROTO.IPV6, posix.IPV6.RECVTCLASS, 1);
    if (!ipv6 or sys.is_linux) _ = sys.trySetsockoptInt(fd, posix.IPPROTO.IP, posix.IP.RECVTOS, 1);
}

/// Room for one TOS or Traffic Class message (an int at most).
const ecn_cmsg_space = sys.cmsgSpace(@sizeOf(c_int));

/// The ECN codepoint in a received datagram's control messages.
fn ecnFromControl(control: []const u8) Ecn {
    var pos: usize = 0;
    while (pos + sys.cmsg_hdr_len <= control.len) {
        const hdr: *align(1) const sys.cmsghdr = @ptrCast(control[pos..].ptr);
        const len: usize = @intCast(hdr.len);
        if (len < sys.cmsg_hdr_len or pos + len > control.len) break;
        const data = control[pos + sys.cmsg_hdr_len .. pos + len];
        const tos = (hdr.level == posix.IPPROTO.IP and (hdr.type == ip_tos_recv or hdr.type == posix.IP.TOS)) or
            (hdr.level == posix.IPPROTO.IPV6 and hdr.type == posix.IPV6.TCLASS);
        // One byte (IP_TOS) or an int (IPV6_TCLASS); ECN is in the low bits.
        if (tos and data.len > 0) return @fromBackingInt(@as(u2, @truncate(if (data.len >= 4) std.mem.readInt(u32, data[0..4], builtin.cpu.arch.endian()) else data[0])));
        pos += std.mem.alignForward(usize, len, sys.cmsg_align);
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
        control: [n][ecn_cmsg_space]u8 align(@alignOf(sys.cmsghdr)) = undefined,
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
                            .controllen = ecn_cmsg_space,
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
                                self.ecns[i] = if (hdr.controllen == 0) .not_ect else ecnFromControl(self.control[i][0..@min(hdr.controllen, ecn_cmsg_space)]);
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
                    .controllen = ecn_cmsg_space,
                    .flags = 0,
                };
                const rc = std.c.recvmsg(fd, &msg, 0);
                if (rc < 0) break;
                self.addrs[count].len = msg.namelen;
                self.lens[count] = @intCast(rc);
                self.ecns[count] = if (msg.controllen == 0) .not_ect else ecnFromControl(self.control[count][0..@min(msg.controllen, ecn_cmsg_space)]);
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

pub const SendError = error{
    WouldBlock,
    Unexpected,
    /// Sent (all of it, or up to a datagram that would block or failed:
    /// lost, to QUIC), but unmarked: the kernel refused the TOS control
    /// message (EINVAL with it, success without). The caller sends
    /// unmarked from then on, per `tosKind` (ECN validation then ends each
    /// connection's marking).
    TosRefused,
    /// The datagram is larger than the local interface takes, with DF set
    /// (EMSGSIZE): not sent. For a PMTU probe, a failed probe.
    MessageTooBig,
};

/// The control message that sets a send's codepoint: IP_TOS (0) for IPv4
/// (on Linux, IPv4-mapped addresses on an IPv6 socket too), else
/// IPV6_TCLASS (1). A kernel may refuse one and not the other.
pub fn tosKind(to: *const Addr) u1 {
    const v4 = to.storage.family == posix.AF.INET or (sys.is_linux and isMapped(to));
    return if (v4) 0 else 1;
}

fn isMapped(to: *const Addr) bool {
    return std.mem.eql(u8, to.storage.addr[0..12], &[12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff });
}

/// Whether datagrams to `to` travel in IPv6 packets (not IPv4, nor
/// IPv4-mapped on a dual-stack socket): 20 more bytes of header each.
pub fn isIpv6(to: *const Addr) bool {
    return to.storage.family == posix.AF.INET6 and !isMapped(to);
}

/// One sendmsg of `data` to `to` with `control`, retried on EINTR.
fn sendmsg(fd: fd_t, to: *const Addr, data: []const u8, control: []u8) posix.E {
    var iov = [1]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
    const Msg = if (sys.is_linux) linux.msghdr_const else std.c.msghdr_const;
    const msg: Msg = .{
        .name = to.sockaddr(),
        .namelen = to.len,
        .iov = &iov,
        .iovlen = 1,
        .control = if (control.len > 0) control.ptr else null,
        .controllen = @intCast(control.len),
        .flags = 0,
    };
    while (true) {
        const e = if (sys.is_linux) posix.errno(linux.sendmsg(fd, &msg, 0)) else posix.errno(std.c.sendmsg(fd, &msg, 0));
        if (e != .INTR) return e;
    }
}

/// Sends `data` to `to`: one datagram, or (Linux, `segment` set) several
/// datagrams of `segment` bytes each, the last possibly shorter, all with
/// the ECN codepoint `ecn` (no control message for Not-ECT).
pub fn send(fd: fd_t, to: *const Addr, data: []const u8, segment: ?u16, ecn: Ecn) SendError!void {
    var control: [2 * ecn_cmsg_space]u8 align(@alignOf(sys.cmsghdr)) = @splat(0);
    var len: usize = 0;
    if (sys.is_linux) {
        if (segment) |seg| {
            if (data.len > seg) len = sys.putCmsg(&control, len, SOL_UDP, UDP_SEGMENT, std.mem.asBytes(&seg));
        }
    }
    // The TOS message last, so it can be dropped.
    const plain = len;
    if (ecn != .not_ect) {
        const v: c_int = @backingInt(ecn);
        len = switch (tosKind(to)) {
            0 => sys.putCmsg(&control, len, posix.IPPROTO.IP, posix.IP.TOS, std.mem.asBytes(&v)),
            1 => sys.putCmsg(&control, len, posix.IPPROTO.IPV6, posix.IPV6.TCLASS, std.mem.asBytes(&v)),
        };
    }
    var refused = false;
    var rest = data;
    // Elsewhere than Linux: datagram by datagram.
    const seg = if (sys.is_linux) data.len else segment orelse data.len;
    while (rest.len > 0) {
        const n = @min(rest.len, seg);
        var e = sendmsg(fd, to, rest[0..n], control[0..len]);
        if (e == .INVAL and len > plain) {
            // EINVAL has other causes (a peer at port 0, a GSO segment
            // over the route's MTU): it is the TOS message only if the
            // send goes without it.
            e = sendmsg(fd, to, rest[0..n], control[0..plain]);
            if (e == .SUCCESS) {
                refused = true;
                len = plain;
            }
        }
        switch (e) {
            .SUCCESS => {},
            // (The refusal is news the caller keeps.)
            .AGAIN => return if (refused) error.TosRefused else error.WouldBlock,
            .MSGSIZE => return error.MessageTooBig,
            // EIO: GSO unsupported by the device; ECONNREFUSED and
            // friends: ICMP errors from earlier sends. Drop.
            else => return if (refused) error.TosRefused else error.Unexpected,
        }
        rest = rest[n..];
    }
    if (refused) return error.TosRefused;
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

fn putInt(control: []u8, pos: usize, level: i32, ty: i32, comptime T: type, value: T) usize {
    return sys.putCmsg(control, pos, level, ty, std.mem.asBytes(&value));
}

test "ECN codepoint from control messages" {
    var control: [3 * ecn_cmsg_space]u8 align(@alignOf(sys.cmsghdr)) = @splat(0);
    // IP_TOS as one byte (Linux), DSCP bits above the ECN field.
    var len = putInt(&control, 0, posix.IPPROTO.IP, ip_tos_recv, u8, 0xb8 | 3);
    try testing.expectEqual(Ecn.ce, ecnFromControl(control[0..len]));
    // IPV6_TCLASS as an int, after a message of another kind.
    len = putInt(&control, 0, posix.SOL.SOCKET, 1, c_int, 7);
    len = putInt(&control, len, posix.IPPROTO.IPV6, posix.IPV6.TCLASS, c_int, 0x22);
    try testing.expectEqual(Ecn.ect0, ecnFromControl(control[0..len]));
    // Nothing, a cut header, a length beyond the buffer or under a header.
    try testing.expectEqual(Ecn.not_ect, ecnFromControl(control[0..0]));
    try testing.expectEqual(Ecn.not_ect, ecnFromControl(control[0 .. sys.cmsg_hdr_len - 1]));
    len = putInt(&control, 0, posix.IPPROTO.IP, ip_tos_recv, c_int, 1);
    try testing.expectEqual(Ecn.ect1, ecnFromControl(control[0..len]));
    try testing.expectEqual(Ecn.not_ect, ecnFromControl(control[0 .. len - sys.cmsg_align]));
    const hdr: *align(1) sys.cmsghdr = @ptrCast(&control);
    hdr.len = 2;
    try testing.expectEqual(Ecn.not_ect, ecnFromControl(control[0..len]));
}

test "ECN codepoints set per send come back on loopback (GSO sends too)" {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    const fd = try bind(addr, false);
    defer sys.close(fd);
    enableEcn(fd, false);
    addr.setPort(try localPort(fd));
    const to: Addr = .fromIp(addr);
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

// -- verify ECN: adversarial cases --------------------------------------------

/// Sends `data` from `from_fd` to `to` with each codepoint and checks
/// what arrives on `to_fd`.
fn expectCodepoints(from_fd: fd_t, to_fd: fd_t, to: *const Addr, segment: ?u16) !void {
    const batch = try testing.allocator.create(RecvBatch(8, 2048));
    defer testing.allocator.destroy(batch);
    const data: [2000]u8 = @splat(0x5a);
    for ([_]Ecn{ .ect0, .ce, .not_ect, .ect1, .ect0 }) |ecn| {
        try send(from_fd, to, &data, segment, ecn);
        const want: usize = if (segment != null) 2 else 1;
        var got: usize = 0;
        var tries: usize = 0;
        while (got < want and tries < 200_000) : (tries += 1) {
            const n = batch.recv(to_fd);
            for (0..n) |i| try testing.expectEqual(ecn, batch.get(i).ecn);
            got += n;
        }
        try testing.expectEqual(want, got);
    }
}

test "verify ECN: IPv6 loopback, and IPv4-mapped peers on a dual-stack socket" {
    // IPv6 both ways.
    {
        var a6: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = std.mem.zeroes([16]u8), .port = 0 } };
        a6.ip6.bytes[15] = 1;
        const s = bind(a6, false) catch return error.SkipZigTest; // no IPv6 here
        defer sys.close(s);
        enableEcn(s, true);
        const c = try bind(a6, false);
        defer sys.close(c);
        enableEcn(c, true);
        a6.setPort(try localPort(s));
        const to = Addr.fromIp(a6);
        try expectCodepoints(c, s, &to, null);
        try expectCodepoints(c, s, &to, 1000);
    }
    // A dual-stack server socket ([::]) and an IPv4 client, both ways:
    // the server sends to the client's IPv4-mapped address.
    {
        var any6: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = std.mem.zeroes([16]u8), .port = 0 } };
        const s = try bind(any6, false);
        defer sys.close(s);
        // (Dual stack: the default on Linux and macOS.)
        enableEcn(s, true);
        any6.setPort(try localPort(s));
        var a4: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
        const c = try bind(a4, false);
        defer sys.close(c);
        enableEcn(c, false);
        a4.setPort(any6.ip6.port);
        // Client to server: an IPv4 datagram arrives on the IPv6 socket.
        const to_server = Addr.fromIp(a4);
        try expectCodepoints(c, s, &to_server, null);
        // Server to client, at the client's mapped address (the sockaddr
        // the server's recvmsg reported).
        const mapped: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 }, .port = try localPort(c) } };
        const to_client = Addr.fromIp(mapped);
        try expectCodepoints(s, c, &to_client, null);
        try expectCodepoints(s, c, &to_client, 1000);
    }
}

test "verify ECN: a send failing EINVAL for another reason doesn't stop marking" {
    if (!sys.is_linux) return error.SkipZigTest;
    var addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    const fd = try bind(addr, false);
    defer sys.close(fd);
    enableEcn(fd, false);
    // A peer at port 0 (a client can send from it, through a raw socket):
    // Linux's udp_sendmsg refuses the destination with EINVAL, TOS or not.
    var port0 = Addr.fromIp(addr);
    try testing.expectError(error.Unexpected, send(fd, &port0, "x", null, .ect0));
    // Every other peer's datagrams still carry their marks.
    addr.setPort(try localPort(fd));
    const to = Addr.fromIp(addr);
    try expectCodepoints(fd, fd, &to, null);
}

test "DF: a datagram larger than the interface fails with MessageTooBig instead of being fragmented" {
    var addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    const fd = try bind(addr, false);
    defer sys.close(fd);
    try testing.expect(setDontFragment(fd, false));
    addr.setPort(try localPort(fd));
    const self_addr: Addr = .fromIp(addr);
    const big = try testing.allocator.alloc(u8, 16384);
    defer testing.allocator.free(big);
    @memset(big, 0x5a);
    if (sys.is_linux) {
        var v: c_int = 0;
        var len: posix.socklen_t = @sizeOf(c_int);
        try testing.expectEqual(posix.E.SUCCESS, posix.errno(linux.getsockopt(fd, posix.IPPROTO.IP, linux.IP.MTU_DISCOVER, @ptrCast(&v), &len)));
        try testing.expectEqual(@as(c_int, linux.IP.PMTUDISC_PROBE), v);
        // Out of an Ethernet-sized interface (Docker's), where there is a
        // route: 1600 bytes don't fit in 1500 and aren't fragmented.
        const far: Addr = .fromIp(.{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9 } });
        const plain_fd = try bind(.{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } }, false);
        defer sys.close(plain_fd);
        const routed = if (send(plain_fd, &far, big[0..1600], null, .not_ect)) true else |_| false;
        if (routed) {
            const df = try bind(.{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } }, false);
            defer sys.close(df);
            try testing.expect(setDontFragment(df, false));
            send(df, &far, big[0..1600], null, .not_ect) catch |err| try testing.expectEqual(error.MessageTooBig, err);
        }
        return;
    }
    // macOS: lo0's MTU is 16384, so a 16384-byte payload needs fragments.
    try testing.expectError(error.MessageTooBig, send(fd, &self_addr, big, null, .not_ect));
    try send(fd, &self_addr, big[0 .. 16384 - 28], null, .not_ect);
    // Without DF the kernel fragments it.
    const plain = try bind(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } }, false);
    defer sys.close(plain);
    try send(plain, &self_addr, big, null, .not_ect);
    // IPv6 too, where there is IPv6.
    var a6: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = std.mem.zeroes([16]u8), .port = 0 } };
    a6.ip6.bytes[15] = 1;
    const s6 = bind(a6, false) catch return;
    defer sys.close(s6);
    try testing.expect(setDontFragment(s6, true));
    a6.setPort(try localPort(s6));
    const to6: Addr = .fromIp(a6);
    try testing.expectError(error.MessageTooBig, send(s6, &to6, big, null, .not_ect));
}
