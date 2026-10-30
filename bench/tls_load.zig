//! TLS 1.3 handshake load generator (Linux): new connections as fast as
//! the server completes them, each a full handshake (or a resumption) and
//! one request.
//! Usage: tls-load [ip] [port] [threads] [connections] [seconds] [group] [http1|h2] [full|resume] [warm-up seconds] [ecdsa|rsa] [verify 1 in N]
//! Defaults: 127.0.0.1 8443 6 192 8 x25519 http1 full 1 ecdsa 1.
//! group: x25519, p256 (secp256r1) or mlkem (X25519MLKEM768).
//!
//! `connections` is how many are in flight at once, spread over the
//! threads, each with its own epoll. A connection is done when its
//! response has arrived; it is then closed with a reset (SO_LINGER 0, so
//! neither side keeps a TIME_WAIT socket) and replaced by a new one.
//!
//! What the server sees is a browser-like ClientHello: a 32-byte
//! legacy_session_id (middlebox compatibility, so a change_cipher_spec
//! each way), SNI "localhost", signature algorithms for ECDSA, RSA-PSS and
//! Ed25519, psk_dhe_ke (so the server sends its tickets), ALPN. The client
//! spends less than a browser so that 6 cores of it can keep 6 server
//! cores busy: it offers only TLS_AES_128_GCM_SHA256 and the one group,
//! keeps one key share per thread (so it computes only the shared secret
//! per connection), and does not build or check a certificate chain.
//! OpenSSL clients (wrk, h2load) spend more per handshake than the servers
//! measured and peak at about 4000/s on 6 cores.
//!
//! What it does check in every full handshake: the server's certificate
//! is the benchmark's (`ecdsa`: bench/cert.pem, P-256; `rsa`: bench/rsa.pem,
//! RSA-2048), byte for byte, and its CertificateVerify uses that key's
//! scheme (ecdsa_secp256r1_sha256 or rsa_pss_rsae_sha256). The signature
//! itself is verified with std (about as costly as the server's whole
//! handshake for ECDSA) in one full handshake in N per thread, so that a
//! client can afford it against 6 server cores; N = 1 verifies every one.
//! The server's Finished is checked in every handshake, resumed ones too
//! (it proves the key exchange and the transcript).
//!
//! With `resume`, a thread without a ticket makes a full handshake; then
//! every connection offers the newest ticket the thread holds (one
//! pre_shared_key identity, psk_dhe_ke: a resumption with a fresh key
//! exchange and no certificate or signature).
//!
//! Requests: `http1` is "GET / HTTP/1.1" with `Connection: close`, done
//! when the Content-Length body has arrived; `h2` sends the preface, an
//! empty SETTINGS and a GET on stream 1 (with the Finished, in one write),
//! acknowledges the server's SETTINGS, and is done at the stream's
//! END_STREAM. Every response must be 200.
//!
//! After the warm-up it prints "measuring" and after `seconds` "measured"
//! (a caller reads the server's CPU time at each), then the handshakes
//! completed in between, the rate, how many resumed, how many had their
//! signature verified, the client's own CPU time in between as cores used,
//! the parameters the first full and the first resumed connection
//! negotiated (suite, group, signature algorithm, ALPN, the certificate,
//! tickets) and the errors.
const std = @import("std");
const per = @import("peregrine");
const sys = per.internal.sys;
const record = per.internal.tls_record;
const x25519 = per.internal.tls_x25519;
const p256 = per.internal.tls_p256;
const posix = std.posix;
const linux = std.os.linux;
const tls = std.crypto.tls;
const Sha256 = std.crypto.hash.sha2.Sha256;
const MLKem768 = std.crypto.kem.ml_kem.MLKem768;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Certificate = std.crypto.Certificate;
const Rsa = Certificate.rsa;
const Protection = record.Protection;

const suite: record.Suite = .aes_128_gcm_sha256;
const ks = suite.Schedule();

const Group = enum {
    x25519,
    p256,
    mlkem,

    fn named(g: Group) tls.NamedGroup {
        return switch (g) {
            .x25519 => .x25519,
            .p256 => .secp256r1,
            .mlkem => .x25519_ml_kem768,
        };
    }
};

const Proto = enum { http1, h2 };

const CertKind = enum { ecdsa, rsa };

/// The certificate every server is given, and its key for checking
/// CertificateVerify.
const Expected = struct {
    der: []const u8,
    scheme: tls.SignatureScheme,
    key: union(enum) {
        ecdsa: EcdsaP256Sha256.PublicKey,
        rsa: Rsa.PublicKey,
    },

    const rsa_len = 256;

    fn init(which: CertKind, buf: []u8) !Expected {
        const pem = switch (which) {
            .ecdsa => @embedFile("cert.pem"),
            .rsa => @embedFile("rsa.pem"),
        };
        const begin = "-----BEGIN CERTIFICATE-----";
        const start = (std.mem.indexOf(u8, pem, begin) orelse return error.BadPem) + begin.len;
        const end = std.mem.indexOfPos(u8, pem, start, "-----END CERTIFICATE-----") orelse return error.BadPem;
        const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
        if (decoder.calcSizeUpperBound(end - start) > buf.len) return error.BadPem;
        const der = buf[0..try decoder.decode(buf, pem[start..end])];
        const parsed = try (Certificate{ .buffer = der, .index = 0 }).parse();
        return switch (which) {
            .ecdsa => .{
                .der = der,
                .scheme = .ecdsa_secp256r1_sha256,
                .key = .{ .ecdsa = try .fromSec1(parsed.pubKey()) },
            },
            .rsa => blk: {
                const parts = try Rsa.PublicKey.parseDer(parsed.pubKey());
                if (parts.modulus.len != rsa_len) return error.NotRsa2048;
                break :blk .{
                    .der = der,
                    .scheme = .rsa_pss_rsae_sha256,
                    .key = .{ .rsa = try .fromBytes(parts.exponent, parts.modulus) },
                };
            },
        };
    }

    /// Checks a CertificateVerify signature over `transcript_hash` (RFC
    /// 8446 §4.4.3).
    fn verify(self: *const Expected, sig: []const u8, transcript_hash: *const [32]u8) !void {
        const context = "TLS 1.3, server CertificateVerify";
        var content: [64 + context.len + 1 + 32]u8 = undefined;
        @memset(content[0..64], 0x20);
        content[64..][0..context.len].* = context.*;
        content[64 + context.len] = 0;
        content[64 + context.len + 1 ..].* = transcript_hash.*;
        switch (self.key) {
            .ecdsa => |key| try (try EcdsaP256Sha256.Signature.fromDer(sig)).verify(&content, key),
            .rsa => |key| {
                if (sig.len != rsa_len) return error.BadSignature;
                try Rsa.PSSSignature.verify(rsa_len, sig[0..rsa_len], &content, key, Sha256);
            },
        }
    }
};

const Options = struct {
    ip: [4]u8 = .{ 127, 0, 0, 1 },
    port: u16 = 8443,
    threads: usize = 6,
    connections: usize = 192,
    seconds: u64 = 8,
    group: Group = .x25519,
    proto: Proto = .http1,
    resume_: bool = false,
    warm_up: u64 = 1,
    expected: Expected = undefined,
    verify_every: u64 = 1,
};

/// A connection that hasn't finished in this long is counted as an error
/// and replaced.
const timeout_ns = 5 * std.time.ns_per_s;

const mlkem_share_len = MLKem768.PublicKey.encoded_length + 32;
const mlkem_reply_len = MLKem768.ciphertext_length + 32;

/// One thread's key share, offered on every connection.
const KeyShare = struct {
    group: Group,
    x_secret: [32]u8 = undefined,
    p_secret: [32]u8 = undefined,
    mlkem: MLKem768.SecretKey = undefined,
    public: [mlkem_share_len]u8 = undefined,
    public_len: usize = 0,

    fn init(group: Group) !KeyShare {
        var ks_: KeyShare = .{ .group = group };
        var seed: [MLKem768.seed_length]u8 = undefined;
        sys.randomBytes(&seed);
        switch (group) {
            .x25519 => {
                ks_.x_secret = seed[0..32].*;
                ks_.public[0..32].* = x25519.publicKey(ks_.x_secret);
                ks_.public_len = 32;
            },
            .p256 => {
                const kp = try p256.keyPair(seed[0..32].*);
                ks_.p_secret = kp.secret_key;
                ks_.public[0..65].* = kp.public_key;
                ks_.public_len = 65;
            },
            .mlkem => {
                const kp = try MLKem768.KeyPair.generateDeterministic(seed);
                ks_.mlkem = kp.secret_key;
                sys.randomBytes(&ks_.x_secret);
                ks_.public[0..MLKem768.PublicKey.encoded_length].* = kp.public_key.toBytes();
                ks_.public[MLKem768.PublicKey.encoded_length..][0..32].* = x25519.publicKey(ks_.x_secret);
                ks_.public_len = mlkem_share_len;
            },
        }
        return ks_;
    }

    /// The shared secret for the server's key share.
    fn shared(self: *const KeyShare, server: []const u8, out: *[64]u8) ![]const u8 {
        switch (self.group) {
            .x25519 => {
                if (server.len != 32) return error.BadKeyShare;
                out[0..32].* = try x25519.sharedSecret(self.x_secret, server[0..32].*);
                return out[0..32];
            },
            .p256 => {
                out[0..32].* = try p256.sharedSecret(self.p_secret, server);
                return out[0..32];
            },
            .mlkem => {
                if (server.len != mlkem_reply_len) return error.BadKeyShare;
                out[0..32].* = try self.mlkem.decaps(server[0..MLKem768.ciphertext_length]);
                out[32..64].* = try x25519.sharedSecret(self.x_secret, server[MLKem768.ciphertext_length..][0..32].*);
                return out[0..64];
            },
        }
    }
};

const max_ticket = 1024;

const Ticket = struct {
    identity: [max_ticket]u8 = undefined,
    len: usize = 0,
    psk: ks.Secret = undefined,
    age_add: u32 = 0,
    received_ns: u64 = 0,
};

/// What the first completed connection negotiated.
const Negotiated = struct {
    cipher: u16 = 0,
    group: u16 = 0,
    sig: u16 = 0,
    alpn: [16]u8 = undefined,
    alpn_len: usize = 0,
    cert_len: usize = 0,
    tickets: usize = 0,
    resumed: bool = false,
};

const State = enum { connecting, hello, flight, app };

const in_cap = record.max_record + 1024;
const hs_cap = 16 * 1024;
const resp_cap = 4096;

const Conn = struct {
    fd: sys.fd_t = -1,
    gen: u32 = 0,
    state: State = .connecting,
    started_ns: u64 = 0,
    in_len: usize = 0,
    hs_len: usize = 0,
    resp_len: usize = 0,
    transcript: Sha256 = undefined,
    offered_psk: bool = false,
    psk: ks.Secret = undefined,
    resumed: bool = false,
    /// Its CertificateVerify signature was verified.
    verified: bool = false,
    hs_secret: ks.Secret = undefined,
    c_hs: ks.Secret = undefined,
    s_hs: ks.Secret = undefined,
    res_master: ks.Secret = undefined,
    read: Protection = undefined,
    write: Protection = undefined,
    neg: Negotiated = .{},
    /// http1: where the body starts and how long it is, once the head is in.
    body_at: usize = 0,
    body_len: usize = 0,
    status_ok: bool = false,
    answered: bool = false,
    in: [in_cap]u8 = undefined,
    hs: [hs_cap]u8 = undefined,
    resp: [resp_cap]u8 = undefined,

    /// Ready for a new connection (field by field: the buffers stay).
    fn reset(c: *Conn, gen: u32) void {
        c.fd = -1;
        c.gen = gen;
        c.state = .connecting;
        c.in_len = 0;
        c.hs_len = 0;
        c.resp_len = 0;
        c.offered_psk = false;
        c.resumed = false;
        c.verified = false;
        c.neg = .{};
        c.body_at = 0;
        c.body_len = 0;
        c.status_ok = false;
        c.answered = false;
    }
};

const Worker = struct {
    o: *const Options,
    conn_count: usize,
    share: KeyShare = undefined,
    ticket: Ticket = .{},
    rng: std.Random.DefaultPrng = undefined,
    epfd: i32 = -1,
    completed: std.atomic.Value(u64) = .init(0),
    resumed: std.atomic.Value(u64) = .init(0),
    verified: std.atomic.Value(u64) = .init(0),
    tickets: std.atomic.Value(u64) = .init(0),
    /// CertificateVerify messages seen, for verifying one in N.
    signatures: u64 = 0,
    errors: std.atomic.Value(u64) = .init(0),
    first_error: ?anyerror = null,
    first_full: ?Negotiated = null,
    first_resumed: ?Negotiated = null,
    thread: std.Thread = undefined,

    fn run(self: *Worker, stop: *std.atomic.Value(bool)) void {
        self.loop(stop) catch |err| {
            std.debug.print("tls-load: {s}\n", .{@errorName(err)});
            if (self.first_error == null) self.first_error = err;
            _ = self.errors.fetchAdd(1, .release);
        };
    }

    fn loop(self: *Worker, stop: *std.atomic.Value(bool)) !void {
        const allocator = std.heap.smp_allocator;
        self.share = try KeyShare.init(self.o.group);
        var seed: [8]u8 = undefined;
        sys.randomBytes(&seed);
        self.rng = .init(std.mem.readInt(u64, &seed, .little));
        const conns = try allocator.alloc(Conn, self.conn_count);
        defer allocator.free(conns);
        const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (posix.errno(epfd_rc) != .SUCCESS) return error.EpollFailed;
        self.epfd = @intCast(epfd_rc);
        defer sys.close(self.epfd);
        for (conns) |*c| c.reset(0);
        defer for (conns) |*c| if (c.fd >= 0) sys.close(c.fd);
        for (conns, 0..) |*c, i| self.restart(c, i);
        var events: [256]linux.epoll_event = undefined;
        var last_scan = sys.nanoTimestamp();
        while (!stop.load(.acquire)) {
            const rc = linux.epoll_wait(self.epfd, &events, events.len, 50);
            if (posix.errno(rc) == .SUCCESS) {
                for (events[0..rc]) |ev| {
                    const i: usize = @intCast(ev.data.u64 & 0xffff_ffff);
                    const c = &conns[i];
                    if (c.gen != @as(u32, @intCast(ev.data.u64 >> 32)) or c.fd < 0) continue;
                    const done = self.onEvent(c, ev.events) catch |err| {
                        self.failed(err);
                        self.restart(c, i);
                        continue;
                    };
                    if (done) {
                        self.finish(c);
                        self.restart(c, i);
                    }
                }
            }
            const now = sys.nanoTimestamp();
            if (now - last_scan > 100 * std.time.ns_per_ms) {
                last_scan = now;
                for (conns, 0..) |*c, i| {
                    if (now - c.started_ns > timeout_ns) {
                        self.failed(error.Timeout);
                        self.restart(c, i);
                    }
                }
            }
        }
    }

    fn failed(self: *Worker, err: anyerror) void {
        if (self.first_error == null) {
            self.first_error = err;
            std.debug.print("tls-load: first error: {s}\n", .{@errorName(err)});
        }
        _ = self.errors.fetchAdd(1, .release);
    }

    fn finish(self: *Worker, c: *Conn) void {
        _ = self.completed.fetchAdd(1, .release);
        if (c.resumed) _ = self.resumed.fetchAdd(1, .release);
        if (c.verified) _ = self.verified.fetchAdd(1, .release);
        _ = self.tickets.fetchAdd(c.neg.tickets, .release);
        const first = if (c.resumed) &self.first_resumed else &self.first_full;
        if (first.* == null) first.* = c.neg;
    }

    /// Closes the slot's connection (with a reset) and opens a new one.
    fn restart(self: *Worker, c: *Conn, i: usize) void {
        if (c.fd >= 0) {
            const linger = extern struct { onoff: c_int, linger: c_int }{ .onoff = 1, .linger = 0 };
            _ = linux.setsockopt(c.fd, linux.SOL.SOCKET, linux.SO.LINGER, std.mem.asBytes(&linger), @sizeOf(@TypeOf(linger)));
            sys.close(c.fd);
            c.fd = -1;
        }
        c.reset(c.gen +% 1);
        self.open(c, i) catch |err| {
            // Counted, and retried by the timeout scan.
            self.failed(err);
            c.started_ns = sys.nanoTimestamp();
        };
    }

    fn open(self: *Worker, c: *Conn, i: usize) !void {
        c.started_ns = sys.nanoTimestamp();
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, linux.IPPROTO.TCP);
        if (posix.errno(rc) != .SUCCESS) return error.SocketFailed;
        c.fd = @intCast(rc);
        try sys.setsockoptInt(c.fd, linux.IPPROTO.TCP, sys.TCP_NODELAY, 1);
        var ev = linux.epoll_event{
            .events = linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.RDHUP | linux.EPOLL.ET,
            .data = .{ .u64 = @as(u64, c.gen) << 32 | i },
        };
        if (posix.errno(linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, c.fd, &ev)) != .SUCCESS) return error.EpollFailed;
        var addr = std.mem.zeroes(linux.sockaddr.in);
        addr.family = linux.AF.INET;
        addr.port = std.mem.nativeToBig(u16, self.o.port);
        addr.addr = @bitCast(self.o.ip);
        switch (posix.errno(linux.connect(c.fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)))) {
            .SUCCESS => try self.sendHello(c),
            .INPROGRESS => {},
            else => return error.ConnectFailed,
        }
    }

    /// Returns whether the connection is done.
    fn onEvent(self: *Worker, c: *Conn, events: u32) !bool {
        if (c.state == .connecting) {
            if (events & (linux.EPOLL.ERR | linux.EPOLL.HUP) != 0) return error.ConnectFailed;
            if (events & linux.EPOLL.OUT == 0) return false;
            try self.sendHello(c);
        }
        if (events & linux.EPOLL.IN != 0 or events & (linux.EPOLL.RDHUP | linux.EPOLL.HUP | linux.EPOLL.ERR) != 0) {
            while (true) {
                if (c.in_len == c.in.len) return error.RecordTooLong;
                const n = sys.read(c.fd, c.in[c.in_len..]) catch |err| switch (err) {
                    error.WouldBlock => return false,
                    else => return err,
                };
                if (n == 0) {
                    if (c.answered) return true;
                    return error.ConnectionClosed;
                }
                c.in_len += n;
                if (try self.records(c)) return true;
            }
        }
        return false;
    }

    fn sendAll(c: *Conn, data: []const u8) !void {
        // Small writes into an empty socket buffer: they always fit.
        const n = try sys.write(c.fd, data);
        if (n != data.len) return error.ShortWrite;
    }

    fn sendHello(self: *Worker, c: *Conn) !void {
        var buf: [4096]u8 = undefined;
        var w: Writer = .{ .buf = &buf };
        w.int(u8, @backingInt(tls.ContentType.handshake));
        w.int(u16, 0x0301);
        const rec = w.begin(u16);
        const msg_start = w.pos;
        w.int(u8, @backingInt(tls.HandshakeType.client_hello));
        const msg = w.begin(u24);
        w.int(u16, 0x0303);
        var random: [64]u8 = undefined;
        self.rng.fill(&random);
        w.bytes(random[0..32]);
        w.int(u8, 32);
        w.bytes(random[32..64]); // legacy_session_id
        w.int(u16, 2);
        w.int(u16, @backingInt(suite));
        w.int(u8, 1);
        w.int(u8, 0);
        const exts = w.begin(u16);
        // server_name
        w.int(u16, @backingInt(tls.ExtensionType.server_name));
        const sn = w.begin(u16);
        const sn_list = w.begin(u16);
        w.int(u8, 0);
        w.int(u16, "localhost".len);
        w.bytes("localhost");
        w.end(u16, sn_list);
        w.end(u16, sn);
        w.int(u16, @backingInt(tls.ExtensionType.supported_versions));
        w.int(u16, 3);
        w.int(u8, 2);
        w.int(u16, 0x0304);
        w.int(u16, @backingInt(tls.ExtensionType.supported_groups));
        w.int(u16, 4);
        w.int(u16, 2);
        w.int(u16, @backingInt(self.o.group.named()));
        w.int(u16, @backingInt(tls.ExtensionType.signature_algorithms));
        const sa = w.begin(u16);
        const sa_list = w.begin(u16);
        for ([_]u16{ 0x0403, 0x0804, 0x0807, 0x0503, 0x0805, 0x0603, 0x0806 }) |alg| w.int(u16, alg);
        w.end(u16, sa_list);
        w.end(u16, sa);
        w.int(u16, @backingInt(tls.ExtensionType.key_share));
        const share = self.share.public[0..self.share.public_len];
        w.int(u16, @intCast(share.len + 6));
        w.int(u16, @intCast(share.len + 4));
        w.int(u16, @backingInt(self.o.group.named()));
        w.int(u16, @intCast(share.len));
        w.bytes(share);
        w.int(u16, @backingInt(tls.ExtensionType.psk_key_exchange_modes));
        w.int(u16, 2);
        w.int(u8, 1);
        w.int(u8, 1); // psk_dhe_ke
        w.int(u16, @backingInt(tls.ExtensionType.application_layer_protocol_negotiation));
        const alpn: []const u8 = if (self.o.proto == .h2) "h2" else "http/1.1";
        w.int(u16, @intCast(alpn.len + 3));
        w.int(u16, @intCast(alpn.len + 1));
        w.int(u8, @intCast(alpn.len));
        w.bytes(alpn);
        const t = &self.ticket;
        c.offered_psk = self.o.resume_ and t.len > 0;
        if (c.offered_psk) {
            // pre_shared_key, last: one identity and its binder over the
            // ClientHello up to the binders (RFC 8446 §4.2.11.2).
            w.int(u16, @backingInt(tls.ExtensionType.pre_shared_key));
            w.int(u16, @intCast(2 + 2 + t.len + 4 + 2 + 1 + ks.hash_len));
            w.int(u16, @intCast(2 + t.len + 4));
            w.int(u16, @intCast(t.len));
            w.bytes(t.identity[0..t.len]);
            const age_ms: u32 = @truncate((sys.nanoTimestamp() - t.received_ns) / std.time.ns_per_ms);
            w.int(u32, age_ms +% t.age_add);
            const binders_at = w.pos;
            w.int(u16, 1 + ks.hash_len);
            w.int(u8, ks.hash_len);
            w.fill(ks.hash_len, 0);
            w.end(u16, exts);
            w.end(u24, msg);
            w.end(u16, rec);
            c.psk = t.psk;
            const early = ks.earlySecretPsk(&c.psk);
            const binder_key = ks.deriveSecret(early, "res binder", &ks.empty_hash);
            var partial = Sha256.init(.{});
            partial.update(buf[msg_start..binders_at]);
            const binder = ks.finishedVerifyData(binder_key, &partial.finalResult());
            @memcpy(buf[binders_at + 3 ..][0..ks.hash_len], &binder);
        } else {
            w.end(u16, exts);
            w.end(u24, msg);
            w.end(u16, rec);
        }
        c.transcript = Sha256.init(.{});
        c.transcript.update(buf[msg_start..w.pos]);
        try sendAll(c, buf[0..w.pos]);
        c.state = .hello;
    }

    /// Handles every whole record in the input; returns whether the
    /// connection is done.
    fn records(self: *Worker, c: *Conn) !bool {
        var pos: usize = 0;
        defer {
            std.mem.copyForwards(u8, c.in[0 .. c.in_len - pos], c.in[pos..c.in_len]);
            c.in_len -= pos;
        }
        while (c.in_len - pos >= record.header_len) {
            const len = std.mem.readInt(u16, c.in[pos + 3 ..][0..2], .big);
            if (len > record.max_ciphertext) return error.RecordOverflow;
            if (c.in_len - pos < record.header_len + len) break;
            const rec = c.in[pos..][0 .. record.header_len + len];
            pos += rec.len;
            switch (rec[0]) {
                @backingInt(tls.ContentType.change_cipher_spec) => {},
                @backingInt(tls.ContentType.alert) => return error.AlertReceived,
                @backingInt(tls.ContentType.handshake) => {
                    if (c.state != .hello) return error.UnexpectedMessage;
                    try self.handshakeBytes(c, rec[record.header_len..]);
                },
                @backingInt(tls.ContentType.application_data) => {
                    if (c.state == .hello) return error.UnexpectedMessage;
                    const opened = try c.read.open(rec);
                    switch (opened.content_type) {
                        .handshake => try self.handshakeBytes(c, opened.data),
                        .application_data => {
                            if (c.state != .app) return error.UnexpectedMessage;
                            try self.response(c, opened.data);
                        },
                        .alert => {
                            if (opened.data.len == 2 and opened.data[1] == 0 and c.answered) return true;
                            return error.AlertReceived;
                        },
                        else => return error.UnexpectedMessage,
                    }
                },
                else => return error.UnexpectedMessage,
            }
            if (c.answered and (!self.o.resume_ or c.neg.tickets > 0 or self.ticket.len > 0)) return true;
        }
        return false;
    }

    fn handshakeBytes(self: *Worker, c: *Conn, data: []const u8) !void {
        if (c.hs_len + data.len > c.hs.len) return error.HandshakeTooLong;
        @memcpy(c.hs[c.hs_len..][0..data.len], data);
        c.hs_len += data.len;
        var pos: usize = 0;
        defer {
            std.mem.copyForwards(u8, c.hs[0 .. c.hs_len - pos], c.hs[pos..c.hs_len]);
            c.hs_len -= pos;
        }
        while (c.hs_len - pos >= 4) {
            const len = std.mem.readInt(u24, c.hs[pos + 1 ..][0..3], .big);
            if (c.hs_len - pos < 4 + len) break;
            const msg = c.hs[pos..][0 .. 4 + len];
            pos += msg.len;
            const keys_change = try self.message(c, msg);
            // A key change must come at the end of a record (§5.1).
            if (keys_change and pos != c.hs_len) return error.UnexpectedMessage;
        }
    }

    /// Returns whether the read keys changed.
    fn message(self: *Worker, c: *Conn, msg: []const u8) !bool {
        const body = msg[4..];
        switch (c.state) {
            .connecting => unreachable,
            .hello => {
                if (msg[0] != @backingInt(tls.HandshakeType.server_hello)) return error.UnexpectedMessage;
                try self.serverHello(c, body);
                c.transcript.update(msg);
                var shared_buf: [64]u8 = undefined;
                const server_share = try serverKeyShare(body);
                const shared = try self.share.shared(server_share, &shared_buf);
                const early = if (c.resumed) ks.earlySecretPsk(&c.psk) else ks.earlySecret();
                c.hs_secret = ks.handshakeSecret(early, shared);
                const hello_hash = c.transcript.peek();
                c.c_hs = ks.deriveSecret(c.hs_secret, "c hs traffic", &hello_hash);
                c.s_hs = ks.deriveSecret(c.hs_secret, "s hs traffic", &hello_hash);
                c.read = .init(suite, &c.s_hs);
                c.state = .flight;
                return true;
            },
            .flight => switch (msg[0]) {
                @backingInt(tls.HandshakeType.encrypted_extensions) => {
                    try encryptedExtensions(c, body);
                    c.transcript.update(msg);
                },
                @backingInt(tls.HandshakeType.certificate) => {
                    if (c.resumed or c.neg.cert_len != 0) return error.UnexpectedMessage;
                    try self.certificate(body);
                    c.neg.cert_len = msg.len;
                    c.transcript.update(msg);
                },
                @backingInt(tls.HandshakeType.certificate_verify) => {
                    if (c.resumed or c.neg.cert_len == 0 or c.neg.sig != 0) return error.UnexpectedMessage;
                    try self.certificateVerify(c, body);
                    c.transcript.update(msg);
                },
                @backingInt(tls.HandshakeType.finished) => {
                    if (!c.resumed and c.neg.sig == 0) return error.UnexpectedMessage;
                    const expected = ks.finishedVerifyData(c.s_hs, &c.transcript.peek());
                    if (body.len != expected.len or !std.mem.eql(u8, body, &expected)) return error.BadFinished;
                    c.transcript.update(msg);
                    try self.clientFlight(c);
                    return true;
                },
                else => return error.UnexpectedMessage,
            },
            .app => {
                if (msg[0] != @backingInt(tls.HandshakeType.new_session_ticket)) return error.UnexpectedMessage;
                c.neg.tickets += 1;
                if (self.o.resume_) try self.newTicket(c, body);
            },
        }
        return false;
    }

    fn serverHello(self: *Worker, c: *Conn, body: []const u8) !void {
        var r: Reader = .{ .buf = body };
        if ((try r.int(u16)) != 0x0303) return error.BadServerHello;
        const random = try r.bytes(32);
        if (std.mem.eql(u8, random, &tls.hello_retry_request_sequence)) return error.HelloRetryRequest;
        _ = try r.bytes(try r.int(u8));
        c.neg.cipher = try r.int(u16);
        if (c.neg.cipher != @backingInt(suite)) return error.BadServerHello;
        _ = try r.int(u8);
        var exts: Reader = .{ .buf = try r.bytes(try r.int(u16)) };
        var version: u16 = 0;
        while (exts.pos < exts.buf.len) {
            const ty = try exts.int(u16);
            var ext: Reader = .{ .buf = try exts.bytes(try exts.int(u16)) };
            switch (ty) {
                @backingInt(tls.ExtensionType.supported_versions) => version = try ext.int(u16),
                @backingInt(tls.ExtensionType.key_share) => c.neg.group = try ext.int(u16),
                @backingInt(tls.ExtensionType.pre_shared_key) => {
                    if (!c.offered_psk or (try ext.int(u16)) != 0) return error.BadServerHello;
                    c.resumed = true;
                },
                else => {},
            }
        }
        if (version != 0x0304) return error.NotTls13;
        if (c.neg.group != @backingInt(self.o.group.named())) return error.WrongGroup;
        c.neg.resumed = c.resumed;
    }

    /// The certificate list must start with the benchmark's certificate.
    fn certificate(self: *Worker, body: []const u8) !void {
        var r: Reader = .{ .buf = body };
        if ((try r.int(u8)) != 0) return error.BadCertificate; // certificate_request_context
        var list: Reader = .{ .buf = try r.bytes(try r.int(u24)) };
        if (r.pos != body.len) return error.BadCertificate;
        const leaf = try list.bytes(try list.int(u24));
        if (!std.mem.eql(u8, leaf, self.o.expected.der)) return error.WrongCertificate;
    }

    fn certificateVerify(self: *Worker, c: *Conn, body: []const u8) !void {
        var r: Reader = .{ .buf = body };
        c.neg.sig = try r.int(u16);
        const sig = try r.bytes(try r.int(u16));
        if (r.pos != body.len) return error.BadCertificateVerify;
        if (c.neg.sig != @backingInt(self.o.expected.scheme)) return error.WrongSignatureScheme;
        defer self.signatures += 1;
        if (self.signatures % self.o.verify_every != 0) return;
        try self.o.expected.verify(sig, &c.transcript.peek());
        c.verified = true;
    }

    fn serverKeyShare(body: []const u8) ![]const u8 {
        var r: Reader = .{ .buf = body };
        _ = try r.bytes(2 + 32);
        _ = try r.bytes(try r.int(u8));
        _ = try r.bytes(3);
        var exts: Reader = .{ .buf = try r.bytes(try r.int(u16)) };
        while (exts.pos < exts.buf.len) {
            const ty = try exts.int(u16);
            var ext: Reader = .{ .buf = try exts.bytes(try exts.int(u16)) };
            if (ty == @backingInt(tls.ExtensionType.key_share)) {
                _ = try ext.int(u16);
                return ext.bytes(try ext.int(u16));
            }
        }
        return error.NoKeyShare;
    }

    fn encryptedExtensions(c: *Conn, body: []const u8) !void {
        var r: Reader = .{ .buf = body };
        var exts: Reader = .{ .buf = try r.bytes(try r.int(u16)) };
        while (exts.pos < exts.buf.len) {
            const ty = try exts.int(u16);
            var ext: Reader = .{ .buf = try exts.bytes(try exts.int(u16)) };
            if (ty == @backingInt(tls.ExtensionType.application_layer_protocol_negotiation)) {
                _ = try ext.int(u16);
                const proto = try ext.bytes(try ext.int(u8));
                if (proto.len > c.neg.alpn.len) return error.BadAlpn;
                @memcpy(c.neg.alpn[0..proto.len], proto);
                c.neg.alpn_len = proto.len;
            }
        }
    }

    /// After the server's Finished: our change_cipher_spec, Finished and
    /// request in one write.
    fn clientFlight(self: *Worker, c: *Conn) !void {
        const fin_hash = c.transcript.peek();
        const master = ks.masterSecret(c.hs_secret);
        const c_ap = ks.deriveSecret(master, "c ap traffic", &fin_hash);
        const s_ap = ks.deriveSecret(master, "s ap traffic", &fin_hash);
        var fin: [4 + ks.hash_len]u8 = undefined;
        fin[0] = @backingInt(tls.HandshakeType.finished);
        std.mem.writeInt(u24, fin[1..4], ks.hash_len, .big);
        fin[4..].* = ks.finishedVerifyData(c.c_hs, &fin_hash);
        c.transcript.update(&fin);
        if (self.o.resume_) c.res_master = ks.deriveSecret(master, "res master", &c.transcript.peek());

        var out: [512]u8 = undefined;
        @memcpy(out[0..6], &[_]u8{ 20, 3, 3, 0, 1, 1 });
        var len: usize = 6;
        var hs_write: Protection = .init(suite, &c.c_hs);
        len += hs_write.seal(out[len..], .handshake, &fin);
        c.write = .init(suite, &c_ap);
        len += c.write.seal(out[len..], .application_data, switch (self.o.proto) {
            .http1 => "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            .h2 => h2_request,
        });
        try sendAll(c, out[0..len]);
        c.read = .init(suite, &s_ap);
        c.state = .app;
    }

    fn newTicket(self: *Worker, c: *Conn, body: []const u8) !void {
        var r: Reader = .{ .buf = body };
        _ = try r.int(u32); // lifetime
        const age_add = try r.int(u32);
        const nonce = try r.bytes(try r.int(u8));
        const identity = try r.bytes(try r.int(u16));
        if (identity.len == 0 or identity.len > max_ticket) return error.BadTicket;
        const t = &self.ticket;
        @memcpy(t.identity[0..identity.len], identity);
        t.len = identity.len;
        t.age_add = age_add;
        t.psk = ks.resumptionPsk(c.res_master, nonce);
        t.received_ns = sys.nanoTimestamp();
    }

    fn response(self: *Worker, c: *Conn, data: []const u8) !void {
        if (c.resp_len + data.len > c.resp.len) return error.ResponseTooLong;
        @memcpy(c.resp[c.resp_len..][0..data.len], data);
        c.resp_len += data.len;
        switch (self.o.proto) {
            .http1 => {
                if (c.body_at == 0) {
                    const head = c.resp[0..c.resp_len];
                    const end = std.mem.indexOf(u8, head, "\r\n\r\n") orelse return;
                    if (!std.mem.startsWith(u8, head, "HTTP/1.1 200 ")) return error.BadStatus;
                    const cl = std.ascii.findIgnoreCase(head[0..end], "\r\ncontent-length:") orelse return error.NoContentLength;
                    const value = std.mem.trim(u8, head[cl + 17 .. std.mem.indexOfPos(u8, head, cl + 2, "\r\n").?], " \t");
                    c.body_len = try std.fmt.parseInt(usize, value, 10);
                    c.body_at = end + 4;
                }
                if (c.resp_len >= c.body_at + c.body_len) c.answered = true;
            },
            .h2 => {
                var pos: usize = 0;
                defer {
                    std.mem.copyForwards(u8, c.resp[0 .. c.resp_len - pos], c.resp[pos..c.resp_len]);
                    c.resp_len -= pos;
                }
                while (c.resp_len - pos >= 9) {
                    const len = std.mem.readInt(u24, c.resp[pos..][0..3], .big);
                    if (c.resp_len - pos < 9 + len) break;
                    const ty = c.resp[pos + 3];
                    const flags = c.resp[pos + 4];
                    const stream = std.mem.readInt(u32, c.resp[pos + 5 ..][0..4], .big) & 0x7fff_ffff;
                    var payload = c.resp[pos + 9 ..][0..len];
                    pos += 9 + len;
                    switch (ty) {
                        1 => if (stream == 1) { // HEADERS
                            if (flags & 0x8 != 0) payload = payload[1 .. payload.len - payload[0]];
                            if (flags & 0x20 != 0) payload = payload[5..];
                            // :status 200 from the static table, or as a literal.
                            if (!(payload.len > 0 and payload[0] == 0x88) and
                                std.mem.indexOf(u8, payload, "\x03200") == null) return error.BadStatus;
                            c.status_ok = true;
                        },
                        3 => if (stream == 1) return error.StreamReset,
                        4 => if (flags & 0x1 == 0) { // SETTINGS: acknowledged, as clients must
                            var out: [9 + record.overhead]u8 = undefined;
                            try sendAll(c, out[0..c.write.seal(&out, .application_data, "\x00\x00\x00\x04\x01\x00\x00\x00\x00")]);
                        },
                        7 => return error.GoAway,
                        else => {},
                    }
                    if (stream == 1 and flags & 0x1 != 0 and (ty == 0 or ty == 1)) {
                        if (!c.status_ok) return error.BadStatus;
                        c.answered = true;
                    }
                }
            },
        }
    }
};

/// The connection preface, an empty SETTINGS and HEADERS for GET / on
/// stream 1 (END_STREAM, END_HEADERS): :method GET, :scheme https,
/// :path / from the static table, :authority localhost as a literal.
const h2_request = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" ++
    "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++
    "\x00\x00\x0e\x01\x05\x00\x00\x00\x01" ++ "\x82\x87\x84\x41\x09localhost";

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn bytes(w: *Writer, b: []const u8) void {
        @memcpy(w.buf[w.pos..][0..b.len], b);
        w.pos += b.len;
    }

    fn fill(w: *Writer, n: usize, v: u8) void {
        @memset(w.buf[w.pos..][0..n], v);
        w.pos += n;
    }

    fn int(w: *Writer, comptime T: type, v: T) void {
        std.mem.writeInt(T, w.buf[w.pos..][0..@divExact(@bitSizeOf(T), 8)], v, .big);
        w.pos += @divExact(@bitSizeOf(T), 8);
    }

    fn begin(w: *Writer, comptime T: type) usize {
        const at = w.pos;
        w.pos += @divExact(@bitSizeOf(T), 8);
        return at;
    }

    fn end(w: *Writer, comptime T: type, at: usize) void {
        std.mem.writeInt(T, w.buf[at..][0..@divExact(@bitSizeOf(T), 8)], @intCast(w.pos - at - @divExact(@bitSizeOf(T), 8)), .big);
    }
};

const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn bytes(r: *Reader, n: usize) ![]const u8 {
        if (r.buf.len - r.pos < n) return error.Truncated;
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }

    fn int(r: *Reader, comptime T: type) !T {
        return std.mem.readInt(T, (try r.bytes(@divExact(@bitSizeOf(T), 8)))[0..@divExact(@bitSizeOf(T), 8)], .big);
    }
};

fn parseIp(s: []const u8) ![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    for (&out) |*b| b.* = try std.fmt.parseInt(u8, it.next() orelse return error.BadIp, 10);
    if (it.next() != null) return error.BadIp;
    return out;
}

fn sleepMs(ms: u64) void {
    var ts: posix.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = linux.nanosleep(&ts, &ts);
}

fn name(comptime E: type, v: u16) []const u8 {
    return std.enums.tagName(E, @fromBackingInt(v)) orelse "unknown";
}

/// This process's CPU time (all threads, user and system), in ns.
fn cpuTime() u64 {
    var ru: linux.rusage = undefined;
    _ = linux.getrusage(linux.rusage.SELF, &ru);
    var ns: u64 = 0;
    for ([_]linux.timeval{ ru.utime, ru.stime }) |t| ns += @as(u64, @intCast(t.sec)) * std.time.ns_per_s + @as(u64, @intCast(t.usec)) * std.time.ns_per_us;
    return ns;
}

fn sum(workers: []Worker, comptime field: []const u8) u64 {
    var total: u64 = 0;
    for (workers) |*w| total += @field(w, field).load(.acquire);
    return total;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var o: Options = .{};
    if (args.len > 1) o.ip = try parseIp(args[1]);
    if (args.len > 2) o.port = try std.fmt.parseInt(u16, args[2], 10);
    if (args.len > 3) o.threads = try std.fmt.parseInt(usize, args[3], 10);
    if (args.len > 4) o.connections = try std.fmt.parseInt(usize, args[4], 10);
    if (args.len > 5) o.seconds = try std.fmt.parseInt(u64, args[5], 10);
    if (args.len > 6) o.group = std.meta.stringToEnum(Group, args[6]) orelse return error.BadGroup;
    if (args.len > 7) o.proto = std.meta.stringToEnum(Proto, args[7]) orelse return error.BadProtocol;
    if (args.len > 8) o.resume_ = std.mem.eql(u8, args[8], "resume") or
        (if (std.mem.eql(u8, args[8], "full")) false else return error.BadMode);
    if (args.len > 9) o.warm_up = try std.fmt.parseInt(u64, args[9], 10);
    var cert_buf: [4096]u8 = undefined;
    o.expected = try .init(if (args.len > 10) std.meta.stringToEnum(CertKind, args[10]) orelse return error.BadCertificate else .ecdsa, &cert_buf);
    if (args.len > 11) o.verify_every = try std.fmt.parseInt(u64, args[11], 10);
    if (o.threads == 0 or o.connections < o.threads or o.verify_every == 0) return error.BadArguments;

    const allocator = std.heap.smp_allocator;
    const workers = try allocator.alloc(Worker, o.threads);
    defer allocator.free(workers);
    var stop: std.atomic.Value(bool) = .init(false);
    for (workers, 0..) |*w, i| {
        w.* = .{ .o = &o, .conn_count = o.connections / o.threads + @intFromBool(i < o.connections % o.threads) };
        w.thread = try std.Thread.spawn(.{}, Worker.run, .{ w, &stop });
    }
    sleepMs(o.warm_up * 1000);
    const n0 = sum(workers, "completed");
    const r0 = sum(workers, "resumed");
    const v0 = sum(workers, "verified");
    const t0 = sum(workers, "tickets");
    const e0 = sum(workers, "errors");
    const start = sys.nanoTimestamp();
    const cpu0 = cpuTime();
    std.debug.print("measuring\n", .{});
    sleepMs(o.seconds * 1000);
    const n = sum(workers, "completed") - n0;
    const resumed = sum(workers, "resumed") - r0;
    const verified = sum(workers, "verified") - v0;
    const tickets = sum(workers, "tickets") - t0;
    const errors = sum(workers, "errors") - e0;
    const elapsed = sys.nanoTimestamp() - start;
    const cpu = cpuTime() - cpu0;
    std.debug.print("measured\n", .{});
    stop.store(true, .release);
    for (workers) |*w| w.thread.join();
    const secs = @as(f64, @floatFromInt(elapsed)) / std.time.ns_per_s;
    std.debug.print("{d} conns, {s}, {s}, {s}: {d} handshakes in {d:.2} s, {d:.0} /s, {d} resumed, {d} signatures verified, {d:.2} tickets each, {d} errors\n", .{
        o.connections,                                                                    @tagName(o.group), @tagName(o.proto),
        if (o.resume_) "resume" else "full",                                              n,                 secs,
        @as(f64, @floatFromInt(n)) / secs,                                                resumed,           verified,
        if (n == 0) 0 else @as(f64, @floatFromInt(tickets)) / @as(f64, @floatFromInt(n)), errors,
    });
    std.debug.print("client: {d:.2} cores\n", .{@as(f64, @floatFromInt(cpu)) / @as(f64, @floatFromInt(elapsed))});
    var first_error: ?anyerror = null;
    var full: ?Negotiated = null;
    var res: ?Negotiated = null;
    for (workers) |*w| {
        first_error = first_error orelse w.first_error;
        full = full orelse w.first_full;
        res = res orelse w.first_resumed;
    }
    for ([_]?Negotiated{ full, res }) |neg| {
        const f = neg orelse continue;
        std.debug.print("negotiated: TLSv1.3 {s} {s} {s} alpn {s} certificate {d} B {s}\n", .{
            name(tls.CipherSuite, f.cipher), name(tls.NamedGroup, f.group), if (f.resumed) "psk" else name(tls.SignatureScheme, f.sig),
            f.alpn[0..f.alpn_len],           f.cert_len,                    if (f.resumed) "resumed" else "full",
        });
    }
    if (first_error) |err| std.debug.print("first error: {s}\n", .{@errorName(err)});
    if (n == 0) return error.NoHandshakes;
}

test "CertificateVerify: the servers' signatures verify, altered ones don't" {
    const credentials = per.internal.tls_credentials;
    for ([_]CertKind{ .ecdsa, .rsa }) |kind| {
        var buf: [4096]u8 = undefined;
        const expected: Expected = try .init(kind, &buf);
        var creds: credentials.Credentials = try .fromPem(
            std.testing.allocator,
            if (kind == .ecdsa) @embedFile("cert.pem") else @embedFile("rsa.pem"),
            if (kind == .ecdsa) @embedFile("key.pem") else @embedFile("rsa.key"),
        );
        defer creds.deinit();
        try std.testing.expectEqualSlices(u8, creds.chain[0], expected.der);
        try std.testing.expectEqual(creds.key.scheme(), expected.scheme);

        var hash: [32]u8 = undefined;
        sys.randomBytes(&hash);
        // What the server signs (RFC 8446 §4.4.3).
        const content = @as([64]u8, @splat(0x20)) ++ "TLS 1.3, server CertificateVerify".* ++ [1]u8{0} ++ hash;
        var noise: [credentials.noise_len]u8 = undefined;
        sys.randomBytes(&noise);
        var out: [credentials.max_signature_len]u8 = undefined;
        const sig = try creds.key.sign(&content, noise, &out);
        try expected.verify(sig, &hash);

        var other = hash;
        other[7] ^= 1;
        try std.testing.expect(std.meta.isError(expected.verify(sig, &other)));
        out[sig.len / 2] ^= 0x10;
        try std.testing.expect(std.meta.isError(expected.verify(sig, &hash)));
    }
}
