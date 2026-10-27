const std = @import("std");
const posix = std.posix;
const sys = @import("./sys.zig");
const parser = @import("./http/parser.zig");
const Request = @import("./request.zig").Request;
const Response = @import("./response.zig").Response;
const http_worker = @import("./http/worker.zig");
const worker_uring = if (sys.is_linux) @import("./http/worker_uring.zig") else struct {};

pub const Backend = enum {
    /// Currently epoll/kqueue everywhere. io_uring measured no faster for
    /// keep-alive and pipelined plaintext (see PLAN.md), and epoll also works
    /// under Docker's default seccomp profile, which blocks io_uring.
    auto,
    /// epoll on Linux, kqueue on BSD/macOS.
    epoll,
    /// Linux only. Fails at init if io_uring is unavailable.
    io_uring,
};
const ws = @import("./ws/conn.zig");
const tls_conn = @import("./tls/conn.zig");
pub const H2Options = @import("./h2/conn.zig").Options;
const Credentials = @import("./tls/credentials.zig").Credentials;
const quic_conn = @import("./quic/conn.zig");
const quic_endpoint = @import("./quic/endpoint.zig");
const udp = @import("./quic/udp.zig");
const h3 = @import("./h3/conn.zig");
const recovery = @import("./quic/recovery.zig");

pub const Http3Options = struct {
    /// UDP port; 0 for the TLS listener's port.
    port: u16 = 0,
    /// Validate every client's address with a Retry before its handshake
    /// (one more round trip; a defence against spoofed floods).
    retry: bool = false,
    max_connections_per_worker: u32 = 4096,
    /// Concurrent requests per connection.
    max_streams: u32 = 100,
    /// Largest UDP payload sent. 1200 bytes is safe on every path; 1350
    /// fits typical Ethernet paths with room for tunnels.
    max_datagram_size: u16 = 1350,
    /// Milliseconds without traffic before a connection is closed.
    idle_timeout_ms: u64 = 30_000,
    congestion: recovery.Algorithm = .cubic,
    /// Connection receive window, and per request stream.
    max_data: u64 = 16 * 1024 * 1024,
    max_stream_data: u64 = 1024 * 1024,
    /// Advertise HTTP/3 on every response (Alt-Svc, RFC 7838), which is how
    /// browsers find it. The port is the UDP port.
    alt_svc: bool = true,
    /// Alt-Svc lifetime, in seconds.
    alt_svc_max_age: u32 = 86400,
};

pub const TlsOptions = struct {
    /// PEM certificate chain, leaf first.
    cert_pem: []const u8,
    /// PEM private key: PKCS#8 ("PRIVATE KEY") or SEC1 ("EC PRIVATE KEY").
    /// ECDSA P-256/P-384 and Ed25519 keys are supported.
    key_pem: []const u8,
    /// ALPN protocol names offered, in preference order.
    alpn: []const []const u8 = &.{"http/1.1"},
    /// TLS record buffers preallocated per worker (input and output each).
    /// Like read buffers, only connections with unprocessed or unsent
    /// bytes hold one.
    buffer_pool_size: usize = 64,
};

pub const Config = struct {
    /// I/O backend.
    backend: Backend = .auto,
    /// Listening IP address (IPv4 or IPv6 literal).
    ip: []const u8 = "0.0.0.0",
    /// Number of worker threads. Defaults to CPU core count.
    worker_thread_count: usize = 0,
    /// Stack size for each worker thread.
    worker_stack_size: usize = 1024 * 1024,
    /// Linux: pin worker N to the Nth allowed CPU.
    pin_workers: bool = true,
    /// Maximum open connections per worker. Further connections are
    /// accepted and immediately closed.
    max_connections_per_worker: u32 = 16 * 1024,
    /// Size of each pooled read buffer. Requests larger than this (head plus
    /// body) temporarily use a heap buffer, up to the limits below.
    read_buffer_size: usize = 16 * 1024,
    /// Read buffers preallocated per worker. Only connections with
    /// unprocessed bytes hold one; idle keep-alive connections don't.
    buffer_pool_size: usize = 256,
    /// Per-worker buffer for Response.setBody. Bodies set with
    /// setBodyBorrowed are not copied and have no size limit.
    response_body_buffer_size: usize = 1024 * 1024,
    /// Per-worker buffer for serialised response headers.
    response_header_buffer_size: usize = 8 * 1024,
    /// Per-worker buffer that batches responses into one write.
    out_buffer_size: usize = 64 * 1024,
    /// Request size limits.
    limits: parser.Limits = .{},
    /// Close idle keep-alive connections after this many seconds.
    keep_alive_timeout_s: u32 = 5,
    /// Maximum time to receive a complete request or make progress writing a
    /// response, in seconds.
    request_timeout_s: u32 = 10,
    /// 0 means unlimited.
    max_requests_per_connection: u32 = 0,
    /// WebSocket messages larger than this fail the connection (1009).
    websocket_max_message_size: usize = 16 * 1024 * 1024,
    /// Unsent WebSocket output per connection before `Conn.send` fails with
    /// SendQueueFull. A connection whose peer stops reading is closed after
    /// `request_timeout_s` without write progress.
    websocket_max_send_queue_bytes: usize = 4 * 1024 * 1024,
    /// Requests a worker may hold open at once through `resp.later()` or
    /// `resp.stream()`; beyond this they fail with TooManyExchanges.
    max_exchanges_per_worker: u32 = 1024,
    /// Unsent bytes per exchange before `ex.write` fails with WouldBlock
    /// (handleWritable is called once it drains).
    max_exchange_queue_bytes: usize = 4 * 1024 * 1024,
    /// Seconds a `resp.later()` exchange may wait for its response before
    /// the connection is closed (`ex.setTimeout` overrides it). A stream
    /// gets `request_timeout_s` between writes.
    response_timeout_s: u32 = 30,
    /// Install SIGINT/SIGTERM handlers that shut the server down.
    handle_signals: bool = true,
    /// Serve TLS 1.3 on this port. The PEM data is parsed during init and
    /// need not outlive it.
    tls: ?TlsOptions = null,
    /// HTTP/2 with prior knowledge on plaintext connections: a client that
    /// sends the HTTP/2 connection preface instead of an HTTP/1.1 request
    /// gets HTTP/2 (RFC 9113 §3.3). Over TLS, HTTP/2 is negotiated with
    /// ALPN when "h2" is in `TlsOptions.alpn`.
    h2c: bool = false,
    /// HTTP/2 connection settings. `limits`, the HPACK header list size and
    /// the request timeout are taken from this Config.
    h2: H2Options = .{},
    /// HTTP/3 over QUIC on a UDP port, with the TLS certificate. Needs
    /// `tls`.
    http3: ?Http3Options = null,
};

/// The server that a signal handler should stop.
var signal_target: ?*const SignalTarget = null;

const SignalTarget = struct {
    shutdown: *std.atomic.Value(bool),
    wakers: []const sys.Waker,
    /// Shutdown requests still waking workers; the server isn't freed
    /// until this is zero.
    waking: *std.atomic.Value(u32),
};

fn handleSignal(_: posix.SIG) callconv(.c) void {
    const target = signal_target orelse return;
    _ = target.waking.fetchAdd(1, .acquire);
    defer _ = target.waking.fetchSub(1, .release);
    target.shutdown.store(true, .release);
    // write(2) is async-signal-safe.
    for (target.wakers) |w| w.wake();
}

pub fn Server(comptime Handler: type) type {
    comptime {
        if (!@hasDecl(Handler, "init")) {
            @compileError("Handler must implement init(std.mem.Allocator) !*@This()");
        }
        if (!@hasDecl(Handler, "deinit")) {
            @compileError("Handler must implement deinit(*@This()) void");
        }
        if (!@hasDecl(Handler, "handleRequest")) {
            @compileError("Handler must implement handleRequest(*@This(), *Request, *Response) void");
        }
    }
    return struct {
        const Self = @This();
        const PollWorker = http_worker.Worker(Handler);
        const UringWorker = if (sys.is_linux) worker_uring.Worker(Handler) else void;

        const AnyWorker = union(enum) {
            poll: PollWorker,
            uring: UringWorker,

            fn spawn(self: *AnyWorker, stack_size: usize, pin: bool) !void {
                switch (self.*) {
                    .poll => |*w| try w.spawn(stack_size, pin),
                    .uring => |*w| if (sys.is_linux) try w.spawn(stack_size, pin) else unreachable,
                }
            }

            fn wake(self: *AnyWorker) void {
                switch (self.*) {
                    .poll => |*w| w.wake(),
                    .uring => |*w| if (sys.is_linux) w.wake() else unreachable,
                }
            }

            fn join(self: *AnyWorker) void {
                switch (self.*) {
                    .poll => |*w| w.join(),
                    .uring => |*w| if (sys.is_linux) w.join() else unreachable,
                }
            }

            fn deinit(self: *AnyWorker) void {
                switch (self.*) {
                    .poll => |*w| w.deinit(),
                    .uring => |*w| if (sys.is_linux) w.deinit() else unreachable,
                }
            }

            fn waker(self: *const AnyWorker) sys.Waker {
                return switch (self.*) {
                    .poll => |*w| w.waker,
                    .uring => |*w| if (sys.is_linux) w.waker else unreachable,
                };
            }
        };

        allocator: std.mem.Allocator,
        handler: *Handler,
        workers: []AnyWorker,
        backend: Backend,
        wakers: []sys.Waker,
        shutdown_flag: std.atomic.Value(bool),
        /// See SignalTarget.waking.
        waking: std.atomic.Value(u32),
        signal_target: SignalTarget,
        cfg: Config,
        port: u16,
        tls_credentials: ?Credentials = null,
        tls_config: tls_conn.Config = undefined,
        quic_tls_config: tls_conn.Config = undefined,
        quic_port: u16 = 0,
        alt_svc_buf: [64]u8 = undefined,

        pub fn init(allocator: std.mem.Allocator, port: u16, cfg: Config) !*Self {
            const address = try std.Io.net.IpAddress.parse(cfg.ip, port);
            const worker_count = if (cfg.worker_thread_count > 0)
                cfg.worker_thread_count
            else
                try std.Thread.getCpuCount();
            const backend: Backend = switch (cfg.backend) {
                .auto => .epoll,
                .io_uring => if (sys.is_linux and worker_uring.available())
                    .io_uring
                else
                    return error.IoUringUnavailable,
                .epoll => .epoll,
            };

            // A write to a closed socket must return EPIPE, not kill us.
            var ignore = posix.Sigaction{
                .handler = .{ .handler = posix.SIG.IGN },
                .mask = posix.sigemptyset(),
                .flags = 0,
            };
            posix.sigaction(.PIPE, &ignore, null);

            const srv = try allocator.create(Self);
            errdefer allocator.destroy(srv);
            const handler = try Handler.init(allocator);
            errdefer handler.deinit();
            srv.* = .{
                .allocator = allocator,
                .handler = handler,
                .workers = try allocator.alloc(AnyWorker, worker_count),
                .backend = backend,
                .wakers = try allocator.alloc(sys.Waker, worker_count),
                .shutdown_flag = .init(false),
                .waking = .init(0),
                .signal_target = undefined,
                .cfg = cfg,
                .port = port,
            };
            errdefer {
                allocator.free(srv.workers);
                allocator.free(srv.wakers);
            }
            if (cfg.tls) |t| {
                srv.tls_credentials = try Credentials.fromPem(allocator, t.cert_pem, t.key_pem);
                srv.tls_config = .{ .credentials = &srv.tls_credentials.?, .alpn = t.alpn };
                srv.quic_tls_config = .{ .credentials = &srv.tls_credentials.?, .alpn = &.{"h3"}, .quic = true };
                srv.cfg.tls = null; // the PEM data may be freed after init
            }
            errdefer if (srv.tls_credentials) |*c| c.deinit();
            if (cfg.http3 != null and srv.tls_credentials == null) return error.Http3NeedsTls;
            // Linux steers each connection's datagrams to its worker
            // (SO_REUSEPORT with a BPF program); elsewhere only the first
            // worker serves HTTP/3.
            var udp_fds: [256]sys.fd_t = @splat(-1);
            if (worker_count > udp_fds.len and cfg.http3 != null) return error.TooManyWorkers;
            errdefer for (udp_fds) |fd| {
                if (fd >= 0) sys.close(fd);
            };

            // Linux load-balances SO_REUSEPORT listeners across workers, so
            // each worker gets its own: no shared accept queue, no handoff.
            // Elsewhere, workers share one listener.
            const per_worker = sys.is_linux or @hasDecl(posix.SO, "REUSEPORT_LB");
            var shared: sys.fd_t = -1;
            errdefer {
                if (!per_worker and shared >= 0) sys.close(shared);
            }
            var initialised: usize = 0;
            errdefer for (srv.workers[0..initialised]) |*w| w.deinit();
            var h2_opts = cfg.h2;
            h2_opts.limits = cfg.limits;
            h2_opts.hpack.max_header_list_size = @intCast(@min(cfg.limits.max_header_bytes, std.math.maxInt(u32)));
            h2_opts.request_timeout_s = cfg.request_timeout_s;
            var bind_address = address;
            for (srv.workers, 0..) |*w, i| {
                const listener = if (per_worker or shared < 0) blk: {
                    const fd = try sys.listenTcp(bind_address, .{ .reuse_port = per_worker });
                    if (i == 0) {
                        // With port 0, the others must bind the chosen port.
                        srv.port = try sys.localPort(fd);
                        bind_address.setPort(srv.port);
                    }
                    if (sys.is_linux) {
                        // Only wake accept() once data has arrived.
                        sys.setsockoptInt(fd, posix.IPPROTO.TCP, std.os.linux.TCP.DEFER_ACCEPT, 1) catch {};
                    }
                    if (!per_worker) shared = fd;
                    break :blk fd;
                } else shared;
                var opts: http_worker.Options = .{
                    .session = .{
                        .limits = cfg.limits,
                        .max_requests_per_connection = cfg.max_requests_per_connection,
                    },
                    .max_connections = cfg.max_connections_per_worker,
                    .read_buffer_size = cfg.read_buffer_size,
                    .buffer_pool_size = cfg.buffer_pool_size,
                    .out_buffer_size = cfg.out_buffer_size,
                    .response_body_buffer_size = cfg.response_body_buffer_size,
                    .response_header_buffer_size = cfg.response_header_buffer_size,
                    .keep_alive_timeout_s = cfg.keep_alive_timeout_s,
                    .request_timeout_s = cfg.request_timeout_s,
                    .read_on_accept = sys.is_linux,
                    .websocket = .{
                        .max_message_size = cfg.websocket_max_message_size,
                        .max_send_queue_bytes = cfg.websocket_max_send_queue_bytes,
                    },
                    .max_exchanges = cfg.max_exchanges_per_worker,
                    .exchange = .{
                        .max_queue_bytes = cfg.max_exchange_queue_bytes,
                        .response_timeout_s = cfg.response_timeout_s,
                        .request_timeout_s = cfg.request_timeout_s,
                    },
                    .h2c = cfg.h2c,
                    .h2 = h2_opts,
                    .tls = if (srv.tls_credentials != null) &srv.tls_config else null,
                    .tls_buffer_pool_size = if (cfg.tls) |t| t.buffer_pool_size else 0,
                    .quic = if (cfg.http3) |o| srv.quicOptions(o, i, worker_count) else null,
                };
                if (cfg.http3) |o| {
                    if (sys.is_linux or i == 0) {
                        if (i == 0) srv.quic_port = if (o.port != 0) o.port else srv.port;
                        var ua = address;
                        ua.setPort(srv.quic_port);
                        udp_fds[i] = try udp.bind(ua, sys.is_linux);
                        if (i == 0 and srv.quic_port == 0) srv.quic_port = try udp.localPort(udp_fds[0]);
                    }
                    if (o.alt_svc) {
                        opts.preset_headers = std.fmt.bufPrint(&srv.alt_svc_buf, "alt-svc: h3=\":{d}\"; ma={d}\r\n", .{ srv.quic_port, o.alt_svc_max_age }) catch unreachable;
                    }
                }
                const result = switch (backend) {
                    .io_uring => if (sys.is_linux) blk: {
                        w.* = .{ .uring = undefined };
                        break :blk w.uring.init(.{
                            .id = i,
                            .allocator = allocator,
                            .handler = handler,
                            .shutdown = &srv.shutdown_flag,
                            .listener = listener,
                            .opts = opts,
                            .udp = udp_fds[i],
                        });
                    } else unreachable,
                    else => blk: {
                        w.* = .{ .poll = undefined };
                        break :blk w.poll.init(.{
                            .id = i,
                            .allocator = allocator,
                            .handler = handler,
                            .shutdown = &srv.shutdown_flag,
                            .listener = listener,
                            .owns_listener = per_worker,
                            .opts = opts,
                            .udp = udp_fds[i],
                        });
                    },
                };
                // The worker owns its UDP socket now.
                udp_fds[i] = -1;
                result catch |err| {
                    if (per_worker) sys.close(listener);
                    return err;
                };
                initialised += 1;
                srv.wakers[i] = w.waker();
            }
            if (cfg.http3 != null and sys.is_linux and worker_count > 1) {
                // Without steering the kernel hashes the 4-tuple, which keeps
                // a connection on one worker until the client's address
                // changes; with it, connection IDs decide.
                const fd0 = switch (srv.workers[0]) {
                    .poll => |*w| w.udp,
                    .uring => |*w| if (sys.is_linux) w.udp else unreachable,
                };
                udp.attachSteering(fd0, @intCast(worker_count)) catch {};
            }
            srv.signal_target = .{ .shutdown = &srv.shutdown_flag, .wakers = srv.wakers, .waking = &srv.waking };
            return srv;
        }

        fn quicOptions(srv: *Self, o: Http3Options, index: usize, count: usize) quic_endpoint.Options {
            var h3_opts: h3.Options = .{ .limits = srv.cfg.limits };
            h3_opts.qpack.max_field_section_size = @intCast(@min(srv.cfg.limits.max_header_bytes, std.math.maxInt(u32)));
            return .{
                .quic = .{
                    .tls = &srv.quic_tls_config,
                    .max_idle_timeout_ms = o.idle_timeout_ms,
                    .max_data = o.max_data,
                    .max_stream_data_bidi = o.max_stream_data,
                    .max_streams_bidi = o.max_streams,
                    .max_datagram_size = o.max_datagram_size,
                    .congestion = o.congestion,
                },
                .h3 = h3_opts,
                .max_connections = o.max_connections_per_worker,
                .worker_index = @intCast(index),
                .worker_count = @intCast(if (sys.is_linux) count else 1),
                .retry = if (o.retry) .always else .never,
            };
        }

        /// The UDP port serving HTTP/3 (useful after binding port 0).
        pub fn getQuicPort(self: *const Self) u16 {
            return self.quic_port;
        }

        /// The I/O backend in use (resolves `.auto`).
        pub fn getBackend(self: *const Self) Backend {
            return self.backend;
        }

        /// The bound port (useful after binding port 0).
        pub fn getPort(self: *const Self) u16 {
            return self.port;
        }

        /// Blocks until the server is shut down, then frees it.
        pub fn start(self: *Self) !void {
            if (self.cfg.handle_signals) {
                signal_target = &self.signal_target;
                var action = posix.Sigaction{
                    .handler = .{ .handler = handleSignal },
                    .mask = posix.sigemptyset(),
                    .flags = 0,
                };
                posix.sigaction(.INT, &action, null);
                posix.sigaction(.TERM, &action, null);
            }
            var spawned: usize = 0;
            errdefer {
                self.shutdown();
                for (self.workers[0..spawned]) |*w| w.join();
            }
            const pin = self.cfg.pin_workers and sys.is_linux;
            for (self.workers) |*w| {
                try w.spawn(self.cfg.worker_stack_size, pin);
                spawned += 1;
            }
            for (self.workers) |*w| w.join();
            if (self.cfg.handle_signals) signal_target = null;
            // Workers may exit as soon as the flag is set, while shutdown()
            // is still waking the others: wait for it to finish.
            while (self.waking.load(.acquire) != 0) std.Thread.yield() catch {};
            self.destroy();
        }

        /// Thread-safe. Workers stop promptly; start() then returns.
        pub fn shutdown(self: *Self) void {
            _ = self.waking.fetchAdd(1, .acquire);
            defer _ = self.waking.fetchSub(1, .release);
            self.shutdown_flag.store(true, .release);
            for (self.workers) |*w| w.wake();
        }

        fn destroy(self: *Self) void {
            const shared_listener = if (self.workers.len > 0 and self.workers[0] == .poll and
                !self.workers[0].poll.owns_listener)
                self.workers[0].poll.listener
            else
                -1;
            for (self.workers) |*w| w.deinit();
            if (shared_listener >= 0) sys.close(shared_listener);
            if (self.tls_credentials) |*c| c.deinit();
            self.handler.deinit();
            self.allocator.free(self.workers);
            self.allocator.free(self.wakers);
            self.allocator.destroy(self);
        }
    };
}
