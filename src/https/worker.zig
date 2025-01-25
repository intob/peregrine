const native_os = @import("builtin").os.tag;
const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const Poller = @import("../poller.zig").Poller;
const Header = @import("../header.zig").Header;
const Request = @import("../request.zig").Request;
const TLSReader = @import("./reader.zig").TLSReader;
const Response = @import("../response.zig").Response;
const Status = @import("../status.zig").Status;
const WebsocketServer = @import("../ws/server.zig").WebsocketServer;
const parser = @import("./parser.zig");
const writer = @import("./writer.zig");
const Connection = @import("./connection.zig").Connection;

const CONNECTION_MAX_REQUESTS: u16 = 65535;
// This is added to a response that contains no body. This is more efficient than
// having the user provide the header to be serialised.
const CONTENT_LENGTH_ZERO_HEADER = "content-length: 0\r\n";
// These headers are added last, so they have an extra CRLF to terminate the headers.
// This is simpler and more efficient than appending \r\n separately.
const KEEP_ALIVE_HEADERS = "connection: keep-alive\r\nkeep-alive: timeout=3, max=65535\r\n\r\n";
const CLOSE_HEADER = "connection: close\r\n\r\n";
const UPGRADE_HEADER = "connection: upgrade\r\n\r\n";

const CommonIovecs = struct {
    const content_len_zero: posix.iovec_const align(64) = .{
        .base = CONTENT_LENGTH_ZERO_HEADER,
        .len = CONTENT_LENGTH_ZERO_HEADER.len,
    };
    const keep_alive: posix.iovec_const align(64) = .{
        .base = KEEP_ALIVE_HEADERS,
        .len = KEEP_ALIVE_HEADERS.len,
    };
    const close: posix.iovec_const align(64) = .{
        .base = CLOSE_HEADER,
        .len = CLOSE_HEADER.len,
    };
    const upgrade: posix.iovec_const align(64) = .{
        .base = UPGRADE_HEADER,
        .len = UPGRADE_HEADER.len,
    };
};

pub fn TLSWorker(comptime Handler: type) type {
    return struct {
        const Self = @This();
        const EventType = switch (native_os) {
            .freebsd, .netbsd, .openbsd, .dragonfly, .macos => posix.Kevent,
            .linux => linux.epoll_event,
            else => unreachable,
        };
        const WorkerConfig = struct {
            allocator: std.mem.Allocator,
            resp_body_buffer_size: usize,
            req_buffer_size: usize,
            stack_size: usize,
            handler: *Handler,
            ws: *WebsocketServer(Handler),
            cert_filename: []const u8,
            key_filename: []const u8,
        };
        const getFd = blk: {
            break :blk switch (native_os) {
                .freebsd, .netbsd, .openbsd, .dragonfly, .macos => struct {
                    fn get(event: posix.Kevent) i32 {
                        return @intCast(event.udata);
                    }
                }.get,
                .linux => struct {
                    fn get(event: linux.epoll_event) i32 {
                        return event.data.fd;
                    }
                }.get,
                else => unreachable,
            };
        };

        shutdown: std.atomic.Value(bool) align(64),
        connections: []Connection align(64),
        handler: *Handler,
        poller: Poller,
        reader: *TLSReader,
        req: *Request,
        resp: *Response,
        iovecs: [4]posix.iovec_const align(64),
        ws: *WebsocketServer(Handler),
        thread: std.Thread,
        allocator: std.mem.Allocator,

        pub fn init(self: *Self, cfg: WorkerConfig) !void {
            const allocator = cfg.allocator;
            self.allocator = allocator;
            self.handler = cfg.handler;
            self.poller = try Poller.init();
            self.req = try Request.init(allocator);
            self.resp = try Response.init(allocator, cfg.resp_body_buffer_size);
            self.reader = try TLSReader.init(self.allocator, cfg.req_buffer_size);
            self.connections = try allocator.alignedAlloc(Connection, 64, std.math.maxInt(i16));
            self.ws = cfg.ws;
            self.shutdown = std.atomic.Value(bool).init(false);
            self.thread = try std.Thread.spawn(.{
                .stack_size = cfg.stack_size,
                .allocator = allocator,
            }, workerLoop, .{self});
            std.debug.print("{s}, {s}\n", .{ cfg.cert_filename, cfg.key_filename });
            for (self.connections) |*c| {
                c.init(allocator);
            }
        }

        pub fn deinit(self: *Self) void {
            self.shutdown.store(true, .monotonic);
            self.thread.join();
            self.reader.deinit();
            self.req.deinit();
            self.resp.deinit();
            for (self.connections) |*c| {
                c.deinit();
            }
            self.allocator.free(self.connections);
            // server frees worker
        }

        pub fn addClient(self: *Self, fd: posix.socket_t) !void {
            try self.poller.addSocket(fd);
        }

        fn workerLoop(self: *Self) void {
            var events: [1024]EventType align(64) = undefined;
            var ready_count: usize align(64) = 0;
            var fd: i32 align(64) = 0;
            var conn: *Connection = undefined;
            while (!self.shutdown.load(.unordered)) {
                ready_count = self.poller.wait(&events) catch |err| {
                    std.debug.print("error waiting for events: {any}\n", .{err});
                    continue;
                };
                for (events[0..ready_count]) |event| {
                    fd = getFd(event);
                    conn = &self.connections[@intCast(fd)];
                    self.readSocket(conn, fd) catch |err| {
                        posix.close(fd);
                        conn.reset();
                        std.debug.print("error reading socket: {any}\n", .{err});
                    };
                }
            }
        }

        inline fn readSocket(self: *Self, conn: *Connection, fd: i32) !void {
            switch (conn.state) {
                .@"01_ClientHello" => {
                    try self.readClientHello(conn, fd);
                    try conn.generateKey();
                    try self.writeServerHello(conn, fd);
                    try conn.deriveKeys();
                    try self.writeEncryptedExtensions(conn, fd);
                    //try self.writeCertificate(conn, fd);
                    //try self.writeCertificateVerify(conn, fd);
                    //try self.writeFinished(conn, fd);
                    conn.state = .@"02_WaitClientFinished";
                    std.debug.print("fd {} now in state {}", .{ fd, conn.state });
                },
                else => std.debug.print("I'm a teapot. State: {}\n", .{conn.state}),
            }
        }

        fn readClientHello(self: *Self, conn: *Connection, fd: i32) !void {
            const record = try parser.parseRecord(self.reader, fd);
            if (record.record_type != .handshake) return error.ExpectedHandshake;
            try conn.handshake_to_digest.appendSlice(record.data[5..]);
            const hello = try parser.parseClientHello(self.allocator, record.data);
            defer hello.deinit();
            conn.legacy_session_id = hello.legacy_session_id;
            if (hello.cipher_suites.items.len == 0) return error.NoCipherSuites;
            conn.cipher_suite = hello.cipher_suites.items[0];
            conn.hash = switch (conn.cipher_suite) {
                .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256 => .SHA256,
                .TLS_AES_256_GCM_SHA384 => .SHA384,
            };
            if (hello.supported_groups.items.len == 0) return error.NoSupportedGroups;
            if (hello.key_shares.items.len == 0) return error.NoKeyShares;
            conn.client_key_share = hello.key_shares.items[0];
        }

        fn writeServerHello(self: *Self, conn: *Connection, fd: i32) !void {
            const response = try writer.buildServerHello(self.allocator, .{
                .cs = conn.cipher_suite,
                .ks = .{
                    .group = conn.client_key_share.group,
                    .key_exchange = switch (conn.client_key_share.group) {
                        .x25519 => conn.server_key.ecdhe.public_key[0..],
                        else => return error.KeyShareNotImplemented,
                    },
                },
                .legacy_session_id = conn.legacy_session_id,
            });
            defer {
                response.deinit();
                self.allocator.destroy(response);
            }
            try conn.handshake_to_digest.appendSlice(response.items[5..]);
            var n: usize = 0;
            while (n < response.items.len) {
                n += try posix.write(fd, response.items[n..]);
            }
            std.debug.print("responsed with {x}\n", .{response.items});
        }

        fn writeEncryptedExtensions(self: *Self, conn: *Connection, fd: i32) !void {
            const msg = [_]u8{
                @intFromEnum(parser.HandshakeType.encrypted_extensions),
                0x00, 0x00, 0x02, // length (2 bytes)
                0x00, 0x00, // empty extensions list
            };
            switch (conn.hash) {
                .SHA256 => try self.writeEncrypted(32, conn, fd, &msg),
                .SHA384 => try self.writeEncrypted(48, conn, fd, &msg),
            }
        }

        fn writeEncrypted(self: *Self, comptime hash_len: u8, conn: *Connection, fd: i32, msg: []const u8) !void {
            var buffer = std.ArrayList(u8).init(self.allocator);
            defer buffer.deinit();
            try buffer.appendSlice(&[_]u8{
                @intFromEnum(parser.RecordType.application_data),
                0x03, 0x03, // legacy_record_version TLS 1.2
                0x00, 0x00, // length placeholder
            });
            var plaintext = try self.allocator.alloc(u8, msg.len + 1);
            defer self.allocator.free(plaintext);
            plaintext[0] = 0x17; // application_data
            @memcpy(plaintext[1..][0..msg.len], msg);
            const key = switch (hash_len) {
                32 => conn.server_hash_keys.SHA256.getAes128Key(),
                48 => conn.server_hash_keys.SHA384.getAes256Key(),
                else => return error.UnsupportedHashLen,
            };
            var ciphertext = try self.allocator.alloc(u8, plaintext.len);
            defer self.allocator.free(ciphertext);
            _ = &ciphertext;
            var tag: [16]u8 = undefined;
            const aes = switch (key.len) {
                32 => std.crypto.aead.aes_gcm.Aes256Gcm,
                16 => std.crypto.aead.aes_gcm.Aes128Gcm,
                else => return error.UnsupportedKeySize,
            };
            aes.encrypt(ciphertext, &tag, plaintext, &[0]u8{}, conn.server_handshake_iv, key);
            const encrypted_len = ciphertext.len + tag.len;
            buffer.items[3] = @intCast((encrypted_len >> 8) & 0xFF);
            buffer.items[4] = @intCast(encrypted_len & 0xFF);
            try buffer.appendSlice(ciphertext);
            try buffer.appendSlice(&tag);
            var n: usize = 0;
            while (n < buffer.items.len) {
                n += try posix.write(fd, buffer.items[n..]);
            }
            try conn.handshake_to_digest.appendSlice(msg);
        }

        fn respond(self: *Self, fd: posix.socket_t, keep_alive: bool) !void {
            const status_len = try self.resp.serialiseStatusAndHeaders();
            self.iovecs[0] = .{
                .base = @ptrCast(self.resp.status_buf[0..status_len]),
                .len = status_len,
            };
            var total = status_len;
            var iovecs_len: u8 = 1;
            if (self.resp.body_len == 0) {
                self.iovecs[1] = CommonIovecs.content_len_zero;
                iovecs_len += 1;
                total += CONTENT_LENGTH_ZERO_HEADER.len;
            }
            if (self.resp.is_ws_upgrade) {
                self.iovecs[iovecs_len] = CommonIovecs.upgrade;
                total += UPGRADE_HEADER.len;
            } else {
                if (keep_alive) {
                    self.iovecs[iovecs_len] = CommonIovecs.keep_alive;
                    total += KEEP_ALIVE_HEADERS.len;
                } else {
                    self.iovecs[iovecs_len] = CommonIovecs.close;
                    total += CLOSE_HEADER.len;
                }
            }
            iovecs_len += 1;
            if (self.resp.body_len > 0) {
                self.iovecs[iovecs_len] = .{
                    .base = @ptrCast(self.resp.body[0..self.resp.body_len]),
                    .len = self.resp.body_len,
                };
                iovecs_len += 1;
                total += self.resp.body_len;
            }
            const n = try posix.writev(fd, self.iovecs[0..iovecs_len]);
            if (n != total) {
                return error.PartialWrite;
            }
        }
    };
}
