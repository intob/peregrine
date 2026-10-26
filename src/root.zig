pub const Header = @import("./header.zig").Header;
pub const Method = @import("./method.zig").Method;
pub const Request = @import("./request.zig").Request;
pub const Response = @import("./response.zig").Response;
pub const Server = @import("./server.zig").Server;
pub const Config = @import("./server.zig").Config;
pub const ServerConfig = Config;
pub const Backend = @import("./server.zig").Backend;
pub const TlsOptions = @import("./server.zig").TlsOptions;
pub const Limits = @import("./http/parser.zig").Limits;
pub const Status = @import("./status.zig").Status;
pub const Version = @import("./version.zig").Version;

/// Utilities and helpers
pub const util = @import("./util/util.zig");

/// Internals exposed for benchmarks. Not a stable API.
pub const internal = struct {
    pub const parser = @import("./http/parser.zig");
    pub const session = @import("./http/session.zig");
    pub const date = @import("./http/date.zig");
    pub const sys = @import("./sys.zig");
    pub const tls_record = @import("./tls/record.zig");
};

/// Websocket helpers
pub const ws = @import("./ws/ws.zig");

test {
    _ = @import("./http/parser.zig");
    _ = @import("./http/session.zig");
    _ = @import("./http/date.zig");
    _ = @import("./poller.zig");
    _ = @import("./sys.zig");
    _ = @import("./ws/protocol.zig");
    _ = @import("./ws/conn.zig");
    _ = @import("./tls/key_schedule.zig");
    _ = @import("./tls/record.zig");
    _ = @import("./tls/credentials.zig");
    _ = @import("./tls/handshake.zig");
    _ = @import("./tls/conn.zig");
    _ = @import("./tls/fuzz.zig");
    _ = @import("./server_test.zig");
    @import("std").testing.refAllDecls(@This());
}
