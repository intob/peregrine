pub const Header = @import("./header.zig").Header;
pub const Method = @import("./method.zig").Method;
pub const Request = @import("./request.zig").Request;
pub const Response = @import("./response.zig").Response;
/// A request answered after handleRequest returns (`resp.later()`) or
/// streamed (`resp.stream()`). See src/http/exchange.zig.
pub const Exchange = @import("./http/exchange.zig").Exchange;
pub const ExchangeHead = @import("./http/exchange.zig").Head;
pub const ExchangeError = @import("./http/exchange.zig").Error;
pub const Release = @import("./http/exchange.zig").Release;
pub const Server = @import("./server.zig").Server;
pub const Config = @import("./server.zig").Config;
pub const ServerConfig = Config;
pub const Backend = @import("./server.zig").Backend;
pub const TlsOptions = @import("./server.zig").TlsOptions;
pub const H2Options = @import("./server.zig").H2Options;
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
    _ = @import("./http/exchange.zig");
    _ = @import("./mailbox.zig");
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
    _ = @import("./h2/hpack.zig");
    _ = @import("./h2/frame.zig");
    _ = @import("./h2/conn.zig");
    _ = @import("./quic/packet.zig");
    _ = @import("./quic/protection.zig");
    _ = @import("./quic/frame.zig");
    _ = @import("./quic/transport_params.zig");
    _ = @import("./quic/ranges.zig");
    _ = @import("./quic/recovery.zig");
    _ = @import("./quic/stream.zig");
    _ = @import("./quic/sent.zig");
    _ = @import("./quic/conn_test.zig");
    _ = @import("./h3/qpack.zig");
    _ = @import("./h3/frame.zig");
    _ = @import("./h3/conn.zig");
    _ = @import("./h3/conn_test.zig");
    _ = @import("./http/fields.zig");
    _ = @import("./server_test.zig");
    @import("std").testing.refAllDecls(@This());
}
