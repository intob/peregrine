//! WebSocket support. Handle the upgrade in `handleRequest` with
//! `upgrader.handleUpgrade`; the connection then stays on the same worker
//! and the handler's `handleWSConn`, `handleWSFrame` and `handleWSDisconn`
//! hooks are called with a `*Conn`, which is also how messages are sent.
pub const upgrader = @import("./upgrader.zig");
pub const protocol = @import("./protocol.zig");
pub const Conn = @import("./conn.zig").Conn;
pub const Options = @import("./conn.zig").Options;
pub const SendError = @import("./conn.zig").SendError;
pub const Frame = protocol.Frame;
pub const Opcode = protocol.Opcode;
pub const close_code = protocol.close_code;
