//! HTTPS on port 3443 with the self-signed certificate in this directory
//! (CN=localhost, created with server.conf), HTTP/2 negotiated with ALPN,
//! and HTTP/3 on UDP port 3443. Try:
//!   curl --cacert example/https/server.pem https://localhost:3443/
//!   curl --http2 --cacert example/https/server.pem -v https://localhost:3443/
//!   curl --http3-only --cacert example/https/server.pem https://localhost:3443/
//! (the last needs a curl built with HTTP/3).
const std = @import("std");
const per = @import("peregrine");

const Handler = struct {
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        return try allocator.create(Self);
    }

    pub fn deinit(_: *Self) void {}

    pub fn handleRequest(_: *Self, _: *per.Request, resp: *per.Response) void {
        resp.addNewHeader("content-type", "text/plain") catch {};
        resp.setBodyBorrowed("Kawww, securely\n");
    }
};

pub fn main(init: std.process.Init) !void {
    const srv = try per.Server(Handler).init(init.gpa, 3443, .{
        .tls = .{
            .cert_pem = @embedFile("server.pem"),
            .key_pem = @embedFile("server.key"),
            .alpn = &.{ "h2", "http/1.1" },
        },
        .http3 = .{},
    });
    std.debug.print("listening on https://localhost:3443\n", .{});
    try srv.start(); // Blocks until shutdown
}
