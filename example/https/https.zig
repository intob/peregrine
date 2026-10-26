//! HTTPS on port 3443 with the self-signed certificate in this directory
//! (CN=localhost, created with server.conf). Try:
//!   curl --cacert example/https/server.pem https://localhost:3443/
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
        },
    });
    std.debug.print("listening on https://localhost:3443\n", .{});
    try srv.start(); // Blocks until shutdown
}
