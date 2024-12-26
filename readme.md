# Peregrine - a bleeding fast HTTP server 🦅
This is a HTTP server written in pure Zig with no dependencies other than Zig's standard library.

The main goal of this project is to provide a HTTP server, with the following priorities (in order of prevalence):
- Reliability
- Performance
- Simplicity

Currently, all heap allocations are made during startup. Internally, no heap allocations are made per-request.

Note: This project has just started. Kqueue is done, but Epoll is not. Therefore, this will not yet work on Linux. This will work on FreeBSD and MacOS.

## Getting started

### Run the example server
```bash
zig build run-example
```

### Example usage
```zig
const std = @import("std");
const peregrine = @import("peregrine");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try peregrine.Server.init(.{
        .allocator = allocator,
        .port = 3000,
        .on_request = handleRequest,
        // .ip defaults to 0.0.0.0
        // .worker_count defaults to CPU core count
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // This blocks if there is no error
}

fn handleRequest(req: *pereg.Request, resp: *pereg.Response) void {
    default(resp) catch {}; // Error handling omitted for brevity
}

fn default(resp: *pereg.Response) !void {
    try resp.setBody("Kawww\n");
    try resp.headers.append(try pereg.Header.init(.{
        .key = "Content-Length",
        .value = "6",
    }));
}
```

As it stands, the configuration is minimal, with sensible defaults. Simply provide a request handler function.

The server will shutdown gracefully if an interrupt signal is received. Alternatively, you can call `srv.shutdown()` yourself.

## No magic behind the scenes
For example, you need to set the Content-Length header yourself. Regardless of whether it's an ArrayList or a HashMap, checking if it was set already by the user would incur a cost (albeit small). Again, this library is designed to be reliable, performant, and simple.

## I need your feedback
I started this project as a way to learn Zig. As such, some of it will be garbage. I would value any feedback.

## This is no framework
This is not a framework for building web applications. This is purely a HTTP server designed from the ground up to be stable and performant. There are no built-in features such as routing or authentication.

If you want a more substantial HTTP library, I suggest that you look at [Zap](https://github.com/zigzap/zap), built on [Facil.io](http://facil.io). Facil.io is an excellent battle-tested library written in C.

## Benchmarks
I will add some graphs later.

Currently, this (unfinished) server is around 2-3% faster than Zap/Facil.io for static GET requests. Although, this is not a fair comparison because Facil.io is a production-ready and complete HTTP server.

I would be very happy if this could consistently outperform Facil.io even by just a hair, while being robust.

## To do
- Epoll (support Linux)
- Query params
- Redirects
- HTTP/1.1 (keep-alive)
- API reference
- Better task scheduling
- WebSockets
- HTTP/2
