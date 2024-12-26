# Peregrine - a bleeding fast HTTP server 🦅
This is a high-performance, event-driven HTTP server. Written in pure Zig, with no dependencies other than Zig's standard library. Supports Linux (epoll) and BSD/MacOS (kqueue) systems.

The main goal of this project is to provide a HTTP server with the following priorities (in order of prevalence):
- Reliability
- Performance
- Simplicity

Currently, all heap allocations are made during startup. Internally, no heap allocations are made per-request.

Note: This project has just started, and is not yet a complete HTTP server implementation. See [To do section](#to-do).

## Features

- Cross-platform IO Multiplexing
    - Kqueue support for BSD and MacOS systems
    - Epoll support for Linux systems

- Multi-Worker Architecture
    - Automatic worker scaling based on CPU core count
    - Configurable worker count
    - Thread-safe request handling

- Performance Optimisations
    - Non-blocking socket operations
    - Efficient event-driven architecture
    - Aligned buffer allocation for optimal IO performance

## Architecture

### Server
- Server configuration and initialization
- Worker pool management
- Signal handling for graceful shutdown
- Platform-specific I/O handlers

### Workers
- Simple worker-per-thread design
- Request parsing and handling
- Response generation
- Connection management
- Event loop processing

### Signal Handling
The server handles the following signals for graceful shutdown:
- SIGINT (Ctrl+C)
- SIGTERM

### Timeouts
Connection timeouts are configured with:
- Receive timeout: 2.5 seconds
- Send timeout: 2.5 seconds

## Usage

### Run the example server natively
```bash
zig build run-example
```

### Run the example in a Linux Docker container

#### x86_64
```bash
zig build -Dtarget=x86_64-linux-musl && \
docker build -t example . -f ./example/Dockerfile && \
docker run -p 3000:3000 example
```
#### aarch64 (ARM)
```bash
zig build -Dtarget=aarch64-linux-musl && \
docker build -t example . -f ./example/Dockerfile && \
docker run -p 3000:3000 example
```

### Implement a server
```zig
const std = @import("std");
const pereg = @import("peregrine");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try pereg.Server.init(.{
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
    std.debug.print("got request {any} {s}\n", .{req.method, req.getPath()})
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

The configuration is minimal, with reasonable defaults. Simply provide an allocator, port number, and a request handler function.

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
- Query params
- Redirects
- HTTP/1.1 (keep-alive)
- TLS support
- API reference
- WebSockets support
- HTTP/2 support
- Windows support