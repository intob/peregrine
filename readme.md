# Peregrine - a bleeding fast HTTP server 🦅
This is a high-performance, event-driven HTTP server. Written in pure Zig, with no dependencies other than Zig's standard library. Supports Linux (epoll) and BSD/MacOS (kqueue) systems.

The main goal of this project is to provide a HTTP server with the following priorities (in order of prevalence):
- Reliability
- Performance
- Simplicity

Currently, all heap allocations are made during startup. Internally, no heap allocations are made per-request unless pre-allocated buffers overflow.

Note: This project has just started, and is not yet a complete HTTP server implementation. See [To do section](#to-do). The exposed API is still likely to change.

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

- Support for HTTP/1.0 and HTTP/1.1

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
        .on_request = mainHandler,
        // .ip defaults to 0.0.0.0
        // .worker_count defaults to CPU core count
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // This blocks if there is no error
}

fn mainHandler(req: *pereg.Request, resp: *pereg.Response) void {
    std.debug.print("got request {any} {s}\n", .{req.method, req.getPath()})
    handle(resp) catch {}; // Error handling omitted for brevity
}

fn handle(resp: *pereg.Response) !void {
    try resp.setBody("Kawww\n");
    try resp.headers.append(try pereg.Header.init(.{
        .key = "Content-Length",
        .value = "6",
    }));
}
```

The configuration is minimal, with reasonable defaults. Simply provide an allocator, port number, and a request handler function.

The server will shutdown gracefully if an interrupt signal is received. Alternatively, you can call `srv.shutdown()` yourself.

### Query params
`req.parseQuery()` returns `!?std.StringHashMap([]const u8)` - an error union containing an optional hash map. The semantics are:
- Returns error.OutOfMemory if hash map insertion fails
- Returns null in two cases:
    - No query string exists (no '?' in path)
    - Malformed query string (missing '=' between key-value pairs)
- Returns the populated hash map on successful parsing

The hash map (`req.query`) is cleared at the start of each `parseQuery()` call using `clearRetainingCapacity()`. Accessing `req.query` without first calling `parseQuery()` will expose stale data from previous requests.

Emptying the hash map has a cost, and we should only pay that price if we want to use the query, not unconditionally for each request.

Example usage:
```zig
if (try req.parseQuery()) |query| {
    // use query hash map
}
if (req.query.get("some-key")) |value| {
    // it's safe to access the map directly after calling parseQuery
}
```

## No magic behind the scenes
For example, you need to set the Content-Length header yourself. Regardless of whether it's an ArrayList or a HashMap, checking if it was set already by the user would incur a cost (albeit small). Again, this library is designed to be reliable, performant, and simple.

Connection and Keep-Alive headers ARE set by the Worker. This is because there is internal logic to handle connection persistence, and it would hurt developer experience to not set these headers appropriately.

## I need your feedback
I started this project as a way to learn Zig. As such, some of it will be garbage. I would value any feedback.

## This is no framework
This is not a framework for building web applications. This is purely a HTTP server designed from the ground up to be stable and performant. There are no built-in features such as routing or authentication.

If you want a more substantial HTTP library, I suggest that you look at [Zap](https://github.com/zigzap/zap), built on [Facil.io](http://facil.io). Facil.io is an excellent battle-tested library written in C.

## Benchmarks
Currently, this (unfinished) server is as fast as Zap/Facil.io for static GET requests on BSD (kqueue). Although, this is not an entirely fair comparison because Facil.io is a production-ready and complete HTTP server. I would be very happy if this could match the performance of Facil.io. I will first implement the missing core HTTP features before benchmarking properly.

## To do
- Redirect support
- TLS support
- Compression support
- WebSocket support
- HTTP/2 support
- API reference
- Windows support