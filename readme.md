# Peregrine - a bleeding fast HTTP server 🦅
This is a high-performance, event-driven HTTP server. Written in pure Zig, with no dependencies other than Zig's standard library. Supports Linux (epoll) and BSD/MacOS (kqueue) systems.

The main goal of this project is to provide a HTTP server with the following priorities (in order of prevalence):
- Reliability
- Performance
- Simplicity

Currently, all heap allocations are made during startup. Internally, no heap allocations are made per-request unless pre-allocated buffers overflow.

Note: This project has just started, and is not yet a complete HTTP server implementation. See [To do section](#to-do). The API is likely to change.

## Features

- Simple API

- Support for HTTP/1.0 and HTTP/1.1

- Cross-platform IO Multiplexing
    - Kqueue support for BSD and MacOS systems
    - Epoll support for Linux systems

- Multi-Worker Architecture
    - Automatic worker scaling based on CPU core count
    - Configurable worker-thread count
    - Configurable accept-thread count
    - Thread-safe request handling

- Performance Optimisations
    - Non-blocking socket operations
    - Efficient event-driven architecture
    - Aligned buffer allocation for optimal IO performance
    - Vectored IO writes the response with a single syscall
    - Zero heap allocations per-request
    - Header case-insensitivity handled when searching, not parsing (unused headers are not transformed)
    - Query only parsed on demand
    - Optimised header, method and version parsing
    - Fixed sized array for request headers (faster than std.ArrayList)


## Architecture

### Server
- Server configuration and initialization
- Worker pool management
- Signal handling for graceful shutdown
- Platform-specific I/O handlers

### Worker Threads
- Request parsing and handling
- Response serialisation
- Connection management

### Accept Threads
- Accepts connections
- Sets client socket options
- Assigns the socket to the next worker
- Monotonically increments the next_worker counter

### Signal Handling
The server handles the following signals for graceful shutdown:
- SIGINT (Ctrl+C)
- SIGTERM

### Timeouts
Connection timeouts are configured with:
- Receive timeout: 3 seconds
- Send timeout: 3 seconds

## Usage

### Run the counter example server natively
```bash
zig build run-counter
```

### Run the counter example in a Linux Docker container

#### x86_64
```bash
zig build -Dtarget=x86_64-linux-musl && \
docker build -t counter . -f ./example/counter.Dockerfile && \
docker run -p 3000:3000 counter
```
#### aarch64 (ARM)
```bash
zig build -Dtarget=aarch64-linux-musl && \
docker build -t counter . -f ./example/counter.Dockerfile && \
docker run -p 3000:3000 counter
```

### Implement a server
```zig
const std = @import("std");
const pereg = @import("peregrine");

const MyHandler = struct {
    pub fn init(allocator: std.mem.Allocator) !*@This() {
        return try allocator.create(@This());
    }

    pub fn deinit(_: *@This()) void {}

    pub fn handle(self: *@This(), req: *pereg.Request, resp: *pereg.Response) void {
        self.handleWithError(req, resp) catch |err| {
            std.debug.print("error handling request: {any}\n", .{err});
        };
    }

    fn handleWithError(_: *@This(), _: *pereg.Request, resp: *pereg.Response) !void {
        _ = try resp.setBody("Kawww\n");
        const len_header = try pereg.Header.init("Content-Length", "6");
        try resp.headers.append(len_header);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const srv = try pereg.Server(MyHandler).init(.{
        .allocator = allocator,
        .port = 3000,
    });
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}
```

Using Zig's comptime metaprogramming, the Server is compiled with your handler interface. Simply implement the `init`, `deinit` and `handle` methods. Compile-time checks have your back.

The configuration is minimal, with reasonable defaults. Simply provide an allocator and port number.

The server will shutdown gracefully if an interrupt signal is received. Alternatively, you can call `Server.shutdown()`.

### Query params
`req.parseQuery()` returns `!?std.StringHashMap([]const u8)` - an error union containing an optional hash map. The semantics are:
- Returns error.OutOfMemory if hash map insertion fails
- Returns null in two cases:
    - No query string exists (no '?' in path)
    - Malformed query string (missing '=' between key-value pairs)
- Returns the populated hash map on successful parsing

The `Request.query` hash map is cleared on the call to `parseQuery()`. Accessing the query field without first calling `parseQuery()` will expose stale data from previous requests. Emptying the hash map has a cost, and we should only pay that price if we want to use the query, not unconditionally for each request.

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

I will provide some helpers to help with common use-cases, such as serving a directory.

If you want a more substantial HTTP library, I suggest that you look at [Zap](https://github.com/zigzap/zap), built on [Facil.io](http://facil.io). Facil.io is an excellent battle-tested library written in C.

## Benchmarks
Currently, Zap/Facil.io is around 15% faster for static GET requests. I am working to improve this, but as I'm new to systems programming, this is a challenge for me. I would be happy to match Zap/Facil.io's performance.

## To do
- Static file helpers
- Templating support
- TLS support
- WebSocket support
- HTTP/2 support
- API reference
- Windows support