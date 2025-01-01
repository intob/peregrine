# Peregrine - a simple high-performance HTTP server
This is an event-driven HTTP server. Written in pure Zig, with no dependencies other than Zig's standard library. Supports Linux (epoll) and BSD/MacOS (kqueue) systems.

The main goal of this project is to provide a HTTP server with the following priorities (in order of prevalence):
- Reliability
- Performance
- Simplicity

Currently, all heap allocations are made during startup. Internally, no heap allocations are made per-request unless pre-allocated buffers overflow.

Note: This project has just started, and is not yet a complete HTTP server implementation. See [To do section](#to-do). The API is likely to change. It is currently NOT FIT FOR PRODUCTION use.

## Features

- Simple API
- Support for HTTP/1.0 and HTTP/1.1
- Support for WebSockets
- Cross-platform IO Multiplexing
    - Kqueue support for BSD and MacOS systems
    - Epoll support for Linux systems
- Multi-Worker Architecture
    - Automatic worker scaling based on CPU core count
    - Configurable worker-thread count
    - Configurable accept-thread count
    - Thread-safe request handling

## Performance optimisations

- Non-blocking socket operations
- Event-driven architecture
- Aligned buffer allocation
- Vectored IO writes the response with a single syscall
- Zero heap allocations per-request
- Header case-insensitivity handled when searching, not parsing (unused headers are not transformed)
- Query only parsed on demand
- Optimised header, method and version parsing
- Fixed sized array for headers (faster than std.ArrayList)

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

## No TLS support (for now)
I spent a couple of hours deliberating over how to either provide TLS support, or expose an interface for users to provide their choice of TLS implementation. I'm looking for a clean way to handle this without sacrificing performance or usability.

I think something like this would be ideal for the user:
```zig
const http_server = try pereg.Server(Handler).init(.{
    .allocator = allocator,
    .port = 3000,
});
// Or for HTTPS...
const https_server = try pereg.TLSServer(Handler, TLS).init(.{
    .allocator = allocator,
    .port = 3000,
});
```

When I tried to implement this, I quickly saw that it would be challenging because TLSServer has a handshake, and the plain HTTP server does not. The two look entirely different at the socket level.

Then I realised that even if I added TLS support, server performance would pale in comparison to the plain HTTP version. At this point, I'd rather offload TLS termination (to a load balancer, for example), allowing this server to focus on efficient HTTP parsing without becoming overwhelmingly complex.

In future when I'm more familiar with comptime generics and interfaces in Zig, I may have another crack at this. For now, I don't see a way to win here... So, If you're looking for a Zig HTTP server that supports TLS, I suggest looking at [Zap](https://github.com/zigzap/zap).

In addition, I am absolutely not ready to implement TLS from scratch. It would be the death of this project if I tried.

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

const Handler = struct {
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        return try allocator.create(Self);
    }

    pub fn deinit(_: *Self) void {}

    // Error handling omitted for brevity
    pub fn handleRequest(_: *Self, _: *pereg.Request, resp: *pereg.Response) void {
        _ = resp.setBody("Kawww\n") catch {};
        resp.addNewHeader("Content-Length", "6") catch {};
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const port: u16 = 3000;
    const srv = try pereg.Server(Handler).init(allocator, port, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}

```

Using Zig's comptime metaprogramming, the Server is compiled with your handler interface. Simply implement the `init`, `deinit` and `handle` methods. Compile-time checks have your back.

The configuration is minimal, with reasonable defaults. Simply provide an allocator and port number. Optionally set parameters in the configuration struct.

The server will shutdown gracefully if an interrupt signal is received. Alternatively, you can call `Server.shutdown()`.

## Memory Management Model

### Request lifecycle
The server manages request and response buffers internally, reusing them across requests to avoid allocations. When a handler processes a request, it must copy any data it needs to retain, as the underlying buffers will be reused for subsequent requests.

### Handler responsibilities
- Handlers own and manage their internal memory
- Any data extracted from requests must be copied before the handler returns
- Response bodies must be copied to handler-owned memory before being set
- All handler-allocated memory must be freed within the handle function

### Concurrent access
The current design intentionally avoids an `after_request` hook because:
- Handlers are shared across multiple worker threads
- Adding post-processing would require mutex synchronization
- Locking would create contention, hurting performance

## Need to know

### Response headers
If the body is not zero-length, you must set the Content-Length header yourself. I will write a helper for this soon.

Regardless of whether it's an ArrayList or a HashMap, checking if it was set already by the user would incur a cost (albeit small).

If you do not give a response body, the "content-length: 0" header will be added automatically. This is because it's faster to add a hard-coded iovec than to serialise an extra header.

Again, this library is designed to be reliable, performant, and simple. Occasionally simplicity is sacrificed for performance.

Connection and keep-alive headers are set by the Worker. This is because there is internal logic to handle connection persistence, and it would hurt developer experience to not set these headers appropriately.

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

### WebSockets
Implementing WebSockets is easy. Simply handle the upgrade request, and add the WS handler hooks. Check out the working example in `./example/websocket`.
```zig
pub fn handleRequest(self: *@This(), req: *pereg.Request, resp: *pereg.Response) void {
    self.handleRequestWithError(req, resp) catch |err| {
        std.debug.print("error handling request: {any}\n", .{err});
    };
}

fn handleRequestWithError(self: *@This(), req: *pereg.Request, resp: *pereg.Response) !void {
    if (std.mem.eql(u8, req.getPath(), "/ws")) {
        // You must explicitly handle the upgrade to support websockets.
        try pereg.ws.upgrader.handleUpgrade(self.allocator, req, resp);
        return;
    }
    try self.dirServer.serve(req, resp);
}

pub fn handleWSConn(_: *@This(), fd: posix.socket_t) void {
    std.debug.print("handle ws conn... {d}\n", .{fd});
}

pub fn handleWSDisconn(_: *@This(), fd: posix.socket_t) void {
    std.debug.print("handle ws disconn... {d}\n", .{fd});
}

pub fn handleWSFrame(_: *@This(), fd: posix.socket_t, frame: *pereg.ws.Frame) void {
    // Reply to the client
    pereg.ws.writer.writeMessage(fd, "Hello client!", false) catch |err| {
        std.debug.print("error writing websocket: {any}\n", .{err});
    };
}
```

## I need your feedback
I started this project as a way to learn Zig. As such, some of it will be garbage. I would value any feedback.

## This is no framework
This is not a framework for building web applications. This is purely a HTTP server designed from the ground up to be stable and performant. There are no built-in features such as routing or authentication. There are some utilities for common use-cases, such as serving a directory of static files, `util.DirServer`.

If you want a more substantial HTTP library, I suggest that you look at [Zap](https://github.com/zigzap/zap), built on [Facil.io](http://facil.io). Facil.io is an excellent battle-tested library written in C.

## Benchmarks
Currently, Zap/Facil.io is around 6% faster for static GET requests. I am working to improve this, but as I'm new to systems programming, this is a challenge for me. I would be happy to match Zap/Facil.io's performance.

## To do
- Handle request body
- Increase TCP buffer size
- Increase socket backlog size
- API reference
- HTTP/2 support
- Windows support
- Templating util (possibly extend util.DirServer to be composable)

Also to do:
Add a response helper to set content-length header from an integer. Maybe use a pre-allocated buffer that can be reused.
