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

## Benchmarks
With 1000 connections, Peregrine outperforms Go stdlib and NGINX by around 2x, and h2o by around 1.15x. Facil.io stays in the lead, outperforming Peregrine by 1.06x.

Note that this simply measures the overhead of the server, and does not indicate real-world performance unless you're only serving static files. For this test, the response length was 6150 bytes.

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

### Worker threads
- Manage connections
- Parse and handle requests
- Serialise and write responses

### Accept threads
- Accept connections
- Set client socket options
- Assign each client to the next worker
- Monotonically increment the next_worker counter

### WebSocket threads
- Join immediately if there are no WS handlers
- Manage WebSocket connections
- Parse and handle WebSocket frames

### Signal handling
The server handles the following signals for graceful shutdown:
- SIGINT (Ctrl+C)
- SIGTERM

## No TLS support (for now)
I spent a couple of hours deliberating over how to either provide TLS support, or expose an interface for users to provide their choice of TLS implementation. I'm looking for a clean way to handle this without sacrificing performance or usability. I think something like this would be ideal for the user:
```zig
const http_server = try per.Server(Handler).init(allocator, port, .{});
const https_server = try per.TLSServer(Handler, TLS).init(allocator, port, .{});
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
const per = @import("peregrine");

const Handler = struct {
    const Self = @This();

    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.allocator = allocator;
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    pub fn handleRequest(_: *Self, _: *per.Request, resp: *per.Response) void {
        _ = resp.setBody("Kawww\n") catch {};
        resp.addNewHeader("Content-Length", "6") catch {};
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const srv = try per.Server(Handler).init(gpa.allocator(), 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks if there is no error
}

```

Using Zig's comptime metaprogramming, the Server is compiled with your handler interface. Simply implement the `init`, `deinit` and `handle` methods. Compile-time checks have your back.

The configuration is minimal, with reasonable defaults. Simply provide an allocator and port number. Optionally set parameters in the configuration struct.

The server will shutdown gracefully if an interrupt signal is received. Alternatively, you can call `Server.shutdown()`.

## Memory management model

### Request lifecycle
The server manages request and response buffers internally, reusing them across requests to avoid allocations. When a handler processes a request, it must copy any data it needs to retain, as the underlying buffers will be reused for subsequent requests.

### Handler responsibilities
- Handlers own and manage their internal memory
- Any data extracted from requests must be copied before the handler returns
- Handlers are shared across multiple worker threads

## Need to know

### Memory usage
Each worker thread gets it's own resources (obviously). By default, the number of worker threads is equal to the number of CPU cores. Therefore, the memory usage will depend on allocated buffer sizes, stack sizes, and the number of worker threads. You can adjust these parameters in the configuration struct. Example memory usage:
```
Workers:    Response buffer:    10MB
            Request buffer:     1MB
            Stack size:         1MB
            Overhead:           ~70KB

            Total:              12.07MB
_______________________________________________________________________
            Worker count:       12
            Main thread stack:  ~1MB (currently dependent on the OS)
            Total:              12.07 * 12 + 0.1 + 0.2 = 145.14MB
```
Thanks to the zero-allocation design, even under high load, these numbers won't change beyond what your handler allocates.

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
pub fn handleRequest(self: *Self, req: *per.Request, resp: *per.Response) void {
    if (std.mem.eql(u8, req.getPath(), "/ws")) {
        // You must explicitly handle the upgrade to support websockets.
        per.ws.upgrader.handleUpgrade(self.allocator, req, resp) catch {};
        return;
    }
    self.dirServer.serve(req, resp) catch {};
}

pub fn handleWSConn(_: *Self, fd: posix.socket_t) void {
    std.debug.print("handle ws conn... {d}\n", .{fd});
}

pub fn handleWSDisconn(_: *Self, fd: posix.socket_t) void {
    std.debug.print("handle ws disconn... {d}\n", .{fd});
}

pub fn handleWSFrame(_: *Self, fd: posix.socket_t, frame: *per.ws.Frame) void {
    // Reply to the client
    per.ws.writer.writeMessage(fd, "Hello client!", false) catch |err| {
        std.debug.print("error writing websocket: {any}\n", .{err});
    };
}
```

## I need your feedback
I started this project as a way to learn Zig. As such, some of it will be garbage. I would value any feedback.

## This is no framework
This is not a framework for building web applications. This is purely a HTTP server designed from the ground up to be stable and performant. There are no built-in features such as routing or authentication. There are some utilities for common use-cases, such as serving a directory of static files, `util.DirServer`.

If you want a more substantial HTTP library, I suggest that you look at [Zap](https://github.com/zigzap/zap), built on [Facil.io](http://facil.io). Facil.io is an excellent battle-tested library written in C.

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

## Thanks
Thank you to [Bo](https://github.com/boazsegev) for his advice (not all applied yet), and also for his library [Facil.io](https://facil.io). This served as a great model for robust server design, and a solid performance benchmark.

Also, thanks to Karl Seguin for his excellent guide to [writing TCP servers in Zig](https://www.openmymind.net/TCP-Server-In-Zig-Part-1-Single-Threaded/). The start of this project was an exercise in learning Zig, and I found this guide to be very helpful for getting started.
