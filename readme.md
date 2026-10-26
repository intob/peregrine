# Peregrine - a simple high-performance HTTP server
This is an event-driven HTTP server. Written in pure Zig, with no dependencies other than Zig's standard library. Supports Linux (epoll, optionally io_uring) and BSD/MacOS (kqueue) systems. Requires Zig 0.17.

The main goal of this project is to provide a HTTP server with the following priorities (in order of prevalence):
- Reliability
- Performance
- Simplicity

Currently, all heap allocations are made during startup. Internally, no heap allocations are made per-request unless pre-allocated buffers overflow (for example, a request body larger than a pooled read buffer, or a response that can't be written in one go).

Note: This project has just started, and is not yet a complete HTTP server implementation. See [To do section](#to-do). The API is likely to change. It is currently NOT FIT FOR PRODUCTION use.

## Features

- Simple API
- Support for HTTP/1.0 and HTTP/1.1
    - Keep-alive and pipelining (pipelined responses are batched into one write)
    - Request bodies: `Content-Length` and `Transfer-Encoding: chunked`
    - `Expect: 100-continue`, `HEAD`, automatic `Content-Length` and `Date`
    - Strict parsing that rejects request smuggling vectors (see `src/http/parser.zig`)
    - Request size limits, idle/request timeouts (slowloris-resistant)
- Support for WebSockets
- Cross-platform IO Multiplexing
    - Kqueue support for BSD and MacOS systems
    - Epoll support for Linux systems
    - io_uring support for Linux (opt-in, `.backend = .io_uring`)
- Multi-Worker Architecture
    - Automatic worker scaling based on CPU core count
    - Configurable worker-thread count
    - Each worker accepts its own connections (`SO_REUSEPORT` on Linux), pinned to a core
    - Thread-safe request handling

## Benchmarks
Plaintext "Hello, World!" on Linux (Docker on an M2 Pro: kernel 6.12, aarch64). Server on 6 cores (6 workers), `wrk -t6 -c256 -d10s` on the other 6, over loopback. Two runs each; numbers vary by about 10% between runs, so treat epoll and io_uring as equal here. Same machine for client and server, so these are relative, not absolute.

| Requests/sec | NGINX | Peregrine (epoll) | Peregrine (io_uring) |
|--------|-------|-----|-----|
| Keep-alive | 767k–944k | 956k–1.09M | 995k–1.07M |
| Pipelined ×16 | 1.24M–1.47M | 8.2M–9.4M | 8.5M–8.8M |

Reproduce: `zig build bench-server -Dtarget=aarch64-linux` (the server takes `[workers] [auto|epoll|io_uring] [port]`), and `zig build bench` for parser micro-benchmarks (about 190 ns to parse a 437-byte browser request with 8 headers).

The previous version, run using wrk on an M2 Pro (macOS) with 1000 connections:

| Metric | NGINX | h2o | Zap (Facil.io) | Peregrine |
|--------|-------|-----|----------------|-----------|
| Requests/sec | 81,852 | 149,267 | 167,963 | **175,675** |
| Avg Latency | 12.19ms | 8.54ms | **4.84ms** | 5.64ms |
| Latency Stdev | 4.19ms | 8.87ms | 2.23ms | 412.57μs |
| Latency +/- Stdev | 74.74% | 90.81 | 78.32% | **93.00%** |

Facil.io is still superior to this library as it is battle-tested, production-ready and supports TLS. While working on this library, I've seen just how well-implemented and stable Facil.io is...

Note that these benchmarks simply measure serving static GET requests, and they do not indicate real-world performance unless you're only serving static files. For the previous-version tests, the response length was 6150 bytes.

## Performance optimisations

- Raw syscalls (no libc on Linux), non-blocking sockets, edge-triggered events
- Event-driven architecture, one event loop per core, no cross-thread handoff
- SIMD scanning for the end of the head, request-target and header values
- Zero-copy request parsing: headers, path and body are slices into the read buffer
- Vectored IO: pipelined responses go out in a single `writev`
- Zero heap allocations per-request
- Read buffers are pooled and only held while a connection has unprocessed bytes, so idle keep-alive connections use no buffer memory
- Zero-copy response bodies with `setBodyBorrowed`
- `Date` header formatted once per second, not per request
- Timeouts without a syscall per connection (deadline-ordered intrusive lists)
- Linux: `TCP_DEFER_ACCEPT` plus reading straight after accept
- Header case-insensitivity handled when searching, not parsing (unused headers are not transformed)
- Query only parsed on demand
- Optimised header, method and version parsing

## Architecture

### Server
- Server configuration and initialization
- Worker pool management
- Signal handling for graceful shutdown
- Platform-specific I/O handlers

### Worker threads
- Accept connections (own `SO_REUSEPORT` listener on Linux; a shared listener elsewhere)
- Manage connections, timeouts and backpressure
- Feed bytes to the per-connection state machine (`src/http/session.zig`), which parses and handles requests and serialises responses without doing any I/O itself
- Write responses

### WebSockets
- No separate threads: after the upgrade a connection stays on the worker that accepted it, so WebSockets scale with cores like HTTP does
- Frames are decoded by an I/O-free per-connection state machine (`src/ws/protocol.zig`): resumable across reads, several frames per read, fragments reassembled, pings answered, close handshake done by the server
- Output is queued per connection and written as the socket allows; a peer that stops reading is closed after `request_timeout_s`

### Signal handling
The server handles the following signals for graceful shutdown:
- SIGINT (Ctrl+C)
- SIGTERM

## Usage

### Run the counter example server natively
```bash
zig build run-counter
```

### Run the counter example in a Linux Docker container

#### x86_64
```bash
zig build -Dtarget=x86_64-linux-musl && \
docker build -t counter . -f ./example/counter/Dockerfile && \
docker run -p 3000:3000 counter
```
#### aarch64 (ARM)
```bash
zig build -Dtarget=aarch64-linux-musl && \
docker build -t counter . -f ./example/counter/Dockerfile && \
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
        resp.addNewHeader("content-type", "text/plain") catch {};
        resp.setBodyBorrowed("Kawww\n"); // static data: no copy
    }
};

pub fn main(init: std.process.Init) !void {
    const srv = try per.Server(Handler).init(init.gpa, 3000, .{});
    std.debug.print("listening on 0.0.0.0:3000\n", .{});
    try srv.start(); // Blocks until shutdown
}

```

Using Zig's comptime metaprogramming, the Server is compiled with your handler interface. Simply implement the `init`, `deinit` and `handle` methods. Compile-time checks have your back.

The configuration is minimal, with reasonable defaults. Simply provide an allocator and port number. Optionally set parameters in the configuration struct.

The server will shutdown gracefully if an interrupt signal is received. Alternatively, you can call `Server.shutdown()`.

## Memory management model

### Request lifecycle
The server manages request and response buffers internally, reusing them across requests to avoid allocations. `Request` fields (path, headers, body) are slices into the connection's read buffer and are only valid until `handleRequest` returns. When a handler processes a request, it must copy any data it needs to retain, as the underlying buffers will be reused for subsequent requests.

Response headers are copied as they are added, so their values can be freed straight away. For the body:
- `setBody(buf)` copies into the worker's response buffer (`response_body_buffer_size`).
- `bodyWriteBuffer()` + `commitBody(len)` let you format straight into that buffer.
- `setBodyBorrowed(buf)` sends `buf` without copying. It must stay valid and unchanged until the response is sent, so use it for static or cached content.

### Handler responsibilities
- Handlers own and manage their internal memory
- Any data extracted from requests must be copied before the handler returns
- Handlers are shared across multiple worker threads

## Need to know

### Memory usage
Each worker thread gets it's own resources (obviously). By default, the number of worker threads is equal to the number of CPU cores. Therefore, the memory usage will depend on allocated buffer sizes, stack sizes, and the number of worker threads. You can adjust these parameters in the configuration struct. Default memory usage per worker (epoll backend):
```
Workers:    Read buffer pool:   256 x 16KB = 4MB
            Response buffer:    1MB
            Output buffer:      64KB
            Connection slab:    16384 connections, ~2MB
            Stack size:         1MB

            Total:              ~8MB
```
Read buffers are only held while a connection has unprocessed bytes, so many idle keep-alive connections don't need many buffers. If the pool runs out, buffers overflow to the heap and are freed afterwards.

### Response headers
`Content-Length`, `Date` and `Connection` are set by the server (no `Content-Length` on 1xx/204 responses; `HEAD` responses keep the length but omit the body). Adding any of them, or `Transfer-Encoding`, with `addNewHeader` is a compile error, so they can't be duplicated by accident. Set `resp.close = true` to close the connection after the response.

Header keys and values containing CR or LF are rejected (`error.InvalidHeader`), which prevents response splitting.

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

pub fn handleWSConn(_: *Self, conn: *per.ws.Conn) void {
    std.debug.print("handle ws conn... {d}\n", .{conn.fd});
}

pub fn handleWSDisconn(_: *Self, conn: *per.ws.Conn) void {
    std.debug.print("handle ws disconn... {d}\n", .{conn.fd});
}

// Called with each complete message: text, binary, ping, pong or close.
// Fragments are reassembled, pings are answered and close frames echoed
// before the handler sees them.
pub fn handleWSFrame(_: *Self, conn: *per.ws.Conn, frame: *per.ws.Frame) void {
    if (frame.opcode != .text and frame.opcode != .binary) return;
    // Reply to the client (queued; written as the socket allows)
    conn.send("Hello client!", false) catch |err| {
        std.debug.print("error writing websocket: {any}\n", .{err});
    };
}
```

The hooks run on the worker thread that owns the connection. A `*per.ws.Conn` is valid from `handleWSConn` until `handleWSDisconn` returns; `conn.send`, `conn.ping` and `conn.close(code, reason)` may be called from any thread in that window (for example to broadcast from another connection's handler), so a handler that keeps handles in a table must remove them in `handleWSDisconn` under its own lock. `conn.user` is free for per-connection state. Messages larger than `websocket_max_message_size` fail the connection with close code 1009; `send` fails with `SendQueueFull` once `websocket_max_send_queue_bytes` are unsent.

## I need your feedback
I started this project as a way to learn Zig. As such, some of it will be garbage. I would value any feedback.

## This is no framework
This is not a framework for building web applications. This is purely a HTTP server designed from the ground up to be stable and performant. There are no built-in features such as routing or authentication. There are some utilities for common use-cases, such as serving a directory of static files, `util.DirServer`.

If you want a more substantial HTTP library, I suggest that you look at [Zap](https://github.com/zigzap/zap), built on [Facil.io](http://facil.io). Facil.io is an excellent battle-tested library written in C.

## To do
Until these things are done, I don't think that this project can possibly be considered production-ready.

See [PLAN.md](PLAN.md) for the full checklist. The main open items:

- TLS 1.3 support
- Streaming (chunked) responses
- `sendfile` for file bodies
- WebSocket extras: `permessage-deflate`, an idle timeout, the Autobahn test suite
- Tune the io_uring backend until it beats epoll
- Soak, adversarial and differential (HTTP Garden) testing
- API reference

## Nice to have
- HTTP/2 support
- HTTP/3 support
- Windows support
- Templating util (possibly adapt util.DirServer to be composable)

## Thanks
Thank you to [Bo](https://github.com/boazsegev) for his advice (not all applied yet), and also for his library [Facil.io](https://facil.io). This served as a great model for robust server design, and a solid performance benchmark. The more I work on this project, the more I've come to appreciate Facil.io's astonishing performance under load.

Also, thanks to Karl Seguin for his excellent guide to [writing TCP servers in Zig](https://www.openmymind.net/TCP-Server-In-Zig-Part-1-Single-Threaded/). The start of this project was an exercise in learning Zig, and I found this guide to be very helpful for getting started.
