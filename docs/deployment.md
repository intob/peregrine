# Deploying Peregrine

Three ways to put a Peregrine app on the internet, from least to most of
Peregrine doing the work. Peregrine is not fit for production yet (see the
readme); these are for dev projects and for trying it under real traffic.

| | Behind a Cloudflare Tunnel | Behind Cloudflare's proxy | Exposed directly |
|---|---|---|---|
| Who terminates the client's TLS | Cloudflare | Cloudflare | Peregrine |
| Cloudflare → Peregrine | `cloudflared`, plain HTTP/1.1 on loopback | TLS over the internet | n/a |
| Peregrine's TLS, HTTP/2, HTTP/3 | unused | TLS (and HTTP/2 if Cloudflare uses it to the origin) | all of it |
| Open ports | none | 443/tcp, Cloudflare's IPs only | 443/tcp and 443/udp |
| Certificates | Cloudflare's | a Cloudflare Origin CA certificate (up to 15 years) | yours to issue and renew |
| Client IP | `CF-Connecting-IP` header | `CF-Connecting-IP` header | not available (see below) |
| Bottleneck | `cloudflared` | the network | Peregrine |

Two gaps apply to all three:

- **No client address.** `Request` doesn't carry the peer's address. Behind
  Cloudflare, read the `CF-Connecting-IP` header (`req.findHeader`) instead;
  exposed directly, there is no client IP for logs or rate limits.
- **No ACME, no certificate reload.** Certificates are PEM passed to `init`,
  parsed once. A new certificate means a restart (SIGTERM shuts down
  gracefully).

On Linux, `.backend = .auto` is right everywhere: Docker's default seccomp
profile blocks io_uring, so it falls back to epoll, which is as fast for
keep-alive requests. Ubuntu 6.8 kernels from 6.8.0-136 reject correct
io_uring buffer-ring registrations; Peregrine works around that.

## 1. Behind a Cloudflare Tunnel

Browser → Cloudflare edge (TLS, HTTP/2, HTTP/3) → `cloudflared` → plain
HTTP/1.1 on loopback → Peregrine.

The cheapest and simplest: no open ports, no certificates, and any small
machine already running `cloudflared` will do. It also gives Peregrine the
least to do. Cloudflare's edge speaks TLS, HTTP/2 and HTTP/3 to the browser,
so Peregrine's own implementations go unused; what Peregrine serves is
plaintext HTTP/1.1, its fastest path. `cloudflared` (a Go proxy) costs far
more CPU per request than Peregrine, and the hop through Cloudflare's edge
adds more latency than anything on the machine. Neither matters for dev
traffic.

WebSockets and streamed responses (`resp.stream()`) work through the tunnel.
Cloudflare's free plan caps request bodies at 100 MB and answers 524 if a
response hasn't started within 100 seconds.

```zig
const srv = try per.Server(Handler).init(gpa, 8080, .{
    .ip = "127.0.0.1", // only cloudflared connects
    .worker_thread_count = 2, // leave the cores to cloudflared and the app
    .keep_alive_timeout_s = 120, // longer than cloudflared's pool (below)
});
```

```yaml
# cloudflared config.yml
ingress:
  - hostname: app.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

- **Keep-alive timeouts.** `cloudflared` keeps idle connections to the
  origin for 90 seconds by default (`originRequest.keepAliveTimeout`);
  Peregrine closes them after 5 (`keep_alive_timeout_s`). When Peregrine
  closes first, `cloudflared` sometimes sends a request on a connection
  that is closing and the client gets a 502. Keep Peregrine's timeout the
  longer one: raise `keep_alive_timeout_s` above 90, or lower
  `keepAliveTimeout`.
- **No `tls`, no `http3`, no `h2c`.** `cloudflared` speaks HTTP/1.1 to a
  plaintext origin (its `http2Origin` needs an https origin), and `http3`
  would add an `Alt-Svc` header for a port no one can reach.

## 2. Behind Cloudflare's proxy, without a tunnel

Browser → Cloudflare edge → TLS over the internet → Peregrine on 443.

The DNS record is proxied (orange cloud) and points at the server's address.
There is no `cloudflared`: Cloudflare connects to Peregrine itself, so
Peregrine's TLS does the work a Go proxy did in option 1, and Cloudflare's
cache and DDoS protection stay in front.

- **Certificate.** Issue a Cloudflare Origin CA certificate (SSL/TLS →
  Origin Server) and set the zone's SSL mode to Full (strict). Choose ECDSA:
  an RSA signature costs Peregrine about 25 times an ECDSA P-256 one. The
  certificate lasts up to 15 years, which covers the missing ACME.
- **Firewall.** Allow 443/tcp only from Cloudflare's published IP ranges
  (cloudflare.com/ips), or anyone who finds the address can skip
  Cloudflare. Peregrine doesn't verify client certificates, so
  Authenticated Origin Pulls isn't an option.
- **HTTP/2.** Offer `"h2"` in ALPN so Cloudflare can use HTTP/2 to the
  origin when the zone's "HTTP/2 to Origin" setting is on; it falls back to
  HTTP/1.1 otherwise.

```zig
const srv = try per.Server(Handler).init(gpa, 443, .{
    .tls = .{
        .cert_pem = cert_pem, // the Origin CA certificate
        .key_pem = key_pem,
        .alpn = &.{ "h2", "http/1.1" },
    },
    .keep_alive_timeout_s = 120, // Cloudflare reuses origin connections
});
```

Leave `http3` off: Cloudflare connects to origins over TCP, and the edge
already offers HTTP/3 to browsers.

## 3. Exposed directly

Browser → Peregrine on 443 (TCP and UDP).

The fastest, and the only option where browsers get Peregrine's own
HTTP/2, HTTP/3, priorities and 0-RTT. Any small VPS will do; Peregrine
allocates its buffers at startup, so memory use is small and flat, and a
2-core ARM instance is plenty for a dev project. Build with
`-Dtarget=aarch64-linux-musl` (and `-Dcpu` for the instance, or aarch64 has
no AES instructions) or `x86_64-linux-musl`: the binary is static, with no
libc.

```zig
const srv = try per.Server(Handler).init(gpa, 443, .{
    .tls = .{
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .alpn = &.{ "h2", "http/1.1" },
        .ticket_key = ticket_key, // optional: tickets survive restarts
    },
    .http3 = .{}, // UDP 443; Alt-Svc on every response
});
```

- **Certificates.** Issue them outside Peregrine (certbot or lego, HTTP-01
  through a short-lived listener or DNS-01) and restart to load renewals.
  Use an ECDSA key.
- **Firewall.** Open 443/udp as well as 443/tcp, or browsers try HTTP/3,
  time out and stay on HTTP/2.
- **kTLS.** With the kernel's `tls` module loaded (`modprobe tls`), files
  sent with `Response.sendFile` go out with sendfile over TLS. Kernels
  before 6.14 can't rekey a kTLS connection, so one whose client asks for a
  KeyUpdate is closed; clients rarely do.
- **No client IP, nothing in front.** Requests carry no peer address, and
  there is no CDN or filtering between the internet and the server.
