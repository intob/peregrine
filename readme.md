# Peregrine - a bleeding fast HTTP server
This is a HTTP server written in pure Zig with no dependencies other than Zig's standard library.

The main goal of this project is to provide a HTTP server, with the following priorities (in order of prevalence):
- Reliability
- Performance
- Simplicity

## I need your feedback
I started this project as a way to learn Zig. As such, some of it will be garbage. I would value any feedback.

## This is no framework
This is not a framework for building web applications. This is purely a HTTP server designed from the ground up to be stable and performant. There are no built-in features such as routing or authentication.

If you want a more substantial HTTP library, I suggest that you look at [Zap][https://github.com/zigzap/zap], built on [Facil.io][http://facil.io]. Facil.io is an excellent battle-tested library written in C.

## Benchmarks
I will add some graphs later. Currently, this (unfinished) server is around 3-5% faster than Zap/Facil.io for static GET requests.

## To do
- Query params
- HTTP/1.1 (keep-alive)
- HTTP/2
- WebSockets
- Redirects
