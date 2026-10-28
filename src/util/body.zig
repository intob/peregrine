//! A static body for the file servers: small files held in memory (sent
//! with the response head in one write), larger ones kept open and sent
//! from the file (`Response.sendFile`: sendfile on plaintext HTTP/1.1).
const std = @import("std");
const sys = @import("../sys.zig");
const Response = @import("../response.zig").Response;

pub const Body = union(enum) {
    memory: []u8,
    file: struct { fd: sys.fd_t, len: u64 },

    /// Reads `file` into memory if it is at most `memory_max` bytes, and
    /// closes it; otherwise keeps it open.
    pub fn load(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File, memory_max: usize) !Body {
        const len = try file.length(io);
        if (len > memory_max) return .{ .file = .{ .fd = file.handle, .len = len } };
        defer file.close(io);
        const buf = try allocator.alloc(u8, @intCast(len));
        errdefer allocator.free(buf);
        if (try file.readPositionalAll(io, buf, 0) != buf.len) return error.FileChanged;
        return .{ .memory = buf };
    }

    pub fn deinit(self: Body, allocator: std.mem.Allocator) void {
        switch (self) {
            .memory => |m| allocator.free(m),
            .file => |f| sys.close(f.fd),
        }
    }

    /// Sets `resp`'s body (no copy either way).
    pub fn serve(self: Body, resp: *Response) void {
        switch (self) {
            .memory => |m| resp.setBodyBorrowed(m),
            .file => |f| resp.sendFile(.{ .fd = f.fd, .len = f.len }),
        }
    }
};
