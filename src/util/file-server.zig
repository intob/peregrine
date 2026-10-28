const std = @import("std");
const Response = @import("../response.zig").Response;
const Mime = @import("./mime.zig").Mime;
const Body = @import("./body.zig").Body;

pub const FileServerConfig = struct {
    /// Files up to this size are held in memory; larger ones stay open and
    /// are sent from the file (sendfile on plaintext HTTP/1.1).
    memory_max: usize = 64 * 1024,
};

/// Serves one file, opened (and, if small, read) once at init: changes to
/// the file afterwards are not seen.
pub const FileServer = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    body: Body,
    content_type: []const u8,

    pub fn init(allocator: std.mem.Allocator, path: []const u8, cfg: FileServerConfig) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        var threaded: std.Io.Threaded = .init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        const file = try std.Io.Dir.cwd().openFile(io, path, .{});
        self.* = .{
            .allocator = allocator,
            .body = try Body.load(allocator, io, file, cfg.memory_max),
            .content_type = Mime.fromExtension(std.fs.path.extension(path)).toString(),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.body.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn serve(self: *Self, resp: *Response) !void {
        try resp.addNewHeader("content-type", self.content_type);
        self.body.serve(resp);
    }
};

test "FileServer: small files from memory, large ones from the open file" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var big: [70_000]u8 = undefined;
    @memset(&big, 'x');
    for ([_]struct { []const u8, []const u8 }{ .{ "small.html", "<p>hi</p>" }, .{ "big.css", &big } }) |f| {
        const file = try tmp.dir.createFile(io, f[0], .{});
        defer file.close(io);
        try file.writeStreamingAll(io, f[1]);
    }
    const resp = try Response.init(testing.allocator, 16, 256);
    defer resp.deinit();
    var path_buf: [128]u8 = undefined;
    const small = try FileServer.init(testing.allocator, try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/small.html", .{tmp.sub_path}), .{});
    defer small.deinit();
    try small.serve(resp);
    try testing.expectEqualStrings("<p>hi</p>", resp.body);
    try testing.expect(resp.file == null);
    try testing.expect(std.mem.indexOf(u8, resp.headerBytes(), "text/html") != null);
    resp.reset();
    const large = try FileServer.init(testing.allocator, try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/big.css", .{tmp.sub_path}), .{});
    defer large.deinit();
    try large.serve(resp);
    try testing.expectEqual(@as(u64, big.len), resp.file.?.len);
    try testing.expect(!resp.file.?.close);
    resp.reset();
}
