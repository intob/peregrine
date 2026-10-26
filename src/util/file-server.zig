const std = @import("std");
const Response = @import("../response.zig").Response;
const Mime = @import("./mime.zig").Mime;

pub const FileServerConfig = struct {
    /// Disabling lazy_load will cause the file to be loaded on init.
    lazy_load: bool = true,
};

/// Serves one file from memory, without copying it per request.
pub const FileServer = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    absolute_path: []const u8,
    content: []u8,
    content_type: []const u8,
    loaded: std.atomic.Value(bool),
    load_mutex: std.Io.Mutex,

    pub fn init(allocator: std.mem.Allocator, absolute_path: []const u8, cfg: FileServerConfig) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .absolute_path = try allocator.dupe(u8, absolute_path),
            .content = &.{},
            .content_type = Mime.fromExtension(std.fs.path.extension(absolute_path)).toString(),
            .loaded = .init(false),
            .load_mutex = .init,
        };
        errdefer allocator.free(self.absolute_path);
        // Verify that the file can be read, even when loading lazily.
        try self.load();
        if (cfg.lazy_load) {
            allocator.free(self.content);
            self.content = &.{};
            self.loaded.store(false, .release);
        }
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.absolute_path);
        if (self.loaded.load(.acquire)) self.allocator.free(self.content);
        self.allocator.destroy(self);
    }

    pub fn serve(self: *Self, resp: *Response) !void {
        if (!self.loaded.load(.acquire)) try self.load();
        try resp.addNewHeader("content-type", self.content_type);
        resp.setBodyBorrowed(self.content);
    }

    fn load(self: *Self) !void {
        var threaded: std.Io.Threaded = .init(self.allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        self.load_mutex.lockUncancelable(io);
        defer self.load_mutex.unlock(io);
        if (self.loaded.load(.acquire)) return;
        self.content = try std.Io.Dir.cwd().readFileAlloc(io, self.absolute_path, self.allocator, .unlimited);
        self.loaded.store(true, .release);
    }
};
