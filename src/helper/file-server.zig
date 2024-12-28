const std = @import("std");
const Header = @import("../header.zig").Header;
const Response = @import("../response.zig").Response;

pub const FileServerConfig = struct {
    /// Disabling lazy_load will cause the file to be loaded on init.
    lazy_load: bool = true,
};

pub const FileServer = struct {
    allocator: std.mem.Allocator,
    absolute_path: []const u8,
    content: []u8,
    content_len_header: []const u8,
    loaded: bool,
    load_mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, absolute_path: []const u8, cfg: FileServerConfig) !*@This() {
        // Verify that file exists and can be opened for reading
        const file = try std.fs.openFileAbsolute(absolute_path, .{ .mode = .read_only });
        file.close();
        const self = try allocator.create(@This());
        self.* = .{
            .allocator = allocator,
            .absolute_path = try allocator.dupe(u8, absolute_path),
            .content = undefined,
            .content_len_header = undefined,
            .loaded = false,
            .load_mutex = std.Thread.Mutex{},
        };
        if (!cfg.lazy_load) try self.load();
        return self;
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.absolute_path);
        if (self.loaded) {
            self.allocator.free(self.content);
            self.allocator.free(self.content_len_header);
        }
        self.allocator.destroy(self);
    }

    pub fn load(self: *@This()) !void {
        self.load_mutex.lock();
        defer self.load_mutex.unlock();
        if (self.loaded) return;
        const file = try std.fs.openFileAbsolute(self.absolute_path, .{ .mode = .read_only });
        defer file.close();
        const stat = try file.stat();
        self.content = try self.allocator.alloc(u8, @intCast(stat.size));
        const n = try file.readAll(self.content);
        self.content_len_header = try std.fmt.allocPrint(self.allocator, "{d}", .{n});
        self.loaded = true;
    }

    pub fn serve(self: *@This(), resp: *Response) !void {
        if (!self.loaded) try self.load();
        _ = try resp.setBody(self.content);
        try resp.headers.append(try Header.init(.{
            .key = "Content-Length",
            .value = self.content_len_header,
        }));
    }
};
