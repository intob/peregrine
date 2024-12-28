const std = @import("std");
const Header = @import("../header.zig").Header;
const Response = @import("../response.zig").Response;

pub const FileServerConfig = struct {
    lazy_load: bool = true,
};

pub const FileServer = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    content: []u8,
    content_len_header: []const u8,
    loaded: bool,
    load_mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, file: std.fs.File, cfg: FileServerConfig) !*@This() {
        const self = try allocator.create(@This());
        self.* = .{
            .allocator = allocator,
            .file = file,
            .content = undefined,
            .content_len_header = undefined,
            .loaded = false,
            .load_mutex = std.Thread.Mutex{},
        };
        if (!cfg.lazy_load) try self.load();
        return self;
    }

    pub fn deinit(self: *@This()) void {
        if (!self.loaded) {
            self.file.close();
        } else {
            self.allocator.free(self.content);
            self.allocator.free(self.content_len_header);
        }
        self.allocator.destroy(self);
    }

    pub fn load(self: *@This()) !void {
        self.load_mutex.lock();
        defer self.load_mutex.unlock();
        if (self.loaded) return;
        const stat = try self.file.stat();
        self.content = try self.allocator.alloc(u8, @intCast(stat.size));
        const n = try self.file.readAll(self.content);
        self.content_len_header = try std.fmt.allocPrint(self.allocator, "{d}", .{n});
        self.file.close();
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
