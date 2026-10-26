const std = @import("std");
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const Mime = @import("./mime.zig").Mime;

const Hit = struct {
    contents: []u8,
    content_type: []const u8,
};

pub const DirServerConfig = struct {
    request_path: []const u8 = "/",
};

/// DirServer simply loads all files into memory on init. This
/// prevents risk of OOM errors without unloading existing entries.
/// Files are served without copying.
pub const DirServer = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    req_path: []const u8,
    hits: std.ArrayList(*Hit),
    files: std.StringHashMap(*Hit),

    pub fn init(allocator: std.mem.Allocator, absolute_path: []const u8, cfg: DirServerConfig) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .req_path = cfg.request_path,
            .hits = .empty,
            .files = std.StringHashMap(*Hit).init(allocator),
        };
        errdefer self.deinit();
        var threaded: std.Io.Threaded = .init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();
        var dir = try std.Io.Dir.openDirAbsolute(io, absolute_path, .{ .iterate = true });
        defer dir.close(io);
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (entry.kind == .file) {
                try self.loadEntry(io, entry);
            }
        }
        return self;
    }

    pub fn deinit(self: *Self) void {
        var keys = self.files.keyIterator();
        while (keys.next()) |k| self.allocator.free(k.*);
        self.files.deinit();
        for (self.hits.items) |hit| {
            self.allocator.free(hit.contents);
            self.allocator.destroy(hit);
        }
        self.hits.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn serve(self: *Self, req: *Request, resp: *Response) !void {
        const path = req.getPath();
        if (!std.mem.startsWith(u8, path, self.req_path)) {
            resp.status = .not_found;
            return;
        }
        const rel_path = path[self.req_path.len..];
        if (self.files.get(rel_path)) |hit| {
            try resp.addNewHeader("content-type", hit.content_type);
            resp.setBodyBorrowed(hit.contents);
        } else {
            resp.status = .not_found;
        }
    }

    fn loadEntry(self: *Self, io: std.Io, entry: std.Io.Dir.Walker.Entry) !void {
        const hit = try self.allocator.create(Hit);
        errdefer self.allocator.destroy(hit);
        hit.* = .{
            .contents = try entry.dir.readFileAlloc(io, entry.basename, self.allocator, .unlimited),
            .content_type = Mime.fromExtension(std.fs.path.extension(entry.basename)).toString(),
        };
        errdefer self.allocator.free(hit.contents);
        try self.hits.append(self.allocator, hit);
        try self.putPath(entry.path, hit);
        if (std.mem.eql(u8, entry.basename, "index.html")) {
            const dir_path = std.fs.path.dirname(entry.path) orelse "";
            try self.putPath(dir_path, hit);
            const dir_with_slash = try std.fmt.allocPrint(self.allocator, "{s}/", .{dir_path});
            defer self.allocator.free(dir_with_slash);
            if (dir_path.len > 0) try self.putPath(dir_with_slash, hit);
        }
    }

    fn putPath(self: *Self, path: []const u8, hit: *Hit) !void {
        if (self.files.contains(path)) return;
        const key = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(key);
        try self.files.put(key, hit);
    }
};
