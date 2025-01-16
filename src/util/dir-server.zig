const std = @import("std");
const fs = std.fs;
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const Header = @import("../header.zig").Header;
const Mime = @import("./mime.zig").Mime;

const Hit = struct {
    allocator: std.mem.Allocator,
    contents: []u8,
    headers: std.ArrayList(Header),

    pub fn init(allocator: std.mem.Allocator) !*Hit {
        const self = try allocator.create(Hit);
        self.allocator = allocator;
        self.headers = std.ArrayList(Header).init(allocator);
        return self;
    }

    pub fn deinit(self: *Hit) void {
        if (self.contents.len > 0) {
            self.allocator.free(self.contents);
        }
        self.headers.deinit();
        self.allocator.destroy(self);
    }
};

pub const DirServerConfig = struct {
    request_path: []const u8 = "/",
};

/// DirServer simply loads all files into memory on init. This
/// prevents risk of OOM errors without unloading existing entries.
pub const DirServer = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    abs_path: []const u8,
    req_path: []const u8,
    files: std.StringHashMap(*Hit),

    pub fn init(allocator: std.mem.Allocator, absolute_path: []const u8, cfg: DirServerConfig) !*Self {
        const self = try allocator.create(Self);
        self.* = .{
            .allocator = allocator,
            .abs_path = absolute_path,
            .req_path = cfg.request_path,
            .files = std.StringHashMap(*Hit).init(allocator),
        };
        var dir = try fs.openDirAbsolute(absolute_path, .{
            .access_sub_paths = true,
            .iterate = true,
        });
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind == .file) {
                try self.loadEntry(entry);
            }
        }
        return self;
    }

    pub fn deinit(self: *Self) void {
        var seen = std.AutoHashMap(usize, void).init(self.allocator);
        var iterator = self.files.iterator();
        while (iterator.next()) |entry| {
            const hit = entry.value_ptr.*;
            const ptr_num: usize = @intFromPtr(hit);
            if (seen.get(ptr_num) == null) {
                seen.put(ptr_num, {}) catch |err| {
                    std.debug.print("Failed to put in seen map: {any}\n", .{err});
                    continue;
                };
                hit.deinit();
            }
            self.allocator.free(entry.key_ptr.*);
        }
        seen.deinit();
        self.files.deinit();
        self.allocator.destroy(self);
    }

    pub fn serve(self: *Self, req: *Request, resp: *Response) !void {
        if (!std.mem.startsWith(u8, req.path_and_query, self.req_path)) {
            resp.status = .not_found;
            return;
        }
        const rel_path = req.path_and_query[self.req_path.len..];
        if (self.files.get(rel_path)) |hit| {
            for (hit.headers.items) |h| try resp.addHeader(h);
            _ = try resp.setBody(hit.contents);
        } else {
            resp.status = .not_found;
            return;
        }
    }

    fn loadEntry(self: *Self, entry: fs.Dir.Walker.Entry) !void {
        const file = try entry.dir.openFile(entry.basename, .{ .mode = .read_only });
        defer file.close();
        const stat = try file.stat();
        const hit = try Hit.init(self.allocator);
        errdefer hit.deinit();
        hit.contents = try self.allocator.alloc(u8, @intCast(stat.size));
        _ = try file.readAll(hit.contents);
        const content_length = try std.fmt.allocPrint(self.allocator, "{d}", .{stat.size});
        defer self.allocator.free(content_length);
        try hit.headers.append(try Header.init("content-length", content_length));
        try hit.headers.append(try Header.init(
            "content-type",
            Mime.fromExtension(fs.path.extension(entry.basename)).toString(),
        ));
        try self.files.put(try self.allocator.dupe(u8, entry.path), hit);
        if (std.mem.eql(u8, entry.basename, "index.html")) {
            const dir_path = fs.path.dirname(entry.path) orelse "";
            const dir_with_slash = try std.fmt.allocPrint(self.allocator, "{s}/", .{dir_path});
            try self.files.put(try self.allocator.dupe(u8, dir_path), hit);
            try self.files.put(dir_with_slash, hit);
            std.debug.print("put entry [{s}, {s}, {s}]\n", .{ entry.path, dir_path, dir_with_slash });
        } else {
            std.debug.print("put entry [{s}]\n", .{entry.path});
        }
    }
};
