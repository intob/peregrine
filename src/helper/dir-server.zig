const std = @import("std");
const fs = std.fs;
const Request = @import("../request.zig").Request;
const Response = @import("../response.zig").Response;
const Header = @import("../header.zig").Header;

pub const DirServerConfig = struct {
    request_path: []const u8 = "/",
};

const Mime = enum {
    text_plain,
    text_html,
    text_css,
    application_json,
    application_javascript,
    image_avif,

    pub fn toString(self: Mime) []const u8 {
        return switch (self) {
            .text_plain => "text/plain",
            .text_html => "text/html",
            .text_css => "text/css",
            .application_json => "application/json",
            .application_javascript => "application/javascript",
            .image_avif => "image/avif",
        };
    }

    pub fn fromExtension(ext: []const u8) Mime {
        if (std.mem.eql(u8, ext, ".html")) {
            return .text_html;
        }
        if (std.mem.eql(u8, ext, ".css")) {
            return .text_css;
        }
        if (std.mem.eql(u8, ext, ".json")) {
            return .application_json;
        }
        if (std.mem.eql(u8, ext, ".js") or std.mem.eql(u8, ext, ".mjs")) {
            return .application_javascript;
        }
        if (std.mem.eql(u8, ext, ".avif")) {
            return .image_avif;
        }
        return .text_plain;
    }
};

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

pub const DirServer = struct {
    allocator: std.mem.Allocator,
    abs_path: []const u8,
    req_path: []const u8,
    files: std.StringHashMap(*Hit),

    pub fn init(
        allocator: std.mem.Allocator,
        absolute_path: []const u8,
        cfg: DirServerConfig,
    ) !*@This() {
        const self = try allocator.create(@This());
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

    pub fn deinit(self: *@This()) void {
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

    pub fn serve(self: *@This(), req: *Request, resp: *Response) !void {
        const req_path = req.getPath();
        if (!std.mem.startsWith(u8, req_path, self.req_path)) {
            resp.status = .not_found;
            try resp.addNewHeader("Content-Length", "0");
            return;
        }
        const rel_path = req_path[self.req_path.len..];
        std.debug.print("looking for [{s}]\n", .{rel_path});
        if (self.files.get(rel_path)) |hit| {
            for (hit.headers.items) |h| try resp.addHeader(h);
            resp.status = .ok;
            _ = try resp.setBody(hit.contents);
        } else {
            // TODO: pre-allocate some standard responses like this,
            // so that we don't need to memcpy the header.
            resp.status = .not_found;
            try resp.addNewHeader("Content-Length", "0");
            return;
        }
    }

    fn loadEntry(self: *@This(), entry: fs.Dir.Walker.Entry) !void {
        const file = try entry.dir.openFile(entry.basename, .{ .mode = .read_only });
        defer file.close();
        const stat = try file.stat();
        const hit = try Hit.init(self.allocator);
        errdefer hit.deinit();
        hit.contents = try self.allocator.alloc(u8, @intCast(stat.size));
        _ = try file.readAll(hit.contents);
        const content_length = try std.fmt.allocPrint(self.allocator, "{d}", .{stat.size});
        defer self.allocator.free(content_length);
        try hit.headers.append(try Header.init("Content-Length", content_length));
        try hit.headers.append(try Header.init(
            "Content-Type",
            Mime.fromExtension(fs.path.extension(entry.basename)).toString(),
        ));
        try self.files.put(try self.allocator.dupe(u8, entry.path), hit);
        if (std.mem.eql(u8, entry.basename, "index.html")) {
            const dir_path = fs.path.dirname(entry.path) orelse "";
            const dir_with_slash = try std.fmt.allocPrint(self.allocator, "{s}/", .{dir_path});
            try self.files.put(try self.allocator.dupe(u8, dir_path), hit);
            try self.files.put(dir_with_slash, hit);
            std.debug.print("put entry [{s}, {s}, {s}]: ", .{ entry.path, dir_path, dir_with_slash });
        } else {
            std.debug.print("put entry [{s}]: ", .{entry.path});
        }
        if (stat.size > 1000) {
            std.debug.print("[FILE_TOO_LARGE]\n", .{});
        } else {
            std.debug.print("{s}\n", .{hit.contents});
        }
    }
};
