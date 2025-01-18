const std = @import("std");

pub fn readKeyFile(allocator: std.mem.Allocator, filename: []const u8) ![]const u8 {
    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);
    std.debug.print("cwd: {s}\n", .{cwd_path});
    const abs_path = try std.fs.path.join(allocator, &.{ cwd_path, filename });
    defer allocator.free(abs_path);
    const file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_only });
    defer file.close();
    const stat = try file.stat();
    var buf = try allocator.alloc(u8, @intCast(stat.size));
    _ = &buf;
    _ = try file.readAll(buf);
    return buf;
}

test readKeyFile {
    const key = try readKeyFile(std.testing.allocator, "./example/basic/key.pem");
    defer std.testing.allocator.free(key);
}
