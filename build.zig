const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addModule("peregrine", .{
        .root_source_file = b.path("./src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lib_test = b.addTest(.{
        .name = "tests",
        .root_source_file = b.path("./src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lib_test_step = b.step("test", "Run library tests");
    lib_test_step.dependOn(&b.addRunArtifact(lib_test).step);

    // TODO: Clean up this mess. Zap has a good example of how to do this.
    // Create a []struct, and iterate over it...

    inline for ([_]struct {
        name: []const u8,
        src: []const u8,
    }{
        .{ .name = "basic", .src = "./example/basic/basic.zig" },
        //.{ .name = "counter", .src = "./example/counter/counter.zig" },
        //.{ .name = "fileserver", .src = "./example/fileserver/fileserver.zig" },
        //.{ .name = "dirserver", .src = "./example/dirserver/dirserver.zig" },
        //.{ .name = "websocket", .src = "./example/websocket/websocket.zig" },
    }) |excfg| {
        const exe = b.addExecutable(.{
            .name = excfg.name,
            .root_source_file = b.path(excfg.src),
            .target = target,
            .optimize = optimize,
        });
        exe.root_module.addImport("peregrine", lib);
        b.installArtifact(exe);
        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| run_cmd.addArgs(args);
        const name = try std.fmt.allocPrint(b.allocator, "run-{s}", .{excfg.name});
        const desc = try std.fmt.allocPrint(b.allocator, "Run the {s} example", .{excfg.name});
        const run_step = b.step(name, desc);
        run_step.dependOn(&run_cmd.step);
    }
}
