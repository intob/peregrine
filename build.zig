const std = @import("std");

pub fn build(b: *std.Build) void {
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

    // Example app
    const example = b.addExecutable(.{
        .name = "example",
        .root_source_file = b.path("./example/example.zig"),
        .target = target,
        .optimize = optimize,
    });
    example.root_module.addImport("peregrine", lib);
    b.installArtifact(example);
    const example_run_cmd = b.addRunArtifact(example);
    example_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        example_run_cmd.addArgs(args);
    }
    const example_run_step = b.step("run-example", "Run the example app");
    example_run_step.dependOn(&example_run_cmd.step);
}
