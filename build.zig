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

    // TODO: Clean up this mess. Zap has a good example of how to do this.
    // Create a []struct, and iterate over it...

    // Basic example
    const basic = b.addExecutable(.{
        .name = "basic",
        .root_source_file = b.path("./example/basic/basic.zig"),
        .target = target,
        .optimize = optimize,
    });
    basic.root_module.addImport("peregrine", lib);
    b.installArtifact(basic);
    const basic_run_cmd = b.addRunArtifact(basic);
    basic_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| basic_run_cmd.addArgs(args);
    const basic_run_step = b.step("run-basic", "Run the basic example");
    basic_run_step.dependOn(&basic_run_cmd.step);

    // Counter example
    const counter = b.addExecutable(.{
        .name = "counter",
        .root_source_file = b.path("./example/counter/counter.zig"),
        .target = target,
        .optimize = optimize,
    });
    counter.root_module.addImport("peregrine", lib);
    b.installArtifact(counter);
    const counter_run_cmd = b.addRunArtifact(counter);
    counter_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| counter_run_cmd.addArgs(args);
    const counter_run_step = b.step("run-counter", "Run the counter example");
    counter_run_step.dependOn(&counter_run_cmd.step);

    // Fileserver example
    const fileserver = b.addExecutable(.{
        .name = "fileserver",
        .root_source_file = b.path("./example/fileserver/fileserver.zig"),
        .target = target,
        .optimize = optimize,
    });
    fileserver.root_module.addImport("peregrine", lib);
    b.installArtifact(fileserver);
    const fileserver_run_cmd = b.addRunArtifact(fileserver);
    fileserver_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| fileserver_run_cmd.addArgs(args);
    const fileserver_run_step = b.step("run-fileserver", "Run the fileserver example");
    fileserver_run_step.dependOn(&fileserver_run_cmd.step);

    // Dirserver example
    const dirserver = b.addExecutable(.{
        .name = "dirserver",
        .root_source_file = b.path("./example/dirserver/dirserver.zig"),
        .target = target,
        .optimize = optimize,
    });
    dirserver.root_module.addImport("peregrine", lib);
    b.installArtifact(dirserver);
    const dirserver_run_cmd = b.addRunArtifact(dirserver);
    dirserver_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| dirserver_run_cmd.addArgs(args);
    const dirserver_run_step = b.step("run-dirserver", "Run the dirserver example");
    dirserver_run_step.dependOn(&dirserver_run_cmd.step);

    // Websocket example
    const websocket = b.addExecutable(.{
        .name = "websocket",
        .root_source_file = b.path("./example/websocket/websocket.zig"),
        .target = target,
        .optimize = optimize,
    });
    websocket.root_module.addImport("peregrine", lib);
    b.installArtifact(websocket);
    const websocket_run_cmd = b.addRunArtifact(websocket);
    websocket_run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| websocket_run_cmd.addArgs(args);
    const websocket_run_step = b.step("run-websocket", "Run the websocket example");
    websocket_run_step.dependOn(&websocket_run_cmd.step);
}
