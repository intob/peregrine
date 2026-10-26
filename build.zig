const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addModule("peregrine", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    // e.g. -Dtest-filter="fuzz: tls" to fuzz one target.
    const test_filters = b.option([]const []const u8, "test-filter", "Only build tests whose names contain this") orelse &.{};
    const lib_test = b.addTest(.{
        .name = "tests",
        .root_module = lib,
        .filters = test_filters,
    });
    const lib_test_step = b.step("test", "Run library tests");
    lib_test_step.dependOn(&b.addRunArtifact(lib_test).step);

    const examples = [_]struct { name: []const u8, src: []const u8 }{
        .{ .name = "basic", .src = "example/basic/basic.zig" },
        .{ .name = "counter", .src = "example/counter/counter.zig" },
        .{ .name = "fileserver", .src = "example/fileserver/fileserver.zig" },
        .{ .name = "dirserver", .src = "example/dirserver/dirserver.zig" },
        .{ .name = "websocket", .src = "example/websocket/websocket.zig" },
        .{ .name = "https", .src = "example/https/https.zig" },
    };
    for (examples) |excfg| {
        const exe = b.addExecutable(.{
            .name = excfg.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(excfg.src),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "peregrine", .module = lib }},
            }),
        });
        b.installArtifact(exe);
        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        run_cmd.addPassthruArgs();
        const name = b.fmt("run-{s}", .{excfg.name});
        const desc = b.fmt("Run the {s} example", .{excfg.name});
        const run_step = b.step(name, desc);
        run_step.dependOn(&run_cmd.step);
    }

    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/parser.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "peregrine", .module = lib }},
        }),
    });
    const bench_step = b.step("bench", "Run parser micro-benchmarks");
    bench_step.dependOn(&b.addRunArtifact(bench).step);

    // Load-test target: zig build bench-server [-Dtarget=...]
    const bench_server = b.addExecutable(.{
        .name = "bench-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/server.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "peregrine", .module = lib }},
        }),
    });
    const bench_server_step = b.step("bench-server", "Build the plaintext benchmark server");
    bench_server_step.dependOn(&b.addInstallArtifact(bench_server, .{}).step);
}
