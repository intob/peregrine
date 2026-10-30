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

    // The benchmarks import the library built for speed too: a module
    // keeps its own optimize mode, so `lib` would be a Debug build (with
    // runtime safety) unless -Doptimize is given.
    const lib_fast = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .fast,
    });
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/parser.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "peregrine", .module = lib_fast }},
        }),
    });
    const bench_step = b.step("bench", "Run parser micro-benchmarks");
    bench_step.dependOn(&b.addRunArtifact(bench).step);

    const bench_tls = b.addExecutable(.{
        .name = "bench-tls",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "peregrine", .module = lib_fast }},
        }),
    });
    const bench_tls_step = b.step("bench-tls", "Run TLS micro-benchmarks (`-- handshake` for handshakes)");
    const bench_tls_run = b.addRunArtifact(bench_tls);
    bench_tls_run.addPassthruArgs();
    bench_tls_step.dependOn(&bench_tls_run.step);

    // Load-test target: zig build bench-server [-Dtarget=...]
    const bench_server = b.addExecutable(.{
        .name = "bench-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/server.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "peregrine", .module = lib_fast }},
        }),
    });
    const bench_server_step = b.step("bench-server", "Build the plaintext benchmark server");
    bench_server_step.dependOn(&b.addInstallArtifact(bench_server, .{}).step);

    // Body-checking server for HTTP/2 churn tests: zig build verify-server
    const verify_server = b.addExecutable(.{
        .name = "verify-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/verify_server.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "peregrine", .module = lib_fast }},
        }),
    });
    const verify_server_step = b.step("verify-server", "Build the body-checking server for HTTP/2 churn tests");
    verify_server_step.dependOn(&b.addInstallArtifact(verify_server, .{}).step);

    // WebSocket load generator (Linux): zig build ws-load -Dtarget=...
    const ws_load = b.addExecutable(.{
        .name = "ws-load",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/ws_load.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "peregrine", .module = lib_fast }},
        }),
    });
    const ws_load_step = b.step("ws-load", "Build the WebSocket load generator (Linux)");
    ws_load_step.dependOn(&b.addInstallArtifact(ws_load, .{}).step);

    // TLS handshake load generator (Linux): zig build tls-load -Dtarget=...
    const tls_load = b.addExecutable(.{
        .name = "tls-load",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/tls_load.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "peregrine", .module = lib_fast }},
        }),
    });
    const tls_load_step = b.step("tls-load", "Build the TLS handshake load generator (Linux)");
    tls_load_step.dependOn(&b.addInstallArtifact(tls_load, .{}).step);
    const tls_load_test = b.addTest(.{ .name = "tls-load-test", .root_module = tls_load.root_module });
    const tls_load_test_step = b.step("test-tls-load", "Test tls-load's CertificateVerify check");
    tls_load_test_step.dependOn(&b.addRunArtifact(tls_load_test).step);
}
