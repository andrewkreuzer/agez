const std = @import("std");
const cwd = std.fs.cwd;
const stem = std.fs.path.stem;
const Dir = std.fs.Dir;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const run_step = b.step("run", "Run the app");
    const run_keygen_step = b.step("run-keygen", "Run the app");
    const test_step = b.step("test", "Run unit tests");
    const testkit_step = b.step("testkit", "Run testkit tests");

    const argz = b.dependency("argz", .{ .target = target, .optimize = optimize });

    const libagez_mod = b.addModule("libagez",
        .{ .root_source_file = b.path("src/lib.zig") }
    );

    const exe = b.addExecutable(.{
        .name = "agez",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bin/agez.zig"),
            .target = target,
            .optimize = optimize,
        })
    });
    exe.root_module.addImport("agez", libagez_mod);
    exe.root_module.addImport("argz", argz.module("argz"));

    b.installArtifact(exe);

    const exe_keygen = b.addExecutable(.{
        .name = "agez-keygen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bin/agez-keygen.zig"),
            .target = target,
            .optimize = optimize,
        })
    });
    exe_keygen.root_module.addImport("agez", libagez_mod);
    exe_keygen.root_module.addImport("argz", argz.module("argz"));

    b.installArtifact(exe_keygen);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| { run_cmd.addArgs(args); }
    run_step.dependOn(&run_cmd.step);

    const run_keygen_cmd = b.addRunArtifact(exe_keygen);
    run_keygen_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| { run_keygen_cmd.addArgs(args); }
    run_keygen_step.dependOn(&run_keygen_cmd.step);

    const lib_unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    test_step.dependOn(&run_lib_unit_tests.step);

    const testkit = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/testkit.zig"),
            .target = target,
            .optimize = optimize,
        })
    });
    testkit.root_module.addImport("agez", libagez_mod);
    const run_testkit = b.addRunArtifact(testkit);
    testkit_step.dependOn(&run_testkit.step);
}
