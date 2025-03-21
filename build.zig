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

    const lib = b.addStaticLibrary(.{
        .name = "agez",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
    });

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    test_step.dependOn(&run_lib_unit_tests.step);

    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "agez",
        .root_source_file = b.path("src/bin/agez.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("lib", lib_module);

    b.installArtifact(exe);
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| { run_cmd.addArgs(args); }
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/bin/agez.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    test_step.dependOn(&run_exe_unit_tests.step);

    const exe_keygen = b.addExecutable(.{
        .name = "agez-keygen",
        .root_source_file = b.path("src/bin/agez-keygen.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_keygen.root_module.addImport("lib", lib_module);

    b.installArtifact(exe_keygen);
    const run_keygen_cmd = b.addRunArtifact(exe_keygen);
    run_keygen_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| { run_keygen_cmd.addArgs(args); }
    run_keygen_step.dependOn(&run_keygen_cmd.step);

    const testkit = b.addTest(.{
        .root_source_file = b.path("tests/testkit.zig"),
        .target = target,
        .optimize = optimize,
    });
    testkit.root_module.addImport("lib", lib_module);
    const run_testkit = b.addRunArtifact(testkit);
    testkit_step.dependOn(&run_testkit.step);
}
