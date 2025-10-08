const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build options
    const enable_benchmarks = b.option(bool, "benchmarks", "Build benchmarks") orelse false;
    const enable_examples = b.option(bool, "examples", "Build examples") orelse false;

    // Create the main library module
    const zigeth_mod = b.addModule("zigeth", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add dependencies to the module if they exist
    // Uncomment these as you add the actual dependencies
    // const crypto_dep = b.dependency("zig-crypto", .{
    //     .target = target,
    //     .optimize = optimize,
    // });
    // zigeth_mod.addImport("crypto", crypto_dep.module("crypto"));

    // Build static library
    const lib = b.addStaticLibrary(.{
        .name = "zigeth",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link libc (required for some std library functions)
    lib.linkLibC();

    b.installArtifact(lib);

    // Build executable (CLI tool)
    const exe = b.addExecutable(.{
        .name = "zigeth",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("zigeth", zigeth_mod);
    exe.linkLibC();

    b.installArtifact(exe);

    // Run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the zigeth CLI");
    run_step.dependOn(&run_cmd.step);

    // Unit tests for library
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_unit_tests.linkLibC();

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Unit tests for executable
    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe_unit_tests.root_module.addImport("zigeth", zigeth_mod);
    exe_unit_tests.linkLibC();

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Test step
    const test_step = b.step("test", "Run all unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);

    // Documentation generation
    const doc_step = b.step("docs", "Generate documentation");
    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    doc_step.dependOn(&install_docs.step);

    // Benchmarks (if enabled)
    if (enable_benchmarks) {
        const bench_step = b.step("bench", "Run benchmarks");

        // Example benchmark structure
        // const bench_exe = b.addExecutable(.{
        //     .name = "bench",
        //     .root_source_file = b.path("bench/main.zig"),
        //     .target = target,
        //     .optimize = .ReleaseFast,
        // });
        // bench_exe.root_module.addImport("zigeth", zigeth_mod);
        // const run_bench = b.addRunArtifact(bench_exe);
        // bench_step.dependOn(&run_bench.step);

        _ = bench_step;
    }

    // Examples (if enabled)
    if (enable_examples) {
        const examples_step = b.step("examples", "Build all examples");

        // Add example executables here
        const example_names = [_][]const u8{
            "basic_usage",
            "rpc_client",
            "contract_interaction",
            "wallet_management",
            "transaction_signing",
        };

        for (example_names) |example_name| {
            const example_path = b.fmt("examples/{s}.zig", .{example_name});

            const example_exe = b.addExecutable(.{
                .name = example_name,
                .root_source_file = b.path(example_path),
                .target = target,
                .optimize = optimize,
            });

            example_exe.root_module.addImport("zigeth", zigeth_mod);
            example_exe.linkLibC();

            const install_example = b.addInstallArtifact(example_exe, .{
                .dest_dir = .{
                    .override = .{
                        .custom = "examples",
                    },
                },
            });

            examples_step.dependOn(&install_example.step);

            // Create individual run steps for each example
            const run_example = b.addRunArtifact(example_exe);
            const run_example_step = b.step(
                b.fmt("run-{s}", .{example_name}),
                b.fmt("Run the {s} example", .{example_name}),
            );
            run_example_step.dependOn(&run_example.step);
        }
    }

    // Format check
    const fmt_step = b.step("fmt", "Format all source files");
    const fmt = b.addFmt(.{
        .paths = &.{ "src", "build.zig" },
        .check = false,
    });
    fmt_step.dependOn(&fmt.step);

    // Format check (for CI)
    const fmt_check_step = b.step("fmt-check", "Check formatting of all source files");
    const fmt_check = b.addFmt(.{
        .paths = &.{ "src", "build.zig" },
        .check = true,
    });
    fmt_check_step.dependOn(&fmt_check.step);

    // Lint step (comprehensive code quality checks)
    const lint_step = b.step("lint", "Run all linting and code quality checks");

    // 1. Format checking
    lint_step.dependOn(&fmt_check.step);

    // 2. Build library with warnings
    const lint_lib = b.addStaticLibrary(.{
        .name = "zigeth-lint",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .Debug,
    });
    lint_lib.linkLibC();

    const lint_lib_check = b.addInstallArtifact(lint_lib, .{
        .dest_dir = .{ .override = .{ .custom = "lint" } },
    });
    lint_step.dependOn(&lint_lib_check.step);

    // 3. Build executable with warnings
    const lint_exe = b.addExecutable(.{
        .name = "zigeth-lint",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = .Debug,
    });
    lint_exe.root_module.addImport("zigeth", zigeth_mod);
    lint_exe.linkLibC();

    const lint_exe_check = b.addInstallArtifact(lint_exe, .{
        .dest_dir = .{ .override = .{ .custom = "lint" } },
    });
    lint_step.dependOn(&lint_exe_check.step);

    // 4. Run all tests as part of lint
    lint_step.dependOn(&run_lib_unit_tests.step);
    lint_step.dependOn(&run_exe_unit_tests.step);

    // Clean step
    const clean_step = b.step("clean", "Remove build artifacts");
    const remove_zig_cache = b.addRemoveDirTree(b.path("zig-cache"));
    const remove_zig_out = b.addRemoveDirTree(b.path("zig-out"));
    clean_step.dependOn(&remove_zig_cache.step);
    clean_step.dependOn(&remove_zig_out.step);
}
