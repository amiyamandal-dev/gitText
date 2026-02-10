const std = @import("std");

pub fn build(b: *std.Build) void {
    // WASM target
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    // Build the WASM module
    const exe = b.addExecutable(.{
        .name = "editor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseSmall,
        }),
    });

    // WASM-specific settings
    exe.entry = .disabled;
    exe.rdynamic = true;

    // Install to docs directory
    const install_step = b.addInstallArtifact(exe, .{
        .dest_dir = .{ .override = .{ .custom = "../docs" } },
    });

    b.getInstallStep().dependOn(&install_step.step);

    // Add a run step for convenience (just an alias for build)
    const run_step = b.step("run", "Build the WASM module");
    run_step.dependOn(b.getInstallStep());
}
