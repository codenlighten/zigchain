const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Government-grade default: ship ReleaseSafe. A deterministic safety trap is
    // strictly preferable to undefined behaviour that could fork the chain.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "zigchain",
        .root_module = root_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    const unit_tests = b.addTest(.{ .root_module = root_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // `zig build sim` — Phase-0 propagation feasibility table.
    const sim_mod = b.createModule(.{
        .root_source_file = b.path("src/sim_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const sim_exe = b.addExecutable(.{ .name = "zigchain-sim", .root_module = sim_mod });
    b.installArtifact(sim_exe);
    const run_sim = b.addRunArtifact(sim_exe);
    const sim_step = b.step("sim", "Run the propagation simulation");
    sim_step.dependOn(&run_sim.step);

    // `zig build demo` — full end-to-end chain run.
    const demo_mod = b.createModule(.{
        .root_source_file = b.path("src/demo_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const demo_exe = b.addExecutable(.{ .name = "zigchain-demo", .root_module = demo_mod });
    b.installArtifact(demo_exe);
    const run_demo = b.addRunArtifact(demo_exe);
    const demo_step = b.step("demo", "Run the end-to-end chain demo");
    demo_step.dependOn(&run_demo.step);
}
