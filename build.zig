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

    // `zig build vectors -- <scenarios.json>` — differential test report.
    const vectors_mod = b.createModule(.{
        .root_source_file = b.path("src/vectors_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    vectors_mod.addAnonymousImport("scenarios_json", .{ .root_source_file = b.path("spec/vectors/scenarios.json") });
    const vectors_exe = b.addExecutable(.{ .name = "zigchain-vectors", .root_module = vectors_mod });
    b.installArtifact(vectors_exe);
    const run_vectors = b.addRunArtifact(vectors_exe);
    if (b.args) |args| run_vectors.addArgs(args);
    const vectors_step = b.step("vectors", "Emit the differential-test vector report");
    vectors_step.dependOn(&run_vectors.step);

    // `zig build bench` — measured scaling benchmark.
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/bench_main.zig"),
        .target = target,
        .optimize = .ReleaseFast, // measure real throughput
    });
    const bench_exe = b.addExecutable(.{ .name = "zigchain-bench", .root_module = bench_mod });
    b.installArtifact(bench_exe);
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run the scaling benchmark");
    bench_step.dependOn(&run_bench.step);

    // `zig build node -- <args>` — a standalone networked node process.
    const node_mod = b.createModule(.{
        .root_source_file = b.path("src/node_main.zig"),
        .target = target,
        // ReleaseFast: uses the thread-safe smp allocator (no debug leak-tracking
        // noise; the node intentionally persists block memory for the chain).
        .optimize = .ReleaseFast,
    });
    const node_exe = b.addExecutable(.{ .name = "zigchain-node", .root_module = node_mod });
    b.installArtifact(node_exe);
    const run_node = b.addRunArtifact(node_exe);
    if (b.args) |args| run_node.addArgs(args);
    const node_step = b.step("node", "Run a standalone networked node");
    node_step.dependOn(&run_node.step);
}
