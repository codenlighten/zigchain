const std = @import("std");

// Vendored PQClean SPHINCS+ (see vendor/pqclean/). Each scheme's C is the same
// set of filenames with scheme-prefixed symbols, so the two schemes are built
// as separate static libraries with isolated include paths (their headers share
// names). SHAKE/RNG live in one shared library to avoid duplicate symbols.
const sphincs_files = [_][]const u8{
    "address.c",     "context_shake.c",      "fors.c",  "hash_shake.c",
    "merkle.c",      "sign.c",               "utils.c", "utilsx1.c",
    "wots.c",        "wotsx1.c",             "thash_shake_simple.c",
};

const PqClean = struct { common: *std.Build.Step.Compile, f128: *std.Build.Step.Compile, s128: *std.Build.Step.Compile };

fn buildPqclean(b: *std.Build, target: std.Build.ResolvedTarget) PqClean {
    const cflags = [_][]const u8{ "-O3", "-std=c99" };

    const common = b.addLibrary(.{ .name = "pqclean_common", .linkage = .static, .root_module = b.createModule(.{
        .target = target,
        .optimize = .ReleaseFast,
        .link_libc = true,
    }) });
    common.root_module.addCSourceFiles(.{ .root = b.path("vendor/pqclean/common"), .files = &.{ "fips202.c", "randombytes.c" }, .flags = &cflags });
    common.root_module.addIncludePath(b.path("vendor/pqclean/common"));

    const scheme = struct {
        fn make(bb: *std.Build, t: std.Build.ResolvedTarget, name: []const u8, dir: []const u8, flags: []const []const u8) *std.Build.Step.Compile {
            const lib = bb.addLibrary(.{ .name = name, .linkage = .static, .root_module = bb.createModule(.{
                .target = t,
                .optimize = .ReleaseFast,
                .link_libc = true,
            }) });
            lib.root_module.addCSourceFiles(.{ .root = bb.path(dir), .files = &sphincs_files, .flags = flags });
            lib.root_module.addIncludePath(bb.path(dir));
            lib.root_module.addIncludePath(bb.path("vendor/pqclean/common"));
            return lib;
        }
    };
    return .{
        .common = common,
        .f128 = scheme.make(b, target, "pqclean_sphincs_128f", "vendor/pqclean/sphincs-shake-128f-simple", &cflags),
        .s128 = scheme.make(b, target, "pqclean_sphincs_128s", "vendor/pqclean/sphincs-shake-128s-simple", &cflags),
    };
}

fn linkPqclean(artifact: *std.Build.Step.Compile, pq: PqClean) void {
    artifact.root_module.linkLibrary(pq.f128);
    artifact.root_module.linkLibrary(pq.s128);
    artifact.root_module.linkLibrary(pq.common);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Government-grade default: ship ReleaseSafe. A deterministic safety trap is
    // strictly preferable to undefined behaviour that could fork the chain.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    // Vendored post-quantum vault crypto, linked into every artifact that
    // reaches the scheme registry (i.e. all of them, via root.zig).
    const pq = buildPqclean(b, target);

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
    linkPqclean(lib, pq);
    b.installArtifact(lib);

    const unit_tests = b.addTest(.{ .root_module = root_mod });
    linkPqclean(unit_tests, pq);
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
    linkPqclean(sim_exe, pq);
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
    linkPqclean(demo_exe, pq);
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
    linkPqclean(vectors_exe, pq);
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
    linkPqclean(bench_exe, pq);
    b.installArtifact(bench_exe);
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run the scaling benchmark");
    bench_step.dependOn(&run_bench.step);

    // `zig build node -- <args>` — a standalone networked node process.
    // `-Dnode-safe` builds it in ReleaseSafe (runtime integer-overflow / bounds
    // traps kept on) — recommended for deployment, where the node validates
    // untrusted network input. With a libc (e.g. musl) target this still uses
    // the C allocator, so there is no debug-allocator leak noise. Default is
    // ReleaseFast for local dev/mining speed.
    const node_safe = b.option(bool, "node-safe", "Build the node in ReleaseSafe (recommended for deployment)") orelse false;
    const node_mod = b.createModule(.{
        .root_source_file = b.path("src/node_main.zig"),
        .target = target,
        .optimize = if (node_safe) .ReleaseSafe else .ReleaseFast,
        // Link libc so the runtime uses the C allocator: no debug-allocator
        // leak-tracking (the node deliberately retains the chain's working set
        // for its lifetime), while ReleaseSafe's overflow/bounds traps stay on.
        // With a musl target this still produces a static binary.
        .link_libc = true,
    });
    const node_exe = b.addExecutable(.{ .name = "zigchain-node", .root_module = node_mod });
    linkPqclean(node_exe, pq);
    b.installArtifact(node_exe);
    const run_node = b.addRunArtifact(node_exe);
    if (b.args) |args| run_node.addArgs(args);
    const node_step = b.step("node", "Run a standalone networked node");
    node_step.dependOn(&run_node.step);

    // `zig build license -- <keygen|issue|verify> ...` — the SmartLedger PQ
    // software-license tool.
    const license_mod = b.createModule(.{
        .root_source_file = b.path("src/license_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const license_exe = b.addExecutable(.{ .name = "zigchain-license", .root_module = license_mod });
    linkPqclean(license_exe, pq);
    b.installArtifact(license_exe);
    const run_license = b.addRunArtifact(license_exe);
    if (b.args) |args| run_license.addArgs(args);
    const license_step = b.step("license", "Issue/verify PQ software licenses");
    license_step.dependOn(&run_license.step);

    // `zig build vault -- <address|sign|verify> ...` — the air-gapped custody tool.
    const vault_mod = b.createModule(.{
        .root_source_file = b.path("src/vault_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const vault_exe = b.addExecutable(.{ .name = "zigchain-vault", .root_module = vault_mod });
    linkPqclean(vault_exe, pq);
    b.installArtifact(vault_exe);
    const run_vault = b.addRunArtifact(vault_exe);
    if (b.args) |args| run_vault.addArgs(args);
    const vault_step = b.step("vault", "Air-gapped custody: derive keys and sign offline");
    vault_step.dependOn(&run_vault.step);
}
