//! `zig build sim` — prints the propagation feasibility table.
//!
//! Sweeps block rate × block size and reports the GHOSTDAG red (orphan) fraction
//! and max mergeset, so the feasible (rate, size, k) envelope is visible at a
//! glance. This is a Phase-0 analysis artifact, not part of the node.

const std = @import("std");
const sim = @import("sim/simnet.zig");

pub fn main() !void {
    var gpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const rates = [_]f64{ 1, 5, 10, 20 };
    // Representative block sizes: ~1 tx, a modest block, a large PQ-fat block.
    const sizes = [_]u64{ 4_000, 400_000, 4_000_000 };
    const k: u32 = 8;

    std.debug.print(
        \\ZigChain propagation feasibility (100 Mbit/s links, 50ms latency, 20 nodes, k={d})
        \\Each cell: red% (orphaned work) | max mergeset
        \\
        \\
    , .{k});

    std.debug.print("  rate\\size |", .{});
    for (sizes) |s| std.debug.print("  {d:>10} B |", .{s});
    std.debug.print("\n", .{});

    for (rates) |rate| {
        std.debug.print("  {d:>6.0}/s  |", .{rate});
        for (sizes) |size| {
            const m = try sim.runScenario(gpa, .{
                .block_rate_per_sec = rate,
                .block_size_bytes = size,
                .duration_sec = 30.0,
                .k = k,
                .seed = 42,
            });
            std.debug.print("  {d:>5.1}% mm{d:>3} |", .{ m.red_fraction * 100.0, m.max_mergeset });
        }
        std.debug.print("\n", .{});
    }

    std.debug.print(
        \\
        \\Reading it: pick the highest (rate, size) whose red% stays low and whose
        \\max mergeset stays within your chosen k. That is the throughput ceiling
        \\for this bandwidth — raise link bandwidth to move it.
        \\
    , .{});
}
