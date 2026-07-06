//! Randomized property tests for the consensus core.
//!
//! These generate hundreds of random BlockDAGs from fixed seeds (reproducible in
//! CI) and assert structural invariants the hand-written golden vectors can't
//! cover exhaustively. This is the same harness the differential fuzzer will
//! later drive against the Rust reference implementation; the invariants here
//! are the properties that must hold for *any* DAG, in every implementation.

const std = @import("std");
const hashmod = @import("../core/crypto/hash.zig");
const Dag = @import("../core/consensus/dag.zig").Dag;
const Ghostdag = @import("../core/consensus/ghostdag.zig").Ghostdag;

const Hash256 = hashmod.Hash256;
const testing = std.testing;

fn idOf(i: u32) Hash256 {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, i, .little);
    return hashmod.hash(.block_header, &buf);
}

/// A random DAG structure: `parents[i]` are the parent *indices* of block i,
/// all strictly less than i (so index order is a valid insertion order).
const Structure = struct {
    parents: [][]u32,

    fn deinit(self: *Structure, gpa: std.mem.Allocator) void {
        for (self.parents) |p| gpa.free(p);
        gpa.free(self.parents);
    }
};

fn randomStructure(gpa: std.mem.Allocator, rng: std.Random, n: u32) !Structure {
    const parents = try gpa.alloc([]u32, n);
    for (0..n) |i| {
        if (i == 0) {
            parents[i] = try gpa.alloc(u32, 0); // genesis
            continue;
        }
        // 1..min(i,3) distinct earlier indices.
        const max_p: u32 = @min(@as(u32, @intCast(i)), 3);
        const cnt = rng.intRangeAtMost(u32, 1, max_p);
        var chosen: std.ArrayList(u32) = .empty;
        defer chosen.deinit(gpa);
        while (chosen.items.len < cnt) {
            const cand = rng.intRangeLessThan(u32, 0, @intCast(i));
            if (std.mem.indexOfScalar(u32, chosen.items, cand) == null) {
                try chosen.append(gpa, cand);
            }
        }
        parents[i] = try chosen.toOwnedSlice(gpa);
    }
    return .{ .parents = parents };
}

/// Build a Dag, inserting blocks in a caller-supplied order (which must respect
/// dependencies). Returns the populated Dag.
fn buildDag(gpa: std.mem.Allocator, s: Structure, insert_order: []const u32) !Dag {
    var dag = Dag.init(gpa);
    errdefer dag.deinit();
    for (insert_order) |i| {
        var ps = try gpa.alloc(Hash256, s.parents[i].len);
        defer gpa.free(ps);
        for (s.parents[i], 0..) |p, j| ps[j] = idOf(p);
        try dag.addBlock(idOf(i), ps);
    }
    return dag;
}

/// A random valid insertion order (topological): repeatedly pick, uniformly at
/// random, a not-yet-inserted block whose parents are all inserted.
fn randomInsertionOrder(gpa: std.mem.Allocator, rng: std.Random, s: Structure) ![]u32 {
    const n = s.parents.len;
    const inserted = try gpa.alloc(bool, n);
    defer gpa.free(inserted);
    @memset(inserted, false);

    var order: std.ArrayList(u32) = .empty;
    errdefer order.deinit(gpa);
    var cands: std.ArrayList(u32) = .empty;
    defer cands.deinit(gpa);

    while (order.items.len < n) {
        cands.clearRetainingCapacity();
        for (0..n) |i| {
            if (inserted[i]) continue;
            var ready = true;
            for (s.parents[i]) |p| {
                if (!inserted[p]) {
                    ready = false;
                    break;
                }
            }
            if (ready) try cands.append(gpa, @intCast(i));
        }
        const pick = cands.items[rng.intRangeLessThan(usize, 0, cands.items.len)];
        inserted[pick] = true;
        try order.append(gpa, pick);
    }
    return order.toOwnedSlice(gpa);
}

fn positionMap(gpa: std.mem.Allocator, order: []const Hash256) !std.AutoHashMapUnmanaged(Hash256, usize) {
    var m: std.AutoHashMapUnmanaged(Hash256, usize) = .empty;
    errdefer m.deinit(gpa);
    for (order, 0..) |id, i| try m.put(gpa, id, i);
    return m;
}

test "property: topological order is valid and insertion-order independent" {
    const gpa = testing.allocator;
    var seed: u64 = 0;
    while (seed < 80) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const rng = prng.random();
        const n = rng.intRangeAtMost(u32, 1, 14);

        var s = try randomStructure(gpa, rng, n);
        defer s.deinit(gpa);

        // Canonical build: index order.
        const index_order = try gpa.alloc(u32, n);
        defer gpa.free(index_order);
        for (0..n) |i| index_order[i] = @intCast(i);

        var dag_a = try buildDag(gpa, s, index_order);
        defer dag_a.deinit();
        const order_a = try dag_a.topoOrder(gpa);
        defer gpa.free(order_a);

        // Parents strictly precede children.
        var pos = try positionMap(gpa, order_a);
        defer pos.deinit(gpa);
        try testing.expectEqual(@as(usize, n), order_a.len);
        for (0..n) |i| {
            for (s.parents[i]) |p| {
                try testing.expect(pos.get(idOf(p)).? < pos.get(idOf(@intCast(i))).?);
            }
        }

        // A different valid insertion order yields the identical topo order.
        const shuffled = try randomInsertionOrder(gpa, rng, s);
        defer gpa.free(shuffled);
        var dag_b = try buildDag(gpa, s, shuffled);
        defer dag_b.deinit();
        const order_b = try dag_b.topoOrder(gpa);
        defer gpa.free(order_b);
        try testing.expectEqualSlices(Hash256, order_a, order_b);
    }
}

test "property: GHOSTDAG invariants hold on random DAGs" {
    const gpa = testing.allocator;
    var seed: u64 = 1000;
    while (seed < 1080) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const rng = prng.random();
        const n = rng.intRangeAtMost(u32, 1, 14);
        const k = rng.intRangeAtMost(u32, 0, 3);

        var s = try randomStructure(gpa, rng, n);
        defer s.deinit(gpa);
        const index_order = try gpa.alloc(u32, n);
        defer gpa.free(index_order);
        for (0..n) |i| index_order[i] = @intCast(i);
        var dag = try buildDag(gpa, s, index_order);
        defer dag.deinit();

        var gd = Ghostdag.init(gpa, &dag, k);
        defer gd.deinit();
        try gd.compute();

        // (1) blue_score recurrence + self-in-own-blue-set.
        var max_score: u64 = 0;
        for (0..n) |i| {
            const d = gd.get(idOf(@intCast(i))).?;
            try testing.expect(d.isBlue(idOf(@intCast(i)))); // block is blue in its own set
            if (d.selected_parent) |sp| {
                const spd = gd.get(sp).?;
                try testing.expectEqual(spd.blue_score + 1 + d.mergeset_blues.len, d.blue_score);
            } else {
                try testing.expectEqual(@as(u64, 0), d.blue_score); // genesis
            }
            if (d.blue_score > max_score) max_score = d.blue_score;
        }

        // (2) selectedTip has the maximum blue score.
        const tip = gd.selectedTip().?;
        try testing.expectEqual(max_score, gd.get(tip).?.blue_score);

        // (3) order() is a topologically-valid permutation of all blocks.
        const order = try gd.order(gpa);
        defer gpa.free(order);
        try testing.expectEqual(@as(usize, n), order.len);
        var pos = try positionMap(gpa, order);
        defer pos.deinit(gpa);
        try testing.expectEqual(@as(usize, n), pos.count()); // no duplicates
        for (0..n) |i| {
            try testing.expect(pos.contains(idOf(@intCast(i)))); // covers every block
            for (s.parents[i]) |p| {
                try testing.expect(pos.get(idOf(p)).? < pos.get(idOf(@intCast(i))).?);
            }
        }
    }
}

test "property: incremental GHOSTDAG (addBlock) equals batch GHOSTDAG (compute)" {
    const gpa = testing.allocator;
    var seed: u64 = 2000;
    while (seed < 2060) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const rng = prng.random();
        const n = rng.intRangeAtMost(u32, 1, 14);
        const k = rng.intRangeAtMost(u32, 0, 3);

        var s = try randomStructure(gpa, rng, n);
        defer s.deinit(gpa);
        const index_order = try gpa.alloc(u32, n);
        defer gpa.free(index_order);
        for (0..n) |i| index_order[i] = @intCast(i);

        // Batch: full DAG, color in one shot.
        var dag_b = try buildDag(gpa, s, index_order);
        defer dag_b.deinit();
        var gd_batch = Ghostdag.init(gpa, &dag_b, k);
        defer gd_batch.deinit();
        try gd_batch.compute();

        // Incremental: grow the DAG and color each block as it arrives (the
        // chain engine's exact usage pattern).
        var dag_i = Dag.init(gpa);
        defer dag_i.deinit();
        var gd_inc = Ghostdag.init(gpa, &dag_i, k);
        defer gd_inc.deinit();
        for (0..n) |i| {
            const ps = try gpa.alloc(Hash256, s.parents[i].len);
            defer gpa.free(ps);
            for (s.parents[i], 0..) |pi, j| ps[j] = idOf(pi);
            try dag_i.addBlock(idOf(@intCast(i)), ps);
            try gd_inc.addBlock(idOf(@intCast(i)));
        }

        // Every block must have identical coloring.
        for (0..n) |i| {
            const id = idOf(@intCast(i));
            const d1 = gd_batch.get(id).?;
            const d2 = gd_inc.get(id).?;
            try testing.expectEqual(d1.blue_score, d2.blue_score);
            if (d1.selected_parent) |sp1| {
                try testing.expect(d2.selected_parent != null);
                try testing.expectEqualSlices(u8, &sp1, &d2.selected_parent.?);
            } else {
                try testing.expect(d2.selected_parent == null);
            }
            try testing.expectEqualSlices(Hash256, d1.mergeset_blues, d2.mergeset_blues);
            try testing.expectEqualSlices(Hash256, d1.mergeset_reds, d2.mergeset_reds);
        }

        // ...and the same virtual-chain order.
        const o1 = try gd_batch.order(gpa);
        defer gpa.free(o1);
        const o2 = try gd_inc.order(gpa);
        defer gpa.free(o2);
        try testing.expectEqualSlices(Hash256, o1, o2);
    }
}
