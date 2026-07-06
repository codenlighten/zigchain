//! GHOSTDAG coloring and the virtual-chain total order.
//!
//! Implements the algorithm specified in `spec/ghostdag.md`. Correctness here is
//! consensus-critical and subtle (the k-cluster rule), so the implementation is
//! deliberately the straightforward, spec-faithful one: reachability is computed
//! by breadth-first search rather than a reachability oracle. That is O(n) per
//! query and therefore fine for tests and small DAGs; a Phase-2 interval-labeling
//! oracle (Kaspa-style) is the planned optimization and must produce identical
//! colorings — the golden vectors in the test module guard that.

const std = @import("std");
const hashmod = @import("../crypto/hash.zig");
const dag_mod = @import("dag.zig");
const Dag = dag_mod.Dag;

const Hash256 = hashmod.Hash256;
const HashSet = std.AutoHashMapUnmanaged(Hash256, void);

pub const Error = error{MissingBlock} || dag_mod.Error || std.mem.Allocator.Error;

fn eql(a: Hash256, b: Hash256) bool {
    return std.mem.eql(u8, &a, &b);
}
fn less(a: Hash256, b: Hash256) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

pub const GhostdagData = struct {
    blue_score: u64,
    selected_parent: ?Hash256,
    mergeset_blues: []Hash256,
    mergeset_reds: []Hash256,
    /// Keys are exactly this block's blue set ({B} ∪ blues(past(B))).
    blue_anticone_sizes: std.AutoHashMapUnmanaged(Hash256, u32),

    fn deinit(self: *GhostdagData, gpa: std.mem.Allocator) void {
        gpa.free(self.mergeset_blues);
        gpa.free(self.mergeset_reds);
        self.blue_anticone_sizes.deinit(gpa);
    }

    pub fn isBlue(self: GhostdagData, id: Hash256) bool {
        return self.blue_anticone_sizes.contains(id);
    }
};

pub const Ghostdag = struct {
    gpa: std.mem.Allocator,
    dag: *const Dag,
    k: u32,
    data: std.AutoHashMapUnmanaged(Hash256, GhostdagData) = .empty,
    /// Position of each block in the DAG's deterministic topological order.
    topo_index: std.AutoHashMapUnmanaged(Hash256, u32) = .empty,
    /// The topological order itself (index -> block id).
    topo: []Hash256 = &.{},
    /// Reachability cache: `past_bits[i]` has bit j set iff topo[j] ∈ past(topo[i]).
    /// Built once in `compute`, this makes ancestor queries O(1) instead of O(n)
    /// BFS — the difference between O(n⁴) and O(n³) coloring at scale.
    past_bits: []std.DynamicBitSetUnmanaged = &.{},

    pub fn init(gpa: std.mem.Allocator, dag: *const Dag, k: u32) Ghostdag {
        return .{ .gpa = gpa, .dag = dag, .k = k };
    }

    pub fn deinit(self: *Ghostdag) void {
        var it = self.data.iterator();
        while (it.next()) |e| e.value_ptr.deinit(self.gpa);
        self.data.deinit(self.gpa);
        self.topo_index.deinit(self.gpa);
        for (self.past_bits) |*b| b.deinit(self.gpa);
        if (self.past_bits.len > 0) self.gpa.free(self.past_bits);
        if (self.topo.len > 0) self.gpa.free(self.topo);
    }

    pub fn get(self: *const Ghostdag, id: Hash256) ?*const GhostdagData {
        return self.data.getPtr(id);
    }

    /// Is `a` an ancestor of `b`, or `a == b`? Used by the finality gadget to
    /// decide whether a block lies within a finalized cut's past. Valid only
    /// after `compute`.
    pub fn isAncestorOrSelf(self: *const Ghostdag, a: Hash256, b: Hash256) bool {
        if (eql(a, b)) return true;
        _ = self.topo_index.get(a) orelse return false;
        _ = self.topo_index.get(b) orelse return false;
        return self.bitAncestor(a, b);
    }

    /// Color the entire DAG. Processes blocks in topological order so each
    /// block's selected parent is already computed.
    pub fn compute(self: *Ghostdag) Error!void {
        const topo = try self.dag.topoOrder(self.gpa);
        self.topo = topo; // ownership transferred; freed in deinit
        for (topo, 0..) |id, i| try self.topo_index.put(self.gpa, id, @intCast(i));

        // Build the reachability cache in topological order: a block's past is
        // the union of each parent's past plus the parent itself.
        const n = topo.len;
        self.past_bits = try self.gpa.alloc(std.DynamicBitSetUnmanaged, n);
        for (topo, 0..) |id, i| {
            self.past_bits[i] = try std.DynamicBitSetUnmanaged.initEmpty(self.gpa, n);
            const parents = self.dag.parentsOf(id) orelse return Error.MissingBlock;
            for (parents) |p| {
                const pi = self.topo_index.get(p).?;
                self.past_bits[i].set(pi);
                self.past_bits[i].setUnion(self.past_bits[pi]);
            }
        }

        for (topo) |id| try self.computeBlock(id);
    }

    fn computeBlock(self: *Ghostdag, id: Hash256) Error!void {
        const parents = self.dag.parentsOf(id) orelse return Error.MissingBlock;

        // Genesis.
        if (parents.len == 0) {
            var m: std.AutoHashMapUnmanaged(Hash256, u32) = .empty;
            try m.put(self.gpa, id, 0);
            try self.data.put(self.gpa, id, .{
                .blue_score = 0,
                .selected_parent = null,
                .mergeset_blues = try self.gpa.alloc(Hash256, 0),
                .mergeset_reds = try self.gpa.alloc(Hash256, 0),
                .blue_anticone_sizes = m,
            });
            return;
        }

        // Selected parent: max blue_score, tie → smaller id.
        var sp = parents[0];
        var sp_score = self.data.get(sp).?.blue_score;
        for (parents[1..]) |p| {
            const s = self.data.get(p).?.blue_score;
            if (s > sp_score or (s == sp_score and less(p, sp))) {
                sp = p;
                sp_score = s;
            }
        }
        const sp_data = self.data.get(sp).?;

        // Inherit sp's blue set (includes sp itself).
        var blues = try cloneMap(self.gpa, sp_data.blue_anticone_sizes);
        errdefer blues.deinit(self.gpa);

        // Mergeset = past(id) \ past(sp) \ {sp}, in topological order.
        const mergeset = try self.orderedMergeset(id, sp);
        defer self.gpa.free(mergeset);

        var mergeset_blues: std.ArrayList(Hash256) = .empty;
        errdefer mergeset_blues.deinit(self.gpa);
        var mergeset_reds: std.ArrayList(Hash256) = .empty;
        errdefer mergeset_reds.deinit(self.gpa);

        for (mergeset) |k_block| {
            if (try self.tryColorBlue(&blues, k_block)) {
                try mergeset_blues.append(self.gpa, k_block);
            } else {
                try mergeset_reds.append(self.gpa, k_block);
            }
        }

        // Add the block itself (anticone 0 — it is in the future of all ancestors).
        try blues.put(self.gpa, id, 0);

        try self.data.put(self.gpa, id, .{
            .blue_score = sp_data.blue_score + 1 + mergeset_blues.items.len,
            .selected_parent = sp,
            .mergeset_blues = try mergeset_blues.toOwnedSlice(self.gpa),
            .mergeset_reds = try mergeset_reds.toOwnedSlice(self.gpa),
            .blue_anticone_sizes = blues,
        });
    }

    /// Apply the k-cluster rule to candidate `k_block` against the working blue
    /// set `blues`. On success, mutates `blues` (adds k_block, bumps affected
    /// anticone sizes) and returns true.
    fn tryColorBlue(self: *Ghostdag, blues: *std.AutoHashMapUnmanaged(Hash256, u32), k_block: Hash256) Error!bool {
        // Collect the blue blocks in the candidate's anticone.
        var anticone: std.ArrayList(Hash256) = .empty;
        defer anticone.deinit(self.gpa);

        var it = blues.iterator();
        while (it.next()) |e| {
            const x = e.key_ptr.*;
            if (self.inAnticone(x, k_block)) {
                if (anticone.items.len == self.k) return false; // would exceed k for the candidate
                // If any affected blue block is already at the limit, adding
                // k_block would push its anticone over k.
                if (e.value_ptr.* == self.k) return false;
                try anticone.append(self.gpa, x);
            }
        }

        // Accept: record and bump.
        try blues.put(self.gpa, k_block, @intCast(anticone.items.len));
        for (anticone.items) |x| {
            const ptr = blues.getPtr(x).?;
            ptr.* += 1;
        }
        return true;
    }

    /// Mergeset = past(id) \ past(sp) \ {sp}, already in topological order
    /// (iterating ancestor indices ascending == a topological order).
    fn orderedMergeset(self: *Ghostdag, id: Hash256, sp: Hash256) Error![]Hash256 {
        const n = self.topo.len;
        const past_id = &self.past_bits[self.topo_index.get(id).?];
        const isp = self.topo_index.get(sp).?;
        const past_sp = &self.past_bits[isp];

        var out: std.ArrayList(Hash256) = .empty;
        errdefer out.deinit(self.gpa);
        var ai: usize = 0;
        while (ai < n) : (ai += 1) {
            if (!past_id.isSet(ai)) continue; // not in past(id)
            if (ai == isp) continue; // that's sp
            if (past_sp.isSet(ai)) continue; // in past(sp)
            try out.append(self.gpa, self.topo[ai]);
        }
        return out.toOwnedSlice(self.gpa);
    }

    // --- reachability (O(1) via the precomputed cache) ---

    /// Is `a` an ancestor of `b` (a ∈ past(b))?
    fn bitAncestor(self: *const Ghostdag, a: Hash256, b: Hash256) bool {
        const ia = self.topo_index.get(a).?;
        const ib = self.topo_index.get(b).?;
        return self.past_bits[ib].isSet(ia);
    }

    fn inAnticone(self: *const Ghostdag, x: Hash256, y: Hash256) bool {
        if (eql(x, y)) return false;
        if (self.bitAncestor(x, y)) return false;
        if (self.bitAncestor(y, x)) return false;
        return true;
    }

    // --- virtual-chain total order ---

    /// The block with the highest blue_score (tie → smaller id). This is the
    /// virtual block's selected parent — the tip of the selected chain.
    pub fn selectedTip(self: *const Ghostdag) ?Hash256 {
        var best: ?Hash256 = null;
        var best_score: u64 = 0;
        var it = self.data.iterator();
        while (it.next()) |e| {
            const id = e.key_ptr.*;
            const score = e.value_ptr.blue_score;
            if (best == null or score > best_score or (score == best_score and less(id, best.?))) {
                best = id;
                best_score = score;
            }
        }
        return best;
    }

    /// Deterministic, topologically-valid consensus order over all blocks.
    /// Caller owns the returned slice.
    pub fn order(self: *Ghostdag, gpa: std.mem.Allocator) Error![]Hash256 {
        var result: std.ArrayList(Hash256) = .empty;
        errdefer result.deinit(gpa);
        var visited: HashSet = .empty;
        defer visited.deinit(gpa);

        // Emit tips in ascending id so the whole DAG is covered deterministically.
        var tips: std.ArrayList(Hash256) = .empty;
        defer tips.deinit(gpa);
        try self.collectTips(gpa, &tips);
        std.mem.sort(Hash256, tips.items, {}, struct {
            fn lt(_: void, a: Hash256, b: Hash256) bool {
                return less(a, b);
            }
        }.lt);

        for (tips.items) |t| try self.emit(gpa, &result, &visited, t);
        return result.toOwnedSlice(gpa);
    }

    fn emit(self: *Ghostdag, gpa: std.mem.Allocator, result: *std.ArrayList(Hash256), visited: *HashSet, id: Hash256) Error!void {
        if (visited.contains(id)) return;
        const d = self.data.get(id) orelse return Error.MissingBlock;
        if (d.selected_parent) |sp| try self.emit(gpa, result, visited, sp);
        for (d.mergeset_blues) |b| try self.emit(gpa, result, visited, b);
        for (d.mergeset_reds) |r| try self.emit(gpa, result, visited, r);
        // Re-check: recursion above may have emitted `id` transitively? No —
        // id is only reachable as a descendant, never as its own ancestor.
        try visited.put(gpa, id, {});
        try result.append(gpa, id);
    }

    fn collectTips(self: *const Ghostdag, gpa: std.mem.Allocator, out: *std.ArrayList(Hash256)) Error!void {
        var has_child: HashSet = .empty;
        defer has_child.deinit(gpa);
        var it = self.dag.nodes.iterator();
        while (it.next()) |e| {
            for (e.value_ptr.*) |p| try has_child.put(gpa, p, {});
        }
        var it2 = self.dag.nodes.iterator();
        while (it2.next()) |e| {
            if (!has_child.contains(e.key_ptr.*)) try out.append(gpa, e.key_ptr.*);
        }
    }
};

fn cloneMap(gpa: std.mem.Allocator, src: std.AutoHashMapUnmanaged(Hash256, u32)) !std.AutoHashMapUnmanaged(Hash256, u32) {
    var dst: std.AutoHashMapUnmanaged(Hash256, u32) = .empty;
    errdefer dst.deinit(gpa);
    var it = src.iterator();
    while (it.next()) |e| try dst.put(gpa, e.key_ptr.*, e.value_ptr.*);
    return dst;
}

// ---------------------------------------------------------------------------
// Golden vectors
// ---------------------------------------------------------------------------

const testing = std.testing;

fn h(byte: u8) Hash256 {
    return [_]u8{byte} ** 32;
}

test "linear chain: blue scores increment, all blue, order is the chain" {
    const gpa = testing.allocator;
    var dag = Dag.init(gpa);
    defer dag.deinit();
    try dag.addBlock(h(1), &.{}); // genesis
    try dag.addBlock(h(2), &.{h(1)});
    try dag.addBlock(h(3), &.{h(2)});
    try dag.addBlock(h(4), &.{h(3)});

    var gd = Ghostdag.init(gpa, &dag, 3);
    defer gd.deinit();
    try gd.compute();

    try testing.expectEqual(@as(u64, 0), gd.get(h(1)).?.blue_score);
    try testing.expectEqual(@as(u64, 1), gd.get(h(2)).?.blue_score);
    try testing.expectEqual(@as(u64, 2), gd.get(h(3)).?.blue_score);
    try testing.expectEqual(@as(u64, 3), gd.get(h(4)).?.blue_score);
    try testing.expectEqualSlices(u8, &h(4), &gd.selectedTip().?);

    const ord = try gd.order(gpa);
    defer gpa.free(ord);
    try testing.expectEqualSlices(Hash256, &.{ h(1), h(2), h(3), h(4) }, ord);
}

test "diamond with k>=1: the merged sibling is BLUE" {
    const gpa = testing.allocator;
    var dag = Dag.init(gpa);
    defer dag.deinit();
    try dag.addBlock(h(1), &.{}); // A (genesis)
    try dag.addBlock(h(2), &.{h(1)}); // B
    try dag.addBlock(h(3), &.{h(1)}); // C  (parallel to B)
    try dag.addBlock(h(4), &.{ h(2), h(3) }); // D merges B and C

    var gd = Ghostdag.init(gpa, &dag, 1);
    defer gd.deinit();
    try gd.compute();

    // sp(D) = min(B,C) by id = B (equal blue scores). Mergeset(D) = {C}.
    const d = gd.get(h(4)).?;
    try testing.expectEqualSlices(u8, &h(2), &d.selected_parent.?);
    try testing.expect(d.isBlue(h(3))); // C colored blue
    try testing.expectEqual(@as(usize, 0), d.mergeset_reds.len);
    try testing.expectEqual(@as(u64, 3), d.blue_score); // A,B,C all blue in D's past
}

test "diamond with k=0: the merged sibling is RED (anticone exceeds k)" {
    const gpa = testing.allocator;
    var dag = Dag.init(gpa);
    defer dag.deinit();
    try dag.addBlock(h(1), &.{});
    try dag.addBlock(h(2), &.{h(1)});
    try dag.addBlock(h(3), &.{h(1)});
    try dag.addBlock(h(4), &.{ h(2), h(3) });

    var gd = Ghostdag.init(gpa, &dag, 0);
    defer gd.deinit();
    try gd.compute();

    const d = gd.get(h(4)).?;
    try testing.expect(!d.isBlue(h(3))); // C is red
    try testing.expectEqual(@as(usize, 1), d.mergeset_reds.len);
    try testing.expectEqual(@as(u64, 2), d.blue_score); // only A,B blue in D's past
}
