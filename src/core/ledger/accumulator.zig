//! Utreexo-style hash accumulator — the state-scalability lever.
//!
//! The UTXO set is represented as a forest of perfect Merkle binary trees, one
//! per set bit in the leaf count (a binary counter). The whole set is committed
//! to by just its ROOTS — a handful of 32-byte hashes regardless of how many
//! coins exist. A *stateless* node stores only those roots; to spend a coin it
//! is handed an inclusion proof, and `verify` checks it against the roots alone.
//! That is what lets state scale to billions of UTXOs without every node holding
//! all of them — the honest path to global-settlement state sizes.
//!
//! `Forest` is the bridge node: it stores the full structure and can generate
//! proofs, add, and delete. `verify` is the stateless check.
//!
//! Deletion uses the clean identity: removing one leaf from a perfect tree of
//! height h leaves exactly the h sibling subtrees along its path — perfect trees
//! of heights 0..h-1 — which are re-absorbed into the forest. No leaf moves that
//! isn't on the deleted path, so all other proofs regenerate correctly.

const std = @import("std");
const hashmod = @import("../crypto/hash.zig");

const Hash256 = hashmod.Hash256;

pub const max_height = 64;

pub const ProofStep = struct {
    hash: Hash256,
    /// True if the sibling is the LEFT child (so the proven node is the right).
    sibling_is_left: bool,
};

fn parentHash(l: Hash256, r: Hash256) Hash256 {
    var h = hashmod.Hasher.init(.accumulator);
    h.update(&l);
    h.update(&r);
    return h.final();
}

/// Stateless membership check: fold `leaf` with its proof and confirm the
/// resulting root is among the accumulator `roots`. Needs no state but the roots.
pub fn verify(roots: []const Hash256, leaf: Hash256, proof: []const ProofStep) bool {
    var h = leaf;
    for (proof) |step| {
        h = if (step.sibling_is_left) parentHash(step.hash, h) else parentHash(h, step.hash);
    }
    for (roots) |r| {
        if (std.mem.eql(u8, &r, &h)) return true;
    }
    return false;
}

const Node = struct {
    hash: Hash256,
    parent: ?*Node = null,
    left: ?*Node = null,
    right: ?*Node = null,
    height: u8 = 0,
};

pub const Forest = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    roots: [max_height]?*Node = [_]?*Node{null} ** max_height,
    leaves: std.AutoHashMapUnmanaged(Hash256, *Node) = .empty,
    num_leaves: u64 = 0,

    pub fn init(gpa: std.mem.Allocator) Forest {
        return .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
    }

    pub fn deinit(self: *Forest) void {
        self.leaves.deinit(self.gpa);
        self.arena.deinit();
    }

    fn newNode(self: *Forest, n: Node) *Node {
        const p = self.arena.allocator().create(Node) catch unreachable;
        p.* = n;
        return p;
    }

    /// Merge `node` (a perfect subtree at its height) upward into the forest,
    /// maintaining at most one tree per height.
    fn mergeUp(self: *Forest, node_in: *Node) void {
        var node = node_in;
        var height = node.height;
        while (self.roots[height]) |left| {
            self.roots[height] = null;
            const parent = self.newNode(.{
                .hash = parentHash(left.hash, node.hash),
                .height = height + 1,
                .left = left,
                .right = node,
            });
            left.parent = parent;
            node.parent = parent;
            node = parent;
            height += 1;
        }
        self.roots[height] = node;
    }

    pub fn add(self: *Forest, leaf: Hash256) !void {
        const node = self.newNode(.{ .hash = leaf, .height = 0 });
        try self.leaves.put(self.gpa, leaf, node);
        self.mergeUp(node);
        self.num_leaves += 1;
    }

    pub fn contains(self: *const Forest, leaf: Hash256) bool {
        return self.leaves.contains(leaf);
    }

    /// Generate an inclusion proof for `leaf`, or null if absent. Caller owns it.
    pub fn prove(self: *const Forest, gpa: std.mem.Allocator, leaf: Hash256) !?[]ProofStep {
        const start = self.leaves.get(leaf) orelse return null;
        var steps: std.ArrayList(ProofStep) = .empty;
        errdefer steps.deinit(gpa);
        var node = start;
        while (node.parent) |p| {
            const sibling_is_left = (p.left.? != node);
            const sib = if (sibling_is_left) p.left.? else p.right.?;
            try steps.append(gpa, .{ .hash = sib.hash, .sibling_is_left = sibling_is_left });
            node = p;
        }
        return try steps.toOwnedSlice(gpa);
    }

    pub const DeleteError = error{NotFound} || std.mem.Allocator.Error;

    pub fn delete(self: *Forest, leaf: Hash256) DeleteError!void {
        const start = self.leaves.get(leaf) orelse return DeleteError.NotFound;
        _ = self.leaves.remove(leaf);

        // The sibling subtrees along the path become new roots.
        var detached: std.ArrayList(*Node) = .empty;
        defer detached.deinit(self.gpa);
        var node = start;
        while (node.parent) |p| {
            const sib = if (p.left.? == node) p.right.? else p.left.?;
            try detached.append(self.gpa, sib);
            node = p;
        }
        // `node` is the tree root; the whole tree leaves the forest.
        self.roots[node.height] = null;
        // Re-absorb the sibling subtrees (heights 0,1,...) back into the forest.
        for (detached.items) |sub| {
            sub.parent = null;
            self.mergeUp(sub);
        }
        self.num_leaves -= 1;
    }

    /// The current accumulator roots (what a stateless node stores). Caller owns.
    pub fn rootHashes(self: *const Forest, gpa: std.mem.Allocator) ![]Hash256 {
        var out: std.ArrayList(Hash256) = .empty;
        errdefer out.deinit(gpa);
        for (self.roots) |maybe| {
            if (maybe) |r| try out.append(gpa, r.hash);
        }
        return out.toOwnedSlice(gpa);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn leafOf(i: u32) Hash256 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, i, .little);
    return hashmod.hash(.txid, &b);
}

test "add: every leaf proves against the roots; non-members do not" {
    const gpa = testing.allocator;
    var f = Forest.init(gpa);
    defer f.deinit();

    for (0..7) |i| try f.add(leafOf(@intCast(i)));
    const roots = try f.rootHashes(gpa);
    defer gpa.free(roots);
    try testing.expectEqual(@as(usize, 3), roots.len); // popcount(7) = 3 trees

    for (0..7) |i| {
        const proof = (try f.prove(gpa, leafOf(@intCast(i)))).?;
        defer gpa.free(proof);
        try testing.expect(verify(roots, leafOf(@intCast(i)), proof));
    }

    // A leaf that was never added has no proof and cannot be forged with another's.
    try testing.expect((try f.prove(gpa, leafOf(999))) == null);
    const p0 = (try f.prove(gpa, leafOf(0))).?;
    defer gpa.free(p0);
    try testing.expect(!verify(roots, leafOf(999), p0));
}

test "delete: removed leaf is gone, survivors still prove against new roots" {
    const gpa = testing.allocator;
    var f = Forest.init(gpa);
    defer f.deinit();

    for (0..8) |i| try f.add(leafOf(@intCast(i)));
    try f.delete(leafOf(3));
    try testing.expect(!f.contains(leafOf(3)));
    try testing.expectEqual(@as(u64, 7), f.num_leaves);

    const roots = try f.rootHashes(gpa);
    defer gpa.free(roots);

    // The deleted leaf can no longer be proven.
    try testing.expect((try f.prove(gpa, leafOf(3))) == null);

    // Every survivor still has a valid proof against the updated roots.
    for (0..8) |i| {
        if (i == 3) continue;
        const proof = (try f.prove(gpa, leafOf(@intCast(i)))).?;
        defer gpa.free(proof);
        try testing.expect(verify(roots, leafOf(@intCast(i)), proof));
    }
}

test "property: random add/delete keeps all live leaves provable" {
    const gpa = testing.allocator;
    var seed: u64 = 0;
    while (seed < 40) : (seed += 1) {
        var prng = std.Random.DefaultPrng.init(seed);
        const rng = prng.random();

        var f = Forest.init(gpa);
        defer f.deinit();
        var live: std.ArrayList(u32) = .empty;
        defer live.deinit(gpa);
        var next: u32 = 0;

        for (0..60) |_| {
            const add = live.items.len == 0 or rng.boolean();
            if (add) {
                try f.add(leafOf(next));
                try live.append(gpa, next);
                next += 1;
            } else {
                const idx = rng.intRangeLessThan(usize, 0, live.items.len);
                const victim = live.swapRemove(idx);
                try f.delete(leafOf(victim));
            }

            // Invariants: root count == popcount(size); every live leaf proves.
            try testing.expectEqual(@as(u64, @intCast(live.items.len)), f.num_leaves);
            const roots = try f.rootHashes(gpa);
            defer gpa.free(roots);
            try testing.expectEqual(@popCount(f.num_leaves), roots.len);
            for (live.items) |v| {
                const proof = (try f.prove(gpa, leafOf(v))).?;
                defer gpa.free(proof);
                try testing.expect(verify(roots, leafOf(v), proof));
            }
        }
    }
}
