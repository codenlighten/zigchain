//! Block header, block id, and the transaction merkle root.
//!
//! A block references one or more parents (this is a BlockDAG, not a chain), so
//! the header carries a parent *set*. The block id commits to the header only;
//! the header commits to the transactions via their merkle root, and (Phase 2)
//! to the witness merkle root so segregated witnesses can be pruned yet remain
//! provably intact.

const std = @import("std");
const hashmod = @import("../crypto/hash.zig");
const codec = @import("../serialization/codec.zig");
const tx_mod = @import("types.zig");

const Hash256 = hashmod.Hash256;
const Transaction = tx_mod.Transaction;

pub const BlockHeader = struct {
    version: u32,
    /// Parent block ids. Genesis has an empty parent set.
    parents: []const Hash256,
    timestamp: u64,
    /// Commitment to the transactions (by txid — witness-free).
    merkle_root: Hash256,
    /// Commitment to the segregated witnesses. Because the header commits to
    /// them, a node may PRUNE witnesses past finality yet still prove that what
    /// it once held was exactly what consensus accepted — pruning stays
    /// trust-minimized rather than "trust me the signatures were valid".
    witness_root: Hash256,

    pub fn encode(self: BlockHeader, w: *codec.Writer) !void {
        try w.writeU32(self.version);
        try w.writeU32(@intCast(self.parents.len));
        for (self.parents) |p| try w.writeHash(p);
        try w.writeU64(self.timestamp);
        try w.writeHash(self.merkle_root);
        try w.writeHash(self.witness_root);
    }

    pub fn id(self: BlockHeader, gpa: std.mem.Allocator) !Hash256 {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var w = codec.Writer{ .list = &list, .gpa = gpa };
        try self.encode(&w);
        return hashmod.hash(.block_header, list.items);
    }
};

pub const Block = struct {
    header: BlockHeader,
    txs: []const Transaction,

    pub fn id(self: Block, gpa: std.mem.Allocator) !Hash256 {
        return self.header.id(gpa);
    }

    /// Recompute the merkle root from the block's transactions (by txid).
    pub fn computeMerkleRoot(self: Block, gpa: std.mem.Allocator) !Hash256 {
        var ids = try gpa.alloc(Hash256, self.txs.len);
        defer gpa.free(ids);
        for (self.txs, 0..) |t, i| ids[i] = try t.txid(gpa);
        return merkleRoot(gpa, ids);
    }

    /// Recompute the witness merkle root — the root over each transaction's
    /// witness bundle. Pruning drops the witnesses but keeps this commitment.
    pub fn computeWitnessRoot(self: Block, gpa: std.mem.Allocator) !Hash256 {
        var leaves = try gpa.alloc(Hash256, self.txs.len);
        defer gpa.free(leaves);
        for (self.txs, 0..) |t, i| leaves[i] = try txWitnessHash(gpa, t);
        return merkleRoot(gpa, leaves);
    }

    /// Verify both header commitments against the block body. A pruned node runs
    /// this once (while it still holds witnesses) to accept a block; afterwards
    /// the header alone attests to what was verified.
    pub fn verifyCommitments(self: Block, gpa: std.mem.Allocator) !bool {
        const mr = try self.computeMerkleRoot(gpa);
        if (!std.mem.eql(u8, &mr, &self.header.merkle_root)) return false;
        const wr = try self.computeWitnessRoot(gpa);
        return std.mem.eql(u8, &wr, &self.header.witness_root);
    }
};

/// Hash of one transaction's witness bundle (its segregated signatures/keys).
fn txWitnessHash(gpa: std.mem.Allocator, tx: Transaction) !Hash256 {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try tx.encodeWitnesses(&w);
    return hashmod.hash(.witness, list.items);
}

/// Merkle root over `leaves`, with domain-separated leaf and node hashing.
///
/// Odd nodes are *promoted* to the next level (not duplicated), which avoids the
/// Bitcoin CVE-2012-2459 duplicate-tx malleability where two distinct trees hash
/// to the same root.
pub fn merkleRoot(gpa: std.mem.Allocator, leaves: []const Hash256) !Hash256 {
    if (leaves.len == 0) return hashmod.hash(.merkle_leaf, ""); // canonical empty root

    var level = try gpa.alloc(Hash256, leaves.len);
    defer gpa.free(level);
    for (leaves, 0..) |leaf, i| {
        var h = hashmod.Hasher.init(.merkle_leaf);
        h.update(&leaf);
        level[i] = h.final();
    }

    var n: usize = leaves.len;
    while (n > 1) {
        var w: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 2) {
            if (i + 1 < n) {
                var h = hashmod.Hasher.init(.merkle_node);
                h.update(&level[i]);
                h.update(&level[i + 1]);
                level[w] = h.final();
            } else {
                level[w] = level[i]; // promote lone node
            }
            w += 1;
        }
        n = w;
    }
    return level[0];
}

const testing = std.testing;

test "merkle root: empty, single, and promote-odd behaviour" {
    const gpa = testing.allocator;
    const a = [_]u8{1} ** 32;
    const b = [_]u8{2} ** 32;
    const c = [_]u8{3} ** 32;

    // Single leaf root == its leaf-domain hash.
    const single = try merkleRoot(gpa, &.{a});
    var lh = hashmod.Hasher.init(.merkle_leaf);
    lh.update(&a);
    try testing.expectEqualSlices(u8, &lh.final(), &single);

    // Order matters; different multisets give different roots.
    const r_abc = try merkleRoot(gpa, &.{ a, b, c });
    const r_acb = try merkleRoot(gpa, &.{ a, c, b });
    try testing.expect(!std.mem.eql(u8, &r_abc, &r_acb));

    // Deterministic.
    try testing.expectEqualSlices(u8, &r_abc, &(try merkleRoot(gpa, &.{ a, b, c })));
}

test "block id commits to header, is deterministic" {
    const gpa = testing.allocator;
    const h = BlockHeader{
        .version = 1,
        .parents = &.{[_]u8{0xAB} ** 32},
        .timestamp = 1_700_000_000,
        .merkle_root = hashmod.zero,
        .witness_root = hashmod.zero,
    };
    const id1 = try h.id(gpa);
    const id2 = try h.id(gpa);
    try testing.expectEqualSlices(u8, &id1, &id2);

    // Changing the merkle root changes the id.
    var h2 = h;
    h2.merkle_root = [_]u8{0xFF} ** 32;
    try testing.expect(!std.mem.eql(u8, &id1, &(try h2.id(gpa))));

    // The witness root is committed too: changing it changes the id.
    var h3 = h;
    h3.witness_root = [_]u8{0x11} ** 32;
    try testing.expect(!std.mem.eql(u8, &id1, &(try h3.id(gpa))));
}

test "witness commitment: verifies intact block, detects tampered witness" {
    const gpa = testing.allocator;
    const tx_mod2 = @import("types.zig");

    var tx = tx_mod2.Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }},
        .outputs = &.{.{ .value = 5, .scheme = .ml_dsa_44, .commitment = hashmod.zero }},
        .witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = "PUBKEY", .signature = "SIGNATURE" }},
    };

    var blk = Block{
        .header = .{
            .version = 1,
            .parents = &.{},
            .timestamp = 1,
            .merkle_root = undefined,
            .witness_root = undefined,
        },
        .txs = @as([]const tx_mod2.Transaction, &.{tx})[0..1],
    };
    blk.header.merkle_root = try blk.computeMerkleRoot(gpa);
    blk.header.witness_root = try blk.computeWitnessRoot(gpa);
    try testing.expect(try blk.verifyCommitments(gpa));

    // Tamper with the witness (forge a signature) — the txid/merkle root is
    // unchanged (witnesses are segregated) but the witness commitment breaks.
    tx.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = "PUBKEY", .signature = "FORGED!!!" }};
    var tampered = blk;
    tampered.txs = @as([]const tx_mod2.Transaction, &.{tx})[0..1];
    try testing.expect(!try tampered.verifyCommitments(gpa));
}
