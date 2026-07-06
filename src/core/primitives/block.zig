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
const pow = @import("../consensus/pow.zig");
const heavyhash = @import("../consensus/heavyhash.zig");

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
    /// Compact difficulty target this block must satisfy.
    bits: u32 = pow.easy_bits,
    /// Proof-of-work nonce (varied by the miner).
    nonce: u64 = 0,

    pub fn encode(self: BlockHeader, w: *codec.Writer) !void {
        try w.writeU32(self.version);
        try w.writeU32(@intCast(self.parents.len));
        for (self.parents) |p| try w.writeHash(p);
        try w.writeU64(self.timestamp);
        try w.writeHash(self.merkle_root);
        try w.writeHash(self.witness_root);
        try w.writeU32(self.bits);
        try w.writeU64(self.nonce);
    }

    pub fn id(self: BlockHeader, gpa: std.mem.Allocator) !Hash256 {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var w = codec.Writer{ .list = &list, .gpa = gpa };
        try self.encode(&w);
        return hashmod.hash(.block_header, list.items);
    }

    pub const max_parents: u32 = 1 << 16;

    pub fn decode(r: *codec.Reader, gpa: std.mem.Allocator) !BlockHeader {
        const version = try r.readU32();
        const parent_count = try r.readU32();
        if (parent_count > max_parents) return codec.ReadError.TooLarge;
        const parents = try gpa.alloc(Hash256, parent_count);
        errdefer gpa.free(parents);
        for (parents) |*p| p.* = try r.readHash();
        const timestamp = try r.readU64();
        const merkle_root = try r.readHash();
        const witness_root = try r.readHash();
        const bits = try r.readU32();
        const nonce = try r.readU64();
        return .{
            .version = version,
            .parents = parents,
            .timestamp = timestamp,
            .merkle_root = merkle_root,
            .witness_root = witness_root,
            .bits = bits,
            .nonce = nonce,
        };
    }

    /// The 32-byte encoding of this header (the message the PoW hash grinds).
    fn encodeBytes(self: BlockHeader, gpa: std.mem.Allocator) ![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(gpa);
        var w = codec.Writer{ .list = &list, .gpa = gpa };
        try self.encode(&w);
        return list.toOwnedSlice(gpa);
    }

    /// The per-block heavy-hash matrix seed: this header with the nonce zeroed,
    /// hashed under the `.pow` domain. Fixed for the whole nonce search, so the
    /// matrix is computed once and reused across nonces.
    fn powSeed(self: BlockHeader, gpa: std.mem.Allocator) !Hash256 {
        var pre = self;
        pre.nonce = 0;
        const bytes = try pre.encodeBytes(gpa);
        defer gpa.free(bytes);
        return hashmod.hash(.pow, bytes);
    }

    /// The proof-of-work hash: the ZigChain heavy-hash of the header under the
    /// block's matrix. A separate domain from the block id, so the PoW function
    /// is swappable without touching identity hashing.
    pub fn powHash(self: BlockHeader, gpa: std.mem.Allocator) !Hash256 {
        const seed = try self.powSeed(gpa);
        const bytes = try self.encodeBytes(gpa);
        defer gpa.free(bytes);
        return heavyhash.heavyHash(seed, bytes);
    }

    /// Does this header satisfy its own difficulty target?
    pub fn validatePow(self: BlockHeader, gpa: std.mem.Allocator) !bool {
        return pow.meetsTarget(try self.powHash(gpa), self.bits);
    }

    /// Search for a nonce that satisfies `self.bits`, up to `max_iters`.
    /// Mutates `self.nonce`. Returns the number of iterations, or error on
    /// exhaustion. The matrix depends only on the nonce-free header, so it is
    /// computed once and reused — the per-nonce cost is one re-encode + one
    /// heavy-hash.
    pub fn mine(self: *BlockHeader, gpa: std.mem.Allocator, max_iters: u64) !u64 {
        const seed = try self.powSeed(gpa);
        var matrix = heavyhash.genMatrix(seed);
        var i: u64 = 0;
        while (i < max_iters) : (i += 1) {
            self.nonce = i;
            const bytes = try self.encodeBytes(gpa);
            defer gpa.free(bytes);
            if (pow.meetsTarget(heavyhash.heavyHashWithMatrix(&matrix, bytes), self.bits)) return i;
        }
        return error.PowNotFound;
    }
};

pub const Block = struct {
    header: BlockHeader,
    txs: []const Transaction,

    pub fn id(self: Block, gpa: std.mem.Allocator) !Hash256 {
        return self.header.id(gpa);
    }

    pub const max_txs: u32 = 1 << 24;

    /// Full block wire encoding: header, then each transaction (body + witnesses).
    pub fn encode(self: Block, w: *codec.Writer) !void {
        try self.header.encode(w);
        try w.writeU32(@intCast(self.txs.len));
        for (self.txs) |t| {
            try t.encodeBody(w);
            try t.encodeWitnesses(w);
        }
    }

    pub fn decode(r: *codec.Reader, gpa: std.mem.Allocator) !Block {
        const header = try BlockHeader.decode(r, gpa);
        const tx_count = try r.readU32();
        if (tx_count > max_txs) return codec.ReadError.TooLarge;
        const txs = try gpa.alloc(Transaction, tx_count);
        errdefer gpa.free(txs);
        for (txs) |*t| t.* = try Transaction.decode(r, gpa);
        return .{ .header = header, .txs = txs };
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

test "proof-of-work: mine a header, validate it, reject at higher difficulty" {
    const gpa = testing.allocator;
    var hdr = BlockHeader{
        .version = 1,
        .parents = &.{},
        .timestamp = 1,
        .merkle_root = hashmod.zero,
        .witness_root = hashmod.zero,
        .bits = pow.easy_bits,
    };
    _ = try hdr.mine(gpa, 1_000_000); // finds a satisfying nonce
    try testing.expect(try hdr.validatePow(gpa));

    // At a far harder target the same header almost certainly fails.
    hdr.bits = 0x1c00ffff; // target ~2^216, ~2^-40 pass probability
    try testing.expect(!try hdr.validatePow(gpa));
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

test "block wire codec round-trips (header + txs + witnesses)" {
    const gpa = testing.allocator;
    const tx_mod2 = @import("types.zig");

    const h0 = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };
    const cb = tx_mod2.Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{.{ .value = 50, .scheme = .ml_dsa_44, .commitment = [_]u8{7} ** 32 }},
        .witnesses = &.{},
        .payload = &h0,
    };
    const spend = tx_mod2.Transaction{
        .version = 2,
        .inputs = &.{.{ .outpoint = .{ .txid = [_]u8{9} ** 32, .index = 3 } }},
        .outputs = &.{.{ .value = 40, .scheme = .ml_dsa_44, .commitment = [_]u8{8} ** 32 }},
        .witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = "abc", .signature = "defg" }},
    };
    const original = Block{
        .header = .{
            .version = 1,
            .parents = &.{ [_]u8{0xA1} ** 32, [_]u8{0xB2} ** 32 },
            .timestamp = 1_700_000_123,
            .merkle_root = [_]u8{0xCC} ** 32,
            .witness_root = [_]u8{0xDD} ** 32,
            .bits = 0x2000ffff,
            .nonce = 42,
        },
        .txs = &.{ cb, spend },
    };

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try original.encode(&w);

    var r = codec.Reader{ .buf = list.items };
    const decoded = try Block.decode(&r, gpa);
    defer {
        gpa.free(decoded.header.parents);
        for (decoded.txs) |t| {
            gpa.free(t.inputs);
            gpa.free(t.outputs);
            gpa.free(t.witnesses);
        }
        gpa.free(decoded.txs);
    }
    try r.finish();

    // The decoded block is identical — proven by matching ids and structure.
    try testing.expectEqualSlices(u8, &(try original.id(gpa)), &(try decoded.id(gpa)));
    try testing.expectEqual(@as(usize, 2), decoded.txs.len);
    try testing.expectEqual(@as(u64, 40), decoded.txs[1].outputs[0].value);
    try testing.expectEqualStrings("abc", decoded.txs[1].witnesses[0].pubkey);
    try testing.expectEqual(@as(u64, 42), decoded.header.nonce);
}
