//! The chain engine — the block-acceptance pipeline that ties the subsystems
//! into an actual node.
//!
//! A block is accepted only if:
//!   1. its proof-of-work satisfies its stated difficulty,
//!   2. its stated difficulty equals what the DAA expects from its parents,
//!   3. it passes context-free validation (coinbase, commitments, mass, subsidy)
//!      at its computed DAG height,
//! after which it joins the DAG, the GHOSTDAG coloring is recomputed, and the
//! UTXO state can be re-derived from the new consensus order.
//!
//! This first engine recolors and re-derives from scratch on each accept —
//! O(n), correctness-first. Incremental coloring + an incremental UTXO with
//! reorg handling is the planned optimization; the differential harness and the
//! recompute-from-genesis path are the oracle it must match.

const std = @import("std");
const blk = @import("../primitives/block.zig");
const prim = @import("../primitives/types.zig");
const pow = @import("pow.zig");
const dag_mod = @import("dag.zig");
const ghostdag = @import("ghostdag.zig");
const block_validation = @import("../ledger/block_validation.zig");
const utxo = @import("../ledger/utxo.zig");
const processor = @import("processor.zig");
const hashmod = @import("../crypto/hash.zig");

const Hash256 = hashmod.Hash256;
const Block = blk.Block;
const Dag = dag_mod.Dag;
const Ghostdag = ghostdag.Ghostdag;

pub const Config = struct {
    genesis_bits: u32 = pow.easy_bits,
    subsidy: u64 = 50,
    max_block_mass: u64 = 1_000_000,
    target_block_ms: u64 = 1000,
    daa_window: u32 = 10,
    ghostdag_k: u32 = 8,
};

const validation = @import("../ledger/validation.zig");

pub const Error = error{
    DuplicateBlock,
    UnknownParent,
    InvalidPow,
    WrongDifficulty,
} || block_validation.Error || dag_mod.Error || ghostdag.Error ||
    validation.Error || utxo.Error || std.mem.Allocator.Error;

pub const Chain = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    dag: Dag,
    /// Borrows block contents — the caller must keep accepted blocks alive
    /// (an arena covering the chain's lifetime is ideal).
    blocks: std.AutoHashMapUnmanaged(Hash256, Block) = .empty,
    heights: std.AutoHashMapUnmanaged(Hash256, u64) = .empty,
    gd: ?Ghostdag = null,

    pub fn init(gpa: std.mem.Allocator, cfg: Config) Chain {
        return .{ .gpa = gpa, .cfg = cfg, .dag = Dag.init(gpa) };
    }

    pub fn deinit(self: *Chain) void {
        if (self.gd) |*g| g.deinit();
        self.blocks.deinit(self.gpa);
        self.heights.deinit(self.gpa);
        self.dag.deinit();
    }

    fn selectedParentOf(self: *const Chain, parents: []const Hash256) Hash256 {
        var sp = parents[0];
        var sp_score = self.gd.?.get(sp).?.blue_score;
        for (parents[1..]) |p| {
            const s = self.gd.?.get(p).?.blue_score;
            if (s > sp_score or (s == sp_score and std.mem.order(u8, &p, &sp) == .lt)) {
                sp = p;
                sp_score = s;
            }
        }
        return sp;
    }

    /// DAG height of a block with these parents = selected-parent height + 1.
    pub fn heightOf(self: *const Chain, parents: []const Hash256) u64 {
        if (parents.len == 0) return 0;
        return self.heights.get(self.selectedParentOf(parents)).? + 1;
    }

    /// The difficulty a block with these parents must use, per the DAA.
    pub fn expectedBits(self: *const Chain, parents: []const Hash256) u32 {
        if (parents.len == 0) return self.cfg.genesis_bits;
        const sp = self.selectedParentOf(parents);
        const sp_hdr = self.blocks.get(sp).?.header;

        // Walk the selected chain back `daa_window` steps.
        var cur = sp;
        var steps: u32 = 0;
        while (steps < self.cfg.daa_window) : (steps += 1) {
            const d = self.gd.?.get(cur).?;
            cur = d.selected_parent orelse break;
        }
        if (steps < self.cfg.daa_window) return sp_hdr.bits; // not enough history yet

        const oldest_ts = self.blocks.get(cur).?.header.timestamp;
        const actual = sp_hdr.timestamp -| oldest_ts;
        const expected = self.cfg.target_block_ms * self.cfg.daa_window;
        return pow.retarget(sp_hdr.bits, actual, expected);
    }

    /// Validate and accept a block. Returns its id.
    pub fn acceptBlock(self: *Chain, block: Block) Error!Hash256 {
        const id = try block.header.id(self.gpa);
        if (self.blocks.contains(id)) return Error.DuplicateBlock;
        for (block.header.parents) |p| {
            if (!self.dag.contains(p)) return Error.UnknownParent;
        }

        // 1. Proof of work.
        if (!try block.header.validatePow(self.gpa)) return Error.InvalidPow;

        // 2. Difficulty matches the DAA expectation.
        if (block.header.bits != self.expectedBits(block.header.parents)) return Error.WrongDifficulty;

        // 3. Context-free validation at the computed height.
        const block_height = self.heightOf(block.header.parents);
        try block_validation.validateStateless(self.gpa, block, .{
            .subsidy = self.cfg.subsidy,
            .max_block_mass = self.cfg.max_block_mass,
            .height = block_height,
        });

        // Commit: DAG + metadata, then recolor.
        try self.dag.addBlock(id, block.header.parents);
        try self.blocks.put(self.gpa, id, block);
        try self.heights.put(self.gpa, id, block_height);
        try self.recolor();
        return id;
    }

    fn recolor(self: *Chain) Error!void {
        if (self.gd) |*g| g.deinit();
        self.gd = Ghostdag.init(self.gpa, &self.dag, self.cfg.ghostdag_k);
        try self.gd.?.compute();
    }

    pub fn tip(self: *const Chain) ?Hash256 {
        return (self.gd orelse return null).selectedTip();
    }

    pub fn height(self: *const Chain, id: Hash256) ?u64 {
        return self.heights.get(id);
    }

    /// Re-derive the UTXO state from the current consensus order. Caller owns
    /// the returned set.
    pub fn utxoSet(self: *Chain) Error!utxo.UtxoSet {
        var items: std.ArrayList(processor.BlockTxs) = .empty;
        defer items.deinit(self.gpa);
        var it = self.blocks.iterator();
        while (it.next()) |e| {
            try items.append(self.gpa, .{ .id = e.key_ptr.*, .txs = e.value_ptr.txs });
        }
        var set: utxo.UtxoSet = .{};
        errdefer set.deinit(self.gpa);
        _ = try processor.applyOrder(self.gpa, &set, &self.gd.?, items.items);
        return set;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Mine a block that the chain will accept: correct parents, DAA difficulty,
/// coinbase carrying the right height, and a valid nonce.
fn mineBlock(
    arena: std.mem.Allocator,
    chain: *Chain,
    parents: []const Hash256,
    timestamp: u64,
    extra_txs: []const prim.Transaction,
    cb_commitment: Hash256,
) !Block {
    const height = chain.heightOf(parents);
    const payload = arena.alloc(u8, 8) catch unreachable;
    std.mem.writeInt(u64, payload[0..8], height, .little);

    const cb = prim.Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = arena.dupe(prim.Output, &.{.{ .value = chain.cfg.subsidy, .scheme = .ml_dsa_44, .commitment = cb_commitment }}) catch unreachable,
        .witnesses = &.{},
        .payload = payload,
    };
    var txs: std.ArrayList(prim.Transaction) = .empty;
    try txs.append(arena, cb);
    try txs.appendSlice(arena, extra_txs);
    const txs_slice = try txs.toOwnedSlice(arena);

    var hdr = blk.BlockHeader{
        .version = 1,
        .parents = arena.dupe(Hash256, parents) catch unreachable,
        .timestamp = timestamp,
        .merkle_root = hashmod.zero,
        .witness_root = hashmod.zero,
        .bits = chain.expectedBits(parents),
    };
    const body = Block{ .header = hdr, .txs = txs_slice };
    hdr.merkle_root = try body.computeMerkleRoot(arena);
    hdr.witness_root = try body.computeWitnessRoot(arena);
    _ = try hdr.mine(arena, 10_000_000);
    return Block{ .header = hdr, .txs = txs_slice };
}

test "chain accepts mined blocks; height and tip advance" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var chain = Chain.init(testing.allocator, .{});
    defer chain.deinit();

    const genesis = try mineBlock(arena, &chain, &.{}, 1000, &.{}, hashmod.zero);
    const g_id = try chain.acceptBlock(genesis);
    try testing.expectEqual(@as(u64, 0), chain.height(g_id).?);

    var prev = g_id;
    var ts: u64 = 2000;
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const b = try mineBlock(arena, &chain, &.{prev}, ts, &.{}, hashmod.zero);
        prev = try chain.acceptBlock(b);
        ts += 1000;
    }
    try testing.expectEqual(@as(u64, 5), chain.height(prev).?);
    try testing.expectEqualSlices(u8, &prev, &chain.tip().?);

    // Six coinbases minted 50 each.
    var set = try chain.utxoSet();
    defer set.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 6), set.count());
}

test "chain rejects a block without valid proof-of-work" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var chain = Chain.init(testing.allocator, .{});
    defer chain.deinit();
    const genesis = try mineBlock(arena, &chain, &.{}, 1000, &.{}, hashmod.zero);
    _ = try chain.acceptBlock(genesis);

    // Build a child but wreck its nonce so PoW fails.
    var bad = try mineBlock(arena, &chain, &.{try genesis.header.id(arena)}, 2000, &.{}, hashmod.zero);
    // Set the difficulty to the hardest possible so no nonce we have satisfies it.
    bad.header.bits = 0x03000001; // target = 1: essentially unsatisfiable
    try testing.expect(!try bad.header.validatePow(arena));
    // (expectedBits won't match either, but PoW is checked first.)
    try testing.expectError(Error.InvalidPow, chain.acceptBlock(bad));
}

test "chain rejects a block whose difficulty does not match the DAA" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var chain = Chain.init(testing.allocator, .{});
    defer chain.deinit();
    const genesis = try mineBlock(arena, &chain, &.{}, 1000, &.{}, hashmod.zero);
    const g_id = try chain.acceptBlock(genesis);

    // Mine a child at the wrong (easier-encoded but non-expected) difficulty.
    const height = chain.heightOf(&.{g_id});
    const payload = arena.alloc(u8, 8) catch unreachable;
    std.mem.writeInt(u64, payload[0..8], height, .little);
    const cb = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = arena.dupe(prim.Output, &.{.{ .value = 50, .scheme = .ml_dsa_44, .commitment = hashmod.zero }}) catch unreachable, .witnesses = &.{}, .payload = payload };
    var hdr = blk.BlockHeader{ .version = 1, .parents = arena.dupe(Hash256, &.{g_id}) catch unreachable, .timestamp = 2000, .merkle_root = hashmod.zero, .witness_root = hashmod.zero, .bits = 0x2100ffff }; // easier than genesis, so != expected but trivially mineable
    const body = Block{ .header = hdr, .txs = arena.dupe(prim.Transaction, &.{cb}) catch unreachable };
    hdr.merkle_root = try body.computeMerkleRoot(arena);
    hdr.witness_root = try body.computeWitnessRoot(arena);
    _ = try hdr.mine(arena, 10_000_000);
    const wrong = Block{ .header = hdr, .txs = body.txs };
    try testing.expectError(Error.WrongDifficulty, chain.acceptBlock(wrong));
}

test "chain rejects a coinbase with the wrong height" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var chain = Chain.init(testing.allocator, .{});
    defer chain.deinit();
    const genesis = try mineBlock(arena, &chain, &.{}, 1000, &.{}, hashmod.zero);
    const g_id = try chain.acceptBlock(genesis);

    // Coinbase claims height 9 instead of 1.
    const payload = arena.alloc(u8, 8) catch unreachable;
    std.mem.writeInt(u64, payload[0..8], 9, .little);
    const cb = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = arena.dupe(prim.Output, &.{.{ .value = 50, .scheme = .ml_dsa_44, .commitment = hashmod.zero }}) catch unreachable, .witnesses = &.{}, .payload = payload };
    var hdr = blk.BlockHeader{ .version = 1, .parents = arena.dupe(Hash256, &.{g_id}) catch unreachable, .timestamp = 2000, .merkle_root = hashmod.zero, .witness_root = hashmod.zero, .bits = chain.expectedBits(&.{g_id}) };
    const body = Block{ .header = hdr, .txs = arena.dupe(prim.Transaction, &.{cb}) catch unreachable };
    hdr.merkle_root = try body.computeMerkleRoot(arena);
    hdr.witness_root = try body.computeWitnessRoot(arena);
    _ = try hdr.mine(arena, 10_000_000);
    const wrong = Block{ .header = hdr, .txs = body.txs };
    try testing.expectError(block_validation.Error.BadCoinbaseHeight, chain.acceptBlock(wrong));
}

test "difficulty adjusts: fast blocks raise difficulty past the window" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // target_block_ms=1000, window=4 for a short test.
    var chain = Chain.init(testing.allocator, .{ .daa_window = 4, .target_block_ms = 1000 });
    defer chain.deinit();

    var prev = try chain.acceptBlock(try mineBlock(arena, &chain, &.{}, 0, &.{}, hashmod.zero));
    const genesis_bits = chain.cfg.genesis_bits;

    // Fill the window with blocks arriving every 100ms — 10x faster than the
    // 1000ms target. These are all still mined at genesis difficulty (the DAA
    // only kicks in once the window is full), keeping the test cheap.
    var ts: u64 = 0;
    var i: u32 = 0;
    while (i < chain.cfg.daa_window) : (i += 1) {
        ts += 100;
        prev = try chain.acceptBlock(try mineBlock(arena, &chain, &.{prev}, ts, &.{}, hashmod.zero));
    }
    // With the window now full of fast blocks, the DAA demands harder difficulty.
    const now_bits = chain.expectedBits(&.{prev});
    try testing.expect(pow.compactToTarget(now_bits) < pow.compactToTarget(genesis_bits));
}
