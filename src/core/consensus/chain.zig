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
const acc = @import("../ledger/accumulator.zig");
const ledger_state = @import("ledger_state.zig");
const hashmod = @import("../crypto/hash.zig");

const Hash256 = hashmod.Hash256;
const OutPoint = prim.OutPoint;
const Output = prim.Output;
const Block = blk.Block;
const Dag = dag_mod.Dag;
const Ghostdag = ghostdag.Ghostdag;

/// The accumulator leaf committing to one unspent coin (outpoint + output).
/// Fixed 77-byte encoding, so no allocation.
pub fn utxoLeaf(op: OutPoint, out: Output) Hash256 {
    var buf: [77]u8 = undefined;
    @memcpy(buf[0..32], &op.txid);
    std.mem.writeInt(u32, buf[32..36], op.index, .little);
    std.mem.writeInt(u64, buf[36..44], out.value, .little);
    buf[44] = @intFromEnum(out.scheme);
    @memcpy(buf[45..77], &out.commitment);
    return hashmod.hash(.utxo, &buf);
}

const Coin = struct { op: OutPoint, out: Output };
fn lessCoin(_: void, a: Coin, b: Coin) bool {
    const ord = std.mem.order(u8, &a.op.txid, &b.op.txid);
    if (ord != .eq) return ord == .lt;
    return a.op.index < b.op.index;
}

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
    /// Incrementally-maintained, reorg-aware UTXO state.
    led: ledger_state.IncrementalUtxo,
    txmap: ledger_state.BlockTxMap = .empty,

    pub fn init(gpa: std.mem.Allocator, cfg: Config) Chain {
        return .{ .gpa = gpa, .cfg = cfg, .dag = Dag.init(gpa), .led = ledger_state.IncrementalUtxo.init(gpa) };
    }

    pub fn deinit(self: *Chain) void {
        if (self.gd) |*g| g.deinit();
        self.blocks.deinit(self.gpa);
        self.heights.deinit(self.gpa);
        self.led.deinit();
        self.txmap.deinit(self.gpa);
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

        // Commit: DAG + metadata, then color just this block.
        try self.dag.addBlock(id, block.header.parents);
        try self.blocks.put(self.gpa, id, block);
        try self.heights.put(self.gpa, id, block_height);
        try self.colorNewBlock(id);

        // Incrementally bring the UTXO state in line with the new consensus
        // order (handles reorgs via undo data — see ledger_state.zig).
        try self.txmap.put(self.gpa, id, block.txs);
        const order = try self.gd.?.order(self.gpa);
        defer self.gpa.free(order);
        try self.led.update(order, &self.txmap);
        return id;
    }

    /// Incrementally color the newly-accepted block, reusing all prior coloring
    /// — the GHOSTDAG data of existing blocks is immutable, so nothing is
    /// recomputed. (The engine previously rebuilt the entire coloring on every
    /// accept, which was O(n) reachability + recolor-all per block.)
    fn colorNewBlock(self: *Chain, id: Hash256) Error!void {
        if (self.gd == null) self.gd = Ghostdag.init(self.gpa, &self.dag, self.cfg.ghostdag_k);
        try self.gd.?.addBlock(id);
    }

    pub fn tip(self: *const Chain) ?Hash256 {
        return (self.gd orelse return null).selectedTip();
    }

    pub fn height(self: *const Chain, id: Hash256) ?u64 {
        return self.heights.get(id);
    }

    /// A copy of the current UTXO state. Caller owns the returned set. (The
    /// authoritative state is maintained incrementally in `self.led`.)
    pub fn utxoSet(self: *Chain) Error!utxo.UtxoSet {
        var set: utxo.UtxoSet = .{};
        errdefer set.deinit(self.gpa);
        var it = self.led.set.map.iterator();
        while (it.next()) |e| try set.add(self.gpa, e.key_ptr.*, e.value_ptr.*);
        return set;
    }

    /// Build the UTXO accumulator (a Utreexo forest) over the current committed
    /// state. Coins are inserted in canonical outpoint order so the resulting
    /// roots — and hence the commitment — are deterministic. Caller deinits.
    pub fn buildAccumulator(self: *Chain) Error!acc.Forest {
        var coins: std.ArrayList(Coin) = .empty;
        defer coins.deinit(self.gpa);
        var it = self.led.set.map.iterator();
        while (it.next()) |e| try coins.append(self.gpa, .{ .op = e.key_ptr.*, .out = e.value_ptr.* });
        std.mem.sort(Coin, coins.items, {}, lessCoin);

        var f = acc.Forest.init(self.gpa);
        errdefer f.deinit();
        for (coins.items) |c| try f.add(utxoLeaf(c.op, c.out));
        return f;
    }

    /// A single hash committing to the entire UTXO state (over the accumulator
    /// roots). This is what a block header would commit to, and what a stateless
    /// node checks proofs against. Deterministic for a given DAG.
    pub fn utxoCommitment(self: *Chain) Error!Hash256 {
        var f = try self.buildAccumulator();
        defer f.deinit();
        const roots = try f.rootHashes(self.gpa);
        defer self.gpa.free(roots);
        var h = hashmod.Hasher.init(.utxo);
        for (roots) |r| h.update(&r);
        return h.final();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Mine a block that the chain will accept: correct parents, DAA difficulty,
/// coinbase carrying the right height, and a valid nonce. Public so nodes,
/// tests, and demos can construct valid blocks. Block memory is drawn from
/// `arena` and must outlive its use by the chain.
pub fn mineBlock(
    arena: std.mem.Allocator,
    chain: *Chain,
    parents: []const Hash256,
    timestamp: u64,
    extra_txs: []const prim.Transaction,
    cb_commitment: Hash256,
) !Block {
    const height = chain.heightOf(parents);
    // payload = height (committed) ++ timestamp as extranonce, so sibling
    // coinbases at the same height still get distinct txids.
    const payload = arena.alloc(u8, 16) catch unreachable;
    std.mem.writeInt(u64, payload[0..8], height, .little);
    std.mem.writeInt(u64, payload[8..16], timestamp, .little);

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

/// A random valid insertion order (topological) over parents-by-index.
fn randomTopo(arena: std.mem.Allocator, rng: std.Random, parents_idx: []const []u32) ![]u32 {
    const n = parents_idx.len;
    const inserted = try arena.alloc(bool, n);
    @memset(inserted, false);
    var order: std.ArrayList(u32) = .empty;
    var cands: std.ArrayList(u32) = .empty;
    while (order.items.len < n) {
        cands.clearRetainingCapacity();
        for (0..n) |i| {
            if (inserted[i]) continue;
            var ready = true;
            for (parents_idx[i]) |p| {
                if (!inserted[p]) {
                    ready = false;
                    break;
                }
            }
            if (ready) try cands.append(arena, @intCast(i));
        }
        const pick = cands.items[rng.intRangeLessThan(usize, 0, cands.items.len)];
        inserted[pick] = true;
        try order.append(arena, pick);
    }
    return order.toOwnedSlice(arena);
}

test "property: block arrival order does not change the resulting state" {
    var seed: u64 = 0;
    while (seed < 12) : (seed += 1) {
        var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var prng = std.Random.DefaultPrng.init(seed);
        const rng = prng.random();
        const n = rng.intRangeAtMost(u32, 1, 7);

        // Random DAG structure: parents_idx[i] are indices < i.
        const parents_idx = try arena.alloc([]u32, n);
        for (0..n) |i| {
            if (i == 0) {
                parents_idx[i] = try arena.alloc(u32, 0);
                continue;
            }
            const maxp = @min(@as(u32, @intCast(i)), 3);
            const cnt = rng.intRangeAtMost(u32, 1, maxp);
            var chosen: std.ArrayList(u32) = .empty;
            while (chosen.items.len < cnt) {
                const c = rng.intRangeLessThan(u32, 0, @intCast(i));
                if (std.mem.indexOfScalar(u32, chosen.items, c) == null) try chosen.append(arena, c);
            }
            parents_idx[i] = try chosen.toOwnedSlice(arena);
        }

        // Build chain1 in index order (which is topological), collecting blocks.
        var chain1 = Chain.init(testing.allocator, .{});
        defer chain1.deinit();
        const blocks = try arena.alloc(Block, n);
        const ids = try arena.alloc(Hash256, n);
        for (0..n) |i| {
            const ps = try arena.alloc(Hash256, parents_idx[i].len);
            for (parents_idx[i], 0..) |pi, j| ps[j] = ids[pi];
            blocks[i] = try mineBlock(arena, &chain1, ps, 1000 + i, &.{}, hashmod.zero);
            ids[i] = try chain1.acceptBlock(blocks[i]);
        }
        const tip1 = chain1.tip().?;
        var set1 = try chain1.utxoSet();
        defer set1.deinit(testing.allocator);

        // Accept the identical blocks into chain2 in a different topological order.
        const order = try randomTopo(arena, rng, parents_idx);
        var chain2 = Chain.init(testing.allocator, .{});
        defer chain2.deinit();
        for (order) |i| _ = try chain2.acceptBlock(blocks[i]);
        const tip2 = chain2.tip().?;
        var set2 = try chain2.utxoSet();
        defer set2.deinit(testing.allocator);

        // Same tip, same ledger — arrival order is irrelevant.
        try testing.expectEqualSlices(u8, &tip1, &tip2);
        try testing.expectEqual(set1.count(), set2.count());
        // Supply conservation: each block minted exactly one coinbase output.
        try testing.expectEqual(@as(usize, n), set1.count());
    }
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

test "chain commits to UTXO state; a coin proves statelessly against it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var chain = Chain.init(testing.allocator, .{});
    defer chain.deinit();

    const genesis = try mineBlock(arena, &chain, &.{}, 1000, &.{}, hashmod.zero);
    var prev = try chain.acceptBlock(genesis);
    var ts: u64 = 2000;
    for (0..3) |_| {
        prev = try chain.acceptBlock(try mineBlock(arena, &chain, &.{prev}, ts, &.{}, hashmod.zero));
        ts += 1000;
    }

    // The state commitment is deterministic.
    const c1 = try chain.utxoCommitment();
    const c2 = try chain.utxoCommitment();
    try testing.expectEqualSlices(u8, &c1, &c2);

    // Prove the genesis coinbase coin against the accumulator roots — statelessly.
    const cb = genesis.txs[0];
    const cb_id = try cb.txid(arena);
    const coin_op = OutPoint{ .txid = cb_id, .index = 0 };
    const leaf = utxoLeaf(coin_op, cb.outputs[0]);

    var f = try chain.buildAccumulator();
    defer f.deinit();
    const roots = try f.rootHashes(testing.allocator);
    defer testing.allocator.free(roots);

    const proof = (try f.prove(testing.allocator, leaf)).?;
    defer testing.allocator.free(proof);
    try testing.expect(acc.verify(roots, leaf, proof));

    // A coin that does not exist cannot be proven, and a real proof does not
    // validate a different (forged) coin.
    const fake_op = OutPoint{ .txid = [_]u8{0xFF} ** 32, .index = 0 };
    const fake_leaf = utxoLeaf(fake_op, cb.outputs[0]);
    try testing.expect((try f.prove(testing.allocator, fake_leaf)) == null);
    try testing.expect(!acc.verify(roots, fake_leaf, proof));
}

fn acceptAll(nodes: []Chain, block: Block) !void {
    for (nodes) |*n| {
        _ = n.acceptBlock(block) catch |e| switch (e) {
            error.DuplicateBlock => {},
            else => return e,
        };
    }
}

test "multi-node: concurrent mining forks then converges on all nodes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var nodes = [_]Chain{
        Chain.init(testing.allocator, .{}),
        Chain.init(testing.allocator, .{}),
        Chain.init(testing.allocator, .{}),
    };
    defer for (&nodes) |*n| n.deinit();

    // Node 0 mines genesis; everyone accepts (gossip).
    const g = try mineBlock(arena, &nodes[0], &.{}, 1000, &.{}, hashmod.zero);
    try acceptAll(&nodes, g);
    const gid = try g.header.id(arena);

    // Nodes 1 and 2 mine CONCURRENTLY on the same tip — a natural fork. Both
    // blocks propagate to everyone, so all nodes now hold a 2-tip DAG.
    const b1 = try mineBlock(arena, &nodes[1], &.{gid}, 2000, &.{}, hashmod.zero);
    const b2 = try mineBlock(arena, &nodes[2], &.{gid}, 2001, &.{}, hashmod.zero);
    try acceptAll(&nodes, b1);
    try acceptAll(&nodes, b2);

    // Node 0 mines a block merging the fork; everyone accepts.
    const id1 = try b1.header.id(arena);
    const id2 = try b2.header.id(arena);
    const m = try mineBlock(arena, &nodes[0], &.{ id1, id2 }, 3000, &.{}, hashmod.zero);
    try acceptAll(&nodes, m);

    // Convergence: every node agrees on the selected tip AND the full UTXO
    // state commitment — despite different mining and gossip participation.
    const tip0 = nodes[0].tip().?;
    const commit0 = try nodes[0].utxoCommitment();
    for (&nodes) |*n| {
        try testing.expectEqualSlices(u8, &tip0, &n.tip().?);
        try testing.expectEqualSlices(u8, &commit0, &(try n.utxoCommitment()));
    }
    // 4 coinbases minted (genesis, b1, b2, merge), all unspent.
    var set = try nodes[0].utxoSet();
    defer set.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 4), set.count());
}
