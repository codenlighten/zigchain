//! Incremental, reorg-aware UTXO state.
//!
//! The chain engine can derive the UTXO set by replaying the whole GHOSTDAG
//! order (see `processor.applyOrder`), but that is O(n) every time. This module
//! maintains the set INCREMENTALLY as the consensus order changes.
//!
//! The hard part is that a BlockDAG reorganises: when a block is added the
//! consensus order can change, and a transaction that previously applied may
//! become invalid (e.g. a block that now sorts earlier double-spends a coin a
//! later block was spending). So this is not an append — it is a true reorg.
//!
//! Mechanism: for every applied block we record UNDO data (the outpoints it
//! created and the coins it spent). On `update(newOrder)` we find the longest
//! common prefix with the currently-applied order, roll the divergent suffix
//! BACK using the undo data (restoring spent coins, removing created ones), then
//! apply the new suffix forward — recording fresh undo data. In the common case
//! (a block simply extends the tip) the suffix is empty and this is O(1); only a
//! real reorg pays for the blocks it rewinds.
//!
//! Correctness is pinned against the recompute-from-scratch path
//! (`processor.applyOrder`) as a differential oracle — see the tests, including
//! a reorg that flips which of two conflicting transactions wins.

const std = @import("std");
const prim = @import("../primitives/types.zig");
const utxo = @import("../ledger/utxo.zig");
const validation = @import("../ledger/validation.zig");
const hashmod = @import("../crypto/hash.zig");

const Hash256 = hashmod.Hash256;
const OutPoint = prim.OutPoint;
const Output = prim.Output;
const Transaction = prim.Transaction;
const UtxoSet = utxo.UtxoSet;

fn eql(a: Hash256, b: Hash256) bool {
    return std.mem.eql(u8, &a, &b);
}

/// A spent coin captured for undo. `cb` is the coinbase creation height if the
/// coin was a (still-immature-tracked) coinbase output, so a reorg can restore
/// the coinbase-maturity side-table exactly.
const Coin = struct { op: OutPoint, out: Output, cb: ?u64 = null };

/// Undo record for one applied block: how to reverse its effect on the set.
const BlockUndo = struct {
    removed: []OutPoint, // outpoints this block created (spend them to undo)
    restored: []Coin, // coins this block spent (re-add them to undo)

    fn deinit(self: *BlockUndo, gpa: std.mem.Allocator) void {
        gpa.free(self.removed);
        gpa.free(self.restored);
    }
};

/// A lookup from block id to its transactions.
pub const BlockTxMap = std.AutoHashMapUnmanaged(Hash256, []const Transaction);

pub const IncrementalUtxo = struct {
    gpa: std.mem.Allocator,
    set: UtxoSet = .{},
    /// Coinbase outpoint -> the block height at which it was minted. An entry
    /// exists only while the coinbase output is unspent; used for the maturity
    /// check and maintained (with undo) across reorgs.
    cb_height: std.AutoHashMapUnmanaged(OutPoint, u64) = .empty,
    applied: std.ArrayList(Hash256) = .empty, // block ids currently applied, in order
    undo: std.ArrayList(BlockUndo) = .empty, // parallel undo data

    pub fn init(gpa: std.mem.Allocator) IncrementalUtxo {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *IncrementalUtxo) void {
        self.set.deinit(self.gpa);
        self.cb_height.deinit(self.gpa);
        self.applied.deinit(self.gpa);
        for (self.undo.items) |*u| u.deinit(self.gpa);
        self.undo.deinit(self.gpa);
    }

    /// Bring the applied state in line with `order` (a consensus ordering of
    /// blocks), looking transactions up in `blocks` and each block's height in
    /// `heights`. A coinbase output cannot be spent until `maturity` blocks after
    /// its creation (0 disables the check).
    pub fn update(
        self: *IncrementalUtxo,
        order: []const Hash256,
        blocks: *const BlockTxMap,
        heights: *const std.AutoHashMapUnmanaged(Hash256, u64),
        maturity: u64,
    ) !void {
        // Longest common prefix of the currently-applied order and the new one.
        var d: usize = 0;
        while (d < self.applied.items.len and d < order.len and eql(self.applied.items[d], order[d])) : (d += 1) {}

        // Roll the divergent suffix BACK (last applied first).
        while (self.applied.items.len > d) {
            var bu = self.undo.pop().?;
            _ = self.applied.pop();
            for (bu.removed) |op| {
                _ = self.set.spend(op);
                _ = self.cb_height.remove(op); // undo a minted coinbase's maturity entry
            }
            for (bu.restored) |c| {
                try self.set.add(self.gpa, c.op, c.out);
                if (c.cb) |h| try self.cb_height.put(self.gpa, c.op, h); // restore a spent coinbase's entry
            }
            bu.deinit(self.gpa);
        }

        // Apply the new suffix forward, recording undo data.
        for (order[d..]) |id| {
            const txs = if (blocks.get(id)) |t| t else &.{};
            const height = heights.get(id) orelse 0;
            const bu = try self.applyBlock(txs, height, maturity);
            try self.applied.append(self.gpa, id);
            try self.undo.append(self.gpa, bu);
        }
    }

    /// Apply one block's transactions (same rules as processor.applyOrder:
    /// coinbases mint; other txs apply if valid AND their coinbase inputs are
    /// mature, else are dropped), returning the undo data.
    fn applyBlock(self: *IncrementalUtxo, txs: []const Transaction, height: u64, maturity: u64) !BlockUndo {
        var removed: std.ArrayList(OutPoint) = .empty;
        errdefer removed.deinit(self.gpa);
        var restored: std.ArrayList(Coin) = .empty;
        errdefer restored.deinit(self.gpa);

        for (txs) |tx| {
            if (tx.isCoinbase()) {
                const txid = try tx.txid(self.gpa);
                for (tx.outputs, 0..) |o, i| {
                    const op = OutPoint{ .txid = txid, .index = @intCast(i) };
                    try self.set.add(self.gpa, op, o);
                    try self.cb_height.put(self.gpa, op, height);
                    try removed.append(self.gpa, op);
                }
            } else {
                _ = validation.validateTx(&self.set, tx, self.gpa) catch continue; // losing double-spend
                // Coinbase maturity: every coinbase input must be `maturity` deep.
                if (self.immatureSpend(tx, height, maturity)) continue;
                const txid = try tx.txid(self.gpa);
                for (tx.inputs) |in| {
                    const coin = self.set.get(in.outpoint).?;
                    _ = self.set.spend(in.outpoint);
                    const cb = self.cb_height.fetchRemove(in.outpoint);
                    try restored.append(self.gpa, .{ .op = in.outpoint, .out = coin, .cb = if (cb) |e| e.value else null });
                }
                for (tx.outputs, 0..) |o, i| {
                    const op = OutPoint{ .txid = txid, .index = @intCast(i) };
                    try self.set.add(self.gpa, op, o);
                    try removed.append(self.gpa, op);
                }
            }
        }
        return .{
            .removed = try removed.toOwnedSlice(self.gpa),
            .restored = try restored.toOwnedSlice(self.gpa),
        };
    }

    /// True if `tx` spends a coinbase output that is not yet `maturity` blocks
    /// deep at the spending `height`.
    fn immatureSpend(self: *const IncrementalUtxo, tx: Transaction, height: u64, maturity: u64) bool {
        if (maturity == 0) return false;
        for (tx.inputs) |in| {
            if (self.cb_height.get(in.outpoint)) |h| {
                if (height < h +| maturity) return true;
            }
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const Dag = @import("dag.zig").Dag;
const Ghostdag = @import("ghostdag.zig").Ghostdag;
const processor = @import("processor.zig");
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

fn idOf(i: u32) Hash256 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, i, .little);
    return hashmod.hash(.block_header, &b);
}

fn sameSet(a: *UtxoSet, b: *UtxoSet) bool {
    if (a.count() != b.count()) return false;
    var it = a.map.iterator();
    while (it.next()) |e| {
        const other = b.get(e.key_ptr.*) orelse return false;
        if (other.value != e.value_ptr.value) return false;
    }
    return true;
}

test "property: incremental UTXO equals recompute across random DAG growth" {
    const gpa = testing.allocator;
    var seed: u64 = 3000;
    while (seed < 3050) : (seed += 1) {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var prng = std.Random.DefaultPrng.init(seed);
        const rng = prng.random();
        const n = rng.intRangeAtMost(u32, 1, 12);
        const k = rng.intRangeAtMost(u32, 0, 3);

        // Each block carries one coinbase minting a distinct coin.
        var blocks: BlockTxMap = .empty;
        defer blocks.deinit(gpa);
        var heights: std.AutoHashMapUnmanaged(Hash256, u64) = .empty;
        defer heights.deinit(gpa);
        var parents_by_idx = try arena.alloc([]u32, n);

        var dag = Dag.init(gpa);
        defer dag.deinit();
        var gd = Ghostdag.init(gpa, &dag, k);
        defer gd.deinit();
        var inc = IncrementalUtxo.init(gpa);
        defer inc.deinit();

        for (0..n) |i| {
            // random parents (earlier indices)
            var plist: std.ArrayList(u32) = .empty;
            if (i > 0) {
                const cnt = rng.intRangeAtMost(u32, 1, @min(@as(u32, @intCast(i)), 3));
                while (plist.items.len < cnt) {
                    const c = rng.intRangeLessThan(u32, 0, @intCast(i));
                    if (std.mem.indexOfScalar(u32, plist.items, c) == null) try plist.append(arena, c);
                }
            }
            parents_by_idx[i] = try plist.toOwnedSlice(arena);
            const ps = try arena.alloc(Hash256, parents_by_idx[i].len);
            for (parents_by_idx[i], 0..) |pi, j| ps[j] = idOf(pi);

            // coinbase for this block (payload = index → unique txid)
            const payload = try arena.alloc(u8, 8);
            std.mem.writeInt(u64, payload[0..8], i, .little);
            const cb = try arena.create(Transaction);
            cb.* = .{ .version = 1, .inputs = &.{}, .outputs = try arena.dupe(prim.Output, &.{.{ .value = 50, .scheme = .ml_dsa_44, .commitment = idOf(@intCast(1000 + i)) }}), .witnesses = &.{}, .payload = payload };
            try blocks.put(gpa, idOf(@intCast(i)), cb[0..1]);
            try heights.put(gpa, idOf(@intCast(i)), i);

            try dag.addBlock(idOf(@intCast(i)), ps);
            try gd.addBlock(idOf(@intCast(i)));
            const order = try gd.order(gpa);
            defer gpa.free(order);
            try inc.update(order, &blocks, &heights, 100);
        }

        // Recompute from scratch and compare.
        var items: std.ArrayList(processor.BlockTxs) = .empty;
        defer items.deinit(gpa);
        var bit = blocks.iterator();
        while (bit.next()) |e| try items.append(gpa, .{ .id = e.key_ptr.*, .txs = e.value_ptr.* });
        var rec: UtxoSet = .{};
        defer rec.deinit(gpa);
        _ = try processor.applyOrder(gpa, &rec, &gd, items.items, &heights, 100);

        try testing.expect(sameSet(&inc.set, &rec));
    }
}

const Key = struct {
    kp: MlDsa44.KeyPair,
    pk: [MlDsa44.PublicKey.encoded_length]u8,
    fn init(seed: u8) Key {
        const kp = MlDsa44.KeyPair.generateDeterministic([_]u8{seed} ** 32) catch unreachable;
        return .{ .kp = kp, .pk = kp.public_key.toBytes() };
    }
    fn commitment(self: Key) Hash256 {
        return prim.addressCommitment(.ml_dsa_44, &self.pk);
    }
    fn sign(self: Key, sh: Hash256) [MlDsa44.Signature.encoded_length]u8 {
        const ctx = [_]u8{0x01};
        return (self.kp.signWithContext(&sh, null, &ctx) catch unreachable).toBytes();
    }
};

test "reorg flips a double-spend winner; state matches recompute" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const alice = Key.init(1);
    const bob = Key.init(2);
    const carol = Key.init(3);

    // Block G: coinbase mints 1000 to Alice.
    const h0 = [_]u8{0} ** 8;
    const cbG = Transaction{ .version = 1, .inputs = &.{}, .outputs = try arena.dupe(prim.Output, &.{.{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() }}), .witnesses = &.{}, .payload = &h0 };
    const cbG_id = try cbG.txid(arena);
    const alice_coin = OutPoint{ .txid = cbG_id, .index = 0 };

    // Two conflicting spends of Alice's coin.
    var toBob = Transaction{ .version = 1, .inputs = try arena.dupe(prim.Input, &.{.{ .outpoint = alice_coin }}), .outputs = try arena.dupe(prim.Output, &.{.{ .value = 900, .scheme = .ml_dsa_44, .commitment = bob.commitment() }}), .witnesses = &.{} };
    const sB = alice.sign(try toBob.sighash(arena, .ml_dsa_44));
    toBob.witnesses = try arena.dupe(prim.Witness, &.{.{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sB }});

    var toCarol = Transaction{ .version = 1, .inputs = try arena.dupe(prim.Input, &.{.{ .outpoint = alice_coin }}), .outputs = try arena.dupe(prim.Output, &.{.{ .value = 900, .scheme = .ml_dsa_44, .commitment = carol.commitment() }}), .witnesses = &.{} };
    const sC = alice.sign(try toCarol.sighash(arena, .ml_dsa_44));
    toCarol.witnesses = try arena.dupe(prim.Witness, &.{.{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sC }});

    const G = idOf(100);
    const B1 = idOf(101); // carries toBob
    const B2 = idOf(102); // carries toCarol
    var blocks: BlockTxMap = .empty;
    defer blocks.deinit(gpa);
    try blocks.put(gpa, G, try arena.dupe(Transaction, &.{cbG}));
    try blocks.put(gpa, B1, try arena.dupe(Transaction, &.{toBob}));
    try blocks.put(gpa, B2, try arena.dupe(Transaction, &.{toCarol}));

    const toBob_id = try toBob.txid(arena);
    const toCarol_id = try toCarol.txid(arena);

    var inc = IncrementalUtxo.init(gpa);
    defer inc.deinit();
    // This test isolates reorg / double-spend resolution, so maturity is disabled
    // (0); a heights map is required by the signature but unused when maturity=0.
    var heights: std.AutoHashMapUnmanaged(Hash256, u64) = .empty;
    defer heights.deinit(gpa);

    // Order 1: B1 before B2 → Bob wins, Carol's tx is a losing double-spend.
    try inc.update(&.{ G, B1, B2 }, &blocks, &heights, 0);
    try testing.expect(inc.set.contains(.{ .txid = toBob_id, .index = 0 }));
    try testing.expect(!inc.set.contains(.{ .txid = toCarol_id, .index = 0 }));

    // A reorg swaps the order: B2 before B1 → Carol wins, Bob's tx now loses.
    try inc.update(&.{ G, B2, B1 }, &blocks, &heights, 0);
    try testing.expect(inc.set.contains(.{ .txid = toCarol_id, .index = 0 }));
    try testing.expect(!inc.set.contains(.{ .txid = toBob_id, .index = 0 }));

    // The incrementally-reorged state matches a from-scratch recompute of order 2.
    var rec = IncrementalUtxo.init(gpa);
    defer rec.deinit();
    try rec.update(&.{ G, B2, B1 }, &blocks, &heights, 0);
    try testing.expect(sameSet(&inc.set, &rec.set));
}
