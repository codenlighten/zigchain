//! The mempool — pending transactions awaiting inclusion in a block.
//!
//! This is an EDGE component, not consensus. In particular the optional
//! `Policy` hook is where a node operator applies relay/compliance rules
//! (allow/deny lists, sanction screening, jurisdiction policy) WITHOUT changing
//! what the network considers valid. Consensus validity stays jurisdiction-
//! neutral; two operators with different policies still agree on the chain.
//!
//! Transactions are admitted only if they are consensus-valid against the
//! confirmed UTXO set and do not conflict (double-spend) with the confirmed set
//! or another mempool entry. Block selection is greedy by fee-rate (fee/mass)
//! under a mass cap. In-mempool chaining (spending an unconfirmed output) is a
//! planned extension; v1 validates against confirmed state only.

const std = @import("std");
const prim = @import("../core/primitives/types.zig");
const hashmod = @import("../core/crypto/hash.zig");
const utxo = @import("../core/ledger/utxo.zig");
const validation = @import("../core/ledger/validation.zig");
const massmod = @import("../core/consensus/mass.zig");

const Hash256 = hashmod.Hash256;
const Transaction = prim.Transaction;
const OutPoint = prim.OutPoint;
const UtxoSet = utxo.UtxoSet;

/// Node-local relay/compliance filter. Returns true to allow the transaction.
/// This is policy, never consensus.
pub const Policy = *const fn (tx: Transaction) bool;

pub const AddResult = enum { admitted, duplicate, rejected_by_policy, conflict, invalid };

pub const Entry = struct {
    tx: Transaction,
    txid: Hash256,
    fee: u64,
    mass: u64,
};

pub const Mempool = struct {
    gpa: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    /// Outpoints claimed by some mempool entry (in-pool double-spend guard).
    spent: std.AutoHashMapUnmanaged(OutPoint, void) = .empty,
    /// txids present (dedup).
    ids: std.AutoHashMapUnmanaged(Hash256, void) = .empty,

    pub fn init(gpa: std.mem.Allocator) Mempool {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Mempool) void {
        self.entries.deinit(self.gpa);
        self.spent.deinit(self.gpa);
        self.ids.deinit(self.gpa);
    }

    pub fn count(self: *const Mempool) usize {
        return self.entries.items.len;
    }

    /// Try to admit `tx`. `set` is the confirmed UTXO view.
    pub fn add(self: *Mempool, set: *const UtxoSet, tx: Transaction, policy: ?Policy) !AddResult {
        // Edge policy first — a policy rejection is not a validity judgement.
        if (policy) |p| {
            if (!p(tx)) return .rejected_by_policy;
        }

        const id = try tx.txid(self.gpa);
        if (self.ids.contains(id)) return .duplicate;

        // Reject if any input is already claimed by another mempool entry.
        for (tx.inputs) |in| {
            if (self.spent.contains(in.outpoint)) return .conflict;
        }

        // Consensus validity against confirmed state (also proves no confirmed
        // double-spend). Returns the fee.
        const fee = validation.validateTx(set, tx, self.gpa) catch return .invalid;
        const m = massmod.txMass(self.gpa, tx) catch return .invalid;

        for (tx.inputs) |in| try self.spent.put(self.gpa, in.outpoint, {});
        try self.ids.put(self.gpa, id, {});
        try self.entries.append(self.gpa, .{ .tx = tx, .txid = id, .fee = fee, .mass = m });
        return .admitted;
    }

    /// a has a higher fee-rate than b (fee/mass), compared without division.
    fn higherFeeRate(_: void, a: Entry, b: Entry) bool {
        // a.fee/a.mass > b.fee/b.mass  <=>  a.fee*b.mass > b.fee*a.mass
        const lhs = @as(u128, a.fee) * @as(u128, b.mass);
        const rhs = @as(u128, b.fee) * @as(u128, a.mass);
        if (lhs != rhs) return lhs > rhs;
        return std.mem.order(u8, &a.txid, &b.txid) == .lt; // deterministic tie-break
    }

    /// Select transactions for a block: highest fee-rate first, staying within
    /// `max_mass` and never picking two that spend the same coin. Caller owns
    /// the returned slice.
    pub fn selectForBlock(self: *Mempool, gpa: std.mem.Allocator, max_mass: u64) ![]Transaction {
        const sorted = try gpa.dupe(Entry, self.entries.items);
        defer gpa.free(sorted);
        std.mem.sort(Entry, sorted, {}, higherFeeRate);

        var used_mass: u64 = 0;
        var claimed: std.AutoHashMapUnmanaged(OutPoint, void) = .empty;
        defer claimed.deinit(gpa);
        var out: std.ArrayList(Transaction) = .empty;
        errdefer out.deinit(gpa);

        for (sorted) |e| {
            if (used_mass + e.mass > max_mass) continue;
            var conflicts = false;
            for (e.tx.inputs) |in| {
                if (claimed.contains(in.outpoint)) {
                    conflicts = true;
                    break;
                }
            }
            if (conflicts) continue;
            for (e.tx.inputs) |in| try claimed.put(gpa, in.outpoint, {});
            used_mass += e.mass;
            try out.append(gpa, e.tx);
        }
        return out.toOwnedSlice(gpa);
    }

    /// Drop transactions (by txid) that were included in an accepted block,
    /// releasing the inputs they claimed.
    pub fn removeIncluded(self: *Mempool, included: []const Hash256) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = self.entries.items[i];
            var found = false;
            for (included) |id| {
                if (std.mem.eql(u8, &e.txid, &id)) {
                    found = true;
                    break;
                }
            }
            if (found) {
                for (e.tx.inputs) |in| _ = self.spent.remove(in.outpoint);
                _ = self.ids.remove(e.txid);
                _ = self.entries.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

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
    fn sign(self: Key, sighash: Hash256) [MlDsa44.Signature.encoded_length]u8 {
        const ctx = [_]u8{0x01};
        return (self.kp.signWithContext(&sighash, null, &ctx) catch unreachable).toBytes();
    }
};

/// Build a signed 1-in/1-out transaction spending `op`, paying `value` to `to`.
fn makeSpend(arena: std.mem.Allocator, key: Key, op: OutPoint, to: Hash256, value: u64) !Transaction {
    var tx = Transaction{
        .version = 1,
        .inputs = try arena.dupe(prim.Input, &.{.{ .outpoint = op }}),
        .outputs = try arena.dupe(prim.Output, &.{.{ .value = value, .scheme = .ml_dsa_44, .commitment = to }}),
        .witnesses = &.{},
    };
    const sh = try tx.sighash(arena, .ml_dsa_44);
    const sig = try arena.dupe(u8, &key.sign(sh));
    const pk = try arena.dupe(u8, &key.pk);
    tx.witnesses = try arena.dupe(prim.Witness, &.{.{ .scheme = .ml_dsa_44, .pubkey = pk, .signature = sig }});
    return tx;
}

test "mempool admits valid txs, rejects duplicates and conflicts" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const alice = Key.init(1);
    const bob = Key.init(2);

    var set: UtxoSet = .{};
    defer set.deinit(testing.allocator);
    const coin = OutPoint{ .txid = [_]u8{0xA1} ** 32, .index = 0 };
    try set.add(testing.allocator, coin, .{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() });

    var mp = Mempool.init(testing.allocator);
    defer mp.deinit();

    const tx = try makeSpend(arena, alice, coin, bob.commitment(), 900);
    try testing.expectEqual(AddResult.admitted, try mp.add(&set, tx, null));
    try testing.expectEqual(@as(usize, 1), mp.count());

    // Same tx again -> duplicate.
    try testing.expectEqual(AddResult.duplicate, try mp.add(&set, tx, null));

    // A different tx spending the same coin -> conflict.
    const conflict = try makeSpend(arena, alice, coin, alice.commitment(), 800);
    try testing.expectEqual(AddResult.conflict, try mp.add(&set, conflict, null));

    // A tx spending a non-existent coin -> invalid.
    const bad = try makeSpend(arena, alice, .{ .txid = [_]u8{0xFF} ** 32, .index = 0 }, bob.commitment(), 1);
    try testing.expectEqual(AddResult.invalid, try mp.add(&set, bad, null));
}

fn denyBob(tx: Transaction) bool {
    // Example edge policy: refuse to relay anything paying a sanctioned address.
    const sanctioned = Key.init(2).commitment();
    for (tx.outputs) |o| {
        if (std.mem.eql(u8, &o.commitment, &sanctioned)) return false;
    }
    return true;
}

test "policy hook filters at the edge without affecting validity" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const alice = Key.init(1);
    const bob = Key.init(2);

    var set: UtxoSet = .{};
    defer set.deinit(testing.allocator);
    const coin = OutPoint{ .txid = [_]u8{0xB2} ** 32, .index = 0 };
    try set.add(testing.allocator, coin, .{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() });

    var mp = Mempool.init(testing.allocator);
    defer mp.deinit();

    // Paying Bob is refused by policy (but the tx is perfectly valid).
    const to_bob = try makeSpend(arena, alice, coin, bob.commitment(), 900);
    try testing.expectEqual(AddResult.rejected_by_policy, try mp.add(&set, to_bob, denyBob));
    try testing.expectEqual(@as(usize, 0), mp.count());

    // The very same tx is admitted with no policy — proving policy != validity.
    try testing.expectEqual(AddResult.admitted, try mp.add(&set, to_bob, null));
}

test "block selection is fee-rate ordered and mass-capped" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const alice = Key.init(1);
    const dest = Key.init(9).commitment();

    var set: UtxoSet = .{};
    defer set.deinit(testing.allocator);
    // Three independent coins so the three txs don't conflict.
    const coins = [_]OutPoint{
        .{ .txid = [_]u8{0x01} ** 32, .index = 0 },
        .{ .txid = [_]u8{0x02} ** 32, .index = 0 },
        .{ .txid = [_]u8{0x03} ** 32, .index = 0 },
    };
    for (coins) |c| try set.add(testing.allocator, c, .{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() });

    var mp = Mempool.init(testing.allocator);
    defer mp.deinit();

    // Same size (mass), different fees -> different fee-rates.
    _ = try mp.add(&set, try makeSpend(arena, alice, coins[0], dest, 900), null); // fee 100
    _ = try mp.add(&set, try makeSpend(arena, alice, coins[1], dest, 500), null); // fee 500 (best)
    _ = try mp.add(&set, try makeSpend(arena, alice, coins[2], dest, 700), null); // fee 300
    try testing.expectEqual(@as(usize, 3), mp.count());

    // All three fit: highest fee-rate first. Fee = 1000 - output, so the tx
    // paying 500 has the biggest fee, then 700 (fee 300), then 900 (fee 100).
    const all = try mp.selectForBlock(arena, 1_000_000);
    try testing.expectEqual(@as(usize, 3), all.len);
    try testing.expectEqual(@as(u64, 500), all[0].outputs[0].value);
    try testing.expectEqual(@as(u64, 700), all[1].outputs[0].value);
    try testing.expectEqual(@as(u64, 900), all[2].outputs[0].value);

    // With a mass cap that fits only one, we get just the best-fee tx.
    const one_mass = massmod.txMass(arena, all[0]) catch unreachable;
    const top = try mp.selectForBlock(arena, one_mass);
    try testing.expectEqual(@as(usize, 1), top.len);
    try testing.expectEqual(@as(u64, 500), top[0].outputs[0].value);
}
