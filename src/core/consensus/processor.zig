//! The DAG ledger processor — where consensus ordering meets the UTXO ledger.
//!
//! Given a colored DAG, transactions are applied to the UTXO set in GHOSTDAG's
//! deterministic total order. Two transactions in *parallel* (anticone) blocks
//! may spend the same coin; this is a double-spend that a linear chain never
//! sees. The resolution rule is unambiguous and consensus-critical:
//!
//!     the transaction that appears FIRST in the GHOSTDAG order wins;
//!     any later transaction whose input is already spent is simply invalid
//!     and skipped.
//!
//! Because the order is a deterministic function of the DAG alone, every honest
//! node selects the same winner — no coordination, no ambiguity.

const std = @import("std");
const hashmod = @import("../crypto/hash.zig");
const prim = @import("../primitives/types.zig");
const utxo = @import("../ledger/utxo.zig");
const val = @import("../ledger/validation.zig");
const Ghostdag = @import("ghostdag.zig").Ghostdag;

const Hash256 = hashmod.Hash256;
const Transaction = prim.Transaction;
const UtxoSet = utxo.UtxoSet;

pub const BlockTxs = struct {
    id: Hash256,
    txs: []const Transaction,
};

pub const Stats = struct {
    applied: usize = 0,
    rejected: usize = 0,
};

/// Apply every block's transactions to `set` in the GHOSTDAG consensus order,
/// from scratch. This is the recompute ORACLE that the incremental engine
/// (ledger_state.zig) is checked against, so it enforces the identical rules:
/// coinbases mint; a transaction is skipped (a losing double-spend) if its input
/// was already spent OR if it spends a coinbase output that is not yet `maturity`
/// blocks deep at the spending block's height (`heights`). `maturity == 0`
/// disables the maturity check.
pub fn applyOrder(
    gpa: std.mem.Allocator,
    set: *UtxoSet,
    gd: *Ghostdag,
    blocks: []const BlockTxs,
    heights: *const std.AutoHashMapUnmanaged(Hash256, u64),
    maturity: u64,
) !Stats {
    // Index block id -> transactions.
    var by_id: std.AutoHashMapUnmanaged(Hash256, []const Transaction) = .empty;
    defer by_id.deinit(gpa);
    for (blocks) |b| try by_id.put(gpa, b.id, b.txs);

    // Coinbase outpoint -> creation height, for the maturity check.
    var cb_height: std.AutoHashMapUnmanaged(prim.OutPoint, u64) = .empty;
    defer cb_height.deinit(gpa);

    const order = try gd.order(gpa);
    defer gpa.free(order);

    var stats: Stats = .{};
    for (order) |id| {
        const txs = by_id.get(id) orelse continue; // block carries no txs
        const height = heights.get(id) orelse 0;
        for (txs) |tx| {
            if (tx.isCoinbase()) {
                try val.connectTx(set, tx, gpa);
                const txid = try tx.txid(gpa);
                for (tx.outputs, 0..) |_, i| try cb_height.put(gpa, .{ .txid = txid, .index = @intCast(i) }, height);
                stats.applied += 1;
                continue;
            }
            _ = val.validateTx(set, tx, gpa) catch {
                stats.rejected += 1;
                continue;
            };
            // Coinbase maturity.
            var immature = false;
            if (maturity != 0) for (tx.inputs) |in| {
                if (cb_height.get(in.outpoint)) |cbh| {
                    if (height < cbh +| maturity) {
                        immature = true;
                        break;
                    }
                }
            };
            if (immature) {
                stats.rejected += 1;
                continue;
            }
            for (tx.inputs) |in| _ = cb_height.remove(in.outpoint);
            try val.connectTx(set, tx, gpa);
            stats.applied += 1;
        }
    }
    return stats;
}

// ---------------------------------------------------------------------------
// Capstone test: Phase-1 goal — apply a DAG of PQ-signed txs, resolve a
// cross-anticone double-spend deterministically.
// ---------------------------------------------------------------------------

const testing = std.testing;
const prim_addr = prim.addressCommitment;
const Dag = @import("dag.zig").Dag;
const OutPoint = prim.OutPoint;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

const Key = struct {
    kp: MlDsa44.KeyPair,
    pk: [MlDsa44.PublicKey.encoded_length]u8,
    fn init(seed: u8) Key {
        const kp = MlDsa44.KeyPair.generateDeterministic([_]u8{seed} ** 32) catch unreachable;
        return .{ .kp = kp, .pk = kp.public_key.toBytes() };
    }
    fn commitment(self: Key) Hash256 {
        return prim_addr(.ml_dsa_44, &self.pk);
    }
    fn sign(self: Key, sighash: Hash256) [MlDsa44.Signature.encoded_length]u8 {
        const ctx = [_]u8{0x01}; // ml_dsa_44 scheme tag, bound as signature context
        return (self.kp.signWithContext(&sighash, null, &ctx) catch unreachable).toBytes();
    }
};

fn h(byte: u8) Hash256 {
    return [_]u8{byte} ** 32;
}

test "cross-anticone double-spend resolves to a single deterministic winner" {
    const gpa = testing.allocator;

    const alice = Key.init(1);
    const bob = Key.init(2);
    const carol = Key.init(3);

    // Pre-seed: Alice owns one coin worth 1000.
    var set: UtxoSet = .{};
    defer set.deinit(gpa);
    const funding = OutPoint{ .txid = h(0xF0), .index = 0 };
    try set.add(gpa, funding, .{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() });

    // Two conflicting transactions spending the SAME coin.
    var tx_to_bob = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = funding }},
        .outputs = &.{.{ .value = 900, .scheme = .ml_dsa_44, .commitment = bob.commitment() }},
        .witnesses = &.{},
    };
    const sh_b = try tx_to_bob.sighash(gpa, .ml_dsa_44);
    const sig_b = alice.sign(sh_b);
    tx_to_bob.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sig_b }};

    var tx_to_carol = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = funding }},
        .outputs = &.{.{ .value = 900, .scheme = .ml_dsa_44, .commitment = carol.commitment() }},
        .witnesses = &.{},
    };
    const sh_c = try tx_to_carol.sighash(gpa, .ml_dsa_44);
    const sig_c = alice.sign(sh_c);
    tx_to_carol.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sig_c }};

    // DAG: A (genesis) -> B, C in parallel; D merges them.
    // B (id h(2)) carries tx_to_bob; C (id h(3)) carries tx_to_carol.
    var dag = Dag.init(gpa);
    defer dag.deinit();
    try dag.addBlock(h(1), &.{});
    try dag.addBlock(h(2), &.{h(1)});
    try dag.addBlock(h(3), &.{h(1)});
    try dag.addBlock(h(4), &.{ h(2), h(3) });

    var gd = Ghostdag.init(gpa, &dag, 1);
    defer gd.deinit();
    try gd.compute();

    const blocks = [_]BlockTxs{
        .{ .id = h(2), .txs = &.{tx_to_bob} },
        .{ .id = h(3), .txs = &.{tx_to_carol} },
        .{ .id = h(1), .txs = &.{} },
        .{ .id = h(4), .txs = &.{} },
    };

    var nh: std.AutoHashMapUnmanaged(Hash256, u64) = .empty;
    const stats = try applyOrder(gpa, &set, &gd, &blocks, &nh, 0);

    // Exactly one of the two conflicting txs is applied; the other is rejected.
    try testing.expectEqual(@as(usize, 1), stats.applied);
    try testing.expectEqual(@as(usize, 1), stats.rejected);

    // The winner is deterministic: block B (id h(2)) precedes C (h(3)) in the
    // GHOSTDAG order (it is D's selected-parent side), so Bob is paid, not Carol.
    const bob_id = (try tx_to_bob.txid(gpa));
    const carol_id = (try tx_to_carol.txid(gpa));
    try testing.expect(set.contains(.{ .txid = bob_id, .index = 0 }));
    try testing.expect(!set.contains(.{ .txid = carol_id, .index = 0 }));

    // The coin is spent exactly once; ledger has: Bob's output only.
    try testing.expect(!set.contains(funding));
    try testing.expectEqual(@as(usize, 1), set.count());
}

test "self-contained chain: coinbase mints, then the coin is spent" {
    const gpa = testing.allocator;
    const alice = Key.init(1);
    const bob = Key.init(2);

    // Block A (genesis): coinbase mints 1000 to Alice. No pre-seeding.
    const h0 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }; // height 0, LE
    const cb_a = Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{.{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() }},
        .witnesses = &.{},
        .payload = &h0,
    };
    const cb_a_id = try cb_a.txid(gpa);

    // Block B: coinbase (height 1) + Alice spends her minted coin to Bob.
    const h1 = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };
    const cb_b = Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{.{ .value = 50, .scheme = .ml_dsa_44, .commitment = bob.commitment() }},
        .witnesses = &.{},
        .payload = &h1,
    };
    var alice_spend = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = cb_a_id, .index = 0 } }},
        .outputs = &.{.{ .value = 900, .scheme = .ml_dsa_44, .commitment = bob.commitment() }},
        .witnesses = &.{},
    };
    const sh = try alice_spend.sighash(gpa, .ml_dsa_44);
    const sig = alice.sign(sh);
    alice_spend.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sig }};

    var dag = Dag.init(gpa);
    defer dag.deinit();
    try dag.addBlock(h(1), &.{});
    try dag.addBlock(h(2), &.{h(1)});

    var gd = Ghostdag.init(gpa, &dag, 1);
    defer gd.deinit();
    try gd.compute();

    var set: UtxoSet = .{};
    defer set.deinit(gpa);
    const blocks = [_]BlockTxs{
        .{ .id = h(1), .txs = &.{cb_a} },
        .{ .id = h(2), .txs = &.{ cb_b, alice_spend } },
    };
    var nh: std.AutoHashMapUnmanaged(Hash256, u64) = .empty;
    const stats = try applyOrder(gpa, &set, &gd, &blocks, &nh, 0);

    try testing.expectEqual(@as(usize, 3), stats.applied); // 2 coinbases + 1 spend
    try testing.expectEqual(@as(usize, 0), stats.rejected);

    // Alice's minted coin is spent; Bob holds cb_b's 50 and the 900 from Alice.
    try testing.expect(!set.contains(.{ .txid = cb_a_id, .index = 0 }));
    const spend_id = try alice_spend.txid(gpa);
    try testing.expect(set.contains(.{ .txid = spend_id, .index = 0 }));
    try testing.expectEqual(@as(usize, 2), set.count()); // cb_b output + alice->bob output
}
