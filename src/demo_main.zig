//! `zig build demo` — a full end-to-end run of ZigChain.
//!
//! Mines a small BlockDAG of post-quantum-signed transactions (including a
//! cross-fork double-spend), orders it with GHOSTDAG, applies it to the UTXO
//! ledger, and finalizes a cut with a post-quantum BFT validator set — printing
//! the whole story. This is the "it's a real chain" artifact.

const std = @import("std");
const hashmod = @import("core/crypto/hash.zig");
const prim = @import("core/primitives/types.zig");
const blk = @import("core/primitives/block.zig");
const powmod = @import("core/consensus/pow.zig");
const utxo = @import("core/ledger/utxo.zig");
const proc = @import("core/consensus/processor.zig");
const Dag = @import("core/consensus/dag.zig").Dag;
const Ghostdag = @import("core/consensus/ghostdag.zig").Ghostdag;
const finality = @import("core/consensus/finality.zig");

const Hash256 = hashmod.Hash256;
const Transaction = prim.Transaction;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

const sig_len = MlDsa44.Signature.encoded_length;
const pk_len = MlDsa44.PublicKey.encoded_length;

const Wallet = struct {
    name: []const u8,
    kp: MlDsa44.KeyPair,
    pk: [pk_len]u8,
    commitment: Hash256,

    fn init(name: []const u8, seed: u8) Wallet {
        const kp = MlDsa44.KeyPair.generateDeterministic([_]u8{seed} ** 32) catch unreachable;
        const pk = kp.public_key.toBytes();
        return .{ .name = name, .kp = kp, .pk = pk, .commitment = prim.addressCommitment(.ml_dsa_44, &pk) };
    }
    fn sign(self: Wallet, sighash: Hash256) [sig_len]u8 {
        const ctx = [_]u8{0x01};
        return (self.kp.signWithContext(&sighash, null, &ctx) catch unreachable).toBytes();
    }
};

fn hp(n: u64) [8]u8 {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, n, .little);
    return b;
}

fn h(byte: u8) Hash256 {
    return [_]u8{byte} ** 32;
}

fn balanceOf(set: utxo.UtxoSet, commitment: Hash256) u64 {
    var total: u64 = 0;
    var it = set.map.iterator();
    while (it.next()) |e| {
        if (std.mem.eql(u8, &e.value_ptr.commitment, &commitment)) total += e.value_ptr.value;
    }
    return total;
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const alice = Wallet.init("Alice", 1);
    const bob = Wallet.init("Bob", 2);
    const carol = Wallet.init("Carol", 3);
    const miner = Wallet.init("Miner", 4);

    std.debug.print(
        \\============================================================
        \\  ZigChain — post-quantum PoW BlockDAG, end-to-end
        \\============================================================
        \\Signatures: ML-DSA-44 (FIPS 204)  pubkey={d}B  sig={d}B
        \\Wallets: Alice, Bob, Carol, Miner (each a real PQ keypair)
        \\
        \\
    , .{ pk_len, sig_len });

    // --- coinbases (unique payload = height) ---
    const p0 = hp(0);
    const p1 = hp(1);
    const p2 = hp(2);
    const p3 = hp(3);
    const p4 = hp(4);
    const p5 = hp(5);
    const p6 = hp(6);

    const cb0 = coinbase(alice.commitment, 1000, &p0); // genesis mints 1000 to Alice
    const cb1 = coinbase(miner.commitment, 50, &p1);
    const cb2 = coinbase(miner.commitment, 50, &p2);
    const cb3 = coinbase(miner.commitment, 50, &p3);
    const cb4 = coinbase(miner.commitment, 50, &p4);
    const cb5 = coinbase(miner.commitment, 50, &p5);
    const cb6 = coinbase(miner.commitment, 50, &p6);

    // --- transactions ---
    const cb0_id = try cb0.txid(gpa);
    var a2b = spend(.{ .txid = cb0_id, .index = 0 }, bob.commitment, 1000);
    const a2b_sig = alice.sign(try a2b.sighash(gpa, .ml_dsa_44));
    a2b.witnesses = wit(&alice.pk, &a2b_sig);
    const a2b_id = try a2b.txid(gpa);

    // Two conflicting spends of Bob's coin (a cross-fork double-spend).
    var b2c = spend(.{ .txid = a2b_id, .index = 0 }, carol.commitment, 1000);
    const b2c_sig = bob.sign(try b2c.sighash(gpa, .ml_dsa_44));
    b2c.witnesses = wit(&bob.pk, &b2c_sig);

    var b2a = spend(.{ .txid = a2b_id, .index = 0 }, alice.commitment, 1000);
    const b2a_sig = bob.sign(try b2a.sighash(gpa, .ml_dsa_44));
    b2a.witnesses = wit(&bob.pk, &b2a_sig);

    // --- the DAG: a chain with one fork (h3 ∥ h4) merged at h5 ---
    var dag = Dag.init(gpa);
    try dag.addBlock(h(1), &.{});
    try dag.addBlock(h(2), &.{h(1)});
    try dag.addBlock(h(3), &.{h(2)});
    try dag.addBlock(h(4), &.{h(2)}); // parallel to h3
    try dag.addBlock(h(5), &.{ h(3), h(4) }); // merges the fork
    try dag.addBlock(h(6), &.{h(5)});
    try dag.addBlock(h(7), &.{h(6)});

    var gd = Ghostdag.init(gpa, &dag, 3);
    try gd.compute();

    const blocks = [_]proc.BlockTxs{
        .{ .id = h(1), .txs = &.{cb0} },
        .{ .id = h(2), .txs = &.{ cb1, a2b } },
        .{ .id = h(3), .txs = &.{ cb2, b2c } }, // Bob -> Carol
        .{ .id = h(4), .txs = &.{ cb3, b2a } }, // Bob -> Alice (conflicts)
        .{ .id = h(5), .txs = &.{cb4} },
        .{ .id = h(6), .txs = &.{cb5} },
        .{ .id = h(7), .txs = &.{cb6} },
    };

    // --- print the DAG ---
    std.debug.print("BlockDAG (GHOSTDAG k=3):\n", .{});
    const labels = [_][]const u8{ "genesis", "Alice->Bob 1000", "Bob->Carol 1000", "Bob->Alice 1000 (conflict)", "merge fork", "", "" };
    for (1..8) |i| {
        const id = h(@intCast(i));
        const d = gd.get(id).?;
        std.debug.print("  block h{d}  blue_score={d:<2}  {s}\n", .{ i, d.blue_score, labels[i - 1] });
    }

    // --- apply in consensus order ---
    var set: utxo.UtxoSet = .{};
    var no_heights: std.AutoHashMapUnmanaged(hashmod.Hash256, u64) = .empty;
    const stats = try proc.applyOrder(gpa, &set, &gd, &blocks, &no_heights, .{});
    const order = try gd.order(gpa);

    std.debug.print("\nGHOSTDAG consensus order: ", .{});
    for (order) |id| {
        for (1..8) |i| {
            if (std.mem.eql(u8, &id, &h(@intCast(i)))) std.debug.print("h{d} ", .{i});
        }
    }
    std.debug.print("\n  applied={d}  rejected={d} (the losing double-spend)\n", .{ stats.applied, stats.rejected });

    const carol_won = balanceOf(set, carol.commitment) == 1000;
    std.debug.print("  double-spend resolved: Bob's coin went to {s}\n", .{if (carol_won) "Carol (h3 precedes h4 in the order)" else "Alice"});

    // --- balances ---
    std.debug.print("\nLedger balances:\n", .{});
    const wallets = [_]Wallet{ alice, bob, carol, miner };
    var total: u64 = 0;
    for (wallets) |wlt| {
        const bal = balanceOf(set, wlt.commitment);
        total += bal;
        std.debug.print("  {s:<6} {d:>5}\n", .{ wlt.name, bal });
    }
    std.debug.print("  ----------\n  supply {d:>5}  (1000 genesis + 6x50 coinbase = 1300, conserved)\n", .{total});

    // --- proof of work: actually mine each block header ---
    std.debug.print("\nProof-of-work (mining each block header to its difficulty target):\n", .{});
    const parent_sets = [_][]const Hash256{
        &.{}, &.{h(1)}, &.{h(2)}, &.{h(2)}, &.{ h(3), h(4) }, &.{h(5)}, &.{h(6)},
    };
    var total_iters: u64 = 0;
    for (blocks, 0..) |b, i| {
        var hdr = blk.BlockHeader{
            .version = 1,
            .parents = parent_sets[i],
            .timestamp = @intCast(1_700_000_000 + i),
            .merkle_root = hashmod.zero,
            .witness_root = hashmod.zero,
            .bits = powmod.easy_bits,
        };
        const body = blk.Block{ .header = hdr, .txs = b.txs };
        hdr.merkle_root = try body.computeMerkleRoot(gpa);
        hdr.witness_root = try body.computeWitnessRoot(gpa);
        const iters = try hdr.mine(gpa, 100_000_000);
        total_iters += iters;
        const ph = try hdr.powHash(gpa);
        std.debug.print("  block h{d}  nonce={d:<4} powhash={s}...  valid={}\n", .{
            i + 1, hdr.nonce, std.fmt.bytesToHex(ph, .lower)[0..12], try hdr.validatePow(gpa),
        });
    }
    std.debug.print("  total hashes searched: {d}\n", .{total_iters});

    // --- finality ---
    var validators_kp: [4]Wallet = .{ Wallet.init("V0", 100), Wallet.init("V1", 101), Wallet.init("V2", 102), Wallet.init("V3", 103) };
    var validators: [4]finality.Validator = undefined;
    for (&validators, 0..) |*v, i| v.* = .{ .scheme = .ml_dsa_44, .pubkey = &validators_kp[i].pk, .weight = 1 };
    const vset = finality.ValidatorSet.init(&validators);

    var gadget = finality.Gadget.init(gpa, vset, 2);
    const cut = gadget.candidate(&gd).?;

    std.debug.print(
        \\
        \\Post-quantum BFT finality (4 validators, quorum={d}, depth=2):
        \\  candidate cut = block at blue_score {d}
        \\
    , .{ vset.quorum(), cut.blue_score });

    for (0..3) |i| {
        const vote = finality.FinalityVote{
            .validator_index = @intCast(i),
            .cut_block = cut.block,
            .cut_blue_score = cut.blue_score,
            .signature = &validators_kp[i].sign(finality.voteMessage(cut)),
        };
        const res = try gadget.submitVote(vote);
        std.debug.print("  V{d} signs cut (ML-DSA) -> {s}\n", .{ i, @tagName(res) });
    }

    var finalized_blocks: usize = 0;
    for (1..8) |i| {
        if (gadget.isFinalized(&gd, h(@intCast(i)))) finalized_blocks += 1;
    }
    std.debug.print("  FINALIZED: blocks up to the cut are now irreversible ({d}/7 blocks final).\n", .{finalized_blocks});
    std.debug.print("\nThat is a self-minting, PQ-signed, DAG-ordered, BFT-finalized ledger.\n", .{});
}

fn coinbase(commitment: Hash256, value: u64, payload: []const u8) Transaction {
    const outs = std.heap.page_allocator.dupe(prim.Output, &.{.{ .value = value, .scheme = .ml_dsa_44, .commitment = commitment }}) catch unreachable;
    return .{ .version = 1, .inputs = &.{}, .outputs = outs, .witnesses = &.{}, .payload = payload };
}

fn spend(outpoint: prim.OutPoint, commitment: Hash256, value: u64) Transaction {
    const ins = std.heap.page_allocator.dupe(prim.Input, &.{.{ .outpoint = outpoint }}) catch unreachable;
    const outs = std.heap.page_allocator.dupe(prim.Output, &.{.{ .value = value, .scheme = .ml_dsa_44, .commitment = commitment }}) catch unreachable;
    return .{ .version = 1, .inputs = ins, .outputs = outs, .witnesses = &.{} };
}

fn wit(pubkey: []const u8, signature: []const u8) []const prim.Witness {
    return std.heap.page_allocator.dupe(prim.Witness, &.{.{ .scheme = .ml_dsa_44, .pubkey = pubkey, .signature = signature }}) catch unreachable;
}
