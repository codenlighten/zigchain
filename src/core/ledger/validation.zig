//! Transaction validation and the UTXO state transition.
//!
//! `validateTx` is a pure predicate over a UTXO view — it mutates nothing and
//! returns the fee. `connectTx` applies an already-validated transaction. The
//! split matters: validation can run in parallel across a block's transactions
//! (it is read-only), and only the tiny `connectTx` mutation must be serialised
//! in the DAG's linearised order.

const std = @import("std");
const prim = @import("../primitives/types.zig");
const utxo = @import("utxo.zig");

const Transaction = prim.Transaction;
const OutPoint = prim.OutPoint;
const UtxoSet = utxo.UtxoSet;

pub const Error = error{
    WitnessCountMismatch,
    MissingInput,
    DuplicateInput,
    SchemeMismatch,
    ValueOverflow,
    Unbalanced, // outputs exceed inputs
} || prim.SpendError || std.mem.Allocator.Error;

/// Validate a non-coinbase transaction against `set`. Returns the fee
/// (sum(inputs) - sum(outputs)). Does not mutate the set.
pub fn validateTx(set: *const UtxoSet, tx: Transaction, gpa: std.mem.Allocator) Error!u64 {
    if (tx.witnesses.len != tx.inputs.len) return Error.WitnessCountMismatch;

    // Detect double-spends *within* this transaction.
    var seen: std.AutoHashMapUnmanaged(OutPoint, void) = .empty;
    defer seen.deinit(gpa);

    var in_sum: u64 = 0;
    for (tx.inputs, tx.witnesses) |input, witness| {
        const op = input.outpoint;
        const gop = try seen.getOrPut(gpa, op);
        if (gop.found_existing) return Error.DuplicateInput;

        const coin = set.get(op) orelse return Error.MissingInput;
        if (witness.scheme != coin.scheme) return Error.SchemeMismatch;

        // The sighash binds this input's scheme tag; verifySpend checks the
        // (scheme, pubkey) commitment then the post-quantum signature.
        const msg = try tx.sighash(gpa, witness.scheme);
        try prim.verifySpend(witness, coin.commitment, msg);

        in_sum = std.math.add(u64, in_sum, coin.value) catch return Error.ValueOverflow;
    }

    var out_sum: u64 = 0;
    for (tx.outputs) |o| {
        out_sum = std.math.add(u64, out_sum, o.value) catch return Error.ValueOverflow;
    }

    if (out_sum > in_sum) return Error.Unbalanced;
    return in_sum - out_sum;
}

/// Apply a validated transaction: remove spent inputs, create new outputs keyed
/// by (txid, index). Must be called only after `validateTx` succeeded.
pub fn connectTx(set: *UtxoSet, tx: Transaction, gpa: std.mem.Allocator) !void {
    const id = try tx.txid(gpa);
    for (tx.inputs) |input| {
        const removed = set.spend(input.outpoint);
        std.debug.assert(removed); // guaranteed by prior validateTx
    }
    for (tx.outputs, 0..) |o, i| {
        try set.add(gpa, .{ .txid = id, .index = @intCast(i) }, o);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const hashmod = @import("../crypto/hash.zig");
const pq = @import("../crypto/pq/registry.zig");
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

const TestKey = struct {
    kp: MlDsa44.KeyPair,
    pk: [MlDsa44.PublicKey.encoded_length]u8,

    fn init(seed: u8) TestKey {
        const kp = MlDsa44.KeyPair.generateDeterministic([_]u8{seed} ** 32) catch unreachable;
        return .{ .kp = kp, .pk = kp.public_key.toBytes() };
    }
    fn commitment(self: TestKey) hashmod.Hash256 {
        return prim.addressCommitment(.ml_dsa_44, &self.pk);
    }
    fn sign(self: TestKey, sighash: hashmod.Hash256) [MlDsa44.Signature.encoded_length]u8 {
        const ctx = [_]u8{@intFromEnum(pq.SchemeTag.ml_dsa_44)};
        return (self.kp.signWithContext(&sighash, null, &ctx) catch unreachable).toBytes();
    }
};

test "valid spend: fee is correct and state transition applies" {
    const gpa = testing.allocator;
    var set: UtxoSet = .{};
    defer set.deinit(gpa);

    const alice = TestKey.init(1);
    const bob = TestKey.init(2);

    const funding = OutPoint{ .txid = [_]u8{0xAA} ** 32, .index = 0 };
    try set.add(gpa, funding, .{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() });

    var tx = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = funding }},
        .outputs = &.{.{ .value = 900, .scheme = .ml_dsa_44, .commitment = bob.commitment() }},
        .witnesses = &.{},
    };
    const sh = try tx.sighash(gpa, .ml_dsa_44);
    const sig = alice.sign(sh);
    tx.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sig }};

    try testing.expectEqual(@as(u64, 100), try validateTx(&set, tx, gpa));

    try connectTx(&set, tx, gpa);
    try testing.expect(!set.contains(funding)); // input consumed
    const id = try tx.txid(gpa);
    try testing.expect(set.contains(.{ .txid = id, .index = 0 })); // output created
    try testing.expectEqual(@as(usize, 1), set.count());
}

test "missing input is rejected" {
    const gpa = testing.allocator;
    var set: UtxoSet = .{};
    defer set.deinit(gpa);
    const alice = TestKey.init(1);

    var tx = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = [_]u8{0xBB} ** 32, .index = 7 } }},
        .outputs = &.{.{ .value = 1, .scheme = .ml_dsa_44, .commitment = alice.commitment() }},
        .witnesses = &.{},
    };
    const sh = try tx.sighash(gpa, .ml_dsa_44);
    const sig = alice.sign(sh);
    tx.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sig }};

    try testing.expectError(Error.MissingInput, validateTx(&set, tx, gpa));
}

test "in-transaction double-spend is rejected" {
    const gpa = testing.allocator;
    var set: UtxoSet = .{};
    defer set.deinit(gpa);
    const alice = TestKey.init(1);

    const funding = OutPoint{ .txid = [_]u8{0xCC} ** 32, .index = 0 };
    try set.add(gpa, funding, .{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() });

    var tx = Transaction{
        .version = 1,
        .inputs = &.{ .{ .outpoint = funding }, .{ .outpoint = funding } }, // same coin twice
        .outputs = &.{.{ .value = 10, .scheme = .ml_dsa_44, .commitment = alice.commitment() }},
        .witnesses = &.{},
    };
    const sh = try tx.sighash(gpa, .ml_dsa_44);
    const sig = alice.sign(sh);
    tx.witnesses = &.{
        .{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sig },
        .{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sig },
    };

    try testing.expectError(Error.DuplicateInput, validateTx(&set, tx, gpa));
}

test "unbalanced transaction (outputs > inputs) is rejected" {
    const gpa = testing.allocator;
    var set: UtxoSet = .{};
    defer set.deinit(gpa);
    const alice = TestKey.init(1);

    const funding = OutPoint{ .txid = [_]u8{0xDD} ** 32, .index = 0 };
    try set.add(gpa, funding, .{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() });

    var tx = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = funding }},
        .outputs = &.{.{ .value = 2000, .scheme = .ml_dsa_44, .commitment = alice.commitment() }}, // mints value
        .witnesses = &.{},
    };
    const sh = try tx.sighash(gpa, .ml_dsa_44);
    const sig = alice.sign(sh);
    tx.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = &alice.pk, .signature = &sig }};

    try testing.expectError(Error.Unbalanced, validateTx(&set, tx, gpa));
}

test "forged witness (wrong key) is rejected as commitment mismatch" {
    const gpa = testing.allocator;
    var set: UtxoSet = .{};
    defer set.deinit(gpa);
    const alice = TestKey.init(1);
    const mallory = TestKey.init(99);

    const funding = OutPoint{ .txid = [_]u8{0xEE} ** 32, .index = 0 };
    try set.add(gpa, funding, .{ .value = 1000, .scheme = .ml_dsa_44, .commitment = alice.commitment() });

    var tx = Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = funding }},
        .outputs = &.{.{ .value = 900, .scheme = .ml_dsa_44, .commitment = mallory.commitment() }},
        .witnesses = &.{},
    };
    const sh = try tx.sighash(gpa, .ml_dsa_44);
    const sig = mallory.sign(sh); // Mallory signs with her own key
    tx.witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = &mallory.pk, .signature = &sig }};

    // Mallory's pubkey does not hash to Alice's committed output.
    try testing.expectError(prim.SpendError.CommitmentMismatch, validateTx(&set, tx, gpa));
}
