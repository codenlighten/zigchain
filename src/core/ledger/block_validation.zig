//! Context-free ("stateless") block validation.
//!
//! These are the checks a node can make on a block in isolation, before it has
//! placed the block in the DAG order — structure, commitments, mass, and the
//! coinbase subsidy bound. The *contextual* checks (does each input exist, is it
//! unspent, does its signature authorize the spend) depend on the GHOSTDAG order
//! and are performed by the processor as it connects transactions. Splitting the
//! two is exactly how a real node cheaply rejects malformed blocks before doing
//! expensive, order-dependent work.

const std = @import("std");
const prim = @import("../primitives/types.zig");
const blk = @import("../primitives/block.zig");
const mass = @import("../consensus/mass.zig");

const Block = blk.Block;

pub const Config = struct {
    /// Maximum newly-minted supply per block (fees are burned in v1, so the
    /// coinbase may claim at most the subsidy).
    subsidy: u64,
    max_block_mass: u64,
    /// The block's height; the coinbase payload must encode it (uniqueness).
    height: u64,
};

pub const Error = error{
    EmptyBlock,
    CoinbaseNotFirst,
    MultipleCoinbase,
    CoinbaseHasWitness,
    BadCoinbaseHeight,
    BadMerkleRoot,
    BadWitnessRoot,
    CoinbaseOverSubsidy,
    ValueOverflow,
} || mass.Error || std.mem.Allocator.Error;

pub fn validateStateless(gpa: std.mem.Allocator, block: Block, cfg: Config) Error!void {
    if (block.txs.len == 0) return Error.EmptyBlock;

    // Exactly one coinbase, and it is first.
    const coinbase = block.txs[0];
    if (!coinbase.isCoinbase()) return Error.CoinbaseNotFirst;
    if (coinbase.witnesses.len != 0) return Error.CoinbaseHasWitness;
    for (block.txs[1..]) |t| {
        if (t.isCoinbase()) return Error.MultipleCoinbase;
    }

    // Coinbase payload must BEGIN with the block height (little-endian u64).
    // Any trailing bytes are a miner extranonce — required because height is not
    // unique in a DAG (parallel blocks share a height), so the extranonce is
    // what keeps sibling coinbase txids distinct.
    if (coinbase.payload.len < 8) return Error.BadCoinbaseHeight;
    var height_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &height_bytes, cfg.height, .little);
    if (!std.mem.eql(u8, coinbase.payload[0..8], &height_bytes)) return Error.BadCoinbaseHeight;

    // Commitments must match the body.
    const mr = try block.computeMerkleRoot(gpa);
    if (!std.mem.eql(u8, &mr, &block.header.merkle_root)) return Error.BadMerkleRoot;
    const wr = try block.computeWitnessRoot(gpa);
    if (!std.mem.eql(u8, &wr, &block.header.witness_root)) return Error.BadWitnessRoot;

    // Signature-verification cost / size is bounded.
    _ = try mass.checkBlockMass(block.txs, cfg.max_block_mass);

    // Coinbase mints at most the subsidy.
    var cb_sum: u64 = 0;
    for (coinbase.outputs) |o| {
        cb_sum = std.math.add(u64, cb_sum, o.value) catch return Error.ValueOverflow;
    }
    if (cb_sum > cfg.subsidy) return Error.CoinbaseOverSubsidy;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const hashmod = @import("../crypto/hash.zig");

fn heightPayload(h: u64) [8]u8 {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, h, .little);
    return b;
}

test "valid coinbase-only block passes stateless validation" {
    const gpa = testing.allocator;
    const hp = heightPayload(1);
    const cb = prim.Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{.{ .value = 50, .scheme = .ml_dsa_44, .commitment = hashmod.zero }},
        .witnesses = &.{},
        .payload = &hp,
    };
    var block = Block{
        .header = .{ .version = 1, .parents = &.{}, .timestamp = 1, .merkle_root = undefined, .witness_root = undefined },
        .txs = &.{cb},
    };
    block.header.merkle_root = try block.computeMerkleRoot(gpa);
    block.header.witness_root = try block.computeWitnessRoot(gpa);

    try validateStateless(gpa, block, .{ .subsidy = 50, .max_block_mass = 1_000_000, .height = 1 });
}

test "coinbase over the subsidy is rejected" {
    const gpa = testing.allocator;
    const hp = heightPayload(1);
    const cb = prim.Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{.{ .value = 999, .scheme = .ml_dsa_44, .commitment = hashmod.zero }},
        .witnesses = &.{},
        .payload = &hp,
    };
    var block = Block{
        .header = .{ .version = 1, .parents = &.{}, .timestamp = 1, .merkle_root = undefined, .witness_root = undefined },
        .txs = &.{cb},
    };
    block.header.merkle_root = try block.computeMerkleRoot(gpa);
    block.header.witness_root = try block.computeWitnessRoot(gpa);

    try testing.expectError(Error.CoinbaseOverSubsidy, validateStateless(gpa, block, .{ .subsidy = 50, .max_block_mass = 1_000_000, .height = 1 }));
}

test "wrong coinbase height and missing coinbase are rejected" {
    const gpa = testing.allocator;
    const hp = heightPayload(9); // wrong height
    const cb = prim.Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{.{ .value = 10, .scheme = .ml_dsa_44, .commitment = hashmod.zero }},
        .witnesses = &.{},
        .payload = &hp,
    };
    var block = Block{
        .header = .{ .version = 1, .parents = &.{}, .timestamp = 1, .merkle_root = undefined, .witness_root = undefined },
        .txs = &.{cb},
    };
    block.header.merkle_root = try block.computeMerkleRoot(gpa);
    block.header.witness_root = try block.computeWitnessRoot(gpa);
    try testing.expectError(Error.BadCoinbaseHeight, validateStateless(gpa, block, .{ .subsidy = 50, .max_block_mass = 1_000_000, .height = 1 }));

    // A block whose first tx has inputs is not a coinbase-first block.
    const noncb = prim.Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }},
        .outputs = &.{},
        .witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = "x", .signature = "y" }},
    };
    var b2 = Block{
        .header = .{ .version = 1, .parents = &.{}, .timestamp = 1, .merkle_root = undefined, .witness_root = undefined },
        .txs = &.{noncb},
    };
    b2.header.merkle_root = try b2.computeMerkleRoot(gpa);
    b2.header.witness_root = try b2.computeWitnessRoot(gpa);
    try testing.expectError(Error.CoinbaseNotFirst, validateStateless(gpa, b2, .{ .subsidy = 50, .max_block_mass = 1_000_000, .height = 1 }));
}
