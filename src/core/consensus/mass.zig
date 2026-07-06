//! Block "mass" accounting — the DoS lever and the fee base.
//!
//! A transaction's mass folds its two real costs into one scalar:
//!
//!   mass = serialized_bytes + Σ verify_cost(scheme)
//!
//! The byte term (bandwidth — the binding constraint) counts the WHOLE encoded
//! transaction, so a transaction with thousands of outputs pays for every byte
//! it puts on the wire, not just its signatures. The verify term weights the
//! per-scheme CPU cost so a block can't be packed with the most-expensive-to-
//! verify post-quantum scheme. The per-block cap bounds both at once.

const std = @import("std");
const prim = @import("../primitives/types.zig");
const pq = @import("../crypto/pq/registry.zig");
const codec = @import("../serialization/codec.zig");

pub const default_max_block_mass: u64 = 1_000_000;

pub const Error = error{BlockTooHeavy} || pq.Error || std.mem.Allocator.Error;

fn addOrHeavy(a: u64, b: u64) Error!u64 {
    return std.math.add(u64, a, b) catch Error.BlockTooHeavy;
}

pub fn txMass(gpa: std.mem.Allocator, tx: prim.Transaction) Error!u64 {
    // Full serialized footprint (body + segregated witnesses).
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try tx.encodeBody(&w);
    try tx.encodeWitnesses(&w);

    var m: u64 = @intCast(list.items.len);
    for (tx.witnesses) |wit| {
        const meta = try pq.info(wit.scheme);
        m = try addOrHeavy(m, meta.verify_mass);
    }
    return m;
}

pub fn blockMass(gpa: std.mem.Allocator, txs: []const prim.Transaction) Error!u64 {
    var total: u64 = 0;
    for (txs) |tx| total = try addOrHeavy(total, try txMass(gpa, tx));
    return total;
}

/// Returns the block mass, or `BlockTooHeavy` if it exceeds `max`.
pub fn checkBlockMass(gpa: std.mem.Allocator, txs: []const prim.Transaction, max: u64) Error!u64 {
    const m = try blockMass(gpa, txs);
    if (m > max) return Error.BlockTooHeavy;
    return m;
}

const testing = std.testing;
const hashmod = @import("../crypto/hash.zig");

fn dummyWitness(comptime scheme: pq.SchemeTag) prim.Witness {
    const info = pq.info(scheme) catch unreachable;
    const pk = [_]u8{0} ** 4096;
    const sig = [_]u8{0} ** 32768;
    return .{ .scheme = scheme, .pubkey = pk[0..info.pubkey_len], .signature = sig[0..info.sig_len] };
}

test "mass counts full serialized bytes plus verify cost" {
    const gpa = testing.allocator;
    const tx = prim.Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }},
        .outputs = &.{.{ .value = 1, .scheme = .ml_dsa_44, .commitment = hashmod.zero }},
        .witnesses = &.{dummyWitness(.ml_dsa_44)},
    };
    // The signature dominates the byte count; mass must exceed the raw sig size.
    const m = try txMass(gpa, tx);
    try testing.expect(m > 2420);
}

test "a settlement tx with many outputs pays for its bytes" {
    const gpa = testing.allocator;
    const outs = try gpa.alloc(prim.Output, 1000);
    defer gpa.free(outs);
    for (outs) |*o| o.* = .{ .value = 1, .scheme = .ml_dsa_44, .commitment = hashmod.zero };
    const big = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = outs, .witnesses = &.{} };
    const small = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = &.{}, .witnesses = &.{} };
    // 1000 outputs (~41 KB) weigh far more than an empty tx — the old model
    // (witness bytes only) would have rated both near zero.
    try testing.expect((try txMass(gpa, big)) > (try txMass(gpa, small)) + 40_000);
}

test "vault scheme is heavier than the hot scheme (verify + bytes)" {
    const gpa = testing.allocator;
    const hot = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = &.{}, .witnesses = &.{dummyWitness(.ml_dsa_44)} };
    const vault = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = &.{}, .witnesses = &.{dummyWitness(.slh_dsa_128f)} };
    try testing.expect((try txMass(gpa, vault)) > (try txMass(gpa, hot)));
}

test "block over the cap is rejected" {
    const gpa = testing.allocator;
    const tx = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = &.{}, .witnesses = &.{dummyWitness(.ml_dsa_44)} };
    const txs = [_]prim.Transaction{ tx, tx, tx };
    _ = try checkBlockMass(gpa, &txs, default_max_block_mass);
    try testing.expectError(Error.BlockTooHeavy, checkBlockMass(gpa, &txs, 5000));
}

test "unknown scheme propagates as a consensus error" {
    const gpa = testing.allocator;
    const tx = prim.Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{},
        .witnesses = &.{.{ .scheme = @enumFromInt(0x7e), .pubkey = "x", .signature = "y" }},
    };
    try testing.expectError(pq.Error.UnknownScheme, txMass(gpa, tx));
}
