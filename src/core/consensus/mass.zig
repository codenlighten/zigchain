//! Block "mass" accounting — the DoS lever.
//!
//! Post-quantum signatures differ enormously in both verification cost and byte
//! size (an ML-DSA-44 witness is ~3.7 KB and cheap to verify; an SLH-DSA-128f
//! vault witness is ~17 KB and far costlier). Without accounting, an attacker
//! packs a block with the most expensive scheme and every node pays. "Mass"
//! folds both dimensions into one scalar that a block must stay under.
//!
//! mass(witness) = verify_mass(scheme)          // relative CPU cost
//!               + pubkey_bytes + signature_bytes // bandwidth cost (dominant)
//!
//! Bandwidth is our binding constraint, so byte size dominates the scalar by
//! design. The cap is a consensus parameter (pinned during Phase-0 alongside the
//! propagation model).

const std = @import("std");
const prim = @import("../primitives/types.zig");
const pq = @import("../crypto/pq/registry.zig");

pub const default_max_block_mass: u64 = 1_000_000;

pub const Error = error{BlockTooHeavy} || pq.Error;

fn addOrHeavy(a: u64, b: u64) Error!u64 {
    return std.math.add(u64, a, b) catch Error.BlockTooHeavy;
}

pub fn txMass(tx: prim.Transaction) Error!u64 {
    var m: u64 = 0;
    for (tx.witnesses) |w| {
        const meta = try pq.info(w.scheme);
        m = try addOrHeavy(m, meta.verify_mass);
        m = try addOrHeavy(m, w.pubkey.len);
        m = try addOrHeavy(m, w.signature.len);
    }
    return m;
}

pub fn blockMass(txs: []const prim.Transaction) Error!u64 {
    var total: u64 = 0;
    for (txs) |tx| total = try addOrHeavy(total, try txMass(tx));
    return total;
}

/// Returns the block mass, or `BlockTooHeavy` if it exceeds `max`.
pub fn checkBlockMass(txs: []const prim.Transaction, max: u64) Error!u64 {
    const m = try blockMass(txs);
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

test "mass reflects verify cost + byte size, dominated by bytes" {
    const tx = prim.Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }},
        .outputs = &.{},
        .witnesses = &.{dummyWitness(.ml_dsa_44)},
    };
    // 1 (verify_mass) + 1312 (pk) + 2420 (sig) = 3733
    try testing.expectEqual(@as(u64, 3733), try txMass(tx));
}

test "vault scheme is much heavier than the hot scheme" {
    const hot = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = &.{}, .witnesses = &.{dummyWitness(.ml_dsa_44)} };
    const vault = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = &.{}, .witnesses = &.{dummyWitness(.slh_dsa_128f)} };
    try testing.expect((try txMass(vault)) > 4 * (try txMass(hot)));
}

test "block over the cap is rejected; under the cap returns its mass" {
    const tx = prim.Transaction{ .version = 1, .inputs = &.{}, .outputs = &.{}, .witnesses = &.{dummyWitness(.ml_dsa_44)} };
    const txs = [_]prim.Transaction{ tx, tx, tx };
    try testing.expectEqual(@as(u64, 3 * 3733), try checkBlockMass(&txs, default_max_block_mass));
    try testing.expectError(Error.BlockTooHeavy, checkBlockMass(&txs, 5000));
}

test "unknown scheme propagates as a consensus error" {
    const tx = prim.Transaction{
        .version = 1,
        .inputs = &.{},
        .outputs = &.{},
        .witnesses = &.{.{ .scheme = @enumFromInt(0x7e), .pubkey = "x", .signature = "y" }},
    };
    try testing.expectError(pq.Error.UnknownScheme, txMass(tx));
}
