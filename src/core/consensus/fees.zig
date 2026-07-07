//! Fee model.
//!
//! A transaction's fee floor is proportional to the block "mass" it consumes
//! (verification cost + bytes — see mass.zig), so fees track the real resource a
//! transaction burns. The key to sub-penny settlement is not a low rate per se
//! but AMORTISATION: one settlement transaction can net thousands of transfers
//! into a handful of inputs and many small outputs, so the (dominant) signature
//! cost is paid once and the per-transfer fee collapses. `perTransferZats`
//! expresses that.

const std = @import("std");
const prim = @import("../primitives/types.zig");
const massmod = @import("mass.zig");

/// Base units per token ("zats"), 8 decimals — like a satoshi.
pub const base_per_token: u64 = 100_000_000;

pub const FeeParams = struct {
    /// Fee per unit of mass, in base units.
    rate_per_mass: u64 = 1,
};

/// Economic rules the ledger applies while connecting a block's transactions.
/// Threaded (unchanged) through both the incremental engine and the
/// recompute oracle so the two cannot diverge.
pub const Policy = struct {
    /// A coinbase output — and any fee tip minted to a producer — cannot be
    /// spent until this many blocks deep. 0 disables the check.
    maturity: u64 = 0,
    /// Mandatory base fee per unit of mass, in base units. The base portion of
    /// every fee is BURNED (removed from supply). 0 means no base fee.
    base_fee_rate: u64 = 0,
    /// When true, the tip (the fee above the base) is minted to the block's
    /// coinbase beneficiary — the EIP-1559 producer reward. When false the whole
    /// fee is burned (the v1 default and the model the ledger unit tests assume).
    collect_tips: bool = false,
};

pub const Split = struct { base: u64, tip: u64 };

/// EIP-1559 split of a transaction's `fee` given the `tx_mass` it consumes: the
/// base is the mass-proportional floor (burned), the tip is whatever the sender
/// attached on top (paid to the producer). A fee below the floor pays all of
/// itself as base and tips nothing — the mandatory-minimum-fee *rejection* is a
/// mempool/relay policy at the edge, not a consensus rule, so this never
/// underflows and never invalidates a block.
pub fn split(fee: u64, tx_mass: u64, base_fee_rate: u64) Split {
    const base = @min(fee, tx_mass *| base_fee_rate);
    return .{ .base = base, .tip = fee - base };
}

/// The fee floor a transaction pays: its mass times the rate.
pub fn txFeeZats(gpa: std.mem.Allocator, tx: prim.Transaction, params: FeeParams) massmod.Error!u64 {
    const m = try massmod.txMass(gpa, tx);
    return m *| params.rate_per_mass;
}

/// When one transaction settles `transfers` net positions (many outputs), the
/// per-transfer fee is the total fee spread across them.
pub fn perTransferZats(total_fee: u64, transfers: usize) u64 {
    if (transfers == 0) return total_fee;
    return total_fee / @as(u64, @intCast(transfers));
}

const testing = std.testing;
const hashmod = @import("../crypto/hash.zig");

test "fee is mass * rate; amortises across a settlement batch" {
    // A settlement tx: one input (one signature) paying 1000 outputs.
    const outs = try testing.allocator.alloc(prim.Output, 1000);
    defer testing.allocator.free(outs);
    for (outs) |*o| o.* = .{ .value = 100, .scheme = .ml_dsa_44, .commitment = hashmod.zero };

    const pk = [_]u8{0} ** 1312;
    const sig = [_]u8{0} ** 2420;
    const tx = prim.Transaction{
        .version = 1,
        .inputs = &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }},
        .outputs = outs,
        .witnesses = &.{.{ .scheme = .ml_dsa_44, .pubkey = &pk, .signature = &sig }},
    };

    const fee = try txFeeZats(testing.allocator, tx, .{ .rate_per_mass = 1 });
    // mass now includes the whole serialized tx (1000 outputs + one signature).
    // The per-transfer fee is still tiny — the signature is paid once.
    const per = perTransferZats(fee, 1000);
    try testing.expect(per > 0 and per < 100);
}

test "EIP-1559 split: base is the mass floor (burned), tip is the surplus" {
    // fee 1000, mass 100, rate 3 -> base 300 burned, tip 700 to the producer.
    const a = split(1000, 100, 3);
    try testing.expectEqual(@as(u64, 300), a.base);
    try testing.expectEqual(@as(u64, 700), a.tip);
    // No base fee configured -> the whole fee is a tip.
    const b = split(1000, 100, 0);
    try testing.expectEqual(@as(u64, 0), b.base);
    try testing.expectEqual(@as(u64, 1000), b.tip);
    // Fee below the floor: it all becomes base, tips nothing, never underflows.
    const c = split(50, 100, 3); // floor 300 > fee 50
    try testing.expectEqual(@as(u64, 50), c.base);
    try testing.expectEqual(@as(u64, 0), c.tip);
    // Floor computation saturates instead of overflowing.
    const d = split(std.math.maxInt(u64), std.math.maxInt(u64), 2);
    try testing.expectEqual(@as(u64, 0), d.tip); // base saturates to the whole fee
}
