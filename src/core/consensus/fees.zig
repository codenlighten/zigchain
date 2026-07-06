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

/// The fee floor a transaction pays: its mass times the rate.
pub fn txFeeZats(tx: prim.Transaction, params: FeeParams) massmod.Error!u64 {
    const m = try massmod.txMass(tx);
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

    const fee = try txFeeZats(tx, .{ .rate_per_mass = 1 });
    // mass = 1 (verify) + 1312 + 2420 = 3733 (dominated by the single signature).
    try testing.expectEqual(@as(u64, 3733), fee);

    // Spread over 1000 transfers, the per-transfer fee is a few zats.
    try testing.expectEqual(@as(u64, 3), perTransferZats(fee, 1000));
}
