//! Proof-of-work: compact difficulty targets, target checking, and difficulty
//! retargeting. Zig's native fixed-width big integers (`u256`/`u512`) make the
//! 256-bit target arithmetic exact and painless.
//!
//! The PoW *hash function* is deliberately a separate concern from data hashing
//! (see the plan): it is the ZigChain heavy-hash (kHeavyHash-lineage — a per-block
//! matrix-vector product sandwiched between two `.pow`-domain hashes), which is
//! more ASIC/GPU-balanced than plain hashing. See `heavyhash.zig`. This module
//! owns only the difficulty *target* math (compact bits, target check, retarget);
//! the heavy-hash itself lives next door and is swappable in one place. Grover is
//! a non-threat to PoW (≤ quadratic, absorbed by difficulty), so the 256-bit
//! search space is ample.

const std = @import("std");

/// Bitcoin-style compact target ("nBits"): one exponent byte + 3 mantissa bytes.
/// Genesis-ish easy default used by tests/tools.
pub const easy_bits: u32 = 0x2000ffff;

/// Decode compact bits into a 256-bit target.
pub fn compactToTarget(bits: u32) u256 {
    const exponent: u32 = bits >> 24;
    const mantissa: u256 = bits & 0x007fffff;
    if (exponent <= 3) {
        return mantissa >> @intCast(8 * (3 - exponent));
    }
    const shift: u32 = 8 * (exponent - 3);
    if (shift >= 256) return std.math.maxInt(u256);
    return mantissa << @intCast(shift);
}

/// Encode a 256-bit target back into compact bits (canonical form).
pub fn targetToCompact(target: u256) u32 {
    // Number of significant bytes.
    var size: u32 = 0;
    var t = target;
    while (t != 0) : (t >>= 8) size += 1;

    var mantissa: u32 = undefined;
    if (size <= 3) {
        mantissa = @intCast(target << @intCast(8 * (3 - size)));
    } else {
        mantissa = @intCast(target >> @intCast(8 * (size - 3)));
    }
    // If the high bit of the mantissa is set, shift down (mantissa is signed-ish).
    if (mantissa & 0x00800000 != 0) {
        mantissa >>= 8;
        size += 1;
    }
    return (size << 24) | (mantissa & 0x007fffff);
}

/// Does a 32-byte PoW hash (interpreted big-endian) meet the difficulty `bits`?
pub fn meetsTarget(pow_hash: [32]u8, bits: u32) bool {
    const h = std.mem.readInt(u256, &pow_hash, .big);
    return h <= compactToTarget(bits);
}

/// The easiest allowed target (difficulty floor). Difficulty never drops below
/// this — retargeting clamps to it.
pub const pow_limit: u256 = compactToTargetComptime(0x2100ffff);

fn compactToTargetComptime(comptime bits: u32) u256 {
    @setEvalBranchQuota(10000);
    return compactToTarget(bits);
}

/// Retarget: given the difficulty of the previous window and how long that
/// window actually took vs how long it should have, compute the next `bits`.
/// The adjustment factor is clamped to [1/4, 4] to resist timestamp gaming.
pub fn retarget(old_bits: u32, actual_ms: u64, target_ms: u64) u32 {
    std.debug.assert(target_ms > 0);
    const lo = target_ms / 4;
    const hi = target_ms *| 4;
    const clamped: u64 = std.math.clamp(actual_ms, lo, hi);

    const old_target = compactToTarget(old_bits);
    // new = old * clamped / target_ms, computed in u512 to avoid overflow.
    const scaled: u512 = (@as(u512, old_target) * clamped) / target_ms;
    const capped: u512 = @min(scaled, @as(u512, pow_limit));
    return targetToCompact(@intCast(capped));
}

const testing = std.testing;

test "compact <-> target round-trips" {
    for ([_]u32{ 0x2000ffff, 0x1d00ffff, 0x1b0404cb, 0x2100ffff, 0x03123456 }) |bits| {
        const t = compactToTarget(bits);
        const back = targetToCompact(t);
        // Re-decoding the canonical compact form yields the same target.
        try testing.expectEqual(t, compactToTarget(back));
    }
}

test "meetsTarget: below target passes, above fails" {
    // easy_bits has a very high target, so a mid-range hash passes.
    var low = [_]u8{0} ** 32;
    low[2] = 0x01;
    try testing.expect(meetsTarget(low, easy_bits));

    // A hash that is all 0xFF exceeds any real target.
    const high = [_]u8{0xFF} ** 32;
    try testing.expect(!meetsTarget(high, 0x1d00ffff));
}

test "retarget: faster blocks raise difficulty (lower target), slower lower it" {
    const bits = 0x1d00ffff;
    const target_ms: u64 = 10_000;

    // Blocks came in twice as fast -> target should shrink (harder).
    const harder = retarget(bits, 5_000, target_ms);
    try testing.expect(compactToTarget(harder) < compactToTarget(bits));

    // Blocks came in twice as slow -> target should grow (easier).
    const easier = retarget(bits, 20_000, target_ms);
    try testing.expect(compactToTarget(easier) > compactToTarget(bits));
}

test "retarget clamps extreme timespans to a factor of 4" {
    const bits = 0x1d00ffff;
    const target_ms: u64 = 10_000;
    // Absurdly slow (100x) is clamped to 4x.
    const clamped = retarget(bits, 1_000_000, target_ms);
    const at_4x = retarget(bits, 40_000, target_ms);
    try testing.expectEqual(compactToTarget(at_4x), compactToTarget(clamped));
}

test "difficulty floor: retarget never eases past pow_limit" {
    const easy = targetToCompact(pow_limit);
    const eased = retarget(easy, 1_000_000, 10_000);
    try testing.expect(compactToTarget(eased) <= pow_limit);
}
