//! The UTXO set — the ledger's committed state.
//!
//! This is a single-map implementation with a small, intention-revealing API.
//! The interface (get / contains / add / spend by OutPoint) is deliberately the
//! one a *sharded* set will also expose, so Phase-2 sharding (partition by
//! OutPoint hash, per-shard lock, parallel lookups) is a drop-in replacement,
//! not a rewrite.
//!
//! Determinism note: the map is used only for keyed lookups. It is NEVER
//! iterated in a consensus-visible way (hash-map iteration order is unstable);
//! anything that must enumerate the set will sort first.

const std = @import("std");
const prim = @import("../primitives/types.zig");

const OutPoint = prim.OutPoint;
const Output = prim.Output;

pub const Error = error{DuplicateOutpoint} || std.mem.Allocator.Error;

pub const UtxoSet = struct {
    map: std.AutoHashMapUnmanaged(OutPoint, Output) = .empty,

    pub fn deinit(self: *UtxoSet, gpa: std.mem.Allocator) void {
        self.map.deinit(gpa);
    }

    pub fn count(self: UtxoSet) usize {
        return self.map.count();
    }

    pub fn get(self: UtxoSet, op: OutPoint) ?Output {
        return self.map.get(op);
    }

    pub fn contains(self: UtxoSet, op: OutPoint) bool {
        return self.map.contains(op);
    }

    /// Insert a new unspent output. A pre-existing outpoint is a consensus-level
    /// impossibility (txids are collision-resistant), so we surface it loudly.
    pub fn add(self: *UtxoSet, gpa: std.mem.Allocator, op: OutPoint, out: Output) Error!void {
        const gop = try self.map.getOrPut(gpa, op);
        if (gop.found_existing) return Error.DuplicateOutpoint;
        gop.value_ptr.* = out;
    }

    /// Remove a spent output. Returns true if it was present.
    pub fn spend(self: *UtxoSet, op: OutPoint) bool {
        return self.map.remove(op);
    }
};

const testing = std.testing;
const hashmod = @import("../crypto/hash.zig");

test "add / get / contains / spend / count" {
    const gpa = testing.allocator;
    var set: UtxoSet = .{};
    defer set.deinit(gpa);

    const op = OutPoint{ .txid = [_]u8{1} ** 32, .index = 0 };
    const out = Output{ .value = 500, .scheme = .ml_dsa_44, .commitment = hashmod.zero };

    try testing.expect(!set.contains(op));
    try set.add(gpa, op, out);
    try testing.expect(set.contains(op));
    try testing.expectEqual(@as(u64, 500), set.get(op).?.value);
    try testing.expectEqual(@as(usize, 1), set.count());

    try testing.expectError(Error.DuplicateOutpoint, set.add(gpa, op, out));

    try testing.expect(set.spend(op));
    try testing.expect(!set.contains(op));
    try testing.expect(!set.spend(op)); // already gone
    try testing.expectEqual(@as(usize, 0), set.count());
}
