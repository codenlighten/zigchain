//! Sharded UTXO set — the horizontal-scale storage for the ledger state.
//!
//! Coins are partitioned across shards by their outpoint, each shard guarded by
//! its own lock. Because a coin lives in exactly one shard and most transactions
//! touch unrelated coins, validation threads contend rarely: an operation on a
//! given coin serialises only against other operations on THAT coin's shard.
//! This is the single-node form of the same
//! partitioning that later lets different nodes hold different shards — the real
//! path past one machine's memory and bandwidth for global-settlement state.
//!
//! It exposes the same get/add/spend/contains/count surface as the simple
//! `UtxoSet`, so it is a drop-in replacement once parallel validation lands.

const std = @import("std");
const prim = @import("../primitives/types.zig");

const OutPoint = prim.OutPoint;
const Output = prim.Output;

pub const Error = error{DuplicateOutpoint} || std.mem.Allocator.Error;

/// Minimal per-shard spinlock. 0.16 moved Mutex/RwLock behind the async `Io`
/// interface; a spinlock over an atomic flag keeps this component Io-free, and
/// with many shards contention is rare enough that spinning is cheap. (A shared
/// read lock would allow concurrent reads — a later refinement.)
const SpinLock = struct {
    flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    fn lock(self: *SpinLock) void {
        while (self.flag.swap(true, .acquire)) std.atomic.spinLoopHint();
    }
    fn unlock(self: *SpinLock) void {
        self.flag.store(false, .release);
    }
};

pub const ShardedUtxoSet = struct {
    const Shard = struct {
        lock: SpinLock = .{},
        map: std.AutoHashMapUnmanaged(OutPoint, Output) = .empty,
    };

    gpa: std.mem.Allocator,
    shards: []Shard,

    pub fn init(gpa: std.mem.Allocator, num_shards: usize) !ShardedUtxoSet {
        std.debug.assert(num_shards > 0);
        const shards = try gpa.alloc(Shard, num_shards);
        for (shards) |*s| s.* = .{};
        return .{ .gpa = gpa, .shards = shards };
    }

    pub fn deinit(self: *ShardedUtxoSet) void {
        for (self.shards) |*s| s.map.deinit(self.gpa);
        self.gpa.free(self.shards);
    }

    fn shardOf(self: *ShardedUtxoSet, op: OutPoint) *Shard {
        // Outpoint txids are collision-resistant hashes, hence uniform — the top
        // 8 bytes make a good, cheap shard selector.
        const h = std.mem.readInt(u64, op.txid[0..8], .little);
        return &self.shards[@intCast(h % self.shards.len)];
    }

    pub fn add(self: *ShardedUtxoSet, op: OutPoint, out: Output) Error!void {
        const s = self.shardOf(op);
        s.lock.lock();
        defer s.lock.unlock();
        const gop = try s.map.getOrPut(self.gpa, op);
        if (gop.found_existing) return Error.DuplicateOutpoint;
        gop.value_ptr.* = out;
    }

    pub fn get(self: *ShardedUtxoSet, op: OutPoint) ?Output {
        const s = self.shardOf(op);
        s.lock.lock();
        defer s.lock.unlock();
        return s.map.get(op);
    }

    pub fn contains(self: *ShardedUtxoSet, op: OutPoint) bool {
        const s = self.shardOf(op);
        s.lock.lock();
        defer s.lock.unlock();
        return s.map.contains(op);
    }

    pub fn spend(self: *ShardedUtxoSet, op: OutPoint) bool {
        const s = self.shardOf(op);
        s.lock.lock();
        defer s.lock.unlock();
        return s.map.remove(op);
    }

    pub fn count(self: *ShardedUtxoSet) usize {
        var total: usize = 0;
        for (self.shards) |*s| {
            s.lock.lock();
            total += s.map.count();
            s.lock.unlock();
        }
        return total;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const hashmod = @import("../crypto/hash.zig");

fn opOf(a: u8, b: u32) OutPoint {
    var txid: [32]u8 = [_]u8{a} ** 32;
    std.mem.writeInt(u32, txid[8..12], b, .little); // vary beyond the shard-selector bytes
    return .{ .txid = txid, .index = 0 };
}

test "sharded set: basic add/get/spend/count across shards" {
    const gpa = testing.allocator;
    var set = try ShardedUtxoSet.init(gpa, 16);
    defer set.deinit();

    for (0..100) |i| {
        try set.add(opOf(1, @intCast(i)), .{ .value = i, .scheme = .ml_dsa_44, .commitment = hashmod.zero });
    }
    try testing.expectEqual(@as(usize, 100), set.count());
    try testing.expectEqual(@as(u64, 42), set.get(opOf(1, 42)).?.value);
    try testing.expect(set.spend(opOf(1, 42)));
    try testing.expect(!set.contains(opOf(1, 42)));
    try testing.expectEqual(@as(usize, 99), set.count());
    try testing.expectError(Error.DuplicateOutpoint, set.add(opOf(1, 0), .{ .value = 0, .scheme = .ml_dsa_44, .commitment = hashmod.zero }));
}

const Worker = struct {
    set: *ShardedUtxoSet,
    tag: u8,
    n: u32,
    fn run(self: *Worker) void {
        for (0..self.n) |i| {
            self.set.add(opOf(self.tag, @intCast(i)), .{ .value = i, .scheme = .ml_dsa_44, .commitment = hashmod.zero }) catch unreachable;
        }
    }
};

test "sharded set: concurrent inserts from many threads are correct" {
    const gpa = testing.allocator;
    var set = try ShardedUtxoSet.init(gpa, 64);
    defer set.deinit();

    const T = 8;
    const per = 500;
    var workers: [T]Worker = undefined;
    var threads: [T]std.Thread = undefined;
    for (0..T) |t| {
        workers[t] = .{ .set = &set, .tag = @intCast(t + 1), .n = per };
        threads[t] = try std.Thread.spawn(.{}, Worker.run, .{&workers[t]});
    }
    for (threads) |th| th.join();

    // Every disjoint coin from every thread is present exactly once.
    try testing.expectEqual(@as(usize, T * per), set.count());
    for (0..T) |t| {
        try testing.expect(set.contains(opOf(@intCast(t + 1), 0)));
        try testing.expect(set.contains(opOf(@intCast(t + 1), per - 1)));
    }
}
