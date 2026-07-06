//! The BlockDAG store and a *deterministic* topological order.
//!
//! Every node references a set of parent block ids. This module owns the graph
//! structure and answers reachability / ordering queries. The topological order
//! here is the neutral substrate GHOSTDAG builds on: given the same DAG, every
//! implementation MUST produce byte-identical output, so ties are broken by
//! block-id hash (ascending, lexicographic). Any nondeterminism here is a
//! consensus split, so the order is fixed and tested, not incidental.

const std = @import("std");
const hashmod = @import("../crypto/hash.zig");

const Hash256 = hashmod.Hash256;

pub const Error = error{
    DuplicateBlock,
    MissingParent,
    Cycle,
} || std.mem.Allocator.Error;

/// Lexicographic ascending order on 32-byte ids — the canonical tie-break.
fn hashLess(_: void, a: Hash256, b: Hash256) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

pub const Dag = struct {
    gpa: std.mem.Allocator,
    /// block id -> owned slice of parent ids.
    nodes: std.AutoHashMapUnmanaged(Hash256, []Hash256) = .empty,

    pub fn init(gpa: std.mem.Allocator) Dag {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Dag) void {
        var it = self.nodes.iterator();
        while (it.next()) |e| self.gpa.free(e.value_ptr.*);
        self.nodes.deinit(self.gpa);
    }

    pub fn contains(self: Dag, id: Hash256) bool {
        return self.nodes.contains(id);
    }

    pub fn count(self: Dag) usize {
        return self.nodes.count();
    }

    pub fn parentsOf(self: Dag, id: Hash256) ?[]const Hash256 {
        return self.nodes.get(id);
    }

    /// Add a block. All parents must already be present (a DAG is built in
    /// dependency order), and the id must be new.
    pub fn addBlock(self: *Dag, id: Hash256, parents: []const Hash256) Error!void {
        if (self.contains(id)) return Error.DuplicateBlock;
        for (parents) |p| if (!self.contains(p)) return Error.MissingParent;
        const owned = try self.gpa.dupe(Hash256, parents);
        errdefer self.gpa.free(owned);
        try self.nodes.put(self.gpa, id, owned);
    }

    /// Deterministic topological order: parents strictly precede children, ties
    /// broken by ascending id. Caller owns the returned slice.
    pub fn topoOrder(self: Dag, gpa: std.mem.Allocator) Error![]Hash256 {
        var indeg: std.AutoHashMapUnmanaged(Hash256, usize) = .empty;
        defer indeg.deinit(gpa);
        var children: std.AutoHashMapUnmanaged(Hash256, std.ArrayList(Hash256)) = .empty;
        defer {
            var cit = children.iterator();
            while (cit.next()) |e| e.value_ptr.deinit(gpa);
            children.deinit(gpa);
        }

        // Build in-degrees and child adjacency.
        var it = self.nodes.iterator();
        while (it.next()) |e| {
            const id = e.key_ptr.*;
            const parents = e.value_ptr.*;
            try indeg.put(gpa, id, parents.len);
            for (parents) |p| {
                const gop = try children.getOrPut(gpa, p);
                if (!gop.found_existing) gop.value_ptr.* = .empty;
                try gop.value_ptr.append(gpa, id);
            }
        }

        // Ready = in-degree 0. Kahn's algorithm, always emitting the smallest
        // ready id so the result is unique for a given DAG.
        var ready: std.ArrayList(Hash256) = .empty;
        defer ready.deinit(gpa);
        var di = indeg.iterator();
        while (di.next()) |e| {
            if (e.value_ptr.* == 0) try ready.append(gpa, e.key_ptr.*);
        }

        var out: std.ArrayList(Hash256) = .empty;
        errdefer out.deinit(gpa);

        while (ready.items.len > 0) {
            // Select and remove the minimum-id ready node.
            var min_i: usize = 0;
            for (ready.items, 0..) |candidate, i| {
                if (hashLess({}, candidate, ready.items[min_i])) min_i = i;
            }
            const id = ready.swapRemove(min_i);
            try out.append(gpa, id);

            if (children.get(id)) |kids| {
                for (kids.items) |c| {
                    const e = indeg.getPtr(c).?;
                    e.* -= 1;
                    if (e.* == 0) try ready.append(gpa, c);
                }
            }
        }

        if (out.items.len != self.nodes.count()) {
            out.deinit(gpa);
            return Error.Cycle;
        }
        return out.toOwnedSlice(gpa);
    }
};

const testing = std.testing;

fn h(byte: u8) Hash256 {
    return [_]u8{byte} ** 32;
}

test "addBlock enforces parent presence and uniqueness" {
    var dag = Dag.init(testing.allocator);
    defer dag.deinit();

    try dag.addBlock(h(1), &.{}); // genesis
    try testing.expectError(Error.DuplicateBlock, dag.addBlock(h(1), &.{}));
    try testing.expectError(Error.MissingParent, dag.addBlock(h(2), &.{h(9)}));
    try dag.addBlock(h(2), &.{h(1)});
    try testing.expectEqual(@as(usize, 2), dag.count());
}

test "topological order: parents precede children, deterministic tie-break" {
    const gpa = testing.allocator;
    var dag = Dag.init(gpa);
    defer dag.deinit();

    // Diamond: 1 -> {2,3} -> 4, with 2 and 3 independent (tie broken by id).
    try dag.addBlock(h(1), &.{});
    try dag.addBlock(h(3), &.{h(1)});
    try dag.addBlock(h(2), &.{h(1)});
    try dag.addBlock(h(4), &.{ h(2), h(3) });

    const order = try dag.topoOrder(gpa);
    defer gpa.free(order);

    // Unique order for this DAG: genesis, then smaller id (2) before (3), then 4.
    try testing.expectEqualSlices(u8, &h(1), &order[0]);
    try testing.expectEqualSlices(u8, &h(2), &order[1]);
    try testing.expectEqualSlices(u8, &h(3), &order[2]);
    try testing.expectEqualSlices(u8, &h(4), &order[3]);

    // Insertion order must not affect the result.
    var dag2 = Dag.init(gpa);
    defer dag2.deinit();
    try dag2.addBlock(h(1), &.{});
    try dag2.addBlock(h(2), &.{h(1)});
    try dag2.addBlock(h(3), &.{h(1)});
    try dag2.addBlock(h(4), &.{ h(3), h(2) });
    const order2 = try dag2.topoOrder(gpa);
    defer gpa.free(order2);
    try testing.expectEqualSlices(Hash256, order, order2);
}
