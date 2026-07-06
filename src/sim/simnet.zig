//! Phase-0 network propagation simulation.
//!
//! This is an *analysis tool*, not consensus code — floats are fine here, and it
//! is kept deterministic by seeding the PRNG. It answers the question the whole
//! design hinges on: at a given block rate and (post-quantum-fat) block size,
//! does GHOSTDAG stay healthy, or does the DAG widen into wasted work?
//!
//! Method: a discrete-event gossip simulation produces a real BlockDAG (miners
//! reference the tips they currently know; blocks propagate with delay
//! `latency + size/bandwidth`). That DAG is then colored by the *actual*
//! `Ghostdag` implementation, and we measure the fraction of blocks left RED
//! (orphaned work) under the virtual coloring, plus the maximum mergeset size
//! (which bounds the required security parameter k).
//!
//! The feasible `(block_rate, block_size, k)` envelope is where the red fraction
//! stays low. That envelope is a required input to the consensus parameters and
//! must be justified before mainnet (see the plan's Phase-0 gate).

const std = @import("std");
const hashmod = @import("../core/crypto/hash.zig");
const Dag = @import("../core/consensus/dag.zig").Dag;
const Ghostdag = @import("../core/consensus/ghostdag.zig").Ghostdag;

const Hash256 = hashmod.Hash256;

pub const Params = struct {
    n_nodes: u32 = 20,
    peers_per_node: u32 = 4,
    bandwidth_bps: u64 = 12_500_000, // 100 Mbit/s in bytes/sec
    latency_ns: u64 = 50_000_000, // 50 ms base link latency
    block_size_bytes: u64 = 4_000, // ~one ML-DSA-44 tx; scale up for full blocks
    block_rate_per_sec: f64 = 1.0, // aggregate network block rate (lambda)
    duration_sec: f64 = 60.0,
    k: u32 = 4,
    seed: u64 = 1,
};

pub const Metrics = struct {
    blocks: u32,
    blue: u32,
    reds: u32,
    red_fraction: f64,
    max_mergeset: u32,
    /// Expected blocks produced within one propagation delay ≈ lambda * D.
    /// A rough lower bound on the concurrency k must tolerate.
    expected_concurrency: f64,
};

const EventKind = enum(u8) { mine = 0, arrival = 1 };
const Event = struct {
    time: u64,
    kind: EventKind,
    node: u32,
    block: u32,
};

fn eventLess(a: Event, b: Event) bool {
    if (a.time != b.time) return a.time < b.time;
    if (a.kind != b.kind) return @intFromEnum(a.kind) < @intFromEnum(b.kind);
    if (a.node != b.node) return a.node < b.node;
    return a.block < b.block;
}

/// Minimal deterministic binary min-heap over events.
const Heap = struct {
    items: std.ArrayList(Event) = .empty,

    fn deinit(self: *Heap, gpa: std.mem.Allocator) void {
        self.items.deinit(gpa);
    }
    fn push(self: *Heap, gpa: std.mem.Allocator, e: Event) !void {
        try self.items.append(gpa, e);
        var i = self.items.items.len - 1;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (eventLess(self.items.items[i], self.items.items[parent])) {
                std.mem.swap(Event, &self.items.items[i], &self.items.items[parent]);
                i = parent;
            } else break;
        }
    }
    fn pop(self: *Heap) ?Event {
        const n = self.items.items.len;
        if (n == 0) return null;
        const top = self.items.items[0];
        self.items.items[0] = self.items.items[n - 1];
        _ = self.items.pop();
        var i: usize = 0;
        const len = self.items.items.len;
        while (true) {
            const l = 2 * i + 1;
            const r = 2 * i + 2;
            var smallest = i;
            if (l < len and eventLess(self.items.items[l], self.items.items[smallest])) smallest = l;
            if (r < len and eventLess(self.items.items[r], self.items.items[smallest])) smallest = r;
            if (smallest == i) break;
            std.mem.swap(Event, &self.items.items[i], &self.items.items[smallest]);
            i = smallest;
        }
        return top;
    }
};

const NodeState = struct {
    known: std.AutoHashMapUnmanaged(u32, void) = .empty,
    tips: std.AutoHashMapUnmanaged(u32, void) = .empty,
    peers: std.ArrayList(u32) = .empty,

    fn deinit(self: *NodeState, gpa: std.mem.Allocator) void {
        self.known.deinit(gpa);
        self.tips.deinit(gpa);
        self.peers.deinit(gpa);
    }
};

fn idOf(i: u32) Hash256 {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, i, .little);
    return hashmod.hash(.block_header, &buf);
}

pub fn runScenario(gpa: std.mem.Allocator, p: Params) !Metrics {
    var prng = std.Random.DefaultPrng.init(p.seed);
    const rng = prng.random();

    const transfer_ns: u64 = @intCast(@as(u128, p.block_size_bytes) * 1_000_000_000 / p.bandwidth_bps);
    const hop_ns = p.latency_ns + transfer_ns;

    // --- topology ---
    var nodes = try gpa.alloc(NodeState, p.n_nodes);
    for (nodes) |*n| n.* = .{};
    defer {
        for (nodes) |*n| n.deinit(gpa);
        gpa.free(nodes);
    }
    for (0..p.n_nodes) |i| {
        var added: u32 = 0;
        while (added < p.peers_per_node) : (added += 1) {
            const peer = rng.intRangeLessThan(u32, 0, p.n_nodes);
            if (peer == i) continue;
            if (std.mem.indexOfScalar(u32, nodes[i].peers.items, peer) != null) continue;
            try nodes[i].peers.append(gpa, peer);
            try nodes[peer].peers.append(gpa, @intCast(i)); // undirected
        }
    }

    // --- blocks: index 0 is genesis, known to all at t=0 ---
    var block_parents: std.ArrayList([]u32) = .empty;
    defer {
        for (block_parents.items) |bp| gpa.free(bp);
        block_parents.deinit(gpa);
    }
    try block_parents.append(gpa, try gpa.alloc(u32, 0)); // genesis parents = {}
    for (nodes) |*n| {
        try n.known.put(gpa, 0, {});
        try n.tips.put(gpa, 0, {});
    }

    // --- event queue: pre-schedule Poisson mining events ---
    var heap: Heap = .{};
    defer heap.deinit(gpa);
    {
        var t: f64 = 0;
        while (true) {
            const u = rng.float(f64);
            t += -@log(1.0 - u) / p.block_rate_per_sec;
            if (t >= p.duration_sec) break;
            const time_ns: u64 = @intFromFloat(t * 1_000_000_000.0);
            const miner = rng.intRangeLessThan(u32, 0, p.n_nodes);
            try heap.push(gpa, .{ .time = time_ns, .kind = .mine, .node = miner, .block = 0 });
        }
    }

    // --- simulate ---
    while (heap.pop()) |ev| {
        switch (ev.kind) {
            .mine => {
                const miner = &nodes[ev.node];
                // Parents = miner's current tips (deterministic order).
                const parents = try tipSlice(gpa, miner);
                errdefer gpa.free(parents);
                const new_idx: u32 = @intCast(block_parents.items.len);
                try block_parents.append(gpa, parents);
                try learn(gpa, miner, new_idx, parents);
                try gossip(gpa, &heap, nodes, ev.node, new_idx, ev.time, hop_ns);
            },
            .arrival => {
                const node = &nodes[ev.node];
                if (node.known.contains(ev.block)) continue;
                try learn(gpa, node, ev.block, block_parents.items[ev.block]);
                try gossip(gpa, &heap, nodes, ev.node, ev.block, ev.time, hop_ns);
            },
        }
    }

    return try analyze(gpa, block_parents.items, nodes, p, hop_ns);
}

fn tipSlice(gpa: std.mem.Allocator, node: *NodeState) ![]u32 {
    var list: std.ArrayList(u32) = .empty;
    errdefer list.deinit(gpa);
    var it = node.tips.iterator();
    while (it.next()) |e| try list.append(gpa, e.key_ptr.*);
    if (list.items.len == 0) try list.append(gpa, 0); // fall back to genesis
    std.mem.sort(u32, list.items, {}, std.sort.asc(u32));
    return list.toOwnedSlice(gpa);
}

fn learn(gpa: std.mem.Allocator, node: *NodeState, block: u32, parents: []const u32) !void {
    try node.known.put(gpa, block, {});
    for (parents) |pp| _ = node.tips.remove(pp);
    try node.tips.put(gpa, block, {});
}

fn gossip(gpa: std.mem.Allocator, heap: *Heap, nodes: []NodeState, from: u32, block: u32, now: u64, hop_ns: u64) !void {
    for (nodes[from].peers.items) |peer| {
        try heap.push(gpa, .{ .time = now + hop_ns, .kind = .arrival, .node = peer, .block = block });
    }
}

fn analyze(gpa: std.mem.Allocator, blocks: []const []u32, nodes: []NodeState, p: Params, hop_ns: u64) !Metrics {
    const num_real: u32 = @intCast(blocks.len);

    var dag = Dag.init(gpa);
    defer dag.deinit();
    for (blocks, 0..) |parents, idx| {
        var ps = try gpa.alloc(Hash256, parents.len);
        defer gpa.free(ps);
        for (parents, 0..) |pp, j| ps[j] = idOf(pp);
        try dag.addBlock(idOf(@intCast(idx)), ps);
    }

    // Virtual block merges all global tips (blocks with no children).
    const virtual_idx: u32 = 0xFFFF_FFFF;
    var has_child = try gpa.alloc(bool, num_real);
    defer gpa.free(has_child);
    @memset(has_child, false);
    for (blocks) |parents| {
        for (parents) |pp| has_child[pp] = true;
    }
    var vparents: std.ArrayList(Hash256) = .empty;
    defer vparents.deinit(gpa);
    for (0..num_real) |i| {
        if (!has_child[i]) try vparents.append(gpa, idOf(@intCast(i)));
    }
    try dag.addBlock(idOf(virtual_idx), vparents.items);

    var gd = Ghostdag.init(gpa, &dag, p.k);
    defer gd.deinit();
    try gd.compute();

    const vdata = gd.get(idOf(virtual_idx)).?;
    var blue: u32 = 0;
    var max_mergeset: u32 = 0;
    for (0..num_real) |i| {
        if (vdata.isBlue(idOf(@intCast(i)))) blue += 1;
        const d = gd.get(idOf(@intCast(i))).?;
        const ms: u32 = @intCast(d.mergeset_blues.len + d.mergeset_reds.len);
        if (ms > max_mergeset) max_mergeset = ms;
    }
    const reds = num_real - blue;

    const hop_sec: f64 = @as(f64, @floatFromInt(hop_ns)) / 1_000_000_000.0;
    _ = nodes;

    return .{
        .blocks = num_real,
        .blue = blue,
        .reds = reds,
        .red_fraction = @as(f64, @floatFromInt(reds)) / @as(f64, @floatFromInt(num_real)),
        .max_mergeset = max_mergeset,
        .expected_concurrency = p.block_rate_per_sec * hop_sec,
    };
}

const testing = std.testing;

test "sanity: slow blocks on fast network are nearly all blue" {
    const m = try runScenario(testing.allocator, .{
        .block_rate_per_sec = 0.5,
        .block_size_bytes = 4_000,
        .duration_sec = 30.0,
        .k = 4,
        .seed = 7,
    });
    try testing.expect(m.blocks > 1);
    try testing.expect(m.red_fraction < 0.15); // healthy
}

test "monotonicity: raising the block rate raises the red fraction" {
    const slow = try runScenario(testing.allocator, .{
        .block_rate_per_sec = 1.0,
        .duration_sec = 20.0,
        .k = 2,
        .seed = 11,
    });
    const fast = try runScenario(testing.allocator, .{
        .block_rate_per_sec = 15.0,
        .duration_sec = 20.0,
        .k = 2,
        .seed = 11,
    });
    // More concurrency at higher rate → at least as much orphaned work.
    try testing.expect(fast.expected_concurrency > slow.expected_concurrency);
    try testing.expect(fast.red_fraction >= slow.red_fraction);
    try testing.expect(fast.max_mergeset >= slow.max_mergeset);
}
