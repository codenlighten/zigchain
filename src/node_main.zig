//! `zig build node -- --port 9000 [--peer 127.0.0.1:9001] [--mine] [--blocks N]`
//!
//! A standalone ZigChain node process: it binds a TCP port, accepts peers,
//! connects out to configured peers, gossips blocks (flooding over ordered TCP),
//! and — if `--mine` — mines blocks and broadcasts them. Two such processes on
//! one machine (or across machines) converge on the same chain. This is the
//! capstone that makes the whole stack runnable as a real network.
//!
//! Threading: one listener thread, one handler thread per peer, and the mining
//! loop on the main thread. All chain/peer mutation is serialised by a single
//! spinlock; block memory comes from the thread-safe `gpa` and persists (the
//! chain borrows it), which is fine for a node that only grows its chain.

const std = @import("std");
const linux = std.os.linux;
const wire = @import("net/wire.zig");
const store_mod = @import("node/store.zig");
const chain = @import("core/consensus/chain.zig");
const blk = @import("core/primitives/block.zig");
const hashmod = @import("core/crypto/hash.zig");
const codec = @import("core/serialization/codec.zig");

const Hash256 = hashmod.Hash256;
const Block = blk.Block;

const SpinLock = struct {
    flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    fn lock(self: *SpinLock) void {
        while (self.flag.swap(true, .acquire)) std.atomic.spinLoopHint();
    }
    fn unlock(self: *SpinLock) void {
        self.flag.store(false, .release);
    }
};

fn nowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn sleepMs(ms: u64) void {
    var ts = linux.timespec{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * 1_000_000) };
    _ = linux.nanosleep(&ts, null);
}

// DoS bounds for a node facing untrusted peers.
const max_peers: usize = 128;
const max_orphans: usize = 8192;

const Peer = struct {
    fd: i32,
    send: SpinLock = .{},
};

/// A block received before its parents — held until they arrive.
const Orphan = struct { bytes: []u8, parents: []Hash256 };

const Node = struct {
    gpa: std.mem.Allocator,
    chain: chain.Chain,
    lock: SpinLock = .{}, // guards chain + peers + orphans
    peers: std.ArrayList(*Peer) = .empty,
    orphans: std.AutoHashMapUnmanaged(Hash256, Orphan) = .empty,
    store: ?store_mod.BlockStore = null, // persistent block log (if --datadir)
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    name: []const u8,

    fn log(self: *Node, comptime fmt: []const u8, args: anytype) void {
        std.debug.print("[{s}] " ++ fmt ++ "\n", .{self.name} ++ args);
    }

    fn blockCount(self: *Node) usize {
        self.lock.lock();
        defer self.lock.unlock();
        return self.chain.dag.count();
    }
};

fn addPeer(node: *Node, fd: i32) void {
    node.lock.lock();
    const full = node.peers.items.len >= max_peers;
    node.lock.unlock();
    if (full) {
        _ = linux.close(fd);
        node.log("peer limit ({d}) reached; dropped connection", .{max_peers});
        return;
    }
    const peer = node.gpa.create(Peer) catch {
        _ = linux.close(fd);
        return;
    };
    peer.* = .{ .fd = fd };
    node.lock.lock();
    node.peers.append(node.gpa, peer) catch {};
    node.lock.unlock();
    _ = std.Thread.spawn(.{}, handleConn, .{ node, peer }) catch {};
}

/// Send an encoded block to every peer except `except_fd`.
fn broadcastBlock(node: *Node, bytes: []const u8, except_fd: i32) void {
    node.lock.lock();
    const snapshot = node.gpa.dupe(*Peer, node.peers.items) catch {
        node.lock.unlock();
        return;
    };
    node.lock.unlock();
    defer node.gpa.free(snapshot);
    for (snapshot) |p| {
        if (p.fd == except_fd) continue;
        p.send.lock();
        wire.sendMessage(p.fd, node.gpa, .{ .block = bytes }) catch {};
        p.send.unlock();
    }
}

fn sendOne(node: *Node, peer: *Peer, msg: wire.Message) void {
    peer.send.lock();
    wire.sendMessage(peer.fd, node.gpa, msg) catch {};
    peer.send.unlock();
}

/// Announce our current tip so a peer can begin syncing from it.
fn sendTipInv(node: *Node, peer: *Peer) void {
    node.lock.lock();
    const tip = node.chain.tip();
    node.lock.unlock();
    if (tip) |t| sendOne(node, peer, .{ .inv = t });
}

fn handleConn(node: *Node, peer: *Peer) void {
    sendTipInv(node, peer); // let a joining peer start pulling history
    while (!node.stop.load(.acquire)) {
        const r = wire.recvMessage(peer.fd, node.gpa) catch break;
        defer node.gpa.free(r.buffer);
        switch (r.msg) {
            .hello => {},
            .inv => |id| {
                node.lock.lock();
                const have = node.chain.dag.contains(id);
                node.lock.unlock();
                if (!have) sendOne(node, peer, .{ .get_block = id });
            },
            .get_block => |id| {
                node.lock.lock();
                const maybe = node.chain.blocks.get(id);
                node.lock.unlock();
                if (maybe) |b| {
                    const bytes = wire.encodeBlock(node.gpa, b) catch continue;
                    defer node.gpa.free(bytes);
                    sendOne(node, peer, .{ .block = bytes });
                }
            },
            .block => |bytes| processBlock(node, peer, bytes),
        }
    }
}

fn processBlock(node: *Node, from: *Peer, bytes: []const u8) void {
    var requests: std.ArrayList(Hash256) = .empty;
    defer requests.deinit(node.gpa);
    var to_flood: ?[]u8 = null;

    node.lock.lock();
    ingest(node, bytes, &requests, &to_flood);
    node.lock.unlock();

    // Fetch any missing ancestors from the peer that sent this (walks history back).
    for (requests.items) |pid| sendOne(node, from, .{ .get_block = pid });
    // Re-flood a newly-accepted block to the other peers.
    if (to_flood) |fb| broadcastBlock(node, fb, from.fd);
}

/// Ingest a block (caller holds the lock). Accepts it if its parents are present;
/// otherwise stashes it as an orphan and records the missing parents to request.
/// Accepting a block cascades: any orphan now connectable is accepted too.
fn ingest(node: *Node, bytes: []const u8, requests: *std.ArrayList(Hash256), to_flood: *?[]u8) void {
    const owned = node.gpa.dupe(u8, bytes) catch return;
    var reader = codec.Reader{ .buf = owned };
    const block = Block.decode(&reader, node.gpa) catch {
        node.gpa.free(owned);
        return;
    };
    const id = block.header.id(node.gpa) catch {
        node.gpa.free(owned);
        return;
    };
    if (node.chain.dag.contains(id) or node.orphans.contains(id)) {
        node.gpa.free(owned);
        return;
    }

    var missing = false;
    for (block.header.parents) |p| {
        if (!node.chain.dag.contains(p)) {
            missing = true;
            requests.append(node.gpa, p) catch {};
        }
    }
    if (missing) {
        // Bound the orphan pool so a peer can't exhaust memory with blocks whose
        // parents never arrive.
        if (node.orphans.count() >= max_orphans) {
            node.gpa.free(owned);
            return;
        }
        const parents_copy = node.gpa.dupe(Hash256, block.header.parents) catch {
            node.gpa.free(owned);
            return;
        };
        node.orphans.put(node.gpa, id, .{ .bytes = owned, .parents = parents_copy }) catch {};
        return;
    }

    _ = node.chain.acceptBlock(block) catch {
        node.gpa.free(owned);
        return;
    };
    persist(node, owned);
    node.log("accepted block (chain now {d})", .{node.chain.dag.count()});
    to_flood.* = owned;
    cascade(node);
}

/// Connect every orphan whose parents are now present, repeatedly.
fn cascade(node: *Node) void {
    var changed = true;
    while (changed) {
        changed = false;
        var ready: ?Hash256 = null;
        var it = node.orphans.iterator();
        while (it.next()) |e| {
            var all = true;
            for (e.value_ptr.parents) |p| {
                if (!node.chain.dag.contains(p)) {
                    all = false;
                    break;
                }
            }
            if (all) {
                ready = e.key_ptr.*;
                break;
            }
        }
        if (ready) |rid| {
            const orph = node.orphans.fetchRemove(rid).?.value;
            node.gpa.free(orph.parents);
            var rd = codec.Reader{ .buf = orph.bytes };
            const b = Block.decode(&rd, node.gpa) catch continue;
            _ = node.chain.acceptBlock(b) catch continue;
            persist(node, orph.bytes);
            node.log("connected orphan (chain now {d})", .{node.chain.dag.count()});
            changed = true;
        }
    }
}

/// Append an accepted block to the on-disk log (no-op without --datadir).
fn persist(node: *Node, bytes: []const u8) void {
    if (node.store) |*s| s.append(bytes) catch {};
}

/// Replay callback: decode a stored block and accept it (startup, single-thread).
fn replayAccept(node: *Node, bytes: []const u8) void {
    const owned = node.gpa.dupe(u8, bytes) catch return;
    var reader = codec.Reader{ .buf = owned };
    const block = Block.decode(&reader, node.gpa) catch {
        node.gpa.free(owned);
        return;
    };
    _ = node.chain.acceptBlock(block) catch node.gpa.free(owned);
}

fn listen(node: *Node, port: u16) void {
    const l = wire.tcpListen(port) catch |e| {
        node.log("listen failed: {any}", .{e});
        return;
    };
    node.log("listening on tcp/{d}", .{port});
    while (!node.stop.load(.acquire)) {
        const fd = wire.tcpAccept(l) catch break;
        node.log("peer connected (inbound)", .{});
        addPeer(node, fd);
    }
}

fn mineLoop(node: *Node, target: usize) void {
    var seq: u64 = 0;
    while (!node.stop.load(.acquire) and node.blockCount() < target) {
        node.lock.lock();
        var pbuf: [1]Hash256 = undefined;
        const parents: []const Hash256 = if (node.chain.tip()) |t| p: {
            pbuf[0] = t;
            break :p pbuf[0..1];
        } else &.{};
        seq += 1;
        const ts = nowNs() + seq; // unique per block (coinbase extranonce)
        const block = chain.mineBlock(node.gpa, &node.chain, parents, ts, &.{}, hashmod.zero) catch {
            node.lock.unlock();
            sleepMs(100);
            continue;
        };
        const accepted = if (node.chain.acceptBlock(block)) |_| true else |_| false;
        if (!accepted) {
            node.lock.unlock();
            sleepMs(100);
            continue;
        }
        const count = node.chain.dag.count();
        const bytes = wire.encodeBlock(node.gpa, block) catch {
            node.lock.unlock();
            continue;
        };
        persist(node, bytes); // durably log the block before announcing it
        node.lock.unlock();

        node.log("mined block {d}", .{count});
        broadcastBlock(node, bytes, -1);
        node.gpa.free(bytes);
        sleepMs(500);
    }
}

const PeerAddr = struct { ip: [4]u8, port: u16 };

fn parsePeer(s: []const u8) ?PeerAddr {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const host = s[0..colon];
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;
    var ip: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, host, '.');
    var i: usize = 0;
    while (it.next()) |octet| : (i += 1) {
        if (i >= 4) return null;
        ip[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
    }
    if (i != 4) return null;
    return .{ .ip = ip, .port = port };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.skip(); // argv0

    var port: u16 = 0;
    var mine = false;
    var target: usize = 6;
    var name: []const u8 = "node";
    var serve_secs: u64 = 0;
    var datadir: ?[]const u8 = null;
    var peer_addrs: std.ArrayList(PeerAddr) = .empty;
    defer peer_addrs.deinit(gpa);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            port = std.fmt.parseInt(u16, args.next() orelse "0", 10) catch 0;
        } else if (std.mem.eql(u8, arg, "--peer")) {
            if (parsePeer(args.next() orelse "")) |pa| try peer_addrs.append(gpa, pa);
        } else if (std.mem.eql(u8, arg, "--mine")) {
            mine = true;
        } else if (std.mem.eql(u8, arg, "--blocks")) {
            target = std.fmt.parseInt(usize, args.next() orelse "6", 10) catch 6;
        } else if (std.mem.eql(u8, arg, "--name")) {
            name = args.next() orelse "node";
        } else if (std.mem.eql(u8, arg, "--serve-secs")) {
            serve_secs = std.fmt.parseInt(u64, args.next() orelse "0", 10) catch 0;
        } else if (std.mem.eql(u8, arg, "--datadir")) {
            datadir = args.next();
        }
    }

    const node = try gpa.create(Node);
    node.* = .{ .gpa = gpa, .chain = chain.Chain.init(gpa, .{}), .name = name };

    // Persistence: open the block log and replay it to rebuild the chain.
    if (datadir) |dir| {
        const path = try std.fmt.allocPrintSentinel(gpa, "{s}/blocks.log", .{dir}, 0);
        var s = store_mod.BlockStore.open(path) catch {
            node.log("could not open block store at {s}", .{path});
            return;
        };
        const replayed = s.replay(gpa, node, replayAccept) catch 0;
        if (replayed > 0) node.log("restored {d} blocks from disk (chain now {d})", .{ replayed, node.chain.dag.count() });
        node.store = s;
    }

    if (port > 0) _ = try std.Thread.spawn(.{}, listen, .{ node, port });
    sleepMs(300); // let listeners bind

    for (peer_addrs.items) |pa| {
        const fd = wire.tcpConnect(pa.ip, pa.port) catch {
            node.log("connect to peer failed", .{});
            continue;
        };
        node.log("connected to peer (outbound)", .{});
        addPeer(node, fd);
    }
    sleepMs(300);

    if (mine) {
        mineLoop(node, target);
    } else {
        // Wait until we've synced `target` blocks (or time out).
        const deadline = nowNs() + 30 * std.time.ns_per_s;
        while (node.blockCount() < target and nowNs() < deadline) sleepMs(100);
    }

    // Give gossip a moment to settle, then report final state.
    sleepMs(800);
    node.lock.lock();
    const tip = node.chain.tip();
    const count = node.chain.dag.count();
    const commit = node.chain.utxoCommitment() catch hashmod.zero;
    node.lock.unlock();

    if (tip) |t| {
        node.log("FINAL: blocks={d} tip={s} utxo_commitment={s}", .{
            count,
            std.fmt.bytesToHex(t, .lower)[0..12],
            std.fmt.bytesToHex(commit, .lower)[0..12],
        });
    } else {
        node.log("FINAL: no blocks", .{});
    }

    // Keep serving history/gossip to peers (e.g. late joiners) before exiting.
    if (serve_secs > 0) {
        node.log("serving peers for {d}s...", .{serve_secs});
        sleepMs(serve_secs * 1000);
    }
    node.stop.store(true, .release);
}
