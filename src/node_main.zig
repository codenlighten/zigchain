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

const Peer = struct {
    fd: i32,
    send: SpinLock = .{},
};

const Node = struct {
    gpa: std.mem.Allocator,
    chain: chain.Chain,
    lock: SpinLock = .{}, // guards chain + peers
    peers: std.ArrayList(*Peer) = .empty,
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
    const peer = node.gpa.create(Peer) catch return;
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

fn handleConn(node: *Node, peer: *Peer) void {
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
    node.lock.lock();
    // Persist the bytes; the chain borrows the decoded block's memory.
    const owned = node.gpa.dupe(u8, bytes) catch {
        node.lock.unlock();
        return;
    };
    var reader = codec.Reader{ .buf = owned };
    const block = Block.decode(&reader, node.gpa) catch {
        node.gpa.free(owned);
        node.lock.unlock();
        return;
    };
    const id = block.header.id(node.gpa) catch {
        node.lock.unlock();
        return;
    };
    if (node.chain.dag.contains(id)) {
        node.gpa.free(owned);
        node.lock.unlock();
        return;
    }
    const accepted = if (node.chain.acceptBlock(block)) |_| true else |_| false;
    const count = node.chain.dag.count();
    node.lock.unlock();

    if (accepted) {
        node.log("accepted block over the wire (chain now {d} blocks)", .{count});
        broadcastBlock(node, owned, from.fd); // flood to other peers
    }
    // On failure (invalid / unknown-parent) we simply drop it; over ordered TCP
    // with a single miner, parents always precede children so this is rare.
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
        const count = node.chain.dag.count();
        node.lock.unlock();
        if (!accepted) {
            sleepMs(100);
            continue;
        }
        node.log("mined block {d}", .{count});
        const bytes = wire.encodeBlock(node.gpa, block) catch continue;
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
        }
    }

    const node = try gpa.create(Node);
    node.* = .{ .gpa = gpa, .chain = chain.Chain.init(gpa, .{}), .name = name };

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
    node.stop.store(true, .release);
}
