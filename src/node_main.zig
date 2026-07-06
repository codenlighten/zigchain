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
const ratelimit = @import("net/ratelimit.zig");
const addrbook = @import("net/addrbook.zig");
const store_mod = @import("node/store.zig");
const chain = @import("core/consensus/chain.zig");
const blk = @import("core/primitives/block.zig");
const hashmod = @import("core/crypto/hash.zig");
const codec = @import("core/serialization/codec.zig");
const lic = @import("licensing/license.zig");

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
const max_book: usize = 1024; // known-peer address book cap
// Per-peer message rate: a 512-message burst, refilling ~500/s. An over-budget
// message is DROPPED (not processed), which throttles a flood without aborting a
// legitimate sync; only sustained flooding (many consecutive drops) disconnects.
const rate_burst: u32 = 512;
const rate_refill_ms: u32 = 2;
const max_drop_strikes: u32 = 4096; // consecutive rate-limited drops before disconnect
const discovery_interval_ms: u64 = 2000;
const dial_cooldown_ms: u64 = 30_000; // minimum interval between dial attempts to one address

const NetAddr = wire.NetAddr;

fn nowMs() u64 {
    return nowNs() / 1_000_000;
}

/// Pack an address into a hashable key (IPv4 big-endian in the high 32 bits).
fn packAddr(a: NetAddr) u64 {
    return (@as(u64, std.mem.readInt(u32, &a.ip, .big)) << 16) | a.port;
}

const Peer = struct {
    fd: i32,
    ip: [4]u8,
    send: SpinLock = .{},
    limiter: ratelimit.RateLimiter,
    /// The peer's advertised dial address, once its hello is seen (guarded by node.lock).
    listen_addr: ?NetAddr = null,
    drop_strikes: u32 = 0, // consecutive rate-limited drops (handleConn thread only)
    /// Reference count: the peer list holds one; broadcastBlock takes one while
    /// sending. The fd is closed and the struct freed when it drops to zero, so a
    /// peer can be removed from the list without a use-after-free in a concurrent
    /// broadcast.
    rc: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

    fn retain(self: *Peer) void {
        _ = self.rc.fetchAdd(1, .monotonic);
    }
    fn release(self: *Peer, gpa: std.mem.Allocator) void {
        if (self.rc.fetchSub(1, .acq_rel) == 1) {
            _ = linux.close(self.fd);
            gpa.destroy(self);
        }
    }
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
    // Peer discovery (PEX). `book` is the set of known dial addresses; `dialed`
    // maps a packed address to the last dial-attempt time (a cooldown, so a
    // transient failure is retried later rather than blacklisted forever). Both
    // guarded by `lock`. `self_nonce` is echoed in hello to detect self-connections.
    listen_port: u16 = 0,
    self_nonce: u64 = 0,
    book: addrbook.AddressBook = undefined,
    dialed: std.AutoHashMapUnmanaged(u64, u64) = .empty,

    fn log(self: *Node, comptime fmt: []const u8, args: anytype) void {
        std.debug.print("[{s}] " ++ fmt ++ "\n", .{self.name} ++ args);
    }

    fn blockCount(self: *Node) usize {
        self.lock.lock();
        defer self.lock.unlock();
        return self.chain.dag.count();
    }
};

fn addPeer(node: *Node, fd: i32, ip: [4]u8, listen_addr: ?NetAddr) void {
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
    peer.* = .{
        .fd = fd,
        .ip = ip,
        .listen_addr = listen_addr,
        .limiter = ratelimit.RateLimiter.init(rate_burst, rate_refill_ms, nowMs()),
    };
    node.lock.lock();
    node.peers.append(node.gpa, peer) catch {};
    node.lock.unlock();
    _ = std.Thread.spawn(.{}, handleConn, .{ node, peer }) catch {};
}

/// Remove a peer from the active list and drop the list's reference. The fd is
/// closed and the struct freed only once the last reference (e.g. an in-flight
/// broadcast) is gone.
fn removePeer(node: *Node, peer: *Peer) void {
    node.lock.lock();
    for (node.peers.items, 0..) |p, i| {
        if (p == peer) {
            _ = node.peers.swapRemove(i);
            break;
        }
    }
    node.lock.unlock();
    peer.release(node.gpa);
}

/// Are we already connected to a node that advertised dial address `a`? Caller
/// must hold node.lock.
fn connectedToLocked(node: *Node, a: NetAddr) bool {
    for (node.peers.items) |p| {
        if (p.listen_addr) |la| {
            if (la.eql(a)) return true;
        }
    }
    return false;
}

/// Send an encoded block to every peer except `except_fd`.
fn broadcastBlock(node: *Node, bytes: []const u8, except_fd: i32) void {
    node.lock.lock();
    const snapshot = node.gpa.dupe(*Peer, node.peers.items) catch {
        node.lock.unlock();
        return;
    };
    for (snapshot) |p| p.retain(); // keep peers alive for the send, even if removed concurrently
    node.lock.unlock();
    defer node.gpa.free(snapshot);
    for (snapshot) |p| {
        defer p.release(node.gpa);
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

/// Reply to `getaddr` with up to `max_addrs_per_msg` known addresses.
fn sendAddrs(node: *Node, peer: *Peer) void {
    var buf: [wire.max_addrs_per_msg * 6]u8 = undefined;
    node.lock.lock();
    const items = node.book.items();
    const count = @min(items.len, wire.max_addrs_per_msg);
    for (items[0..count], 0..) |a, i| a.write6(buf[i * 6 ..][0..6]);
    node.lock.unlock();
    if (count > 0) sendOne(node, peer, .{ .addr = buf[0 .. count * 6] });
}

fn handleConn(node: *Node, peer: *Peer) void {
    defer removePeer(node, peer); // always close the fd and free the peer on exit

    // Introduce ourselves (version, listen port, self nonce) and ask for peers.
    sendOne(node, peer, .{ .hello = .{ .version = 1, .listen_port = node.listen_port, .nonce = node.self_nonce } });
    sendOne(node, peer, .getaddr);
    sendTipInv(node, peer); // let a joining peer start pulling history
    while (!node.stop.load(.acquire)) {
        const r = wire.recvMessage(peer.fd, node.gpa) catch break;
        defer node.gpa.free(r.buffer);
        // Rate-limit: an over-budget message is DROPPED (not processed), which
        // throttles a flood without aborting a legitimate sync burst. Only a peer
        // that sustains the flood past `max_drop_strikes` is disconnected.
        if (!peer.limiter.allow(nowMs())) {
            peer.drop_strikes += 1;
            if (peer.drop_strikes > max_drop_strikes) {
                node.log("peer sustained flooding; disconnecting", .{});
                break;
            }
            continue;
        }
        peer.drop_strikes = 0;
        switch (r.msg) {
            .hello => |h| {
                if (h.nonce != 0 and h.nonce == node.self_nonce) break; // connected to ourselves
                // Learn the peer's real dial address: its source IP + advertised port.
                const a = NetAddr{ .ip = peer.ip, .port = h.listen_port };
                node.lock.lock();
                peer.listen_addr = a;
                _ = node.book.add(a);
                node.lock.unlock();
            },
            .getaddr => sendAddrs(node, peer),
            .addr => |bytes| {
                node.lock.lock();
                var i: usize = 0;
                while (i + 6 <= bytes.len) : (i += 6) _ = node.book.add(NetAddr.read6(bytes[i .. i + 6]));
                node.lock.unlock();
            },
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
        addPeer(node, fd, wire.peerIp(fd), null); // inbound: dial address learned from its hello
    }
}

/// Peer discovery: periodically dial known addresses we haven't dialed yet,
/// up to the peer cap. Addresses come from `hello`/`addr` peer exchange.
fn discover(node: *Node) void {
    while (!node.stop.load(.acquire)) {
        sleepMs(discovery_interval_ms);
        var targets: [8]NetAddr = undefined;
        var nt: usize = 0;
        const now = nowMs();
        node.lock.lock();
        if (node.peers.items.len < max_peers) {
            for (node.book.items()) |a| {
                if (nt >= targets.len) break;
                if (connectedToLocked(node, a)) continue; // already connected — no duplicate link
                if (node.dialed.get(packAddr(a))) |last| {
                    if (now - last < dial_cooldown_ms) continue; // dialed recently; back off
                }
                node.dialed.put(node.gpa, packAddr(a), now) catch {};
                targets[nt] = a;
                nt += 1;
            }
        }
        node.lock.unlock();
        for (targets[0..nt]) |a| {
            const fd = wire.tcpConnect(a.ip, a.port) catch continue;
            node.log("discovered peer {d}.{d}.{d}.{d}:{d}", .{ a.ip[0], a.ip[1], a.ip[2], a.ip[3], a.port });
            addPeer(node, fd, a.ip, a); // outbound: dial address is the listen address
        }
    }
}

fn mineLoop(node: *Node, target: usize) void {
    var seq: u64 = 0;
    // target == 0 means "run forever" (daemon mode).
    while (!node.stop.load(.acquire) and (target == 0 or node.blockCount() < target)) {
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

const PeerAddr = NetAddr;

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

fn realtimeSeconds() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

fn readFileAlloc(gpa: std.mem.Allocator, path: [*:0]const u8) ?[]u8 {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var list: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &buf) catch break;
        if (n == 0) break;
        list.appendSlice(gpa, buf[0..n]) catch return null;
    }
    return list.toOwnedSlice(gpa) catch null;
}

/// Verify a SmartLedger PQ software license. No license → community tier. A
/// license that is present but invalid/expired → refuse to start (fail-closed).
fn checkLicense(node: *Node, gpa: std.mem.Allocator, license_path: ?[]const u8, issuer_hex: ?[]const u8) void {
    const path = license_path orelse {
        node.log("no license supplied — running in community tier", .{});
        return;
    };
    const ih = issuer_hex orelse {
        node.log("license supplied but no --issuer-key to verify it; refusing to start", .{});
        linux.exit(3);
    };
    const pubkey = gpa.alloc(u8, ih.len / 2) catch return;
    _ = std.fmt.hexToBytes(pubkey, ih) catch {
        node.log("bad --issuer-key hex; refusing to start", .{});
        linux.exit(3);
    };
    const pathz = gpa.dupeZ(u8, path) catch return;
    const data = readFileAlloc(gpa, pathz) orelse {
        node.log("cannot read license file {s}; refusing to start", .{path});
        linux.exit(3);
    };
    var r = codec.Reader{ .buf = data };
    const token = lic.SignedLicense.decode(&r, gpa) catch {
        node.log("malformed license file; refusing to start", .{});
        linux.exit(3);
    };
    lic.verify(gpa, pubkey, token.license, token.signature, realtimeSeconds()) catch |e| {
        node.log("LICENSE INVALID ({s}) — refusing to start", .{@errorName(e)});
        linux.exit(3);
    };
    node.log("licensed to '{s}' (tier={d}, features=0x{x}, max_nodes={d}, expires={d})", .{
        token.license.licensee,
        @intFromEnum(token.license.tier),
        token.license.features,
        token.license.max_nodes,
        token.license.expires_at,
    });
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.skip(); // argv0

    var port: u16 = 0;
    var mine = false;
    var target: usize = 0; // 0 = run forever (daemon); demos/tests pass --blocks N
    var name: []const u8 = "node";
    var serve_secs: u64 = 0;
    var datadir: ?[]const u8 = null;
    var license_path: ?[]const u8 = null;
    var issuer_hex: ?[]const u8 = null;
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
        } else if (std.mem.eql(u8, arg, "--license")) {
            license_path = args.next();
        } else if (std.mem.eql(u8, arg, "--issuer-key")) {
            issuer_hex = args.next();
        }
    }

    const node = try gpa.create(Node);
    node.* = .{ .gpa = gpa, .chain = chain.Chain.init(gpa, .{}), .name = name };

    // Verify the SmartLedger software license (fail-closed if one is supplied
    // but invalid; community tier if none is supplied).
    checkLicense(node, gpa, license_path, issuer_hex);

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

    // Peer discovery state: a per-process nonce (self-connection detection), the
    // loopback self address (a cheap first-line self filter), and the address
    // book seeded with the configured --peer addresses.
    node.listen_port = port;
    node.self_nonce = nowNs() ^ (@as(u64, @intCast(linux.getpid())) << 32) ^ (@as(u64, port) << 16);
    node.book = addrbook.AddressBook.init(gpa, .{ .ip = .{ 127, 0, 0, 1 }, .port = port }, max_book);
    const now_ms = nowMs();
    for (peer_addrs.items) |pa| {
        _ = node.book.add(pa);
        node.dialed.put(gpa, packAddr(pa), now_ms) catch {}; // dialed explicitly below
    }

    if (port > 0) _ = try std.Thread.spawn(.{}, listen, .{ node, port });
    sleepMs(300); // let listeners bind

    for (peer_addrs.items) |pa| {
        const fd = wire.tcpConnect(pa.ip, pa.port) catch {
            node.log("connect to peer failed", .{});
            continue;
        };
        node.log("connected to peer (outbound)", .{});
        addPeer(node, fd, pa.ip, pa); // outbound: dial address is the listen address
    }

    // Discover further peers via PEX (needs a listener so discovered peers can
    // reach us back).
    if (port > 0) _ = try std.Thread.spawn(.{}, discover, .{node});
    sleepMs(300);

    // A daemon (no --blocks target) runs until killed; otherwise it stops at a
    // target block height (used by demos and integration tests).
    const daemon = target == 0;

    if (mine) {
        mineLoop(node, target); // target 0 = mine forever
    } else if (daemon) {
        node.log("running as a daemon (serving/syncing); Ctrl-C to stop", .{});
        while (!node.stop.load(.acquire)) sleepMs(1000);
    } else {
        // Wait until we've synced `target` blocks (or time out).
        const deadline = nowNs() + 30 * std.time.ns_per_s;
        while (node.blockCount() < target and nowNs() < deadline) sleepMs(100);
    }

    if (daemon) return; // never reached in practice; the loops above run forever

    // Bounded run: give gossip a moment to settle, then report final state.
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
