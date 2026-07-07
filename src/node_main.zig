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
// Per-source-IP rate limit applied ONLY to the amplification-prone control
// messages (getaddr/addr): a burst of `rate_burst`, refilling one per
// `rate_refill_ms`. Over-budget control messages are ignored. Block flow
// (inv/get_block/block) is never rate-limited — see handleConn.
const rate_burst: u32 = 512;
const rate_refill_ms: u32 = 2;
const discovery_interval_ms: u64 = 2000;
const dial_cooldown_ms: u64 = 30_000; // minimum interval between dial attempts to one address
const max_ip_buckets: usize = 65536; // cap on distinct source-IP rate-limit buckets
const status_ckpt_interval: u64 = 50; // STATUS reports the selected block at this height granularity
const max_future_drift_ms: u64 = 2 * 60 * 60 * 1000; // reject blocks timestamped >2h ahead of our clock

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
    /// The peer's advertised dial address, once its hello is seen (guarded by node.net_lock).
    listen_addr: ?NetAddr = null,
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
    lock: SpinLock = .{}, // guards chain + orphans + store
    net_lock: SpinLock = .{}, // guards peers + book + dialed + ip_limits (never held with `lock`)
    peers: std.ArrayList(*Peer) = .empty,
    orphans: std.AutoHashMapUnmanaged(Hash256, Orphan) = .empty,
    /// Per-source-IP rate-limit buckets, so a flooder cannot reset its budget by
    /// reconnecting or opening parallel connections. Bounded by max_ip_buckets.
    ip_limits: std.AutoHashMapUnmanaged([4]u8, ratelimit.RateLimiter) = .empty,
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
    /// Packed addresses discovered to be OURSELVES (learned when a connection
    /// echoes our own nonce). The loopback self-filter can't know our real
    /// external IP, so we learn it here and never dial it again.
    self_addrs: std.AutoHashMapUnmanaged(u64, void) = .empty,

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
    node.net_lock.lock();
    const full = node.peers.items.len >= max_peers;
    node.net_lock.unlock();
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
    };
    node.net_lock.lock();
    node.peers.append(node.gpa, peer) catch {};
    node.net_lock.unlock();
    _ = std.Thread.spawn(.{}, handleConn, .{ node, peer }) catch {};
}

/// Remove a peer from the active list and drop the list's reference. The fd is
/// closed and the struct freed only once the last reference (e.g. an in-flight
/// broadcast) is gone.
fn removePeer(node: *Node, peer: *Peer) void {
    node.net_lock.lock();
    for (node.peers.items, 0..) |p, i| {
        if (p == peer) {
            _ = node.peers.swapRemove(i);
            break;
        }
    }
    node.net_lock.unlock();
    peer.release(node.gpa);
}

/// Per-source-IP token bucket. Returns true if a message from `ip` is within
/// budget. Buckets persist across connections (so reconnecting doesn't reset the
/// budget) and are bounded; when the table is full, new IPs fail open.
fn allowMessage(node: *Node, ip: [4]u8) bool {
    node.net_lock.lock();
    defer node.net_lock.unlock();
    const now = nowMs();
    if (node.ip_limits.getPtr(ip)) |rl| return rl.allow(now);
    if (node.ip_limits.count() >= max_ip_buckets) return true;
    node.ip_limits.put(node.gpa, ip, ratelimit.RateLimiter.init(rate_burst, rate_refill_ms, now)) catch return true;
    return node.ip_limits.getPtr(ip).?.allow(now);
}

/// Are we already connected to a node that advertised dial address `a`? Caller
/// must hold node.net_lock.
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
    node.net_lock.lock();
    const snapshot = node.gpa.dupe(*Peer, node.peers.items) catch {
        node.net_lock.unlock();
        return;
    };
    for (snapshot) |p| p.retain(); // keep peers alive for the send, even if removed concurrently
    node.net_lock.unlock();
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
    node.net_lock.lock();
    const items = node.book.items();
    const count = @min(items.len, wire.max_addrs_per_msg);
    for (items[0..count], 0..) |a, i| a.write6(buf[i * 6 ..][0..6]);
    node.net_lock.unlock();
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
        switch (r.msg) {
            .hello => |h| {
                const a = NetAddr{ .ip = peer.ip, .port = h.listen_port };
                if (h.nonce != 0 and h.nonce == node.self_nonce) {
                    // Connected to ourselves — record our own external address so
                    // discovery never dials it again, then drop the connection.
                    node.net_lock.lock();
                    _ = node.self_addrs.put(node.gpa, packAddr(a), {}) catch {};
                    if (peer.listen_addr) |la| _ = node.self_addrs.put(node.gpa, packAddr(la), {}) catch {};
                    node.net_lock.unlock();
                    break;
                }
                // Learn the peer's real dial address: its source IP + advertised port.
                node.net_lock.lock();
                peer.listen_addr = a;
                _ = node.book.add(a);
                node.net_lock.unlock();
            },
            // Rate-limit ONLY the amplification-prone control messages: getaddr
            // (one request → up to 64 addresses) and addr (O(n) book work). An
            // over-budget one is simply ignored, bounding the amplification.
            // Block flow (inv/get_block/block) is NEVER rate-limited: it is
            // self-limited by proof-of-work, and dropping a block mid-sync would
            // stall an orphan cascade (a dropped block-response is never
            // re-requested), which breaks synchronization entirely.
            .getaddr => if (allowMessage(node, peer.ip)) sendAddrs(node, peer),
            .addr => |bytes| if (allowMessage(node, peer.ip)) {
                node.net_lock.lock();
                var i: usize = 0;
                while (i + 6 <= bytes.len) : (i += 6) _ = node.book.add(NetAddr.read6(bytes[i .. i + 6]));
                node.net_lock.unlock();
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
    // Future-time acceptance policy (wall-clock, node-local — NOT a consensus
    // rule): drop a block timestamped too far ahead of our clock. If it is
    // legitimate we re-learn it once time catches up, so this can't fork us.
    if (block.header.timestamp > realtimeMs() + max_future_drift_ms) {
        node.gpa.free(owned);
        return;
    }
    if (node.chain.dag.contains(id) or node.orphans.contains(id)) {
        node.gpa.free(owned);
        return;
    }

    var missing = false;
    for (block.header.parents) |p| {
        if (!node.chain.dag.contains(p)) {
            missing = true; // this block can't be accepted yet
            // Request the parent ONLY if we don't already hold it as an orphan.
            // Re-requesting orphaned ancestors is what drowns a behind node in a
            // request storm: with tip-merging every new block references many
            // ancestors, so without this a catch-up never converges.
            if (!node.orphans.contains(p)) requests.append(node.gpa, p) catch {};
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
        // Try to drain the orphan pool: a behind node under tip-merging receives
        // every new block as an orphan, so if the cascade only ran on a direct
        // accept it would never fire and the (complete) orphan DAG would pile up
        // forever. Running it here connects any orphan whose ancestry is present.
        cascade(node);
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
        node.net_lock.lock();
        if (node.peers.items.len < max_peers) {
            for (node.book.items()) |a| {
                if (nt >= targets.len) break;
                if (node.self_addrs.contains(packAddr(a))) continue; // that's us
                if (connectedToLocked(node, a)) continue; // already connected — no duplicate link
                if (node.dialed.get(packAddr(a))) |last| {
                    if (now - last < dial_cooldown_ms) continue; // dialed recently; back off
                }
                node.dialed.put(node.gpa, packAddr(a), now) catch {};
                targets[nt] = a;
                nt += 1;
            }
        }
        node.net_lock.unlock();
        for (targets[0..nt]) |a| {
            const fd = wire.tcpConnect(a.ip, a.port) catch continue;
            node.log("discovered peer {d}.{d}.{d}.{d}:{d}", .{ a.ip[0], a.ip[1], a.ip[2], a.ip[3], a.port });
            addPeer(node, fd, a.ip, a); // outbound: dial address is the listen address
        }
    }
}

/// Periodically log a one-line status so an external harness (or `docker logs`)
/// can observe convergence and peer counts without an RPC interface.
fn statusLoop(node: *Node) void {
    while (!node.stop.load(.acquire)) {
        sleepMs(3000);
        node.lock.lock();
        const tip = node.chain.tip();
        // The selected tip's height, and a checkpoint block at a rounded-down
        // absolute height that peers on the same chain all agree on. `count` is
        // the total DAG block count — when count > height the DAG genuinely
        // forked (off-selected-chain sibling blocks exist), so agreement on the
        // stable checkpoint proves GHOSTDAG resolved the forks identically.
        const tip_h: u64 = if (tip) |t| (node.chain.height(t) orelse 0) else 0;
        const count: usize = node.chain.dag.count();
        const ckpt: u64 = (tip_h / status_ckpt_interval) * status_ckpt_interval;
        const stable = node.chain.selectedBlockAtHeight(ckpt);
        node.lock.unlock();
        node.net_lock.lock();
        const npeers = node.peers.items.len;
        node.net_lock.unlock();
        if (tip) |t| {
            node.log("STATUS height={d} count={d} ckpt={d} peers={d} tip={s} stable={s}", .{
                tip_h,
                count,
                ckpt,
                npeers,
                std.fmt.bytesToHex(t, .lower)[0..12],
                std.fmt.bytesToHex(stable orelse hashmod.zero, .lower)[0..12],
            });
        } else {
            node.log("STATUS height=0 count=0 ckpt=0 peers={d} tip=none stable=none", .{npeers});
        }
    }
}

fn mineLoop(node: *Node, target: usize) void {
    var seq: u64 = 0;
    // target == 0 means "run forever" (daemon mode).
    while (!node.stop.load(.acquire) and (target == 0 or node.blockCount() < target)) {
        node.lock.lock();
        // Mine on ALL current DAG tips (not just the selected tip) so competing
        // blocks from other miners are merged into one DAG — this is what lets
        // GHOSTDAG converge two miners onto one chain. Empty for genesis.
        const parents = node.chain.dag.tips(node.gpa) catch {
            node.lock.unlock();
            sleepMs(100);
            continue;
        };
        defer node.gpa.free(parents);
        seq += 1;
        // Wall-clock timestamp (unix ms, the DAA's unit), bumped past
        // median-time-past so the block is always accepted even when mining
        // faster than clock resolution. A separate unique extranonce keeps
        // sibling coinbases distinct.
        const ts = @max(realtimeMs(), node.chain.medianTimePast(parents) + 1);
        const block = chain.mineBlockExtra(node.gpa, &node.chain, parents, ts, seq, &.{}, hashmod.zero) catch {
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

fn realtimeMs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
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
    _ = std.Thread.spawn(.{}, statusLoop, .{node}) catch {};
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
