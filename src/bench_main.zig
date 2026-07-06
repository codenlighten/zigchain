//! `zig build bench` — measured scaling numbers.
//!
//! Answers the settlement-scale question with real measurements plus honest
//! arithmetic: how fast can this machine verify post-quantum signatures across
//! cores, what is the on-chain footprint per transaction, and why does batched
//! (netted) settlement drive per-transfer fees sub-penny.

const std = @import("std");
const hashmod = @import("core/crypto/hash.zig");
const prim = @import("core/primitives/types.zig");
const codec = @import("core/serialization/codec.zig");
const parallel = @import("core/consensus/parallel.zig");
const sharded = @import("core/ledger/sharded_utxo.zig");
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

const Hash256 = hashmod.Hash256;

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn encodedLen(gpa: std.mem.Allocator, tx: prim.Transaction) !usize {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try tx.encodeBody(&w);
    try tx.encodeWitnesses(&w);
    return list.items.len;
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    const cores = parallel.hardwareThreads();
    std.debug.print(
        \\============================================================
        \\  ZigChain scaling benchmark  (cores available: {d})
        \\============================================================
        \\
    , .{cores});

    // --- 1. Post-quantum verification throughput ---
    const M: usize = 3000;
    const kp = try MlDsa44.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const pk = kp.public_key.toBytes();
    const ctx = [_]u8{0x01}; // ml_dsa_44 scheme tag, bound as signature context

    const tasks = try gpa.alloc(parallel.VerifyTask, M);
    const sigs = try gpa.alloc([MlDsa44.Signature.encoded_length]u8, M);
    for (0..M) |i| {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, i, .little);
        const msg = hashmod.hash(.sighash, &b);
        sigs[i] = (try kp.signWithContext(&msg, null, &ctx)).toBytes();
        tasks[i] = .{ .scheme = .ml_dsa_44, .pubkey = &pk, .msg = msg, .sig = &sigs[i] };
    }

    const t0 = nowNs();
    const r1 = try parallel.verifyBatch(gpa, tasks, 1);
    const serial_ns = nowNs() - t0;

    const t1 = nowNs();
    const r2 = try parallel.verifyBatch(gpa, tasks, cores);
    const par_ns = nowNs() - t1;

    // sanity: both agree, all valid
    var ok: usize = 0;
    for (r1, r2) |a, b| {
        if (a and b) ok += 1;
    }

    const serial_per_sec = @as(f64, @floatFromInt(M)) / (@as(f64, @floatFromInt(serial_ns)) / 1e9);
    const par_per_sec = @as(f64, @floatFromInt(M)) / (@as(f64, @floatFromInt(par_ns)) / 1e9);
    const us_per_verify = (@as(f64, @floatFromInt(serial_ns)) / 1e3) / @as(f64, @floatFromInt(M));

    std.debug.print(
        \\1) ML-DSA-44 verification ({d} sigs, all valid: {d})
        \\   latency:  {d:.1} us/signature
        \\   serial:   {d:.0} verifications/sec  (1 core)
        \\   parallel: {d:.0} verifications/sec  ({d} cores, {d:.1}x)
        \\
        \\
    , .{ M, ok, us_per_verify, serial_per_sec, par_per_sec, cores, par_per_sec / serial_per_sec });

    // --- 1b. Full-spend verification (commitment + signature) via sharded state ---
    // Each input's committed output is looked up from a sharded UTXO set (the
    // horizontal-scale storage), then the (scheme,pubkey)->commitment and the
    // signature are checked — the complete per-input validation, parallelised.
    var shard = try sharded.ShardedUtxoSet.init(gpa, 512);
    const commitment = prim.addressCommitment(.ml_dsa_44, &pk);
    for (0..M) |i| try shard.add(opN(i), .{ .value = 1, .scheme = .ml_dsa_44, .commitment = commitment });

    const spends = try gpa.alloc(parallel.SpendTask, M);
    for (0..M) |i| {
        const coin = shard.get(opN(i)).?; // sharded-state lookup
        spends[i] = .{ .scheme = .ml_dsa_44, .pubkey = &pk, .commitment = coin.commitment, .msg = tasks[i].msg, .sig = tasks[i].sig };
    }
    const t2 = nowNs();
    const rs = try parallel.verifySpends(gpa, spends, cores);
    const spend_ns = nowNs() - t2;
    var full_ok: usize = 0;
    for (rs) |v| {
        if (v) full_ok += 1;
    }
    const spends_per_sec = @as(f64, @floatFromInt(M)) / (@as(f64, @floatFromInt(spend_ns)) / 1e9);
    std.debug.print(
        \\1b) Full-spend validation (commitment + signature, sharded lookups)
        \\    parallel: {d:.0} spends fully validated/sec  ({d} valid)
        \\
        \\
    , .{ spends_per_sec, full_ok });

    // --- 2. On-chain footprint per transaction ---
    const naive = try encodedLen(gpa, oneInOneOut(gpa, &pk, &sigs[0]));
    std.debug.print(
        \\2) On-chain footprint
        \\   standalone 1-in/1-out tx: {d} bytes  (dominated by the 2420B PQ signature)
        \\
    , .{naive});

    const gbps10 = 10.0e9 / 8.0; // bytes/sec on a 10 Gbit/s link
    std.debug.print("   bandwidth ceiling @ 10 Gbit/s: {d:.0} standalone tx/sec\n\n", .{gbps10 / @as(f64, @floatFromInt(naive))});

    // --- 3. Batched settlement (netting) ---
    const N: usize = 10_000;
    const batch = try settlement(gpa, &pk, &sigs[0], N);
    const batch_bytes = try encodedLen(gpa, batch);
    const per_transfer = @as(f64, @floatFromInt(batch_bytes)) / @as(f64, @floatFromInt(N));

    std.debug.print(
        \\3) Batched settlement — one signed tx netting {d} transfers
        \\   total size:       {d} bytes
        \\   per transfer:     {d:.1} bytes   ({d:.0}x smaller than a standalone tx)
        \\   signatures:       1  (verified once, amortised over {d} transfers)
        \\
        \\
    , .{ N, batch_bytes, per_transfer, @as(f64, @floatFromInt(naive)) / per_transfer, N });

    // --- 4. Throughput + fee at settlement scale ---
    const transfers_bw = gbps10 / per_transfer;
    // Fee floor: cover the per-transfer bytes. Assume a generous relay price of
    // $0.10 per GiB relayed and a token worth $1 (both stated, both swappable).
    const usd_per_byte = 0.10 / (1024.0 * 1024.0 * 1024.0);
    const fee_usd = per_transfer * usd_per_byte;
    std.debug.print(
        \\4) At settlement scale (10 Gbit/s node, batched)
        \\   bandwidth throughput: {d:.0} transfers/sec
        \\   verification:         not the bottleneck (1 sig per {d} transfers)
        \\   per-transfer fee floor: ${d:.9}   (assuming $0.10/GiB relay cost)
        \\   => that is {d:.0}x below one US cent.
        \\
        \\Nasdaq peaks at a few hundred thousand trades/sec; this leaves orders
        \\of magnitude of headroom, and per-transfer fees sit far under a penny.
        \\
    , .{ transfers_bw, N, fee_usd, 0.01 / fee_usd });
}

fn opN(i: usize) prim.OutPoint {
    var txid: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u64, txid[0..8], @intCast(i), .little); // spreads across shards
    return .{ .txid = txid, .index = 0 };
}

fn oneInOneOut(gpa: std.mem.Allocator, pk: []const u8, sig: []const u8) prim.Transaction {
    return .{
        .version = 1,
        .inputs = gpa.dupe(prim.Input, &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }}) catch unreachable,
        .outputs = gpa.dupe(prim.Output, &.{.{ .value = 100, .scheme = .ml_dsa_44, .commitment = hashmod.zero }}) catch unreachable,
        .witnesses = gpa.dupe(prim.Witness, &.{.{ .scheme = .ml_dsa_44, .pubkey = pk, .signature = sig }}) catch unreachable,
    };
}

fn settlement(gpa: std.mem.Allocator, pk: []const u8, sig: []const u8, n: usize) !prim.Transaction {
    const outs = try gpa.alloc(prim.Output, n);
    for (outs) |*o| o.* = .{ .value = 100, .scheme = .ml_dsa_44, .commitment = hashmod.zero };
    return .{
        .version = 1,
        .inputs = try gpa.dupe(prim.Input, &.{.{ .outpoint = .{ .txid = hashmod.zero, .index = 0 } }}),
        .outputs = outs,
        .witnesses = try gpa.dupe(prim.Witness, &.{.{ .scheme = .ml_dsa_44, .pubkey = pk, .signature = sig }}),
    };
}
