//! Parallel signature verification.
//!
//! The whole point of the UTXO model for scale: given that inputs exist and
//! aren't double-spent, every signature verifies independently. That is
//! embarrassingly parallel, and post-quantum verification is CPU-heavy, so this
//! is where multi-core throughput comes from. Verification touches no shared
//! mutable state and allocates nothing, so it scales cleanly across threads.

const std = @import("std");
const pq = @import("../crypto/pq/registry.zig");
const hashmod = @import("../crypto/hash.zig");
const prim = @import("../primitives/types.zig");

const Hash256 = hashmod.Hash256;

pub const VerifyTask = struct {
    scheme: pq.SchemeTag,
    pubkey: []const u8,
    msg: Hash256, // the sighash
    sig: []const u8,
};

/// A full spend to verify: the (scheme, pubkey) must hash to the committed
/// output, and the signature must be valid over the sighash. This is the whole
/// per-input cryptographic check, and it is independent across inputs — the
/// property that makes validation scale across cores.
pub const SpendTask = struct {
    scheme: pq.SchemeTag,
    pubkey: []const u8,
    commitment: Hash256, // the output's address commitment
    msg: Hash256, // the sighash
    sig: []const u8,
};

const Shared = struct {
    tasks: []const VerifyTask,
    results: []bool,
};

fn worker(shared: *const Shared, start: usize, end: usize) void {
    var i = start;
    while (i < end) : (i += 1) {
        const t = shared.tasks[i];
        shared.results[i] = if (pq.verify(t.scheme, t.pubkey, &t.msg, t.sig)) |_| true else |_| false;
    }
}

/// Verify every task, using up to `threads` OS threads. Returns a per-task
/// validity slice (caller owns it).
pub fn verifyBatch(gpa: std.mem.Allocator, tasks: []const VerifyTask, threads: usize) ![]bool {
    const results = try gpa.alloc(bool, tasks.len);
    errdefer gpa.free(results);
    var shared = Shared{ .tasks = tasks, .results = results };

    const nthreads = @max(1, threads);
    if (nthreads == 1 or tasks.len < 2) {
        worker(&shared, 0, tasks.len);
        return results;
    }

    const chunk = (tasks.len + nthreads - 1) / nthreads;
    const handles = try gpa.alloc(std.Thread, nthreads);
    defer gpa.free(handles);

    var spawned: usize = 0;
    var start: usize = 0;
    while (start < tasks.len) : (start += chunk) {
        const end = @min(start + chunk, tasks.len);
        handles[spawned] = try std.Thread.spawn(.{}, worker, .{ &shared, start, end });
        spawned += 1;
    }
    for (handles[0..spawned]) |h| h.join();
    return results;
}

// --- full-spend verification (commitment + signature) ---

const SpendShared = struct {
    tasks: []const SpendTask,
    results: []bool,
};

fn spendWorker(shared: *const SpendShared, start: usize, end: usize) void {
    var i = start;
    while (i < end) : (i += 1) {
        const t = shared.tasks[i];
        const derived = prim.addressCommitment(t.scheme, t.pubkey);
        if (!std.mem.eql(u8, &derived, &t.commitment)) {
            shared.results[i] = false;
            continue;
        }
        shared.results[i] = if (pq.verify(t.scheme, t.pubkey, &t.msg, t.sig)) |_| true else |_| false;
    }
}

/// Verify a batch of full spends across up to `threads` threads.
pub fn verifySpends(gpa: std.mem.Allocator, tasks: []const SpendTask, threads: usize) ![]bool {
    const results = try gpa.alloc(bool, tasks.len);
    errdefer gpa.free(results);
    var shared = SpendShared{ .tasks = tasks, .results = results };

    const nthreads = @max(1, threads);
    if (nthreads == 1 or tasks.len < 2) {
        spendWorker(&shared, 0, tasks.len);
        return results;
    }
    const chunk = (tasks.len + nthreads - 1) / nthreads;
    const handles = try gpa.alloc(std.Thread, nthreads);
    defer gpa.free(handles);
    var spawned: usize = 0;
    var start: usize = 0;
    while (start < tasks.len) : (start += chunk) {
        const end = @min(start + chunk, tasks.len);
        handles[spawned] = try std.Thread.spawn(.{}, spendWorker, .{ &shared, start, end });
        spawned += 1;
    }
    for (handles[0..spawned]) |h| h.join();
    return results;
}

/// Convenience: available hardware parallelism (falls back to 1).
pub fn hardwareThreads() usize {
    return std.Thread.getCpuCount() catch 1;
}

const testing = std.testing;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

test "parallel verification matches serial and flags tampered signatures" {
    const gpa = testing.allocator;
    const kp = try MlDsa44.KeyPair.generateDeterministic([_]u8{5} ** 32);
    const pk = kp.public_key.toBytes();
    const ctx = [_]u8{@intFromEnum(pq.SchemeTag.ml_dsa_44)};

    var msgs: [16]Hash256 = undefined;
    var sigs: [16][MlDsa44.Signature.encoded_length]u8 = undefined;
    var tasks: [16]VerifyTask = undefined;
    for (0..16) |i| {
        msgs[i] = hashmod.hash(.sighash, &[_]u8{@intCast(i)});
        sigs[i] = (try kp.signWithContext(&msgs[i], null, &ctx)).toBytes();
        tasks[i] = .{ .scheme = .ml_dsa_44, .pubkey = &pk, .msg = msgs[i], .sig = &sigs[i] };
    }
    // Tamper with two of them.
    tasks[3].msg = hashmod.hash(.sighash, "different");
    tasks[10].msg = hashmod.hash(.sighash, "also different");

    const serial = try verifyBatch(gpa, &tasks, 1);
    defer gpa.free(serial);
    const parallel = try verifyBatch(gpa, &tasks, 8);
    defer gpa.free(parallel);

    try testing.expectEqualSlices(bool, serial, parallel);
    var valid: usize = 0;
    for (parallel) |ok| {
        if (ok) valid += 1;
    }
    try testing.expectEqual(@as(usize, 14), valid); // 16 - 2 tampered
    try testing.expect(!parallel[3] and !parallel[10]);
}

test "parallel full-spend verification checks commitment and signature" {
    const gpa = testing.allocator;
    const kp = try MlDsa44.KeyPair.generateDeterministic([_]u8{6} ** 32);
    const pk = kp.public_key.toBytes();
    const commitment = prim.addressCommitment(.ml_dsa_44, &pk);
    const ctx = [_]u8{@intFromEnum(pq.SchemeTag.ml_dsa_44)};

    var msgs: [8]Hash256 = undefined;
    var sigs: [8][MlDsa44.Signature.encoded_length]u8 = undefined;
    var tasks: [8]SpendTask = undefined;
    for (0..8) |i| {
        msgs[i] = hashmod.hash(.sighash, &[_]u8{@intCast(i)});
        sigs[i] = (try kp.signWithContext(&msgs[i], null, &ctx)).toBytes();
        tasks[i] = .{ .scheme = .ml_dsa_44, .pubkey = &pk, .commitment = commitment, .msg = msgs[i], .sig = &sigs[i] };
    }
    tasks[2].commitment = hashmod.zero; // spends the wrong output
    tasks[5].msg = hashmod.hash(.sighash, "forged"); // signature won't match

    const res = try verifySpends(gpa, &tasks, 4);
    defer gpa.free(res);
    var valid: usize = 0;
    for (res) |ok| {
        if (ok) valid += 1;
    }
    try testing.expectEqual(@as(usize, 6), valid);
    try testing.expect(!res[2] and !res[5]);
}
