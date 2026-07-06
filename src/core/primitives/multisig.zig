//! Script-level k-of-n threshold multisignature.
//!
//! There is no post-quantum threshold *signature* primitive (no BLS analogue),
//! so k-of-n is done at the script level: an output commits to a POLICY
//! (threshold `k` and `n` participant keys), and a spend REVEALS the policy and
//! supplies `k` full signatures from distinct participants — the P2SH pattern.
//! The cost is on-chain size (each of the k signatures is a full PQ signature);
//! that is the deliberate trade the plan calls out.
//!
//! Wire mapping onto the existing witness triple (no new witness type, no
//! serialization change): a spend uses the `multisig` marker scheme, the witness
//! `pubkey` field carries the canonical POLICY bytes, and the `signature` field
//! carries the canonical SIGNER-SET bytes. The output commitment is
//! `H(multisig, policy_bytes)`.
//!
//! Verification is a single streaming merge pass — participants are encoded in
//! order and signers must reference ascending distinct indices — so it needs no
//! allocation and no random access.

const std = @import("std");
const codec = @import("../serialization/codec.zig");
const hashmod = @import("../crypto/hash.zig");
const pq = @import("../crypto/pq/registry.zig");

const Hash256 = hashmod.Hash256;
const SchemeTag = pq.SchemeTag;

/// The marker scheme a multisig output/witness uses.
pub const marker: SchemeTag = .multisig;

pub const max_participants: u32 = 32;
const max_pubkey_len: u32 = 64 * 1024;
const max_sig_len: u32 = 64 * 1024;

pub const Error = error{
    BadPolicy, // malformed policy, out-of-range threshold, or bad participant count
    ThresholdNotMet, // signer count != k
    NonCanonicalSigners, // indices not strictly ascending / trailing bytes
    CommitmentMismatch,
} || pq.Error || codec.ReadError;

pub const Participant = struct { scheme: SchemeTag, pubkey: []const u8 };

/// Encode a policy: threshold, then each participant (in order). Caller owns the
/// returned bytes; `H(multisig, bytes)` is the output commitment.
pub fn encodePolicy(gpa: std.mem.Allocator, threshold: u32, participants: []const Participant) ![]u8 {
    std.debug.assert(participants.len >= 1 and participants.len <= max_participants);
    std.debug.assert(threshold >= 1 and threshold <= participants.len);
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try w.writeU32(threshold);
    try w.writeU32(@intCast(participants.len));
    for (participants) |p| {
        try w.writeByte(@intFromEnum(p.scheme));
        try w.writeVarBytes(p.pubkey);
    }
    return list.toOwnedSlice(gpa);
}

pub fn commitment(policy_bytes: []const u8) Hash256 {
    return hashmod.hash(.multisig, policy_bytes);
}

pub const SignerShare = struct { index: u32, signature: []const u8 };

/// Encode a signer set (indices MUST be strictly ascending). Caller owns bytes.
pub fn encodeSigners(gpa: std.mem.Allocator, shares: []const SignerShare) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try w.writeU32(@intCast(shares.len));
    for (shares) |s| {
        try w.writeU32(s.index);
        try w.writeVarBytes(s.signature);
    }
    return list.toOwnedSlice(gpa);
}

/// Verify a k-of-n spend. `policy_bytes` = witness.pubkey, `signers_bytes` =
/// witness.signature. Allocation-free single pass.
pub fn verify(expected_commitment: Hash256, policy_bytes: []const u8, signers_bytes: []const u8, sighash: Hash256) Error!void {
    if (!std.mem.eql(u8, &commitment(policy_bytes), &expected_commitment)) return Error.CommitmentMismatch;

    var pr = codec.Reader{ .buf = policy_bytes };
    const k = try pr.readU32();
    const n = try pr.readU32();
    if (n == 0 or n > max_participants) return Error.BadPolicy;
    if (k == 0 or k > n) return Error.BadPolicy;

    var sr = codec.Reader{ .buf = signers_bytes };
    if (try sr.readU32() != k) return Error.ThresholdNotMet;

    var next: u32 = 0; // next participant not yet consumed from `pr`
    var prev: i64 = -1;
    var i: u32 = 0;
    while (i < k) : (i += 1) {
        const index = try sr.readU32();
        const sig = try sr.readVarBytes(max_sig_len);
        if (index >= n) return Error.BadPolicy;
        if (@as(i64, index) <= prev) return Error.NonCanonicalSigners; // strictly ascending → distinct
        while (next < index) : (next += 1) { // skip participants before `index`
            _ = try pr.readByte();
            _ = try pr.readVarBytes(max_pubkey_len);
        }
        const pscheme: SchemeTag = @enumFromInt(try pr.readByte());
        const ppub = try pr.readVarBytes(max_pubkey_len);
        next += 1;
        try pq.verify(pscheme, ppub, &sighash, sig); // a participant must be a leaf scheme
        prev = index;
    }
    try sr.finish(); // reject trailing signer bytes (malleability)
}

/// Verification cost for block "mass": the sum of the participating schemes'
/// per-verify costs (k signatures, each a real PQ verify).
pub fn witnessMass(policy_bytes: []const u8, signers_bytes: []const u8) Error!u64 {
    var pr = codec.Reader{ .buf = policy_bytes };
    const k = try pr.readU32();
    const n = try pr.readU32();
    if (n == 0 or n > max_participants or k == 0 or k > n) return Error.BadPolicy;
    var sr = codec.Reader{ .buf = signers_bytes };
    if (try sr.readU32() != k) return Error.ThresholdNotMet;

    var next: u32 = 0;
    var prev: i64 = -1;
    var total: u64 = 0;
    var i: u32 = 0;
    while (i < k) : (i += 1) {
        const index = try sr.readU32();
        _ = try sr.readVarBytes(max_sig_len);
        if (index >= n) return Error.BadPolicy;
        if (@as(i64, index) <= prev) return Error.NonCanonicalSigners;
        while (next < index) : (next += 1) {
            _ = try pr.readByte();
            _ = try pr.readVarBytes(max_pubkey_len);
        }
        const pscheme: SchemeTag = @enumFromInt(try pr.readByte());
        _ = try pr.readVarBytes(max_pubkey_len);
        next += 1;
        total = total +| (pq.info(pscheme) catch return Error.UnknownScheme).verify_mass;
        prev = index;
    }
    return total;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;
const MlDsa65 = std.crypto.sign.mldsa.MLDSA65;

fn makeParticipant(gpa: std.mem.Allocator, comptime M: type, tag: SchemeTag, seed: u8) !Participant {
    const kp = try M.KeyPair.generateDeterministic([_]u8{seed} ** 32);
    return .{ .scheme = tag, .pubkey = try gpa.dupe(u8, &kp.public_key.toBytes()) };
}

fn signWith(gpa: std.mem.Allocator, comptime M: type, tag: SchemeTag, seed: u8, msg: Hash256) ![]u8 {
    const kp = try M.KeyPair.generateDeterministic([_]u8{seed} ** 32);
    const ctx = [_]u8{@intFromEnum(tag)};
    return gpa.dupe(u8, &(try kp.signWithContext(&msg, null, &ctx)).toBytes());
}

test "2-of-3 multisig (mixed schemes) verifies; other subsets and tampering fail" {
    const gpa = testing.allocator;
    const sighash = hashmod.hash(.sighash, "multisig spend");

    // Three participants: two ML-DSA-44, one ML-DSA-65.
    var parts: [3]Participant = .{
        try makeParticipant(gpa, MlDsa44, .ml_dsa_44, 1),
        try makeParticipant(gpa, MlDsa65, .ml_dsa_65, 2),
        try makeParticipant(gpa, MlDsa44, .ml_dsa_44, 3),
    };
    defer for (&parts) |*p| gpa.free(p.pubkey);

    const policy = try encodePolicy(gpa, 2, &parts);
    defer gpa.free(policy);
    const commit = commitment(policy);

    // Sign with participants 0 and 2 (a valid 2-of-3 subset, ascending indices).
    const sig0 = try signWith(gpa, MlDsa44, .ml_dsa_44, 1, sighash);
    defer gpa.free(sig0);
    const sig2 = try signWith(gpa, MlDsa44, .ml_dsa_44, 3, sighash);
    defer gpa.free(sig2);
    const good = try encodeSigners(gpa, &.{ .{ .index = 0, .signature = sig0 }, .{ .index = 2, .signature = sig2 } });
    defer gpa.free(good);
    try verify(commit, policy, good, sighash);

    // Mass = sum of the two participating schemes (ml_dsa_44=1, ml_dsa_44=1).
    try testing.expectEqual(@as(u64, 2), try witnessMass(policy, good));

    // Only one signature → threshold not met.
    const one = try encodeSigners(gpa, &.{.{ .index = 0, .signature = sig0 }});
    defer gpa.free(one);
    try testing.expectError(Error.ThresholdNotMet, verify(commit, policy, one, sighash));

    // Duplicate / non-ascending indices → rejected (malleability guard).
    const dup = try encodeSigners(gpa, &.{ .{ .index = 0, .signature = sig0 }, .{ .index = 0, .signature = sig0 } });
    defer gpa.free(dup);
    try testing.expectError(Error.NonCanonicalSigners, verify(commit, policy, dup, sighash));

    // A signature that is valid but attributed to the wrong participant index
    // (index 1 is ML-DSA-65; sig0 is an ML-DSA-44 sig) → invalid.
    const wrong = try encodeSigners(gpa, &.{ .{ .index = 1, .signature = sig0 }, .{ .index = 2, .signature = sig2 } });
    defer gpa.free(wrong);
    try testing.expectError(pq.Error.BadSignatureLength, verify(commit, policy, wrong, sighash));

    // Wrong commitment (spending a different policy's output) → rejected.
    try testing.expectError(Error.CommitmentMismatch, verify(hashmod.zero, policy, good, sighash));

    // Tampered sighash → the real signatures no longer verify.
    const other = hashmod.hash(.sighash, "different spend");
    try testing.expectError(pq.Error.InvalidSignature, verify(commit, policy, good, other));
}

test "threshold bounds are enforced" {
    const gpa = testing.allocator;
    var parts: [2]Participant = .{
        try makeParticipant(gpa, MlDsa44, .ml_dsa_44, 5),
        try makeParticipant(gpa, MlDsa44, .ml_dsa_44, 6),
    };
    defer for (&parts) |*p| gpa.free(p.pubkey);

    // Hand-craft a policy claiming threshold 3 of 2 participants → BadPolicy.
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try w.writeU32(3); // threshold
    try w.writeU32(2); // n
    for (parts) |p| {
        try w.writeByte(@intFromEnum(p.scheme));
        try w.writeVarBytes(p.pubkey);
    }
    const bad_policy = list.items;
    const empty_signers = try encodeSigners(gpa, &.{});
    defer gpa.free(empty_signers);
    try testing.expectError(Error.BadPolicy, verify(commitment(bad_policy), bad_policy, empty_signers, hashmod.zero));
}
