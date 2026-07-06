//! Custody signer — derive a key from a master seed and produce a signature
//! that the consensus registry accepts.
//!
//! This is the air-gapped / remote-signer core: it needs only a master seed, a
//! scheme, a derivation path, and the message (a sighash) — never the online
//! node. Its guarantee, pinned by tests, is that for every supported scheme the
//! produced `(pubkey, sig)` verifies through `registry.verify(scheme, ...)`, so
//! a vault-signed witness is valid on-chain by construction.

const std = @import("std");
const registry = @import("../core/crypto/pq/registry.zig");
const sphincs = @import("../core/crypto/pq/sphincs.zig");
const kdf = @import("../core/crypto/kdf.zig");
const prim = @import("../core/primitives/types.zig");
const hashmod = @import("../core/crypto/hash.zig");

const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;
const MlDsa65 = std.crypto.sign.mldsa.MLDSA65;
const SchemeTag = registry.SchemeTag;
const Hash256 = hashmod.Hash256;

pub const Error = error{UnsupportedScheme} || std.mem.Allocator.Error;

/// A derived public identity: the public key and the on-chain address that
/// commits to it (and to the scheme). Safe to expose from an air-gapped vault.
pub const Identity = struct {
    scheme: SchemeTag,
    pubkey: []u8, // owned

    pub fn address(self: Identity) Hash256 {
        return prim.addressCommitment(self.scheme, self.pubkey);
    }
    pub fn deinit(self: *Identity, gpa: std.mem.Allocator) void {
        gpa.free(self.pubkey);
    }
};

/// A vault-produced witness: verifies through `registry.verify`.
pub const Signature = struct {
    scheme: SchemeTag,
    pubkey: []u8, // owned
    sig: []u8, // owned

    pub fn deinit(self: *Signature, gpa: std.mem.Allocator) void {
        gpa.free(self.pubkey);
        gpa.free(self.sig);
    }
};

/// Derive the public identity for `path` under `scheme` from the master seed.
pub fn identity(gpa: std.mem.Allocator, master: [32]u8, scheme: SchemeTag, path: []const u32) Error!Identity {
    const pk = switch (scheme) {
        .ml_dsa_44 => try mlDsaPubkey(MlDsa44, gpa, master, scheme, path),
        .ml_dsa_65 => try mlDsaPubkey(MlDsa65, gpa, master, scheme, path),
        .sphincs_shake_128f => try sphincsPubkey(gpa, master, scheme, path),
        .sphincs_shake_128s => try sphincsPubkey(gpa, master, scheme, path),
        else => return Error.UnsupportedScheme,
    };
    return .{ .scheme = scheme, .pubkey = pk };
}

/// Sign `msg` (a sighash) with the derived key. The result verifies through
/// `registry.verify(scheme, result.pubkey, msg, result.sig)`.
pub fn sign(gpa: std.mem.Allocator, master: [32]u8, scheme: SchemeTag, path: []const u32, msg: []const u8) Error!Signature {
    return switch (scheme) {
        .ml_dsa_44 => mlDsaSign(MlDsa44, gpa, master, scheme, path, msg),
        .ml_dsa_65 => mlDsaSign(MlDsa65, gpa, master, scheme, path, msg),
        .sphincs_shake_128f => sphincsSign(sphincs.v128f, gpa, master, scheme, path, msg),
        .sphincs_shake_128s => sphincsSign(sphincs.v128s, gpa, master, scheme, path, msg),
        else => Error.UnsupportedScheme,
    };
}

// --- ML-DSA ---

fn mlDsaKeypair(comptime M: type, master: [32]u8, scheme: SchemeTag, path: []const u32) Error!M.KeyPair {
    var seed: [32]u8 = undefined;
    kdf.deriveSeed(master, @intFromEnum(scheme), path, &seed);
    return M.KeyPair.generateDeterministic(seed) catch Error.UnsupportedScheme;
}

fn mlDsaPubkey(comptime M: type, gpa: std.mem.Allocator, master: [32]u8, scheme: SchemeTag, path: []const u32) Error![]u8 {
    const kp = try mlDsaKeypair(M, master, scheme, path);
    return gpa.dupe(u8, &kp.public_key.toBytes());
}

fn mlDsaSign(comptime M: type, gpa: std.mem.Allocator, master: [32]u8, scheme: SchemeTag, path: []const u32, msg: []const u8) Error!Signature {
    const kp = try mlDsaKeypair(M, master, scheme, path);
    const ctx = [_]u8{@intFromEnum(scheme)}; // matches registry.verify's context binding
    const sig = kp.signWithContext(msg, null, &ctx) catch return Error.UnsupportedScheme;
    const pk = try gpa.dupe(u8, &kp.public_key.toBytes());
    errdefer gpa.free(pk);
    return .{ .scheme = scheme, .pubkey = pk, .sig = try gpa.dupe(u8, &sig.toBytes()) };
}

// --- SPHINCS+ ---

fn sphincsPubkey(gpa: std.mem.Allocator, master: [32]u8, scheme: SchemeTag, path: []const u32) Error![]u8 {
    const variant = if (scheme == .sphincs_shake_128f) sphincs.v128f else sphincs.v128s;
    var seed: [sphincs.seed_len]u8 = undefined;
    kdf.deriveSeed(master, @intFromEnum(scheme), path, &seed);
    var pk: [sphincs.pubkey_len]u8 = undefined;
    var sk: [sphincs.sk_len]u8 = undefined;
    if (!variant.seedKeypair(&pk, &sk, &seed)) return Error.UnsupportedScheme;
    return gpa.dupe(u8, &pk);
}

fn sphincsSign(variant: sphincs.Variant, gpa: std.mem.Allocator, master: [32]u8, scheme: SchemeTag, path: []const u32, msg: []const u8) Error!Signature {
    var seed: [sphincs.seed_len]u8 = undefined;
    kdf.deriveSeed(master, @intFromEnum(scheme), path, &seed);
    var pk: [sphincs.pubkey_len]u8 = undefined;
    var sk: [sphincs.sk_len]u8 = undefined;
    if (!variant.seedKeypair(&pk, &sk, &seed)) return Error.UnsupportedScheme;

    var sigbuf: [17088]u8 = undefined;
    const sig = variant.sign(sigbuf[0..variant.sig_len], msg, &sk) orelse return Error.UnsupportedScheme;
    const pkc = try gpa.dupe(u8, &pk);
    errdefer gpa.free(pkc);
    return .{ .scheme = scheme, .pubkey = pkc, .sig = try gpa.dupe(u8, sig) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "every scheme: a vault-signed witness verifies through the consensus registry" {
    const gpa = testing.allocator;
    const master = [_]u8{0x5A} ** 32;
    const path = [_]u32{ 44, 0, 7 };
    const sighash = hashmod.hash(.sighash, "spend authorization");

    for ([_]SchemeTag{ .ml_dsa_44, .ml_dsa_65, .sphincs_shake_128f, .sphincs_shake_128s }) |scheme| {
        var s = try sign(gpa, master, scheme, &path, &sighash);
        defer s.deinit(gpa);

        // The core guarantee: consensus accepts what the vault produced.
        try registry.verify(scheme, s.pubkey, &sighash, s.sig);

        // A different message must not verify against this signature.
        const other = hashmod.hash(.sighash, "different authorization");
        try testing.expectError(registry.Error.InvalidSignature, registry.verify(scheme, s.pubkey, &other, s.sig));
    }
}

test "identity is deterministic, path-bound, and matches the signing key" {
    const gpa = testing.allocator;
    const master = [_]u8{0x11} ** 32;

    var id0 = try identity(gpa, master, .ml_dsa_44, &.{ 0, 0 });
    defer id0.deinit(gpa);
    var id0b = try identity(gpa, master, .ml_dsa_44, &.{ 0, 0 });
    defer id0b.deinit(gpa);
    try testing.expectEqualSlices(u8, id0.pubkey, id0b.pubkey);

    // A different path gives a different address.
    var id1 = try identity(gpa, master, .ml_dsa_44, &.{ 0, 1 });
    defer id1.deinit(gpa);
    try testing.expect(!std.mem.eql(u8, &id0.address(), &id1.address()));

    // The identity's pubkey is the same key `sign` uses.
    const sighash = hashmod.hash(.sighash, "x");
    var s = try sign(gpa, master, .ml_dsa_44, &.{ 0, 0 }, &sighash);
    defer s.deinit(gpa);
    try testing.expectEqualSlices(u8, id0.pubkey, s.pubkey);
}
