//! SPHINCS+ (hash-based) signatures, backed by vendored, pinned PQClean C.
//!
//! These are the cold-vault / long-term-custody schemes: huge signatures
//! (7.9–17 KB) but a security assumption resting only on the hash function, with
//! no algebraic structure — the most conservative post-quantum choice, kept for
//! keys that must survive decades.
//!
//! Provenance: the C sources live under `vendor/pqclean/`, pinned to a specific
//! PQClean commit and checksummed (`vendor/pqclean/MANIFEST.txt`). Those exact
//! bytes are validated against the NIST/SPHINCS+ known-answer tests by PQClean's
//! own CI — that is where correctness-vs-standard assurance comes from; we never
//! hand-roll the primitive. This is SPHINCS+ round-3.1 "simple"; FIPS 205
//! SLH-DSA is the same parameter set with different domain separation, a future
//! drop-in.
//!
//! FFI safety (the plan's rule): every length is validated on the ZIG side
//! *before* the C runs. C is never trusted to bounds-check.

const std = @import("std");

pub const seed_len: usize = 48;
pub const sk_len: usize = 64;
pub const pubkey_len: usize = 32;

// --- extern C entry points (PQClean clean impls; prefixed, no symbol clash) ---

const c = struct {
    extern fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(sig: [*]const u8, siglen: usize, m: [*]const u8, mlen: usize, pk: [*]const u8) c_int;
    extern fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_seed_keypair(pk: [*]u8, sk: [*]u8, seed: [*]const u8) c_int;
    extern fn PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(sig: [*]u8, siglen: *usize, m: [*]const u8, mlen: usize, sk: [*]const u8) c_int;

    extern fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(sig: [*]const u8, siglen: usize, m: [*]const u8, mlen: usize, pk: [*]const u8) c_int;
    extern fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_seed_keypair(pk: [*]u8, sk: [*]u8, seed: [*]const u8) c_int;
    extern fn PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig: [*]u8, siglen: *usize, m: [*]const u8, mlen: usize, sk: [*]const u8) c_int;
};

/// One SPHINCS+ parameter set, wrapping its three C entry points behind
/// length-checked Zig functions.
pub const Variant = struct {
    sig_len: usize,
    verify_fn: *const fn ([*]const u8, usize, [*]const u8, usize, [*]const u8) callconv(.c) c_int,
    keypair_fn: *const fn ([*]u8, [*]u8, [*]const u8) callconv(.c) c_int,
    sign_fn: *const fn ([*]u8, *usize, [*]const u8, usize, [*]const u8) callconv(.c) c_int,

    /// Verify a detached signature. All lengths are checked here before the C
    /// touches any buffer; returns false on any length mismatch or bad signature.
    pub fn verify(self: Variant, pubkey: []const u8, msg: []const u8, sig: []const u8) bool {
        if (pubkey.len != pubkey_len) return false;
        if (sig.len != self.sig_len) return false;
        return self.verify_fn(sig.ptr, sig.len, msg.ptr, msg.len, pubkey.ptr) == 0;
    }

    /// Deterministic keypair from a 48-byte seed. `pk`/`sk` must be exactly
    /// `pubkey_len`/`sk_len`. Used by the vault tool and tests (not consensus).
    pub fn seedKeypair(self: Variant, pk: []u8, sk: []u8, seed: []const u8) bool {
        if (pk.len != pubkey_len or sk.len != sk_len or seed.len != seed_len) return false;
        return self.keypair_fn(pk.ptr, sk.ptr, seed.ptr) == 0;
    }

    /// Sign `msg` (detached). `sig_out` must be at least `sig_len`. Returns the
    /// signature slice on success. (Signing randomises `optrand` via the C RNG.)
    pub fn sign(self: Variant, sig_out: []u8, msg: []const u8, sk: []const u8) ?[]u8 {
        if (sig_out.len < self.sig_len or sk.len != sk_len) return null;
        var siglen: usize = 0;
        if (self.sign_fn(sig_out.ptr, &siglen, msg.ptr, msg.len, sk.ptr) != 0) return null;
        if (siglen != self.sig_len) return null;
        return sig_out[0..siglen];
    }
};

pub const v128f: Variant = .{
    .sig_len = 17088,
    .verify_fn = c.PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify,
    .keypair_fn = c.PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_seed_keypair,
    .sign_fn = c.PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature,
};

pub const v128s: Variant = .{
    .sig_len = 7856,
    .verify_fn = c.PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify,
    .keypair_fn = c.PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_seed_keypair,
    .sign_fn = c.PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature,
};

// ---------------------------------------------------------------------------
// Tests (require the vendored C to be linked — see build.zig).
// ---------------------------------------------------------------------------

const testing = std.testing;

fn roundTrip(comptime variant: Variant) !void {
    var seed: [seed_len]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    var pk: [pubkey_len]u8 = undefined;
    var sk: [sk_len]u8 = undefined;
    try testing.expect(variant.seedKeypair(&pk, &sk, &seed));

    const msg = "zigchain cold-vault authorization";
    var sigbuf: [17088]u8 = undefined;
    const sig = variant.sign(sigbuf[0..variant.sig_len], msg, &sk) orelse return error.SignFailed;

    // Valid signature verifies; tamper and wrong-message do not.
    try testing.expect(variant.verify(&pk, msg, sig));
    try testing.expect(!variant.verify(&pk, "different message", sig));
    var bad = sigbuf;
    bad[100] ^= 1;
    try testing.expect(!variant.verify(&pk, msg, bad[0..variant.sig_len]));

    // Length validation happens before the C: wrong lengths → false, no crash.
    try testing.expect(!variant.verify(pk[0 .. pubkey_len - 1], msg, sig));
    try testing.expect(!variant.verify(&pk, msg, sig[0 .. sig.len - 1]));
}

test "sphincs+ 128f round-trips and rejects tampering" {
    try roundTrip(v128f);
}

test "sphincs+ 128s round-trips and rejects tampering" {
    try roundTrip(v128s);
}

test "sphincs+ deterministic keygen is stable (regression KAT on the public key)" {
    // A fixed seed must always produce the same public key. This pins the
    // vendored build against silent parameter/source drift: the second half of
    // pk is the hashed Merkle-tree root, so matching it exercises the full
    // SPHINCS+ key generation. Value = PQClean 128f seed_keypair for
    // seed = 0x00,0x01,…,0x2f.
    var seed: [seed_len]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    var pk: [pubkey_len]u8 = undefined;
    var sk: [sk_len]u8 = undefined;
    try testing.expect(v128f.seedKeypair(&pk, &sk, &seed));
    try testing.expectEqualStrings(
        "202122232425262728292a2b2c2d2e2fa90e4715b9a925c332801767fd786371",
        &std.fmt.bytesToHex(pk, .lower),
    );
}
