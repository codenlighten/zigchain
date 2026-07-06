//! Post-quantum signature scheme registry (tagged / versioned).
//!
//! Every witness carries a one-byte `SchemeTag`. Fixed lengths per tag let us
//! reject malformed witnesses *before* touching any crypto. The scheme tag is
//! additionally bound as the signature *context*, so a signature produced under
//! one scheme can never be replayed under another — the downgrade / cross-
//! protocol guard, complementing the tag binding in the sighash and address.
//!
//! ML-DSA (Dilithium) is provided natively by the Zig standard library, so our
//! default hot schemes require no C FFI — a direct win for the memory-safety /
//! assurance story. The hash-based vault schemes are SPHINCS+ (shake-128, simple),
//! backed by vendored, pinned, checksummed PQClean C (see `sphincs.zig` and
//! `vendor/pqclean/`) — the primitive is never hand-rolled. (These are SPHINCS+
//! round-3.1; FIPS 205 SLH-DSA is the same parameters with different domain
//! separation, a future drop-in.) Stateful schemes (XMSS/LMS) are permanently
//! banned from the registry: one-time-key reuse is catastrophic.

const std = @import("std");
const sphincs = @import("sphincs.zig");
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;
const MlDsa65 = std.crypto.sign.mldsa.MLDSA65;

pub const SchemeTag = enum(u8) {
    ml_dsa_44 = 0x01, // default hot
    ml_dsa_65 = 0x02,
    sphincs_shake_128s = 0x03, // vault / cold — small signature (7856 B)
    sphincs_shake_128f = 0x04, // vault / cold — fast signing (17088 B)
    multisig = 0x10, // marker: script-level k-of-n (see primitives/multisig.zig).
    // Not a base signature scheme — verified via multisig.verify, never the
    // generic path, so info()/verify() below reject it as a directly-usable scheme.
    _, // any other value is consensus-invalid (UnknownScheme)
};

pub const Error = error{
    UnknownScheme,
    UnimplementedScheme,
    BadPublicKeyLength,
    BadSignatureLength,
    InvalidSignature,
};

pub const SchemeInfo = struct {
    pubkey_len: u32,
    sig_len: u32,
    /// Relative verification cost, used for block "mass" / DoS accounting so a
    /// block cannot be packed with the most-expensive-to-verify scheme.
    verify_mass: u64,
    implemented: bool,
};

pub fn info(tag: SchemeTag) Error!SchemeInfo {
    return switch (tag) {
        .ml_dsa_44 => .{
            .pubkey_len = @intCast(MlDsa44.PublicKey.encoded_length),
            .sig_len = @intCast(MlDsa44.Signature.encoded_length),
            .verify_mass = 1,
            .implemented = true,
        },
        .ml_dsa_65 => .{
            .pubkey_len = @intCast(MlDsa65.PublicKey.encoded_length),
            .sig_len = @intCast(MlDsa65.Signature.encoded_length),
            .verify_mass = 2,
            .implemented = true,
        },
        .sphincs_shake_128s => .{ .pubkey_len = 32, .sig_len = 7856, .verify_mass = 64, .implemented = true },
        .sphincs_shake_128f => .{ .pubkey_len = 32, .sig_len = 17088, .verify_mass = 128, .implemented = true },
        .multisig => Error.UnimplementedScheme, // handled by multisig.verify, not here
        _ => Error.UnknownScheme,
    };
}

/// Verify `sig` over `msg` (the sighash) for public key `pubkey` under `tag`.
/// Lengths are checked against the registry before any crypto runs.
pub fn verify(tag: SchemeTag, pubkey: []const u8, msg: []const u8, sig: []const u8) Error!void {
    const meta = try info(tag);
    if (!meta.implemented) return Error.UnimplementedScheme;
    if (pubkey.len != meta.pubkey_len) return Error.BadPublicKeyLength;
    if (sig.len != meta.sig_len) return Error.BadSignatureLength;

    const ctx = [_]u8{@intFromEnum(tag)}; // bind scheme tag as signature context
    switch (tag) {
        .ml_dsa_44 => try verifyMlDsa(MlDsa44, pubkey, msg, sig, &ctx),
        .ml_dsa_65 => try verifyMlDsa(MlDsa65, pubkey, msg, sig, &ctx),
        // SPHINCS+ has no signature-context parameter; downgrade protection comes
        // from the scheme tag already being bound into the sighash and the address
        // commitment (see primitives/types.zig).
        .sphincs_shake_128f => if (!sphincs.v128f.verify(pubkey, msg, sig)) return Error.InvalidSignature,
        .sphincs_shake_128s => if (!sphincs.v128s.verify(pubkey, msg, sig)) return Error.InvalidSignature,
        .multisig => return Error.UnimplementedScheme, // nested multisig is not a leaf scheme
        else => return Error.UnimplementedScheme,
    }
}

fn verifyMlDsa(comptime M: type, pubkey: []const u8, msg: []const u8, sig: []const u8, ctx: []const u8) Error!void {
    const pk = M.PublicKey.fromBytes(pubkey[0..M.PublicKey.encoded_length].*) catch return Error.InvalidSignature;
    const s = M.Signature.fromBytes(sig[0..M.Signature.encoded_length].*) catch return Error.InvalidSignature;
    s.verifyWithContext(msg, pk, ctx) catch return Error.InvalidSignature;
}

const testing = std.testing;

test "registry sizes are the quantum-safe, standardised values" {
    const info44 = try info(.ml_dsa_44);
    try testing.expectEqual(@as(u32, 1312), info44.pubkey_len);
    try testing.expectEqual(@as(u32, 2420), info44.sig_len);
    const info65 = try info(.ml_dsa_65);
    try testing.expectEqual(@as(u32, 1952), info65.pubkey_len);
    try testing.expectEqual(@as(u32, 3309), info65.sig_len); // FIPS 204 final
}

test "unknown tag is consensus-invalid" {
    try testing.expectError(Error.UnknownScheme, info(@enumFromInt(0x7f)));
}

test "SPHINCS+ vault scheme verifies end-to-end through the registry" {
    inline for (.{ .{ SchemeTag.sphincs_shake_128f, sphincs.v128f }, .{ SchemeTag.sphincs_shake_128s, sphincs.v128s } }) |pair| {
        const tag = pair[0];
        const variant = pair[1];
        var seed: [sphincs.seed_len]u8 = undefined;
        for (&seed, 0..) |*b, i| b.* = @intCast(i);
        var pk: [sphincs.pubkey_len]u8 = undefined;
        var sk: [sphincs.sk_len]u8 = undefined;
        try testing.expect(variant.seedKeypair(&pk, &sk, &seed));

        const msg = "vault sighash";
        var sigbuf: [17088]u8 = undefined;
        const sig = variant.sign(sigbuf[0..variant.sig_len], msg, &sk).?;

        try verify(tag, &pk, msg, sig);
        try testing.expectError(Error.InvalidSignature, verify(tag, &pk, "vault sighasH", sig));
    }
}

test "an all-zero signature of the right length is rejected, not a silent pass" {
    try testing.expectError(Error.InvalidSignature, verify(.sphincs_shake_128s, &[_]u8{0} ** 32, "x", &[_]u8{0} ** 7856));
}

test "wrong-length inputs rejected before crypto" {
    try testing.expectError(Error.BadPublicKeyLength, verify(.ml_dsa_44, "short", "x", &[_]u8{0} ** 2420));
    try testing.expectError(Error.BadSignatureLength, verify(.ml_dsa_44, &[_]u8{0} ** 1312, "x", "short"));
}

test "end-to-end ML-DSA-44 verify through the registry" {
    const kp = try MlDsa44.KeyPair.generateDeterministic([_]u8{3} ** 32);
    const pk = kp.public_key.toBytes();
    const msg = "sighash-like message";
    const ctx = [_]u8{@intFromEnum(SchemeTag.ml_dsa_44)};
    const sig = (try kp.signWithContext(msg, null, &ctx)).toBytes();

    try verify(.ml_dsa_44, &pk, msg, &sig);
    // Tampered message must fail.
    try testing.expectError(Error.InvalidSignature, verify(.ml_dsa_44, &pk, "sighash-like messagE", &sig));
}
