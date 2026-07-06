//! Post-quantum software licenses.
//!
//! SmartLedger (the issuer) signs a license with a post-quantum key (ML-DSA);
//! every node verifies it OFFLINE against SmartLedger's embedded public key — no
//! phone-home, which suits air-gapped government deployments. A license is a
//! canonically-serialized statement of who is licensed, under what tier, which
//! features, what node/capacity limits, and until when — signed over a
//! domain-separated hash so a license can never be replayed as any other signed
//! object.
//!
//! The model is deliberately flexible so pricing stays a business decision:
//! per-node subscriptions, capacity tiers, feature unlocks (open-core), and
//! consortium/perpetual licenses are all expressible in one structure.

const std = @import("std");
const pq = @import("../core/crypto/pq/registry.zig");
const hashmod = @import("../core/crypto/hash.zig");
const codec = @import("../core/serialization/codec.zig");

const Hash256 = hashmod.Hash256;
const SchemeTag = pq.SchemeTag;

pub const Tier = enum(u8) {
    community = 0, // free — the public network, basic features
    standard = 1,
    enterprise = 2, // vault scheme, compliance modules, higher capacity
    sovereign = 3, // air-gapped, unlimited nodes, priority SLA
    _,
};

/// Feature bit-flags a license may grant (open-core capabilities).
pub const Feature = struct {
    pub const vault_scheme: u64 = 1 << 0; // SPHINCS+ cold-vault signing
    pub const compliance_policy: u64 = 1 << 1; // mempool policy / sanction screening
    pub const high_capacity: u64 = 1 << 2; // above the community throughput cap
    pub const priority_support: u64 = 1 << 3;
};

pub const max_licensee_len: u32 = 256;

pub const License = struct {
    version: u32 = 1,
    /// Unique license identifier (for revocation lists, audit).
    license_id: [16]u8,
    /// The licensed organisation / deployment.
    licensee: []const u8,
    tier: Tier,
    features: u64, // OR of Feature.*
    max_nodes: u32, // 0 = unlimited
    max_tps: u32, // 0 = unlimited
    issued_at: u64, // unix seconds
    expires_at: u64, // unix seconds, 0 = perpetual
    scheme: SchemeTag, // issuer signature scheme

    /// Canonical byte encoding — the exact preimage the signature commits to.
    pub fn encode(self: License, w: *codec.Writer) !void {
        try w.writeU32(self.version);
        try w.writeBytes(&self.license_id);
        try w.writeVarBytes(self.licensee);
        try w.writeByte(@intFromEnum(self.tier));
        try w.writeU64(self.features);
        try w.writeU32(self.max_nodes);
        try w.writeU32(self.max_tps);
        try w.writeU64(self.issued_at);
        try w.writeU64(self.expires_at);
        try w.writeByte(@intFromEnum(self.scheme));
    }

    /// Domain-separated hash of the canonical encoding (what is signed).
    pub fn digest(self: License, gpa: std.mem.Allocator) !Hash256 {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        var w = codec.Writer{ .list = &list, .gpa = gpa };
        try self.encode(&w);
        return hashmod.hash(.license, list.items);
    }

    pub fn hasFeature(self: License, f: u64) bool {
        return (self.features & f) == f;
    }

    /// Valid at time `now` (seconds)? Perpetual if expires_at == 0.
    pub fn withinValidity(self: License, now: u64) bool {
        if (now < self.issued_at) return false;
        if (self.expires_at != 0 and now >= self.expires_at) return false;
        return true;
    }
};

pub const Error = error{
    InvalidSignature,
    Expired,
    NotYetValid,
} || pq.Error || std.mem.Allocator.Error;

/// Sign a license with the issuer's ML-DSA-44 key. Returns the signature bytes
/// (caller owns). The issuer keeps the secret key; the public key is embedded
/// in the software for verification.
pub fn sign(gpa: std.mem.Allocator, kp: MlDsa44.KeyPair, license: License) ![]u8 {
    std.debug.assert(license.scheme == .ml_dsa_44);
    const h = try license.digest(gpa);
    const ctx = [_]u8{@intFromEnum(SchemeTag.ml_dsa_44)};
    const sig = try kp.signWithContext(&h, null, &ctx);
    return gpa.dupe(u8, &sig.toBytes());
}

/// Verify a license against the issuer's public key, offline, at time `now`.
/// Returns the granted License on success.
pub fn verify(gpa: std.mem.Allocator, issuer_pubkey: []const u8, license: License, sig: []const u8, now: u64) Error!void {
    const h = try license.digest(gpa);
    pq.verify(license.scheme, issuer_pubkey, &h, sig) catch return Error.InvalidSignature;
    if (now < license.issued_at) return Error.NotYetValid;
    if (license.expires_at != 0 and now >= license.expires_at) return Error.Expired;
}

/// A license plus its signature — the token stored/distributed as a file.
pub const SignedLicense = struct {
    license: License,
    signature: []const u8,

    pub fn encode(self: SignedLicense, w: *codec.Writer) !void {
        try self.license.encode(w);
        try w.writeVarBytes(self.signature);
    }

    /// Decode a token. Variable fields reference the reader buffer (keep it alive).
    pub fn decode(r: *codec.Reader, gpa: std.mem.Allocator) !SignedLicense {
        _ = gpa;
        const version = try r.readU32();
        var license_id: [16]u8 = undefined;
        @memcpy(&license_id, (try r.readN(16))[0..16]);
        const licensee = try r.readVarBytes(max_licensee_len);
        const tier: Tier = @enumFromInt(try r.readByte());
        const features = try r.readU64();
        const max_nodes = try r.readU32();
        const max_tps = try r.readU32();
        const issued_at = try r.readU64();
        const expires_at = try r.readU64();
        const scheme: SchemeTag = @enumFromInt(try r.readByte());
        const signature = try r.readVarBytes(64 * 1024);
        return .{
            .license = .{
                .version = version,
                .license_id = license_id,
                .licensee = licensee,
                .tier = tier,
                .features = features,
                .max_nodes = max_nodes,
                .max_tps = max_tps,
                .issued_at = issued_at,
                .expires_at = expires_at,
                .scheme = scheme,
            },
            .signature = signature,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;

fn sampleLicense() License {
    return .{
        .license_id = [_]u8{0xA1} ** 16,
        .licensee = "Acme Clearing Corp",
        .tier = .enterprise,
        .features = Feature.vault_scheme | Feature.compliance_policy,
        .max_nodes = 10,
        .max_tps = 0,
        .issued_at = 1_700_000_000,
        .expires_at = 1_800_000_000,
        .scheme = .ml_dsa_44,
    };
}

test "license: sign then verify offline, with feature + expiry semantics" {
    const gpa = testing.allocator;
    const issuer = try MlDsa44.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const pub_bytes = issuer.public_key.toBytes();

    const lic = sampleLicense();
    const sig = try sign(gpa, issuer, lic);
    defer gpa.free(sig);

    // Valid at a time inside the window.
    try verify(gpa, &pub_bytes, lic, sig, 1_750_000_000);

    // Feature gating.
    try testing.expect(lic.hasFeature(Feature.vault_scheme));
    try testing.expect(lic.hasFeature(Feature.compliance_policy));
    try testing.expect(!lic.hasFeature(Feature.high_capacity));

    // Expired / not-yet-valid.
    try testing.expectError(Error.Expired, verify(gpa, &pub_bytes, lic, sig, 1_800_000_001));
    try testing.expectError(Error.NotYetValid, verify(gpa, &pub_bytes, lic, sig, 1_699_999_999));
}

test "license: tampering and wrong issuer are rejected" {
    const gpa = testing.allocator;
    const issuer = try MlDsa44.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const pub_bytes = issuer.public_key.toBytes();
    const impostor = try MlDsa44.KeyPair.generateDeterministic([_]u8{9} ** 32);
    const impostor_pub = impostor.public_key.toBytes();

    const lic = sampleLicense();
    const sig = try sign(gpa, issuer, lic);
    defer gpa.free(sig);

    // Same signature, different (impostor) verifying key → rejected.
    try testing.expectError(Error.InvalidSignature, verify(gpa, &impostor_pub, lic, sig, 1_750_000_000));

    // Tampered terms (upgrade the tier / lift the node cap) → signature no longer matches.
    var upgraded = lic;
    upgraded.tier = .sovereign;
    upgraded.max_nodes = 0;
    try testing.expectError(Error.InvalidSignature, verify(gpa, &pub_bytes, upgraded, sig, 1_750_000_000));
}

test "license: signed token round-trips through the wire" {
    const gpa = testing.allocator;
    const issuer = try MlDsa44.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const pub_bytes = issuer.public_key.toBytes();
    const lic = sampleLicense();
    const sig = try sign(gpa, issuer, lic);
    defer gpa.free(sig);

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    var w = codec.Writer{ .list = &list, .gpa = gpa };
    try (SignedLicense{ .license = lic, .signature = sig }).encode(&w);

    var r = codec.Reader{ .buf = list.items };
    const token = try SignedLicense.decode(&r, gpa);
    try r.finish();

    try testing.expectEqualStrings("Acme Clearing Corp", token.license.licensee);
    try testing.expectEqual(Tier.enterprise, token.license.tier);
    // The decoded token still verifies against the issuer key.
    try verify(gpa, &pub_bytes, token.license, token.signature, 1_750_000_000);
}
