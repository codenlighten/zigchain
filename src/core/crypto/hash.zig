//! Domain-separated hashing for ZigChain.
//!
//! Every distinct hash use in consensus MUST have its own `Domain` so that a
//! preimage produced in one context can never be reinterpreted in another
//! (a classic source of cross-protocol attacks). We use a BIP340-style tagged
//! hash over BLAKE3: the state is primed with `H(tag) || H(tag)` before the
//! message, making the domain boundary itself collision-resistant.
//!
//! Note on conservatism: BLAKE3 is used here for internal, adversary-facing but
//! non-standardised hashing. The Phase-0 spec decision on whether consensus
//! *commitments* should instead use SHAKE256 (FIPS 202) is tracked separately;
//! all such uses are funnelled through this module so the swap is localised.

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;

pub const Hash256 = [32]u8;

pub const zero: Hash256 = [_]u8{0} ** 32;

/// Domain-separation contexts. Adding a variant is a conscious protocol change.
pub const Domain = enum {
    txid,
    wtxid,
    sighash,
    address,
    merkle_leaf,
    merkle_node,
    block_header,
    witness,
    finality_vote,
    pow,
    accumulator,
    utxo,

    pub fn context(self: Domain) []const u8 {
        return switch (self) {
            .txid => "zigchain.v1.txid",
            .wtxid => "zigchain.v1.wtxid",
            .sighash => "zigchain.v1.sighash",
            .address => "zigchain.v1.address",
            .merkle_leaf => "zigchain.v1.merkle.leaf",
            .merkle_node => "zigchain.v1.merkle.node",
            .block_header => "zigchain.v1.block.header",
            .witness => "zigchain.v1.witness",
            .finality_vote => "zigchain.v1.finality.vote",
            .pow => "zigchain.v1.pow",
            .accumulator => "zigchain.v1.accumulator",
            .utxo => "zigchain.v1.utxo",
        };
    }
};

/// Incremental domain-separated hasher.
pub const Hasher = struct {
    inner: Blake3,

    pub fn init(domain: Domain) Hasher {
        const tag = tagDigest(domain);
        var inner = Blake3.init(.{});
        inner.update(&tag);
        inner.update(&tag);
        return .{ .inner = inner };
    }

    pub fn update(self: *Hasher, bytes: []const u8) void {
        self.inner.update(bytes);
    }

    pub fn final(self: *Hasher) Hash256 {
        var out: Hash256 = undefined;
        self.inner.final(&out);
        return out;
    }
};

fn tagDigest(domain: Domain) Hash256 {
    var out: Hash256 = undefined;
    Blake3.hash(domain.context(), &out, .{});
    return out;
}

/// One-shot domain-separated hash of a single byte string.
pub fn hash(domain: Domain, msg: []const u8) Hash256 {
    var h = Hasher.init(domain);
    h.update(msg);
    return h.final();
}

const testing = std.testing;

test "domain separation: same message, different domains -> different digests" {
    const msg = "the quick brown fox";
    const a = hash(.txid, msg);
    const b = hash(.wtxid, msg);
    const c = hash(.sighash, msg);
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expect(!std.mem.eql(u8, &a, &c));
    try testing.expect(!std.mem.eql(u8, &b, &c));
}

test "hashing is deterministic and incremental == one-shot" {
    const one = hash(.address, "abcdef");
    var h = Hasher.init(.address);
    h.update("abc");
    h.update("def");
    const inc = h.final();
    try testing.expectEqualSlices(u8, &one, &inc);
}

test "output is 256-bit (quantum-safe width, no truncation)" {
    try testing.expectEqual(@as(usize, 32), @typeInfo(Hash256).array.len);
}
