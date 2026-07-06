//! Post-quantum HD key derivation — a hardened-only seed tree.
//!
//! Lattice/hash-based signatures (ML-DSA, SPHINCS+) have no BIP32-style additive
//! homomorphism, so there is **no public (watch-only) derivation** — every child
//! key needs the master secret. That is a genuine limitation, documented rather
//! than hidden. Derivation is therefore a plain domain-separated KDF over the
//! master seed, the scheme tag, and a hardened path:
//!
//!     seed_i = BLAKE3-tagged(kdf, master ‖ scheme ‖ path ‖ counter)   (counter-mode XOF)
//!
//! Binding the scheme tag means the same path under two schemes yields unrelated
//! keys, and binding the whole path means siblings are independent.

const std = @import("std");
const hashmod = @import("hash.zig");

pub const master_len: usize = 32;

/// Fill `out` with `out.len` bytes of key material derived from `master`, the
/// one-byte `scheme_tag`, and the hardened `path`. Deterministic. `out` is
/// typically 32 bytes (ML-DSA seed) or 48 bytes (SPHINCS+ seed).
pub fn deriveSeed(master: [master_len]u8, scheme_tag: u8, path: []const u32, out: []u8) void {
    var counter: u32 = 0;
    var off: usize = 0;
    while (off < out.len) : (counter += 1) {
        var h = hashmod.Hasher.init(.key_derivation);
        h.update(&master);
        h.update(&[_]u8{scheme_tag});
        var b: [4]u8 = undefined;
        for (path) |p| {
            std.mem.writeInt(u32, &b, p, .little);
            h.update(&b);
        }
        std.mem.writeInt(u32, &b, counter, .little);
        h.update(&b);
        const block = h.final(); // 32 bytes
        const n = @min(block.len, out.len - off);
        @memcpy(out[off .. off + n], block[0..n]);
        off += n;
    }
}

const testing = std.testing;

test "derivation is deterministic and fills any length" {
    const master = [_]u8{0xAB} ** 32;
    var a: [48]u8 = undefined;
    var b: [48]u8 = undefined;
    deriveSeed(master, 0x01, &.{ 0, 5, 9 }, &a);
    deriveSeed(master, 0x01, &.{ 0, 5, 9 }, &b);
    try testing.expectEqualSlices(u8, &a, &b);

    // A 32-byte draw is the prefix-independent first block of the same stream.
    var s32: [32]u8 = undefined;
    deriveSeed(master, 0x01, &.{ 0, 5, 9 }, &s32);
    try testing.expectEqualSlices(u8, a[0..32], &s32);
}

test "path, scheme and master are all binding" {
    const master = [_]u8{7} ** 32;
    var base: [32]u8 = undefined;
    deriveSeed(master, 0x01, &.{ 0, 0 }, &base);

    var diff_path: [32]u8 = undefined;
    deriveSeed(master, 0x01, &.{ 0, 1 }, &diff_path);
    try testing.expect(!std.mem.eql(u8, &base, &diff_path));

    var diff_scheme: [32]u8 = undefined;
    deriveSeed(master, 0x04, &.{ 0, 0 }, &diff_scheme);
    try testing.expect(!std.mem.eql(u8, &base, &diff_scheme));

    var diff_master: [32]u8 = undefined;
    deriveSeed([_]u8{8} ** 32, 0x01, &.{ 0, 0 }, &diff_master);
    try testing.expect(!std.mem.eql(u8, &base, &diff_master));

    // Sibling of a different depth is independent too.
    var deeper: [32]u8 = undefined;
    deriveSeed(master, 0x01, &.{ 0, 0, 0 }, &deeper);
    try testing.expect(!std.mem.eql(u8, &base, &deeper));
}
