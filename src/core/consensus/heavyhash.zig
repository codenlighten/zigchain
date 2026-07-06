//! ZigChain heavy-hash — the proof-of-work function (kHeavyHash-lineage).
//!
//! Plain hashing (BLAKE3) is a poor PoW: cheap to ASIC and cheap on GPU, so it
//! centralises fast. A "heavy" hash sandwiches a per-block matrix-vector product
//! between two hashes, adding an arithmetic core that balances the work across
//! hardware types (the Kaspa/Optical-PoW approach). This is a *ZigChain variant*
//! of that lineage — the construction is fixed here; the exact
//! ASIC-decentralisation parameter tuning remains a documented Phase-0/audit
//! decision (see the plan), not something this module claims to have settled.
//!
//! Consensus-critical properties, honoured deliberately:
//!  - Fully DETERMINISTIC and integer-only. Kaspa's full-rank matrix regeneration
//!    uses floating-point Gaussian elimination, which is non-reproducible across
//!    platforms → a consensus split. We do NOT do that: the matrix is derived
//!    deterministically and used as-is (a random nibble matrix is full-rank with
//!    overwhelming probability; the rank *check* is a marginal refinement left as
//!    future work, noted rather than hidden).
//!  - Fixed-width arithmetic, no usize on any value that affects the digest.
//!
//! Algorithm (N = 64):
//!   matrix M[N][N] of nibbles ← derived from a 32-byte per-block `seed`
//!   heavyHash(M, data):
//!     h1 = H_pow(data)                         # 32 bytes = 64 nibbles
//!     v[j] = nibble j of h1
//!     p[i] = ( Σ_j M[i][j]·v[j] ) >> 10  & 0xF
//!     mixed[k] = h1[k] XOR (p[2k]<<4 | p[2k+1])
//!     return H_pow(mixed)

const std = @import("std");
const hashmod = @import("../crypto/hash.zig");

const Hash256 = hashmod.Hash256;

pub const n: usize = 64;
pub const Matrix = [n][n]u8; // entries are nibbles, 0..15

/// Derive the per-block matrix from a 32-byte seed. Deterministic: fills 64×64
/// nibbles from the byte stream H_pow(seed ‖ counter_le), counter = 0,1,2,…
pub fn genMatrix(seed: Hash256) Matrix {
    var m: Matrix = undefined;
    var buf: [36]u8 = undefined;
    @memcpy(buf[0..32], &seed);

    var k: usize = 0; // nibble index, row-major
    var counter: u32 = 0;
    while (k < n * n) : (counter += 1) {
        std.mem.writeInt(u32, buf[32..36], counter, .little);
        const block = hashmod.hash(.pow, &buf); // 32 bytes = 64 nibbles
        for (block) |byte| {
            if (k >= n * n) break;
            m[k / n][k % n] = byte >> 4;
            k += 1;
            if (k >= n * n) break;
            m[k / n][k % n] = byte & 0x0F;
            k += 1;
        }
    }
    return m;
}

/// The heavy-hash of `data` under a precomputed matrix (the mining hot path:
/// the matrix is computed once per block, this runs once per nonce).
pub fn heavyHashWithMatrix(m: *const Matrix, data: []const u8) Hash256 {
    const h1 = hashmod.hash(.pow, data);

    // 64 nibbles of h1 (high nibble first within each byte).
    var v: [n]u8 = undefined;
    for (0..32) |k| {
        v[2 * k] = h1[k] >> 4;
        v[2 * k + 1] = h1[k] & 0x0F;
    }

    // p[i] = (Σ_j M[i][j]·v[j]) >> 10, reduced to a nibble.
    var p: [n]u8 = undefined;
    for (0..n) |i| {
        var sum: u32 = 0;
        for (0..n) |j| sum += @as(u32, m[i][j]) * @as(u32, v[j]);
        p[i] = @intCast((sum >> 10) & 0x0F);
    }

    // Fold the product back into h1, then hash again.
    var mixed: [32]u8 = undefined;
    for (0..32) |k| mixed[k] = h1[k] ^ ((p[2 * k] << 4) | p[2 * k + 1]);

    return hashmod.hash(.pow, &mixed);
}

/// Convenience: derive the matrix from `seed` and heavy-hash `data`. Used on the
/// validation path (one shot); miners cache the matrix via `genMatrix`.
pub fn heavyHash(seed: Hash256, data: []const u8) Hash256 {
    const m = genMatrix(seed);
    return heavyHashWithMatrix(&m, data);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "heavy-hash is deterministic and matrix-dependent" {
    const seed = hashmod.hash(.pow, "block-seed");
    const data = "header-with-nonce";

    // Deterministic: same inputs → same digest.
    const a = heavyHash(seed, data);
    const b = heavyHash(seed, data);
    try testing.expectEqualSlices(u8, &a, &b);

    // The cached-matrix path matches the one-shot path exactly.
    var m = genMatrix(seed);
    const c = heavyHashWithMatrix(&m, data);
    try testing.expectEqualSlices(u8, &a, &c);

    // A different block seed (different matrix) changes the digest even for the
    // same data — the matrix genuinely participates.
    const seed2 = hashmod.hash(.pow, "other-seed");
    const d = heavyHash(seed2, data);
    try testing.expect(!std.mem.eql(u8, &a, &d));
}

test "heavy-hash differs from plain domain hashing (the matrix step matters)" {
    const seed = hashmod.hash(.pow, "seed");
    const data = "abc";
    const heavy = heavyHash(seed, data);
    const plain = hashmod.hash(.pow, data);
    try testing.expect(!std.mem.eql(u8, &heavy, &plain));
}

test "heavy-hash avalanches on a one-bit input change" {
    const seed = hashmod.hash(.pow, "seed");
    var m = genMatrix(seed);
    const h0 = heavyHashWithMatrix(&m, "nonce-00000000");
    const h1 = heavyHashWithMatrix(&m, "nonce-00000001");
    var diff: usize = 0;
    for (h0, h1) |x, y| diff += @popCount(x ^ y);
    // Expect roughly half of 256 bits to flip; assert it is clearly not stuck.
    try testing.expect(diff > 64 and diff < 192);
}

test "matrix entries are all nibbles" {
    const m = genMatrix(hashmod.hash(.pow, "s"));
    for (m) |row| for (row) |e| try testing.expect(e <= 15);
}
