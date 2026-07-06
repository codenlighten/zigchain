# ZigChain Proof-of-Work — heavy-hash

Status: normative for the current implementation. The *construction* below is
fixed and covered by cross-implementation test vectors; the *economic parameter
tuning* (ASIC/decentralisation trade-offs) remains a Phase-0/audit decision.

## Rationale

Plain BLAKE3 is a poor PoW: cheap to ASIC and cheap on GPU, so hashrate
centralises quickly. A **heavy-hash** (kHeavyHash / Optical-PoW lineage) inserts
a matrix-vector product between two hashes, adding an arithmetic core that
balances the work across hardware types. Grover gives only a quadratic speedup to
pre-image search, which difficulty absorbs, so PoW is **not** over-engineered for
quantum resistance (unlike signatures, which are fully post-quantum).

## Determinism (why this differs from Kaspa)

Kaspa regenerates its matrix until it is full-rank, computing rank with
**floating-point** Gaussian elimination. Floating point is not reproducible
across platforms and would cause a **consensus split**, so ZigChain does **not**
do this. The matrix is derived deterministically and used as-is. A random 64×64
nibble matrix is full-rank with overwhelming probability; an integer-field rank
check is a possible future refinement, explicitly deferred rather than faked.

All arithmetic is fixed-width and integer-only.

## Construction (N = 64)

Let `H(x)` = the domain-separated tagged hash under domain `zigchain.v1.pow`.

**Per-block matrix** `M` (64×64, entries are nibbles 0..15), from a 32-byte
`seed`:

```
k ← 0 ; counter ← 0
while k < 64*64:
    block ← H(seed ‖ u32_le(counter))        # 32 bytes = 64 nibbles
    for byte in block:
        M[k/64][k%64] ← byte >> 4   ; k ← k+1
        M[k/64][k%64] ← byte & 0x0F ; k ← k+1
    counter ← counter + 1
```

**Heavy-hash** of `data` under `M`:

```
h1 ← H(data)                                  # 32 bytes
v[2k]   ← h1[k] >> 4       for k in 0..32      # 64 nibbles, high nibble first
v[2k+1] ← h1[k] & 0x0F
for i in 0..64:
    p[i] ← ( Σ_{j} M[i][j]·v[j] ) >> 10  & 0x0F
mixed[k] ← h1[k] XOR ( p[2k]<<4 | p[2k+1] )   for k in 0..32
return H(mixed)                               # 32 bytes → compared to the target
```

## Block binding

- `seed` = `H(header-with-nonce-zeroed)`. The matrix therefore depends on every
  header field except the nonce, and is computed **once** per block; miners grind
  the nonce through the cheap inner hash + matrix multiply.
- `data` = the full header encoding (including the nonce).
- The resulting 32-byte digest is compared big-endian against the compact
  difficulty target (`pow.zig`).

## Test vectors

`spec/vectors/scenarios.json` drives a report that includes `heavyhash i <hex>`
lines for deterministic `(seed, data)` pairs. The Zig implementation
(`heavyhash.zig`) and the Rust reference (`refimpl-rs`) must produce identical
bytes — enforced by `tools/difftest.sh`.
