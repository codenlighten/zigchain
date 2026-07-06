# ZigChain

A post-quantum, proof-of-work **BlockDAG** Layer-1 with a **UTXO** ledger and a
**BFT finality gadget**, written in Zig for government / enterprise settlement.
The design bar is *maximally robust and defensible in a security audit*, not
*ship fast*. See the full architecture plan for the reasoning behind every
decision (trust model, finality, assurance strategy).

## Status

Phase 1 foundation (single-node core primitives), all dependency-free and tested:

| Module | Path | What it does |
|---|---|---|
| Hashing | `src/core/crypto/hash.zig` | BLAKE3 tagged / domain-separated hashing, 256-bit output |
| PQ registry | `src/core/crypto/pq/registry.zig` | Tagged multi-scheme signatures; ML-DSA-44/65 native, SLH-DSA reserved |
| Serialization | `src/core/serialization/codec.zig` | Canonical, byte-exact, little-endian, bounded decode |
| Primitives | `src/core/primitives/types.zig` | OutPoint/Input/Output/Witness/Transaction, txid/wtxid/sighash, addresses |
| Block | `src/core/primitives/block.zig` | BlockHeader + block id; promote-odd merkle root (CVE-2012-2459-safe) |
| UTXO set | `src/core/ledger/utxo.zig` | OutPoint-keyed unspent-output set (sharding-ready interface) |
| Tx validation | `src/core/ledger/validation.zig` | Double-spend, value conservation, PQ-signature auth → fee; connect |
| DAG | `src/core/consensus/dag.zig` | BlockDAG store + deterministic topological order (hash tie-break) |
| GHOSTDAG | `src/core/consensus/ghostdag.zig` | k-cluster blue-set coloring, blue score, virtual-chain order (spec: `spec/ghostdag.md`) |
| Processor | `src/core/consensus/processor.zig` | Applies txs in GHOSTDAG order; deterministic cross-anticone double-spend resolution |

```
zig build test --summary all      # 28/28 passing
```

**Phase-1 goal reached:** a DAG of post-quantum-signed transactions is colored by
GHOSTDAG, linearized, and applied to the UTXO set — with double-spends across
parallel (anticone) blocks resolved to a single deterministic winner
(first-in-consensus-order wins). End-to-end, all in memory-safe native Zig.

## Key properties already enforced in code

- **Post-quantum only.** ML-DSA (Dilithium) is provided *natively* by Zig's std
  library — our default hot schemes need **no C FFI**, a direct win for the
  memory-safety / assurance story. (This refines the original plan, which
  assumed PQClean bindings for ML-DSA; C vendoring is now only needed for the
  SPHINCS+ vault schemes in Phase 4.)
- **Tagged, versioned scheme registry** from day one; unknown tag = invalid;
  fixed per-scheme lengths reject malformed witnesses before any crypto runs.
- **Downgrade / cross-protocol defence in depth:** the scheme tag is bound into
  the sighash, into the address commitment, *and* as the signature context.
- **Segregated witnesses:** the txid commits to the witness-free body, so
  signatures are malleability-free and prunable (verified by test).
- **Quantum-safe widths:** 256-bit hashes and address commitments — no
  sub-256-bit truncation that would make the address the weakest link.
- **Determinism:** fixed-width little-endian encoding, no `usize` on the wire.

## Build requirements

- Zig `0.16.0-dev` (uses native `std.crypto.sign.mldsa`)

## Roadmap

Phase 0 (propagation simulation + formal spec & TLA+ finality proof) → Phase 1
(this, plus minimal GHOSTDAG) → Phase 2 (sharded UTXO set + finality) →
Phase 3 (networking) → Phase 4 (multi-scheme + custody) → Phase 5 (enterprise).
