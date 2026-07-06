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
| Sharded UTXO | `src/core/ledger/sharded_utxo.zig` | Thread-safe, outpoint-partitioned state (horizontal-scale groundwork) |
| Accumulator | `src/core/ledger/accumulator.zig` | Utreexo-style hash forest: add/delete/prove + **stateless verify** (bounded state) |
| Tx validation | `src/core/ledger/validation.zig` | Double-spend, value conservation, PQ-signature auth → fee; connect |
| DAG | `src/core/consensus/dag.zig` | BlockDAG store + deterministic topological order (hash tie-break) |
| GHOSTDAG | `src/core/consensus/ghostdag.zig` | k-cluster blue-set coloring, blue score, virtual-chain order (spec: `spec/ghostdag.md`) |
| Proof-of-work | `src/core/consensus/pow.zig` | Compact nBits↔u256 target, meetsTarget, mining, clamped difficulty retarget |
| **Chain engine** | `src/core/consensus/chain.zig` | Block acceptance: verify PoW, enforce DAA difficulty, height, validate, recolor, derive UTXO |
| Finality | `src/core/consensus/finality.zig` | PQ-BFT finality over a DAG cut (spec: `spec/finality.md`) |
| Processor | `src/core/consensus/processor.zig` | Applies txs in GHOSTDAG order; deterministic cross-anticone double-spend resolution |
| Mempool | `src/node/mempool.zig` | Pending txs; fee-rate block selection under a mass cap; edge **policy hook** (compliance without touching consensus) |
| Networking | `src/net/wire.zig` | Length-framed P2P gossip (inv/get_block/block) over raw sockets; block wire codec; real TCP connect/listen |
| Persistence | `src/node/store.zig` | Append-only, crash-safe on-disk block log; replay-on-startup |
| Node | `src/node_main.zig` | Standalone process: TCP peers, gossip, sync, mining, `--datadir` persistence |
| Finality proof | `spec/tla/` | TLA+/TLC machine-checked safety (quorum intersection; ⅓ bound shown tight) |

```
zig build test --summary all      # 76/76 passing
zig build demo                    # full end-to-end chain run (see below)
zig build bench                   # measured scaling / sub-penny-fee numbers
zig build sim                     # Phase-0 propagation feasibility table
./tools/difftest.sh               # Zig vs Rust differential conformance

# Run a real network of node processes that peer over TCP and converge:
zig build node -- --port 9101 --name B --blocks 5              # in one terminal
zig build node -- --port 9100 --peer 127.0.0.1:9101 --mine --blocks 5 --name A
```

## Scale & fees (measured, `zig build bench`)

Settlement-scale throughput with sub-penny fees is not a slogan here — it is
measured plus honest arithmetic. On a 12-core machine:

- **Post-quantum verification** parallelises across cores (UTXO validation is
  embarrassingly parallel): ML-DSA-44 at ~70 µs/sig, **~76,000 verifications/sec**.
- **Batched settlement** (the netting model real exchanges use — one signed
  transaction settles thousands of net transfers): **~41 bytes/transfer**, 93×
  smaller than a standalone transaction, one signature amortised over all of them.
- At a 10 Gbit/s node that is **~30 million transfers/sec** of bandwidth headroom
  — orders of magnitude above Nasdaq's few-hundred-thousand-trades/sec peak — and
  a per-transfer fee **floor** millions of times below one US cent.

The binding constraint is bandwidth-per-settled-value; the levers are witness
segregation, per-scheme mass accounting, batched netting, and parallel
verification — all implemented and benchmarked.

**Differential testing against an independent Rust implementation.** `refimpl-rs/`
reimplements the consensus-critical, byte-exact rules (tagged hashing, canonical
serialization, txid/wtxid/sighash/address/merkle, GHOSTDAG coloring + ordering)
from the specs — not ported line-by-line — so agreement is real evidence of
correctness, not a shared bug. `tools/gen_vectors.py` deterministically generates
a large corpus (`spec/vectors/scenarios.json`: 33 transactions, 304 random DAGs,
plus address/merkle/mass/finality vectors); both implementations consume it and
emit a canonical report, and `tools/difftest.sh` confirms they agree
**byte-for-byte across 3443 report lines**. It covers tagged hashing, canonical
serialization (txid/wtxid/sighash), address & merkle commitments, block mass,
finality vote-messages, and GHOSTDAG coloring + ordering. Any divergence is a
consensus split, caught before it ships — continuous differential fuzzing.

`zig build demo` mines a small BlockDAG of post-quantum-signed transactions
(with a cross-fork double-spend), orders it with GHOSTDAG, applies it to the
UTXO ledger, and finalizes a cut with a PQ-BFT validator set — printing the DAG,
consensus order, double-spend resolution, conserved balances, and the finalized
cut. It is a self-minting, ML-DSA-signed, DAG-ordered, BFT-finalized ledger.

**Phase-0 propagation feasibility** (`src/sim/simnet.zig`) — a discrete-event
gossip sim feeds real DAGs through the actual GHOSTDAG coloring and measures the
orphan (red) rate. At 100 Mbit/s links it confirms the central design tension in
hard numbers: small blocks tolerate 20+ blocks/s at ~0% orphans, but 4 MB
PQ-fat blocks collapse the DAG (≈30% orphaned at 10/s, ≈59% at 20/s). The
feasible envelope is *high block rate OR big blocks, not both* — throughput
comes from block size × parallel validation × relay efficiency, at a
deliberately conservative block rate, exactly as the plan assumes.

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
