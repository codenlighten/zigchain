# Cold-vault signatures — SPHINCS+ (vendored)

## Why a second scheme

ML-DSA (Dilithium) is the hot, default scheme: small, fast, lattice-based. For
**long-term custody** — keys that must remain secure for decades, or that guard
treasury/sovereign reserves — ZigChain adds SPHINCS+, a **hash-based** signature
whose security rests *only* on the hash function, with no algebraic structure to
be broken by a future cryptanalytic advance. The price is signature size
(7.9 KB for `128s`, 17 KB for `128f`), which is why it is a cold-vault scheme,
not the everyday one.

| tag | scheme | pubkey | signature | verify mass |
|---|---|---|---|---|
| `0x01` | ML-DSA-44 | 1312 | 2420 | 1 |
| `0x02` | ML-DSA-65 | 1952 | 3309 | 2 |
| `0x03` | SPHINCS+-SHAKE-128s-simple | 32 | 7856 | 64 |
| `0x04` | SPHINCS+-SHAKE-128f-simple | 32 | 17088 | 128 |

The large `verify_mass` weights make SPHINCS+ expensive in block-mass accounting,
so a block cannot be cheaply packed with the most-expensive-to-verify scheme
(a DoS guard). Stateful hash schemes (XMSS/LMS) are permanently **banned** from
the registry: a single one-time-key reuse is catastrophic.

## Assurance: vendored, not hand-rolled

Cryptographic primitives are **never hand-rolled** (a locked project decision).
The SPHINCS+ implementation is the **PQClean** "clean" C, vendored under
`vendor/pqclean/`:

- **Pinned** to a specific PQClean commit and **checksummed**
  (`vendor/pqclean/MANIFEST.txt`, SHA-256 per file).
- Correctness-vs-standard assurance is **inherited**: those exact bytes are
  validated against the NIST/SPHINCS+ known-answer tests by PQClean's own CI.
- Locally we additionally pin a **regression KAT** on deterministic key
  generation (`sphincs.zig`), so any accidental change to the sources, flags, or
  parameters is caught by `zig build test`.

### FFI safety

The Zig↔C boundary follows the plan's rule: **every length is validated on the
Zig side before the C runs** (`sphincs.zig` `Variant.verify/seedKeypair/sign`).
The C is never trusted to bounds-check. Consensus only ever calls **verify**,
which uses no RNG and no dynamic allocation; key generation and signing (which do
use the RNG) live outside the consensus path, in vault/wallet tooling.

### Round-3.1 vs FIPS 205

The vendored code is SPHINCS+ **round 3.1** ("simple"). FIPS 205 SLH-DSA uses the
same parameter sets with different domain separation; because ZigChain binds the
scheme tag into the sighash and address commitment itself, swapping the backend
to a FIPS 205 implementation later is a localized change behind the same registry
interface.
