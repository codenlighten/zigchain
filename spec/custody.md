# Custody — HD derivation and air-gapped signing

## Key derivation (`kdf.zig`)

Lattice and hash-based post-quantum schemes have **no BIP32-style additive
homomorphism**, so there is **no public / watch-only derivation**: every child
key requires the master secret. This is a real limitation, stated plainly rather
than worked around. Derivation is a hardened-only seed tree — a domain-separated
KDF over the master seed, the scheme tag, and the path:

```
seed_i = BLAKE3-tagged(kdf, master ‖ scheme_tag ‖ path ‖ counter)   # counter-mode
```

- Binding the **scheme tag** means the same path under ML-DSA and SPHINCS+ yields
  unrelated keys.
- Binding the **whole path** means siblings — and paths of different depth — are
  independent.
- The draw is as long as the scheme needs (32 bytes for ML-DSA, 48 for SPHINCS+).

## Signer (`custody/signer.zig`)

`sign(master, scheme, path, sighash)` derives the key and returns `(pubkey, sig)`.
Its guarantee, pinned by a test over **all four schemes**, is:

```
registry.verify(scheme, pubkey, sighash, sig)   // always accepts
```

i.e. a vault-signed witness is valid on-chain by construction. For ML-DSA the
signature is produced with the scheme tag bound as context, exactly matching how
consensus verifies; for SPHINCS+ the scheme tag is bound via the sighash and
address commitment.

## The vault CLI (`zig build vault`)

An air-gapped tool that holds only the master seed and never emits secrets:

```sh
# Receive address for an account path:
vault address --seed <hex32> --scheme ml_dsa_44 --path 44/0/0

# Air-gapped signing: the online node computes a transaction's sighash; the
# offline vault signs it; the node assembles the witness from pubkey+signature.
vault sign   --seed <hex32> --scheme sphincs_128f --path 44/0/0 --sighash <hex32>
vault verify --scheme sphincs_128f --pubkey <hex> --sighash <hex32> --sig <hex>
```

Schemes: `ml_dsa_44`, `ml_dsa_65` (hot), `sphincs_128s`, `sphincs_128f` (cold
vault). `sign` re-verifies its own output before printing — it never emits a
witness it cannot itself validate.

### Remote-signer flow

The `sign` command *is* the remote-signer primitive: the online node needs only
to transport a 32-byte sighash to the vault and receive back a pubkey+signature.
That request/response is small enough to move across an air gap (file or QR). A
production signer should additionally receive the full transaction and recompute
the sighash itself, rather than blind-signing a hash — a straightforward
extension of this interface.

## Not yet built

Script-level **k-of-n multi-signature** (threshold custody) is a future addition;
it is deliberately script-level (no BLS threshold, which has no post-quantum
analogue) and its on-chain size must be budgeted against the large PQ signatures.
