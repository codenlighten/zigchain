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

## Threshold k-of-n multisig

There is no post-quantum threshold *signature* primitive (no BLS analogue), so
k-of-n is **script-level** (`core/primitives/multisig.zig`): an output commits to
a policy `H(multisig, threshold ‖ participants)`, and a spend reveals the policy
and supplies `k` full signatures from distinct participants — the P2SH pattern.
The trade-off is on-chain size (k full PQ signatures), budgeted via block mass
(a multisig witness costs the sum of its participants' verify costs).

It rides the existing witness triple with no wire-format change: the `multisig`
marker scheme (`0x10`), the policy in the witness `pubkey` field, the signer set
in the `signature` field. Verification is a single allocation-free streaming pass
(participants ordered; signer indices strictly ascending → distinct, canonical,
malleability-free). `verifySpend` dispatches to it, so a k-of-n spend is
consensus-native and validated exactly like a single-key spend. Participants may
mix schemes (e.g. two ML-DSA hot keys + one SPHINCS+ vault key).

```sh
# Build a 2-of-3 address from participant pubkeys (from `vault address`):
vault multisig-address --threshold 2 \
  --participant ml_dsa_44:<pk0> --participant ml_dsa_65:<pk1> --participant sphincs_128f:<pk2>

# Each signer runs `vault sign` on the spend sighash; combine k of them:
vault multisig-combine --policy <hex> --sighash <hex32> --sig 0:<sig0> --sig 2:<sig2>
```
