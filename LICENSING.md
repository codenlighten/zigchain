# Licensing ZigChain

This document covers two things: **how SmartLedger should price the software**,
and the **post-quantum license mechanism** that enforces it.

## Recommended model

**Per running node/validator, tiered by capacity + features, with consortium
licensing for private networks.** This is the standard open-core shape for
infrastructure software, and it fits regulated settlement.

| Tier | For | Typically grants |
|---|---|---|
| **Community** | public network, evaluation | run a node, basic throughput — free |
| **Standard** | production single-org | higher capacity, support |
| **Enterprise** | banks, exchanges | SPHINCS+ cold-vault signing, compliance/policy modules, high capacity |
| **Sovereign** | governments, air-gapped | unlimited nodes, priority SLA, on-prem |

**Why not per-transaction?** The chain already charges a sub-penny *network* fee
per transaction. Layering a per-transaction *software* fee on top means metering
trust ("who counts the transactions?"), settlement friction, and a poor fit for
air-gapped deployments that can't phone home. If SmartLedger wants usage-based
revenue, put it in a **protocol fee-split** (a fraction of network fees routed to
the issuer) — a tokenomics lever — not the software license.

**Consortium / network license:** one agreement covering a whole permissioned
deployment, priced by scale (`max_nodes`), rather than licensing each member.

The license structure below expresses *all* of these (tier, feature bits,
`max_nodes`, `max_tps`, expiry, perpetual), so pricing stays a business decision
you can change without touching code.

## The mechanism: post-quantum, offline-verifiable licenses

SmartLedger (the issuer) signs a license with a post-quantum key (**ML-DSA-44**).
Every node verifies it **offline** against SmartLedger's embedded public key — no
phone-home, which matters for air-gapped government deployments. The license is a
canonically-serialized statement (licensee, tier, features, node/capacity limits,
issued/expiry) signed over a **domain-separated** hash (`zigchain.v1.license`), so
a license can never be replayed as any other signed object on the chain.

Guarantees (all covered by tests in `src/licensing/license.zig`):
- **Unforgeable** — only the holder of SmartLedger's secret key can issue one.
- **Tamper-evident** — changing the tier, node cap, or expiry breaks the signature.
- **Wrong-issuer-proof** — a license verifies only against the true issuer key.
- **Time-bounded** — `expires_at` (0 = perpetual); not-yet-valid and expired are
  distinct, checked results.

### Issue a license (`zig build license`)

```sh
# 1. One-time: generate the issuer key. Keep the seed SECRET; publish/embed the
#    printed public key in the software.
zig build license -- keygen --seed <64-hex-char seed>

# 2. Issue a license file for a customer.
zig build license -- issue --seed <issuer-seed> \
    --licensee "Acme Clearing Corp" \
    --tier enterprise \
    --features vault,compliance \
    --nodes 10 --days 365 \
    --out acme.lic

# 3. Anyone can verify it offline against the public key.
zig build license -- verify --in acme.lic --pubkey <issuer-pubkey-hex>
```

Features: `vault`, `compliance`, `high_capacity`, `priority_support` (comma-sep).
`--days 0` issues a perpetual license; `--nodes 0` / `--tps 0` mean unlimited.

### Enforcement in the node

```sh
zigchain-node --license acme.lic --issuer-key <issuer-pubkey-hex> ...
```

- **No `--license`** → the node logs *community tier* and runs.
- **Valid license** → the node logs the licensee, tier, features, and expiry.
- **Present but invalid/expired/wrong-issuer** → the node **refuses to start**
  (fail-closed).

In production, SmartLedger's issuer public key is compiled into the binary rather
than passed on the command line, so the license check needs no configuration.
Enterprise-only capabilities (the vault scheme, compliance policy, capacity above
the community cap) gate on the license's `features`/limits at their call sites as
they are built.
