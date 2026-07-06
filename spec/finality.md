# Finality — specification (v0, Phase-2)

Status: **draft, code-paired.** Source of truth for `consensus/finality.zig`.
A formal TLA+/Quint safety model is a required follow-up before mainnet; the
argument below is the standard BFT reasoning the model must discharge.

## Why a finality gadget

PoW + GHOSTDAG gives *probabilistic* confirmation — reorg probability decays but
never reaches zero. Government and enterprise settlement need a **point of no
return**: an auditable moment after which a transaction is irreversible. The
finality gadget provides that by having a validator set finalize a cut of the
DAG. PoW chooses the chain and provides liveness; the gadget provides safety.
Crucially, the finality votes are themselves **post-quantum signed** (ML-DSA), so
finality inherits the chain's quantum resistance.

## The finality cut

GHOSTDAG induces a selected-parent chain ending at the selected tip `T`
(max blue score). The **finality candidate** is the block `C` on that chain such
that `blueScore(T) − blueScore(C) ≥ finality_depth`, chosen closest to `T`
(the shallowest block that is deep enough). Finalizing `C` finalizes
`{C} ∪ past(C)` — a *cut* of the DAG, not a single chain tip.

## Validators, votes, quorum

- A **validator set** is a fixed list of `(scheme, pubkey, weight)`. `total` is
  the sum of weights. The **quorum** is `⌊2·total/3⌋ + 1` (strictly more than
  two thirds).
- A **finality vote** by validator `i` is a post-quantum signature over
  `H_finality(cut.block ‖ cut.blueScore)` using `i`'s key (scheme tag bound as
  the signature context, as everywhere else).
- When votes from validators whose combined weight ≥ quorum name the **same**
  cut, that cut is **finalized**.

## Rules

1. **Verify** every vote's signature before counting it; reject invalid ones.
2. **No double-count**: a validator's weight counts at most once per cut.
3. **Monotonicity**: the finalized point only advances — a vote for a cut whose
   blueScore ≤ the current finalized blueScore is stale and ignored.
4. **Reorg protection**: once `C` is finalized, a block is only valid if `C` is
   in its past (or it *is* `C`); i.e. the chain may not reorganize past a
   finalized cut. `isFinalized`/`isAncestorOrSelf` expose the predicate.

## Safety (quorum intersection)

Two conflicting cuts at the same height cannot both finalize while ≤ 1/3 of
weight is Byzantine: each needs > 2/3, and any two > 2/3 sets intersect in
> 1/3 of weight, so finalizing both would require an honest validator to vote
for two conflicting cuts — which honest validators never do. Equivocation by
> 1/3 Byzantine weight is the classic BFT threshold and is out of the safety
envelope (and, being signed, is externally attributable/slashable).

## Liveness

Requires the selected chain to keep advancing (provided by PoW) and > 2/3 of
weight honest and online to reach quorum. The gadget never *creates* blocks; it
only certifies them, so it cannot stall block production.
