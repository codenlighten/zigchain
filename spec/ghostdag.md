# GHOSTDAG ordering — specification (v0, Phase-1)

Status: **draft, code-paired.** This document is the source of truth for the
GHOSTDAG coloring implemented in `src/core/consensus/ghostdag.zig`. It will be
extended with a formal (TLA+/Quint) treatment before Phase-2 finality work; the
BFT finality gadget remains separately gated on that proof.

## Definitions

For a BlockDAG where each block references a set of parent block ids:

- **past(B)** — all blocks reachable from B by following parent edges (B's
  ancestors), excluding B.
- **future(B)** — all blocks that have B in their past.
- **anticone(B)** — blocks that are neither in past(B) nor future(B) nor B
  itself (blocks concurrent with B).
- **k** — the security parameter bounding tolerated concurrency. A set S is a
  *k-cluster* if every block in S has at most k blocks of S in its anticone.

## Per-block data

Each block B carries `GhostdagData`:

- `selected_parent` — the parent of B with the highest `blue_score`; ties broken
  by the **smaller** block id (lexicographic). `null` for genesis.
- `mergeset_blues`, `mergeset_reds` — the blocks merged by B (i.e.
  `past(B) \ (past(selected_parent) ∪ {selected_parent})`), partitioned by the
  coloring rule, each in topological order.
- `blue_anticone_sizes` — a map whose **keys are exactly B's blue set**
  (`{B} ∪ blues(past(B))`) and whose values are each blue block's anticone size
  *within that blue set*.
- `blue_score` — `|blues(past(B))|`. Equivalently
  `selected_parent.blue_score + 1 + mergeset_blues.len` (genesis = 0).

## Algorithm (per block B, processed in topological order)

1. **Genesis:** `blue_anticone_sizes = {B: 0}`, `blue_score = 0`, no mergeset.
2. **Selected parent:** `sp = argmax(blue_score)` over parents, tie → smaller id.
3. **Inherit:** copy `sp.blue_anticone_sizes` (this is sp's blue set, including
   sp itself) as B's working blue set.
4. **Mergeset:** `past(B) \ past(sp) \ {sp}`, ordered by the DAG's deterministic
   topological order.
5. **Color** each candidate K in that order:
   - `blue_anticone = { X ∈ current_blue_set : X ∈ anticone(K) }`.
   - K is **red** if `|blue_anticone| > k`, or if any `X ∈ blue_anticone`
     already has `blue_anticone_sizes[X] == k` (adding K would push X over k).
   - Otherwise K is **blue**: record `blue_anticone_sizes[K] = |blue_anticone|`,
     and increment `blue_anticone_sizes[X]` for every `X ∈ blue_anticone`.
6. **Finalize:** add B itself to its blue set with anticone size 0 (B is in the
   future of all its ancestors), and set `blue_score` as above.

## Total order (virtual chain)

The consensus linearization emits, for each block, its selected-parent chain
first, then its ordered mergeset, then the block — recursively, with a visited
set, iterating tips in ascending-id order. This yields a **deterministic,
topologically-valid** total order in which the selected chain and blue blocks
take precedence. UTXO application consumes this order; double-spends across the
DAG are resolved by first-in-this-order-wins.

## Determinism requirements (consensus-critical)

- Tie-breaks (selected parent, tips, mergeset order) are **total** and by id.
- No hash-map iteration order is ever observed; all enumerations sort first.
- Every rule above must be byte-reproducible across implementations; the golden
  vectors in the test module are the conformance corpus (shared later with the
  Rust reference implementation).
