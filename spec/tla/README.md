# Machine-checked finality safety

`Finality.tla` is a TLA+ model of the PQ-BFT finality gadget's safety-critical
core, checked with the TLC model checker (TLA+ tools 2.19).

## Property

**Safety:** two *conflicting* cuts can never both be finalized, provided
Byzantine (equivocating) validators hold at most 1/3 of the weight. This is the
quorum-intersection argument stated in `../finality.md`, discharged mechanically
rather than by hand.

## How to run

```
# one-time: fetch the TLC model checker
curl -sL -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar

# honest super-majority (Byzantine <= 1/3): Safety holds
java -cp tla2tools.jar tlc2.TLC -deadlock -config Finality.cfg Finality.tla

# one fault over the threshold (3 of 7): Safety is violated (bound is tight)
java -cp tla2tools.jar tlc2.TLC -deadlock -config FinalityByzExceeded.cfg Finality.tla
```

(`tla2tools.jar` is a build artifact and is not committed.)

## Results (TLC 2.19, Validators = 7)

**Finality.cfg** — `MaxByzNum = 2` (⌊7/3⌋, i.e. ≤ 1/3):

```
Model checking completed. No error has been found.
639605 states generated, 104247 distinct states found, 0 states left on queue.
```

Every Byzantine subset up to 2 validators and every interleaving of votes was
explored; the Safety invariant held in all 104,247 reachable states.

**FinalityByzExceeded.cfg** — `MaxByzNum = 3` (one over 1/3):

```
Error: Invariant Safety is violated.
/\ byz = {v1, v2, v3}
/\ votesA = {v1, v2, v3}   \* then extended to a quorum
/\ votesB = {v1, v2, v3}   \* the same equivocators also fill B's quorum
```

Three equivocating validators make both conflicting cuts reach quorum — a
concrete demonstration that the 1/3 fault tolerance is tight, matching the
`safety: two conflicting cuts...` test in `consensus/finality.zig`.
