---------------------------- MODULE Finality ----------------------------
\* Machine-checked safety model for ZigChain's PQ-BFT finality gadget.
\*
\* Abstracts the gadget (consensus/finality.zig, spec/finality.md) to its
\* safety-critical core: two CONFLICTING cuts, A and B, compete for the same
\* finalization slot. A cut finalizes when the weight of validators voting for
\* it reaches the quorum (strictly more than 2/3 of total weight). Honest
\* validators vote for at most one of two conflicting cuts; Byzantine validators
\* may equivocate (vote for both).
\*
\* THEOREM (Safety): if Byzantine weight is at most 1/3, the two conflicting cuts
\* can never both be finalized. TLC checks this by exploring every Byzantine
\* subset up to MaxByzNum and every interleaving of votes. Setting
\* MaxByzNum one above 1/3 makes TLC find a counterexample (the bound is tight).
\*
\* Weights are unit here (one per validator); the argument is identical for
\* weighted validators with quorum intersection.

EXTENDS Naturals, FiniteSets

CONSTANTS Validators,   \* the validator set
          MaxByzNum      \* max number of Byzantine (equivocating) validators

VARIABLES votesA,       \* validators who have voted for cut A
          votesB,       \* validators who have voted for cut B
          byz           \* the (fixed) Byzantine set, chosen at init

Total  == Cardinality(Validators)
Quorum == (2 * Total) \div 3 + 1      \* strictly greater than two thirds

TypeOK == /\ votesA \subseteq Validators
          /\ votesB \subseteq Validators
          /\ byz    \subseteq Validators

Init == /\ votesA = {}
        /\ votesB = {}
        \* explore every Byzantine set no larger than MaxByzNum
        /\ byz \in { S \in SUBSET Validators : Cardinality(S) <= MaxByzNum }

\* A validator votes for A. An honest validator may not also be in votesB.
VoteA(v) == /\ v \notin votesA
            /\ (v \in byz) \/ (v \notin votesB)
            /\ votesA' = votesA \cup {v}
            /\ UNCHANGED << votesB, byz >>

VoteB(v) == /\ v \notin votesB
            /\ (v \in byz) \/ (v \notin votesA)
            /\ votesB' = votesB \cup {v}
            /\ UNCHANGED << votesA, byz >>

Next == \E v \in Validators : VoteA(v) \/ VoteB(v)

Spec == Init /\ [][Next]_<< votesA, votesB, byz >>

FinalizedA == Cardinality(votesA) >= Quorum
FinalizedB == Cardinality(votesB) >= Quorum

\* The property under test: two conflicting cuts are never both finalized.
Safety == ~(FinalizedA /\ FinalizedB)
=========================================================================
