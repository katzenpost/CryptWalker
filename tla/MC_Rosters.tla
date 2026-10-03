----------------------------- MODULE MC_Rosters -----------------------------
EXTENDS Rosters
CONSTANTS a, b, c, d
MCFounderSeq == <<a, b>>
MCJoiners == {c, d}
MCSymmetry == Permutations(MCJoiners)
=============================================================================
