-------------------------- MODULE MC_RostersClient --------------------------
EXTENDS RostersClient
CONSTANTS a, b, c, d
MCFounderSeq == <<a, b>>
MCJoiners == {c, d}
MCSymmetry == Permutations(MCJoiners)
=============================================================================
