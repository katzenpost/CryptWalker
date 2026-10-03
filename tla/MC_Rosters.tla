----------------------------- MODULE MC_Rosters -----------------------------
EXTENDS Rosters
CONSTANTS a, b, c, d, MCMaxTotal
MCFounderSeq == <<a, b>>
MCJoiners == {c, d}
MCSymmetry == Permutations(MCJoiners)
MCSmall == SumLen(stream, Members) <= MCMaxTotal
=============================================================================
