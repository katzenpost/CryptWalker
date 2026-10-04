---------------------------- MODULE MC_GroupChat ----------------------------
EXTENDS GroupChat
CONSTANTS a, b, c, d, MCMaxTotal
MCFounderSeq == <<a, b>>
MCJoiners == {c, d}
MCSymmetry == Permutations(MCJoiners)
MCSmall == SumLen(stream, Members) <= MCMaxTotal
=============================================================================
