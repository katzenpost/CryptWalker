---------------------------- MODULE MC_Katzenqt ----------------------------
EXTENDS Katzenqt
CONSTANTS a, b, c, d, MCMaxTotal
MCFounderSeq == <<a, b>>
MCJoiners == {c, d}
MCSymmetry == Permutations(MCJoiners)
MCSmall == SumLen(stream, Members) + SumLen(outbox, Members) <= MCMaxTotal
=============================================================================
