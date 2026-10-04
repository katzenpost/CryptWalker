# Group chat models (TLA+)

TLA+ models of the group chat protocol from the katzenpost website's group chat spec
(website#242): opportunistic acknowledgements, rosters, backfill, retention and rewrite-and-scan.
They are checked with TLC. The Lean side is in `CryptWalker/GroupChat/`.

The models are kept at two levels, because they answer different questions:

- **`protocol/`: is the design right?** These models contain only what the spec says, over the
  storage the spec assumes. A failure here is a design flaw: any client that follows the spec has
  it, and the fix belongs in the spec.
- **`impl/`: does an implementation do what the design says?** Each model describes one
  codebase. It is checked against its own invariants, and for refinement against the protocol
  model (`ProtocolSpec`): every step the implementation takes must be a step the protocol allows.
  A failure here is a bug in that codebase, and the fix belongs in its code.

## Running

```
make tla                                      # every config, checked against its EXPECT line
FAST=1 tla/check.sh                           # what CI runs: skips configs marked SLOW
tla/check.sh protocol/MC_GroupChat_SpecReply.cfg
tla/run.sh protocol/MC_GroupChat_SpecReply.cfg  # TLC's full output, with the counterexample
```

You need Java 11 or later, and `tla2tools.jar` in `tla/` or named by `TLA2TOOLS`. `JAVA` selects
the java binary. For long runs, set `TLC_METADIR` to a directory on disk, because TLC's state
files soon outgrow a RAM-backed `/tmp`.

Each `MC_*.cfg` starts with `\* EXPECT pass` or `\* EXPECT violated <Property>`. Many configs
exist to show that something is needed: take it away, and TLC must find the failure. The full
set runs in about three minutes.

## Protocol models

| Module | What it covers |
|---|---|
| `Replica.tla` | One box at one replica, keyed by the epoch it was stored in; `SpecStored`, the storage the spec assumes, where every write stores the box at the current epoch |
| `Backfill.tla` | One member's stream: periodic rewrite, Sent-box retention, acknowledgements and the reader's scan. The replica's write rule is the constant `StoredOp` |
| `GroupChat.tla` | Rosters across a group: acknowledgements by roster index, introductions, the reply to a new member, and every watcher following every roster |

Where the spec can be read more than one way, or these models propose a change, a constant
chooses between them: `NaiveAdopt`, `AckFurthest` and `KeepHoles` in `Backfill.tla`, and
`HandIntroductions` in `GroupChat.tla`.

| Config | Expect | What it shows |
|---|---|---|
| `MC_Backfill_SpecScanTable` | violated `NoOvershoot` | The scan table, read literally, skips the end of a quiet stream |
| `MC_Backfill_SpecAckRule` | violated `NoSilentLoss` | Acknowledging the furthest box read counts a box a scan skipped as read |
| `MC_Backfill_LiveScan` | violated `DeliveryOnceScansStop` | One scan that races a write loses that box for good |
| `MC_Backfill_Proposed` | pass | The proposed scan rule (stay put if nothing was found past the stuck position) and ack rule (up to the unbroken run) |
| `MC_Backfill_LiveHoles` | pass | Polling the positions a scan skipped delivers every box |
| `MC_GroupChat_SpecReply` | violated `RosterPrefix` | Given only `Rosters`, a new member misplaces a member |
| `MC_GroupChat_HandIntroductions` | pass | A reply that also hands over the Introductions and acknowledgements read |

## Implementation models

| Module | What it covers |
|---|---|
| `KatzenpostReplica.tla` | `Backfill.tla` over `replica/state.go`'s write rule: a matching data write succeeds and stores nothing; a tombstone is always stored |
| `Katzenqt.tla` | katzenqt's send path over `GroupChat.tla`: acknowledgements taken when a message is queued, rosters grown when it is written, inductions, and cancel. Each `Bug` constant undoes one fix from katzenqt#108 |

| Config | Expect | What it shows |
|---|---|---|
| `MC_KatzenpostReplica_Refines` | violated `ProtocolSpec` | A matching rewrite stores nothing, where the protocol stores the box again |
| `MC_KatzenpostReplica_Populated` | violated `Populated` | The consequence: a box rewritten every epoch is still collected |
| `MC_KatzenpostReplica_LiveNoScan` | pass | Without scans, every box still reaches the reader; the collected box returns at the next rewrite |
| `MC_KatzenpostReplica_LiveHoles` | pass | With the proposed scan, delivery holds on the deployed replica too |
| `MC_Katzenqt_Fixed` | pass | After #108, katzenqt only takes steps the protocol allows, and owes no ack it never sends |
| `MC_Katzenqt_NoWaitAcks` | violated `ProtocolSpec` | 6f06a4b undone: a queued message numbers someone ahead of the Introduction |
| `MC_Katzenqt_NoWaitIntro` | violated `ProtocolSpec` | b88abff undone: two inductions promise the same roster index |
| `MC_Katzenqt_CancelKeepsAcks` | violated `NoLostAck` | f2e4c01 undone. Every step is still one the protocol allows; only katzenqt's own invariant catches this bug |

Both implementations use BACAP's stateless API. katzenqt keeps its own read and write positions
and hands kpclientd a capability and an index with each request; kpclientd keeps no reader or
writer state (katzenpost#1200). The models have the same shape: a member's `read` and a reader's
`cursor`, `probe` and `holes` are client state, and a scan's probe is a read at a position of the
client's choosing, which the old stateful reader, able only to read its next box, could not make.
kpclientd also refuses an index that is not on its capability's stream (katzenpost#1202), so, as
here, a box is named by its stream and position alone.

katzenqt builds the whole reply to a new member when an induction begins. `Katzenqt.tla` fixes
only the promised roster at that point, and reads the rest off when the Introduction is written,
as the protocol does. An earlier view of read positions is still a valid reply, and the promised
roster is what #108's bugs got wrong.

## Lean

The Lean files split the same way. `AckCodec` and `ReaderScan` port katzenqt's code and prove
properties of it. `Roster.watch_prefix` is a protocol claim: a watcher that has every message up
to where it is reading follows any roster correctly. `Backfill` compares the spec's storage with
`state.go`'s, for every epoch.

## What is not modelled

- Cryptography: unlinkability and unforgeability are the paper's and BACAP's. Boxes are
  positions, and a forged box is not considered.
- Byzantine members: every member follows the protocol. A member sending forged or misnumbered
  `Acks` would test the Sent-box check, and is the natural next step.
- Disappearing messages, and Introductions that carry acknowledgements (`AcksOnIntro`).
- Couriers, replication between replicas, and the mixnet: the stream store behaves as one
  replica that always answers.
- Sizes are small, so a pass is a bounded result.
  - Backfill: 2 readers, 3 boxes and 3 replica epochs (1 reader for liveness).
  - Group chat: 2 founders and 2 joiners, at most 2 messages per stream and 4 across the group
    (`MCMaxTotal`). `MC_GroupChat_HandIntroductions` also passes at 5 (841,045 states).

  The Lean proofs carry the main roster and backfill claims to any size.
