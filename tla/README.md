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
tla/check.sh protocol/MC_GroupChat_Explicit.cfg
tla/run.sh protocol/MC_GroupChat_Explicit.cfg  # TLC's full output, with the counterexample
```

You need Java 11 or later, and `tla2tools.jar` in `tla/` or named by `TLA2TOOLS`. `JAVA` selects
the java binary. For long runs, set `TLC_METADIR` to a directory on disk, because TLC's state
files soon outgrow a RAM-backed `/tmp`.

Each `MC_*.cfg` starts with `\* EXPECT pass` or `\* EXPECT violated <Property>`. Many configs
exist to show that something is needed: take it away, and TLC must find the failure. With
`FAST=1` the set runs in about fifteen minutes; `MC_GroupChat_RostersOnly` adds forty more.

## Protocol models

| Module | What it covers |
|---|---|
| `Replica.tla` | One box at one replica, keyed by the epoch it was stored in; `SpecStored`, the storage the spec assumes, where every write stores the box at the current epoch |
| `Backfill.tla` | One member's stream: periodic rewrite, Sent-box retention, acknowledgements and the readers' jumps and rechecks. The replica's write rule is the constant `StoredOp` |
| `GroupChat.tla` | Rosters across a group with explicit numbering: Numbers, Introductions, IntroducedAt, the reply to a new member, and every watcher following every roster |

Where the spec can be read more than one way, or these models propose a change, a constant
chooses between them: `AckFurthest` and `PollHoles` in `Backfill.tla`, and `HandIntroductions`
and `UseIntroducedAt` in `GroupChat.tla`.

| Config | Expect | What it shows |
|---|---|---|
| `MC_Backfill_SpecAckRule` | violated `NoSilentLoss` | Acknowledging the furthest box read counts a box a jump skipped as read |
| `MC_Backfill_SpecRecheck` | violated `DeliveryOnceScansStop` | Rechecking skipped boxes only during a scan can lose one for good |
| `MC_Backfill_Proposed` | pass | Acknowledging up to the unbroken run: boxes stay populated, nothing is tombstoned early, no reader overshoots |
| `MC_Backfill_LiveHoles` | pass | Polling the boxes a jump skipped until they are read delivers every box |
| `MC_GroupChat_Explicit` | pass | With explicit numbering, the Introductions in the reply and IntroducedAt, every name a watcher gives is right, and a quiet group converges |
| `MC_GroupChat_Skip` | pass | A watcher that skips boxes leaves indexes unresolved, never misplaced |
| `MC_GroupChat_NoIntroducedAt` | violated `RosterAgree` | Without IntroducedAt, a member introduced twice is followed from the wrong introducer's roster |
| `MC_GroupChat_RostersOnly` | violated `Converged` | Handed rosters but not the Introductions, a new member can never name some members; it names nobody wrongly |

## Implementation models

| Module | What it covers |
|---|---|
| `KatzenpostReplica.tla` | `Backfill.tla` over `replica/state.go`'s write rule: a matching data write succeeds and stores nothing; a tombstone is always stored |
| `Katzenqt.tla` | katzenqt's group state machine and its adapter over `GroupChat.tla`: control messages composed then written, indexes reserved while pending, and inductions that hold, wait for what is pending, then hand over the reply and compose the Introduction |

| Config | Expect | What it shows |
|---|---|---|
| `MC_KatzenpostReplica_Refines` | violated `ProtocolSpec` | A matching rewrite stores nothing, where the protocol stores the box again |
| `MC_KatzenpostReplica_Populated` | violated `Populated` | The consequence: a box rewritten every epoch is still collected |
| `MC_KatzenpostReplica_LiveNoScan` | pass | Without scans, every box still reaches the reader; the collected box returns at the next rewrite |
| `MC_KatzenpostReplica_LiveHoles` | pass | With polled holes, delivery holds on the deployed replica too |
| `MC_Katzenqt_Fixed` | pass | katzenqt writes every roster index in order, gives a new member the index its Introduction gives it, and a quiet group converges |
| `MC_Katzenqt_NoWait` | violated `InductionIndex` | A reply built while a control message is pending promises an index that message takes |
| `MC_Katzenqt_AbandonControl` | violated `NoGap` | Were a pending Introduction or control message abandoned, a message composed after it would write past the end of the roster. katzenqt abandons only content |

## Boxes

A box is named by its `MessageBoxIndex`, an opaque BACAP value. The protocol compares two
indexes only for equality, and learns order only by stepping a stream forward. In
`GroupChat.tla` a box is `<<owner, q>>`, unique to one box of one stream; Introductions and
IntroducedAt name boxes by it, and only a reader stepping through a stream uses `q`. In
`Backfill.tla` a box is a position on its one stream, which stands for the order its owner wrote
it and its readers step through it: a jump to an acknowledged box is a walk forward to it.

Both implementations use BACAP's stateless API: the client keeps its own read and write state
and hands kpclientd a capability and an index with each request.

## Lean

The Lean files split the same way. `AckCodec` and `ReaderScan` port katzenqt's code and prove
properties of it: `ReaderScan` covers the walk to an acknowledged box (it proves the box comes
after where the walk began, by stepping forward to it), the boxes a walk keeps, and the recheck
window. `Roster` is a protocol claim for any group size: whoever a watcher names at an index of a
roster is whoever its owner put there, and reading truthful messages, learning Introductions and
following `IntroducedAt` keep that so, however many boxes it skipped. Without `IntroducedAt`, it
misplaces a member introduced twice. `Backfill` compares the spec's storage with `state.go`'s,
for every epoch.

## What is not modelled

- Cryptography: unlinkability and unforgeability are the paper's and BACAP's. A forged box is
  not considered.
- Byzantine members: every member follows the protocol. A member sending forged or misnumbered
  `Acks` would test the Sent-box check, and is the natural next step.
- Disappearing messages, member removal, and acknowledgements in `GroupChat.tla` and
  `Katzenqt.tla`: `Backfill.tla` covers acknowledgements on one stream.
- Couriers, replication between replicas, and the mixnet: the stream store behaves as one
  replica that always answers.
- Sizes are small, so a pass is a bounded result.
  - Backfill: 2 readers, 3 boxes and 3 replica epochs (1 reader for liveness).
  - Group chat: 2 founders and 2 joiners, at most 2 messages per stream and 4 across the group
    (`MCMaxTotal`); 3 when boxes may be skipped (`MC_GroupChat_Skip`), and 6 for
    `MC_GroupChat_RostersOnly`.

  The Lean proofs carry the main roster and backfill claims to any size.
