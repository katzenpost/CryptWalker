# Group chat models

Formal models of the katzenpost group chat protocol: the website's group chat spec
(`content/en/docs/specs/groupchat.md`, website#242), its implementation in katzenqt
(`groupchat/`), and the katzenpost replica it stores boxes on. The spec sections covered are
"Opportunistic acknowledgements and backfill" (acknowledgements, rosters, Sent-box records,
joining), "Rewrite and scan", and the wire formats of `Acks`, `Numbers` and `IntroducedAt`.

These models follow katzenqt#166, where an acknowledgement names a box by its 8-byte BACAP
`Idx64` rather than its whole 104-byte `MessageBoxIndex`. Every member holds every member's read
cap, and so the stream's starting index, from which BACAP derives the box at any later `Idx64`.

There are three tools:

- **Lean** (`*.lean`, `Member/`): proofs for every group size and every run, and an executable
  model of katzenqt's group member that katzenqt's own traces are replayed through.
- **TLA+** (`tla/`): models checked exhaustively with TLC, at small sizes. They cover whole
  groups over time, including liveness, and many configs exist to show that a rule is needed:
  take it away and TLC finds the failure.
- **Veil** (`veil/`): the safety half of `Backfill.tla` as a Veil transition system, whose
  invariants Veil proves inductive with cvc5 for any number of readers and boxes, and which it
  also model-checks.

## Protocol models and implementation models

Every model is one of two kinds, and a failure means something different in each.

- **Protocol model**: only what the spec says, over the storage the spec assumes. A failure is
  a design flaw that every client following the spec would have, and the fix belongs in the spec.
- **Implementation model**: what one codebase does. It is checked against its own invariants, and
  where possible against the protocol model. A failure is a bug in that codebase, and the fix
  belongs in its code.

A model of a *section* covers one part of the protocol or of a codebase, such as one wire format,
one reader, or one replica's storage rule.

| Model | Kind | What it models |
|---|---|---|
| `Roster.lean` | Protocol section | Rosters: a watcher following other members' numbering through `Numbers`, `Introduction` and `IntroducedAt`, against a world that holds each roster as its owner keeps it |
| `AckCodec.lean` | Protocol section | The `Acks` wire format, following katzenqt's `ack_codec.py`: a count, the members, and an `Idx64` for each |
| `ReaderScan.lean` | Protocol section | A reader's advance to a box another member acknowledged by its `Idx64` |
| `Backfill.lean` | Protocol section vs implementation section | One box at one replica: the storage the spec assumes, against `katzenpost/replica/state.go`'s write rule |
| `Member/` | Implementation | katzenqt's group member (`groupchat/group.py`, with `reader.py`, `numbering.py`, `sentbox.py`, `ledger.py`, `wire.py`, `events.py`), executable and replayed against katzenqt |
| `Member/Wire.lean` | Protocol section, as katzenqt implements it | The `Numbers` and `IntroducedAt` wire formats |
| `Member/Gcm.lean`, `Member/Cbor.lean` | Implementation section | katzenqt's `GroupChatMessage` CBOR and box framing (`models.py`), and its `GcmCodec` between a message and what a member reads of it (`acks.py`) |
| `Member/AckBytes.lean` | Implementation section | The executable `Acks` codec, the same functions as `AckCodec.lean` without Mathlib |
| `Member/Membership.lean`, `Member/ReplyWho.lean` | Implementation section | katzenqt's membership hash, and its reply to a new member (`GroupChatReplyWho`) with the `JoinReply` it carries |
| `Member/Walk.lean`, `Member/Persist.lean` | For clients | A walk and index derivation over any way of stepping an index, and a member's state as CBOR |
| `tla/protocol/Replica.tla` | Protocol section | One box at one replica, with the storage the spec assumes (`SpecStored`) |
| `tla/protocol/Backfill.tla` | Protocol section | One member's stream: periodic rewrite, Sent-box retention, acknowledgements, and readers' jumps, rechecks and scans |
| `tla/protocol/GroupChat.tla` | Protocol | Rosters across a whole group: explicit numbering, Introductions, `IntroducedAt`, the reply to a new member, and every member following every roster |
| `tla/impl/KatzenpostReplica.tla` | Implementation section | `Backfill.tla` over the katzenpost replica's write rule (`DeployedStored`) |
| `veil/GroupChatVeil/Backfill.lean` | Protocol section | `Backfill.tla`'s safety properties, for every number of readers and boxes |
| `tla/impl/Katzenqt.tla` | Implementation section | katzenqt's send path over `GroupChat.tla`: control messages composed then written, indexes reserved while pending, and inductions that hold, wait, then reply |

## What is proved (Lean)

These hold for every group size and every interleaving. `make axioms` checks that each rests only
on Lean's own axioms (no `sorry`, no `native_decide`).

### Of the protocol

- **Whoever a member names is right.** Whoever a watcher names at an index of a roster is whoever
  that roster's owner put there, however many messages it missed, provided no two members share a
  key prefix (`Roster.resolve_sound`). Reading a truthful message, learning an Introduction and
  following an `IntroducedAt` each preserve this (`ingest_sound`, `introduce_sound`,
  `begin_sound`). So a skipped box leaves an index unresolved, never misplaced.
- **`IntroducedAt` is needed.** A watcher that instead takes the first Introduction of a member
  it reads misplaces a member introduced twice (`first_introduction_misplaces`).
- **The `Acks` field needs its count.** Without one, a reader would split the field by its
  length, and decoding undoes encoding exactly when each value is longer than 32 bytes
  (`decodeUncounted_encodeUncounted_iff`), so an 8-byte `Idx64` would be misread. With the count
  byte, decoding undoes encoding for values of every size (`decode_encode`), and for the field
  katzenqt sends, of little-endian `Idx64` values (`decodeIdx64_encodeIdx64`). The count less one
  fits a byte (`count_lt`). With the strict parser each set of acknowledgements has exactly one
  field (`encode_decode`, `encodeIdx64_decodeIdx64`). The spec's parser also accepts a list where
  the bitmap is shorter, so one set has two fields (`spec_decode_malleable`).
- **The advance to an acknowledged box is sound.** A walk that finds its target says how many
  steps ahead it is, which proves the target comes after where it began; it keeps the last boxes
  before it, in order; no target lies further within its limit; and a walk that finds none has
  none within its limit (`walk_target`, `walk_skipped`, `walk_furthest`, `walk_none`). These rest
  on one property of BACAP: each step forward adds one to the `Idx64`.
- **Naming a box by its `Idx64` finds the box its whole index names.** On one stream, two boxes
  with the same `Idx64` are the same box (`eq_of_counter_eq`). So for boxes of the reader's own
  stream, the walk by `Idx64` finds the same box, keeps the same boxes and reports the same
  distance as stepping forward and comparing whole indexes, as katzenqt#108 does
  (`walk_eq_walkBoxes`). An acknowledgement read on the wrong stream is a different matter: see
  `AckTrue` below.
- **Rewrites keep boxes only if the replica refreshes them.** If a matching write is stored
  again at the current epoch, a box rewritten in epoch `e` can be read through `e + 1`
  (`refresh_rewrite_kept`). A tombstone is stored at the current epoch either way
  (`tomb_kept`).

### Of katzenqt's implementation

Proved of `Member/`, the model katzenqt's traces are replayed through.

- **A member acknowledges only what it has read.** What a reader acknowledges names a box it read,
  along with every box before it, however its reads, rechecks, walks and forgets interleave
  (`ReaderProofs.run_safe`). Reading never undoes this (`Safe.mono`). Every acknowledgement a
  member sends carries the `Idx64` of that run's end (`GroupProofs.acksOf_safe`). For every member reachable from founding
  or joining by any sequence of calls, every acknowledgement it sends is safe
  (`MemberProofs.acks_sent_safe`). The calls include the client changing its retention policy
  between them, as a user's disappearing messages setting does. The one assumption is that a walk the client reports kept no
  more boxes than it stepped past (`Event.WF`).
- **Acknowledgements of our own stream are checked.** One counts only for a box the Sent-box
  check finds by its `Idx64` (`takeAcks_credit`, `checkAt_some`).
- **Numbering has no gaps.** A control message numbers members at consecutive indexes from the
  next free one, counting what is composed and not yet written (`controlOf_consecutive`).
- **A new member gets the index it was promised.** An `Introduction` gives the new member the
  index the reply promised, when nothing composed before it is still unwritten
  (`introduction_index`). Otherwise it gives a later one (`introduction_index_pending`), which is
  why the spec says to wait.
- **Retention and backfill.** Retention drops plaintext only once every member still read has
  acknowledged it, or the policy has expired it (`retain_spec`). A box is rewritten at most once
  an epoch (`backfill_once`).
- **Names are right in the member too.** `Roster.resolve_sound`, carried to the member's rosters
  (`GroupProofs.resolve_sound`).
- **The wire formats round trip.** `Numbers` and `IntroducedAt` decode back to what was encoded
  (`decodeNumbers_encodeNumbers`, `decodeIntroducedAt_encodeIntroducedAt`). So does every
  `GroupChatMessage` this client writes (`Gcm.decode_encode`), on CBOR headers that read back as
  written (`Cbor.readHeader_header`).
- **The executable `Acks` codec is the proved one.** `AckBytes` computes `AckCodec`'s encoding and
  its spec parser (`AckBytes.encodeNat_eq`, `AckBytes.decodeNat_eq`), so `AckCodec`'s theorems
  hold of the codec a client runs (`AckBytes.decodeNat_encodeNat`).

### Of the katzenpost replica

- **A rewritten box is still collected.** A box written in epoch `e` and rewritten in `e + 1`
  cannot be read in `e + 2`, for every `e` (`Backfill.deployed_rewrite_lost`). A matching data
  write succeeds without storing anything, so the box keeps the epoch it was first stored in.
  This breaks the spec's "every position stays populated".

## Checking katzenqt against the Lean member

`replay.lean` checks that `Member/` is katzenqt's member and not just a likeness of it.
katzenqt's `groupchat/trace.py` records every call made on a member: its arguments, its result and
the member's whole state afterwards. The replay makes the same calls on the Lean member and
requires the same results and state. It also checks every index the trace says BACAP produced
against CryptWalker's own BACAP, including each walk, which advances to the acknowledged
`Idx64` with `advanceIndexTo`.

There are two kinds of trace. A simulated member's (`scenario-*.jsonl`) is driven by katzenqt's
simulator, which runs the member against a simulated Pigeonhole. The app's
(`adapter-scenario.jsonl`) is recorded from katzenqt's adapter, `acks.py`, and its network code, as
the app drives them: reads, sends, a user's scans, backfill and a change of retention policy,
against a database and a fake thin client that derives real BACAP indexes. So the replay checks
the member itself, and also the calls the app really makes on it.

A member's Sent box keeps what each of its boxes holds as a `Payload`: a message the member
composed, which its client encodes, or the bytes a client that writes for itself handed over,
which the member never looks into. The app hands over the box exactly as written, so a rewrite
writes the same bytes, even for a box that points to a large message's own stream.

`testdata/groupchat_traces/` holds the traces of katzenqt's scenarios and the app's. Run
`python tools/groupchat_traces.py DIR 0` in katzenqt to regenerate them. katzenqt's nightly job
replays fresh random runs (`tests/test_groupchat_trace.py`, with `CRYPTWALKER` set).
`ack_codec_test.lean` checks the `Acks` codec against vectors from katzenqt's Python codec, the
only one that implements the counted `Idx64` layout: fields it writes, fields its parser accepts
though it never writes them, and fields it refuses, under both `AckCodec` and `AckBytes`.
`scripts/gen_acks_vectors.py` generates them, and `make verify-vectors` regenerates them and
compares. `wire_vectors_test.lean` checks `Gcm`, `Membership` and `ReplyWho` against vectors from
katzenqt itself: each message reads as katzenqt reads it and is written back as katzenqt writes
it, and each reply carries the `JoinReply` katzenqt takes from it. `make
gen-groupchat-wire-vectors` regenerates them with katzenqt's Python. The replay also checks that
every state it reaches loads as `Persist` saved it.

```
lake exe CryptWalker.GroupChat.replay        # every trace in testdata/groupchat_traces/
lake exe CryptWalker.GroupChat.ack_codec_test
lake exe CryptWalker.GroupChat.wire_vectors_test
make axioms
```

## What is model-checked (TLA+)

### Invariants and properties

| Name | Module | Says |
|---|---|---|
| `Populated` | `Backfill` | A box its owner wrote or rewrote this epoch or the last can be read: the spec's "every position stays populated" |
| `NoSilentLoss` | `Backfill` | What a reader acknowledges, it has read, with every box before it |
| `NoOvershoot` | `Backfill` | A reader never expects a box beyond the one the owner writes next |
| `NoPrematureTombstone` | `Backfill` | A tombstone stands only where every reader has acknowledged |
| `DeliveryOnceScansStop` | `Backfill` | Liveness: if users ask for scans only finitely often, every box written reaches every reader while its owner still holds it |
| `RosterNoDup` | `GroupChat` | No member appears twice in a roster |
| `RosterAgree` | `GroupChat` | Whoever a watcher can name at an index of a roster is whoever its owner put there |
| `InductionIndex` | `GroupChat` | The index a new member takes is the one its introducer gives it |
| `Converged` | `GroupChat` | Once everyone has read everything and owes nothing, every watcher can name every index of every roster |
| `AckTrue` | `GroupChat` | A watcher takes an acknowledgement as naming the box its sender acknowledged, or as naming nothing |
| `ProtocolSpec` | `KatzenpostReplica` | Refinement: every step the deployed replica takes is a step the protocol allows |
| `NoGap` | `Katzenqt` | Every index a member writes is the next of its roster |
| `CConverged` | `Katzenqt` | `Converged`, once nothing is pending and no induction holds |

Where the spec can be read more than one way, or these models propose a change, a constant
chooses between the readings: `AckFurthest` and `PollHoles` in `Backfill.tla`, and
`HandIntroductions` and `UseIntroducedAt` in `GroupChat.tla`. `AckByIdx64` in `GroupChat.tla`
chooses between this variant's acknowledgements and katzenqt#108's. In `Katzenqt.tla`, `BugNoWait`
and `AbandonControl` each remove one guard.

### Protocol configs (`tla/protocol/`)

| Config | Expect | What it shows |
|---|---|---|
| `MC_Backfill_SpecAckRule` | violated `NoSilentLoss` | Acknowledging the furthest box read counts a box a jump skipped as read, so its owner may tombstone it |
| `MC_Backfill_SpecRecheck` | violated `DeliveryOnceScansStop` | Rechecking skipped boxes only during a scan can lose one for good |
| `MC_Backfill_Proposed` | pass | Acknowledging up to the unbroken run: `Populated`, `NoSilentLoss`, `NoOvershoot` and `NoPrematureTombstone` all hold |
| `MC_Backfill_LiveHoles` | pass | Polling the boxes a jump skipped until they are read delivers every box |
| `MC_GroupChat_Explicit` | pass | With explicit numbering, the Introductions in the reply and `IntroducedAt`: `RosterNoDup`, `RosterAgree`, `InductionIndex`, `Converged` and `AckTrue` all hold |
| `MC_GroupChat_Skip` | pass | A watcher that skips boxes leaves indexes unresolved, never misplaced, so acknowledgements by `Idx64` stay true |
| `MC_GroupChat_NoIntroducedAt` | violated `RosterAgree` | Without `IntroducedAt`, a member introduced twice is followed from the wrong introducer's roster |
| `MC_GroupChat_AckIdx64Misresolved` | violated `AckTrue` | The consequence for acknowledgements by `Idx64`: read on the wrong member's stream, one names a box its sender never meant |
| `MC_GroupChat_AckIndexMisresolved` | pass | The same, with katzenqt#108's acknowledgements by whole index: the box is never met on the wrong stream, so the acknowledgement names nothing |
| `MC_GroupChat_RostersOnly` | violated `Converged` | Handed rosters but not the Introductions, a new member can never name some members, though it names nobody wrongly |

### Implementation configs (`tla/impl/`)

| Config | Expect | What it shows |
|---|---|---|
| `MC_KatzenpostReplica_Refines` | violated `ProtocolSpec` | A matching rewrite stores nothing, where the protocol stores the box again |
| `MC_KatzenpostReplica_Populated` | violated `Populated` | The consequence: a box rewritten every epoch is still collected |
| `MC_KatzenpostReplica_LiveNoScan` | pass | Without scans, every box still reaches the reader; the collected box returns at the next rewrite |
| `MC_KatzenpostReplica_LiveHoles` | pass | With polled holes, delivery holds on the deployed replica too |
| `MC_Katzenqt_Fixed` | pass | katzenqt writes every roster index in order, gives a new member the index its Introduction gives it, a quiet group converges, and its acknowledgements by `Idx64` are true |
| `MC_Katzenqt_NoWait` | violated `InductionIndex` | A reply built while a control message is pending promises an index that message takes |
| `MC_Katzenqt_AbandonControl` | violated `NoGap` | Were a pending Introduction or control message abandoned, a message composed after it would write past the end of the roster. katzenqt abandons only content |

### Boxes

A box is named by its `MessageBoxIndex`, a BACAP value whose `Idx64` grows by one at each step
forward. Introductions and `IntroducedAt` name a box by its whole index; an acknowledgement names
it by a roster index and its `Idx64`, which mean a box only once the roster index has been
resolved to a stream. In `GroupChat.tla` a box is `<<owner, q>>`, unique to one box of one stream,
with `q` its `Idx64`. In `Backfill.tla` a box is a position on its one stream, which is its
`Idx64` counted from where the stream starts: a jump to an acknowledged box advances straight to
it. `ReaderScan.lean` proves that this lands where katzenqt#108's walk, comparing whole indexes,
would.

### Running

```
make tla                                      # every config, checked against its EXPECT line
FAST=1 tla/check.sh                           # what CI runs: skips configs marked SLOW
tla/check.sh protocol/MC_GroupChat_Explicit.cfg
tla/run.sh protocol/MC_GroupChat_Explicit.cfg  # TLC's full output, with the counterexample
```

Paths are relative to this directory. You need Java 11 or later, and `tla2tools.jar` in `tla/` or
named by `TLA2TOOLS`; `JAVA` selects the java binary. For long runs, set `TLC_METADIR` to a
directory on disk, because TLC's state files soon outgrow a RAM-backed `/tmp`.

Each `MC_*.cfg` starts with `\* EXPECT pass` or `\* EXPECT violated <Property>`. With `FAST=1`
the set runs in about two minutes; `MC_GroupChat_RostersOnly` adds about thirty more.

## What is proved (Veil)

`veil/GroupChatVeil/Backfill.lean` restates `Backfill.tla` in [Veil](https://github.com/verse-lab/veil),
with readers and positions as uninterpreted types. `#check_invariants` proves that `Populated`,
`NoSilentLoss`, `NoOvershoot` and `NoPrematureTombstone`, with nine auxiliary invariants, hold
in every reachable state, for any number of readers and any length of stream, under the proposed
acknowledgement rule. cvc5 finds each proof, and Lean checks it (`veil.smt.trust false`); the
file then checks that every theorem rests on Lean's own axioms only.

The model differs from `Backfill.tla` only by allowing more: epochs are unbounded, a box is the
slot for the current epoch and the slot for the last, `Discard` may come at any time, polling and
scans are always enabled, a reader keeps every position it skips, and a scan's jump is a separate
`Jump` step. A safety property that holds of it holds of `Backfill.tla`. The file's header lists
the differences. One assumption is made of positions: any position below another has a next one,
as in any finite order.

The same file model-checks 2 readers and 3 positions (`#model_check`), and finds, with the
solver, the run that `MC_Backfill_SpecAckRule` finds: under the spec's rule, a reader that jumped
over a box acknowledges it (`sat trace [spec_ack_rule_loses]`). Liveness, and the deployed
replica's write rule, stay with TLC.

```
make veil      # or: cd veil && lake build
```

`veil/` is its own Lake project, on Veil's toolchain (Lean 4.32.0, no Mathlib), so it does not
import CryptWalker. A first build fetches and compiles Veil, lean-smt and cvc5, and needs `npm`.

## What is not shown

- **Cryptography.** Unlinkability and unforgeability belong to the Echomix paper and BACAP. No
  forged box is considered.
- **Byzantine members.** Every member follows the protocol. A member sending forged or misnumbered
  `Acks` would test the Sent-box check, and is the natural next step.
- **Liveness in Lean.** Delivery and convergence are checked only by TLC, at small sizes.
- **Some features in the group-wide models.** Disappearing messages and member removal are not
  in `GroupChat.tla` or `Katzenqt.tla`. Of acknowledgements, those models check only which stream
  one is read on (`AckTrue`); `Backfill.tla` covers acknowledgements on one stream.
- **The network.** Couriers, replication between replicas and the mixnet are not modelled: the
  stream store behaves as one replica that always answers.
- **Large sizes in TLA+.** A TLC pass is a bounded result. Backfill uses 2 readers, 3 boxes and 3
  replica epochs (1 reader for liveness). Group chat uses 2 founders and 2 joiners, at most 2
  messages per stream and 4 across the group (`MCMaxTotal`), 3 when boxes may be skipped, and 6
  for `MC_GroupChat_RostersOnly`. The Lean proofs carry the main roster, acknowledgement and
  backfill claims to any size, and the Veil model carries `Backfill`'s safety properties.
- **Python against the TLA+ models.** `Katzenqt.tla` is written from katzenqt's code by hand; only
  `Member/` is checked against katzenqt mechanically, by the trace replay.
- **The app's trace is one scenario.** It covers each call the app makes, once. Random runs of
  the app's adapter, like the simulator's nightly runs, are not recorded.
