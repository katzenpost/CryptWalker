# Group chat protocol models (TLA+)

TLA+ models of the group chat protocol in the katzenpost website's group chat spec (website#242):
opportunistic acknowledgements, rosters, backfill, retention and rewrite-and-scan. Checked with
TLC. The Lean side is in `CryptWalker/GroupChat/`.

These model the protocol, not the Python. The one exception is `RostersClient.tla`, which models
the shape of katzenqt's send path, because that is where katzenqt#108's late bugs were.

## Running

```
make tla                               # every config, checked against its EXPECT line
FAST=1 tla/check.sh                    # what CI runs: skips configs marked SLOW
tla/check.sh MC_Backfill_Deployed.cfg  # one config
tla/run.sh MC_Backfill_Deployed.cfg    # TLC's full output, with the counterexample trace
```

You need Java 11 or later, and `tla2tools.jar` in `tla/` or named by `TLA2TOOLS`. `JAVA` selects
the java binary.

Each `MC_*.cfg` starts with `\* EXPECT pass` or `\* EXPECT violated <Property>`. Many configs
exist only to show that a design choice is needed: switch the choice off, and TLC must find the
failure.

## Models

| Module | What it covers |
|---|---|
| `Backfill.tla` | One member's stream: the replica as `replica/state.go` stores boxes (keyed by write epoch, current and previous kept), periodic rewrite, Sent-box retention, acknowledgements, and the reader's scan |
| `Rosters.tla` | Rosters across a group: acknowledgements by roster index, introductions, the reply to a new member, and every watcher following every roster as katzenqt's `rosters.follow` does |
| `RostersClient.tla` | katzenqt's send path over `Rosters.tla`: acknowledgements taken when a message is queued, rosters grown when it is written, inductions, and cancel |

## Configs

| Config | Expect | What it shows |
|---|---|---|
| `MC_Backfill_Deployed` | violated `Populated` | A box rewritten every epoch is still collected at the end of its second epoch |
| `MC_Backfill_Refresh` | pass | With a refreshing replica, the found-something scan rule and acknowledgements up to the unbroken run |
| `MC_Backfill_NaiveAdopt` | violated `NoOvershoot` | Adopting the first empty probe skips the end of a quiet stream |
| `MC_Backfill_AckFurthest` | violated `NoSilentLoss` | Acknowledging the furthest box read counts a skipped box as read |
| `MC_Backfill_LiveNoScan` | pass | Without scans every box is delivered, despite the deployed replica's gaps |
| `MC_Backfill_LiveScan` | violated `DeliveryOnceScansStop` | One scan, racing a write, loses a box for good |
| `MC_Backfill_LiveHoles` | pass | Polling the positions a scan skipped delivers every box |
| `MC_Rosters_SpecOnly` | violated `RosterPrefix` | Given only `Rosters`, a new member misplaces a member |
| `MC_Rosters_Extended` | pass | The hand-over katzenqt sends |
| `MC_RostersClient_Fixed` | pass | katzenqt's send path after #108 |
| `MC_RostersClient_NoWaitAcks` | violated `InductionIndex` | 6f06a4b undone |
| `MC_RostersClient_NoWaitIntro` | violated `InductionIndex` | b88abff undone |
| `MC_RostersClient_CancelKeepsAcks` | violated `NoLostAck` | f2e4c01 undone |

## What is not modelled

- Cryptography: unlinkability and unforgeability are the paper's and BACAP's. Boxes are
  positions, and a forged box is not considered.
- Byzantine members: every member follows the protocol. A member sending forged or misnumbered
  `Acks` would test the Sent-box check, and is the natural next step.
- Disappearing messages.
- Couriers, replication between replicas, and the mixnet: the stream store behaves as one
  replica that always answers.
- Sizes are small, so a pass is a bounded result. Backfill: 2 readers, 3 boxes, 3 replica
  epochs (1 reader for liveness). Rosters: 2 founders and 2 joiners, at most 2 messages per
  stream and 4 across the group (`MCMaxTotal`); `MC_Rosters_Extended` also passes at 5 (841,045
  states, under two minutes). The Lean proofs carry the main roster and backfill claims to any
  size.

Set `TLC_METADIR` to a directory on disk for long runs: TLC's state files outgrow a RAM-backed
`/tmp` quickly.
