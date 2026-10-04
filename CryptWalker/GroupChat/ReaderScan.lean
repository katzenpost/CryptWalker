/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cslib.Foundations.Semantics.LTS.Basic

/-! # The reader's scan state machine

See "Rewrite and scan" in the group chat spec, and katzenqt's `ack_protocol.step`, which this
follows. A reader of one stream is `reading` or `scanning`; each event says what a read of a box
found, or that the user asked for a scan; each step returns the next state and what the driver
should do.

* `scanning_only_by_request`: the only way into `scanning` is the user's request, so no run of
  `BoxIDNotFound`, however long, starts a scan (the spec's MUST NOT).
* `adopt_only_on_not_found`: a frontier is adopted only on `BoxIDNotFound` during a scan.
* `ingest_iff_data`: a message is ingested exactly when a box held one.

Which position a scan should adopt is the driver's business and not in `step`; that question is
`NoOvershoot` in `tla/protocol/Backfill.tla`. -/

namespace CryptWalker.GroupChat.ReaderScan

inductive State | reading | scanning
  deriving DecidableEq

inductive Event | readOk (payload : List UInt8) | readTombstoned | readNotFound | scanRequested
  deriving DecidableEq

inductive Effect
  | ingest (payload : List UInt8) | advanceExpected | probeForward | probeBackward | adoptFrontier
  deriving DecidableEq

/-- One transition, total over every state and event. -/
def step : State → Event → State × List Effect
  | .reading, .readOk p => (.reading, [.ingest p, .advanceExpected])
  | .reading, .readTombstoned => (.reading, [.advanceExpected])
  | .reading, .readNotFound => (.reading, [])
  | .reading, .scanRequested => (.scanning, [.probeBackward, .probeForward])
  | .scanning, .readOk p => (.scanning, [.ingest p, .probeForward])
  | .scanning, .readTombstoned => (.scanning, [.probeForward])
  | .scanning, .readNotFound => (.reading, [.adoptFrontier])
  | .scanning, .scanRequested => (.scanning, [])

/-- The machine as a labelled transition system, labelled by the event and the effects. -/
def lts : Cslib.LTS State (Event × List Effect) :=
  ⟨fun s l s' => step s l.1 = (s', l.2)⟩

theorem scanning_only_by_request {e : Event} (h : (step .reading e).1 = .scanning) :
    e = .scanRequested := by
  cases e <;> simp_all [step]

/-- **No count of `BoxIDNotFound` starts a scan**: reading on through any number of them leaves
the reader reading and doing nothing. -/
theorem not_found_forever (n : ℕ) :
    (List.replicate n Event.readNotFound).foldl (fun s e => (step s e).1) .reading = .reading := by
  induction n with
  | zero => rfl
  | succ n ih => rw [List.replicate_succ', List.foldl_append, ih]; rfl

theorem adopt_only_on_not_found {s : State} {e : Event} (h : .adoptFrontier ∈ (step s e).2) :
    s = .scanning ∧ e = .readNotFound := by
  cases s <;> cases e <;> simp_all [step]

theorem ingest_iff_data (s : State) (e : Event) (p : List UInt8) :
    .ingest p ∈ (step s e).2 ↔ e = .readOk p := by
  cases s <;> cases e <;> simp [step, eq_comm]

end CryptWalker.GroupChat.ReaderScan
