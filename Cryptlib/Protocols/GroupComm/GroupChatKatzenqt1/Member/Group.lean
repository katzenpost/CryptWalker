/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Rosters
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Reader
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.SentBox
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Ledger

/-! # One member of one group chat

A state machine over `Group`, driven either by events (`handle`, returning effects) or by a
client that reads and writes itself (`observe`, `compose`, `written`). A message changes rosters
only once it has a box on the member's stream. -/

namespace Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member

open Cryptlib.Protocols.GroupComm.Common

/-- How many of its own indexes a member derives at a time. -/
def poolSize : Nat := 4

/-- What stands in a roster for a member known only by its place. -/
def placeholder (place : Nat) : Key := "retired".toUTF8.push place.toUInt8

/-- What a composed message does once it has a box. -/
structure Pending where
  /-- Roster indexes it assigns, and to whose `Introduction`; `none` for the one it carries. -/
  numbers : List (Nat × Option At) := []
  introduced : Option Key := none
  /-- Each stream it acknowledges: what had been published before, and now. -/
  acks : Dict Key (Option Index × Index) := {}
  control : Bool := false
  deriving DecidableEq, Inhabited

structure Outgoing where
  token : Nat
  message : Message
  deriving DecidableEq, Inhabited

structure Group where
  /-- Our own read cap: our key and our stream's first index. -/
  readCap : ByteArray
  policy : Retention := {}
  /-- How many boxes behind it a reader keeps one a scan stepped past. -/
  recheck : Nat := 256
  rosters : Rosters := {}
  readers : Dict Key Reader := {}
  sent : SentBox := {}
  ledger : Ledger := {}
  epoch : Nat := 0
  pool : List Index := []
  /-- The furthest of our own indexes derived so far. -/
  tip : Index := .empty
  deriving_ : Bool := false
  /-- Content waiting for an index. -/
  outbox : List ByteArray := []
  /-- Messages composed that have no box yet, by token. -/
  pending : Dict Nat Pending := {}
  tokens : Nat := 0
  /-- Introductions read whose member we have not numbered yet. -/
  unnumbered : List At := []
  /-- Owed in our next message, once we have read our `Introduction`. -/
  introducedAt : Option IntroRef := none
  /-- Our introducer, until we have read our `Introduction`. -/
  joinedThrough : Option Key := none
  /-- `IntroducedAt` read before the `Introduction` it names. -/
  awaitingStart : Dict Key Index := {}
  /-- Content delivered, by sender and box, and the epoch it came. -/
  received : Dict (Key × Index) Nat := {}
  deriving DecidableEq, Inhabited

abbrev GM := StateM Group

namespace Group

def new (readCap : ByteArray) (policy : Retention := {}) (recheck : Nat := 256) : Group :=
  { readCap := readCap, policy := policy, recheck := recheck, tip := startOf readCap, pool := [startOf readCap] }

def me (g : Group) : Key := keyOf g.readCap

def follow (readCap : ByteArray) (start : Index) : GM Unit :=
  modify fun g => { g with readers := g.readers.set (keyOf readCap) ⟨keyOf readCap, readCap, start,
    none, 0, [], none, .idle, []⟩ }

/-- Read the stream of `readCap` from its start, unless we read it already. -/
def followIfNew (readCap : ByteArray) : GM Unit := do
  let g ← get
  if !g.readers.contains (keyOf readCap) then follow readCap (startOf readCap)

/-- Start a group with `founders`' read caps, ours among them. -/
def found (readCap : ByteArray) (founders : List ByteArray) (policy : Retention := {})
    (recheck : Nat := 256) : Group :=
  let g := new readCap policy recheck
  let g := { g with rosters := g.rosters.found (founders.map keyOf) }
  (founders.foldlM (fun _ cap => if keyOf cap ≠ g.me then follow cap (startOf cap) else pure ())
    () |>.run g).2

/-- Join a group from what our introducer handed us. -/
def joined (readCap : ByteArray) (reply : JoinReply) (policy : Retention := {})
    (recheck : Nat := 256) : Group :=
  let g := new readCap policy recheck
  let order : List Key := reply.members.zipIdx.map (fun (m, place) => match m with
    | some (rc, _) => keyOf rc
    | none => placeholder place) ++ [g.me]
  let entries := reply.rosters.zipIdx.foldl (fun e (roster, place) => match roster, order[place]? with
    | some roster, some owner =>
      e.set owner (Dict.ofList (roster.map fun (index, slot) => (index, { key := slot.bind (order[·]?) })))
    | _, _ => e) g.rosters.entries
  let introductions := reply.introductions.foldl (fun d (by_, index, member) =>
    match order[by_]?, order[member]? with
    | some i, some m => d.set (i, index) m
    | _, _ => d) g.rosters.introductions
  let rosters := reply.members.foldl (fun (r : Rosters) slot => match slot with
    | some (rc, _) => r.learn (keyOf rc)
    | none => r) { g.rosters with introductions := introductions }
  let rosters := rosters.learn g.me
  let introducer := order.getD reply.introducer .empty
  let own := ((entries.getD introducer {}).set reply.newcomer { key := some g.me })
  let g := { g with rosters := { rosters with entries := entries.set g.me own } }
  let g := (reply.members.foldlM (fun _ slot => match slot with
    | some (rc, start) => follow rc start
    | none => pure ()) () |>.run g).2
  { g with joinedThrough := some introducer }

/-! ## Reading -/

def heard (g : Group) (stream : Key) : List Nat := (g.ledger.heard.getD stream {}).values

def setReader (r : Reader) : GM Unit := modify fun g => { g with readers := g.readers.set r.stream r }

def scanStream (stream : Key) : GM (List Effect) := do
  let g ← get
  match g.readers.get? stream with
  | none => pure []
  | some r =>
    let (r, es) := r.scan (g.heard stream) g.recheck
    setReader r
    pure es

/-- Whether `member` is in our roster, or will be once what we have composed is written. -/
def numbered (g : Group) (member : Key) : Bool :=
  (g.rosters.indexOf g.me member).isSome ||
    g.pending.values.any fun p => p.introduced = some member ||
      p.numbers.any fun (_, at_) => match at_ with
        | some a => g.rosters.introductions.get? a = some member
        | none => false

/-- `member`'s roster began as `introducer`'s, through the index `introducer` gave it. -/
def beginRoster (member introducer : Key) : GM Unit := modify fun g =>
  match g.rosters.indexOf introducer member with
  | some place => { g with rosters := { g.rosters with started := g.rosters.started.set member (introducer, place) } }
  | none => g

/-- `member` says it joined through the `Introduction` at `index`. -/
def started (member : Key) (index : Index) : GM Unit := do
  let g ← get
  match g.rosters.introductions.pairs.find? (fun ((_, at_), n) => n = member && at_ = index) with
  | some ((introducer, _), _) => beginRoster member introducer
  | none => set { g with awaitingStart := g.awaitingStart.set member index }

/-- Our own `Introduction` by the introducer we joined through: say where, in `IntroducedAt`. -/
def noteOwn (introducer : Key) (index : Index) (new : Key) : GM Unit := do
  let g ← get
  if new = g.me && g.joinedThrough = some introducer then
    match g.rosters.indexOf g.me introducer with
    | some place => set { g with introducedAt := some ⟨place, index⟩, joinedThrough := none }
    | none => pure ()

/-- An `IntroducedAt` read earlier named this `Introduction`. -/
def noteAwaited (introducer : Key) (index : Index) (new : Key) : GM Unit := do
  let g ← get
  if g.awaitingStart.get? new = some index then
    set { g with awaitingStart := g.awaitingStart.erase new }
    beginRoster new introducer

/-- Read the new member's stream, and owe it a number. -/
def noteNew (introducer : Key) (index : Index) (intro : Introduction) : GM Unit := do
  let new := keyOf intro.readCap
  let g ← get
  if new = g.me || g.numbered new then pure ()
  else
    followIfNew intro.readCap
    modify fun g => if g.unnumbered.contains (introducer, index) then g
      else { g with unnumbered := g.unnumbered ++ [(introducer, index)] }

def introduced (introducer : Key) (index : Index) (intro : Introduction) : GM Unit := do
  let new := keyOf intro.readCap
  modify fun g => { g with rosters := ({ g.rosters with
    introductions := g.rosters.introductions.set (introducer, index) new } : Rosters).learn new }
  noteOwn introducer index new
  noteAwaited introducer index new
  noteNew introducer index intro

/-- Take one acknowledgement `sender` sent: of our own stream, it counts only for a box the
Sent-box check finds; of another's, it is heard. -/
def takeAck (sender : Key) (g : Group) (a : Nat × Nat) : Group :=
  match g.rosters.resolve sender a.1 with
  | some acked =>
    if acked = g.me then
      if g.sent.checkAt a.2 then { g with ledger := g.ledger.acked sender a.2 } else g
    else { g with ledger := g.ledger.hear acked a.2 sender }
  | none => g

def deliver (sender : Key) (index : Index) (message : Message) : GM (List Effect) := do
  match message.content with
  | none => pure []
  | some content =>
    modify fun g => { g with received := g.received.set (sender, index) g.epoch }
    pure [.deliver sender index content]

def ingestIntroduction (sender : Key) (index : Index) (message : Message) : GM Unit :=
  match message.introduction with
  | some intro => introduced sender index intro
  | none => pure ()

def ingestIntroducedAt (sender : Key) (message : Message) : GM Unit :=
  match message.introducedAt with
  | some at_ => started sender at_.index
  | none => pure ()

def ingest (sender : Key) (index : Index) (message : Message) : GM (List Effect) := do
  modify fun g => message.numbers.foldl (fun g (number, p) =>
    let entry : Entry := match p, message.introduction with
      | some p, _ => { prefix_ := some p }
      | none, some i => { key := some (keyOf i.readCap) }
      | none, none => {}
    { g with rosters := g.rosters.number sender number entry }) g
  ingestIntroduction sender index message
  ingestIntroducedAt sender message
  modify fun g => message.acks.foldl (takeAck sender) g
  deliver sender index message

def boxRead (stream : Key) (index : Index) (result : ReadResult) (next : Option Index) :
    GM (List Effect) := do
  let g ← get
  match g.readers.get? stream with
  | none => pure []
  | some r =>
    let (message, r, es) := r.found index result next g.recheck
    setReader r
    match message with
    | some m => pure ((← ingest stream index m) ++ es)
    | none => pure es

/-! ## Writing -/

/-- The next index of our roster, counting what is composed. -/
def size (g : Group) : Nat :=
  (g.pending.values.flatMap (·.numbers)).foldl (fun m (n, _) => max m (n + 1)) (g.rosters.size g.me)

def owesControl (g : Group) : Bool :=
  !g.ledger.holding &&
    (g.introducedAt.isSome || g.unnumbered.any fun a => g.rosters.introductions.contains a)

/-- Number every member whose `Introduction` we have read and whose introducer we have numbered,
from the next index on: the message, what it does once written, and who is left unnumbered. -/
def controlStep (g : Group) (acc : Nat × Numbers × List (Nat × Option At) × List At) (a : At) :
    Nat × Numbers × List (Nat × Option At) × List At :=
  match g.rosters.introductions.get? a with
  | none => acc
  | some new => (acc.1 + 1, acc.2.1 ++ [(acc.1, some (prefixOf new))],
      acc.2.2.1 ++ [(acc.1, some a)], acc.2.2.2.eraseP (· = a))

def controlOf (g : Group) : Message × Pending × List At :=
  let r := g.unnumbered.foldl g.controlStep (g.size, [], [], g.unnumbered)
  ({ numbers := r.2.1, introducedAt := g.introducedAt }, { numbers := r.2.2.1, control := true }, r.2.2.2)

/-- Number every member whose `Introduction` we have read and whose introducer we have numbered,
and say where we were introduced. -/
def control : GM (Message × Pending) := do
  let g ← get
  let (m, p, unnumbered) := g.controlOf
  set { g with unnumbered := unnumbered, introducedAt := none }
  pure (m, p)

def release : GM Unit := modify fun g =>
  { g with ledger := { g.ledger with induction := .idle, invitee := none, commit := false, starts := {} } }

def hold : GM Unit := modify fun g =>
  { g with ledger := { g.ledger with induction := .inducting, starts := g.readers.mapValues (·.next) } }

/-- The `Introduction` of the member read by `readCap`, numbering it next unless it is numbered
already, and what it does once written. -/
def introductionOf (g : Group) (name : String) (readCap : ByteArray) : Message × Pending :=
  let new := keyOf readCap
  let assigned : List (Nat × Option At) := if g.numbered new then [] else [(g.size, none)]
  ({ introduction := some ⟨name, readCap⟩, numbers := assigned.map fun (n, _) => (n, none) },
    { numbers := assigned, introduced := some new, control := true })

def introduction (name : String) (readCap : ByteArray) : GM (Message × Pending) := do
  let g ← get
  followIfNew readCap
  release
  pure (g.introductionOf name readCap)

/-- Acknowledge every stream we read whose run has moved on since we last did: the
acknowledgements, keyed by our roster index and naming each box by its `Idx64`, what the message
does once written, and the ledger after. -/
def acksOf (g : Group) (pending : Pending) : List (Nat × Nat) × Pending × Ledger :=
  (g.rosters.known g.me).foldl
    (fun (acc : List (Nat × Nat) × Pending × Ledger) (e : Nat × Option Key) =>
      match e.2.bind g.readers.get? with
      | none => acc
      | some r =>
        match acc.2.2.owed r.stream r.run with
        | none => acc
        | some owed =>
          (acc.1 ++ [(e.1, counter owed)],
            { acc.2.1 with acks := acc.2.1.acks.set r.stream (acc.2.2.published.get? r.stream, owed) },
            acc.2.2.publish r.stream owed))
    ([], pending, g.ledger)

def withAcks (message : Message) (pending : Pending) : GM (Message × Pending) := do
  let g ← get
  let (acks, pending, ledger) := g.acksOf pending
  set { g with ledger := ledger }
  pure ({ message with acks := acks }, pending)

def stage (message : Message) (pending : Pending) : GM Outgoing := do
  modify fun g => { g with tokens := g.tokens + 1, pending := g.pending.set (g.tokens + 1) pending }
  pure ⟨(← get).tokens, message⟩

/-- The message `token` landed in the box `index` of our stream. -/
def written (token : Nat) (index : Index) (plaintext : Option Payload) : GM Unit := modify fun g =>
  match g.pending.get? token with
  | none => g
  | some p =>
    let rosters := p.numbers.foldl (fun r (number, introduced) =>
      let key := match introduced with
        | some a => g.rosters.introductions.get? a
        | none => p.introduced
      r.number g.me number { key := key }) g.rosters
    let rosters := match p.introduced with
      | some n => let r := rosters.learn n
        { r with introductions := r.introductions.set (g.me, index) n }
      | none => rosters
    { g with pending := g.pending.erase token, rosters := rosters,
             sent := g.sent.record index plaintext p.control g.epoch }

def write (o : Outgoing) : GM (List Effect) := do
  match (← get).pool with
  | [] => pure []
  | index :: rest =>
    modify fun g => { g with pool := rest }
    written o.token index (some (.message o.message))
    pure [.writeBox index (.message o.message)]

/-- The message to send next: control if owed, else the oldest content. -/
def next : GM (Message × Pending) := do
  let g ← get
  if g.owesControl then control
  else
    set { g with outbox := g.outbox.drop 1 }
    pure ({ content := g.outbox.head? }, {})

/-- Write what is owed, at most `n` messages. -/
def flushSome : Nat → GM (List Effect)
  | 0 => pure []
  | n + 1 => do
    let g ← get
    if g.pool.isEmpty || !(g.owesControl || !g.outbox.isEmpty) then pure []
    else
      let (m, p) ← next
      let (m, p) ← withAcks m p
      let es ← write (← stage m p)
      pure (es ++ (← flushSome n))

def flush : GM (List Effect) := do
  let effects ← flushSome (← get).pool.length
  let g ← get
  if g.pool.length < 2 && !g.deriving_ then
    set { g with deriving_ := true }
    pure (effects ++ [.deriveIndexes g.me g.tip poolSize])
  else pure effects

def settled (g : Group) : Bool :=
  g.unnumbered.isEmpty && g.outbox.isEmpty && g.readers.values.all (·.mode = .idle)

/-- What to hand a new member, which will start our stream at `ownStart`. -/
def reply (g : Group) (ownStart : Index) : JoinReply :=
  let order := g.rosters.known g.me
  let size := match order.getLast? with
    | some (i, _) => i + 1
    | none => 0
  let place : Dict Key Nat := Dict.ofList (order.filterMap fun (i, k) => k.map (·, i))
  let keyAt := fun (index : Nat) => ((order.find? (·.1 = index)).bind (·.2))
  let members := (List.range size).map fun index =>
    match keyAt index with
    | some k =>
      if k = g.me then some (g.readCap, ownStart)
      else (g.readers.get? k).map fun r => (r.readCap, g.ledger.starts.getD k r.next)
    | none => none
  let rosters := (List.range size).map fun index =>
    let known := match keyAt index with
      | some k => g.rosters.known k
      | none => []
    if known.isEmpty then none else some (known.map fun (i, k) => (i, k.bind place.get?))
  { members := members, rosters := rosters
    introductions := g.rosters.introductions.pairs.filterMap fun ((i, at_), k) =>
      match place.get? i, place.get? k with
      | some a, some b => some (a, at_, b)
      | _, _ => none
    introducer := place.getD g.me 0
    newcomer := size }

def introduceNow (name : String) (readCap : ByteArray) : GM Outgoing := do
  let (m, p) ← introduction name readCap
  stage m p

def commitInduction : GM (List Effect) := do
  let g ← get
  match g.ledger.invitee with
  | none => pure []
  | some (name, readCap) =>
    let r := g.reply (g.pool.headD .empty)
    let es ← write (← introduceNow name readCap)
    pure (es ++ [.sendJoinReply readCap r] ++ (← flush))

/-- Do whatever has become possible: write what is owed, finish catching up, commit an
induction. -/
def holdIfSettled : GM Unit := do
  let g ← get
  if g.ledger.induction = .catchingUp && g.settled then hold

def commitIfReady : GM (List Effect) := do
  let g ← get
  if g.ledger.induction = .inducting && g.ledger.commit && !g.pool.isEmpty then commitInduction
  else pure []

def progress : GM (List Effect) := do
  let effects ← flush
  holdIfSettled
  pure (effects ++ (← commitIfReady))

def derived (indexes : List Index) : GM (List Effect) := do
  modify fun g =>
    { g with deriving_ := false, pool := g.pool ++ indexes, tip := indexes.getLastD g.tip }
  progress

def invite (name : String) (readCap : ByteArray) (commit : Bool) : GM (List Effect) := do
  modify fun g => { g with
    ledger := { g.ledger with induction := .catchingUp, invitee := some (name, readCap), commit := commit } }
  let g ← get
  set { g with readers := g.readers.mapValues (·.read.1) }
  pure ((g.readers.values.flatMap (·.read.2)) ++ (← progress))

/-! ## Membership and time -/

/-- Stop reading `member` and forget its key, keeping its places. -/
def remove (member : Key) : GM Unit := modify fun g =>
  let token := match g.rosters.indexOf g.me member with
    | some place => placeholder place
    | none => "retired:".toUTF8 ++ member.extract 0 8
  let rosters := g.rosters.retire member token
  { g with rosters := rosters, readers := g.readers.erase member, ledger := g.ledger.forget member,
           unnumbered := g.unnumbered.filter fun at_ => rosters.introductions.get? at_ ≠ some token }

def everyoneAcked (g : Group) (idx64 : Nat) : Bool :=
  g.readers.keys.all fun k => match g.ledger.ackedBy.get? k with
    | some s => idx64 ≤ s
    | none => false

def onEpoch (epoch : Nat) : GM (List Effect) := do
  modify fun g => { g with epoch := epoch }
  modify fun g => { g with sent := g.sent.retain epoch g.policy g.everyoneAcked }
  let g ← get
  let expired : List (Key × Index) := match g.policy.keepReceived with
    | some keep => (g.received.pairs.filter fun (_, at_) => at_ + keep ≤ epoch).map (·.1)
    | none => []
  set { g with received := g.received.filter fun k _ => !expired.contains k }
  let effects := expired.map fun (sender, index) => Effect.expire sender index
  let g ← get
  let (sent, backfill) := g.sent.backfill epoch g.everyoneAcked
  set { g with sent := sent }
  pure (effects ++ backfill)

/-! ## Driven by events -/

def handle (event : Event) : GM (List Effect) := do
  let g ← get
  match event with
  | .send content =>
    set { g with outbox := g.outbox ++ [content] }
    progress
  | .read stream =>
    match g.readers.get? stream with
    | some r =>
      let (r, es) := r.read
      setReader r
      pure es
    | none => pure []
  | .scan stream => scanStream stream
  | .boxRead stream index result next => pure ((← boxRead stream index result next) ++ (← progress))
  | .indexesDerived _ indexes => derived indexes
  | .walked stream target skipped steps =>
    match g.readers.get? stream with
    | some r =>
      let (r, es) := r.walked target skipped steps g.recheck
      setReader r
      pure es
    | none => pure []
  | .invite name readCap => invite name readCap false
  | .introduce name readCap =>
    if g.ledger.induction = .idle then invite name readCap true
    else
      set { g with ledger := { g.ledger with commit := true } }
      progress
  | .remove member =>
    remove member
    pure []
  | .epochChanged epoch => onEpoch epoch

/-! ## Driven by a client that reads and writes for itself -/

/-- A box read on `stream`, in order: its message, or `none` for one that holds nothing we can
use. -/
def observe (stream : Key) (index : Index) (message : Option Message) (next : Index) :
    GM (List Effect) := do
  match (← get).readers.get? stream with
  | none => pure []
  | some r =>
    setReader { r with next := index, mode := .reading }
    let es ← boxRead stream index (.data message) (some next)
    modify fun g => { g with readers := g.readers.modify stream fun r => { r with mode := .idle } }
    pure (es.filter fun
      | .deliver .. | .expire .. => true
      | _ => false)

def stageAll : List (Message × Pending) → GM (List Outgoing)
  | [] => pure []
  | (m, p) :: rest => do
    let (m, p) ← withAcks m p
    let o ← stage m p
    pure (o :: (← stageAll rest))

/-- The messages to send now, in order: a control message if one is owed, then `content`. Each
takes effect when `written`. -/
def compose (content : Option ByteArray := none) : GM (List Outgoing) := do
  let owed : List (Message × Pending) ← if (← get).owesControl then (fun x => [x]) <$> control else pure []
  stageAll (owed ++ content.toList.map fun c => ({ content := some c }, Pending.mk [] none {} false))

/-- The message `token` will never be written: whatever it acknowledged is owed again, and whoever
it numbered still needs numbering. -/
def abandoned (token : Nat) : GM Unit := modify fun g =>
  match g.pending.get? token with
  | none => g
  | some p =>
    let published := p.acks.pairs.foldl (fun d (stream, (before, sent)) =>
      if d.get? stream = some sent then
        match before with
        | some b => d.set stream b
        | none => d.erase stream
      else d) g.ledger.published
    { g with pending := g.pending.erase token, ledger := { g.ledger with published },
             unnumbered := if p.introduced.isNone then g.unnumbered ++ p.numbers.filterMap (·.2)
               else g.unnumbered }

/-- Begin inducting a member, starting each stream where we have read it now. Anything owed goes
out first. -/
def beginInduction : GM (List Outgoing) := do
  let out ← compose
  hold
  pure out

def cancelInduction : GM Unit := release

end Group

end Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member
