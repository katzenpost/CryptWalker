/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.BACAP.API
import CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.Group
import CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.Walk
import CryptWalker.Util.Bytes
import HashSig.SLHDSA.Concrete.Keccak

/-! # Run katzenqt's group chat scenarios

katzenqt's scenarios (`tests/data/groupchat/*.txt`) drive members of a group over a simulated
Pigeonhole, and its `groupchat/sim.py` checks each command's output against the lines after it.
This runs the same files through the Lean member, with the same simulated replica, the same
seeded keys, and the same way of printing what was read, written and acknowledged; a scenario
passes when the Lean member prints exactly what katzenqt's does.

Usage: `lake exe CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.scenarios [scenario.txt | dir]...`, by default every scenario
in `testdata/groupchat_scenarios/`. With `--rewrite`, each file takes the output instead. -/

open CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member
open CryptWalker.Protocols.BACAP.Types

namespace Scenarios

open CryptWalker.Protocols.GroupComm.Common

def bytesOf {n : Nat} (v : Vector UInt8 n) : ByteArray := CryptWalker.Util.Bytes.ofVector v

/-- The index after `b`, by BACAP. -/
def step (b : ByteArray) : ByteArray :=
  if b.size ≠ MessageBoxIndexSize then .empty else
  match (unmarshalMessageBoxIndex (CryptWalker.Util.Bytes.toVecN _ b)).nextIndex with
  | some n => bytesOf (marshalMessageBoxIndex n)
  | none => .empty

/-- `shake_256("{name}/{n}")`, the `n`th draw of katzenqt's seeded randomness. -/
def draw (name : String) (n size : Nat) : ByteArray :=
  SLHDSA.Concrete.Keccak.shake256 s!"{name}/{n}".toUTF8 size

def vec (b : ByteArray) (n : Nat) : Vector UInt8 n := Vector.ofFn fun i : Fin n => b[i.val]!

/-- The write cap katzenqt's `WriteCap.generate(seeded(name))` makes: a signing seed, then an HKDF
state and a starting index. -/
def capOf (name : String) : WriteCap :=
  { rootSeed := vec (draw name 1 32) 32
    messageBoxIndex := MessageBoxIndex.random (vec (draw name 2 32 ++ draw name 3 16) 48) }

/-- How far a walk steps, and how far a box is looked for on a stream. -/
def walkLimit : Nat := 256

/-- What a box holds: a message, or a tombstone. -/
abbrev Stored := Option Message

structure Replica where
  epoch : Nat := 0
  /-- Each epoch's boxes, by index. -/
  buckets : List (Nat × List (ByteArray × Stored)) := []

namespace Replica

def kept (r : Replica) : List Nat := if r.epoch = 0 then [0] else [r.epoch, r.epoch - 1]

def bucket (r : Replica) (e : Nat) : List (ByteArray × Stored) := (r.buckets.lookup e).getD []

def find? (r : Replica) (e : Nat) (index : ByteArray) : Option Stored :=
  ((r.bucket e).find? (·.1 == index)).map (·.2)

/-- Store a box: a write to a box still kept succeeds only with what it holds already, and a
tombstone is always stored. -/
def write (r : Replica) (index : ByteArray) (box : Stored) : Replica × String :=
  let existing := if box.isNone then none else r.kept.findSome? (r.find? · index)
  match existing with
  | some old => (r, if old == box then "same" else "refused")
  | none =>
    let b := (r.bucket r.epoch).filter (·.1 != index) ++ [(index, box)]
    ({ r with buckets := (r.buckets.filter (·.1 != r.epoch)) ++ [(r.epoch, b)] }, "stored")

def read (r : Replica) (index : ByteArray) : Option Stored := r.kept.findSome? (r.find? · index)

def advance (r : Replica) : Replica :=
  let r := { r with epoch := r.epoch + 1 }
  { r with buckets := r.buckets.filter fun (e, _) => r.kept.contains e }

end Replica

instance : Inhabited WriteCap := ⟨capOf ""⟩

structure Member where
  name : String
  cap : WriteCap
  readCap : ByteArray
  /-- Our stream's indexes from its first, `walkLimit` of them. -/
  chain : Array ByteArray
  group : Option Group := none
  inbox : Array (Key × Index × String) := #[]
  /-- Every message read, by stream and box, for `acks`. -/
  seen : List ((Key × Index) × Message) := []
  reported : Int := -1
  passive : Bool := false
  unwritten : List Outgoing := []
  nextOwn : ByteArray := .empty
  cursors : Dict Key Index := {}
  deriving Inhabited

def Member.key (m : Member) : Key := keyOf m.readCap

def Member.ordinalOf (m : Member) (index : ByteArray) : Option Nat := m.chain.findIdx? (· == index)

/-- Which box of our stream an `Idx64` names. -/
def Member.ordinalAt (m : Member) (idx64 : Nat) : Option Nat :=
  let first := counter (m.chain[0]!)
  if first ≤ idx64 && idx64 - first < walkLimit then some (idx64 - first) else none

inductive Opt
  | flag (on : Bool)
  | nothing
  | num (n : Nat)

structure World where
  replica : Replica := {}
  members : Array Member := #[]
  options : List (String × Opt) := []

abbrev SimM := StateT World IO

def fail {α : Type} (msg : String) : SimM α := throw (IO.userError msg)

def option? (name : String) : SimM (Option Opt) := return (← get).options.lookup name

def flag (name : String) : SimM Bool := do
  match ← option? name with
  | some (.flag b) => return b
  | _ => return false

def policy : SimM Retention := do
  let num (n : String) (d : Option Nat) : SimM (Option Nat) := do
    match ← option? n with
    | some (.num k) => return some k
    | some .nothing => return none
    | _ => return d
  return { window := ← num "window" (some 3), keepSent := ← num "keep_sent" none,
           keepReceived := ← num "keep_received" none,
           discardAcked := (← option? "discard_acked").all fun | .flag b => b | _ => true }

def recheck : SimM Nat := do
  match ← option? "recheck" with
  | some (.num k) => return k
  | _ => return 256

def newMember (name : String) : SimM Nat := do
  let cap := capOf name
  let first := bytesOf (marshalMessageBoxIndex cap.messageBoxIndex)
  let chain := (List.range (walkLimit - 1)).foldl (fun (c : Array ByteArray) _ => c.push (step c.back!)) #[first]
  let m : Member := { name, cap, readCap := bytesOf (marshalReadCap cap.readCap), chain }
  let w ← get
  match w.members.findIdx? (·.name == name) with
  | some i => set { w with members := w.members.set! i m }; return i
  | none => set { w with members := w.members.push m }; return w.members.size

def member (name : String) : SimM Nat := do
  match (← get).members.findIdx? (·.name == name) with
  | some i => return i
  | none => newMember name

def existing (name : String) : SimM Nat := do
  match (← get).members.findIdx? (·.name == name) with
  | some i => return i
  | none => fail s!"no member {name}"

def mem (i : Nat) : SimM Member := return (← get).members[i]!

def setMem (i : Nat) (f : Member → Member) : SimM Unit :=
  modify fun w => { w with members := w.members.modify i f }

def groupOf (i : Nat) : SimM Group := do
  match (← mem i).group with
  | some g => return g
  | none => fail s!"{(← mem i).name} has not joined"

/-- Run a member's step on `i`'s group. -/
def onGroup {α : Type} (i : Nat) (x : GM α) : SimM α := do
  let (a, g) := x.run (← groupOf i)
  setMem i fun m => { m with group := some g }
  return a

def byKey (k : Key) : SimM (Option Nat) := return (← get).members.findIdx? (·.key == k)

def nameOf (k : Option Key) : SimM String := do
  match k with
  | some k =>
    if "retired".toUTF8.data.toList.isPrefixOf k.data.toList then return "removed"
    match ← byKey k with
    | some i => return (← mem i).name
    | none => return "?"
  | none => return "?"

/-- `name@n`: the `n`th box of its stream. -/
def atIndex (k : Key) (index : ByteArray) : SimM String := do
  let some i ← byKey k | fail "no member with that key"
  let m ← mem i
  return s!"{m.name}@{(m.ordinalOf index).map toString |>.getD "None"}"

def atIdx64 (k : Key) (idx64 : Nat) : SimM String := do
  let some i ← byKey k | fail "no member with that key"
  let m ← mem i
  return s!"{m.name}@{(m.ordinalAt idx64).map toString |>.getD "None"}"

/-- Which stream's box an `Idx64` names. -/
def whereIdx64 (idx64 : Nat) : SimM String := do
  for m in (← get).members do
    if let some n := m.ordinalAt idx64 then return s!"{m.name}@{n}"
  return "?"

/-- Who has a key starting with `prefix`: the truth. -/
def prefixed (pre : ByteArray) : SimM String := do
  let names := (← get).members.toList.filter (pre.data.toList.isPrefixOf ·.key.data.toList)
  return match names with
    | [m] => m.name
    | _ => "?"

/-- Who the `Introduction` in the box `index` introduced: the truth, from its introducer's
records. -/
def introduced (index : Index) : SimM String := do
  for m in (← get).members do
    let some g := m.group | continue
    let some r := g.sent.records.get? (counter index) | continue
    if r.index == index then
      if let some (.message msg) := r.plaintext then
        if let some intro := msg.introduction then return intro.name
  return "?"

def showMsg (msg : Message) : SimM String := do
  let mut parts : Array String := #[]
  if let some c := msg.content then parts := parts.push s!"\"{String.fromUTF8! c}\""
  if let some i := msg.introduction then parts := parts.push s!"introduces {i.name}"
  if let some r := msg.introducedAt then parts := parts.push s!"introduced-at {← introduced r.index}"
  if !msg.numbers.isEmpty then
    let ns ← msg.numbers.mapM fun (n, ref) => do
      let who ← match msg.introduction, ref with
        | some i, none => pure i.name
        | _, some r => if r.size == 0 then pure "?" else prefixed r
        | none, none => pure "?"
      return s!"{n}:{who}"
    parts := parts.push ("numbers " ++ " ".intercalate ns)
  if !msg.acks.isEmpty then
    let sorted := msg.acks.mergeSort (fun a b => a.1 ≤ b.1)
    let acks ← sorted.mapM fun (at_, v) => return s!"{at_}:{← whereIdx64 v}"
    parts := parts.push ("acks " ++ " ".intercalate acks)
  return if parts.isEmpty then "(empty)" else " ".intercalate parts.toList

inductive Fetched
  | data (m : Message)
  | tombstone
  | notFound

def Fetched.value : Fetched → String
  | .tombstone => "tombstone"
  | _ => "not found"

def fetch (index : ByteArray) : SimM (Fetched × Option ByteArray) := do
  match (← get).replica.read index with
  | none => return (.notFound, none)
  | some none => return (.tombstone, some (step index))
  | some (some m) => return (.data m, some (step index))

def store (index : ByteArray) (box : Stored) : SimM String := do
  let (r, result) := (← get).replica.write index box
  modify fun w => { w with replica := r }
  return result

def storeOk (index : ByteArray) (box : Stored) : SimM Unit := do
  let result ← store index box
  unless result == "stored" || result == "same" do fail s!"a write was {result}"

def showRead (i : Nat) (stream : Key) (index : ByteArray) (result : Fetched) (recheck : Bool) :
    SimM (List String) := do
  let where_ ← atIndex stream index
  match result with
  | .data msg =>
    setMem i fun m => { m with seen := m.seen.filter (fun e => e.1 != (stream, index)) ++ [((stream, index), msg)] }
    return [s!"{where_} {← showMsg msg}"]
  | other =>
    if recheck then return [s!"{where_} recheck: {other.value}"]
    let mut lines := [s!"{where_} {other.value}"]
    let some o ← byKey stream | return lines
    let here := (← mem o).ordinalOf index
    if let (.notFound, some here) := (other, here) then
      for (by_, heard) in ((← groupOf i).ledger.heard.getD stream {}).pairs do
        if let some there := (← mem o).ordinalAt heard then
          if there ≥ here then
            lines := lines ++ [s!"  stuck: {← nameOf (some by_)} acked {← atIdx64 stream heard}"]
    return lines

def resultOf : Fetched → ReadResult
  | .data m => .data (some m)
  | .tombstone => .missing .tombstone
  | .notFound => .missing .notFound

def makePassive (i : Nat) : SimM Unit := do
  if ← flag "passive" then
    let first := bytesOf (marshalMessageBoxIndex (← mem i).cap.messageBoxIndex)
    setMem i fun m => { m with passive := true, nextOwn := first }

def join (i : Nat) (reply : JoinReply) : SimM (List String) := do
  let m ← mem i
  if m.group.isSome then return [s!"{m.name} already joined"]
  let g := Group.joined m.readCap reply (← policy) (← recheck)
  let (_, g) := (Group.handle (.epochChanged (← get).replica.epoch)).run g
  setMem i fun m => { m with group := some g }
  makePassive i
  return []

/-- Hand `event` to member `i` and carry out its effects, depth first, until there are none
left. -/
partial def drive (i : Nat) (event : Event) : SimM (List String) := do
  let mut out : List String := []
  let mut pending ← onGroup i (Group.handle event)
  while !pending.isEmpty do
    let effect := pending.head!
    pending := pending.tail
    let mut follow : Option Event := none
    match effect with
    | .writeBox index payload =>
      match payload with
      | .message msg => storeOk index (some msg)
      | .bytes _ => fail "a member asked to write bytes it was never given"
    | .writeTombstone index => storeOk index none
    | .readBox stream _ index recheck =>
      let (result, next) ← fetch index
      out := out ++ (← showRead i stream index result recheck)
      follow := some (.boxRead stream index (resultOf result) next)
    | .deriveIndexes stream start count =>
      let indexes := (List.range (max count 1)).foldl (fun (acc : List ByteArray) _ =>
        acc ++ [step (acc.getLastD start)]) []
      follow := some (.indexesDerived stream indexes)
    | .walk stream start targets keep =>
      let (target, skipped, steps) := Id.run (walkWith (fun b => pure (step b)) start targets keep)
      follow := some (.walked stream target skipped steps)
    | .deliver sender index content =>
      setMem i fun m => { m with inbox := m.inbox.push (sender, index, String.fromUTF8! content) }
    | .expire sender index =>
      setMem i fun m => { m with inbox := m.inbox.filter fun (s, x, _) => !(s == sender && x == index) }
    | .sendJoinReply dest reply =>
      let some n ← byKey (keyOf dest) | fail "a join reply to no member"
      out := out ++ (← join n reply)
    if let some e := follow then
      pending := (← onGroup i (Group.handle e)) ++ pending
  return out

/-- Write what member `i` has composed, in order, as a client's own write queue would. -/
def land (i : Nat) : SimM Unit := do
  for o in (← mem i).unwritten do
    let at_ := (← mem i).nextOwn
    storeOk at_ (some o.message)
    onGroup i (Group.written o.token at_ (some (.message o.message)))
    setMem i fun m => { m with nextOwn := step at_ }
  setMem i fun m => { m with unwritten := [] }

def queue (i : Nat) (outgoing : List Outgoing) : SimM Unit := do
  setMem i fun m => { m with unwritten := m.unwritten ++ outgoing }
  unless ← flag "delay_writes" do land i

/-- What member `i` has written since a command last printed it. -/
def written (i : Nat) : SimM (List String) := do
  let g ← groupOf i
  let records := g.sent.records.pairs.mergeSort (fun a b => a.1 ≤ b.1)
  let mut lines := []
  for (idx64, r) in records do
    if (idx64 : Int) > (← mem i).reported then
      if let some (.message msg) := r.plaintext then
        lines := lines ++ [s!"{← atIndex (← mem i).key r.index} {← showMsg msg}"]
        setMem i fun m => { m with reported := idx64 }
  return lines

def readPassively (i owner : Nat) : SimM (List String) := do
  let g ← groupOf i
  let o ← mem owner
  let some reader := g.readers.get? o.key | return []
  let mut cursor := ((← mem i).cursors.get? o.key).getD reader.next
  let mut out := []
  repeat
    let (result, next) ← fetch cursor
    out := out ++ (← showRead i o.key cursor result false)
    let some next := next | break
    let msg := match result with | .data m => some m | _ => none
    let effects ← onGroup i (Group.observe o.key cursor msg next)
    for e in effects do
      if let .deliver sender index content := e then
        setMem i fun m => { m with inbox := m.inbox.push (sender, index, String.fromUTF8! content) }
    cursor := next
  setMem i fun m => { m with cursors := m.cursors.set o.key cursor }
  return out

partial def invite (who new : String) : SimM (List String) := do
  let i ← existing who
  if (← mem i).passive then
    land i
    queue i (← onGroup i Group.beginInduction)
    land i
    return ← written i
  let n ← member new
  let out ← drive i (.invite new (← mem n).readCap)
  return out ++ (← written i)

def introduce (who new : String) : SimM (List String) := do
  let i ← existing who
  if (← mem i).passive then
    if (← groupOf i).ledger.induction != .inducting then discard <| invite who new
    let reply := (← groupOf i).reply (← mem i).nextOwn
    let n ← member new
    let o ← onGroup i (Group.introduceNow new (← mem n).readCap)
    queue i [o]
    land i
    let out ← join n reply
    return out ++ (← written i)
  let n ← member new
  let out ← drive i (.introduce new (← mem n).readCap)
  return out ++ (← written i)

def joinedNames : SimM (List String) :=
  return ((← get).members.toList.filter (·.group.isSome)).map (·.name) |>.mergeSort (· ≤ ·)

def backfill (who : String) : SimM (List String) := do
  drive (← existing who) (.epochChanged (← get).replica.epoch)

def bytesLe (a b : ByteArray) : Bool := !bytesLt b.data.toList a.data.toList

def command (words : List String) : SimM (List String) := do
  match words with
  | ["option", o, v] =>
    unless (← get).members.isEmpty do fail "set options before new-group"
    let value := if v == "on" then Opt.flag true else if v == "off" then .flag false
      else if v == "none" then .nothing else .num v.toNat!
    modify fun w => { w with options := (o.replace "-" "_", value) :: w.options }
    return []
  | "new-group" :: names =>
    let founders ← names.mapM newMember
    let caps ← founders.mapM fun i => return (← mem i).readCap
    let p ← policy
    let r ← recheck
    for i in founders do
      setMem i fun m => { m with group := some (Group.found m.readCap caps p r) }
      makePassive i
    return []
  | "send" :: who :: text =>
    let i ← existing who
    let content := (" ".intercalate text).toUTF8
    if (← mem i).passive then
      queue i (← onGroup i (Group.compose (some content)))
      return ← written i
    let out ← drive i (.send content)
    return out ++ (← written i)
  | ["invite", who, new] => invite who new
  | ["introduce", who, new] => introduce who new
  | ["land", who] => land (← existing who); return []
  | ["abandon", who] =>
    let i ← existing who
    let pending := (← mem i).unwritten
    let control (msg : Message) := msg.introduction.isSome || !msg.numbers.isEmpty || msg.introducedAt.isSome
    match pending.reverse.find? (!control ·.message) with
    | some o =>
      setMem i fun m => { m with unwritten := m.unwritten.filter (·.token != o.token) }
      onGroup i (Group.abandoned o.token)
    | none => pure ()
    return []
  | ["remove", who, gone] => drive (← existing who) (.remove (← mem (← existing gone)).key)
  | ["read", who, owner] =>
    let i ← existing who
    if (← mem i).passive then return ← readPassively i (← existing owner)
    drive i (.read (← mem (← existing owner)).key)
  | ["scan", who, owner] =>
    let i ← existing who
    if (← mem i).passive then return ← readPassively i (← existing owner)
    drive i (.scan (← mem (← existing owner)).key)
  | "epoch" :: n =>
    for _ in List.range ((n.headD "1").toNat!) do
      modify fun w => { w with replica := w.replica.advance }
    return []
  | ["backfill", who] => backfill who
  | "tick" :: n =>
    let mut out := []
    for _ in List.range ((n.headD "1").toNat!) do
      modify fun w => { w with replica := w.replica.advance }
      for name in ← joinedNames do out := out ++ (← backfill name)
    return out
  | ["roster", who, owner] =>
    let known := (← groupOf (← existing who)).rosters.known (← mem (← existing owner)).key
    let some top := (known.map (·.1)).max? | return ["unknown"]
    let names ← (List.range (top + 1)).mapM fun n => nameOf ((known.lookup n).join)
    return [" ".intercalate names]
  | ["acks", who, owner, n] =>
    let sender ← mem (← existing owner)
    let some msg := (← mem (← existing who)).seen.lookup (sender.key, sender.chain[n.toNat!]!)
      | return ["not read"]
    let rosters := (← groupOf (← existing who)).rosters
    let sorted := msg.acks.mergeSort (fun a b => a.1 ≤ b.1)
    let parts ← sorted.mapM fun (at_, v) => do
      return s!"{← nameOf (rosters.resolve sender.key at_)}={← whereIdx64 v}"
    return [if parts.isEmpty then "none" else " ".intercalate parts]
  | ["acked", who] =>
    let i ← existing who
    let g ← groupOf i
    let sorted := g.ledger.ackedBy.pairs.mergeSort (fun a b => bytesLe a.1 b.1)
    let parts ← sorted.filterMapM fun (acker, idx64) => do
      match g.sent.records.get? idx64 with
      | some r => return some s!"{← nameOf (some acker)}:{← atIndex (← mem i).key r.index}"
      | none => return none
    return [if parts.isEmpty then "none" else " ".intercalate parts]
  | ["inbox", who] =>
    let lines ← (← mem (← existing who)).inbox.toList.mapM fun (s, x, text) => do
      return s!"{← atIndex s x} \"{text}\""
    return if lines.isEmpty then ["empty"] else lines
  | ["peek", owner, n] =>
    let o ← mem (← existing owner)
    match (← fetch o.chain[n.toNat!]!).1 with
    | .data msg => return [← showMsg msg]
    | other => return [other.value]
  | _ => fail s!"unknown command {" ".intercalate words}"

/-- A scenario with every checked command's output replaced by what it printed now. -/
def run (script : String) : IO String := do
  let lines := (script.splitOn "\n").toArray
  let lines := if lines.back? == some "" then lines.pop else lines
  let (out, _) ← (do
    let mut out : Array String := #[]
    let mut i := 0
    while i < lines.size do
      let line := lines[i]!
      out := out.push line
      i := i + 1
      let cmd := ((line.splitOn "#").headD "").trimAscii.toString
      if cmd.isEmpty then continue
      let printed ← command ((cmd.splitOn " ").filter (· ≠ ""))
      if i < lines.size && lines[i]! == "----" then
        out := out.push "----"
        i := i + 1
        while i < lines.size && !lines[i]!.trimAscii.isEmpty do i := i + 1
        out := out ++ printed.toArray
    return out : SimM (Array String)).run {}
  return "\n".intercalate out.toList ++ "\n"

end Scenarios

def scenarioFiles (args : List String) : IO (List System.FilePath) := do
  let args := if args.isEmpty then ["testdata/groupchat_scenarios"] else args
  let mut files := []
  for a in args do
    let p : System.FilePath := a
    if ← p.isDir then
      let entries := ((← p.readDir).map (·.path)).filter (·.extension == some "txt")
      files := files ++ (entries.qsort (·.toString < ·.toString)).toList
    else files := files ++ [p]
  return files

def main (args : List String) : IO UInt32 := do
  let rewrite := args.contains "--rewrite"
  let mut failed := 0
  let files ← scenarioFiles (args.filter (· != "--rewrite"))
  for path in files do
    let script ← IO.FS.readFile path
    let result ← (Scenarios.run script).toBaseIO
    match result with
    | .error e =>
      failed := failed + 1
      IO.println s!"FAIL {path}: {e}"
    | .ok actual =>
      if rewrite then IO.FS.writeFile path actual
      if actual == script || rewrite then IO.println s!"ok   {path}"
      else
        failed := failed + 1
        let a := actual.splitOn "\n"
        let e := script.splitOn "\n"
        match (a.zip e).zipIdx.find? (fun ((x, y), _) => x != y) with
        | some ((x, y), n) => IO.println s!"FAIL {path}: line {n + 1}: expected {repr y}, got {repr x}"
        | none => IO.println s!"FAIL {path}: the lengths differ"
  IO.println s!"{files.length - failed} of {files.length} scenarios print what katzenqt prints"
  return if failed == 0 then 0 else 1
