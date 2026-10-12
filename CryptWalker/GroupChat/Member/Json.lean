/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json

import CryptWalker.GroupChat.Member.Group
import CryptWalker.Util.newhex

/-! # A member as katzenqt's traces write it

katzenqt's `groupchat/trace.py` writes one JSON line per call made on a member: the call, its
arguments, what it returned, and the member's state afterwards, in the shape
`groupchat/state.py` keeps it. Messages are decoded, bytes are hex, a map is a list of pairs in
its order. This file reads arguments and writes results and state in exactly that shape, so the
replay can compare them. -/

namespace CryptWalker.GroupChat.Member.Trace

open Lean
open CryptWalker.Util.newhex

/-! ## Writing -/

def hex (b : ByteArray) : Json := .str (byteArrayToHex b)
def arr (l : List Json) : Json := .arr l.toArray
def opt {α : Type} (f : α → Json) : Option α → Json
  | some a => f a
  | none => .null
def nat (n : Nat) : Json := toJson n
def pairs {K V : Type} (fk : K → Json) (fv : V → Json) (d : Dict K V) : Json :=
  arr (d.pairs.map fun (k, v) => arr [fk k, fv v])

def introRef (r : IntroRef) : Json := arr [nat r.introducer, hex r.index]

def message (m : Message) : Json := Json.mkObj [
  ("content", opt hex m.content),
  ("introduction", opt (fun i => Json.mkObj [("name", .str i.name), ("read_cap", hex i.readCap)])
    m.introduction),
  ("numbers", arr (m.numbers.map fun (k, p) => arr [nat k, opt hex p])),
  ("introduced_at", opt introRef m.introducedAt),
  ("acks", arr (m.acks.map fun (i, v) => arr [nat i, hex v]))]

def joinReply (r : JoinReply) : Json := Json.mkObj [
  ("type", "JoinReply"),
  ("members", arr (r.members.map (opt fun (rc, s) => arr [hex rc, hex s]))),
  ("rosters", arr (r.rosters.map (opt fun l => arr (l.map fun (i, p) => arr [nat i, opt nat p])))),
  ("introductions", arr (r.introductions.map fun (b, i, m) => arr [nat b, hex i, nat m])),
  ("introducer", nat r.introducer),
  ("newcomer", nat r.newcomer)]

def effect : Effect → Json
  | .writeBox i m => Json.mkObj [("type", "WriteBox"), ("index", hex i), ("message", message m)]
  | .writeTombstone i => Json.mkObj [("type", "WriteTombstone"), ("index", hex i)]
  | .readBox s rc i r => Json.mkObj [("type", "ReadBox"), ("stream", hex s), ("read_cap", hex rc),
      ("index", hex i), ("recheck", toJson r)]
  | .deriveIndexes s st c => Json.mkObj [("type", "DeriveIndexes"), ("stream", hex s),
      ("start", hex st), ("count", nat c)]
  | .walk s st ts k => Json.mkObj [("type", "Walk"), ("stream", hex s), ("start", hex st),
      ("targets", arr (ts.map hex)), ("keep", nat k)]
  | .deliver s i c => Json.mkObj [("type", "Deliver"), ("sender", hex s), ("index", hex i),
      ("content", hex c)]
  | .expire s i => Json.mkObj [("type", "Expire"), ("sender", hex s), ("index", hex i)]
  | .sendJoinReply t r => Json.mkObj [("type", "SendJoinReply"), ("to", hex t), ("reply", joinReply r)]

def outgoing (o : Outgoing) : Json :=
  Json.mkObj [("type", "Outgoing"), ("token", nat o.token), ("message", message o.message)]

def mode : Mode → Json
  | .idle => "idle"
  | .reading => "reading"
  | .scanning => "scanning"

def induction : Induction → Json
  | .idle => "idle"
  | .catchingUp => "catching up"
  | .inducting => "inducting"

def at_ (a : At) : Json := arr [hex a.1, hex a.2]

def reader (r : Reader) : Json := Json.mkObj [
  ("stream", hex r.stream), ("read_cap", hex r.readCap), ("next", hex r.next),
  ("last", opt hex r.last), ("passed", nat r.passed),
  ("kept", arr (r.kept.map fun (i, a, b) => arr [hex i, nat a, opt hex b])),
  ("lost", opt (fun (a, b) => arr [nat a, opt hex b]) r.lost),
  ("mode", mode r.mode), ("tried", arr (r.tried.map hex))]

def rosters (r : Rosters) : Json := Json.mkObj [
  ("entries", pairs hex (pairs nat fun e => Json.mkObj [("key", opt hex e.key),
    ("prefix", opt hex e.prefix_)]) r.entries),
  ("started", pairs hex (fun (k, n) => arr [hex k, nat n]) r.started),
  ("introductions", pairs at_ hex r.introductions),
  ("keys", arr (r.keys.map hex))]

def retention (p : Retention) : Json := Json.mkObj [
  ("window", nat p.window), ("discard_acked", toJson p.discardAcked),
  ("keep_sent", opt nat p.keepSent), ("keep_received", opt nat p.keepReceived)]

def sentBox (s : SentBox) : Json := Json.mkObj [
  ("records", pairs hex (fun r => Json.mkObj [("seq", nat r.seq), ("plaintext", opt message r.plaintext),
    ("control", toJson r.control), ("written", nat r.written)]) s.records),
  ("count", nat s.count),
  ("backfilled", match s.backfilled with
    | some e => nat e
    | none => toJson (-1 : Int))]

def ledger (l : Ledger) : Json := Json.mkObj [
  ("published", pairs hex hex l.published), ("acked_by", pairs hex nat l.ackedBy),
  ("heard", pairs hex (pairs hex hex) l.heard), ("induction", induction l.induction),
  ("invitee", opt (fun (n, rc) => arr [.str n, hex rc]) l.invitee), ("commit", toJson l.commit),
  ("starts", pairs hex hex l.starts)]

def pending (p : Pending) : Json := Json.mkObj [
  ("numbers", arr (p.numbers.map fun (n, a) => arr [nat n, opt at_ a])),
  ("introduced", opt hex p.introduced),
  ("acks", pairs hex (fun (b, v) => arr [opt hex b, hex v]) p.acks),
  ("control", toJson p.control)]

def group (g : Group) : Json := Json.mkObj [
  ("read_cap", hex g.readCap), ("policy", retention g.policy), ("recheck", nat g.recheck),
  ("rosters", rosters g.rosters), ("readers", pairs hex reader g.readers),
  ("sent", sentBox g.sent), ("ledger", ledger g.ledger), ("epoch", nat g.epoch),
  ("pool", arr (g.pool.map hex)), ("tip", hex g.tip), ("deriving", toJson g.deriving_),
  ("outbox", arr (g.outbox.map hex)), ("pending", pairs nat pending g.pending),
  ("tokens", nat g.tokens), ("unnumbered", arr (g.unnumbered.map at_)),
  ("introduced_at", opt (fun r => Json.mkObj [("introducer", nat r.introducer), ("index", hex r.index)])
    g.introducedAt),
  ("joined_through", opt hex g.joinedThrough), ("awaiting_start", pairs hex hex g.awaitingStart),
  ("received", pairs at_ nat g.received)]

/-! ## Reading -/

abbrev Parse := Except String

def field (j : Json) (k : String) : Parse Json := j.getObjVal? k

def bytes (j : Json) : Parse ByteArray := do
  let s ← j.getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none => throw s!"not hex: {s}"

def optional {α : Type} (f : Json → Parse α) : Json → Parse (Option α)
  | .null => pure none
  | j => some <$> f j

def list {α : Type} (f : Json → Parse α) (j : Json) : Parse (List α) := do
  (← j.getArr?).toList.mapM f

def pair {α β : Type} (f : Json → Parse α) (g : Json → Parse β) (j : Json) : Parse (α × β) := do
  match (← j.getArr?).toList with
  | [a, b] => pure (← f a, ← g b)
  | _ => throw s!"not a pair: {j.compress}"

def triple {α β γ : Type} (f : Json → Parse α) (g : Json → Parse β) (h : Json → Parse γ) (j : Json) :
    Parse (α × β × γ) := do
  match (← j.getArr?).toList with
  | [a, b, c] => pure (← f a, ← g b, ← h c)
  | _ => throw s!"not a triple: {j.compress}"

def num (j : Json) : Parse Nat := j.getNat?

def readIntroRef (j : Json) : Parse IntroRef := do
  let (i, b) ← pair num bytes j
  pure ⟨i, b⟩

def readMessage (j : Json) : Parse Message := do
  pure {
    content := ← optional bytes (← field j "content")
    introduction := ← optional (fun i => do
      pure ⟨← (← field i "name").getStr?, ← bytes (← field i "read_cap")⟩) (← field j "introduction")
    numbers := ← list (pair num (optional bytes)) (← field j "numbers")
    introducedAt := ← optional readIntroRef (← field j "introduced_at")
    acks := ← list (pair num bytes) (← field j "acks") }

def readJoinReply (j : Json) : Parse JoinReply := do
  pure {
    members := ← list (optional (pair bytes bytes)) (← field j "members")
    rosters := ← list (optional (list (pair num (optional num)))) (← field j "rosters")
    introductions := ← list (triple num bytes num) (← field j "introductions")
    introducer := ← num (← field j "introducer")
    newcomer := ← num (← field j "newcomer") }

def readRetention (j : Json) : Parse Retention := do
  pure {
    window := ← num (← field j "window")
    discardAcked := ← (← field j "discard_acked").getBool?
    keepSent := ← optional num (← field j "keep_sent")
    keepReceived := ← optional num (← field j "keep_received") }

def readResult : Json → Parse ReadResult
  | .str "not found" => pure (.missing .notFound)
  | .str "tombstone" => pure (.missing .tombstone)
  | j => do pure (.data (← optional readMessage (← field j "data")))

def readEvent (j : Json) : Parse Event := do
  let str := fun k => do (← field j k).getStr?
  let by_ := fun k => do bytes (← field j k)
  match ← str "type" with
  | "Send" => pure (.send (← by_ "content"))
  | "Read" => pure (.read (← by_ "stream"))
  | "Scan" => pure (.scan (← by_ "stream"))
  | "BoxRead" => pure (.boxRead (← by_ "stream") (← by_ "index") (← readResult (← field j "result"))
      (← optional bytes (← field j "next_index")))
  | "IndexesDerived" => pure (.indexesDerived (← by_ "stream") (← list bytes (← field j "indexes")))
  | "Walked" => pure (.walked (← by_ "stream") (← optional bytes (← field j "target"))
      (← list bytes (← field j "skipped")) (← num (← field j "steps")))
  | "Invite" => pure (.invite (← str "name") (← by_ "read_cap"))
  | "Introduce" => pure (.introduce (← str "name") (← by_ "read_cap"))
  | "Remove" => pure (.remove (← by_ "member"))
  | "EpochChanged" => pure (.epochChanged (← num (← field j "epoch")))
  | t => throw s!"unknown event {t}"

end CryptWalker.GroupChat.Member.Trace
