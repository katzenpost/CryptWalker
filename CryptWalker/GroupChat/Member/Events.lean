/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.GroupChat.Member.Wire

/-! # What a driver tells a member, and what the member asks the driver to do

katzenqt's `groupchat/events.py`. Effects map onto thin client calls: a member never derives a
BACAP index, encrypts, or touches the network itself. -/

namespace CryptWalker.GroupChat.Member

inductive Missing | tombstone | notFound
  deriving DecidableEq, Inhabited

/-- What reading a box found: a message, `none` for one that holds nothing a member can decode,
or why there is none. -/
inductive ReadResult
  | data (message : Option Message)
  | missing (why : Missing)
  deriving DecidableEq, Inhabited

/-- What an introducer hands a new member. Members are named by their place in `members`, the
introducer's roster; the new member takes place `newcomer`. -/
structure JoinReply where
  /-- Each member's read cap and start index, or `none` for a slot not filled. -/
  members : List (Option (ByteArray × Index))
  /-- Each member's roster as (index, place), or `none` when unknown. -/
  rosters : List (Option (List (Nat × Option Nat)))
  /-- (introducer place, box, member place). -/
  introductions : List (Nat × Index × Nat)
  introducer : Nat
  newcomer : Nat
  deriving DecidableEq, Inhabited

inductive Event
  | send (content : ByteArray)
  | read (stream : Key)
  | scan (stream : Key)
  /-- The result of `Effect.readBox`, with the index after it. -/
  | boxRead (stream : Key) (index : Index) (result : ReadResult) (next : Option Index)
  | indexesDerived (stream : Key) (indexes : List Index)
  /-- The result of `Effect.walk`: the furthest target met, the indexes passed on the way (the
  last `keep` of them), and how many steps it took. -/
  | walked (stream : Key) (target : Option Index) (skipped : List Index) (steps : Nat)
  | invite (name : String) (readCap : ByteArray)
  | introduce (name : String) (readCap : ByteArray)
  | remove (member : Key)
  | epochChanged (epoch : Nat)
  deriving DecidableEq, Inhabited

/-- What a box of the member's own stream holds, as its Sent box keeps it: a message the member
composed, which its client encodes, or the bytes a client that writes for itself handed over,
which the member never looks into. -/
inductive Payload
  | message (message : Message)
  | bytes (bytes : ByteArray)
  deriving DecidableEq, Inhabited

inductive Effect
  | writeBox (index : Index) (payload : Payload)
  | writeTombstone (index : Index)
  | readBox (stream : Key) (readCap : ByteArray) (index : Index) (recheck : Bool)
  | deriveIndexes (stream : Key) (start : Index) (count : Nat)
  | walk (stream : Key) (start : Index) (targets : List Index) (keep : Nat)
  | deliver (sender : Key) (index : Index) (content : ByteArray)
  | expire (sender : Key) (index : Index)
  | sendJoinReply (to : ByteArray) (reply : JoinReply)
  deriving DecidableEq, Inhabited

end CryptWalker.GroupChat.Member
