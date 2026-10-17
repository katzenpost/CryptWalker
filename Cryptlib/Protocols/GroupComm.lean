/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # Group communication protocols

Each protocol lives in `Cryptlib/Protocols/GroupComm/<name>/`, with its models, proofs and
tests, and is listed in `all`. What more than one protocol uses lives in `Common/`. A protocol
depends on `Common` and on the rest of Cryptlib, never on another protocol. A name says where
the protocol comes from, and a number tells apart the versions of it. -/

namespace Cryptlib.Protocols.GroupComm

structure Info where
  /-- The protocol's directory under `Cryptlib/Protocols/GroupComm/`. -/
  name : String
  /-- Where the protocol is defined. -/
  origin : String
  summary : String

def groupChatKatzenqt1 : Info where
  name := "GroupChatKatzenqt1"
  origin := "katzenqt, src/katzenqt/groupchat (https://github.com/katzenpost/katzenqt)"
  summary := "Group chat over Pigeonhole: each member writes its own BACAP stream and reads \
    every other member's, with opportunistic acknowledgements, rosters, Sent-box backfill, and \
    joining through a contact voucher"

def all : List Info := [groupChatKatzenqt1]

end Cryptlib.Protocols.GroupComm
