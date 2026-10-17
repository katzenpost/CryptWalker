/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Hash.Sha2
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Wire

/-! # The membership hash

What a message's `membership_hash` says of its sender's view of the group, as katzenqt's
`canonical_membership_hash` computes it: SHA-256, under a domain, of the members' keys, each once,
in byte order. A member counts itself as `write_cap[32:]`. Hashing keys rather than whole read caps
makes every read cap of one member count once. -/

namespace Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member

def membershipDomain : List UInt8 := "KP:membership:v1".toUTF8.data.toList

/-- The keys of `readCaps`, each once, in byte order. -/
def memberKeys (readCaps : List ByteArray) : List (List UInt8) :=
  ((readCaps.map fun c => (keyOf c).data.toList).eraseDups).mergeSort fun a b => !bytesLt b a

def membershipHash (readCaps : List ByteArray) : ByteArray :=
  (Cryptlib.Primitives.Hash.Sha2.Sha256.hash ⟨(membershipDomain ++ (memberKeys readCaps).flatten).toArray⟩).val

end Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member
