/-
SPDX-FileCopyrightText: © 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/
import Mathlib.Algebra.Field.Defs
import Mathlib.Algebra.Field.Basic
import Mathlib.Data.ZMod.Basic
import Mathlib.Data.ByteArray

import CryptWalker.Util.newnat
import CryptWalker.Util.newhex

open CryptWalker.Util.newhex

namespace CryptWalker.Sign.Ed25519

def p : ℕ := 2^255 - 19
def keySize : ℕ := 32

def fromField (x : ZMod p) : ByteArray :=
  let bytes := ByteArray.mk $ Array.mk $ (ByteArray.toList $ natToBytes x.val).reverse
  bytes ++ ByteArray.mk (Array.mk (List.replicate (keySize - bytes.size) 0))

def toField (ba : ByteArray) : ZMod p :=
  let n := (ByteArray.mk $ Array.mk ba.toList.reverse).foldl (fun acc b => acc * 256 + b.toNat) 0
  n

def basepoint : ZMod p := toField $ falliableHexStringToByteArray "5866666666666666666666666666666666666666666666666666666666666666"


end CryptWalker.Sign.Ed25519
