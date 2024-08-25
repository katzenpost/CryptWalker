/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

-- Security preserving KEM combiner

import CryptWalker.kem.kem
namespace CryptWalker.kem.combiner
open CryptWalker.kem.kem

structure PrivateKey where
  data : ByteArray

structure PublicKey where
  data : ByteArray

instance : kem.Key PrivateKey where
  encode : PrivateKey → ByteArray := fun (key : PrivateKey) => key.data
  decode : ByteArray → Option PrivateKey := fun (bytes : ByteArray) => some (PrivateKey.mk bytes)

instance : kem.Key PublicKey where
  encode : PublicKey → ByteArray := fun (key : PublicKey) => key.data
  decode : ByteArray → Option PublicKey := fun (bytes : ByteArray) => some (PublicKey.mk bytes)






end CryptWalker.kem.combiner
