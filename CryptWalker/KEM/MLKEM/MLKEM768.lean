/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.MLKEM.MLKEM

/-! # ML-KEM-768: `FIPS203` at the `MLKEM768` parameter set -/

namespace CryptWalker.KEM.MLKEM768

open MLKEM

export CryptWalker.KEM.FIPS203 (vectorToByteArray byteArrayToVector hashG hashH ring seedBlock
  State nextDraw stateFromSeed dummySeed SeedPrivateKey)

abbrev ps : ParameterSet := .MLKEM768

abbrev params := FIPS203.params ps
abbrev encoding := FIPS203.encoding ps
abbrev primitives := FIPS203.primitives ps
abbrev encodingLaws := FIPS203.encodingLaws ps

abbrev tBytes := FIPS203.tBytes ps
abbrev bytesT := FIPS203.bytesT ps
abbrev uBytes := FIPS203.uBytes ps
abbrev bytesU := FIPS203.bytesU ps
abbrev vBytes := FIPS203.vBytes ps
abbrev bytesV := FIPS203.bytesV ps

abbrev PublicKey := FIPS203.PublicKey ps
abbrev PrivateKey := FIPS203.PrivateKey ps
abbrev CT := FIPS203.CT ps
abbrev encodePublicKey := FIPS203.encodePublicKey ps
abbrev decodePublicKey := FIPS203.decodePublicKey ps
abbrev encodePrivateKey := FIPS203.encodePrivateKey ps
abbrev decodePrivateKey := FIPS203.decodePrivateKey ps
abbrev encodeCiphertext := FIPS203.encodeCiphertext ps
abbrev decodeCiphertext := FIPS203.decodeCiphertext ps
abbrev decode_encode_pub := FIPS203.decode_encode_pub ps
abbrev decode_encode_priv := FIPS203.decode_encode_priv ps
abbrev decode_encode_ct := FIPS203.decode_encode_ct ps

abbrev keygen768 := FIPS203.keygen ps
abbrev encaps768 := FIPS203.encaps ps
abbrev decaps768 := FIPS203.decaps ps
abbrev keygen768_ek_wf := FIPS203.keygen_ek_wf ps
abbrev keygen768_dk_wf := FIPS203.keygen_dk_wf ps
abbrev checkEncapsulationKey := FIPS203.checkEncapsulationKey ps
abbrev checkDecapsulationKey := FIPS203.checkDecapsulationKey ps

abbrev Reliable := FIPS203.Reliable ps
abbrev encapM := FIPS203.encapM ps
abbrev decapM := FIPS203.decapM ps
abbrev derivePublicKeyM := FIPS203.derivePublicKeyM ps
abbrev honestRoundTripM := FIPS203.honestRoundTripM ps
abbrev decodePrivateKey_totalM := FIPS203.decodePrivateKey_totalM ps
abbrev dummyPk := FIPS203.dummyPk ps
abbrev dummySk := FIPS203.dummySk ps
abbrev dummyCt := FIPS203.dummyCt ps

abbrev derivePublicKeyFromSeed := FIPS203.derivePublicKeyFromSeed ps
abbrev expandSeed := FIPS203.expandSeed ps
abbrev decapMFromSeed := FIPS203.decapMFromSeed ps
abbrev honestRoundTripFromSeed := FIPS203.honestRoundTripFromSeed ps
abbrev encodePrivateKeyFromSeed := FIPS203.encodePrivateKeyFromSeed ps
abbrev decodePrivateKeyFromSeed := FIPS203.decodePrivateKeyFromSeed ps
abbrev decodePrivateKeyFromSeed_total := FIPS203.decodePrivateKeyFromSeed_total ps
abbrev decode_encode_privFromSeed := FIPS203.decode_encode_privFromSeed ps

/-- ML-KEM-768 with the FIPS 203 expanded private key. -/
abbrev kemMLKEM768 := FIPS203.kem ps

/-- ML-KEM-768 with the `ek ‖ d ‖ z` seed private key, wire-compatible with Go's `crypto/mlkem`. -/
abbrev kemMLKEM768Seed := FIPS203.kemSeed ps

end CryptWalker.KEM.MLKEM768
