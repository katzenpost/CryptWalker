/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Protocols.Sphinx.Constants

/-! # Sphinx packet format constants

Scheme-dependent lengths are computed in `geometry.lean`. -/

def nodeIDLength : Nat := 32

def recipientIDLength : Nat := 32

def surbIDLength : Nat := 16

/-- The one-byte tag every routing command starts with. -/
def commandTagLength : Nat := 1

/-- HMAC-SHA256 tag width. -/
def macLength : Nat := 32

/-- AES-256-CTR IV width. -/
def streamIVLength : Nat := 16

/-- AEZ key and nonce widths. -/
def sprpKeyLength : Nat := 48
def sprpIVLength : Nat := streamIVLength

/-- `1 (tag) + nodeIDLength + macLength`. -/
def nextNodeHopLength : Nat := commandTagLength + nodeIDLength + macLength

/-- `1 (tag) + surbIDLength`. -/
def surbReplyLength : Nat := commandTagLength + surbIDLength

/-- The two-byte version prefix on every header. -/
def adLength : Nat := 2

/-- Width of the all-zero tag a correctly decrypted payload ends in. -/
def payloadTagLength : Nat := 32

def sphinxPlaintextHeaderLength : Nat := 2

/-- One SPRP key plus IV. -/
def sprpKeyMaterialLength : Nat := sprpKeyLength + sprpIVLength

end CryptWalker.Protocols.Sphinx.Constants
