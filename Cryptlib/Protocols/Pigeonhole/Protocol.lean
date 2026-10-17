/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Protocols.Pigeonhole.Replica
import Cryptlib.Primitives.MKEM.MKEM
import Cryptlib.Protocols.BACAP.Protocol

/-! # Pigeonhole client-replica exchange

A client MKEM-encrypts a request to the replicas; the courier hands each replica its own share;
the replica handles the request and seals its reply under the envelope's ephemeral key. Delivery
is assumed reliable; courier and replicas honest. -/

namespace Cryptlib.Protocols.Pigeonhole.Protocol

open Cryptlib.Primitives.Sign.Sign (Signature)
open Cryptlib.Primitives.MKEM.MKEM (MKEM MKEMError Ciphertext)
open Cryptlib.Protocols.Pigeonhole.Replica
open Cryptlib.Protocols.BACAP.Protocol (BACAPSpec)

/-- Request and reply codecs; decoding undoes encoding. -/
structure Wire (Sg : Signature) where
  reqEnc : Request Sg → ByteArray
  reqDec : ByteArray → Option (Request Sg)
  replyEnc : Reply Sg → ByteArray
  replyDec : ByteArray → Option (Reply Sg)
  reqDec_reqEnc : ∀ r, reqDec (reqEnc r) = some r
  replyDec_replyEnc : ∀ r, replyDec (replyEnc r) = some r

/-- Why an exchange did not complete. -/
inductive RpcError where
  | mkem (e : MKEMError)
  | badRequest
  | badReply

variable {Sg : Signature} [DecidableEq Sg.PublicKey] (M : MKEM) (W : Wire Sg)

/-- One exchange with replica `i`, holding `skj`. `cs`, `rs` are client and replica randomness.
Returns the replica's new store and the reply the client sees. -/
def rpc (boxSize : Nat) (cs rs : M.State) (pubs : List {pk : M.PublicKey // M.Safe pk})
    (i : Nat) (skj : M.PrivateKey) (store : Store Sg) (req : Request Sg) :
    Except RpcError (Store Sg × Reply Sg) :=
  match M.encapsulate pubs (W.reqEnc req) cs with
  | .error e _ => .error (.mkem e)
  | .ok (eph, ct) _ =>
    match M.decapsulate skj (ct.forRecipient i) with
    | .error e => .error (.mkem e)
    | .ok plaintext =>
      match W.reqDec plaintext with
      | none => .error .badRequest
      | some req' =>
        if h : M.Safe ct.ephPub then
          match M.envelopeReply skj ⟨ct.ephPub, h⟩ (W.replyEnc (step boxSize store req').2) rs with
          | .error e _ => .error (.mkem e)
          | .ok env _ =>
            match M.decryptEnvelope eph ⟨M.derivePublicKey skj, M.derive_safe skj⟩ env with
            | .error e => .error (.mkem e)
            | .ok bytes =>
              match W.replyDec bytes with
              | none => .error .badReply
              | some reply' => .ok ((step boxSize store req').1, reply')
        else .error (.mkem .unsafePublicKey)

/-- If the exchange completes, the client gets exactly what the replica computed. -/
theorem rpc_sound (boxSize : Nat) (cs rs : M.State) (pubs : List {pk : M.PublicKey // M.Safe pk})
    (i : Nat) (hi : i < pubs.length) (skj : M.PrivateKey)
    (hsk : pubs[i] = ⟨M.derivePublicKey skj, M.derive_safe skj⟩)
    (store : Store Sg) (req : Request Sg) (r : Store Sg × Reply Sg)
    (h : rpc M W boxSize cs rs pubs i skj store req = .ok r) :
    r = step boxSize store req := by
  unfold rpc at h
  cases hE : M.encapsulate pubs (W.reqEnc req) cs with
  | error e s' => rw [hE] at h; cases h
  | ok res s' =>
    obtain ⟨eph, ct⟩ := res
    rw [hE] at h
    have hdec := M.decapsulate_encapsulate pubs (W.reqEnc req) cs eph ct s' hE i hi skj hsk
    have hpub := M.encapsulate_ephPub pubs (W.reqEnc req) cs eph ct s' hE
    simp only [hdec, W.reqDec_reqEnc] at h
    by_cases hs : M.Safe ct.ephPub
    · rw [dif_pos hs] at h
      cases hR : M.envelopeReply skj ⟨ct.ephPub, hs⟩ (W.replyEnc (step boxSize store req).2) rs with
      | error e s'' => rw [hR] at h; cases h
      | ok env s'' =>
        rw [hR] at h
        have hpub' : (⟨ct.ephPub, hs⟩ : {pk : M.PublicKey // M.Safe pk})
            = ⟨M.derivePublicKey eph, M.derive_safe eph⟩ := Subtype.ext hpub
        rw [hpub'] at hR
        have hdecE := M.decryptEnvelope_envelopeReply skj eph _ rs env s'' hR
        simp only [hdecE, W.replyDec_replyEnc] at h
        cases h
        rfl
    · rw [dif_neg hs] at h; cases h

/-! ### Writing a message and reading it back -/

/-- A message the writer encrypts and writes to a free box is read back by a reader holding only
`pk`, `idx` and `ctx`: the write succeeds, the read returns the written box, and it decrypts to
`pt`. -/
theorem write_then_read (B : BACAPSpec) [DecidableEq B.blindable.base.PublicKey]
    (W : Wire B.blindable.base) (boxSize : Nat)
    (sk : B.blindable.base.PrivateKey) (pk : B.blindable.base.PublicKey)
    (hpk : pk = B.blindable.base.pub sk) (idx : Cryptlib.Protocols.BACAP.Types.MessageBoxIndex)
    (ctx pt : ByteArray) (store : Store B.blindable.base)
    (hfree : store (B.deriveBoxID pk idx ctx) = none)
    (hne : (B.encryptBox sk pk idx ctx pt).2.1.size ≠ 0)
    (hsize : (B.encryptBox sk pk idx ctx pt).2.1.size = boxSize)
    (cs₁ rs₁ cs₂ rs₂ : M.State) (pubs : List {pk : M.PublicKey // M.Safe pk}) (i : Nat)
    (hi : i < pubs.length) (skj : M.PrivateKey)
    (hsk : pubs[i] = ⟨M.derivePublicKey skj, M.derive_safe skj⟩) :
    (∀ r, rpc M W boxSize cs₁ rs₁ pubs i skj store
        (.write (B.encryptBox sk pk idx ctx pt).1 (B.encryptBox sk pk idx ctx pt).2.1
          (B.encryptBox sk pk idx ctx pt).2.2) = .ok r →
      r = (store.put (B.encryptBox sk pk idx ctx pt).1
            ⟨(B.encryptBox sk pk idx ctx pt).2.1, (B.encryptBox sk pk idx ctx pt).2.2⟩,
          .writeReply .success)) ∧
    (∀ r, rpc M W boxSize cs₂ rs₂ pubs i skj
        (store.put (B.encryptBox sk pk idx ctx pt).1
          ⟨(B.encryptBox sk pk idx ctx pt).2.1, (B.encryptBox sk pk idx ctx pt).2.2⟩)
        (.read (B.deriveBoxID pk idx ctx)) = .ok r →
      r = (store.put (B.encryptBox sk pk idx ctx pt).1
            ⟨(B.encryptBox sk pk idx ctx pt).2.1, (B.encryptBox sk pk idx ctx pt).2.2⟩,
          .readReply .success
            (some ⟨(B.encryptBox sk pk idx ctx pt).2.1, (B.encryptBox sk pk idx ctx pt).2.2⟩))) ∧
    B.decryptBox (B.deriveBoxID pk idx ctx) idx ctx (B.encryptBox sk pk idx ctx pt).2.1
        (B.encryptBox sk pk idx ctx pt).2.2 = some pt := by
  have hid := B.encrypt_boxid sk pk idx ctx pt
  have hv := B.encrypt_verify sk pk idx ctx pt hpk
  have hdec := B.decrypt_encrypt sk pk idx ctx pt hpk
  simp only [] at hv hdec
  have hfree' : store (B.encryptBox sk pk idx ctx pt).1 = none := by rw [hid]; exact hfree
  refine ⟨?_, ?_, ?_⟩
  · intro r hr
    rw [rpc_sound M W boxSize cs₁ rs₁ pubs i hi skj hsk store _ r hr,
      write_fresh boxSize store _ _ _ hne hsize hv hfree']
  · intro r hr
    rw [rpc_sound M W boxSize cs₂ rs₂ pubs i hi skj hsk _ _ r hr, ← hid, step_read_put,
      if_neg hne]
  · rw [← hid]; exact hdec

end Cryptlib.Protocols.Pigeonhole.Protocol
