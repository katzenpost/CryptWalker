/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Pigeonhole.Replica
import CryptWalker.MKEM.MKEM
import CryptWalker.BACAP.Protocol

/-! # Pigeonhole: a client talking to a replica, end to end

The protocol, as `katzenpost/pigeonhole` and `courier` do it:

1. **Writing.** The writer turns a message into a BACAP *box*: a box ID (a public key derived from
   the root key), the AEAD ciphertext, and a signature. It wraps a `write` request in an MKEM
   envelope addressed to the two replicas responsible for that box, and sends it through the mixnet
   to a courier.
2. **Courier and replica.** The courier gives each replica the ciphertext carrying only its own DEK
   (`Ciphertext.forRecipient`), and the replica decrypts it, handles the request (`Replica.step`),
   and seals its reply under the envelope's ephemeral key.
3. **Reading.** A reader who holds only the root public key, an index and a context derives the same
   box ID, sends a `read` the same way, checks the returned signature and decrypts.

`rpc` is one such exchange, with the mixnet and courier abstracted to reliable delivery, over any
`MKEM` (`MKEMAdapter.mkemOfNike` is one, and needs no CTIDH). The theorems:

* `rpc_sound`: **if the exchange completes**, the client's result is exactly what the replica
  computed. The request survives MKEM and the wire codec; so does the reply on the way back.
* `write_then_read`: a message written by the holder of a write capability is read back, intact, by
  a reader holding only the read capability.

These are safety statements: an exchange may fail (an unsafe key, a degenerate shared secret), and
nothing here says it cannot. **Assumed:** a faithful courier and honest replicas. **Not modelled:**
the mixnet, retries and timing, copy commands, epochs, and what an adversarial replica or courier
can do; that is the threat-model side. -/

namespace CryptWalker.Pigeonhole.Protocol

open CryptWalker.Sign.Sign (Signature)
open CryptWalker.MKEM.MKEM (MKEM MKEMError Ciphertext)
open CryptWalker.Pigeonhole.Replica
open CryptWalker.BACAP.Protocol (BACAPSpec)

/-- How requests and replies are put on the wire. `katzenpost` uses trunnel; all the model needs is
that decoding undoes encoding. -/
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

/-- One exchange. The client MKEM-encrypts `req` to the replicas' public keys `pubs`; the courier
hands replica `i`, who holds `skj`, its own share of the ciphertext; the replica decrypts, handles
the request, and seals its reply under the envelope's ephemeral key; the client, who kept the
ephemeral private key, opens it. `cs` and `rs` are the client's and the replica's randomness.
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

/-- **If the exchange completes, the client gets exactly what the replica computed.** Replica `i`
must be the recipient the client addressed (`pubs[i]` is the public key of `skj`); nothing else is
assumed of the MKEM beyond its laws. -/
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

/-- **A written message is read back.** `sk` is the writer's root secret, `pk` its public key (what
a reader holds, with the index and context). The writer BACAP-encrypts `pt` into a box and sends a
`write`; the reader derives the box ID from `pk`, `idx` and `ctx` alone, sends a `read`, and decrypts
what comes back. Over honest replicas with a valid store and a free box, whenever the exchanges
complete: the replica's reply to the write is `success`, the read returns exactly the box that was
written, and decrypting it gives `pt`. -/
theorem write_then_read (B : BACAPSpec) [DecidableEq B.blindable.base.PublicKey]
    (W : Wire B.blindable.base) (boxSize : Nat)
    (sk : B.blindable.base.PrivateKey) (pk : B.blindable.base.PublicKey)
    (hpk : pk = B.blindable.base.pub sk) (idx : CryptWalker.BACAP.Types.MessageBoxIndex)
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

end CryptWalker.Pigeonhole.Protocol
