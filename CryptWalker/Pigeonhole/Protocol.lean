/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Pigeonhole.Replica
import CryptWalker.KEM.MKEM
import CryptWalker.BACAP.Protocol

/-! # Pigeonhole: a client talking to a replica, end to end

The protocol, as `katzenpost/pigeonhole` and `courier` do it:

1. **Writing.** The writer turns a message into a BACAP *box*: a box ID (a public key derived from
   the root key), the AEAD ciphertext, and a signature. It wraps a `write` request in an MKEM
   envelope addressed to the two replicas responsible for that box, and sends it through the mixnet
   to a courier.
2. **Courier and replica.** The courier forwards the envelope to a replica, which decrypts it,
   handles the request (`Replica.step`), and seals its reply under the envelope's ephemeral key.
3. **Reading.** A reader who holds only the root public key, an index and a context derives the same
   box ID, sends a `read` the same way, checks the returned signature and decrypts.

`rpc` is one such exchange, with the mixnet and courier abstracted to reliable delivery. The
theorems, all over abstract `NIKE`, `AEAD`, `Hash` and signature scheme:

* `rpc_correct`: the reply the client obtains is exactly what the replica computed. The request
  survives MKEM and the wire codec; the reply survives them on the way back.
* `write_then_read`: a message written by the holder of a write capability is read back, intact, by
  a reader holding only the read capability.

**Assumed:** delivery (the courier relays faithfully; `Delivery` records the MKEM side conditions,
of which the one that is computational is that recipients' DEKs do not open under each other's
keys) and honest replicas. **Not modelled:** the mixnet, retries and timing, copy commands, epochs,
and what an adversarial replica or courier can do; that is the threat-model side. -/

namespace CryptWalker.Pigeonhole.Protocol

open CryptWalker.Sign.Sign (Signature)
open CryptWalker.KEM.MKEM (Scheme Ciphertext Rand)
open CryptWalker.Pigeonhole.Replica
open CryptWalker.BACAP.Protocol (BACAPSpec)

/-- How requests and replies are put on the wire. `hpqc`/`katzenpost` use trunnel; all the model
needs is that decoding undoes encoding. -/
structure Wire (Sg : Signature) where
  reqEnc : Request Sg → ByteArray
  reqDec : ByteArray → Option (Request Sg)
  replyEnc : Reply Sg → ByteArray
  replyDec : ByteArray → Option (Reply Sg)
  reqDec_reqEnc : ∀ r, reqDec (reqEnc r) = some r
  replyDec_replyEnc : ∀ r, replyDec (replyEnc r) = some r

variable {Sg : Signature} [DecidableEq Sg.PublicKey] (M : Scheme) (W : Wire Sg)

/-- One exchange. The client MKEM-encrypts `req` to the replicas' public keys `pubs`; the replica
holding `skj` decrypts it, handles it, and seals its reply under the envelope's ephemeral key; the
client, who kept the ephemeral private key, opens it. Returns the replica's new store and the reply
the client sees. -/
def rpc (boxSize : Nat) (rand : Rand M) (replyNonce : Vector UInt8 M.aead.nonceSize)
    (pubs : List {pk : M.nike.PublicKey // M.nike.Safe pk}) (skj : M.nike.PrivateKey)
    (store : Store Sg) (req : Request Sg) : Option (Store Sg × Reply Sg) := do
  let (eph, ct) ← M.encapsulate rand pubs (W.reqEnc req)
  let plaintext ← M.decapsulate skj ct
  let req' ← W.reqDec plaintext
  let (store', reply) := step boxSize store req'
  if h : M.nike.Safe ct.ephPub then
    let env ← M.envelopeReply skj ⟨ct.ephPub, h⟩ replyNonce (W.replyEnc reply)
    let bytes ← M.decryptEnvelope eph ⟨M.nike.derivePublicKey skj, M.nike.derive_safe skj⟩ env
    let reply' ← W.replyDec bytes
    pure (store', reply')
  else none

/-- The side conditions under which MKEM delivers `payload` to the replica holding `skj`: the sender
succeeds, the replica is one of the recipients (at index `i`), and no earlier DEK opens under its
key (AEAD authenticity, which `AEAD` cannot state). -/
structure Delivery (rand : Rand M) (pubs : List {pk : M.nike.PublicKey // M.nike.Safe pk})
    (skj : M.nike.PrivateKey) (payload : ByteArray) : Prop where
  ok : ∃ eph ct, M.encapsulate rand pubs payload = some (eph, ct)
  hlen : rand.dekNonces.length = pubs.length
  recipient : ∃ (i : Nat) (hi : i < pubs.length),
    pubs[i] = ⟨M.nike.derivePublicKey skj, M.nike.derive_safe skj⟩ ∧
    ∀ eph ct, M.encapsulate rand pubs payload = some (eph, ct) →
      ∀ k, M.deriveKey eph pubs[i] = some k →
        ∀ j (hj : j < i) (hj' : j < ct.deks.length), M.unsealUnder k ct.deks[j] = none

/-- **The client gets exactly what the replica computed.** -/
theorem rpc_correct (boxSize : Nat) (rand : Rand M) (replyNonce : Vector UInt8 M.aead.nonceSize)
    (pubs : List {pk : M.nike.PublicKey // M.nike.Safe pk}) (skj : M.nike.PrivateKey)
    (store : Store Sg) (req : Request Sg) (hd : Delivery M rand pubs skj (W.reqEnc req)) :
    rpc M W boxSize rand replyNonce pubs skj store req = some (step boxSize store req) := by
  obtain ⟨eph, ct, henc⟩ := hd.ok
  obtain ⟨i, hi, hsk, hcross⟩ := hd.recipient
  have hdec := M.decapsulate_encapsulate rand pubs (W.reqEnc req) eph ct henc hd.hlen i hi skj hsk
    (hcross eph ct henc)
  have hpub := M.encapsulate_ephPub rand pubs (W.reqEnc req) eph ct henc
  unfold rpc
  rw [henc]
  simp only [Bind.bind, Option.bind, hdec, W.reqDec_reqEnc]
  have hsafe : M.nike.Safe ct.ephPub := by rw [hpub]; exact M.nike.derive_safe eph
  rw [dif_pos hsafe]
  cases hrep : M.envelopeReply skj ⟨ct.ephPub, hsafe⟩ replyNonce
      (W.replyEnc (step boxSize store req).2) with
  | none =>
    exfalso
    obtain ⟨_, k, hk⟩ := M.decapsulate_key skj ct _ hdec
    unfold Scheme.envelopeReply at hrep
    simp [hk] at hrep
  | some env =>
    simp only [Bind.bind, Option.bind]
    have hpub' : (⟨ct.ephPub, hsafe⟩ : {pk : M.nike.PublicKey // M.nike.Safe pk})
        = ⟨M.nike.derivePublicKey eph, M.nike.derive_safe eph⟩ := by
      apply Subtype.ext; exact hpub
    rw [hpub'] at hrep
    rw [M.decryptEnvelope_envelopeReply eph skj replyNonce _ env hrep]
    simp [W.replyDec_replyEnc]

/-! ### Writing a message and reading it back -/

/-- **A written message is read back.** `sk` is the writer's root secret, `pk` its public key (what
a reader holds, with the index and context). The writer BACAP-encrypts `pt` into a box and sends a
`write`; the reader derives the box ID from `pk`, `idx` and `ctx` alone, sends a `read`, and
decrypts what comes back. Over honest replicas with a valid store and a free box, and given that
MKEM delivers both requests (`Delivery`), the reader recovers exactly `pt`, and the replica's reply
to the write is `success`. -/
theorem write_then_read (B : BACAPSpec) [DecidableEq B.blindable.base.PublicKey]
    (W : Wire B.blindable.base) (boxSize : Nat)
    (sk : B.blindable.base.PrivateKey) (pk : B.blindable.base.PublicKey)
    (hpk : pk = B.blindable.base.pub sk) (idx : CryptWalker.BACAP.Types.MessageBoxIndex)
    (ctx pt : ByteArray) (store : Store B.blindable.base)
    (hfree : store (B.deriveBoxID pk idx ctx) = none)
    (hne : (B.encryptBox sk pk idx ctx pt).2.1.size ≠ 0)
    (hsize : (B.encryptBox sk pk idx ctx pt).2.1.size = boxSize)
    (randW randR : Rand M) (nonceW nonceR : Vector UInt8 M.aead.nonceSize)
    (pubs : List {pk : M.nike.PublicKey // M.nike.Safe pk}) (skj : M.nike.PrivateKey)
    (dW : Delivery M randW pubs skj (W.reqEnc (.write (B.encryptBox sk pk idx ctx pt).1
      (B.encryptBox sk pk idx ctx pt).2.1 (B.encryptBox sk pk idx ctx pt).2.2)))
    (dR : Delivery M randR pubs skj (W.reqEnc (.read (B.deriveBoxID pk idx ctx)))) :
    ∃ store' : Store B.blindable.base,
      rpc M W boxSize randW nonceW pubs skj store
          (.write (B.encryptBox sk pk idx ctx pt).1 (B.encryptBox sk pk idx ctx pt).2.1
            (B.encryptBox sk pk idx ctx pt).2.2) = some (store', .writeReply .success) ∧
      rpc M W boxSize randR nonceR pubs skj store' (.read (B.deriveBoxID pk idx ctx))
          = some (store', .readReply .success
              (some ⟨(B.encryptBox sk pk idx ctx pt).2.1, (B.encryptBox sk pk idx ctx pt).2.2⟩)) ∧
      B.decryptBox (B.deriveBoxID pk idx ctx) idx ctx (B.encryptBox sk pk idx ctx pt).2.1
          (B.encryptBox sk pk idx ctx pt).2.2 = some pt := by
  have hid := B.encrypt_boxid sk pk idx ctx pt
  have hv := B.encrypt_verify sk pk idx ctx pt hpk
  have hdec := B.decrypt_encrypt sk pk idx ctx pt hpk
  simp only [] at hv hdec
  have hfree' : store (B.encryptBox sk pk idx ctx pt).1 = none := by rw [hid]; exact hfree
  refine ⟨store.put (B.encryptBox sk pk idx ctx pt).1
    ⟨(B.encryptBox sk pk idx ctx pt).2.1, (B.encryptBox sk pk idx ctx pt).2.2⟩, ?_, ?_, ?_⟩
  · rw [rpc_correct M W boxSize randW nonceW pubs skj store _ dW,
      write_fresh boxSize store _ _ _ hne hsize hv hfree']
  · rw [rpc_correct M W boxSize randR nonceR pubs skj _ _ dR, ← hid, step_read_put, if_neg hne]
  · rw [← hid]; exact hdec

end CryptWalker.Pigeonhole.Protocol
