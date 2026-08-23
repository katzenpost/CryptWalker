import Std.Tactic.Do

open Std.Do

namespace CryptWalker.KEM.KEM

inductive KEMError where
  | badCiphertext
  | unsafePublicKey
deriving DecidableEq


structure KEM where
  State : Type
  PublicKey : Type
  PrivateKey : Type
  Ciphertext : Type
  Plaintext : Type
  [pubI  : Inhabited PublicKey]
  [privI : Inhabited PrivateKey]
  [ctI   : Inhabited Ciphertext]
  [ptI   : Inhabited Plaintext]

  publicKeySize  : Nat
  privateKeySize : Nat
  ciphertextSize : Nat
  plaintextSize  : Nat

  encodePublicKey  : PublicKey  → Vector UInt8 publicKeySize
  decodePublicKey  : Vector UInt8 publicKeySize  → Option PublicKey
  encodePrivateKey : PrivateKey → Vector UInt8 privateKeySize
  decodePrivateKey : Vector UInt8 privateKeySize → Option PrivateKey
  encodeCiphertext : Ciphertext → Vector UInt8 ciphertextSize
  decodeCiphertext : Vector UInt8 ciphertextSize → Option Ciphertext
  encodePlaintext  : Plaintext  → Vector UInt8 plaintextSize

  decap : PrivateKey → Ciphertext → EStateM KEMError State Plaintext
  encap : PublicKey → EStateM KEMError State (Ciphertext × Plaintext)
  init : State
  generate : EStateM KEMError State (Σ' (pk : PublicKey), {sk : PrivateKey //
    ∀ s c k s', encap pk s = .ok (c, k) s' → ∀ t, ∃ t', decap sk c t = .ok k t'})

  decode_encode_pub  : ∀ pk, decodePublicKey  (encodePublicKey  pk) = some pk
  decode_encode_priv : ∀ sk, decodePrivateKey (encodePrivateKey sk) = some sk
  decode_encode_ct   : ∀ c,  decodeCiphertext (encodeCiphertext c)  = some c

  [plaintextEq : DecidableEq Plaintext]


instance : Inhabited KEM := ⟨{
  State := Unit
  PublicKey := Unit
  PrivateKey := Unit
  Ciphertext := Unit
  Plaintext := Unit

  publicKeySize  := 0
  privateKeySize := 0
  ciphertextSize := 0
  plaintextSize  := 0

  encodePublicKey  := fun _ => #v[]
  decodePublicKey  := fun _ => some ()
  encodePrivateKey := fun _ => #v[]
  decodePrivateKey := fun _ => some ()
  encodeCiphertext := fun _ => #v[]
  decodeCiphertext := fun _ => some ()
  encodePlaintext  := fun _ => #v[]

  decap := fun _ _ => pure ()
  encap := fun _ => pure ((), ())
  init := ()
  generate := pure ⟨(), (), fun _ _ _ _ _ t => ⟨t, rfl⟩⟩

  decode_encode_pub  := fun _ => rfl
  decode_encode_priv := fun _ => rfl
  decode_encode_ct   := fun _ => rfl

  plaintextEq := inferInstance
}⟩

opaque kemSpec : KEM

instance : Inhabited kemSpec.State := ⟨kemSpec.init⟩

abbrev KEMM := EStateM KEMError kemSpec.State

abbrev PublicKey : Type := kemSpec.PublicKey
instance : Inhabited PublicKey := kemSpec.pubI

abbrev PrivateKey : Type := kemSpec.PrivateKey
instance : Inhabited PrivateKey := kemSpec.privI

abbrev Ciphertext : Type := kemSpec.Ciphertext
instance : Inhabited Ciphertext := kemSpec.ctI

abbrev Plaintext : Type := kemSpec.Plaintext
instance : Inhabited Plaintext := kemSpec.ptI

instance : DecidableEq Plaintext := kemSpec.plaintextEq

def generate : KEMM (PublicKey × PrivateKey) := do
  let ⟨pk, sk, _⟩ ← kemSpec.generate
  pure (pk, sk)

def encap : PublicKey → KEMM (Ciphertext × Plaintext) := kemSpec.encap

def decap : PrivateKey → Ciphertext → KEMM Plaintext := kemSpec.decap

def IsEncapsulation (sk : PrivateKey) (c : Ciphertext) (k : Plaintext) :=
  ∀ t, ∃ t', decap sk c t = .ok k t'

def KeyPair (pk : PublicKey) (sk : PrivateKey) :=
  ∀ s c k s', encap pk s = .ok (c, k) s' → IsEncapsulation sk c k

theorem EStateM_triple {ε σ α} {p : α → Prop} {x : EStateM ε σ α}
    (h : ∀ t, ∃ a t', x t = .ok a t' ∧ p a) :
    ⦃⌜True⌝⦄ x ⦃post⟨fun a => ⌜p a⌝, fun _ => ⌜False⌝⟩⦄ := by
  intro t _
  obtain ⟨a, t', ht, hp⟩ := h t
  sorry

@[spec] theorem generate_ok :
    ⦃⌜True⌝⦄ generate ⦃post⟨fun (pk, sk) => ⌜KeyPair pk sk⌝, fun _ => ⌜False⌝⟩⦄ := by
  sorry

@[spec] theorem encap_ok {pk sk} (h : KeyPair pk sk) :
    ⦃⌜True⌝⦄ encap pk ⦃post⟨fun (c, k) => ⌜IsEncapsulation sk c k⌝, fun _ => ⌜False⌝⟩⦄ := by
  sorry

@[spec] theorem decap_ok {sk ct k} (h : IsEncapsulation sk ct k) :
    ⦃⌜True⌝⦄ decap sk ct ⦃post⟨fun k' => ⌜k' = k⌝, fun _ => ⌜False⌝⟩⦄ :=
  EStateM_triple fun t => let ⟨t', ht⟩ := h t; ⟨k, t', ht, rfl⟩

def roundTrip : KEMM Bool := do
  let (pk, sk) ← generate
  let (c, k)   ← encap pk
  let k'       ← decap sk c
  return k' == k

theorem roundTrip_ok :
    ⦃⌜True⌝⦄ roundTrip ⦃post⟨fun b => ⌜b = true⌝, fun _ => ⌜False⌝⟩⦄ := by
  mvcgen [roundTrip] with grind

end CryptWalker.KEM.KEM
