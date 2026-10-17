import VersoBlog
open Verso Genre Blog

#doc (Page) "Cryptlib" =>

# Abstract

Cryptlib started off as a Lean model of the Golang (and python, rust) cryptography library [hpqc](https://github.com/katzenpost/hpqc/),
hybrid post quantum cryptography, which is used by the [Katzenpost](https://katzenpost.network/) post quamtum decryption mix network.

Beyond that we have two main goals:

* Cryptlib can be used to write real cryptography applications in Lean for high assurance security applications
* Cryptlib can also be used to prove cryptographic security properties of primitives and protocols

In Cryptlib we create a Lean structure type which provides a generic definition for a cryptographic primitive
such as a NIKE (non-interactive key exchange). In languages like Rust traits are mere empty husks
that defines one or more function signatures. There's no trait or interface type in Lean. Instead
we use a structure type in Lean to define a generic cryptographic primitive such as NIKE where some
of the fields contain functions and some of the fields contain data types etc. This is Lean representing
cryptographic primitives in a generic way like Rust or Golang. To take things a step further, we
use dependent types in Lean! For example our NIKE structure type has a proposition that says
the group operation is commutative:

```lean demo
structure NIKE where
/-- ... --/
  commutes : ∀ sk₁ sk₂,
    groupAction sk₁ ⟨derivePublicKey sk₂, derive_safe sk₂⟩
      = groupAction sk₂ ⟨derivePublicKey sk₁, derive_safe sk₁⟩
```
**code block caption**: This code block is found in cryptlib here
https://github.com/katzenpost/cryptlib/blob/main/Cryptlib/Primitives/NIKE/NIKE.lean#L12-L73

In cryptlib each category of cryptographic primitive shall have a structure type defining
the primitive generically. The type definition will define functions and data types as well as
propositions about that cryptographic primitive. Another example is our generic definition of
the KEM (key encapsulation mechanism) is here:

```lean demo
structure KEM where
/-- ... --/
  /-- Pre-encapsulation states that cannot cause a decryption failure. `True` for a perfectly
  correct KEM; a lattice KEM restricts it to states whose sampled noise stays within bounds. -/
  Reliable : State → Prop := fun _ => True
  /-- Round trip for any private key and its derived public key, from a `Reliable` state. -/
  honestRoundTrip : ∀ sk, ∀ s, Reliable s → ∀ c k s', encap (derivePublicKey sk) s = .ok (c, k) s' →
    ∀ t, ∃ t', decap sk c t = .ok k t'
```
**code block caption**: This code block is found in cryptlib here:
https://github.com/katzenpost/cryptlib/blob/main/Cryptlib/Primitives/KEM/KEM.lean#L13-L65

There are some obvious and not so obvious benefits of a cryptography library that uses dependent
types to create these additional proof obligations. The most obvious is that it ensures each instance
of these types at least meets the low bar of quality and satisfies the type proposition fields.
However a less obvious advantage is that we get formalized definitions with fewer transitive proof obligations
overall when we compose these dependent types together.

As an example, we define a NIKE to KEM adapter which is just a hashed ElGamal construction. In Lean it's possible to
write a theorem that says that my NIKE to KEM adapter produces a lawful KEM if it is given a lawful NIKE. However there
is no need to even write that thereom in the first place if dependent types for the NIKE and KEM definitions are
used because they make it impossible to create a type instance that violates their type's proposition fields.

Our cryptlib NIKE to KEM adapter definition is here:
https://github.com/katzenpost/cryptlib/blob/main/Cryptlib/Primitives/KEM/Adapter.lean#L119-L161

This is an example of our usage of depedent types enforcing a proof implicitly and it can do so transitively
as primitive functions are composed together. In many ways this simplifies the proof obligations of the composed protocol.









