import Lake
open Lake DSL

-- XXX how can we set these options globally throughout the source code from this lakefile?
--set_option diagnostics true
--set_option autoImplicit false

package "new" where
  -- Settings applied to both builds and interactive editing
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩ -- pretty-prints `fun a ↦ b`
  ]
  -- add any additional package configuration options here

require mathlib from git
  "https://github.com/leanprover-community/mathlib4"@"v4.10.0"

@[default_target]
lean_lib «CryptWalker» where

@[test_driver]
lean_exe tests {
  root := `Tests.Main
}
