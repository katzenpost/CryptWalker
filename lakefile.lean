import Lake
open Lake DSL

set_option diagnostics true

package "new" where
  -- Settings applied to both builds and interactive editing
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩ -- pretty-prints `fun a ↦ b`
  ]
  -- add any additional package configuration options here

require "leanprover-community" / "mathlib"

@[default_target]
lean_lib «CryptWalker» where

@[test_driver]
lean_exe tests {
  root := `Tests.Main
}
