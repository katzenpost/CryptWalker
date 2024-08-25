import Lake
import Lake.Build.Job
open Lake DSL


set_option diagnostics true

require "leanprover-community" / "batteries"
require "leanprover-community" / "mathlib"

package «crypt_walker» where
  srcDir := "Lean"

@[default_target]
lean_lib «CryptWalker» where

@[test_driver]
lean_exe tests {
  root := `Tests.Main
}
