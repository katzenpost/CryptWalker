import Lake
open Lake DSL

--set_option diagnostics true

package «crypt_walker» where
  srcDir := "Lean"

lean_lib «CryptWalker» where

@[default_target]
lean_exe «crypt_walker» where
  root := `CryptWalker

@[test_driver]
lean_exe tests {
  root := `tests.Main
}

extern_lib crypt_walker_for_lean pkg := do
  proc { cmd := "cargo", args := #["build", "--release"], cwd := pkg.dir / "Rust" }
  let name := nameToStaticLib "crypt_walker_for_lean"
  let srcPath := pkg.dir / "Rust" / "target" / "release" / name
  IO.FS.createDirAll pkg.nativeLibDir
  let tgtPath := pkg.nativeLibDir / name
  IO.FS.writeBinFile tgtPath (← IO.FS.readBinFile srcPath)
  return pure tgtPath
