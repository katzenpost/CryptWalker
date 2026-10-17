"""Generate CryptWalker's API reference with doc-gen4.

doc-gen4's Lake facet processes every module the library imports, about 3,600
of them from Mathlib, before rendering anything. This runs doc-gen4's commands
directly instead: one `single` per CryptWalker module, `genCore` for Lean's
own libraries, then `fromDb`. Declarations from Mathlib and other packages
render as plain text instead of links. The core libraries depend only on the
toolchain, so their database is kept and reused until the toolchain changes.

usage: python3 -I gen-api.py REPO_ROOT JOBS
Writes the HTML to REPO_ROOT/docs/docbuild/.lake/apidocs/doc.
"""

import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

LIB = "CryptWalker"
CORE = ["Init", "Std", "Lean", "Lake"]
IMPORT = re.compile(r"^(?:public |private )?(?:meta )?import (?:all )?([A-Za-z0-9_.]+)", re.M)


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        sys.exit(f"failed ({r.returncode}): {' '.join(map(str, cmd))}\n{r.stdout[-2000:]}{r.stderr[-2000:]}")
    return r.stdout


def lib_modules(root):
    seen, todo = set(), [LIB]
    while todo:
        mod = todo.pop()
        if mod in seen:
            continue
        seen.add(mod)
        src = root / (mod.replace(".", "/") + ".lean")
        todo += [m for m in IMPORT.findall(src.read_text()) if m.split(".")[0] == LIB]
    return sorted(seen)


def source_url(root):
    remote = run(["git", "-C", root, "remote", "get-url", "origin"]).strip()
    remote = re.sub(r"^git@github\.com:", "https://github.com/", remote).removesuffix(".git")
    rev = run(["git", "-C", root, "rev-parse", "HEAD"]).strip()
    return f"{remote}/blob/{rev}"


def main(root, jobs):
    docbuild = root / "docs" / "docbuild"
    out = docbuild / ".lake" / "apidocs"

    run(["lake", "build", LIB, "doc-gen4"], cwd=docbuild)
    env = dict(os.environ, LEAN_PATH=run(["lake", "env", "printenv", "LEAN_PATH"], cwd=docbuild).strip())
    docgen = root / ".lake" / "packages" / "doc-gen4" / ".lake" / "build" / "bin" / "doc-gen4"
    toolchain = (root / "lean-toolchain").read_text().strip().replace("/", "-").replace(":", "-")

    shutil.rmtree(out / "doc", ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    db = out / "api-docs.db"
    core_db = out / f"core-{toolchain}.db"
    for f in out.glob("api-docs.db*"):
        f.unlink()

    run([docgen, "bibPrepass", "--build", out, "--none"], env=env)

    # SQLite in WAL mode: the database is the file plus its -wal and -shm siblings.
    def copy_db(src, dst):
        for suffix in ("", "-wal", "-shm"):
            if Path(f"{src}{suffix}").exists():
                shutil.copy(f"{src}{suffix}", f"{dst}{suffix}")

    if not core_db.exists():
        print("documenting Lean core libraries (once per toolchain)", flush=True)
        with ThreadPoolExecutor(jobs) as pool:
            list(pool.map(lambda c: run([docgen, "genCore", "--build", out, c, db], env=env), CORE))
        copy_db(db, core_db)
    else:
        copy_db(core_db, db)

    mods = lib_modules(root)
    url = source_url(root)
    print(f"documenting {len(mods)} {LIB} modules", flush=True)
    with ThreadPoolExecutor(jobs) as pool:
        list(pool.map(
            lambda m: run([docgen, "single", "--build", out, m, db,
                           f"{url}/{m.replace('.', '/')}.lean"], env=env),
            mods))

    print("rendering HTML", flush=True)
    run([docgen, "fromDb", "--build", out, db, LIB], env=env)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), int(sys.argv[2]))
