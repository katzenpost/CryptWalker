"""Reduce doc-gen4 output to Cryptlib's own modules.

doc-gen4 renders every module the library imports. This deletes the pages of
other packages, points links into them at their hosted documentation where it
exists (plain text otherwise), and trims the search index and navbar to match.

usage: python3 -I prune-api.py DOC_DIR
"""

import json
import posixpath
import re
import shutil
import sys
from pathlib import Path

KEEP = "Cryptlib"

MATHLIB_DOCS = "https://leanprover-community.github.io/mathlib4_docs/"
HOSTED = {
    "Init": MATHLIB_DOCS,
    "Std": MATHLIB_DOCS,
    "Lean": MATHLIB_DOCS,
    "Lake": MATHLIB_DOCS,
    "Mathlib": MATHLIB_DOCS,
    "Batteries": MATHLIB_DOCS,
    "Aesop": MATHLIB_DOCS,
    "Qq": MATHLIB_DOCS,
    "ProofWidgets": MATHLIB_DOCS,
    "Plausible": MATHLIB_DOCS,
    "ImportGraph": MATHLIB_DOCS,
    "LeanSearchClient": MATHLIB_DOCS,
    "Cslib": "https://api.cslib.io/docs/",
}

LINK = re.compile(r'<a href="([^"]*)"([^>]*)>(.*?)</a>', re.S)


def root_of(path):
    return path.split("/", 1)[0].removesuffix(".html")


def rewrite(page, html, dropped):
    page_dir = posixpath.dirname(page)

    def fix(m):
        href, attrs, body = m.groups()
        if re.match(r"[a-z]+:|#", href):
            return m.group(0)
        target = posixpath.normpath(posixpath.join(page_dir, href))
        root = root_of(target)
        if root not in dropped:
            return m.group(0)
        if root in HOSTED:
            return f'<a href="{HOSTED[root]}{target}"{attrs}>{body}</a>'
        return f"<span{attrs}>{body}</span>"

    return LINK.sub(fix, html)


def remove_top_level_sections(navbar, dropped):
    for root in dropped:
        start_tag = f'<details class="nav_sect" data-path="./{root}.html">'
        while (i := navbar.find(start_tag)) != -1:
            depth, j = 0, i
            for m in re.finditer(r"<details|</details>", navbar[i:]):
                depth += 1 if m.group(0) == "<details" else -1
                if depth == 0:
                    j = i + m.end()
                    break
            navbar = navbar[:i] + navbar[j:]
        navbar = navbar.replace(
            f'<div class="nav_link"><a href="./{root}.html">{root}</a></div>', ""
        )
    return navbar


def prune_index(doc):
    path = doc / "declarations" / "declaration-data.bmp"
    data = json.loads(path.read_text())
    prefix = f"./{KEEP}/"
    decls = {
        k: v for k, v in data["declarations"].items()
        if v["docLink"].startswith(prefix) or v["docLink"].startswith(f"./{KEEP}.html")
    }
    data["declarations"] = decls
    for key in ("instances", "instancesFor"):
        data[key] = {
            k: kept for k, v in data[key].items()
            if (kept := [n for n in v if n in decls])
        }
    data["modules"] = {
        k: {**v, "importedBy": [n for n in v.get("importedBy", []) if n.split(".")[0] == KEEP]}
        for k, v in data["modules"].items() if k.split(".")[0] == KEEP
    }
    path.write_text(json.dumps(data, separators=(",", ":")))


def main(doc):
    modules = json.loads((doc / "declarations" / "declaration-data.bmp").read_text())["modules"]
    dropped = {m.split(".")[0] for m in modules} - {KEEP}

    for root in dropped:
        shutil.rmtree(doc / root, ignore_errors=True)
        (doc / f"{root}.html").unlink(missing_ok=True)

    prune_index(doc)

    navbar = doc / "navbar.html"
    navbar.write_text(remove_top_level_sections(navbar.read_text(), dropped))

    for page in doc.rglob("*.html"):
        rel = page.relative_to(doc).as_posix()
        page.write_text(rewrite(rel, page.read_text(), dropped))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
