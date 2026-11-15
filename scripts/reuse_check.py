# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-pqbind-Commercial
# Copyright (c) 2026 VaultScribe Limited Liability Company
"""Responsibility: a small stand-in for `reuse lint` when the reuse tool is not installed.

Checks that every file git knows (tracked, or untracked but not ignored) has an SPDX-License-Identifier line in its first 20
lines, or is covered by an annotation in REUSE.toml, and that every license named exists under LICENSES/. Standard library only.
Run from anywhere: `python -I scripts/reuse_check.py`. Exit 0 when clean, 1 when there are findings.
"""

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPDX = re.compile(r"SPDX-License-Identifier:\s*(.+)")
COPYRIGHT = re.compile(r"(SPDX-FileCopyrightText:|Copyright)\s*(.+)")


def glob_to_regex(pattern: str) -> re.Pattern:
    """REUSE globs: `*` matches within one directory, `**` matches across directories."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def license_ids(expression: str) -> set:
    return {t for t in re.split(r"[\s()]+", expression) if t and t not in ("AND", "OR", "WITH")}


def main() -> int:
    listing = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode("utf-8")
    files = sorted(f for f in listing.split("\0") if f)

    annotations = []
    toml_path = ROOT / "REUSE.toml"
    if toml_path.exists():
        for a in tomllib.loads(toml_path.read_text(encoding="utf-8")).get("annotations", []):
            paths = [a["path"]] if isinstance(a["path"], str) else a["path"]
            annotations.append(([glob_to_regex(p) for p in paths], a))

    problems, used = [], set()
    for f in files:
        if f.startswith("LICENSES/") or re.match(r"LICEN[CS]E", f):
            continue  # license texts need no header
        header = "\n".join((ROOT / f).read_text(encoding="utf-8", errors="replace").splitlines()[:20])
        m = SPDX.search(header)
        if m and COPYRIGHT.search(header):
            used |= license_ids(m.group(1))
            continue
        hit = next((a for pats, a in annotations if any(p.match(f) for p in pats)), None)
        if hit is None:
            problems.append(f"no SPDX header and no REUSE.toml annotation: {f}")
        else:
            if not hit.get("SPDX-FileCopyrightText") or not hit.get("SPDX-License-Identifier"):
                problems.append(f"annotation lacks copyright or license: {f}")
            used |= license_ids(hit.get("SPDX-License-Identifier", ""))

    for lic in sorted(used):
        if not (ROOT / "LICENSES" / f"{lic}.txt").exists():
            problems.append(f"license text missing: LICENSES/{lic}.txt")

    for p in problems:
        print(p)
    print(f"reuse_check: {len(files)} files, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
