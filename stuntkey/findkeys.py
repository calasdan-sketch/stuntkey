"""Look for keys lying around in a project folder: the one look that
`stuntkey start`, `stuntkey setup` and `stuntkey scan` share, so they agree.

It reports three things:
  - findings: keys `scan` would report (real-looking values)
  - examples: values that LOOK like a key but were skipped because they look
    like an example ("your_key_here", "sk-xxxx"). Never silent.
  - env_files: the .env-style files that hold anything, with the names inside

No value is ever returned or printed: only file names, variable names and
line numbers.
"""
from __future__ import annotations

import os
import re

_NAMEISH = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)S?$", re.I)


def _is_env_name(name: str) -> bool:
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def env_files(root: str) -> list:
    """The .env-style files an agent could read, in this folder and below
    (the same files `scan` looks at)."""
    from . import scan as scan_mod
    files, _skipped, _n = scan_mod.collect_files(os.path.abspath(root), False)
    return sorted(f for f in files if _is_env_name(os.path.basename(f)))


def _pairs(path: str, root_real: str) -> list:
    from . import connect_import
    from . import scan as scan_mod
    text, _why = scan_mod.read_text_safely(path, root_real)
    if text is None:
        return []
    try:
        return connect_import.parse_env(text)
    except Exception:           # noqa: BLE001 - an odd file is just not read
        return []


def examples_skipped(root: str, catalog: dict) -> list:
    """[(relative file, variable name)] for values that look like a key but
    were skipped as examples."""
    from . import getmenu
    from . import scan as scan_mod
    root = os.path.abspath(root)
    root_real = os.path.realpath(root)
    out = []
    for path in env_files(root):
        rel = os.path.relpath(path, root).replace("\\", "/")
        for name, value in _pairs(path, root_real):
            value = (value or "").strip()
            if len(value) < 6 or not scan_mod.is_placeholder(value):
                continue
            keyish = bool(_NAMEISH.search(name)) or bool(getmenu.service_for_key(
                value.replace("x", "a"), catalog))
            if keyish or re.match(r"(sk|pk|rk|ghp|gho|xox[bp]|AIza|AKIA)[-_]?", value):
                out.append((rel, name))
    return out


def find_loose(root: str, catalog: dict) -> dict:
    """{"findings": [Finding...], "examples": [(file, name)], "files": [..],
    "incomplete": bool}."""
    from . import scan as scan_mod
    root = os.path.abspath(root)
    res = scan_mod.scan_path(root, catalog)
    return {"findings": res.findings, "examples": examples_skipped(root, catalog),
            "files_scanned": res.files_scanned, "incomplete": res.incomplete}


def examples_text(examples: list, limit: int = 8) -> str:
    """Plain words, no values."""
    from . import recipes as recipes_mod
    p = recipes_mod.printable
    if not examples:
        return ""
    lines = ["  Looks like an example, skipped (not a real key, so not counted):"]
    for rel, name in examples[:limit]:
        lines.append(f"    {p(name)} in {p(rel)}")
    if len(examples) > limit:
        lines.append(f"    ... and {len(examples) - limit} more")
    return "\n".join(lines) + "\n"
