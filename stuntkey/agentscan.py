"""`stuntkey scan --agent-configs`: look in the settings files of AI coding tools.

An AI tool's own settings files (Claude Code's settings.local.json and
.claude folder, .mcp.json, Cursor's .cursor folder, Codex's config) are where
people paste a key "just to make it work". Those files are read by the tool,
and often by the AI itself. This looks in them, in the project and in your
home folder, for text shaped like a key, using the same key shapes as
`stuntkey scan`.

It shows the file, the line and a MASKED form of the key (its first and last
few characters), never the key. Files over 1 MB and binary files are skipped
and said so. Nothing is changed and nothing goes over the network.
"""
from __future__ import annotations

import json
import os
import sys

MAX_BYTES = 1024 * 1024
MAX_FILES = 400
MAX_DEPTH = 3

# (relative path, recurse into it). Looked for in the project folder AND in
# the home folder, so ~/.claude/settings.json is covered too.
PROJECT_NAMES = [(".mcp.json", False), (".claude", True), (".cursor", True),
                 (".codex", True), (".gemini", True)]
HOME_NAMES = [(".claude.json", False), (".mcp.json", False), (".claude", False),
              (".cursor", True), (".codex", True), (".gemini", True)]
# Inside a home .claude folder only its top-level files are read: the
# subfolders hold chat transcripts and caches, which `stuntkey scan` of your
# history covers separately and which can be huge.
SKIP_DIRS = frozenset({"node_modules", ".git", "cache", "logs", "extensions"})
TEXT_SUFFIXES = (".json", ".toml", ".md", ".mdc", ".yml", ".yaml", ".txt", ".local", ".env", ".cfg",
                 ".ini", "")


def _files_in(base: str, recurse: bool, notes: list) -> list:
    out = []
    if os.path.isfile(base):
        return [base]
    if not os.path.isdir(base):
        return out
    stack = [(base, 0)]
    while stack and len(out) < MAX_FILES:
        folder, depth = stack.pop()
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name)
        except OSError:
            notes.append(f"{folder}: a folder that could not be opened")
            continue
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if recurse and depth < MAX_DEPTH and e.name.lower() not in SKIP_DIRS:
                        stack.append((e.path, depth + 1))
                elif e.is_file(follow_symlinks=False) and \
                        os.path.splitext(e.name)[1].lower() in TEXT_SUFFIXES:
                    out.append(e.path)
            except OSError:
                continue
            if len(out) >= MAX_FILES:
                notes.append(f"{folder}: stopped after {MAX_FILES} files")
                break
    return out


def candidate_files(project: str, home: str) -> tuple:
    """([files to read], [notes about what could not be looked at])."""
    notes: list = []
    seen, files = set(), []
    for root, names in ((project, PROJECT_NAMES), (home, HOME_NAMES)):
        if not root:
            continue
        for name, recurse in names:
            for path in _files_in(os.path.join(root, name), recurse, notes):
                key = os.path.normcase(os.path.realpath(path))
                if key not in seen:
                    seen.add(key)
                    files.append(path)
    return files, notes


def scan_agent_configs(catalog: dict, project: str = ".", home: str | None = None) -> dict:
    """{"files": n looked at, "findings": [{file, line, service, masked, fix}],
    "skipped": [text]}."""
    from . import scan as scan_mod
    from . import recipes as recipes_mod
    home = home if home is not None else os.path.expanduser("~")
    project = os.path.abspath(project)
    files, notes = candidate_files(project, home)
    rules = scan_mod.build_rules(catalog)
    words = scan_mod._name_tokens(catalog)
    findings, looked, skipped = [], 0, list(notes)
    for path in files:
        base = os.path.dirname(path)
        text, why = scan_mod.read_text_safely(path, base, MAX_BYTES)
        shown = _display(path, project, home)
        if text is None:
            skipped.append(f"{recipes_mod.printable(shown)}: {why}")
            continue
        looked += 1
        budget = scan_mod.Budget(scan_mod.FILE_SECONDS)
        for f in scan_mod.scan_text(text, shown, rules, catalog, words, budget):
            fix = (f"Rotate it, then run `stuntkey get {f.provider}` and remove this line "
                   "(or run `stuntkey wrap` for a key inside an MCP server's settings)."
                   if f.provider else
                   "Rotate it at the service that issued it, remove this line, and keep "
                   "the new one in `stuntkey get`.")
            findings.append({"file": recipes_mod.printable(shown), "line": f.line,
                             "service": f.provider or "unknown", "masked": f.redacted,
                             "fix": fix})
        if budget.hit:
            skipped.append(f"{recipes_mod.printable(shown)}: scanning stopped early")
    return {"files": looked, "findings": findings, "skipped": skipped}


def _display(path: str, project: str, home: str) -> str:
    for root, label in ((project, ""), (home, "~/")):
        try:
            rel = os.path.relpath(path, root)
        except ValueError:
            continue
        if not rel.startswith(".."):
            return label + rel.replace("\\", "/")
    return path


def render(result: dict) -> str:
    n = len(result["findings"])
    lines = ["", f"  stuntkey scan --agent-configs: looked at {result['files']} settings "
                 f"file{'s' if result['files'] != 1 else ''} of AI tools "
                 "(project and home folder)."]
    if not n:
        lines.append("  No key-shaped text found in them.")
    else:
        lines.append(f"  Found {n} key-shaped value{'s' if n != 1 else ''}:")
        for f in result["findings"]:
            lines.append(f"    {f['file']}:{f['line']}   {f['service']}   {f['masked']}")
        lines.append("  What to do: " + result["findings"][0]["fix"])
    if result["skipped"]:
        lines.append(f"  Not looked at ({len(result['skipped'])}): "
                     + "; ".join(result["skipped"][:4])
                     + (" ..." if len(result["skipped"]) > 4 else ""))
    return "\n".join(lines) + "\n"


def cmd(args, catalog: dict, project: str = ".", home: str | None = None, out=None) -> int:
    """Exit 0 clean, 1 key-shaped text found."""
    out = out or sys.stdout
    result = scan_agent_configs(catalog, project, home)
    if getattr(args, "json", False):
        out.write(json.dumps({"agent_configs": result}, indent=2) + "\n")
    else:
        out.write(render(result))
    return 1 if result["findings"] else 0
