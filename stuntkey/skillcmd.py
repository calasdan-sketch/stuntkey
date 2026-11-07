"""`stuntkey skill install`: put the agent skill where Claude Code reads it.

The skill is a short SKILL.md that tells an AI agent the rules (ask the person
to connect keys, never read .env). It ships inside the package. This copies it
to ~/.claude/skills/stuntkey/ (or ./.claude/skills/stuntkey/ with
--project). It never follows a link, and never replaces a different file
without asking.
"""

from __future__ import annotations

import os
import sys
import tempfile

from . import fsutil
from . import recipes as recipes_mod

SKILL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "skill", "SKILL.md")


def skill_text() -> str:
    with open(SKILL_FILE, encoding="utf-8") as f:
        return f.read()


def _links_in(path: str, stop: str) -> str | None:
    """A link among the folders from `stop` down to `path` (inclusive), or None."""
    here = os.path.abspath(path)
    stop = os.path.abspath(stop)
    while True:
        if os.path.islink(here):
            return here
        if here == stop or os.path.dirname(here) == here:
            return None
        here = os.path.dirname(here)


def cmd_skill(args, out=None, ask=input, home: str | None = None, cwd: str | None = None,
              interactive=None) -> int:
    out = out or sys.stdout
    client = getattr(args, "for_client", "claude")
    if client != "claude":
        from . import agentsetup
        project = os.path.abspath(cwd or os.getcwd())
        targets = ("cursor", "codex", "gemini") if client == "all" else (client,)
        codes = [agentsetup.install_rules(c, project, skill_text(), out) for c in targets]
        if client == "all":
            args = type("A", (), {"project": args.project, "yes": args.yes, "for_client": "claude"})()
            codes.append(cmd_skill(args, out, ask, home, cwd, interactive))
        return max(codes)
    base = os.path.abspath(cwd or os.getcwd()) if args.project else os.path.abspath(
        home or os.path.expanduser("~"))
    claude = os.path.join(base, ".claude")
    target_dir = os.path.join(claude, "skills", "stuntkey")
    target = os.path.join(target_dir, "SKILL.md")
    link = _links_in(target, base)
    if link or os.path.islink(target):
        out.write(f"  {recipes_mod.printable(link or target)} is a link; I will not write through it.\n")
        return 1
    text = skill_text()
    if os.path.isfile(target):
        with open(target, encoding="utf-8", errors="replace") as f:
            if f.read() == text:
                out.write(f"  Already installed and up to date: {recipes_mod.printable(target)}\n")
                return 0
        if not args.yes:
            if interactive is None:
                interactive = lambda: bool(sys.stdin and sys.stdin.isatty())
            if not interactive():
                out.write(f"  {recipes_mod.printable(target)} exists and is different. "
                          f"Add --yes to replace it.\n")
                return 1
            try:
                answer = ask(f"  {recipes_mod.printable(target)} exists and is different. Replace it? [y/N]: ")
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if answer.strip().lower() not in ("y", "yes"):
                out.write("  left as it was.\n")
                return 1
    elif os.path.exists(target):
        out.write(f"  {recipes_mod.printable(target)} exists and is not a plain file.\n")
        return 1
    os.makedirs(target_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".SKILL.", suffix=".tmp", dir=target_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        fsutil.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    out.write(f"  ✓ installed {recipes_mod.printable(target)}\n")
    return 0
