"""`stuntkey adopt`: move the keys you already have into the keychain.

Without it, every key that is already lying in a `.env` costs a trip to the
vendor's site: open the page, make a new key, copy it, paste it. `adopt`
reads the key where it already is and puts it in the OS keychain, once, with
no copying and no new key to make.

* It only takes a value `scan` is sure about: the file is a `.env`-style file,
  the key has a known vendor format, and the service has one secret (a service
  with two values, such as AWS, is left to `stuntkey get`).
* It asks before it stores anything, stores it under the service's usual
  variable name, reads it back, and never shows it.
* The file is NOT changed unless you add `--remove`; with it, each moved line
  becomes a comment (after a second question). A key that was already in a
  file may have been read by an agent or sent to a backup: if it matters,
  rotate it (`stuntkey rotate <service>`).
"""

from __future__ import annotations

import dataclasses
import os
import re
import sys

from . import keychain as keychain_mod
from . import recipes as recipes_mod
from . import safeprompt
from . import scan as scan_mod
from . import store as store_mod

_ENV_NAME_RE = re.compile(r"(?i)^(?:.*\.env|\.env(?:\..*)?)$")
_EXAMPLE_RE = re.compile(r"(?i)(example|sample|template|dist)")
_LINE_RE = re.compile(r"^(?P<lead>\s*(?:export\s+)?)(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
                      r"(?P<eq>\s*=\s*)(?P<q>[\"']?)(?P<value>[^\"'\r\n]*)(?P=q)\s*(?P<nl>\r?\n?)$")


@dataclasses.dataclass
class Candidate:
    service: str
    display: str
    env_var: str
    where: str            # file:line, as shown to the person
    shown: str            # shortened key
    file: str             # path relative to the root
    value: str = dataclasses.field(default="", repr=False)
    removable: bool = False


def _editable_env(rel: str) -> bool:
    base = os.path.basename(rel)
    return (bool(_ENV_NAME_RE.match(base)) and not _EXAMPLE_RE.search(base)
            and ".." not in rel.split("/") and not os.path.isabs(rel))


def plan(root: str, catalog: dict, backend: str | None, keychain=keychain_mod
         ) -> tuple[list[Candidate], list[str]]:
    """(keys to move, things said to the person about the ones left alone)."""
    notes: list[str] = []
    res = scan_mod.scan_path(root, catalog)
    chosen: dict[str, Candidate] = {}
    for f in res.findings:
        if not (f._value and f.provider and f.can_validate):
            continue
        recipe = catalog.get(f.provider)
        if not recipe:
            continue
        fields = recipes_mod.fields(recipe)
        if len(fields) != 1:
            if f.provider not in chosen:
                notes.append(f"{recipe['display']}: has more than one value; use "
                             f"`stuntkey get {f.provider}`.")
                chosen[f.provider] = None  # type: ignore[assignment]
            continue
        if f.provider in chosen:
            prev = chosen[f.provider]
            if prev is not None and prev.value != f._value:
                notes.append(f"{recipe['display']}: a second, different key at "
                             f"{scan_mod.printable(f.file)}:{f.line} was left alone.")
            continue
        env_var = fields[0]["env_var"]
        chosen[f.provider] = Candidate(
            f.provider, recipe["display"], env_var, f"{f.file}:{f.line}", f.redacted,
            f.file, f._value, removable=_editable_env(f.file))
    out = []
    for c in chosen.values():
        if c is None:
            continue
        if backend and keychain.read(c.service, c.env_var, backend):
            notes.append(f"{c.display}: already in the keychain; not replaced.")
            continue
        out.append(c)
    return out, notes


def _remove_lines(root: str, picked: list[Candidate], out) -> int:
    """Comment out the moved NAME=value lines. Each line is found again by its
    value, so a file edited since the scan is never changed at a guessed line."""
    by_file: dict[str, list[Candidate]] = {}
    for c in picked:
        if c.removable:
            by_file.setdefault(c.file, []).append(c)
    changed = 0
    for rel, items in by_file.items():
        path = os.path.join(root, *rel.split("/"))
        try:
            with open(path, encoding="utf-8", newline="") as fh:
                lines = fh.read().splitlines(keepends=True)
        except (OSError, UnicodeDecodeError):
            out.write(f"  Could not read {scan_mod.printable(rel)} again; left as it was.\n")
            continue
        count = 0
        for i, line in enumerate(lines):
            m = _LINE_RE.match(line)
            if not m:
                continue
            for c in items:
                if m.group("value") == c.value:
                    lines[i] = (f"# {m.group('name')} moved to the stuntkey keychain; start "
                                f"your program with `stuntkey run {c.service} -- <command>`"
                                f"{m.group('nl') or chr(10)}")
                    count += 1
                    break
        if not count:
            out.write(f"  {scan_mod.printable(rel)} has changed since the scan; left as it was.\n")
            continue
        try:
            store_mod.write_private(path, "".join(lines))
        except (OSError, store_mod.EnvFileRefused) as e:
            out.write(f"  Could not change {scan_mod.printable(rel)} ({type(e).__name__}); "
                      "left as it was.\n")
            continue
        changed += count
    return changed


def _yes(question: str, out, ask) -> bool:
    return bool(safeprompt.ask(question, out, enter_means=False, reader=ask,
                               if_key="That looked like a key. Do not paste it here. Type y or n."))


def cmd_adopt(args, catalog: dict, out=None, ask=None, keychain=keychain_mod) -> int:
    out = out or sys.stdout
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        out.write("  That is not a folder.\n")
        return 2
    backend = keychain.detect_backend()
    if backend is None and not args.dry_run:
        out.write("  No OS keychain is available on this computer, so there is nowhere safe to "
                  "move a key to.\n  (`stuntkey doctor` says what is missing.) Nothing was changed.\n")
        return 1
    picked, notes = plan(root, catalog, backend, keychain)
    for n in notes:
        out.write(f"  note: {n}\n")
    if not picked:
        out.write("  No key found that can be moved. Nothing was changed.\n")
        return 0
    out.write(f"\n  {len(picked)} key(s) can move into the keychain, with no copying:\n")
    for c in picked:
        out.write(f"    {c.display:22} {scan_mod.printable(c.where)}   {scan_mod.printable(c.shown)}"
                  f"{'' if c.removable else '   (file is not a .env: left in place)'}\n")
    if args.dry_run:
        out.write("\n  --dry-run: nothing was changed.\n")
        return 0
    if not args.yes and not _yes("\n  Store these in the keychain? The files stay as they are. [y/N]: ",
                                 out, ask):
        out.write("  Nothing was changed.\n")
        return 5
    stored: list[Candidate] = []
    for c in picked:
        try:
            keychain.store(c.service, c.env_var, c.value, backend)
            stored.append(c)
        except keychain_mod.KeychainError as e:
            out.write(f"  {c.display}: the keychain refused it ({scan_mod.printable(e)}); not moved.\n")
    for c in stored:
        out.write(f"  stored {c.display} ({c.env_var})\n")
    if args.remove and stored:
        movable = [c for c in stored if c.removable]
        if movable and (args.yes or _yes(
                f"\n  Comment out {len(movable)} line(s) in .env files? Programs that read the "
                f"file stop seeing the key. [y/N]: ", out, ask)):
            n = _remove_lines(root, movable, out)
            out.write(f"  changed {n} line(s).\n")
    elif stored:
        out.write("\n  The keys are also still in the files above. Add --remove to comment those "
                  "lines out.\n")
    if stored:
        out.write("  An AI can now use them through stuntkey; a program of yours can start with "
                  "`stuntkey run <service> -- <command>`.\n  A key that sat in a file may have "
                  "been read by an agent already: `stuntkey rotate <service>` replaces it.\n")
    return 0 if len(stored) == len(picked) else 1
