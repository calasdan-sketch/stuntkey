"""`stuntkey guard`: protect the keys you have not moved yet.

stuntkey recognises a key anywhere (in command output, in a file an agent is
about to write, in a prompt) by a salted fingerprint, but only for keys it was
told about with `get`. A key that already sits in a `.env`, a shell profile, an
`.npmrc`, an MCP config or a shell variable, and that has no well-known vendor
format (a database password, an internal token), was invisible to it.

`guard` reads those places, as `scan` does, and records the FINGERPRINT of each
value it finds. It stores no key and changes no file: the key stays where it is
and the hook now masks, blocks or refuses it wherever else it shows up (a
traceback, a history file, a transcript, a prompt, an Edit that would copy it).
Run it again to refresh: a value that is gone from every place is dropped.

What it does not do: it cannot know a key it was never shown (one that is added
later, or lives only in a password manager), and it learns nothing from a text
that has no recognisable `NAME=value` shape or vendor format except the narrow
"key is <value>" phrasing in chat history files.
"""

from __future__ import annotations

import dataclasses
import glob
import hashlib
import os
import re
import sys
import time

from . import scan as scan_mod
from . import scrub

PREFIX = "guard/"
MAX_LEARNED = 400          # fingerprints are read on every hook call: keep the file small
MAX_HISTORY_FILES = 200
HOME_SECONDS = 30.0        # for ALL the home files together: chat history can be huge

# Files in the home folder that hold a key in plain text. Relative to home.
HOME_FILES = (
    ".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", ".zshenv",
    ".bash_history", ".zsh_history", ".python_history", ".node_repl_history",
    ".npmrc", ".yarnrc", ".pypirc", ".netrc", ".git-credentials", ".gitconfig",
    ".pgpass", ".my.cnf", ".s3cfg", ".boto",
    os.path.join(".aws", "credentials"),
    os.path.join(".config", "gh", "hosts.yml"),
    os.path.join(".config", "stripe", "config.toml"),
    os.path.join(".docker", "config.json"),
    os.path.join(".kube", "config"),
    os.path.join(".claude.json"),
    os.path.join(".claude", "history.jsonl"),
    os.path.join(".claude", "settings.json"),
    os.path.join(".claude", "settings.local.json"),
)
# Claude Code keeps every chat as a file; a key pasted into one is still there.
HISTORY_GLOBS = (
    os.path.join(".claude", "projects", "*", "*.jsonl"),
)

# "my key is X", "token: X", "password = X": only in chat history files, where
# there is no NAME=value shape to go by.
_SAID_RE = re.compile(
    r"(?i)\b(?:api[ _-]?key|key|secret|token|password|passphrase|credential)s?\b"
    r"[\s\"':=,]{0,8}(?:is|are|was)?[\s\"':=,]{0,8}(?P<v>[A-Za-z0-9_\-+/=.~]{20,})")

_ENV_SKIP = frozenset({"PATH", "PWD", "OLDPWD", "HOME", "SHELL", "TERM", "USER", "LOGNAME"})


@dataclasses.dataclass
class Learned:
    source: str         # "project" | "mcp" | "home" | "environment"
    where: str          # file:line, or the variable name
    shown: str          # a shortened form, never the value


@dataclasses.dataclass
class GuardResult:
    learned: list[Learned]
    values: dict[str, str]          # fingerprint name -> value (never printed)
    notes: list[str]
    added: int = 0
    dropped: int = 0
    over_limit: int = 0


def _name(value: str) -> str:
    return PREFIX + hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def _worth_learning(value: str) -> bool:
    if len(value) < 12 or len(value) > 4096:
        return False
    if scan_mod.is_placeholder(value) or scrub.is_example_key(value):
        return False
    return True


def _env_values(environ) -> list[tuple[str, str]]:
    out = []
    for name, value in environ.items():
        if name in _ENV_SKIP or scan_mod.NOT_SECRET_NAME_RE.search(name):
            continue
        if scan_mod.SECRET_NAME_RE.search(name):
            if len(value) >= 16 and scan_mod._secret_value_ok(value):
                out.append((name, value))
        elif scan_mod.PASSWORD_NAME_RE.search(name):
            if scan_mod._password_value_ok(value):
                out.append((name, value))
    return out


CHUNK_BYTES = 1_000_000
MAX_HOME_FILE = 64 * 1_000_000      # most of a long chat history, never an endless file


def _chunks(path: str):
    """The text of a home file in pieces of about 1 MB cut at line ends (chat
    history and shell history are often many MB, past the scanner's per-file
    limit). Yields nothing for anything that is not a plain readable file;
    stops after MAX_HOME_FILE bytes, taking the END of a longer file (the
    recent part)."""
    try:
        if not os.path.isfile(path):
            return
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > MAX_HOME_FILE:
                fh.seek(size - MAX_HOME_FILE)
                fh.readline()                      # start on a whole line
            rest = b""
            while True:
                data = fh.read(CHUNK_BYTES)
                if not data:
                    break
                data = rest + data
                cut = data.rfind(b"\n")
                if cut < 0:
                    cut = len(data) if len(data) > 4 * CHUNK_BYTES else -1
                if cut < 0:
                    rest = data
                    continue
                rest, piece = data[cut + 1:], data[:cut + 1]
                if b"\0" in piece[:4096]:
                    return                         # a binary file
                yield piece.decode("utf-8", errors="replace")
            if rest and b"\0" not in rest[:4096]:
                yield rest.decode("utf-8", errors="replace")
    except OSError:
        return


def collect(root: str, home: str, catalog: dict, environ=None, *,
            include_home: bool = True, include_env: bool = True) -> GuardResult:
    """Every secret value stuntkey can find, de-duplicated. Reads only."""
    notes: list[str] = []
    found: dict[str, Learned] = {}
    values: dict[str, str] = {}

    def add(value: str, source: str, where: str) -> None:
        value = value.strip()
        if not _worth_learning(value):
            return
        key = _name(value)
        if key not in values:
            values[key] = value
            found[key] = Learned(source, where, scan_mod.redact(value))

    # 1. the project: .env files, agent instruction files, credentials
    result = scan_mod.scan_path(root, catalog)
    for f in result.findings:
        if f._value:
            add(f._value, "project", f"{f.file}:{f.line}")
    for s in result.skipped:
        if s.incomplete:
            notes.append(f"{s.path}: {s.reason}")

    # 2. MCP server configs (Claude, Cursor, VS Code, ...)
    try:
        from . import mcpwrap
        for path, _kind, _text, _strict, servers, _c in mcpwrap.find_servers(
                catalog, home, root):
            for srv in servers or []:
                for sec in srv.secrets:
                    for v in {sec.value, getattr(sec.finding, "_value", "")}:
                        if v:
                            add(v, "mcp", os.path.basename(path))
    except Exception as e:  # noqa: BLE001 - one unreadable config must not stop the rest
        notes.append(f"MCP configs could not be read ({type(e).__name__})")

    # 3. dotfiles and chat history in the home folder
    if include_home:
        rules, words = scan_mod.build_rules(catalog), scan_mod._name_tokens(catalog)
        paths = [os.path.join(home, p) for p in HOME_FILES]
        history: list[str] = []
        for g in HISTORY_GLOBS:
            history += sorted(glob.glob(os.path.join(home, g)))[:MAX_HISTORY_FILES]
        deadline = time.monotonic() + HOME_SECONDS
        for path in paths + history:
            if time.monotonic() > deadline:
                notes.append(f"stopped reading home files after {int(HOME_SECONDS)} seconds; "
                             "run `stuntkey guard` again to continue")
                break
            rel = os.path.relpath(path, home).replace("\\", "/")
            said = rel.endswith(".jsonl") or "history" in rel
            first_line = 0
            for text in _chunks(path):
                if time.monotonic() > deadline:
                    break
                for f in scan_mod.scan_text(text, rel, rules, catalog, words,
                                            scan_mod.Budget(scan_mod.FILE_SECONDS)):
                    if f._value:
                        add(f._value, "home", f"~/{rel}:{first_line + f.line}")
                if said:
                    for m in _SAID_RE.finditer(text):
                        v = m.group("v").rstrip(".,;")
                        if scan_mod.looks_random(v, 3.2) and scan_mod._secret_value_ok(v):
                            add(v, "home", f"~/{rel}:{first_line + text.count(chr(10), 0, m.start('v')) + 1}")
                first_line += text.count("\n")

    # 4. variables in this shell that look like keys (an agent inherits them)
    if include_env:
        for name, value in _env_values(os.environ if environ is None else environ):
            add(value, "environment", f"${name}")

    if len(values) > MAX_LEARNED:
        # a hostile project full of fake keys must not push out the ones in your
        # shell and home folder: each place gets its share, nearest-to-you first
        share = MAX_LEARNED // 2
        taken: list[str] = []
        for source in ("environment", "mcp", "home", "project"):
            taken += [k for k in values if found[k].source == source][:share]
        keep = taken[:MAX_LEARNED]
        over = len(values) - len(keep)
        values = {k: values[k] for k in keep}
        found = {k: found[k] for k in keep}
        return GuardResult(list(found.values()), values, notes, over_limit=over)
    return GuardResult(list(found.values()), values, notes)


def cmd_guard(args, catalog: dict, out=None, environ=None, home: str | None = None) -> int:
    out = out or sys.stdout
    home = home or os.path.expanduser("~")
    path = os.path.join(home, ".stuntkey", scrub.FINGERPRINT_FILE)
    if args.forget:
        try:
            added, dropped = scrub.replace_group(PREFIX, {}, path)
        except (OSError, ValueError) as e:
            out.write(f"  Could not update the fingerprint file ({type(e).__name__}).\n")
            return 1
        out.write(f"  Forgot {dropped} guarded value(s). Keys saved with `stuntkey get` are untouched.\n")
        return 0
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        out.write("  That is not a folder.\n")
        return 2
    res = collect(root, home, catalog, environ, include_home=not args.no_home,
                  include_env=not args.no_env)
    if args.dry_run:
        added, dropped = 0, 0
    else:
        try:
            added, dropped = scrub.replace_group(PREFIX, res.values, path)
        except (OSError, ValueError) as e:
            out.write(f"  Could not write the fingerprint file ({type(e).__name__}); "
                      "nothing was learned.\n")
            return 1
    if getattr(args, "quiet", False):
        return 0
    verb = "would learn" if args.dry_run else "learned"
    out.write(f"\n  stuntkey guard {verb} {len(res.values)} value(s). Nothing was moved, "
              "copied or changed;\n  only a salted fingerprint of each is kept, so the "
              "hook can mask or refuse it anywhere.\n\n")
    by: dict[str, list[Learned]] = {}
    for item in res.learned:
        by.setdefault(item.source, []).append(item)
    titles = {"project": "In this project", "mcp": "In MCP server settings",
              "home": "In your home folder", "environment": "In this shell's variables"}
    for source in ("project", "mcp", "home", "environment"):
        items = by.get(source)
        if not items:
            continue
        out.write(f"  {titles[source]} ({len(items)}):\n")
        for it in items[:12]:
            out.write(f"    {scan_mod.printable(it.where)}   {scan_mod.printable(it.shown)}\n")
        if len(items) > 12:
            out.write(f"    ... and {len(items) - 12} more\n")
    if res.over_limit:
        out.write(f"\n  {res.over_limit} more value(s) were not learned (limit {MAX_LEARNED}).\n")
    for note in res.notes[:5]:
        out.write(f"  note: {scan_mod.printable(note)}\n")
    if not args.dry_run and dropped:
        out.write(f"\n  {dropped} value(s) learned earlier are gone from every place and were dropped.\n")
    out.write("\n  Run it again after you add keys. To stop guarding: `stuntkey guard --forget`.\n"
              "  Better still, move a key out of its file: `stuntkey adopt`.\n")
    return 0
