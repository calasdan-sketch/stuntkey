"""`stuntkey undo`: put back the last change that setup, fix or get made.

Before a change, the files it will touch are copied into
~/.stuntkey/undo/<number>/ (a private folder), and keys it saved are written
down by NAME (never by value). `undo` puts the files back as they were and
removes the keys that change added. One step back at a time; the last 10
changes are kept.

A key that a change REPLACED cannot be put back: its old value is not kept
anywhere (that would be a second copy of a secret). Setup never replaces a
key; `rotate` does, and `undo` says so.

Leaf module: it imports nothing from stuntkey at load time.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time

KEEP = 10
_CURRENT = None          # the change being recorded right now, if any


def _home() -> str:
    from . import remote
    return remote.home_dir()


def undo_dir(home: str | None = None) -> str:
    return os.path.join(home or _home(), "undo")


def _journal_path(home: str | None = None) -> str:
    return os.path.join(undo_dir(home), "journal.json")


def _private(path: str) -> None:
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _load(home: str | None = None) -> list:
    try:
        with open(_journal_path(home), encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("changes", []) if isinstance(data, dict) else []
        return [c for c in items if isinstance(c, dict)]
    except (OSError, ValueError):
        return []


def _save(changes: list, home: str | None = None) -> None:
    folder = undo_dir(home)
    _private(folder)
    fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"changes": changes}, f, indent=1)
        os.replace(tmp, _journal_path(home))
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _sha(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


class Change:
    """One recorded change. Snapshot files BEFORE touching them."""

    def __init__(self, what: str, home: str | None = None):
        self.what = what
        self.home = home
        self.id = time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"
        self.files: list = []
        self.keys: list = []
        self.claude_user = False

    def snapshot_file(self, path: str) -> None:
        path = os.path.abspath(path)
        if any(f["path"] == path for f in self.files):
            return
        entry = {"path": path, "existed": os.path.isfile(path), "snapshot": None}
        if entry["existed"]:
            folder = os.path.join(undo_dir(self.home), self.id)
            _private(folder)
            dest = os.path.join(folder, f"{len(self.files)}.snap")
            try:
                fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as dst, open(path, "rb") as src:
                    shutil.copyfileobj(src, dst)
                entry["snapshot"] = dest
            except OSError:
                return                  # cannot snapshot: do not claim it is undoable
        self.files.append(entry)

    def note_key(self, service: str, env_vars: list, store: str = "keychain") -> None:
        self.keys.append({"service": service, "env_vars": list(env_vars), "store": store})

    def note_claude_user(self) -> None:
        self.claude_user = True

    def empty(self) -> bool:
        return not (self.files or self.keys or self.claude_user)

    def commit(self) -> None:
        """Write the change down, with what each file looks like AFTER it."""
        global _CURRENT
        if _CURRENT is self:
            _CURRENT = None
        # a file that was snapshotted and not changed needs no undo step
        files = []
        for f in self.files:
            after = _sha(f["path"])
            before = _sha(f["snapshot"]) if f["snapshot"] else None
            if after == before:
                if f["snapshot"]:
                    try:
                        os.unlink(f["snapshot"])
                    except OSError:
                        pass
                continue
            files.append(dict(f, after=after))
        if not (files or self.keys or self.claude_user):
            return
        changes = _load(self.home)
        changes.append({"id": self.id, "what": self.what, "when": time.time(),
                        "files": files, "keys": self.keys,
                        "claude_user": self.claude_user})
        while len(changes) > KEEP:
            old = changes.pop(0)
            _forget_snapshots(old, self.home)
        _save(changes, self.home)


def _forget_snapshots(change: dict, home: str | None = None) -> None:
    folder = os.path.join(undo_dir(home), str(change.get("id", "")))
    if change.get("id") and os.path.isdir(folder):
        shutil.rmtree(folder, ignore_errors=True)


def begin(what: str, home: str | None = None) -> Change:
    global _CURRENT
    _CURRENT = Change(what, home)
    return _CURRENT


def current():
    return _CURRENT


def note_claude_user() -> None:
    if _CURRENT is not None:
        _CURRENT.note_claude_user()


def discard() -> None:
    global _CURRENT
    _CURRENT = None


def last(home: str | None = None):
    changes = _load(home)
    return changes[-1] if changes else None


def _what_text(c: dict) -> list:
    lines = []
    for f in c.get("files", []):
        name = os.path.basename(f["path"])
        if f["existed"]:
            lines.append(f"put back the old {name} ({f['path']})")
        else:
            lines.append(f"remove {name}, which this change made ({f['path']})")
    for k in c.get("keys", []):
        if k.get("store") == "keychain":
            lines.append(f"remove the saved {k['service']} key from your keychain")
        else:
            lines.append(f"(the {k['service']} key was saved in a file: remove it "
                         f"with `stuntkey forget {k['service']}`)")
    if c.get("claude_user"):
        lines.append("take stuntkey out of Claude Code (all folders)")
    return lines


def _restore(f: dict) -> str | None:
    """None when done, else a plain reason."""
    path = f["path"]
    try:
        if not f["existed"]:
            if os.path.isfile(path):
                os.unlink(path)
            return None
        with open(f["snapshot"], "rb") as src:
            data = src.read()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as dst:
                dst.write(data)
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return None
    except OSError as e:
        return e.strerror or str(e)


def cmd_undo(args=None, out=None, ask=None, interactive=None, home: str | None = None,
             keychain=None, claudecode=None) -> int:
    from . import recipes as recipes_mod
    p = recipes_mod.printable
    out = out or sys.stdout
    c = last(home)
    if c is None:
        out.write("  Nothing to undo: stuntkey has not changed anything here yet "
                  "(or it was already undone).\n")
        return 0
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(c.get("when", 0)))
    out.write(f"\n  The last change was `stuntkey {p(c.get('what', 'change'))}` on {when}.\n"
              "  To undo it I will:\n")
    for line in _what_text(c):
        out.write(f"    - {p(line)}\n")
    for f in c.get("files", []):
        now = _sha(f["path"])
        if now != f.get("after"):
            out.write(f"  Note: {p(os.path.basename(f['path']))} was changed again "
                      "after that. Undoing puts back the older copy.\n")
    if not getattr(args, "yes", False):
        if interactive is None:
            try:
                interactive = bool(sys.stdin and sys.stdin.isatty())
            except (OSError, ValueError):
                interactive = False
        if not interactive and ask is None:
            out.write("  Run it again in a terminal to answer, or add --yes.\n")
            return 2
        from . import safeprompt
        answer = safeprompt.ask("  Go ahead? [y/N] ", out, enter_means=False, reader=ask)
        if answer is not True:
            out.write("  Nothing was changed.\n")
            return 1
    problems = []
    for f in c.get("files", []):
        why = _restore(f)
        if why:
            problems.append(f"could not restore {os.path.basename(f['path'])}: {why}")
    if keychain is None:
        from . import keychain as keychain_mod
        keychain = keychain_mod
    for k in c.get("keys", []):
        if k.get("store") != "keychain":
            continue
        try:
            backend = keychain.detect_backend()
            if backend is None:
                raise OSError("no keychain")
            for var in k.get("env_vars", []):
                keychain.delete(k["service"], var, backend)
        except Exception as e:      # noqa: BLE001
            problems.append(f"could not remove the {k['service']} key: "
                            f"{getattr(e, 'strerror', None) or e}")
    if c.get("claude_user"):
        if claudecode is None:
            from . import claudecode as claudecode_mod
            claudecode = claudecode_mod
        ok, why = claudecode.remove_user_scope()
        if not ok:
            problems.append(why)
    if problems:
        for text in problems:
            out.write(f"  Could not finish: {p(text)}\n")
        out.write("  The rest was undone. Run `stuntkey undo` again after fixing that.\n")
        return 1
    changes = [x for x in _load(home) if x.get("id") != c.get("id")]
    _save(changes, home)
    _forget_snapshots(c, home)
    out.write("  Done. It is back the way it was. "
              + ("Close and reopen Claude so it notices.\n"
                 if c.get("files") or c.get("claude_user") else "\n"))
    return 0
