"""One command to plug stuntkey into the AI tools people use.

`stuntkey install` finds Claude Desktop, Cursor, VS Code and Claude Code
config files, shows exactly what it would add, backs the file up, merges
(never overwrites your other servers) and writes atomically. No keys are
ever written to these files. It uses the full path of this Python so a
look-alike program on PATH cannot take its place.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time

NAME = "stuntkey"
LEGACY_NAME = "oathkey"     # the entry 0.8 wrote: `install` replaces it
PER_FOLDER = ("claude-code", "vscode")     # config lives in the project folder
NO_TERMINAL = "no terminal to answer on; re-run with --yes"
LABELS = {"claude-desktop": "Claude Desktop", "cursor": "Cursor",
          "claude-code": "Claude Code", "vscode": "VS Code"}


def _keychain_available() -> bool:
    try:
        from . import keychain as keychain_mod
        return keychain_mod.detect_backend() is not None
    except Exception:
        return False


def server_entry(keychain_ok: bool | None = None) -> dict:
    """The MCP entry. Keys an AI captures go to the OS keychain when there is
    one: that is the only place the `call_api` tool looks for them."""
    if keychain_ok is None:
        keychain_ok = _keychain_available()
    args = python_flags() + self_args() + ["mcp"]
    if keychain_ok:
        args += ["--default-store", "keychain"]
    return {"command": sys.executable, "args": args}


def self_args() -> list[str]:
    """What follows `python` to start this stuntkey again: `-m stuntkey`, or the
    path of the stuntkey.pyz it runs from (set by the .pyz's own __main__)."""
    pyz = getattr(sys.modules.get("stuntkey"), "PYZ", None)
    return [pyz] if pyz else ["-m", "stuntkey"]


def python_flags() -> list[str]:
    """Do not put the current folder on Python's path: otherwise a file named
    like a standard module, dropped into a project, would run in our place.
    -P does exactly that on 3.11+; -I is the older, stricter equivalent."""
    return ["-P"] if sys.version_info >= (3, 11) else ["-I"]


def targets(env=None, home=None, cwd=None) -> dict:
    env = os.environ if env is None else env
    home = home or os.path.expanduser("~")
    cwd = cwd or os.getcwd()
    out = {}
    if os.name == "nt":
        appdata = env.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        out["claude-desktop"] = (os.path.join(appdata, "Claude", "claude_desktop_config.json"), "mcpServers")
    elif sys.platform == "darwin":
        out["claude-desktop"] = (os.path.join(home, "Library", "Application Support",
                                              "Claude", "claude_desktop_config.json"), "mcpServers")
    else:
        out["claude-desktop"] = (os.path.join(home, ".config", "Claude",
                                              "claude_desktop_config.json"), "mcpServers")
    out["cursor"] = (os.path.join(home, ".cursor", "mcp.json"), "mcpServers")
    out["claude-code"] = (os.path.join(cwd, ".mcp.json"), "mcpServers")
    out["vscode"] = (os.path.join(cwd, ".vscode", "mcp.json"), "servers")
    return out


def where(name: str, cwd: str | None = None) -> str:
    """`claude-code (this folder only: <folder>)`; the others as they are."""
    if name in PER_FOLDER:
        return f"{name} (this folder only: {cwd or os.getcwd()})"
    return name


def _go_ahead(ask, text: str) -> bool:
    try:
        return ask(text).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        raise _NoTerminal from None


class _NoTerminal(Exception):
    pass


def plugged(tg: dict | None = None) -> list[str]:
    """The AI tools whose config file has stuntkey in it (the doctor's check)."""
    out = []
    for name, (path, key) in (targets() if tg is None else tg).items():
        try:
            with open(path, encoding="utf-8-sig") as f:
                if NAME in json.load(f).get(key, {}):
                    out.append(name)
        except (OSError, ValueError, AttributeError, TypeError):
            continue
    return out


def merged(existing: dict, key: str, entry: dict | None = None) -> dict:
    new = json.loads(json.dumps(existing))
    new.setdefault(key, {})
    if not isinstance(new[key], dict):
        raise ValueError(f"'{key}' in that file is not an object; not touching it")
    new[key][NAME] = entry or server_entry()
    return new


def plan(path: str, key: str) -> dict:
    """What would change. Never writes."""
    present = os.path.exists(path)
    existing = {}
    if present:
        with open(path, encoding="utf-8-sig") as f:
            text = f.read()
        existing = json.loads(text) if text.strip() else {}
        if not isinstance(existing, dict):
            raise ValueError("that file is not a JSON object; not touching it")
    entry = server_entry()
    new = merged(existing, key, entry)
    legacy = new[key].pop(LEGACY_NAME, None)
    return {"path": path, "present": present, "existing": existing, "new": new,
            "legacy": legacy, "entry": entry,
            "already": existing.get(key, {}).get(NAME) == entry and legacy is None,
            "others": sorted(k for k in existing.get(key, {}) if k not in (NAME, LEGACY_NAME))}


def legacy_diff(p: dict) -> str:
    """The change from 0.8's "oathkey" entry to ours, as a unified diff."""
    import difflib
    old = json.dumps({LEGACY_NAME: p["legacy"]}, indent=2).splitlines()
    new = json.dumps({NAME: p["entry"]}, indent=2).splitlines()
    return "".join(f"      {line}\n" for line in difflib.unified_diff(
        old, new, "old (oathkey 0.8)", "new (stuntkey)", lineterm=""))


def apply(p: dict) -> str | None:
    """Write p['new'] atomically; returns the backup path (or None)."""
    path = p["path"]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    backup = None
    if p["present"]:
        stamp = time.strftime('%Y%m%d-%H%M%S')
        for i in range(100):
            backup = f"{path}.bak-{stamp}" + (f"-{i}" if i else "")
            try:
                fd0 = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not create a backup file")
        with os.fdopen(fd0, "wb") as dst, open(path, "rb") as src:
            shutil.copyfileobj(src, dst)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(p["new"], f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return backup


def run(names, yes: bool, ask=input, out=print, **kw) -> int:
    try:
        return _run(names, yes, ask, out, **kw)
    except _NoTerminal:
        out(NO_TERMINAL)
        return 1


def _run(names, yes, ask, out, **kw) -> int:
    tg = targets(**kw)
    chosen = names or [n for n, (path, _) in tg.items()
                       if os.path.exists(path) or n in ("claude-code",)]
    done = 0
    unreadable = False
    for n in chosen:
        if n not in tg:
            out(f"unknown target '{n}'. Choose from: {', '.join(tg)}\n"
                "codex and gemini: run `stuntkey setup-agent codex` (or gemini)")
            return 2
        path, key = tg[n]
        try:
            p = plan(path, key)
        except json.JSONDecodeError as e:
            out(f"  {n}: NOT set up. {os.path.abspath(path)} is not valid JSON "
                f"(line {e.lineno}). Fix or delete it, then run stuntkey install "
                f"again. File left untouched.")
            unreadable = True
            continue
        except (ValueError, OSError) as e:
            out(f"  {n}: skipped - {e}")
            continue
        if p["already"]:
            out(f"  {n}: already set up.")
            continue
        out(f"  {n}: will add '{NAME}' to {path}"
            + (f" (keeps your other servers: {', '.join(p['others'])})" if p["others"] else ""))
        if p.get("legacy") is not None:
            out(f"    and replace the old '{LEGACY_NAME}' entry (0.8):\n"
                + legacy_diff(p).rstrip("\n"))
        if not yes and not _go_ahead(ask, "    go ahead? [y/N] "):
            out("    skipped.")
            continue
        b = apply(p)
        out(f"    done." + (f" Backup: {b}" if b else ""))
        done += 1
    if not chosen:
        out("no AI tools found. Name one: " + ", ".join(tg))
    elif done:
        out("\nRestart the AI tool so it loads stuntkey.")
    if chosen:                               # the doctor's connection check
        on = plugged(tg)
        out("")
        for n in chosen:
            out(f"  {LABELS.get(n, n)}: {'connected' if n in on else 'not connected'}")
    return 1 if unreadable else 0


def remove(names, yes: bool, ask=input, out=print, **kw) -> int:
    try:
        return _remove(names, yes, ask, out, **kw)
    except _NoTerminal:
        out(NO_TERMINAL)
        return 1


def _remove(names, yes, ask, out, **kw) -> int:
    """Take stuntkey out of the AI tools' config files (other servers stay)."""
    tg = targets(**kw)
    chosen = names or list(tg)
    for n in chosen:
        if n not in tg:
            out(f"unknown target '{n}'. Choose from: {', '.join(tg)}")
            return 2
        path, key = tg[n]
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8-sig") as f:
                data = json.loads(f.read() or "{}")
        except (ValueError, OSError):
            out(f"  {n}: could not read {path}; not touching it.")
            continue
        if not isinstance(data.get(key), dict) or NAME not in data[key]:
            continue
        out(f"  {n}: will remove '{NAME}' from {path}")
        if not yes and not _go_ahead(ask, "    go ahead? [y/N] "):
            out("    skipped.")
            continue
        new = json.loads(json.dumps(data))
        del new[key][NAME]
        b = apply({"path": path, "present": True, "new": new})
        out(f"    done. Backup: {b}")
    out("\nRestart the AI tool. Your saved keys were not touched "
        "(`stuntkey forget <service>` removes one).")
    return 0
