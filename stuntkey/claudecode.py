"""Plug stuntkey into Claude Code for ALL folders (its "user" scope).

`stuntkey install claude-code` only writes .mcp.json in the current folder.
Here the person's whole Claude Code is covered, using Claude Code's own
command (`claude mcp add --scope user ...`), so its file is written by the
program that owns it. When that command cannot run, the one line to type is
given instead.

Reading Claude Code's file (~/.claude.json) is read-only here.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

NAME = "stuntkey"
RUN = subprocess.run            # tests replace this; nothing real is started then
TIMEOUT = 40


def _home(home: str | None) -> str:
    return home or os.path.expanduser("~")


def config_path(home: str | None = None) -> str:
    return os.path.join(_home(home), ".claude.json")


def _practice_mode() -> bool:
    """A practice or test run (the in-memory keychain is on) must never start
    the real `claude` program, whatever is on this computer. Tests that want
    to see the commands replace RUN (and cli_path) with a stand-in."""
    return RUN is subprocess.run and bool(os.environ.get("STUNTKEY_KEYCHAIN"))


def cli_path(which=shutil.which) -> str | None:
    if _practice_mode():
        return None
    return which("claude")


def detected(home: str | None = None) -> bool:
    """The person uses Claude Code: its folder exists. (The program on PATH
    alone is not proof it was ever used; `fix` only changes things for a
    person who has the folder.)"""
    return os.path.isdir(os.path.join(_home(home), ".claude"))


def _entry() -> dict:
    from . import clients
    return clients.server_entry()


def state(home: str | None = None) -> str:
    """ok | missing | outdated | unreadable (file exists but is not JSON)."""
    path = config_path(home)
    if not os.path.exists(path):
        return "missing"
    try:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
        servers = data.get("mcpServers") if isinstance(data, dict) else None
    except (OSError, ValueError):
        return "unreadable"
    if not isinstance(servers, dict) or not isinstance(servers.get(NAME), dict):
        return "missing"
    want = _entry()
    have = servers[NAME]
    if have.get("command") == want["command"] and have.get("args") == want["args"]:
        return "ok"
    return "outdated"


def add_words() -> list:
    entry = _entry()
    return ["mcp", "add", "--scope", "user", NAME, "--", entry["command"], *entry["args"]]


def one_command() -> str:
    """The line to type when stuntkey cannot do it itself."""
    return subprocess.list2cmdline(["claude", *add_words()]) if os.name == "nt" else \
        " ".join(_quote(w) for w in ["claude", *add_words()])


def _quote(w: str) -> str:
    import shlex
    return shlex.quote(w)


def _run(words: list, which=shutil.which):
    exe = cli_path(which)
    if not exe:
        return None, "the `claude` program was not found"
    try:
        done = RUN([exe, *words], capture_output=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"`claude` did not answer ({getattr(e, 'strerror', None) or type(e).__name__})"
    return done, ""


def add_user_scope(home: str | None = None, which=shutil.which) -> tuple:
    """(ok, plain sentence). Replaces an out-of-date entry."""
    s = state(home)
    if s == "ok":
        return True, "already plugged into Claude Code (all folders)"
    if s == "unreadable":
        return False, ("Claude Code's file (~/.claude.json) cannot be read, so I left it "
                       f"alone. Fix it, or run this yourself: {one_command()}")
    if s == "outdated":
        _run(["mcp", "remove", "--scope", "user", NAME], which)
    done, why = _run(add_words(), which)
    if done is None:
        return False, f"{why}. Run this yourself: {one_command()}"
    if done.returncode != 0:
        return False, ("`claude mcp add` did not work. Run this yourself and read what "
                       f"it says: {one_command()}")
    return True, "plugged into Claude Code for all your folders"


def remove_user_scope(which=shutil.which) -> tuple:
    done, why = _run(["mcp", "remove", "--scope", "user", NAME], which)
    if done is None:
        return False, (f"{why}. To take it out yourself run: "
                       f"claude mcp remove --scope user {NAME}")
    if done.returncode != 0 and state() != "missing":
        return False, ("`claude mcp remove` did not work. Run: "
                       f"claude mcp remove --scope user {NAME}")
    return True, ""
