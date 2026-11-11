"""Set up an AI client to use stuntkey: its MCP config, and its rules file.

`setup-agent <client>` prints (or with --write adds) the exact MCP server entry,
with the ABSOLUTE path of this Python, so the client does not depend on PATH.
`skill install --for <client>` puts the agent rules in the file that client
reads (AGENTS.md, .cursor/rules/stuntkey.mdc, GEMINI.md) inside a marked
block that is replaced on the next install and never touches the rest of the
file.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

from . import recipes as recipes_mod

CLIENTS = ("claude-code", "claude-desktop", "cursor", "codex", "gemini")
BEGIN = "<!-- stuntkey:begin (managed by `stuntkey skill install`; edits inside are replaced) -->"
END = "<!-- stuntkey:end -->"

HONEST = """
  What is enforced where (be honest with yourself about this):
    - The MCP tools never return a key: true for every client.
    - The hook that blocks an agent from reading .env files exists ONLY in Claude
      Code. Cursor, Codex, Gemini and Claude Desktop have no such hook: their agent
      can read a .env file if it tries. For those clients the OS keychain is the
      safer place for keys, and this setup uses it when one is available.
    - The permission window is shown by stuntkey itself, for every client. It is a
      real gate only against an agent that cannot run code as you; the terminal
      `allow-agent` fallback is advisory.
"""


def server_entry(client: str, keychain_ok: bool) -> dict:
    from . import clients
    args = clients.self_args() + ["mcp"]
    if keychain_ok:
        args += ["--default-store", "keychain"]
    return {"command": os.path.abspath(sys.executable), "args": args}


def config_path(client: str, home: str, cwd: str, platform: str | None = None) -> str | None:
    platform = platform or sys.platform
    if client == "claude-desktop":
        if platform == "win32":
            return os.path.join(os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming"),
                                "Claude", "claude_desktop_config.json")
        if platform == "darwin":
            return os.path.join(home, "Library", "Application Support", "Claude",
                                "claude_desktop_config.json")
        return os.path.join(home, ".config", "Claude", "claude_desktop_config.json")
    if client == "cursor":
        return os.path.join(cwd, ".cursor", "mcp.json")
    if client == "gemini":
        return os.path.join(home, ".gemini", "settings.json")
    if client == "codex":
        return os.path.join(home, ".codex", "config.toml")
    return None


def _toml(entry: dict) -> str:
    q = lambda s: json.dumps(s, ensure_ascii=False)
    return (f"[mcp_servers.stuntkey]\ncommand = {q(entry['command'])}\n"
            f"args = [{', '.join(q(a) for a in entry['args'])}]\n")


def _atomic_write(path: str, text: str, bom: bool = False) -> None:
    """Write `text` exactly as given (no newline translation), through a
    temporary file, so a crash never leaves half a config."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".sea-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8-sig" if bom else "utf-8", newline="") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_text(path: str):
    """(text, bom, eol) of an existing file, or raise ValueError with a reason."""
    with open(path, "rb") as f:
        data = f.read()
    bom = data.startswith(b"\xef\xbb\xbf")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("it is not valid UTF-8 text") from None
    return text.replace("\r\n", "\n"), bom, "\r\n" if "\r\n" in text else "\n"


def _command_line(argv: list[str], platform: str | None = None) -> str:
    """One shell-safe command line for the person to paste."""
    if (platform or sys.platform) == "win32":
        return subprocess.list2cmdline(argv)
    return " ".join(shlex.quote(a) for a in argv)


def _toml_ok(text: str) -> bool:
    """True when `text` parses as TOML (Python 3.11+). Older Pythons cannot check,
    so the answer is True there and the existing plain-text handling applies."""
    try:
        import tomllib
    except ImportError:
        return True
    try:
        tomllib.loads(text)
        return True
    except Exception:       # noqa: BLE001 - any parse problem means: do not write
        return False


_TABLE = re.compile(r"^\[mcp_servers\.stuntkey\][^\n]*\n(?:(?!\[)[^\n]*\n?)*", re.M)


def cmd_setup_agent(args, out=None, home: str | None = None, cwd: str | None = None,
                    keychain_ok: bool | None = None, platform: str | None = None) -> int:
    out = out or sys.stdout
    home = home or os.path.expanduser("~")
    cwd = cwd or os.getcwd()
    client = args.client
    if keychain_ok is None:
        from . import keychain as keychain_mod
        try:
            keychain_ok = keychain_mod.detect_backend() is not None
        except Exception:
            keychain_ok = False
    entry = server_entry(client, keychain_ok)
    path = config_path(client, home, cwd)
    if client == "claude-code":
        cmd = _command_line(["claude", "mcp", "add", "stuntkey", "--", entry["command"],
                             *entry["args"]], platform)
        out.write(f"  Run this once:\n\n    {cmd}\n\n"
                  f"  then `stuntkey hook install` (blocks the agent reading .env files)\n"
                  f"  and `stuntkey skill install`.\n")
        return 0
    shown = recipes_mod.printable(path)
    if client == "codex":
        block = _toml(entry)
        if not args.write:
            out.write(f"  Add to {shown}:\n\n{block}\n")
        else:
            existing, bom, eol = "", False, "\n"
            if os.path.isfile(path):
                try:
                    existing, bom, eol = _read_text(path)
                except (OSError, ValueError) as e:
                    out.write(f"  {shown} cannot be read ({recipes_mod.printable(e)}); I will "
                              f"not touch it. Add this by hand:\n\n{block}\n")
                    return 1
            if _TABLE.search(existing):
                new = _TABLE.sub(lambda m: block + ("\n" if m.group(0).endswith("\n\n") else ""),
                                 existing, count=1)
                what = "updated the stuntkey entry in"
            else:
                new = existing + ("\n" if existing and not existing.endswith("\n") else "") + block
                what = "added the stuntkey entry to"
            if new == existing:
                out.write(f"  {shown} already has this stuntkey entry; left alone.\n")
            elif not _toml_ok(new):
                # a table written another way (quoted, spaced, dotted, inline) would
                # be declared twice and Codex would refuse to start: check, don't guess
                out.write(f"  {shown} already mentions stuntkey in a form I cannot safely "
                          f"edit; I will not touch it. Add this by hand:\n\n{block}\n")
                return 1
            else:
                _atomic_write(path, new.replace("\n", eol), bom)
                out.write(f"  \u2713 {what} {shown} (your other entries are kept). Restart the client.\n")
    else:
        snippet = json.dumps({"mcpServers": {"stuntkey": entry}}, indent=2, ensure_ascii=False)
        if not args.write:
            out.write(f"  Add to {shown}:\n\n{snippet}\n")
        else:
            data, bom, eol = {}, False, "\n"
            if os.path.isfile(path):
                try:
                    text, bom, eol = _read_text(path)
                    data = json.loads(text) if text.strip() else {}
                except (OSError, ValueError, RecursionError) as e:
                    out.write(f"  {shown} is not valid JSON ({recipes_mod.printable(e)}); I will "
                              f"not touch it. Add the entry by hand:\n\n{snippet}\n")
                    return 1
                if not isinstance(data, dict):
                    out.write(f"  {shown} holds {type(data).__name__}, not a JSON object; I will "
                              f"not touch it. Add the entry by hand:\n\n{snippet}\n")
                    return 1
            servers = data.setdefault("mcpServers", {})
            if not isinstance(servers, dict):
                out.write(f"  \"mcpServers\" in {shown} is not an object; I will not touch it. "
                          f"Add the entry by hand:\n\n{snippet}\n")
                return 1
            same = servers.get("stuntkey") == entry
            servers["stuntkey"] = entry
            if same:
                out.write(f"  {shown} already has this stuntkey entry; left alone.\n")
            else:
                _atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False).replace("\n", eol)
                              + eol, bom)
                out.write(f"  \u2713 wrote the stuntkey entry to {shown} "
                          f"(your other entries are kept). Restart the client.\n")
    out.write(HONEST)
    if not keychain_ok:
        out.write("  No OS keychain was found, so keys will go to a .env file "
                  "(the call_api tool cannot use those).\n")
    return 0


# ------------------------------------------------------------- rules files

def rules_target(client: str, base: str) -> str | None:
    return {"codex": os.path.join(base, "AGENTS.md"),
            "cursor": os.path.join(base, ".cursor", "rules", "stuntkey.mdc"),
            "gemini": os.path.join(base, "GEMINI.md")}.get(client)


def _skill_body(text: str) -> str:
    """SKILL.md without its front matter."""
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            return text[end + 4:].lstrip("\n")
    return text


def install_rules(client: str, base: str, text: str, out) -> int:
    path = rules_target(client, base)
    block = f"{BEGIN}\n{_skill_body(text).rstrip()}\n{END}\n"
    if os.path.islink(path):
        out.write(f"  {recipes_mod.printable(path)} is a link; I will not write through it.\n")
        return 1
    existing, bom, eol = "", False, "\n"
    if os.path.isfile(path):
        try:
            existing, bom, eol = _read_text(path)
        except (OSError, ValueError) as e:
            out.write(f"  {recipes_mod.printable(path)} cannot be read "
                      f"({recipes_mod.printable(e)}); I will not touch it.\n")
            return 1
    elif os.path.exists(path):
        out.write(f"  {recipes_mod.printable(path)} is not a plain file.\n")
        return 1
    begins, ends = existing.count(BEGIN), existing.count(END)
    if begins or ends:
        if begins != 1 or ends != 1 or existing.index(BEGIN) > existing.index(END):
            out.write(f"  {recipes_mod.printable(path)} has stuntkey markers that are "
                      "doubled, missing one half, or in the wrong order; I will not guess "
                      "what to replace. Fix or delete them and run this again.\n")
            return 1
        head, rest = existing.split(BEGIN, 1)
        tail = rest.split(END, 1)[1].lstrip("\n")
        new = head + block + ("\n" + tail if tail else "")
    elif existing.strip():
        new = existing + "\n\n" + block
    else:
        header = ("---\ndescription: API keys with stuntkey\nalwaysApply: true\n---\n"
                  if client == "cursor" else "")
        new = header + block
    if new == existing:
        out.write(f"  Already up to date: {recipes_mod.printable(path)}\n")
        return 0
    _atomic_write(path, new.replace("\n", eol), bom)
    out.write(f"  \u2713 wrote the stuntkey block to {recipes_mod.printable(path)}\n")
    return 0
