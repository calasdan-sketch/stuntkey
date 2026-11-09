"""Keys written in plain text into AI clients' MCP server configs.

`stuntkey scan` reads the MCP configs of Claude Desktop, Claude Code, Cursor,
VS Code, Windsurf, Codex, Gemini CLI and Zed and reports every key in a
server's env, args, headers or url (masked, like every scan finding).

`stuntkey wrap <client> <server>` moves the keys in that server's "env" into
the OS keychain and rewrites the entry so the client starts the server
through `stuntkey run`, which hands the keys over at start. It shows the
change (keys masked), backs the file up under ~/.stuntkey/wrap-backups (the
backup still holds the old key, so it is kept out of project folders), asks
y, and `--undo` puts that one server entry back from the backup (the rest of
the file stays as it is now). A key passed on the command line or in a header
cannot be handed over that way; it is reported for a move by hand.

How `run` finds the key: by a recipe. A key whose variable is the variable of
a built-in recipe (OPENAI_API_KEY) is saved under that service. Any other key
gets a small recipe of its own, ~/.stuntkey/recipes/mcp-<server>.json, marked
unverified: its check address is a stand-in (.invalid never resolves), so it
cannot be tested and is never sent anywhere.
"""

from __future__ import annotations

import copy
import dataclasses
import difflib
import json
import os
import re
import sys
import time

from . import agentsetup
from . import clients
from . import keychain as keychain_mod
from . import recipes as recipes_mod
from . import safeprompt
from . import scan as scan_mod
from .recipes import printable

CLIENTS = ("claude-desktop", "claude-code", "cursor", "vscode", "windsurf",
           "codex", "gemini", "zed")
CONFIG_LIMIT = 20 * 1024 * 1024        # ~/.claude.json holds history: it gets big
STAND_IN_URL = "https://not-checked.invalid/"
_RUN = ["-m", "stuntkey", "run"]


def _appdata(home: str, env) -> str:
    return env.get("APPDATA") or os.path.join(home, "AppData", "Roaming")


def config_files(client: str, home: str, root: str | None, env=None,
                 platform: str | None = None) -> list[tuple[str, str]]:
    """[(path, kind)] where `client` keeps MCP servers. kind is the JSON key
    holding them, "claude.json" (top level and per project) or "toml"."""
    env = os.environ if env is None else env
    platform = platform or sys.platform
    win, mac = platform == "win32", platform == "darwin"
    out: list[tuple[str, str]] = []
    proj = (lambda *p: out.append((os.path.join(root, *p[:-1]), p[-1]))) if root \
        else (lambda *p: None)
    if client == "claude-desktop":
        out.append((agentsetup.config_path("claude-desktop", home, root or home,
                                           platform), "mcpServers"))
    elif client == "claude-code":
        out.append((os.path.join(home, ".claude.json"), "claude.json"))
        proj(".mcp.json", "mcpServers")
    elif client == "cursor":
        out.append((os.path.join(home, ".cursor", "mcp.json"), "mcpServers"))
        proj(".cursor", "mcp.json", "mcpServers")
    elif client == "vscode":
        base = (os.path.join(_appdata(home, env), "Code", "User") if win else
                os.path.join(home, "Library", "Application Support", "Code", "User")
                if mac else os.path.join(home, ".config", "Code", "User"))
        out.append((os.path.join(base, "mcp.json"), "servers"))
        proj(".vscode", "mcp.json", "servers")
    elif client == "windsurf":
        out.append((os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
                    "mcpServers"))
    elif client == "codex":
        out.append((os.path.join(env.get("CODEX_HOME") or os.path.join(home, ".codex"),
                                 "config.toml"), "toml"))
    elif client == "gemini":
        out.append((os.path.join(home, ".gemini", "settings.json"), "mcpServers"))
        proj(".gemini", "settings.json", "mcpServers")
    elif client == "zed":
        out.append((os.path.join(_appdata(home, env), "Zed", "settings.json") if win
                    else os.path.join(home, ".config", "zed", "settings.json"),
                    "context_servers"))
    return out


# --------------------------------------------------------------------- parse

_JSONC_TOKEN = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/|,(?=\s*[}\]])', re.S)


def parse(text: str, kind: str) -> tuple[dict, bool]:
    """(data, strict). strict is False for JSON with comments or trailing
    commas (Zed, VS Code): readable, but not rewritten. ValueError when it
    cannot be read at all."""
    if kind == "toml":
        try:
            import tomllib
        except ImportError:                      # Python 3.10
            raise ValueError("reading TOML needs Python 3.11 or newer") from None
        try:
            return tomllib.loads(text), True
        except tomllib.TOMLDecodeError as e:
            raise ValueError(f"not valid TOML ({e})") from None
    try:
        data, strict = json.loads(text) if text.strip() else {}, True
    except ValueError:
        try:
            data = json.loads(_JSONC_TOKEN.sub(lambda m: m.group(1) or "", text))
        except ValueError:
            raise ValueError("not valid JSON") from None
        strict = False
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    return data, strict


def containers(data: dict, kind: str):
    """(keys, {name: entry}) for every place in `data` that lists servers."""
    key = {"toml": "mcp_servers", "claude.json": "mcpServers"}.get(kind, kind)
    if isinstance(data.get(key), dict):
        yield (key,), data[key]
    if kind == "claude.json" and isinstance(data.get("projects"), dict):
        for proj, pdata in data["projects"].items():
            if isinstance(pdata, dict) and isinstance(pdata.get("mcpServers"), dict):
                yield ("projects", proj, "mcpServers"), pdata["mcpServers"]


def _parts(entry: dict) -> dict:
    """command, args, env, headers, url of an entry (Zed's older
    {"command": {"path", "args", "env"}} included)."""
    cmd = entry.get("command")
    if isinstance(cmd, dict):                    # Zed, older form
        entry = {**entry, **cmd, "command": cmd.get("path")}
    headers = {}
    for k in ("headers", "http_headers"):
        if isinstance(entry.get(k), dict):
            headers.update(entry[k])
    return {"command": entry.get("command"),
            "args": [a for a in entry.get("args") or [] if isinstance(a, str)]
            if isinstance(entry.get("args"), list) else [],
            "env": entry["env"] if isinstance(entry.get("env"), dict) else {},
            "headers": headers, "url": entry.get("url") or entry.get("httpUrl")}


# -------------------------------------------------------------------- detect

@dataclasses.dataclass
class Secret:
    where: str                 # "env" | "args" | "headers" | "url"
    name: str                  # the variable, flag or header name
    value: str                 # the whole value as written (never printed)
    finding: scan_mod.Finding


@dataclasses.dataclass
class Server:
    client: str
    path: str
    kind: str
    keys: tuple                # where the servers sit in the parsed data
    name: str
    entry: dict
    secrets: list


def _upper(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", name.lstrip("-")).upper()


class _Detector:
    def __init__(self, catalog: dict):
        self.catalog = catalog
        self.rules = scan_mod.build_rules(catalog)
        self.words = scan_mod._name_tokens(catalog)

    def check(self, name: str | None, value) -> scan_mod.Finding | None:
        """The scan's own rules on NAME="value" (or the bare value)."""
        if not isinstance(value, str) or len(value) < 8:
            return None
        line = f"{_upper(name)}={json.dumps(value)}" if name else value
        found = scan_mod.scan_text(line, "", self.rules, self.catalog, self.words)
        return found[0] if found else None

    def secrets(self, entry: dict) -> list[Secret]:
        p = _parts(entry)
        out: list[Secret] = []

        def add(where, name, value):
            f = self.check(name, value)
            if f:
                out.append(Secret(where, name or "", value, f))
        for k, v in p["env"].items():
            add("env", k, v)
        for k, v in p["headers"].items():
            add("headers", k, v)
        add("url", None, p["url"])
        args = p["args"]
        for i, a in enumerate(args):
            if a.startswith("-") and "=" in a:
                flag, _, val = a.partition("=")
                add("args", flag, val)
            elif a.startswith("-") and i + 1 < len(args) and not args[i + 1].startswith("-"):
                add("args", a, args[i + 1])
            elif not (i and args[i - 1].startswith("-") and "=" not in args[i - 1]):
                add("args", None, a)
        return out


def _locate(text: str, value: str) -> tuple[int, int]:
    for form in (json.dumps(value)[1:-1], value):
        at = text.find(form)
        if at >= 0:
            return text.count("\n", 0, at) + 1, at - (text.rfind("\n", 0, at) + 1) + 1
    return 1, 1


def _shown(path: str, home: str, root: str | None) -> str:
    for base, mark in ((root, ""), (home, "~/")):
        if base:
            try:
                rel = os.path.relpath(path, base)
            except ValueError:
                continue
            if not rel.startswith(".."):
                return mark + rel.replace("\\", "/")
    return path


def _fix(client: str, server: str, secret: Secret) -> str:
    if secret.where == "env":
        return (f"Move it into the OS keychain: `stuntkey wrap {client} {server}` "
                f"(the server then gets it at start, through `stuntkey run`). If an "
                f"AI agent could read this file, rotate the key too.")
    return (f"This key is in the server's {secret.where}, which `stuntkey wrap` "
            f"cannot hand over: rotate it, then give the server the new key in "
            f"an environment variable (\"env\") and run `stuntkey wrap {client} {server}`.")


def find_servers(catalog: dict, home: str | None = None, root: str | None = None,
                 env=None, platform: str | None = None, only: str | None = None,
                 skipped: list | None = None):
    """Every server entry in every MCP config that exists, with its keys.
    Returns [(path, kind, text, strict, [Server] or None, client)]; None when
    the file is not readable as a config. Files that cannot be read at all
    are noted in `skipped` (scan.Skipped)."""
    home = home or os.path.expanduser("~")
    detector = _Detector(catalog)
    seen: set[str] = set()
    out = []
    for client in ([only] if only else CLIENTS):
        for path, kind in config_files(client, home, root, env, platform):
            real = os.path.realpath(path)
            if real in seen or not os.path.isfile(path):
                continue
            seen.add(real)
            shown = _shown(path, home, root)
            text, why = scan_mod.read_text_safely(path, os.path.dirname(real), CONFIG_LIMIT)
            if text is None:
                if skipped is not None:
                    skipped.append(scan_mod.Skipped(shown, why or "skipped", True))
                continue
            try:
                data, strict = parse(text, kind)
            except ValueError:
                out.append((path, kind, text, False, None, client))
                continue
            servers = [Server(client, path, kind, keys, name, entry,
                              detector.secrets(entry))
                       for keys, group in containers(data, kind)
                       for name, entry in group.items() if isinstance(entry, dict)]
            out.append((path, kind, text, strict, servers, client))
    return out


def add_to_scan(result: scan_mod.ScanResult, catalog: dict, root: str,
                home: str | None = None, env=None, platform: str | None = None) -> None:
    """`stuntkey scan`: the MCP configs too. Files the folder scan already read
    (a project's .mcp.json) are not reported twice."""
    home = home or os.path.expanduser("~")
    root = os.path.abspath(root) if os.path.isdir(root) else None
    have = {(f.file, f.line, f.redacted) for f in result.findings}
    rules, words = scan_mod.build_rules(catalog), scan_mod._name_tokens(catalog)
    for path, _kind, text, _strict, servers, client in find_servers(
            catalog, home, root, env, platform, skipped=result.skipped):
        result.files_scanned += 1
        shown = _shown(path, home, root)
        if servers is None:                  # unreadable as config: plain text scan
            found = scan_mod.scan_text(text, shown, rules, catalog, words)
        else:
            found = []
            for s in servers:
                for sec in s.secrets:
                    line, col = _locate(text, sec.value)
                    found.append(dataclasses.replace(
                        sec.finding, file=shown, line=line, column=col,
                        fix=_fix(client, s.name, sec)))
        for f in found:
            if (f.file, f.line, f.redacted) not in have:
                have.add((f.file, f.line, f.redacted))
                result.findings.append(f)


# ---------------------------------------------------------------------- wrap

class WrapError(Exception):
    pass


def _slug(text: str, limit: int = 56) -> str:
    s = re.sub(r"[^a-z0-9_-]+", "-", text.lower()).strip("-_")[:limit]
    return s or "server"


def _field(var: str, used: set) -> str:
    base = re.sub(r"[^a-z0-9_]", "_", var.lower())[:28]
    base = base if base and not base[0].isdigit() else "k_" + base
    name, i = base, 2
    while name in used:
        name, i = f"{base}_{i}", i + 1
    used.add(name)
    return name


def user_recipe(slug: str, names: list[str]) -> dict:
    """A recipe that only tells `stuntkey run` which variables to hand over.
    It cannot check the key: the address is a stand-in that never resolves."""
    used: set = set()
    fields = [{"name": _field(n, used), "env_var": n, "label": n} for n in names]
    return {
        "service": slug, "display": f"{slug} (MCP server)",
        "key_url": scan_mod.INFO_URI, "env_var": names[0], "fields": fields,
        "steps": ["Made by `stuntkey wrap` from an MCP server's config.",
                  "To change the key, make a new one where it was issued and "
                  f"run `stuntkey wrap` again, or `stuntkey forget {slug}`."],
        "validate": {"method": "GET", "url": STAND_IN_URL, "expect": [200],
                     "auth": {"type": "headers", "headers": {
                         f"X-Stuntkey-{i}": "{" + f["name"] + "}"
                         for i, f in enumerate(fields, 1)}}},
        "unverified": ["the whole recipe: made by `stuntkey wrap`; its check address "
                       "is a stand-in, so the key was never tested"],
    }


def _builtin_for(var: str, catalog: dict) -> tuple[str | None, bool]:
    """(service, usable): the built-in recipe that stores `var`. usable is
    False when that recipe needs more than this one value."""
    for slug, r in catalog.items():
        if r.get("_builtin") and var in recipes_mod.env_vars(r):
            return slug, len(recipes_mod.fields(r)) == 1
    return None, False


def _is_wrapped(entry: dict) -> bool:
    args = _parts(entry)["args"]
    return any(args[i:i + 3] == _RUN or (str(args[i]).endswith(".pyz")
                                         and args[i + 1:i + 2] == ["run"])
               for i in range(len(args)))


def plan(server: Server, catalog: dict) -> dict:
    """What wrapping `server` means: groups [(service, recipe or None, [Secret])],
    manual [Secret] (not in env), new_entry."""
    if isinstance(server.entry.get("command"), dict):
        raise WrapError("this entry uses Zed's older form; change it to "
                        "\"command\": \"...\", \"args\": [...] first")
    cmd = server.entry.get("command")
    if not isinstance(cmd, str) or not cmd:
        raise WrapError("this server has no command (a remote server): there is "
                        "nothing to start through `stuntkey run`")
    if _is_wrapped(server.entry):
        raise WrapError("this server already starts through `stuntkey run`")
    moved = [s for s in server.secrets if s.where == "env"]
    manual = [s for s in server.secrets if s.where != "env"]
    if not moved:
        raise WrapError("no key in this server's env to move"
                        + (" (the keys found are in its args, headers or url: move "
                           "those by hand, see `stuntkey scan`)" if manual else ""))
    groups: list = []
    own: list[Secret] = []
    for s in moved:
        slug, usable = _builtin_for(s.name, catalog)
        if slug and not usable:
            raise WrapError(f"{s.name} belongs to the built-in '{slug}' recipe, which "
                            f"needs more than one value; set it up with `stuntkey "
                            f"get {slug}` and wrap by hand")
        if slug:
            groups.append((slug, None, [s]))
        else:
            own.append(s)
    if own:
        slug = "mcp-" + _slug(server.name)
        groups.append((slug, user_recipe(slug, [s.name for s in own]), own))
    prefix: list[str] = []
    for slug, _r, _s in groups:
        prefix += [sys.executable, *clients.python_flags(), *clients.self_args(), *_RUN[2:], slug, "--"]
    full = prefix + [cmd, *[a for a in server.entry.get("args") or []]]
    new = {**server.entry, "command": full[0], "args": full[1:]}
    rest = {k: v for k, v in (server.entry.get("env") or {}).items()
            if k not in {s.name for s in moved}}
    if rest:
        new["env"] = rest
    else:
        new.pop("env", None)
    return {"groups": groups, "manual": manual, "new_entry": new}


def _indent(text: str) -> int:
    m = re.search(r"\n([ \t]+)\S", text)
    return len(m.group(1).expandtabs(4)) if m else 2


def rewrite_json(text: str, server: Server, new_entry: dict) -> str:
    data, _ = parse(text, server.kind)
    node = data
    for k in server.keys:
        node = node[k]
    node[server.name] = new_entry
    return json.dumps(data, indent=_indent(text), ensure_ascii=False) + "\n"


def _toml_key(k: str) -> str:
    return k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else json.dumps(k)


def _toml_value(v) -> str:
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{_toml_key(k)} = {_toml_value(x)}"
                                for k, x in v.items()) + " }"
    if isinstance(v, bool):
        return "true" if v else "false"
    return json.dumps(v, ensure_ascii=False)


def _starts(line: str, key: str) -> bool:
    return re.match(r"\s*(?:" + re.escape(key) + "|" + re.escape(json.dumps(key))
                    + r")\s*=", line) is not None


def _brackets(line: str) -> int:
    bare = re.sub(r'"(?:\\.|[^"\\])*"|\'[^\']*\'|#.*', "", line)
    return bare.count("[") + bare.count("{") - bare.count("]") - bare.count("}")


def rewrite_toml(text: str, server: Server, new_entry: dict) -> str:
    """Change only [mcp_servers.<name>] (and its .env table): command, args
    and the moved env lines. The result is read back and compared with what
    was meant; anything else differing means it is refused."""
    lines = text.split("\n")
    name = re.escape(server.name) + "|" + re.escape(json.dumps(server.name))
    head = re.compile(r"\s*\[\s*mcp_servers\s*\.\s*(?:" + name + r")\s*(\.\s*env\s*)?\]\s*(#.*)?$")
    moved = set((server.entry.get("env") or {})) - set(new_entry.get("env") or {})
    out: list[str] = []
    table = None                    # None, "main", "env" or "other"
    skip = 0
    for line in lines:
        if skip:
            skip = max(0, skip + _brackets(line))
            continue
        if re.match(r"\s*\[", line):
            m = head.match(line)
            table = ("env" if m.group(1) else "main") if m else "other"
            out.append(line)
            if table == "main":
                out.append(f"command = {_toml_value(new_entry['command'])}")
                out.append(f"args = {_toml_value(new_entry['args'])}")
            continue
        drop = False
        if table == "main":
            if _starts(line, "env") and new_entry.get("env"):      # inline env table
                out.append(f"env = {_toml_value(new_entry['env'])}")
            drop = any(_starts(line, k) for k in ("command", "args", "env")) or any(
                _starts(line, f"env.{k}") for k in moved)
        elif table == "env":
            drop = any(_starts(line, k) for k in moved)
        if drop:
            skip = max(0, _brackets(line))
            continue
        out.append(line)
    new = "\n".join(out)
    try:
        import tomllib
    except ImportError:                          # Python 3.10
        raise WrapError("changing TOML needs Python 3.11 or newer") from None
    try:
        want = tomllib.loads(text)
        got = tomllib.loads(new)
    except tomllib.TOMLDecodeError:
        raise WrapError("could not change the TOML file safely; edit it by hand") from None
    want["mcp_servers"][server.name] = new_entry
    if got != want:
        raise WrapError("could not change the TOML file safely; edit it by hand")
    return new



def _mask(text: str, values) -> str:
    for v in sorted(set(values), key=len, reverse=True):
        for form in {v, json.dumps(v)[1:-1]}:
            text = text.replace(form, scan_mod.redact(v))
    return text


def _secrets_in(text: str, catalog: dict, extra=()) -> list[str]:
    rules, words = scan_mod.build_rules(catalog), scan_mod._name_tokens(catalog)
    return [f._value for f in scan_mod.scan_text(text, "", rules, catalog, words)
            if f._value] + list(extra)


def diff(old: str, new: str, path: str, values) -> str:
    lines = difflib.unified_diff(_mask(old, values).split("\n"),
                                 _mask(new, values).split("\n"),
                                 path, path + " (after)", lineterm="", n=2)
    return "\n".join("    " + printable(line) for line in lines)


# ------------------------------------------------------------------- backups

def backup_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".stuntkey", "wrap-backups")


def _index_path() -> str:
    return os.path.join(backup_dir(), "index.json")


def _index() -> list:
    try:
        with open(_index_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _write_index(items: list) -> None:
    agentsetup._atomic_write(_index_path(), json.dumps(items, indent=2) + "\n")


def save_backup(path: str, client: str, server: str) -> str:
    os.makedirs(backup_dir(), exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for i in range(100):
        dest = os.path.join(backup_dir(), f"{stamp}-{client}" + (f"-{i}" if i else "") + ".bak")
        try:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            break
        except FileExistsError:
            continue
    else:
        raise OSError("could not create a backup file")
    with os.fdopen(fd, "wb") as dst, open(path, "rb") as src:
        dst.write(src.read())
    _write_index(_index() + [{"path": os.path.abspath(path), "backup": dest,
                              "client": client, "server": server, "time": stamp}])
    return dest


# ------------------------------------------------------------------- command

def _ask(question: str, out, ask) -> bool:
    return bool(safeprompt.ask(question, out, enter_means=False, reader=ask,
                               if_key="That looked like a key. Do not paste it "
                                      "here. Type y or n."))


def wrap_one(server: Server, text: str, strict: bool, catalog: dict, *, dry_run: bool,
             out, ask=None, keychain=keychain_mod, values_seen=()) -> int:
    """0 done (or shown, with dry_run), 1 refused or declined."""
    where = f"{server.client} '{printable(server.name)}'"
    text = text.replace("\r\n", "\n")
    try:
        if not strict:
            raise WrapError("the file has comments or trailing commas; stuntkey "
                            "will not rewrite it (they would be lost). Edit it by hand")
        p = plan(server, catalog)
        new = (rewrite_toml if server.kind == "toml" else rewrite_json)(
            text, server, p["new_entry"])
    except WrapError as e:
        out.write(f"  {where}: not wrapped - {printable(e)}.\n")
        return 1
    for s in p["manual"]:
        out.write(f"  {where}: the key in its {s.where} ({s.finding.redacted}) stays; "
                  f"move it by hand.\n")
    values = [s.value for s in server.secrets] + list(values_seen)
    out.write(f"\n  {where} in {printable(server.path)}:\n")
    for slug, recipe, secs in p["groups"]:
        made = " (a new recipe of yours, marked not validated)" if recipe else ""
        for s in secs:
            out.write(f"    {s.name} ({s.finding.redacted}) -> OS keychain, service "
                      f"'{slug}'{made}\n")
    out.write(diff(text, new, server.path, values) + "\n")
    if dry_run:
        out.write("    (dry run: nothing was changed)\n")
        return 0
    backend = keychain.detect_backend()
    if backend is None:
        out.write("  No OS keychain on this system, so nothing was changed.\n")
        return 1
    replaced = []
    for slug, _r, secs in p["groups"]:
        for s in secs:
            try:
                if keychain.read(slug, s.name, backend) not in (None, s.value):
                    replaced.append(f"{slug}/{s.name}")
            except keychain.KeychainError:
                pass                # the store below says so if it cannot work
    if replaced:
        out.write(f"    This replaces the key already saved for {', '.join(replaced)}.\n")
    if not _ask(f"  Move {'these keys' if len(values) > 1 else 'this key'} and "
                f"change the file? [y/N]: ", out, ask):
        out.write("  Nothing was changed.\n")
        return 1
    try:
        for slug, recipe, _s in p["groups"]:
            if recipe:
                recipes_mod.save_recipe(recipe)
                if slug not in recipes_mod.load_recipes():
                    raise WrapError(f"the recipe '{slug}' was not accepted")
        for slug, _r, secs in p["groups"]:
            for s in secs:
                keychain.store(slug, s.name, s.value, backend)
        backup = save_backup(server.path, server.client, server.name)
        _orig, bom, eol = agentsetup._read_text(server.path)
        agentsetup._atomic_write(server.path, new.replace("\n", eol), bom)
    except (WrapError, OSError, ValueError, recipes_mod.RecipeError,
            keychain.KeychainError) as e:
        out.write(f"  {where}: stopped, the config file was not changed: "
                  f"{printable(e)}.\n")
        return 1
    out.write(f"  Done. The keys are in the {keychain.label(backend)}. Restart "
              f"{server.client} so it starts the server the new way.\n"
              f"  The backup {printable(backup)} still holds the old key: delete it "
              f"once the server works (`stuntkey wrap {server.client} --undo` uses it).\n")
    return 0


def _at(data, keys: tuple):
    for k in keys:
        data = data.get(k) if isinstance(data, dict) else None
    return data


def _undo_text(path: str, name: str, cur_t: str, old_t: str) -> str | None:
    """The current file with only the `name` entry put back as the backup has
    it, so servers added since, numStartups and every other key stay. None
    when nothing else changed since the wrap: then the backup's own bytes go
    back. WrapError when that cannot be done safely."""
    if not cur_t.strip():
        return None
    kind = "toml" if path.lower().endswith(".toml") else "json"
    try:
        old, _ = parse(old_t, kind)
        cur, strict = parse(cur_t, kind)
    except ValueError as e:
        raise WrapError(f"the config file cannot be read ({e})") from None
    kinds = ("toml",) if kind == "toml" else ("claude.json", "servers", "context_servers")
    spots = {keys for k in kinds for keys, group in containers(old, k)
             if name in group and (_at(cur, keys) or {}).get(name) != group[name]}
    if len(spots) != 1 or not isinstance(_at(cur, next(iter(spots))), dict):
        raise WrapError(f"the '{name}' entry is not where `stuntkey wrap` left it")
    keys = spots.pop()
    entry = _at(old, keys)[name]
    put_back = copy.deepcopy(cur)
    _at(put_back, keys)[name] = entry
    if put_back == old:
        return None
    if not strict:
        raise WrapError("the file now has comments or trailing commas, which "
                        "a rewrite would lose; put the entry back by hand")
    server = Server("", path, kind, keys, name, _at(cur, keys).get(name) or {}, [])
    try:
        return (rewrite_toml if kind == "toml" else rewrite_json)(cur_t, server, entry)
    except KeyError:
        raise WrapError("could not change the file safely; put the entry back by hand") from None


def undo(client: str, out, ask=None, only_path: str | None = None,
         catalog: dict | None = None) -> int:
    items = [i for i in _index() if i.get("client") == client
             and (only_path is None or i.get("path") == os.path.abspath(only_path))]
    if not items:
        out.write(f"  No `stuntkey wrap` backup for {client}.\n")
        return 1
    item = items[-1]
    try:
        with open(item["backup"], "rb") as f:
            old = f.read()
        current = open(item["path"], "rb").read() if os.path.exists(item["path"]) else b""
    except OSError as e:
        out.write(f"  Could not read the backup: {printable(e.strerror or e)}.\n")
        return 1
    cur_t, old_t = (b.decode("utf-8-sig", "replace").replace("\r\n", "\n")
                    for b in (current, old))
    name = str(item.get("server"))
    try:
        new_t = _undo_text(item["path"], name, cur_t, old_t)
    except WrapError as e:
        out.write(f"  Not restored: {printable(e)}. The backup is "
                  f"{printable(item['backup'])}.\n")
        return 1
    values = _secrets_in(cur_t + "\n" + old_t, catalog or recipes_mod.load_recipes())
    out.write(f"\n  Put back the '{printable(name)}' entry in {printable(item['path'])} "
              f"as it was before `stuntkey wrap` ({item.get('time')}):\n")
    out.write(diff(cur_t, old_t if new_t is None else new_t, item["path"], values) + "\n")
    if not _ask("  Restore it? [y/N]: ", out, ask):
        out.write("  Nothing was changed.\n")
        return 1
    if new_t is None:
        agentsetup._atomic_write(item["path"], old.decode("utf-8"))
    else:
        _orig, bom, eol = agentsetup._read_text(item["path"])
        agentsetup._atomic_write(item["path"], new_t.replace("\n", eol), bom)
    os.unlink(item["backup"])
    _write_index([i for i in _index() if i != item])
    out.write("  Restored. The key is back in that file in plain text; the copy in "
              "the OS keychain stays until `stuntkey forget <service>`.\n")
    return 0


def cmd_wrap(args, catalog: dict, out=None, ask=None, keychain=keychain_mod,
             home: str | None = None, root: str | None = None) -> int:
    out = out or sys.stdout
    root = root or os.getcwd()
    client = args.client
    if client and client not in CLIENTS:
        out.write(f"  Unknown client. Choose from: {', '.join(CLIENTS)}\n")
        return 2
    if args.undo:
        if not client:
            out.write("  Say which client: stuntkey wrap <client> --undo\n")
            return 2
        return undo(client, out, ask, args.file, catalog)
    if not args.all and not (client and args.server):
        out.write("  Usage: stuntkey wrap <client> <server>, or stuntkey wrap --all "
                  "[--dry-run]\n")
        return 2
    def matching():
        for path, _kind, text, strict, servers, _c in find_servers(
                catalog, home, root, only=client):
            if args.file and os.path.realpath(path) != os.path.realpath(args.file):
                continue
            for s in servers or []:
                if (s.name == args.server if not args.all else
                        any(x.where == "env" for x in s.secrets) and not _is_wrapped(s.entry)):
                    yield s, text, strict
    picked = list(matching())
    if not picked:
        out.write("  No MCP server with a key in its env was found.\n" if args.all else
                  f"  No server named '{printable(args.server)}' in {client}'s config.\n")
        return 1
    if not args.all and len(picked) > 1:
        out.write(f"  '{printable(args.server)}' is in {len(picked)} places; add "
                  f"--file with one of:\n" + "".join(
                      f"    {printable(s.path)}\n" for s, _t, _st in picked))
        return 2
    code = 0
    for want in picked:
        # one file can hold several servers: read it again after each change
        fresh = [m for m in matching() if (m[0].path, m[0].keys, m[0].name)
                 == (want[0].path, want[0].keys, want[0].name)]
        s, text, strict = fresh[0] if fresh else want
        others = _secrets_in(text, catalog)

        code = max(code, wrap_one(s, text, strict, catalog, dry_run=args.dry_run,
                                  out=out, ask=ask, keychain=keychain, values_seen=others))
    return code
