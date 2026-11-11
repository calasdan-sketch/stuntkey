"""`stuntkey status` (one-screen health), `stuntkey fix`, `stuntkey help`,
`stuntkey update-check` and `stuntkey completion`.

Plain words, one next step per problem. Nothing here shows a key or phones
home: the only network use is `update-check --online`, and only because the
person typed that word.

Every check returns an Item: a level (green / yellow / red), what is wrong in
plain words, the ONE next step, and - when stuntkey can repair it by itself -
a fixer. `fix` lists the repairs, asks once, and makes them. Each repair is
the same safe write the setup commands already do (backup first, other
people's entries kept, atomic)."""
from __future__ import annotations

import json
import os
import shlex
import socket
import sys

from . import recipes as recipes_mod

GREEN, YELLOW, RED = "green", "yellow", "red"
DEFAULT_PORT = 8787

# Filled in by extras.py when it loads (it owns these two helpers). They are handed
# over instead of imported so this module never imports extras/cmds/cli (that would
# add to the import cycles the release test watches).
HELPERS: dict = {"self_check": None, "ensure_log_key": None}


class Item:
    def __init__(self, key: str, level: str, text: str, step: str = "",
                 fixer=None, fix_text: str = ""):
        self.key, self.level, self.text = key, level, text
        self.step, self.fixer, self.fix_text = step, fixer, fix_text

    def as_dict(self) -> dict:
        return {"check": self.key, "level": self.level, "text": self.text,
                "next_step": self.step, "can_fix": self.fixer is not None}


def _p(x) -> str:
    return recipes_mod.printable(str(x))


# ----------------------------------------------------------------- the checks

def _program_of(handler: dict) -> str | None:
    """The program a stored hook handler would start (never run here)."""
    cmd = handler.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        return None
    if "args" in handler:
        return cmd
    try:
        tokens = shlex.split(cmd, posix=False)
    except ValueError:
        return None
    if not tokens:
        return None
    tok = tokens[0]
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        tok = tok[1:-1]
    return tok


def _program_exists(program: str | None) -> bool:
    if not program:
        return False
    if os.path.isabs(program):
        return os.path.isfile(program)
    import shutil
    return shutil.which(program) is not None


def fix_hook(path: str) -> str:
    """Install or repair our hook in the settings file `path`. Keeps every
    other hook, keeps a one-string (shell form) hook as it was, and always
    leaves the hook set to block when it fails."""
    from . import hook
    data = hook.load_settings(path)
    had = os.path.exists(path)
    shell_form = None
    try:
        groups = hook._pretool_list(data, create=False) or []
        mine = list(hook._our_handlers(groups))
        if mine and "args" not in mine[0][1] and isinstance(mine[0][1].get("command"), str):
            shell_form = True
    except hook.SettingsError:
        pass
    handler = hook.hook_handler(shell_form=shell_form, fail_closed=True)
    # Test BEFORE writing: a safety check that cannot run, set to block on failure,
    # would stop every Claude Code action.
    if not hook.self_test(handler):
        raise RuntimeError("a test run of the safety check did not answer as expected, "
                           "so I did not switch it on (Claude Code would have been "
                           "blocked). Try `pipx reinstall stuntkey`, then `stuntkey fix`")
    result = hook.merge_install(data, handler)
    if result != "unchanged":
        hook.save_settings(path, data, had)
    return result


def _hook_items(path: str, label: str, required: bool) -> list:
    from . import hook
    out = []
    try:
        data = hook.load_settings(path)
        groups = hook._pretool_list(data, create=False) or []
        post_groups = hook._pretool_list(data, create=False, event="PostToolUse") or []
    except hook.SettingsError as e:
        return [Item(f"hook:{label}", RED,
                     f"Claude Code's settings file cannot be read, so I left it alone "
                     f"({_p(e)[:160]}).",
                     f"Open {_p(path)} in Notepad, fix or delete it, then run `stuntkey fix`.")]
    mine = list(hook._our_handlers(groups))
    fixer = lambda p=path: fix_hook(p)       # noqa: E731
    if not mine:
        if required:
            out.append(Item(
                "hook:user", RED,
                "The safety check for Claude Code is not switched on, so Claude can "
                "still open your .env files.",
                "Run `stuntkey fix`.", fixer,
                f"switch on the Claude Code safety check ({_p(path)})"))
        return out
    group, handler = mine[0]
    program = _program_of(handler)
    if not _program_exists(program):
        out.append(Item(
            f"hook:{label}", RED,
            f"The safety check points at a program that is gone ({_p(program or 'unknown')}). "
            "This usually happens after an upgrade or a move. Until it is repaired, "
            "Claude Code cannot run it.",
            "Run `stuntkey fix`.", fixer,
            f"point the safety check at the program that is installed now ({_p(path)})"))
        return out
    notes = []
    if not list(hook._our_handlers(post_groups)):
        notes.append("it does not yet hide keys in what a command prints")
    elif list(hook._our_handlers(post_groups))[0][0].get("matcher") != hook.POST_MATCHER:
        notes.append("its hiding of keys in command output is out of date")
    if group.get("matcher") != hook.MATCHER:
        notes.append("it does not watch every tool this version of stuntkey does")
    if handler.get("onFailure") != "block":
        notes.append("if it breaks, Claude's action goes through instead of being stopped")
    if hook.is_legacy(handler):
        notes.append("it is the old oathkey version")
    if notes:
        out.append(Item(
            f"hook:{label}", YELLOW,
            "The Claude Code safety check works but needs updating: "
            + "; ".join(notes) + ".",
            "Run `stuntkey fix`.", fixer,
            f"update the safety check ({_p(path)})"))
    else:
        out.append(Item(f"hook:{label}", GREEN,
                        "The Claude Code safety check is switched on."
                        + (" (this project)" if label == "project" else "")))
    return out


def fix_clients(names: list) -> None:
    from . import clients
    tg = clients.targets()
    for n in names:
        path, key = tg[n]
        p = clients.plan(path, key)
        if not p["already"]:
            clients.apply(p)


def _client_items() -> list:
    """Is stuntkey plugged into the AI apps found here, and does each entry still
    point at a program that exists?"""
    from . import clients
    out, found, broken, outdated = [], [], [], []
    tg = clients.targets()
    want = clients.server_entry()
    for name, (path, key) in tg.items():
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8-sig") as f:
                data = json.loads(f.read() or "{}")
            entry = (data.get(key) or {}).get(clients.NAME)
            legacy = (data.get(key) or {}).get(clients.LEGACY_NAME)
        except (OSError, ValueError, AttributeError):
            out.append(Item(f"client:{name}", YELLOW,
                            f"{clients.LABELS.get(name, name)}'s settings file cannot be "
                            f"read ({_p(path)}), so I left it alone.",
                            "Open it in Notepad and fix or delete it, then run `stuntkey fix`."))
            continue
        if legacy is not None:
            outdated.append(name)
            found.append(name)
        if not isinstance(entry, dict):
            continue
        found.append(name)
        if not _program_exists(entry.get("command")):
            broken.append(name)
        elif entry.get("args") != want["args"]:
            outdated.append(name)
    found = sorted(set(found))
    if broken:
        names = sorted(set(broken))
        out.append(Item(
            "client:broken", RED,
            "stuntkey is plugged into " + ", ".join(clients.LABELS.get(n, n) for n in names)
            + ", but the program it points at is gone (after an upgrade or a move), "
            "so that app cannot use your keys.",
            "Run `stuntkey fix`, then restart that app.",
            lambda n=names: fix_clients(n),
            "point " + ", ".join(clients.LABELS.get(n, n) for n in names)
            + " at the program that is installed now"))
    if outdated:
        names = sorted(set(outdated) - set(broken))
        if names:
            out.append(Item(
                "client:outdated", YELLOW,
                "The stuntkey entry in " + ", ".join(clients.LABELS.get(n, n) for n in names)
                + " is out of date.",
                "Run `stuntkey fix`, then restart that app.",
                lambda n=names: fix_clients(n),
                "update the stuntkey entry in "
                + ", ".join(clients.LABELS.get(n, n) for n in names)))
    if not found:
        apps = [n for n in ("claude-desktop", "cursor") if os.path.exists(tg[n][0])]
        if apps:
            out.append(Item(
                "client:none", YELLOW,
                "stuntkey is not plugged into your AI apps yet ("
                + ", ".join(clients.LABELS[n] for n in apps) + " found).",
                "Run `stuntkey fix`, then restart that app.",
                lambda n=apps: fix_clients(n),
                "plug stuntkey into " + ", ".join(clients.LABELS[n] for n in apps)))
        else:
            out.append(Item(
                "client:none", YELLOW,
                "No AI app was found to plug stuntkey into (looked for Claude Desktop "
                "and Cursor).",
                "If you use Claude Code, open your project folder and run "
                "`stuntkey install claude-code`."))
    elif not (broken or outdated):
        out.append(Item("client:ok", GREEN,
                        "stuntkey is plugged into " + ", ".join(
                            clients.LABELS.get(n, n) for n in found) + "."))
    return out


def _keychain_item() -> Item:
    from . import keychain
    try:
        backend = keychain.detect_backend()
    except Exception:           # noqa: BLE001
        backend = None
    if backend is None:
        return Item("keychain", RED,
                    "There is no safe place on this computer to keep keys (on Windows "
                    "that is Credential Manager).",
                    "Sign out of Windows and back in, then run `stuntkey status` again.")
    try:
        keychain.read("stuntkey-health-check", "PROBE", backend)
    except Exception:           # noqa: BLE001
        return Item("keychain", RED,
                    f"{keychain.label(backend)} did not answer. It may be locked or busy.",
                    "Unlock your computer (sign out and in if needed), then run "
                    "`stuntkey status` again.")
    return Item("keychain", GREEN, f"{keychain.label(backend)} works.")


def fix_home() -> None:
    from . import remote
    remote.private_dir(remote.home_dir())
    fn = HELPERS.get("ensure_log_key")
    if fn:
        fn()


def _home_items() -> list:
    from . import remote
    home = remote.home_dir()
    try:
        os.makedirs(home, exist_ok=True)
        probe = os.path.join(home, ".health-probe")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("x")
        os.unlink(probe)
    except OSError:
        return [Item("home", RED,
                     f"stuntkey cannot write to its own folder ({_p(home)}).",
                     "Check that the folder is not read-only or inside a locked "
                     "cloud-sync folder.")]
    out = []
    try:
        from . import broker
        log = broker.AuditLog(os.path.join(home, "audit.log"))
        d = log.verify_detail()
        if not d["ok"]:
            out.append(Item("log", RED,
                            "The activity log does not check out: entries may have been "
                            "changed or removed.",
                            "Run `stuntkey audit show` to see it."))
        elif d.get("key") == "none_yet":
            out.append(Item("log", YELLOW,
                            "The activity log has no signature key yet, so it cannot "
                            "prove nobody edited it.",
                            "Run `stuntkey fix`.", fix_home,
                            "create the activity log's signature key"))
        elif d.get("key") == "unavailable" and d["n"]:
            out.append(Item("log", YELLOW,
                            "The activity log cannot be signed on this computer, so edits "
                            "to it would not be noticed.",
                            "Run `stuntkey status` again after the keychain works."))
        else:
            out.append(Item("log", GREEN,
                            f"The activity log is intact ({d['n']} entries)."))
    except Exception:           # noqa: BLE001
        out.append(Item("log", YELLOW, "The activity log could not be checked.",
                        "Run `stuntkey audit` for details."))
    return out


def _port_item(port: int) -> Item:
    s = socket.socket()
    s.settimeout(0.3)
    try:
        busy = s.connect_ex(("127.0.0.1", port)) == 0
    except OSError:
        busy = False
    finally:
        s.close()
    if busy:
        return Item("port", YELLOW,
                    f"Something is already using port {port}. Fine if it is your own "
                    "stuntkey window; otherwise the web page cannot open on that number.",
                    f"Run `stuntkey serve --port {port + 1}` to use another number.")
    return Item("port", GREEN, f"The web page's port ({port}) is free.")


def _files_item() -> Item | None:
    fn = HELPERS.get("self_check")
    if fn is None:
        return None
    try:
        res = fn()
    except Exception:           # noqa: BLE001
        return None
    if res["state"] == "changed":
        return Item("files", RED,
                    "The installed stuntkey files do not match what the installer wrote: "
                    "a file was changed or is missing.",
                    "Run `pipx reinstall stuntkey`.")
    return None


def _keys_item(catalog: dict | None) -> Item:
    from . import remote

    def has(recipe):
        try:
            remote.collect_values(recipe, ".env")
            return True
        except remote.RemoteError:
            return False
    try:
        if catalog is None:
            catalog = recipes_mod.load_recipes()
        have = [s for s, r in sorted(catalog.items()) if has(r)]
    except Exception:           # noqa: BLE001
        return Item("keys", YELLOW, "Could not look up which keys are saved.", "")
    if have:
        return Item("keys", GREEN, f"{len(have)} key(s) saved: " + ", ".join(have[:8])
                    + ("..." if len(have) > 8 else "") + ".")
    return Item("keys", YELLOW, "No key is saved yet.",
                "Run `stuntkey get github` (or `stuntkey try` for a practice run).")


def collect(catalog: dict | None = None, port: int = DEFAULT_PORT) -> list:
    from . import hook
    items = []
    items.append(_keychain_item())
    items += _hook_items(hook.user_settings_path(), "user", required=True)
    proj = hook.project_settings_path()
    if os.path.exists(proj) and os.path.abspath(proj) != os.path.abspath(hook.user_settings_path()):
        items += _hook_items(proj, "project", required=False)
    items += _client_items()
    items += _home_items()
    items.append(_keys_item(catalog))
    items.append(_port_item(port))
    f = _files_item()
    if f:
        items.append(f)
    return items


# ----------------------------------------------------------------- the screens

def _line(it: Item) -> str:
    from . import brand
    fn = {GREEN: brand.ok, YELLOW: brand.warn, RED: brand.fail}[it.level]
    text = fn(_p(it.text))
    if it.step and it.level != GREEN:
        text += f"\n      Next: {_p(it.step)}"
    return "  " + text


def verdict(items: list) -> tuple:
    red = sum(i.level == RED for i in items)
    yellow = sum(i.level == YELLOW for i in items)
    if red:
        return RED, ("needs attention: " + (f"{red} problem" if red == 1 else f"{red} problems")
                     + (f", {yellow} to look at" if yellow else ""))
    if yellow:
        return YELLOW, "working; " + (f"{yellow} thing to look at" if yellow == 1
                                      else f"{yellow} things to look at")
    return GREEN, "everything is fine"


def render(items: list) -> str:
    from . import __version__
    lvl, words = verdict(items)
    order = {RED: 0, YELLOW: 1, GREEN: 2}
    rows = sorted(items, key=lambda i: order[i.level])
    head = f"\n  stuntkey {__version__}: {words}\n"
    body = "\n".join(_line(i) for i in rows)
    fixable = [i for i in items if i.fixer]
    tail = ""
    if fixable:
        tail = ("\n\n  I can repair " + str(len(fixable)) + " of these for you: run "
                "`stuntkey fix`.")
    return head + "\n" + body + tail + "\n"


def cmd_health(args=None, catalog=None, out=None) -> int:
    out = out or sys.stdout
    items = collect(catalog)
    if args is not None and getattr(args, "json", False):
        lvl, words = verdict(items)
        out.write(json.dumps({"overall": lvl, "summary": words,
                              "checks": [i.as_dict() for i in items]}, indent=2) + "\n")
    else:
        out.write(render(items))
    return 1 if any(i.level == RED for i in items) else 0


def cmd_fix(args, catalog=None, out=None, ask=None, collector=None) -> int:
    out = out or sys.stdout
    items = (collector or collect)(catalog)
    fixable = [i for i in items if i.fixer]
    if getattr(args, "json", False) and not getattr(args, "yes", False):
        out.write(json.dumps({"fixable": [i.as_dict() for i in fixable]}, indent=2) + "\n")
        return 0
    if not fixable:
        out.write(render(items))
        out.write("  Nothing I can repair by myself.\n")
        return 1 if any(i.level == RED for i in items) else 0
    out.write("\n  I can do this for you:\n")
    for i in fixable:
        out.write(f"    - {_p(i.fix_text or i.text)}\n")
    out.write("  Each change keeps a backup copy of the old file. Your keys are not touched.\n")
    if not getattr(args, "yes", False):
        if not sys.stdin or not sys.stdin.isatty():
            out.write("  Run it again in a terminal to answer, or add --yes.\n")
            return 1
        try:
            if (ask or input)("  Go ahead? [y/N] ").strip().lower() not in ("y", "yes"):
                out.write("  Not changed.\n")
                return 0
        except (EOFError, KeyboardInterrupt, OSError):
            out.write("  Not changed.\n")
            return 0
    failed = 0
    done_fixers = []
    for i in fixable:
        if any(i.fixer is d for d in done_fixers):
            continue
        done_fixers.append(i.fixer)
        try:
            i.fixer()
            out.write(f"  Done: {_p(i.fix_text or i.key)}\n")
        except Exception as e:      # noqa: BLE001
            failed += 1
            out.write(f"  Could not do this one ({_p(i.fix_text or i.key)}): "
                      f"{_p(getattr(e, 'strerror', None) or e)[:200]}\n")
    out.write("\n  Now I will check again.\n")
    after = (collector or collect)(catalog)
    out.write(render(after))
    if any(i.key.startswith(("hook", "client")) for i in fixable) and failed == 0:
        out.write("  Restart Claude Code and your other AI apps so they pick this up.\n")
    return 1 if failed or any(i.level == RED for i in after) else 0


# ----------------------------------------------------------------- limits

LIMITS = [
    ("It lowers the risk. It cannot make it zero.",
     "No independent security expert has reviewed StuntKey yet. It is beta software."),
    ("It cannot stop an AI misusing a key it is allowed to use.",
     "If you let your AI read your GitHub, it can read everything that key can read. "
     "Give each key only the permissions it needs, on the service's own website."),
    ("It does not protect you from a virus or a person already using your account.",
     "Anything running as you on this computer can open your keychain, edit the "
     "activity log and click the permission windows. For risky AI tools, use a "
     "separate Windows account."),
    ("The Claude Code safety check is a guard, not a wall.",
     "It looks for known tricks, and a determined or sneaky command can still get "
     "past it. It cannot hide keys from what Claude reads with Read, Grep or web "
     "tools; those are only checked before they run."),
    ("Other AI apps have no safety check.",
     "Cursor, Codex, Gemini and Claude Desktop have no place for one, so their file "
     "tools can read a .env file."),
    ("It does not hide your data.",
     "Answers from a service go to your AI, and so to the AI company. Only the key "
     "is hidden, not the rest."),
    ("A program started with `stuntkey run` holds the key.",
     "That program can print it. Only start programs you trust this way."),
    ("It cannot catch every disguise.",
     "Hiding a key inside an answer (odd letter shapes, compressed or scrambled "
     "text) is checked on a best-effort basis."),
    ("The clipboard and screen are not covered.",
     "While you copy a key, other programs or clipboard history may see it for a "
     "moment. Screenshots are not checked."),
    ("The activity log shows accidents and casual edits, not a determined attacker.",
     "Someone using your account can rewrite it."),
    ("It does not phone home.",
     "StuntKey sends nothing about you. It talks only to the services you call. "
     "`stuntkey update-check --online` is the one thing that looks outside, and "
     "only when you type it."),
]


def render_limits() -> str:
    lines = ["", "  What StuntKey does NOT protect against", ""]
    for i, (head, body) in enumerate(LIMITS, 1):
        import textwrap
        lines.append(f"  {i}. {head}")
        for ln in textwrap.wrap(body, 72):
            lines.append(f"     {ln}")
        lines.append("")
    lines.append("  More detail: docs/THREAT_MODEL.md in the project.")
    return "\n".join(lines) + "\n"


def cmd_limits(args=None, out=None) -> int:
    (out or sys.stdout).write(render_limits())
    return 0


# ----------------------------------------------------------------- help

GROUPS = [
    ("Get started", ["start", "try", "get", "import", "fix"]),
    ("Use a key", ["run", "call", "setup", "serve", "list", "rotate"]),
    ("Keep keys out of your AI's sight", ["install", "hook", "scan", "scan-git",
                                           "skill", "setup-agent", "mcp", "wrap"]),
    ("Check that it is working", ["status", "doctor", "overview", "audit", "selftest",
                                   "limits", "about", "update-check"]),
    ("Undo, stop, or recover", ["uninstall", "forget", "stop", "resume", "panic",
                                 "migrate"]),
]


def _help_texts(parser) -> dict:
    texts = {}
    for a in getattr(parser, "_actions", []):
        if hasattr(a, "_choices_actions"):
            for c in a._choices_actions:
                texts[c.dest] = c.help or ""
    return texts


def render_help(parser) -> str:
    texts = _help_texts(parser)
    shown = set()
    lines = ["", "  stuntkey: let your AI use your API keys without holding them.", ""]
    for title, names in GROUPS:
        lines.append(f"  {title}")
        for n in names:
            if n in texts:
                lines.append(_row(n, texts[n]))
                shown.add(n)
        lines.append("")
    rest = [n for n in texts if n not in shown]
    if rest:
        lines.append("  More (for people who know what they need)")
        for n in sorted(rest):
            lines.append(_row(n, texts[n]))
        lines.append("")
    lines.append("  `stuntkey <command> --help` says more about one command.")
    lines.append("  Something wrong? `stuntkey fix` repairs the common problems.")
    lines.append("  What stuntkey does NOT protect against: `stuntkey limits`.")
    return "\n".join(lines) + "\n"


def _short(text: str) -> str:
    """The first sentence, never cut in the middle of a word."""
    text = " ".join(str(text).split())
    first = text.split(". ")[0].rstrip(".")
    if len(first) <= 72:
        return first
    cut = first[:69].rsplit(" ", 1)[0].rstrip(",:;")
    return cut + " ..."


def _row(name: str, text: str) -> str:
    return f"    stuntkey {name:<14} {_short(text)}"


# ----------------------------------------------------------------- update-check

PYPI_URL = "https://pypi.org/pypi/stuntkey/json"


def _version_tuple(v: str) -> tuple:
    parts = []
    for piece in str(v).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def cmd_update_check(args, out=None, fetch=None) -> int:
    from . import __version__
    out = out or sys.stdout
    out.write(f"  You have stuntkey {__version__}.\n")
    if not getattr(args, "online", False):
        out.write("  I did not look online: stuntkey never contacts anyone unless you ask.\n"
                  "  To look for a newer version, run `stuntkey update-check --online`\n"
                  "  (it asks pypi.org for the latest version number and sends nothing "
                  "about you).\n"
                  "  Or just upgrade: `pipx upgrade stuntkey`.\n")
        return 0
    try:
        if fetch is None:
            import urllib.request
            with urllib.request.urlopen(PYPI_URL, timeout=6) as r:   # noqa: S310
                body = r.read(200_000)
        else:
            body = fetch(PYPI_URL)
        latest = json.loads(body)["info"]["version"]
    except Exception:           # noqa: BLE001
        out.write("  I could not reach pypi.org (no internet, or stuntkey is not "
                  "published there yet). Nothing is wrong with your copy.\n")
        return 0
    if _version_tuple(latest) > _version_tuple(__version__):
        out.write(f"  A newer version, {_p(latest)}, is available. Upgrade with: "
                  "`pipx upgrade stuntkey`\n")
    else:
        out.write("  You have the newest version.\n")
    return 0


# ----------------------------------------------------------------- completion

def render_completion(shell: str, names: list) -> str:
    words = " ".join(sorted(set(names)))
    if shell == "bash":
        return (f'_stuntkey() {{ COMPREPLY=( $(compgen -W "{words}" -- '
                '"${COMP_WORDS[COMP_CWORD]}") ); }\n'
                "complete -F _stuntkey stuntkey\n")
    quoted = ", ".join(f"'{w}'" for w in sorted(set(names)))
    return ("Register-ArgumentCompleter -Native -CommandName stuntkey -ScriptBlock {\n"
            "    param($wordToComplete, $commandAst, $cursorPosition)\n"
            f"    @({quoted}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} |\n"
            "        ForEach-Object { [System.Management.Automation.CompletionResult]::new("
            "$_, $_, 'ParameterValue', $_) }\n"
            "}\n")


def cmd_completion(args, parser, out=None) -> int:
    out = out or sys.stdout
    names = []
    for a in parser._actions:
        if hasattr(a, "choices") and isinstance(a.choices, dict) and "fix" in a.choices:
            names = list(a.choices)
    out.write(render_completion(args.shell, names))
    if args.shell == "powershell":
        out.write("# To keep it: add the lines above to your PowerShell profile "
                  "(run `notepad $PROFILE`).\n")
    return 0
