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
CLEAN_ENV_STEP = ("Run `stuntkey clean-env` to remove the plaintext copy "
                  "(a backup is kept, and `stuntkey undo` puts it back).")

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
    # A busy computer can make the first try time out: try once more before failing.
    if not (hook.self_test(handler) or hook.self_test(handler)):
        raise RuntimeError("a test run of the safety check did not answer as expected, "
                           "so I did not switch it on (Claude Code would have been "
                           "blocked). Run `stuntkey doctor` and read the first red line, "
                           "then run `stuntkey fix` again")
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
                f"switch on the Claude Code safety check ({_p(path)}); if that check itself breaks, Claude's tool calls are blocked until `stuntkey hook uninstall` (or install it with --fail-open)"))
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
        elif not _claude_code_seen():
            out.append(Item(
                "client:none", YELLOW,
                "No AI app was found to plug stuntkey into (looked for Claude Desktop, "
                "Cursor and Claude Code).",
                "Install one of them, then run `stuntkey fix`."))
    elif not (broken or outdated):
        out.append(Item("client:ok", GREEN,
                        "stuntkey is plugged into " + ", ".join(
                            clients.LABELS.get(n, n) for n in found) + "."))
    out += _claude_code_items()
    return out


def _claude_code_seen() -> bool:
    from . import claudecode
    return claudecode.detected()


def fix_claude_code() -> None:
    """Plug stuntkey into Claude Code for every folder (its own command does
    the writing). Raises with a plain sentence when it cannot."""
    from . import claudecode, undo
    ok, why = claudecode.add_user_scope()
    if not ok:
        raise RuntimeError(why)
    undo.note_claude_user()


def _claude_code_items() -> list:
    """Claude Code, all folders. Only for a person who uses Claude Code (its
    folder exists)."""
    from . import claudecode
    if not claudecode.detected():
        return []
    state = claudecode.state()
    if state == "ok":
        return [Item("claude-code:user", GREEN,
                     "stuntkey is plugged into Claude Code for all your folders.")]
    cli = claudecode.cli_path()
    if state == "unreadable":
        return [Item("claude-code:user", YELLOW,
                     "Claude Code's own settings file (~/.claude.json) cannot be read, "
                     "so I left it alone.",
                     "Open it in Notepad and fix or delete it, then run `stuntkey fix`.")]
    what = ("is out of date" if state == "outdated" else "is not plugged into Claude Code "
            "for all your folders (only a folder that has its own .mcp.json)")
    if cli is None:
        return [Item("claude-code:user", YELLOW,
                     f"stuntkey {what}, and I cannot find the `claude` program to do it "
                     "for you.",
                     "Type this one command: " + claudecode.one_command())]
    return [Item("claude-code:user", YELLOW,
                 f"stuntkey {what}.",
                 "Run `stuntkey fix`, then close and reopen Claude Code.",
                 fix_claude_code,
                 "plug stuntkey into Claude Code for all your folders")]


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
                            "set up the activity log so any edit to it can be noticed"))
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
    """Only a note, never a warning: the port matters only to a person who
    opens the stuntkey web page (`stuntkey serve`)."""
    s = socket.socket()
    s.settimeout(0.3)
    try:
        busy = s.connect_ex(("127.0.0.1", port)) == 0
    except OSError:
        busy = False
    finally:
        s.close()
    if busy:
        it = Item("port", GREEN,
                  f"Note, not a problem: another program is using port {port}. This "
                  f"only matters if you use the stuntkey web page; then run "
                  f"`stuntkey serve --port {port + 1}`. Nothing to fix.")
        it.quiet = False
        it.note_only = True         # information, not a check that passed: shown as [i], not [ok]
        return it
    it = Item("port", GREEN, f"The web page's port ({port}) is free.")
    it.quiet = True             # nothing to say: left out of the screen
    return it


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


def key_places_full(catalog: dict | None = None, env_file: str = ".env") -> dict:
    """Where each service's key is: {"safe": [in the keychain], "loose": [ONLY in
    the .env file], "both": [in the keychain AND a plaintext copy in .env],
    "unavailable": [the keychain did not answer, so nothing could be said]}.
    An example value in a .env file (sk-xxxx, your_key_here) is not a key and
    counts for nothing. Never returns a value."""
    from . import remote
    from . import scan as scan_mod
    if catalog is None:
        catalog = recipes_mod.load_recipes()
    res = {"safe": [], "loose": [], "both": [], "unavailable": []}
    for service, recipe in sorted(catalog.items()):
        in_keychain = False
        try:
            remote.collect_values(recipe, "")           # no .env: the keychain only
            in_keychain = True
        except remote.RemoteError as e:
            if "did not answer" in str(e):
                res["unavailable"].append(service)
                continue
        in_env = False
        try:
            # round 3: the .env file is looked at even when the keychain has the key
            values = remote.collect_values(recipe, env_file, backend=False)
            in_env = all(not scan_mod.is_placeholder(str(v)) for v in values.values())
        except remote.RemoteError:
            pass
        if in_keychain and in_env:
            res["both"].append(service)
        if in_keychain:
            res["safe"].append(service)
        elif in_env:
            res["loose"].append(service)
    return res


def key_places(catalog: dict | None = None, env_file: str = ".env") -> tuple:
    """([services with a key in the keychain], [services whose key is ONLY in
    the .env file]). See key_places_full for the rest."""
    r = key_places_full(catalog, env_file)
    return r["safe"], r["loose"]


def _keys_item(catalog: dict | None, env_file: str = ".env") -> Item:
    try:
        r = key_places_full(catalog, env_file)
    except Exception:           # noqa: BLE001
        return Item("keys", YELLOW, "Could not look up which keys are saved.", "")
    have, loose, both, down = r["safe"], r["loose"], r["both"], r["unavailable"]
    if down and not have and not loose:
        return Item("keys", YELLOW,
                    "Keychain unavailable: I could not check which keys are saved "
                    "(it may be locked or busy).",
                    "Unlock your computer (sign out and in if needed), then run "
                    "`stuntkey status` again.")
    note = ""
    if loose:
        note = (f"{len(loose)} more only in a .env file, not protected: "
                + ", ".join(loose[:8]) + ("..." if len(loose) > 8 else "") + ".")
    if both:
        note = (note + " " if note else "") + (
            f"{len(both)} also have a plaintext copy in a .env file: "
            + ", ".join(both[:8]) + ("..." if len(both) > 8 else "")
            + " (remove that copy: it is a second, unprotected place for the key).")
    if down:
        note = (note + " " if note else "") + "Keychain unavailable for some: " \
            + ", ".join(down[:4]) + "."
    if have:
        text = (f"{len(have)} key(s) saved in your keychain: " + ", ".join(have[:8])
                + ("..." if len(have) > 8 else "") + ".")
        if note:
            # a key ONLY in a .env file still has to be moved; a key that is already
            # in the keychain just needs its plaintext copy taken out
            step = ("Run `stuntkey setup` to move them into the keychain." if loose
                    else CLEAN_ENV_STEP if both else "")
            return Item("keys", YELLOW, text + " " + note, step)
        return Item("keys", GREEN, text)
    if loose:
        return Item("keys", YELLOW,
                    "No key is in your keychain. " + note,
                    "Run `stuntkey setup` to move them into the keychain.")
    return Item("keys", YELLOW, "No key is saved yet.",
                "Run `stuntkey get github` (or `stuntkey try` for a practice run).")


def collect(catalog: dict | None = None, port: int = DEFAULT_PORT,
            env_file: str = ".env", include_port: bool = False) -> list:
    """Every check, as Items. `include_port`: also the web-page port note; it
    is only of use to a person who runs `stuntkey serve`, so it is left out
    unless asked for."""
    from . import hook
    items = []
    items.append(_keychain_item())
    items += _hook_items(hook.user_settings_path(), "user", required=True)
    proj = hook.project_settings_path()
    if os.path.exists(proj) and os.path.abspath(proj) != os.path.abspath(hook.user_settings_path()):
        items += _hook_items(proj, "project", required=False)
    items += _client_items()
    items += _home_items()
    items.append(_keys_item(catalog, env_file))
    if include_port:
        port_item = _port_item(port)
        if not getattr(port_item, "quiet", False):
            items.append(port_item)
    f = _files_item()
    if f:
        items.append(f)
    return items


# ----------------------------------------------------------------- the screens

def _line(it: Item) -> str:
    from . import brand
    fn = {GREEN: brand.ok, YELLOW: brand.warn, RED: brand.fail}[it.level]
    if getattr(it, "note_only", False):
        fn = brand.note
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


READY, ALMOST, ATTENTION = "ready", "almost", "attention"
STATE_WORDS = {READY: "ready", ALMOST: "almost ready", ATTENTION: "needs attention"}


def state(items: list) -> tuple:
    """THE one answer to "how is it going?": (ready | almost | attention, plain
    words). `status`, `overview`, `doctor` and `test` all use this, so they can
    never disagree."""
    lvl, words = verdict(items)
    return {GREEN: READY, YELLOW: ALMOST, RED: ATTENTION}[lvl], words


def state_sentence(items: list) -> str:
    name, words = state(items)
    return f"Overall: {STATE_WORDS[name]} ({words})."


def stale_program_warning(which=None, run=None, version=None, practice=None) -> str:
    """One plain line when the `stuntkey` found on PATH is OLDER than the
    package being run now (for example after `python -m stuntkey` from a newer
    folder while the installed program is old); "" when fine or unknown. It
    asks that program only for its version number. Never raises."""
    import re
    import shutil
    import subprocess
    from . import __version__
    version = version or __version__
    if practice is None:
        practice = bool(os.environ.get("STUNTKEY_KEYCHAIN"))
    if practice and which is None and run is None:
        return ""                   # a practice or test run never starts the real program
    try:
        exe = (which or shutil.which)("stuntkey")
        if not exe:
            return ""
        me = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
        if me and os.path.normcase(os.path.abspath(exe)) == os.path.normcase(me):
            return ""
        if run is None:
            done = subprocess.run([exe, "--version"], capture_output=True, timeout=8,
                                  stdin=subprocess.DEVNULL)
            text = (done.stdout or b"").decode("utf-8", "replace")
        else:
            text = run(exe)
        m = re.search(r"(\d+(?:\.\d+)+)", text or "")
        if not m:
            return ""
        theirs = m.group(1)
        if _version_tuple(theirs) < _version_tuple(version):
            return (f"The `stuntkey` program your computer finds first is the older "
                    f"version {theirs}, but this is {version}. Run `pipx upgrade "
                    "stuntkey` so everything uses the new one.")
    except Exception:               # noqa: BLE001 - advice only
        pass
    return ""


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
        # the same things the headline counts: only the ones that are not green
        need = sum(i.level != GREEN for i in items)
        mine = sum(i.level != GREEN for i in fixable)
        if need and mine:
            tail = (f"\n\n  I can repair {mine} of the {need} item"
                    f"{'' if need == 1 else 's'} marked above: run `stuntkey fix`.")
        else:
            tail = "\n\n  I can repair some of these for you: run `stuntkey fix`."
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


def manual_steps(items: list) -> str:
    """What `fix` cannot do by itself and a person must type: with no `claude`
    program, the exact `claude mcp add` line, and the Claude Desktop route in
    plain words. Empty when there is nothing of the kind."""
    if not any(i.key == "claude-code:user" and not i.fixer for i in items):
        return ""
    from . import claudecode
    return ("\n  By hand (I cannot find the `claude` program):\n"
            "    Claude Code: type this one command in any terminal:\n"
            f"      {_p(claudecode.one_command())}\n"
            "    Claude Desktop: no command needed. `stuntkey fix` adds stuntkey to its "
            "settings file itself\n    (Claude Desktop > Settings > Developer > Edit Config "
            "shows that file); then close and reopen it.\n")


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
        out.write(manual_steps(items))
        return 1 if any(i.level == RED for i in items) else 0
    out.write("\n  I can do this for you:\n")
    for i in fixable:
        out.write(f"    - {_p(i.fix_text or i.text)}\n")
    out.write("  Each change keeps a backup copy of the old file. Your keys are not touched.\n")
    out.write(manual_steps(items))
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
    from . import undo
    change = undo.begin("fix")
    try:
        snapshot_files(change)
        failed = apply_fixes(fixable, out)
    finally:
        change.commit()
    out.write("\n  Now I will check again.\n")
    after = (collector or collect)(catalog)
    out.write(render(after))
    if any(i.key.startswith(("hook", "client", "claude-code")) for i in fixable) and failed == 0:
        out.write("  Close and reopen Claude Code and your other AI apps so they pick "
                  "this up. Changed your mind? `stuntkey undo`.\n")
    return 1 if failed or any(i.level == RED for i in after) else 0


def snapshot_files(change) -> None:
    """Copy the files a fix may change, so `stuntkey undo` can put them back."""
    from . import clients, hook
    try:
        change.snapshot_file(hook.user_settings_path())
        proj = hook.project_settings_path()
        if os.path.exists(proj):
            change.snapshot_file(proj)
        for path, _key in clients.targets().values():
            if os.path.exists(path) or path:
                change.snapshot_file(path)
    except Exception:           # noqa: BLE001 - a missing snapshot must not stop a fix
        pass


def apply_fixes(fixable: list, out, succeeded: list | None = None) -> int:
    """Run each repair once (several items may share one). Returns how many
    failed. `succeeded`, when given, receives the items whose repair worked
    (and ONLY those: a failed step is never reported as done)."""
    failed = 0
    done_fixers = []
    for i in fixable:
        if any(i.fixer is d for d in done_fixers):
            continue
        done_fixers.append(i.fixer)
        try:
            i.fixer()
            out.write(f"  Done: {_p(i.fix_text or i.key)}\n")
            if succeeded is not None:
                succeeded.append(i)
        except Exception as e:      # noqa: BLE001
            failed += 1
            out.write(f"  Could not do this one ({_p(i.fix_text or i.key)}): "
                      f"{_p(getattr(e, 'strerror', None) or e)[:300]}\n")
    return failed


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

# ONE way in, said the same everywhere: `stuntkey` on its own, `--help`,
# `help`, `start`, the README and docs/guide.md. A test keeps them equal.
START_HERE_STEPS = [
    ("stuntkey setup", "Does it all after one yes: finds loose keys, moves them into "
                       "your keychain, switches the protection on, tests it."),
    ("stuntkey get github", "Adds a key. Use any service name; `stuntkey get` on its "
                            "own shows a short menu."),
    ("Close and reopen your AI app", "then ask it: \"Who am I on GitHub?\""),
]
START_HERE_EXTRA = [
    "Want to practise first? `stuntkey try` uses a pretend key and touches nothing real.",
    "Check it any time: `stuntkey test`. Changed your mind? `stuntkey undo`.",
]


LIMITS_TEXT = "Beta, not independently reviewed. It lowers risk; it does not stop malware or what your AI does with a key you allow. What it does not protect: `stuntkey limits`."


def _wrap_limits(indent: str = "") -> list:
    """The up-front limits notice, wrapped so no help line is wider than the screens allow."""
    import textwrap
    return textwrap.wrap(LIMITS_TEXT, 76, initial_indent=indent, subsequent_indent=indent)


def render_start_here() -> str:
    import textwrap
    lines = ["  Start here (three steps):"]
    for i, (what, text) in enumerate(START_HERE_STEPS, 1):
        lines.append(f"    {i}. {what}")
        lines += textwrap.wrap(text, 76, initial_indent="       ", subsequent_indent="       ")
    for t in START_HERE_EXTRA:
        lines += [""] if t is START_HERE_EXTRA[0] else []
        lines += textwrap.wrap(t, 76, initial_indent="  ", subsequent_indent="    ")
    return "\n".join(lines) + "\n"


GROUPS = [
    ("Get started", ["setup", "start", "try", "get", "import", "fix", "test"]),
    ("Use a key", ["run", "call", "serve", "list", "rotate", "recipe"]),
    ("Keep keys out of your AI's sight", ["install", "hook", "scan", "scan-git", "clean-env",
                                           "skill", "setup-agent", "mcp", "wrap"]),
    ("Check that it is working", ["status", "doctor", "overview", "audit", "verify",
                                   "explain", "age", "selftest",
                                   "limits", "about", "update-check", "sessions"]),
    ("Undo, stop, or recover", ["undo", "uninstall", "forget", "stop", "resume", "panic",
                                 "revoke", "migrate"]),
]

# The few commands a person uses every day. Shown by plain `stuntkey help`;
# everything else is behind `stuntkey help --all`. Fixed text, so showing
# this does not need to build the whole command parser.
EVERYDAY = [
    ("setup", "Do it all in one go: find keys, protect them, switch it on, test it."),
    ("get", "Add a key: copy it on the service's page; I name it, test it, save it."),
    ("test", "Check that it all works: one line, PASS or FAIL, and what to do next."),
    ("status", "One screen: is everything fine? Green, yellow or red."),
    ("fix", "Repair the usual problems by itself (asks once)."),
    ("undo", "Put back what setup, fix or get changed last."),
    ("run", "Start a program that needs a key. The key stays hidden."),
    ("scan", "Find keys lying around in files your AI can read."),
]


def _help_texts(parser) -> dict:
    texts = {}
    for a in getattr(parser, "_actions", []):
        if hasattr(a, "_choices_actions"):
            for c in a._choices_actions:
                texts[c.dest] = c.help or ""
    return texts


def render_everyday() -> str:
    """The short help: eight commands, in plain words."""
    lines = ["", "  stuntkey: let your AI use your API keys without holding them.",
             ""]
    lines += _wrap_limits("  ") + [""]
    lines += render_start_here().rstrip("\n").split("\n")
    lines += ["", "  The commands you use every day", ""]
    for name, text in EVERYDAY:
        lines.append(_row(name, text))
    lines += ["", "  Undo, stop, or recover",
              "    Take back the last change: stuntkey undo (shown above).",
              "    Remove one key: stuntkey forget <service>. Take it all out: stuntkey uninstall (your keys stay).",
              "    Switch everything off: stuntkey stop (stuntkey resume turns it back on).",
              "    Leaked a key: stuntkey panic <service>."]
    lines += ["", "  `stuntkey help --all` lists every command (more than 50).",
              "  `stuntkey help <command>` says more about one.",
              "  What stuntkey does NOT protect against: `stuntkey limits`."]
    return "\n".join(lines) + "\n"


def render_help(parser) -> str:
    texts = _help_texts(parser)
    shown = set()
    lines = ["", "  stuntkey: let your AI use your API keys without holding them.", ""]
    lines += render_start_here().rstrip("\n").split("\n") + [""]
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
    lines.append(f"  That is {len(shown) + len(rest)} commands in all.")
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
    if not getattr(args, "shell", None):
        out.write("  Say which shell you use:\n"
                  "    Install: stuntkey completion powershell >> $PROFILE     (Windows PowerShell)\n"
                  "    Install: stuntkey completion bash >> ~/.bashrc          (bash)\n"
                  "  Then open a new window. (Nothing is changed until you run one of those.)\n")
        return 2
    names = []
    for a in parser._actions:
        if hasattr(a, "choices") and isinstance(a.choices, dict) and "fix" in a.choices:
            names = list(a.choices)
    out.write(render_completion(args.shell, names))
    # Said as comments, so pasting the whole output into the file is harmless.
    if args.shell == "powershell":
        out.write("# Where to paste this: your PowerShell profile. Open it with\n"
                  "#   notepad $PROFILE\n"
                  "# (if it says the file does not exist: New-Item -Force $PROFILE, then try again).\n"
                  "# Paste the lines above at the end, save, and open a new PowerShell window.\n")
    else:
        out.write("# Where to paste this: the end of ~/.bashrc (on a Mac: ~/.bash_profile).\n"
                  "# Paste the lines above there, save, and open a new terminal window.\n")
    return 0
