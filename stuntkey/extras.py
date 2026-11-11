"""Commands for using a key through the broker (the agent never gets it), and the
checks around it: call, audit, serve, selftest, start, overview, install,
uninstall, remote, trust-server, deploy, scan-git, doctor.

Kept apart from cli.py so the key-capture commands and these stay separate."""
from __future__ import annotations

import argparse
import difflib
import os
import sys

from . import fixcmd
from . import recipes as recipes_mod

COMMANDS = {"remote", "trust-server", "deploy", "install", "uninstall", "start",
            "overview", "audit", "call", "serve", "selftest", "scan-git", "doctor",
            "try", "import", "fix", "update-check", "limits", "test", "check", "try-it",
            "undo", "recipe"}

NEEDS_NEWER = ("This needs a newer stuntkey than the one that is installed. "
               "Run `pipx upgrade stuntkey`, then try again.")


PER_FOLDER_NOTE = ("Run this in your project folder. claude-code and vscode are set up for "
                   "this folder only (.mcp.json, .vscode/mcp.json); claude-desktop and "
                   "cursor once for all projects.")


def add_parsers(sub) -> None:
    rm = sub.add_parser("remote", help="Use a stored key on another machine over "
                                       "ssh (key goes over stdin, never on a command line).",
                        usage="stuntkey remote [options] SERVICE HOST -- COMMAND [ARG ...]",
                        description="Run COMMAND on HOST with SERVICE's key in its "
                                    "environment. Everything after `--` is the command "
                                    "that runs on the far side.")
    rm.add_argument("service", help="Service slug.")
    rm.add_argument("host", help="user@host to ssh into (key-based login).")
    rm.add_argument("--as", dest="run_as", default=None,
                    help="Run the command as this user on the far side (runuser).")
    rm.add_argument("--env-file", default=".env",
                    help="Read the key from this .env file if the keychain has none.")
    rm.add_argument("--ssh-arg", action="append", default=[],
                    help="Extra ssh argument, e.g. --ssh-arg=-i --ssh-arg=~/.ssh/key")
    rm.set_defaults(command=[])   # the part after -- (split off in cli._main)

    sg = sub.add_parser("scan-git", help="Look through git history (or what is about to "
                                         "be committed) for API keys. Never prints a key.")
    sg.add_argument("path", nargs="?", default=".", help="The repository (default: here).")
    sg.add_argument("--staged", action="store_true",
                    help="Only what is about to be committed (for the pre-commit hook).")
    sg.add_argument("--install-hook", action="store_true",
                    help="Install a git pre-commit hook that blocks commits containing keys.")
    sg.add_argument("--json", action="store_true", help="Machine-readable output.")

    dc = sub.add_parser("doctor", help="Check this computer is ready (keychain, ssh, git, "
                                       "and stuntkey's own self-attack test).")
    dc.add_argument("--json", action="store_true", help="Machine-readable output.")
    dc.add_argument("--fix", action="store_true",
                    help="After the check, offer to repair what stuntkey can repair by "
                         "itself (same as `stuntkey fix`).")
    dc.add_argument("--yes", action="store_true",
                    help="With --fix: do not ask first (for scripts).")
    dc.add_argument("--self", dest="self_check", action="store_true",
                    help="Instead: check the installed stuntkey files have not been "
                         "changed since you installed them.")

    # DEPRECATED, to be removed at 1.0: trust-server / deploy / remote.
    # These make ssh keys and run commands on someone else's machine -- by far
    # the largest attack surface in stuntkey -- for a capability nobody has
    # asked for. Keeping it means every security review, and every future
    # change to the broker, has to reason about remote execution too. The tool
    # is for keeping credentials out of an agent's reach on THIS machine.
    ts = sub.add_parser("trust-server", help="DEPRECATED (removed at 1.0). Make a server "
                                             "trust this PC (makes an ssh key, installs "
                                             "it, proves it works).")
    ts.add_argument("host", help="user@host")

    dp = sub.add_parser("deploy", help="DEPRECATED (removed at 1.0). One step: trust the "
                                       "server, send the key, git pull, optionally restart.")
    dp.add_argument("host", help="user@host")
    dp.add_argument("--service", default="github", help="Key to use (default github).")
    dp.add_argument("--dir", required=True, help="Repository folder on the server.")
    dp.add_argument("--as", dest="run_as", default=None,
                    help="Run git as this user on the server (needs root login).")
    dp.add_argument("--then", default=None,
                    help="A command line to run on the server afterwards, e.g. "
                         "'systemctl restart myapp'.")
    dp.add_argument("--env-file", default=".env",
                    help="Read the key from this .env file if the keychain has none.")

    ins = sub.add_parser("install", help="Plug stuntkey into your AI tools (Claude "
                                         "Desktop, Cursor, VS Code, Claude Code). Shows "
                                         "the change and asks first. Run it in your "
                                         "project folder: Claude Code and VS Code are "
                                         "set up per folder; Claude Desktop and Cursor "
                                         "once for all projects.",
                         description=PER_FOLDER_NOTE)
    ins.add_argument("targets", nargs="*", help="claude-desktop, cursor, claude-code, vscode "
                                                "(default: the ones found)")
    ins.add_argument("--yes", action="store_true", help="Do not ask (for scripts)")
    un = sub.add_parser("uninstall", help="Undo the setup: take stuntkey out of your AI "
                                          "tools' settings and switch the Claude Code "
                                          "safety check off (your saved keys are not "
                                          "touched).",
                          description=PER_FOLDER_NOTE + " Also removes the Claude Code "
                                      "safety check from ~/.claude/settings.json (other "
                                      "hooks stay). Use --keep-hook to leave that one.")
    un.add_argument("targets", nargs="*")
    un.add_argument("--yes", action="store_true", help="Do not ask (for scripts)")
    un.add_argument("--keep-hook", action="store_true",
                    help="Do not touch the Claude Code safety check.")
    fx = sub.add_parser("fix", help="Repair the common problems by itself (safety check "
                                    "missing, program moved after an upgrade, AI app "
                                    "not plugged in).",
                        description="Looks for the usual problems, lists what it can "
                                    "repair, asks once, repairs, and checks again. Every "
                                    "changed file is backed up first. Your keys are not "
                                    "touched.")
    fx.add_argument("--yes", action="store_true", help="Do not ask first (for scripts).")
    fx.add_argument("--json", action="store_true",
                    help="Only list what could be repaired, as JSON (changes nothing "
                         "unless --yes is also given).")
    hp = sub.add_parser("help", help="The commands you use every day; --all lists "
                                     "every command.")
    hp.add_argument("topic", nargs="?", default=None,
                    help="A command name, for more about that one.")
    hp.add_argument("--all", action="store_true",
                    help="List every command, grouped by what you want to do.")
    for tname in ("test", "check", "try-it"):       # check and try-it are the same command
        kw = {"help": "Check that it all works: one line, PASS or FAIL, and the "
                      "next step."} if tname == "test" else {}
        tp = sub.add_parser(tname, **kw,
                            description="Sends a pretend AI call through stuntkey to a "
                                        "tiny pretend server on this computer, and "
                                        "checks your safe store, Claude Code's safety "
                                        "check and that your AI app is plugged in. "
                                        "Prints ONE line: PASS or FAIL, and the one "
                                        "next step. Nothing real is used.")
        tp.add_argument("--verbose", action="store_true",
                        help="Also list every problem, not just the first.")
    ud = sub.add_parser("undo", help="Put back what setup, fix or get changed last.",
                        description="Reverses the last change made by `stuntkey setup`, "
                                    "`fix` or `get`, using the copies it made first: "
                                    "settings files go back as they were, and keys that "
                                    "change added are removed from the keychain. A key "
                                    "that `rotate` replaced cannot come back (its old "
                                    "value is not kept). Asks first.")
    ud.add_argument("--yes", action="store_true", help="Do not ask first (for scripts).")
    rc = sub.add_parser("recipe", help="Look at, or approve, recipes you made yourself.")
    rcs = rc.add_subparsers(dest="recipe_cmd", required=True)
    rcs.add_parser("list", help="Your own recipes and whether each is approved.")
    ra = rcs.add_parser("approve", help="Approve one of your own recipes, so it may "
                                        "be used with real keys (asks first).")
    ra.add_argument("service", help="The recipe's service name.")
    rr = rcs.add_parser("revoke", help="Take back the approval of one of your own recipes.")
    rr.add_argument("service", help="The recipe's service name.")
    uc = sub.add_parser("update-check", help="Say which version you have, and (only if you "
                                              "ask) whether a newer one exists.")
    uc.add_argument("--online", action="store_true",
                    help="Ask pypi.org for the latest version number. Nothing else is sent.")
    sub.add_parser("limits", help="What StuntKey does NOT protect you from, in plain words.")
    cp = sub.add_parser("completion", help="Print a script that completes stuntkey "
                                           "commands when you press Tab.")
    cp.add_argument("shell", choices=["powershell", "bash"])
    st = sub.add_parser("start", help="First run: check this computer, look for loose "
                                      "keys, and say what to do next.",
                      description="Run it in your project folder.")
    st.add_argument("--simple", action="store_true",
                    help="Plain-English setup, one question at a time, for apps "
                         "made with Lovable, Bolt, Replit or Vercel.")
    ov = sub.add_parser("overview", help="What is connected, and is the activity log intact.")
    ov.add_argument("--json", action="store_true", help="Machine-readable output.")
    ov.add_argument("--env-file", default=".env")
    au = sub.add_parser("audit", help="Check the activity log has not been tampered with.")
    au.add_argument("action", nargs="?", default="verify", choices=["verify", "show", "reset"],
                    help="verify (the default): check the log; show: list the last calls; "
                         "reset: start a fresh log after a problem (the old one is kept)")
    au.add_argument("--json", action="store_true")
    au.add_argument("--last", type=int, default=20, help="how many entries to show")
    ca = sub.add_parser("call", help="Call a connected service's API; the key is "
                                     "added for you and hidden from the output.")
    ca.add_argument("service")
    ca.add_argument("method", help="GET, or POST/PUT/PATCH/DELETE (asks you first).")
    ca.add_argument("path", help="like /user")
    ca.add_argument("--query", action="append", default=[], help="name=value (repeatable)")
    ca.add_argument("--data", default=None, help="JSON body for POST/PUT/PATCH")
    ca.add_argument("--json", action="store_true")
    ca.add_argument("--env-file", default=".env")
    sv = sub.add_parser("serve", help="Open a private page and doorway on this computer, for AI tools that cannot plug in "
                                      "(OpenAI-style functions, Ollama, scripts).")
    sv.add_argument("--port", type=int, default=8787)
    sv.add_argument("--env-file", default=".env")
    tr = sub.add_parser("try", help="Practice with a pretend key. Nothing real is touched.",
                        description="A guided practice run: add a pretend key, use it, "
                                    "forget it. It uses a throwaway store and a "
                                    "temporary folder - your real keys, keychain and "
                                    "activity log are never touched.")
    tr.add_argument("--auto", action="store_true",
                    help="Go through every step without waiting for Enter.")
    im = sub.add_parser("import", help="Move keys from a .env file, or a 1Password / "
                                       "Bitwarden / Doppler export, into the keychain.",
                        description="Reads the file, shows the NAMES it found (never "
                                    "the values), asks, saves them in the OS keychain, "
                                    "then tells you to delete the file. Names stuntkey "
                                    "does not know are left alone. Formats: .env, "
                                    "JSON (Doppler or Bitwarden), CSV (1Password or "
                                    "Bitwarden).")
    im.add_argument("file", nargs="?", default=None,
                    help="The file to read. Leave it out with --paste.")
    im.add_argument("--paste", action="store_true",
                    help="Paste NAME=value lines yourself (hidden); an empty line ends it.")
    im.add_argument("--yes", action="store_true", help="Do not ask first (for scripts).")
    im.add_argument("--delete-source", action="store_true",
                    help="After saving, overwrite the file and delete it.")
    stp = sub.add_parser("selftest", help="Attack stuntkey with a made-up key and a pretend "
                                          "server; shows how many attacks it stopped.")
    stp.add_argument("--json", action="store_true")
    stp.add_argument("--verbose", action="store_true",
                     help="list every attack, not just the groups")


def install_facts() -> dict:
    """Where this stuntkey is: the program file, the version, the folder it
    lives in. Used by `stuntkey about`."""
    import os
    from . import __version__
    exe = sys.argv[0] if sys.argv and sys.argv[0] else ""
    try:
        exe = os.path.abspath(exe) if exe else ""
    except OSError:
        pass
    return {"version": __version__, "program": exe or "(unknown)",
            "python": sys.executable or "(unknown)",
            "install_folder": os.path.dirname(os.path.abspath(__file__))}


def about_extra() -> str:
    f = install_facts()
    return (f"  Version:           {recipes_mod.printable(f['version'])}\n"
            f"  Program file:      {recipes_mod.printable(f['program'])}\n"
            f"  Installed in:      {recipes_mod.printable(f['install_folder'])}\n"
            f"  Python used:       {recipes_mod.printable(f['python'])}\n")


def self_check(dist=None) -> dict:
    """Hash the installed stuntkey files against the list the installer wrote
    (the wheel's RECORD file). {"state": "ok"|"changed"|"unavailable",
    "checked": n, "changed": [paths], "missing": [paths], "why": text}."""
    import base64
    import hashlib
    import os
    res = {"state": "unavailable", "checked": 0, "changed": [], "missing": [], "why": ""}
    try:
        from importlib import metadata
        dist = dist or metadata.distribution("stuntkey")
        files = list(dist.files or [])
    except Exception:           # noqa: BLE001
        res["why"] = ("stuntkey was not installed with pip or pipx, so there is no "
                      "install list to compare against")
        return res
    hashed = [p for p in files if getattr(p, "hash", None)
              and p.suffix != ".pyc" and p.name != "RECORD"]
    if not hashed:
        res["why"] = ("this looks like a developer install (the installer did not "
                      "record what each file should look like), so there is nothing "
                      "to compare against")
        return res
    for p in hashed:
        try:
            target = str(p.locate())
            algo = p.hash.mode
            with open(target, "rb") as fh:
                digest = hashlib.new(algo, fh.read()).digest()
        except FileNotFoundError:
            res["missing"].append(str(p))
            continue
        except (OSError, ValueError):
            res["changed"].append(str(p))
            continue
        want = p.hash.value
        got = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        res["checked"] += 1
        if got != want:
            res["changed"].append(str(p))
    res["state"] = "changed" if (res["changed"] or res["missing"]) else "ok"
    return res


def format_self_check(res: dict) -> str:
    p = recipes_mod.printable
    if res["state"] == "unavailable":
        return f"  Could not check the installed files: {res['why']}.\n"
    lines = []
    if res["state"] == "ok":
        lines.append(f"  OK: all {res['checked']} installed stuntkey files match what "
                     "the installer wrote. Nothing has been changed since install.")
    else:
        lines.append("  WARNING: the installed stuntkey does not match what the installer "
                     "wrote. A file was changed, replaced or removed after install.")
        for name in res["changed"][:20]:
            lines.append(f"    changed: {p(name)}")
        for name in res["missing"][:20]:
            lines.append(f"    missing: {p(name)}")
        lines.append("  If you did not do this yourself, reinstall: `pipx reinstall stuntkey` "
                     "(or `pip install --force-reinstall stuntkey`).")
    lines.append("  (This catches accidental or clumsy changes. Someone who can edit these "
                 "files can also edit the install list, so it is not proof against a "
                 "determined attacker. Compare with the home page's published checks.)")
    return "\n".join(lines) + "\n"


def _ensure_log_key() -> None:
    """Make the activity log's signing key exist, so a fresh install does not
    say 'not signed'. Careful and quiet: it never fails the command."""
    import os
    try:
        from . import broker, remote
        log = broker.AuditLog(os.path.join(remote.home_dir(), "audit.log"))
        ensure = getattr(log, "ensure_key", None)
        if callable(ensure):
            ensure()
    except Exception:           # noqa: BLE001
        pass


fixcmd.HELPERS.update(self_check=lambda: self_check(), ensure_log_key=lambda: _ensure_log_key())


def unknown_service(catalog: dict, name: str) -> int:
    close = difflib.get_close_matches(str(name).lower(), list(catalog), n=3, cutoff=0.5)
    msg = f"I don't know a service called '{recipes_mod.printable(name)}'."
    if close:
        msg += " Did you mean: " + ", ".join(close) + "?"
    print(msg + "  (`stuntkey list` shows all; `stuntkey add` makes your own.)",
          file=sys.stderr)
    return 3


def no_key_saved(name: str) -> int:
    """run/forget on a name that has no saved key and no recipe."""
    shown = recipes_mod.printable(name)
    print(f"No key saved for {shown}. Run `stuntkey get {shown}`.", file=sys.stderr)
    return 3


def _hook_hint() -> None:
    """After `install`: say so when Claude Code's safety check is not on."""
    try:
        from . import hook
        if not hook.is_installed():
            print("\nOne more step for Claude Code: run `stuntkey fix` to switch on its "
                  "safety check (it stops Claude opening your .env files).")
    except Exception:           # noqa: BLE001
        pass


def _uninstall_hook(yes: bool, ask=None) -> int:
    """The undo for the Claude Code safety check: ask, then take only our own
    entry out of ~/.claude/settings.json (a backup is kept)."""
    import argparse as _ap
    from . import hook
    path = hook.user_settings_path()
    try:
        groups = hook._pretool_list(hook.load_settings(path), create=False) or []
        present = any(True for _ in hook._our_handlers(groups))
    except hook.SettingsError:
        return 0                    # unreadable: leave it alone, say nothing more
    if not present:
        return 0
    print(f"  claude-code safety check: will remove it from {recipes_mod.printable(path)} "
          "(your other hooks stay)")
    if not yes:
        try:
            if (ask or input)("    go ahead? [y/N] ").strip().lower() not in ("y", "yes"):
                print("    skipped.")
                return 0
        except (EOFError, KeyboardInterrupt, OSError):
            print("    skipped (no terminal to answer on; add --yes to go ahead).")
            return 0
    return hook.cmd_hook(_ap.Namespace(hook_cmd="uninstall", project=False, settings=None))


def _recipe_command(args) -> int:
    """`recipe list` / `recipe approve <service>` / `recipe revoke <service>`."""
    from . import remote
    cmd = args.recipe_cmd
    try:
        if cmd == "approve":
            return remote.recipe_approve(args.service)
        if cmd == "revoke":
            took = remote.recipe_revoke(args.service)
            print("Approval taken back." if took else "That recipe had no approval.")
            return 0
        # list
        folder = recipes_mod.user_recipes_dir()
        names = sorted(n[:-5] for n in os.listdir(folder) if n.endswith(".json")) \
            if os.path.isdir(folder) else []
        if not names:
            print("You have no recipes of your own yet. `stuntkey add` makes one.")
            return 0
        for name in names:
            recipe, problem = recipes_mod.load_user_recipe(name)
            if recipe is None:
                print(f"  {recipes_mod.printable(name):20} cannot be used: {recipes_mod.printable(problem)}")
                continue
            label = remote.recipe_flag(recipe) or "approved"
            print(f"  {recipes_mod.printable(name):20} {label}")
            if label != "approved":
                print(f"  {'':20} -> run `stuntkey recipe approve {recipes_mod.printable(name)}` "
                      "if you made it yourself")
        return 0
    except (recipes_mod.RecipeError, OSError) as e:
        print(f"error: {recipes_mod.printable(e)}", file=sys.stderr)
        return 1

def _tail(args) -> list:
    command = list(getattr(args, "command", []) or [])
    return command[1:] if command[:1] == ["--"] else command


def dispatch(args, catalog: dict):
    """Run one of our commands; None when `args.cmd` is not one of them."""
    cmd = args.cmd
    if cmd not in COMMANDS:
        return None
    if cmd == "install":
        from . import clients
        code = clients.run(args.targets, args.yes)
        _hook_hint()
        return code
    if cmd == "uninstall":
        from . import clients
        code = clients.remove(args.targets, args.yes)
        if not args.keep_hook and not args.targets:
            code = max(code, _uninstall_hook(args.yes))
        return code
    if cmd == "fix":
        from . import fixcmd
        return fixcmd.cmd_fix(args, catalog)
    if cmd == "limits":
        from . import fixcmd
        return fixcmd.cmd_limits()
    if cmd == "update-check":
        from . import fixcmd
        return fixcmd.cmd_update_check(args)
    if cmd in ("test", "check", "try-it"):
        from . import setupcmd
        return setupcmd.cmd_test(args, catalog)
    if cmd == "undo":
        from . import undo
        return undo.cmd_undo(args)
    if cmd == "recipe":
        return _recipe_command(args)
    if cmd == "try":
        from . import connect_try
        return connect_try.cmd_try(auto=args.auto)
    if cmd == "import":
        from . import connect_import
        return connect_import.cmd_import(args, catalog)
    if cmd == "selftest":
        from . import selftest
        return selftest.cmd_selftest(args.json, args.verbose)
    if cmd in ("start", "overview", "audit", "call", "serve"):
        from . import cmds
        if cmd == "start":
            if args.simple:
                return cmds.cmd_start_simple(catalog)
            return cmds.cmd_start(catalog, ".env")
        if cmd == "overview":
            return cmds.cmd_status(catalog, args.env_file, args.json)
        if cmd == "audit":
            return cmds.cmd_audit(args.action, args.json, args.last)
        if cmd == "serve":
            return cmds.cmd_serve(catalog, args.port, args.env_file)
        recipe = catalog.get(args.service)
        if not recipe:
            return unknown_service(catalog, args.service)
        return cmds.cmd_call(recipe, args)
    if cmd == "scan-git":
        import json as _json
        from . import gitscan
        if args.install_hook:
            try:
                print("hook installed:", gitscan.install_hook(args.path))
                return 0
            except OSError as e:
                print(f"error: {e}", file=sys.stderr)
                return 1
        g = gitscan.scan_git(args.path, staged=args.staged)
        if g.get("error"):
            print(f"error: {g['error']}", file=sys.stderr)
            return 2
        if args.staged:
            if g["findings"]:
                print("stuntkey: a key looks like it is about to be committed:\n"
                      + gitscan.format_git(g), file=sys.stderr)
                return 1
            return 0
        print(_json.dumps(g, indent=2) if args.json else gitscan.format_git(g))
        return 1 if g["findings"] else 0
    if cmd == "doctor":
        import json as _json
        from . import gitscan
        if getattr(args, "self_check", False):
            found = self_check()
            if args.json:
                print(_json.dumps(found, indent=2))
            else:
                sys.stdout.write(format_self_check(found))
            return 0 if found["state"] == "ok" else 1
        _ensure_log_key()
        res = gitscan.doctor()
        print(_json.dumps(res, indent=2) if args.json else gitscan.format_doctor(res))
        code = 0 if res["ok"] else 1
        if getattr(args, "fix", False) and not args.json:
            from . import fixcmd
            code = max(code, fixcmd.cmd_fix(args, catalog))
        return code
    # remote, trust-server, deploy -- DEPRECATED, removed at 1.0 (see add_parser above).
    print("warning: `stuntkey " + cmd + "` is deprecated and will be removed in 1.0. "
          "It runs commands on another machine, which is the largest attack surface "
          "here and is outside what stuntkey is for. Open an issue if you rely on it.",
          file=sys.stderr)
    from . import remote as remote_mod
    try:
        if cmd == "trust-server":
            remote_mod.ensure_ssh_access(args.host)
            return 0
        recipe = catalog.get(args.service)
        if not recipe:
            return unknown_service(catalog, args.service)
        if cmd == "remote":
            return remote_mod.run_remote(recipe, args.host, _tail(args),
                                         env_file=args.env_file, run_as=args.run_as,
                                         ssh_args=args.ssh_arg)
        remote_mod.ensure_ssh_access(args.host)
        code = remote_mod.run_remote(
            recipe, args.host, ["git", "-C", args.dir, "pull", "--ff-only"],
            env_file=args.env_file, run_as=args.run_as)
        if code == 0 and args.then:
            import subprocess
            key = remote_mod.key_for(args.host)
            ident = ["-i", key, "-o", "IdentitiesOnly=yes"] if key else []
            code = subprocess.run(["ssh", "-T", *ident, "-o", "BatchMode=yes",
                                   "--", args.host, args.then]).returncode
        return code
    except remote_mod.RemoteError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
