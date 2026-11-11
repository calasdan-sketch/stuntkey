"""Commands for using a key without ever holding it (the broker), and the
checks around it: call, audit, serve, selftest, start, overview, install,
uninstall, remote, trust-server, deploy, scan-git, doctor.

Kept apart from cli.py so the key-capture commands and these stay separate."""
from __future__ import annotations

import argparse
import difflib
import sys

from . import recipes as recipes_mod

COMMANDS = {"remote", "trust-server", "deploy", "install", "uninstall", "start",
            "overview", "audit", "call", "serve", "selftest", "scan-git", "doctor",
            "try", "import"}


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
    un = sub.add_parser("uninstall", help="Remove stuntkey from your AI tools' settings "
                                          "(your saved keys are not touched).",
                          description=PER_FOLDER_NOTE)
    un.add_argument("targets", nargs="*")
    un.add_argument("--yes", action="store_true", help="Do not ask (for scripts)")
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
    sv = sub.add_parser("serve", help="Open a local web door for AI tools without MCP "
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
        return clients.run(args.targets, args.yes)
    if cmd == "uninstall":
        from . import clients
        return clients.remove(args.targets, args.yes)
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
        res = gitscan.doctor()
        print(_json.dumps(res, indent=2) if args.json else gitscan.format_doctor(res))
        return 0 if res["ok"] else 1
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
