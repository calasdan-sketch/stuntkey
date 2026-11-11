"""stuntkey CLI: `stuntkey` - the safe tunnel for API keys."""

from __future__ import annotations

import argparse
import difflib
import errno
import json
import os
import re
import subprocess
import sys

from . import __version__
from . import extras
from . import recipes as recipes_mod


class _Lazy:
    """A module that is imported the first time something in it is used.

    Starting `stuntkey --version`, `help` or `status` used to load ~30
    modules (connect, mcp, the hook, the scanner...) it never needs. Each
    command now loads only what it runs. Reading, setting and patching an
    attribute all act on the real module, so code and tests that do
    `cli.keychain_mod.detect_backend` or patch it see the same thing as before.
    """

    def __init__(self, name: str):
        object.__setattr__(self, "_name", name)

    def _mod(self):
        import importlib
        return importlib.import_module("." + object.__getattribute__(self, "_name"),
                                       __package__)

    def __getattr__(self, attr):
        return getattr(self._mod(), attr)

    def __setattr__(self, attr, value):
        setattr(self._mod(), attr, value)

    def __delattr__(self, attr):
        delattr(self._mod(), attr)


connect_mod = _Lazy("connect")
keychain_mod = _Lazy("keychain")
mcp_mod = _Lazy("mcp")
pa_mod = _Lazy("publicapis")
safeprompt = _Lazy("safeprompt")
store_mod = _Lazy("store")


def _harden_streams() -> None:
    """Never crash on a console that cannot encode the check mark, the
    warning sign or a non-ASCII API name (cp1252 on Windows): replace
    instead of raising UnicodeEncodeError half-way through a connect."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        # Both handlers raise UnicodeEncodeError on a character the code
        # page lacks: "strict" (the default) and "surrogateescape" (what a
        # piped stdout reports on Windows 11 / Python 3.11, with cp1252).
        if reconfigure is None or getattr(stream, "errors", None) not in (
                "strict", "surrogateescape"):
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


NEXT_STEPS = """stuntkey: let your AI use your API keys without holding them.

Two steps:
  1. stuntkey setup     does it all after one yes: finds loose keys, moves them to
                        your keychain, switches on the protection, tests it
  2. Close and reopen your AI app, then ask it: "Who am I on GitHub?"

Add one key later:  stuntkey get   (a short menu; or copy the key first, then run it)
Check it works:     stuntkey test  (one line: PASS or FAIL)
Changed your mind?  stuntkey undo  puts back the last change.
New here? `stuntkey try` is a practice run with a pretend key.
Is something not working? `stuntkey status` shows green, yellow or red; `stuntkey fix` repairs it.
`stuntkey help` lists the everyday commands; `stuntkey help --all` lists all of them."""


def _show_banner(cmd: str) -> None:
    """The brand banner above start / doctor / status / get, when the brand module
    exists and the output is a terminal. Never allowed to break a command."""
    if cmd not in ("start", "doctor", "get", "status"):
        return
    try:
        if not sys.stdout.isatty():
            return
        from . import brand
        text = brand.banner()
        if text:
            print(text)
    except Exception:           # no brand module yet, or it failed: no banner
        pass


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        m = re.search(r"invalid choice: '([^']*)'", message)
        if m and message.startswith("argument cmd:"):
            # plain words, one line, no dump of every command name
            word = recipes_mod.printable(m.group(1))
            near = difflib.get_close_matches(m.group(1), list(self._subparsers_choices()), n=1)
            text = f"I don't know '{word}'."
            if near:
                text += f" Did you mean: stuntkey {near[0]}?"
            self.exit(2, text + " Type `stuntkey help` for the list.\n")
        super().error(message)

    def _subparsers_choices(self):
        for a in self._actions:
            if isinstance(a, argparse._SubParsersAction):
                return a.choices
        return ()


def _build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="stuntkey",
        description="Let your AI use your API keys without holding them: guided "
                    "setup, tested, kept in your computer's safe store (on Windows, "
                    "Credential Manager). The key is never shown or written to a log.",
        epilog="Start here: `stuntkey scan` finds keys that leaked into "
               "files an AI agent can read. `stuntkey connect <service>` "
               "sets a key up safely.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    p.add_argument("--project-dir", default=None, metavar="DIR",
                   help="Work as if started in DIR (where stuntkey.json and "
                        ".env live). Without it, stuntkey.json is looked for "
                        "here and up to the git project's top folder, no further.")
    sub = p.add_subparsers(dest="cmd")

    sc = sub.add_parser(
        "scan", help="Find API keys that leaked into files an AI agent can read.",
        description="Find API keys in the files an AI agent reads (.env files, "
                    "CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, the .claude "
                    "folder) and say what to do about each. Works offline; a "
                    "key is never shown in full. Exit status: 0 nothing found, "
                    "1 keys found, 2 could not run or the scan was INCOMPLETE "
                    "(a limit was hit, so a clean result cannot be trusted).")
    sc.add_argument("path", nargs="?", default=".",
                    help="Folder to scan (default: this folder), or one file.")
    sc.add_argument("--all", action="store_true",
                    help="Scan every text file in the folder, not just the "
                         "files an AI agent reads.")
    fmt = sc.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Print the result as JSON.")
    fmt.add_argument("--sarif", action="store_true",
                     help="Print the result as SARIF 2.1.0 (for code-scanning tools).")
    sc.add_argument("--validate", action="store_true",
                    help="Ask each key's own service whether it still works. "
                         "This SENDS the keys over https to that service; the "
                         "hosts are listed first and you are asked.")
    sc.add_argument("--yes", action="store_true",
                    help="With --validate: agree to send, without being asked.")
    sc.add_argument("--fail-on", choices=["any", "live"], default="any",
                    help="Exit 1 for any key found (default), or only for a "
                         "key that still works (needs --validate; a key that "
                         "could not be checked does not count, so this exits 0 "
                         "for it).")
    sc.add_argument("--my-recipes", action="store_true",
                    help="Also use the recipes in ~/.stuntkey/recipes: their "
                         "key formats are searched for (under a timer) and, "
                         "with --validate, their hosts may receive keys - "
                         "after a typed y every time, even with --yes. "
                         "Off by default: only the recipes shipped with "
                         "stuntkey are used.")
    sc.add_argument("--no-mcp", action="store_true",
                    help="Do not also read the MCP server configs of Claude, "
                         "Cursor, VS Code, Windsurf, Codex, Gemini and Zed.")
    sc.add_argument("--bundle", default=None, metavar="DIR_OR_URL",
                    help="Check a built web app (dist/, build/, out/, "
                         ".next/static) or your own public https:// site for "
                         "secret keys sent to every visitor's browser.")

    wr = sub.add_parser(
        "wrap", help="Move keys out of an AI plug-in's settings file into your safe store.",
        description="Move the keys in an MCP server's env (Claude Desktop, "
                    "Claude Code, Cursor, VS Code, Windsurf, Codex, Gemini, Zed) "
                    "into the OS keychain, and start that server through "
                    "`stuntkey run` so it still gets them. Shows the change "
                    "(keys masked), keeps a backup, asks first.")
    wr.add_argument("client", nargs="?", help="claude-desktop, claude-code, cursor, "
                    "vscode, windsurf, codex, gemini or zed.")
    wr.add_argument("server", nargs="?", help="The server's name in that config.")
    wr.add_argument("--all", action="store_true",
                    help="Every server with a key in its env (of CLIENT, or of every client).")
    wr.add_argument("--dry-run", action="store_true", help="Show the change; change nothing.")
    wr.add_argument("--undo", action="store_true",
                    help="Put back the config as it was before the last wrap.")
    wr.add_argument("--file", default=None, help="The config file, when the server "
                    "is in more than one.")

    hk = sub.add_parser(
        "hook", help="Stop Claude Code reading your .env files.",
        description="Install a Claude Code hook that refuses Read, Grep, Bash, "
                    "PowerShell and Monitor calls that touch .env files, and "
                    "Edit, Write, MultiEdit and NotebookEdit calls that change "
                    "one (set STUNTKEY_HOOK_ALLOW_WRITE=1 to allow those). It "
                    "is a guardrail, not a wall: it can be fooled by file names "
                    "built up piece by piece, searches that sweep a whole folder, "
                    "shortcuts to a file, helper agents, or file tools inside "
                    "other plug-ins (see the README, \"What stuntkey does NOT "
                    "protect\").")
    hsub = hk.add_subparsers(dest="hook_cmd", required=True)
    for hname, htext in (("install", "Add the hook (your other hooks are kept)."),
                         ("uninstall", "Remove the hook (your other hooks are kept)."),
                         ("status", "Say whether the hook is installed and works.")):
        h = hsub.add_parser(hname, help=htext)
        h.add_argument("--project", action="store_true",
                       help="Use this project's .claude/settings.json instead "
                            "of ~/.claude/settings.json.")
        h.add_argument("--settings", default=None, metavar="FILE",
                       help="Use this settings file.")
        if hname == "install":
            h.add_argument("--yes", action="store_true",
                           help="Replace an old oathkey 0.8 hook without asking.")
            h.add_argument("--shell-form", action="store_true",
                           help="Write the hook as one command string, for a "
                                "Claude Code too old to know `args` (Windows "
                                "only; elsewhere this is already the default).")
            h.add_argument("--fail-open", action="store_true",
                           help="If the hook itself fails or times out, let the "
                                "tool call through. The default is to block it "
                                "(onFailure: block; needs Claude Code 2.1.295 or "
                                "later).")
            h.add_argument("--fail-closed", action="store_true",
                           help="The default now (kept so old commands still work): "
                                "block the tool call if the hook itself fails "
                                "or times out.")
    hsub.add_parser("check", help="The hook itself: reads Claude Code's JSON "
                                  "on stdin. Not for typing by hand.")

    for name, help_text in (("get", "Add a key: opens the key page, takes the key when you "
                                    "copy it, tests it, saves it in the keychain."),
                            ("connect", "Connect a service (guided key setup)."),
                            ("rotate", "Replace the stored key for a service.")):
        c = sub.add_parser(name, help=help_text)
        c.add_argument("service", help="Service slug (see `stuntkey list`). `get` also "
                                       "takes any site: a name or an address such as "
                                       "example.com (saved untested). Leave it out with "
                                       "`get` to pick from a short menu (or to use a key "
                                       "you just copied).",
                       **({"nargs": "?", "default": None} if name == "get" else {}))
        c.add_argument("--env-file", default=None,
                       help="Where to store the key with --store env "
                            "(default: the manifest's env_file, else .env).")
        c.add_argument("--no-clipboard", action="store_true",
                       help="(get) Use the hidden paste prompt instead of copy-and-go.")
        c.add_argument("--store", choices=["env", "keychain"], default=None,
                       help="keychain (default for get) or env (owner-only .env file, "
                            "default for connect; rotate keeps the key where it is). "
                            "keychain: the OS keychain (macOS Keychain, Windows "
                            "Credential Manager, secret-tool on Linux), "
                            "asking before it falls back to the plain-text .env "
                            "file when none works; use `stuntkey run` to "
                            "consume it.")
        c.add_argument("--no-browser", action="store_true",
                       help="Don't auto-open the key page.")
        c.add_argument("--clipboard", action="store_true",
                       help="Copy-and-go: click the vendor's Copy button and the key "
                            "is taken from the clipboard (then emptied) - no pasting.")
        c.add_argument("--allow-clipboard-history", action="store_true",
                       help="With --clipboard on Windows: go on even though Windows "
                            "clipboard history is on and would keep a copy of the key.")
        c.add_argument("--via-cli", action="store_true",
                       help="Get the key from the vendor's own CLI after its browser "
                            "sign-in (built-in recipes that support it, e.g. github).")
        if name == "get":
            c.add_argument("--key-from-stdin", action="store_true",
                           help="FOR SCRIPTS AND TESTS ONLY: read the key from a pipe "
                                "(one line per value) instead of the clipboard. "
                                "Refused at a terminal. A key in a pipe or script "
                                "can end up in a shell history or a log.")

    ls = sub.add_parser("list", help="List the services stuntkey knows how to connect.")
    ls.add_argument("--json", action="store_true", help="Machine-readable output.")

    dr = sub.add_parser(
        "doctor-recipes", help="Check that the recipes' web addresses still work.",
        description="Visit every recipe's key page, docs link and test server "
                    "over HTTPS - with NO key, nothing secret - and report "
                    "moved or gone pages. Exit status: 0 nothing rotted, 1 "
                    "something rotted, 2 could not run.")
    dr.add_argument("service", nargs="*", help="Only these services.")
    dr.add_argument("--json", action="store_true", help="Print the result as JSON.")
    dr.add_argument("--timeout", type=float, default=15.0,
                    help="Seconds to wait for each address (default 15).")
    dr.add_argument("--my-recipes", action="store_true",
                    help="Also check the recipes in ~/.stuntkey/recipes.")

    fg = sub.add_parser("forget", help="Remove a stored key: from the OS "
                                       "keychain and from the .env file.")
    fg.add_argument("service", help="Service slug.")
    fg.add_argument("--env-file", default=None,
                    help="The .env file to remove the entry from (default: the "
                         "manifest's env_file, else .env).")
    fg.add_argument("--yes", action="store_true",
                    help="Do not ask first (needed when not run in a terminal).")

    aa = sub.add_parser("allow-agent", help="Allow an AI agent to capture a service's key "
                                            "from the clipboard (you type yes, once).")
    aa.add_argument("service", nargs="?", help="Service slug (built-in services only).")
    aa.add_argument("--revoke", action="store_true",
                    help="Take the permission back (all services if none is named).")
    aa.add_argument("--list", action="store_true", help="Show what is allowed in this project.")
    aa.add_argument("--env-file", default=None, metavar="NAME",
                    help="Let the agent write the key to this .env-style file of the project "
                         "(default: .env only).")
    aa.add_argument("--allow-clipboard-history", action="store_true",
                    help="Also accept that Windows clipboard history (Win+V) keeps a copy "
                         "of the key. Without it the agent is refused while history is on.")

    a = sub.add_parser("add", help="Capture a new service recipe interactively.")
    a.add_argument("--recipes-dir", default=None,
                   help="Write the recipe here instead of "
                        f"{recipes_mod.user_recipes_dir()}.")

    r = sub.add_parser("run", help="Run a command with a stored key in its "
                                   "environment (never printed).",
                       description="Run a command with the service's key in ITS "
                                   "environment only. The key comes from the OS "
                                   "keychain or, failing that, the .env file. "
                                   "The command's output is scrubbed of the key "
                                   "unless you pass --no-redact. With --all the "
                                   "first word after run is part of the command "
                                   "and every service in stuntkey.json is "
                                   "injected.")
    r.add_argument("service", help="Service slug (with --all: the start of the command).")
    r.add_argument("command", nargs=argparse.REMAINDER,
                   help="command after -- : stuntkey run stripe -- python app.py")
    r.add_argument("--env-file", default=None,
                   help="The .env file to read keys from (default: .env, or the "
                        "manifest's env_file).")
    r.add_argument("--all", action="store_true",
                   help="Inject every service listed in stuntkey.json.")
    r.add_argument("--no-redact", dest="redact", action="store_false", default=True,
                   help="Do not scrub the command's output (it then runs on your "
                        "terminal directly; use it for interactive programs).")
    r.add_argument("--redact", dest="redact", action="store_true",
                   help="Scrub the key out of the command's output (the default).")

    ini = sub.add_parser("init", help="Write stuntkey.json for this project.",
                         description="Look at the variable names this project uses "
                                     "(source files and .env.example-style templates "
                                     "- never a real .env) and list the services "
                                     "that have a recipe. Shows a preview; --write "
                                     "saves stuntkey.json (names only, safe to "
                                     "commit).")
    ini.add_argument("--write", action="store_true", help="Save the file.")
    ini.add_argument("--add", action="store_true", help="Add newly found services to an existing file.")
    ini.add_argument("--force", action="store_true", help="Start the file over.")

    su = sub.add_parser("setup", help="Do it all in one go: find keys, protect them, "
                                      "switch it on, test it.",
                        description="One command, one yes. It looks for keys lying "
                                    "around in this folder, moves the ones it "
                                    "knows into your computer's safe store, switches "
                                    "on the protection (Claude Code's safety check, "
                                    "Claude Desktop, Cursor, Claude Code for all "
                                    "folders) and tests that it works. Every change "
                                    "keeps a backup: `stuntkey undo` puts it back. "
                                    "To connect the services listed in this project's "
                                    "stuntkey.json one by one instead, name them or "
                                    "add --project.")
    su.add_argument("service", nargs="*", help="Only these services (project mode).")
    su.add_argument("--yes", action="store_true",
                    help="Do not ask first (for scripts).")
    su.add_argument("--project", action="store_true",
                    help="Connect the services in this project's stuntkey.json, "
                         "one by one (the old behaviour of this command).")
    su.add_argument("--env-file", default=None, help="Override the .env file.")
    su.add_argument("--dry-run", action="store_true", help="Say what would be done.")
    su.add_argument("--no-browser", action="store_true", help="Don't auto-open key pages.")
    su.add_argument("--clipboard", action="store_true", help="Copy-and-go for each key.")
    su.add_argument("--allow-clipboard-history", action="store_true",
                    help="Go on with copy-and-go even if Windows clipboard history is on.")

    stt = sub.add_parser("status", help="Where each key lives and how old it is.",
                         description="List the services in stuntkey.json, where "
                                     "each key is stored, when it was added and "
                                     "its age. Never shows a key. Exit status 1 "
                                     "when a key is missing or past its age limit.")
    stt.add_argument("--env-file", default=None, help="Override the .env file.")
    stt.add_argument("--max-age", type=int, default=None, metavar="DAYS",
                     help="Suggest rotating keys older than this (default 90, or "
                          "the manifest's max_age_days).")
    stt.add_argument("--json", action="store_true", help="Print the result as JSON.")

    ex = sub.add_parser("export", help="Send a stored key to GitHub or Vercel.",
                        description="Hand a stored key to the vendor's own tool "
                                    "(gh secret set / vercel env add) through a "
                                    "pipe, so it is never in a command line, a "
                                    "file or on screen. You must have gh / "
                                    "vercel installed and signed in.")
    ex.add_argument("service", help="Service slug.")
    ex.add_argument("--to", required=True, choices=["github", "vercel"])
    ex.add_argument("--repo", default=None, help="GitHub: OWNER/REPO (default: this folder's repository).")
    ex.add_argument("--environment", default=None,
                    help="GitHub: a deployment environment; Vercel: development, "
                         "preview or production (default production).")
    ex.add_argument("--env-file", default=None,
                    help="Where to find the key if it is not in the keychain "
                         "(default: the manifest's env_file, else .env).")
    ex.add_argument("--overwrite", action="store_true", help="Vercel: replace an existing variable.")
    ex.add_argument("--yes", action="store_true", help="Agree without being asked.")

    sk = sub.add_parser("skill", help="Give Claude Code a short instruction sheet: use stuntkey for keys.")
    sksub = sk.add_subparsers(dest="skill_cmd", required=True)
    ski = sksub.add_parser("install", help="Copy SKILL.md to ~/.claude/skills/stuntkey/ "
                                           "(or ./.claude/skills/ with --project).")
    ski.add_argument("--project", action="store_true", help="Install for this project only.")
    ski.add_argument("--for", dest="for_client", default="claude",
                     choices=["claude", "cursor", "codex", "gemini", "all"],
                     help="Which client's rules file: Claude Code's skill (default), or "
                          "the marked block in .cursor/rules/stuntkey.mdc, AGENTS.md "
                          "(Codex) or GEMINI.md (always in this project's folder).")
    ski.add_argument("--yes", action="store_true", help="Replace a different existing file without asking.")

    mc = sub.add_parser("mcp", help="Run in the background for your AI app (it starts this itself; you do not type it).")
    mc.add_argument("--default-store", choices=["env", "keychain"], default=None,
                    help="Where agent-captured keys go unless stuntkey.json says "
                         "otherwise (default: the OS keychain when there is one, "
                         "else a .env file). The call_api tool only reads the keychain.")
    sa = sub.add_parser("setup-agent", help="Show, or write, the setting that plugs stuntkey into one AI app "
                                            "(Claude Code, Claude Desktop, Cursor, Codex, Gemini).")
    sa.add_argument("client", choices=["claude-code", "claude-desktop", "cursor", "codex", "gemini"])
    sa.add_argument("--write", action="store_true",
                    help="Add the entry to the client's config file (other entries are kept).")

    sub.add_parser("about", help="Who made stuntkey, and how to check this is the real one.")
    mg = sub.add_parser("migrate", help="Copy keys saved by oathkey 0.8 to their stuntkey "
                                        "names in the OS keychain (never shows a key).")
    mg.add_argument("--remove-old", action="store_true",
                    help="After each copy is read back and matches, remove the old entry.")

    f = sub.add_parser("find", help="Find free public APIs for a task.")
    f.add_argument("query", help="What you need, e.g. 'weather', 'crypto price'.")
    f.add_argument("--auth", default=None,
                   help="Filter by auth, e.g. No, apiKey, OAuth.")
    f.add_argument("--category", default=None, help="Filter by category.")
    f.add_argument("--limit", type=int, default=10)
    f.add_argument("--refresh", action="store_true",
                   help="Re-download the directory (cached 7 days).")
    extras.add_parsers(sub)
    from . import panic as panic_mod
    panic_mod.add_parser(sub)
    from . import mint as mint_mod
    mint_mod.add_parser(sub)
    from . import proxy as proxy_mod
    proxy_mod.add_parsers(sub)
    return p


def _cmd_list(catalog: dict, as_json: bool = False) -> int:
    if as_json:
        print(json.dumps([{"service": s, "display": catalog[s]["display"],
                           "env_vars": list(recipes_mod.env_vars(catalog[s]))}
                          for s in sorted(catalog)]))
        return 0
    if not catalog:
        print("no recipes yet - add one with `stuntkey add`.")
        return 0
    print("\n  services with saved key recipes:\n")
    for slug in sorted(catalog):
        r = catalog[slug]
        # a recipe is somebody else's text: nothing in it may drive the terminal
        mine = f"  {connect_mod.OVERRIDE_NOTE}" if r.get("_overrides_builtin") else ""
        print(f"    {recipes_mod.printable(slug):14} "
              f"{recipes_mod.printable(r['display'], words=True):38} -> "
              f"{', '.join(recipes_mod.printable(v) for v in recipes_mod.env_vars(r))}"
              f"{mine}")
    print("\n  `stuntkey connect <service>` to set one up.\n")
    return 0


def _prompt(text: str, default: str = "") -> str:
    try:
        val = input(f"  {text}" + (f" [{default}]" if default else "") + ": ")
    except (EOFError, KeyboardInterrupt):
        print("\ncancelled.")
        sys.exit(1)
    return val.strip() or default


def _parse_expect(text: str) -> list[int]:
    """'200, 201' -> [200, 201]; anything that is not a 3-digit status is a
    ValueError with a message meant for a human, not a traceback."""
    codes = []
    for part in text.split(","):
        part = part.strip()
        if not part.isdigit() or not 100 <= int(part) <= 599:
            raise ValueError(
                f"expected HTTP status codes like 200 or 200,201 - got {part!r}")
        codes.append(int(part))
    if not codes:
        raise ValueError("at least one expected status code is required")
    return codes


def _cmd_add(recipes_dir: str | None) -> int:
    print("\n  Capture a new service recipe - teach it once, use it forever.\n")
    service = _prompt("slug (lowercase, no spaces)", "").lower().replace(" ", "-")
    if not service:
        print("  slug is required.")
        return 1
    if not recipes_mod.SLUG_RE.match(service):
        # the slug becomes the file name <slug>.json: "../../evil" or
        # "my service!" must never reach the filesystem
        print(f"  '{service}' is not a valid slug: use lowercase letters, "
              "digits, '-' or '_' (1-64 chars), e.g. 'my-api'.")
        return 1
    reserved = recipes_mod.device_name_problem(service)
    if reserved:
        print(f"  {reserved}.")
        return 1
    recipe = {
        "service": service,
        "display": _prompt("display name"),
        "key_url": _prompt("URL of the page where keys are minted"),
        "env_var": _prompt("env var name (e.g. HEADROOM_API_KEY)").upper(),
        "scopes": [s.strip() for s in
                   _prompt("scopes to select (comma-separated, optional)").split(",")
                   if s.strip()],
        "docs": _prompt("docs URL (optional)"),
        "steps": [],
        "validate": {},
    }
    print("  exact click-path steps (blank line to finish):")
    while True:
        s = _prompt(f"step {len(recipe['steps']) + 1}")
        if not s:
            break
        recipe["steps"].append(s)
    print("  validation - one API call that proves the key works:")
    recipe["validate"] = {
        "method": _prompt("HTTP method", "GET").upper(),
        "url": _prompt("validation URL"),
        "auth": {"type": _prompt("auth type (bearer/header/basic)", "bearer").lower()},
    }
    try:
        recipe["validate"]["expect"] = _parse_expect(
            _prompt("expected status codes (comma-separated)", "200"))
    except ValueError as e:
        print(f"  {e}")
        return 1
    if recipe["validate"]["auth"]["type"] == "header":
        recipe["validate"]["auth"]["header"] = _prompt("header name")
    try:
        from . import remote as _remote     # the person made it at a terminal: approved too
        path, _approved = _remote.recipe_save_and_approve(recipe, recipes_dir)
    except recipes_mod.RecipeError as e:
        print(f"  recipe incomplete: {e}")
        return 1
    print(f"\n  ✓ recipe saved to {path}\n")
    return 0


def _cmd_find(args) -> int:
    try:
        text = pa_mod.fetch(refresh=args.refresh)
    except Exception as e:
        print(f"couldn't fetch the public API directory: {e}")
        print("check your connection and try --refresh later.")
        return 2
    entries = pa_mod.parse(text)
    hits = pa_mod.search(entries, args.query, auth=args.auth,
                         category=args.category, limit=args.limit)
    if not hits:
        print(f"no public APIs match '{args.query}'.")
        return 0
    print(f"\n  public APIs matching '{args.query}':\n")
    for e in hits:
        # All directory strings are community-sourced: sanitize before
        # printing so escape sequences can't execute against the terminal.
        name = pa_mod.sanitize_display(e["name"])
        desc = pa_mod.sanitize_display(e["description"])
        url = pa_mod.sanitize_display(e["url"])
        category = pa_mod.sanitize_display(e["category"])
        auth_tag = "" if e["auth"] == "No" else f" [{e['auth']}]"
        print(f"    {name}{auth_tag}")
        print(f"      {desc}")
        print(f"      {url}  ({category})")
        if e["auth"] == "apiKey":
            print("      needs a key - save its recipe with `stuntkey add`.")
    print()
    return 0


def _stdin_is_terminal() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (OSError, ValueError):
        return False


def keychain_store(recipe: dict, env_file: str, out=None,
                   backend: str | None = None, keychain=keychain_mod,
                   ask=None, interactive=_stdin_is_terminal):
    """store_fn for `--store keychain`: the OS keychain. When the keychain is
    missing or refuses, the key goes to the plain-text .env file ONLY if the
    person says yes at a [y/N] question; with no terminal to ask, or on
    anything but y/yes, nothing is saved (SaveDeclined) - a person who chose
    the keychain must not find the key in a file they did not pick."""
    out = out or sys.stdout
    backend = backend or keychain.detect_backend()
    agreed: list[bool] = []

    def _fallback(env_var: str, key: str, why: str) -> str:
        if not agreed:
            if not interactive():
                raise connect_mod.SaveDeclined(
                    f"{why}, and there is no terminal to ask whether the key "
                    f"may go in the plain-text file {env_file} instead. "
                    f"Nothing was saved.")
            out.write(f"  {why}.\n")
            # read without echo: a key pasted here must not be shown, and
            # is never taken for a yes
            agreed.append(bool(safeprompt.ask(
                f"  Save it in the plain-text file {env_file} instead? [y/N]: ",
                out, enter_means=False, reader=ask,
                if_key="That looked like a key. Do not paste it here. "
                       "Type y or n.")))
        if not agreed[0]:
            raise connect_mod.SaveDeclined(f"{why}. You chose not to use "
                                           f"{env_file}, so nothing was saved.")
        return connect_mod.store_in_env_file(env_file)(env_var, key)

    def _store(env_var: str, key: str) -> str:
        if backend is None:
            return _fallback(env_var, key, "no OS keychain is available on "
                                           "this system")
        try:
            used = keychain.store(recipe["service"], env_var, key, backend)
        except keychain.KeychainError as e:
            return _fallback(env_var, key, f"the keychain could not keep the key ({e})")
        return (f"stored {env_var} in the {keychain.label(used)} "
                f"(never displayed, never logged); use it with "
                f"`stuntkey run {recipe['service']} -- <command>`")
    return _store


def _describe_links(links) -> str:
    """The other names of a file, for a message: the ones in its folder by
    name (shown so that a hostile file name cannot drive the terminal), the
    rest as a count."""
    parts = [recipes_mod.printable(name) for name in links.names]
    if links.elsewhere == 1:
        parts.append("1 in another folder")
    elif links.elsewhere:
        parts.append(f"{links.elsewhere} in other folders")
    return ", ".join(parts)


def _confirm_forget(recipe: dict, yes: bool, out=None, reader=None,
                    interactive=None) -> int | None:
    """None when removing may go ahead; otherwise the exit code. Nothing is
    removed unless --yes was given or the person typed y/yes."""
    if yes:
        return None
    out = out or sys.stdout
    if interactive is None:
        interactive = _stdin_is_terminal()
    if not interactive and reader is None:
        out.write("stuntkey forget needs --yes when not run in a terminal\n")
        return 2
    name = recipes_mod.printable(recipe["display"], words=True)
    answer = safeprompt.ask(f"Remove the stored {name} key? It cannot be "
                            f"recovered. [y/N] ", out, enter_means=False,
                            reader=reader)
    if answer is True:
        return None
    out.write("  nothing was removed.\n")
    return 1


def _cmd_forget(recipe: dict, env_file: str, out=None,
                keychain=keychain_mod, remove_env=None) -> int:
    """Remove the service's key everywhere it may have been stored: the OS
    keychain entry (when this platform has one) and every ENV_VAR= line in
    the .env file. Says what was removed; never shows the key."""
    out = out or sys.stdout
    remove_env = remove_env or store_mod.remove_key
    service, env_var = recipe["service"], recipe["env_var"]
    removed = []
    keychain_problem = None
    backend = keychain.detect_backend()
    if backend is not None:
        try:
            if keychain.delete(service, env_var, backend):
                removed.append(f"the {keychain.label(backend)} entry")
        except keychain.KeychainError as e:
            # The keychain tool hung or would not start. The .env file is
            # still ours to clean, so carry on - and say plainly that the
            # keychain entry may still be there.
            keychain_problem = str(e)
    # Other names of the file are asked BEFORE the rewrite: afterwards
    # env_file is a new file with one name, and the old one lives on, key
    # and all, under the others.
    links = store_mod.other_links(env_file)
    env_problem = None
    try:
        lines = remove_env(env_var, env_file)
    except OSError as e:
        # A link, a file that is not plain text, no permission. What was
        # removed above stays removed, and the leftover copies below are ours
        # to remove whatever happens to .env: carry on, and say what could
        # not be done only after saying what was.
        lines, env_problem = 0, e.strerror or str(e)
    if lines:
        removed.append(f"{env_var} from {env_file}")
    # A write that was killed halfway leaves a whole copy of the file behind.
    gone, stuck = store_mod.remove_leftovers(env_var, env_file)
    for path in gone:
        removed.append(f"a leftover copy in {recipes_mod.printable(path)} "
                       f"(from an interrupted write)")
    problems = []           # what is not done yet, in the order it was found
    if keychain_problem:
        problems.append(
            f"  \u2717 could not remove the {keychain.label(backend)} "
            f"entry: {keychain_problem}.\n"
            f"    The key may still be stored there \u2014 run "
            f"`stuntkey forget {service}` again when it answers.\n")
    if env_problem:
        problems.append(
            f"  \u2717 could not rewrite {recipes_mod.printable(env_file)}: "
            f"{recipes_mod.printable(env_problem)}.\n"
            f"    The key may still be stored there - fix that and run "
            f"`stuntkey forget {service}` again.\n")
    for path, why in stuck:
        problems.append(
            f"  \u2717 could not remove {recipes_mod.printable(path)}: "
            f"{recipes_mod.printable(why)}.\n"
            f"    It is a leftover copy of {recipes_mod.printable(env_file)} "
            f"from an interrupted write and still holds the key - delete it "
            f"yourself.\n")
    if lines and links:
        problems.append(
            f"  \u2717 {recipes_mod.printable(env_file)} also has other names "
            f"(hard links): {_describe_links(links)}.\n"
            f"    They still hold the old contents, {env_var} included - "
            f"rewriting a file cannot change its other names.\n"
            f"    stuntkey does not delete files it did not make; delete "
            f"them yourself if they are stray backups.\n")
    if not removed:
        for text in problems:
            out.write(text)
        if problems:
            return 1
        out.write(f"  nothing stored for '{service}' (checked "
                  f"{keychain.label(backend)} and {env_file}).\n")
        return 0
    # What was done comes first, then what was not: "forgot" only when that
    # is all of it.
    lead = "removed" if problems else f"forgot {service}: removed"
    out.write(f"  \u2713 {lead} {' and '.join(removed)}.\n")
    if isinstance(lines, int) and lines > 1:
        # every one of them, or an older line would take over again
        both = "both" if lines == 2 else f"all {lines}"
        out.write(f"    note: {env_var} appeared {store_mod.times(lines)} in "
                  f"{env_file}; I removed {both}.\n")
    for text in problems:
        out.write(text)
    return 1 if problems else 0


def _is_tty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def _cmd_run(recipes_to_run: list, command: list[str], env_file: str = ".env",
             redact: bool = True, prefer: str = "keychain") -> int:
    cmd = list(command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("error: nothing to run. Put the program after two dashes, for "
              "example: stuntkey run openai -- python app.py", file=sys.stderr)
        return 2
    if not redact and not (_is_tty(sys.stdin) and _is_tty(sys.stdout)):
        print("error: --no-redact only works when you are at a terminal (input and "
              "output both a terminal).\n  Output hiding is the only thing between "
              "a key and whatever is reading this output,\n  so it stays on when "
              "the output goes to a pipe, a file or a program.", file=sys.stderr)
        return 2
    backend = keychain_mod.detect_backend()
    if backend is None and not os.path.isfile(env_file):
        print("error: there is no safe place on this computer to read the key from. "
              "Run `stuntkey status` to see why.", file=sys.stderr)
        return 1
    try:
        # before the keychain is asked for the key: a typo costs no unlock
        cmd[0] = keychain_mod.locate_program(cmd[0])
    except keychain_mod.CannotRun as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    names = ", ".join(r["service"] for r in recipes_to_run)
    try:
        values: dict[str, str] = {}
        for recipe in recipes_to_run:
            values.update(keychain_mod.gather(recipe, backend, None, env_file, prefer))
        return keychain_mod.execute(cmd, values, None, None if redact else subprocess.call, redact)
    except keychain_mod.CannotRun as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    except keychain_mod.KeychainUnavailable as e:
        print(f"error: the {keychain_mod.label(backend)} did not give the key "
              f"for '{names}': {e}. Unlock your computer (sign out and in if "
              "needed), then try again.", file=sys.stderr)
        return 1
    except keychain_mod.KeychainError:
        print(f"No key saved for {names}. Run "
              f"`stuntkey get {recipes_to_run[0]['service']}`.", file=sys.stderr)
        return 1


# True on Windows. A module-level flag (not os.name read on the spot) so a
# test can switch it and check both platforms' behaviour from either one.
_ON_WINDOWS = os.name == "nt"


def is_closed_pipe(exc: BaseException) -> bool:
    """Is `exc` what writing to a pipe nobody reads any more looks like?

    On POSIX that is BrokenPipeError (errno EPIPE). On Windows it is NOT:
    print() of small output works because it is only buffered, and the
    flush - or, under ``python -u``, the print() itself - raises a plain
    OSError with errno 22 (EINVAL) and no winerror (measured on Windows 11
    with Python 3.11). EINVAL is only taken for a closed pipe there: on any
    other system it is a real error and must not be swallowed. And only the
    plain kind: it must carry no file name (EnvFileRefused is an OSError
    with errno EINVAL too, as can be any failed file operation on a path)
    and no winerror (a failed Win32 call such as starting a program), while
    an error from writing to a pipe has neither."""
    if not isinstance(exc, OSError):
        return False
    if isinstance(exc, BrokenPipeError) or exc.errno == errno.EPIPE:
        return True
    return (_ON_WINDOWS and exc.errno == errno.EINVAL
            and exc.filename is None
            and getattr(exc, "winerror", None) is None)


def _after_broken_pipe() -> int:
    """The reader of our output went away (``stuntkey list | head -1``).
    That is not worth a traceback: stop quietly. Python flushes stdout again
    when it exits and would fail a second time ("Exception ignored in ...",
    exit status 120), so fd 1 is pointed at the null device first - the
    recipe from the Python documentation; measured on Windows 11, it makes
    that last flush succeed there too. The status is 1, as Python itself
    uses for EPIPE."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass    # stdout has no real descriptor (a test's StringIO) or is gone
    return 1


def _flush_stdout() -> None:
    flush = getattr(sys.stdout, "flush", None)
    if flush is not None:
        flush()


def _interrupted() -> int:
    """Ctrl-C: say so in a line, not a traceback, and use the status a shell
    reports for a program SIGINT stopped (128 + 2)."""
    try:
        sys.stderr.write("\ninterrupted.\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass    # nobody is reading stderr either
    return 130


def main(argv: list[str] | None = None) -> int:
    try:
        try:
            code = _main(argv)
        except SystemExit:
            # argparse prints --version / --help and exits by exception; what
            # it printed is still in the buffer
            _flush_stdout()
            raise
        # A pipe that was closed on us shows up when the buffer is flushed -
        # here, where it can be handled, not in the interpreter's own exit.
        _flush_stdout()
        return code
    except OSError as e:
        # Any command, and the MCP loop, end up here: BrokenPipeError on
        # POSIX, a plain OSError(EINVAL) on Windows. Anything else is a real
        # error and goes on its way.
        if is_closed_pipe(e):
            return _after_broken_pipe()
        raise
    except KeyboardInterrupt:
        # Any command, the MCP loop and `run` end up here.
        return _interrupted()


def split_remote(argv: list[str]) -> tuple[list[str], list]:
    """Split `... remote SERVICE HOST -- COMMAND` at the `--`, wherever the
    `remote` word is: only global options (--project-dir DIR) may come first."""
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--project-dir":
            i += 2
        elif a.startswith("--project-dir=") or a == "--version":
            i += 1
        else:
            break
    if i < len(argv) and argv[i] == "remote" and "--" in argv[i:]:
        j = argv.index("--", i)
        return argv[:j], argv[j + 1:]
    return argv, []


def _say_examples_skipped(args, catalog: dict) -> None:
    """After a text scan of a folder: values that look like a key but were
    skipped as examples are named here, so nothing is skipped in silence."""
    if getattr(args, "json", False) or getattr(args, "sarif", False) \
            or getattr(args, "bundle", None):
        return
    path = getattr(args, "path", ".") or "."
    try:
        if not os.path.isdir(path):
            return
        from . import findkeys
        text = findkeys.examples_text(findkeys.examples_skipped(path, catalog))
    except Exception:           # noqa: BLE001 - an extra note must never break a scan
        return
    if text:
        sys.stdout.write("\n" + text)


def _keychain_available() -> bool:
    try:
        return keychain_mod.detect_backend() is not None
    except Exception:
        return False


def _store_where_key_lives(recipe: dict) -> str:
    """"keychain" when the OS keychain already holds this service's key, else
    "env": a rotated key replaces the old one where it is."""
    try:
        backend = keychain_mod.detect_backend()
        if backend:
            for var in recipes_mod.env_vars(recipe):
                if keychain_mod.read(recipe["service"], var, backend):
                    return "keychain"
    except Exception:
        pass
    return "env"


def _main(argv: list[str] | None = None) -> int:
    _harden_streams()
    from . import migrate as migrate_mod
    parser = _build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    argv, tail = split_remote(argv)
    args = parser.parse_args(argv)
    if args.cmd != "try":
        # 0.8 users: ~/.oathkey -> ~/.stuntkey, once. Not for the practice
        # run: it must not open anything of the person's.
        migrate_mod.copy_home()
    if args.cmd is None:
        print(NEXT_STEPS)
        return 0
    if args.cmd in ("help", "completion"):      # need the parser itself
        from . import fixcmd
        if args.cmd == "completion":
            return fixcmd.cmd_completion(args, parser)
        if args.topic:
            try:
                parser.parse_args([args.topic, "--help"])
            except SystemExit as e:
                return int(e.code or 0)
        if getattr(args, "all", False):
            sys.stdout.write(fixcmd.render_help(parser))
        else:
            sys.stdout.write(fixcmd.render_everyday())
        return 0
    if args.cmd == "remote":
        args.command = tail
    if args.project_dir:
        try:
            os.chdir(args.project_dir)
        except OSError as e:
            shown = recipes_mod.printable(args.project_dir)
            if isinstance(e, FileNotFoundError):
                why = "there is no such folder"
            elif isinstance(e, NotADirectoryError):
                why = "that is a file, not a folder"
            elif isinstance(e, PermissionError):
                why = "you do not have permission to open it"
            else:
                why = e.strerror or "it cannot be opened"
            print(f"error: I cannot use --project-dir '{shown}': {why}.",
                  file=sys.stderr)
            return 2
    _show_banner(args.cmd)
    if args.cmd in ("check", "try-it"):
        args.cmd = "test"           # the same command under two easier names
    project_setup = args.cmd == "setup" and (args.project or bool(args.service))
    if args.cmd == "status" or project_setup:
        from . import manifest as manifest_mod
        if not manifest_mod.find():
            if args.cmd == "status" and getattr(args, "json", False):
                print(json.dumps({"setup": False, "services": [],
                                  "note": "This folder has no stuntkey setup. "
                                          "Run `stuntkey init` to create one."}))
                return 0
            print("This folder has no stuntkey setup. Run `stuntkey init` to "
                  "create one.\n(To see keys saved anywhere on this computer, "
                  "run `stuntkey overview`.)")
            if args.cmd == "status":          # still show the computer's health
                from . import fixcmd
                sys.stdout.write(fixcmd.render(fixcmd.collect()))
            return 0 if args.cmd == "status" else 1
    if args.cmd == "hook":
        # before the recipes load: the hook's stdout must hold only its answer
        from . import hook as hook_mod
        return hook_mod.cmd_hook(args)
    if args.cmd == "scan":
        from . import scan as scan_mod
        # only the recipes shipped in the package, unless --my-recipes: a recipe
        # of your own names the hosts keys are sent to and brings its own regex
        catalog = (recipes_mod.load_recipes() if args.my_recipes
                   else recipes_mod.load_recipes(recipes_mod.RECIPES_DIR))
        code = scan_mod.cmd_scan(args, catalog)
        _say_examples_skipped(args, catalog)
        return code
    if args.cmd == "skill":
        from . import skillcmd
        return skillcmd.cmd_skill(args)
    if args.cmd == "doctor-recipes":
        from . import doctor as doctor_mod
        catalog = (recipes_mod.load_recipes() if args.my_recipes
                   else recipes_mod.load_recipes(recipes_mod.RECIPES_DIR))
        return doctor_mod.cmd_doctor(args, catalog)
    catalog = recipes_mod.load_recipes()

    if args.cmd == "setup" and not project_setup:
        from . import setupcmd
        return setupcmd.cmd_setup_all(args, catalog)
    if args.cmd == "wrap":
        from . import mcpwrap
        return mcpwrap.cmd_wrap(args, catalog)
    if args.cmd == "allow-agent":

        from . import allowcmd
        return allowcmd.cmd_allow_agent(args, catalog)
    if args.cmd == "about":
        from . import aboutcmd
        code = aboutcmd.cmd_about()
        sys.stdout.write("\n  This copy:\n" + extras.about_extra())
        return code
    if args.cmd == "migrate":
        return migrate_mod.cmd_migrate(args, catalog)
    handled = extras.dispatch(args, catalog)
    if handled is not None:
        return handled
    from . import proxy as proxy_mod
    handled = proxy_mod.dispatch(args, catalog)
    if handled is not None:
        return handled
    if args.cmd == "list":
        return _cmd_list(catalog, getattr(args, "json", False))
    if args.cmd == "find":
        return _cmd_find(args)
    if args.cmd == "add":
        return _cmd_add(args.recipes_dir)
    if args.cmd == "mcp":
        store = args.default_store or ("keychain" if _keychain_available() else "env")
        if store != "env":
            from . import capture as capture_mod
            capture_mod.set_manager(capture_mod.Manager(default_store=store))
        return mcp_mod.serve(catalog)
    if args.cmd == "setup-agent":
        from . import agentsetup
        return agentsetup.cmd_setup_agent(args)
    if args.cmd == "init":
        from . import projectcmds
        return projectcmds.cmd_init(args, catalog)
    if args.cmd == "status":
        from . import projectcmds
        code = projectcmds.cmd_status(args, catalog)
        if not args.json:
            from . import fixcmd
            sys.stdout.write(fixcmd.render(fixcmd.collect(catalog)))
        return code
    if args.cmd == "setup":
        from . import projectcmds

        def connect_one(recipe, store, env_file):
            return connect_service(recipe, env_file=env_file, store=store,
                                   no_browser=args.no_browser,
                                   clipboard=args.clipboard,
                                   allow_history=args.allow_clipboard_history)
        return projectcmds.cmd_setup(args, catalog, connect_one)
    any_site = args.cmd == "get"          # get also takes a site stuntkey does not know
    stdin_key = False
    key_lines = None
    menu_key = None                       # a key picked up from the clipboard by the menu
    menu_clip = None
    if args.cmd == "get" and not args.service:
        # `stuntkey get` on its own: a short menu, or the key just copied
        from . import getmenu
        picked = getmenu.choose(catalog)
        if picked is None:
            return 1
        if picked[0] == "key":
            _kind, args.service, menu_key, menu_clip = picked
        else:
            args.service = picked[1]
    if args.cmd == "get":                 # one command: keychain + copy-and-go
        args.cmd = "connect"
        stdin_key = getattr(args, "key_from_stdin", False)
        if menu_key is not None:
            stdin_key, key_lines = True, [menu_key]
        elif stdin_key:
            key_lines = _lines_from_stdin()
            if key_lines is None:
                return 2
        args.clipboard = (args.clipboard or not args.no_clipboard) and not stdin_key
        if args.store is None:
            args.store = "keychain"
    if getattr(args, "store", "env") is None and args.cmd != "rotate":
        args.store = "env"
    if args.cmd in ("connect", "rotate", "forget", "export") and getattr(args, "env_file", None) is None:
        args.env_file = _project_env_file()
        if args.env_file is None:
            return 1
    if args.cmd == "mint":
        from . import mint as mint_mod
        return mint_mod.cmd_mint(args, catalog)
    if args.cmd == "panic":
        from . import panic as panic_mod
        env_file = args.env_file or _project_env_file()
        if env_file is None:
            return 1
        return panic_mod.cmd_panic(
            args, catalog, env_file=env_file, root=_project_root(),
            connect_fn=lambda r: connect_service(
                r, env_file=env_file, store=_store_where_key_lives(r),
                no_browser=args.no_browser, clipboard=True, rotate=True))
    if args.cmd == "export":
        from . import export as export_mod
        return export_mod.cmd_export(args, catalog)
    if args.cmd == "run" and args.all:
        from . import manifest as manifest_mod
        path = manifest_mod.find()
        if not path:
            print("error: --all needs a stuntkey.json in this project. Run `stuntkey init` first.",
                  file=sys.stderr)
            return 1
        try:
            manifest = manifest_mod.load(path)
        except manifest_mod.ManifestError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        chosen = [catalog[i["service"]] for i in manifest["services"] if i["service"] in catalog]
        try:
            env_file = args.env_file or manifest_mod.env_file_in(os.path.dirname(path), manifest)
        except manifest_mod.ManifestError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        prefer = "env" if all(i.get("store", "env") == "env" for i in manifest["services"]) else "keychain"
        if not chosen:
            print("error: stuntkey.json names no service stuntkey knows. Run "
              "`stuntkey list` to see them, then edit stuntkey.json.", file=sys.stderr)
            return 1
        return _cmd_run(chosen, [args.service] + list(args.command), env_file, args.redact, prefer)
    if args.cmd in ("connect", "rotate", "run", "forget"):
        recipe = catalog.get(args.service)
        if not recipe:
            # "open ai", "git hub", "chatgpt": same service, other spelling
            from . import getmenu
            slug = getmenu.best(args.service, catalog)
            if slug:
                print(f"  (I took '{recipes_mod.printable(args.service)}' to mean "
                      f"{recipes_mod.printable(catalog[slug]['display'], words=True)}.)",
                      file=sys.stderr)
                args.service, recipe = slug, catalog[slug]
        from . import anysite
        if not recipe and any_site and anysite.looks_like_site(args.service, catalog):
            return anysite.cmd_get(
                args.service, catalog,
                lambda r, url: connect_service(
                    r, env_file=args.env_file, store=args.store,
                    no_browser=args.no_browser or stdin_key,
                    clipboard=args.clipboard,
                    allow_history=args.allow_clipboard_history, open_url=url,
                    **({"key_lines": key_lines} if stdin_key else {})))
        if not recipe and args.cmd in ("run", "forget", "rotate"):
            # a site typed as an address (example.com): find the recipe that
            # `get example.com` saved for it
            recipe = _saved_site_recipe(args.service, catalog)
        if not recipe:
            # exit 3 and the short "Did you mean" line; only a short plain
            # name is echoed back (a long or odd one could be a key typed in
            # the wrong place)
            plain = (len(args.service) <= 64 and (
                recipes_mod.SLUG_RE.match(args.service)
                or anysite.site_domain(args.service)))
            if args.cmd in ("run", "forget") and plain and not difflib.get_close_matches(
                    args.service.lower(), list(catalog), n=1, cutoff=0.8):
                return extras.no_key_saved(args.service)
            shown = args.service if plain else "(not shown)"
            return extras.unknown_service(catalog, shown)
        if args.cmd == "rotate" and args.store is None:
            args.store = _store_where_key_lives(recipe)
        if args.cmd == "run":
            from . import manifest as manifest_mod
            env_file, prefer = args.env_file, "keychain"
            found = manifest_mod.find()
            if found:
                try:
                    manifest = manifest_mod.load(found)
                    env_file = env_file or manifest_mod.env_file_in(os.path.dirname(found), manifest)
                    for item in manifest["services"]:
                        if item["service"] == args.service and item.get("store") == "env":
                            prefer = "env"
                except manifest_mod.ManifestError as e:
                    print(f"error: {e}", file=sys.stderr)
                    return 1
            return _cmd_run([recipe], args.command, env_file or ".env", args.redact, prefer)
        if args.cmd == "forget":
            refused = _confirm_forget(recipe, args.yes)
            if refused is not None:
                return refused
            # one pass per stored value: an App ID and its secret are both removed
            code = max(_cmd_forget(dict(recipe, env_var=var), args.env_file)
                       for var in recipes_mod.env_vars(recipe))
            if code == 0:
                from . import ledger as ledger_mod
                ledger_mod.forget(_project_root(), recipe["service"])
            return code
        if args.cmd == "rotate":
            print(f"\n  rotating "
                  f"{recipes_mod.printable(recipe['display'], words=True)} - "
                  f"the stored key will be replaced.\n")
        try:
            return connect_service(recipe, env_file=args.env_file, store=args.store,
                                   no_browser=args.no_browser or stdin_key,
                                   clipboard=args.clipboard,
                                   via_cli=args.via_cli, rotate=args.cmd == "rotate",
                                   allow_history=args.allow_clipboard_history,
                                   **({"key_lines": key_lines} if stdin_key else {}))
        finally:
            if menu_clip is not None:       # the key was used: do not leave it copied
                _empty_clipboard(menu_clip)
                menu_key = key_lines = None
    return 0


def _empty_clipboard(clip) -> None:
    try:
        from . import clipboard as clipboard_mod
        if not clipboard_mod.clear_verified(clip[0], clip[1]):
            print("  I could not empty the clipboard: copy something else (a word) "
                  "so the key is not left there.")
    except Exception:           # noqa: BLE001 - never let this hide the real result
        pass


def _lines_from_stdin() -> list[str] | None:
    """For `get --key-from-stdin`: the piped lines (one value per line), or
    None - after saying why - when that is not allowed. Refused at a terminal:
    there copy-and-go (or the hidden paste) is safer and the key is never
    typed on a command line or kept in a shell history."""
    if _stdin_is_terminal():
        print("--key-from-stdin is for scripts and tests: pipe the key in. At a "
              "terminal just run `stuntkey get <service>` - the key is taken "
              "from your copy and never shown.", file=sys.stderr)
        return None
    lines = [ln.strip() for ln in (sys.stdin.read() if sys.stdin else "").splitlines()
             if ln.strip()]
    if not lines:
        print("--key-from-stdin: nothing was piped in.", file=sys.stderr)
        return None
    return lines


def _saved_site_recipe(name: str, catalog: dict) -> dict | None:
    """The recipe `stuntkey get example.com` saved for that address, if any."""
    from . import anysite
    domain = anysite.site_domain(name)
    if not domain:
        return None
    try:
        recipe = anysite.build_recipe(domain, catalog)
    except recipes_mod.RecipeError:
        return None
    return recipe if recipe.get("service") in catalog else None


def _what_will_happen(recipe: dict, store: str, env_file: str, no_browser: bool,
                      clipboard: bool, via_cli: bool, stdin_key: bool) -> str:
    """One plain line, shown before anything is done."""
    name = recipes_mod.printable(recipe["display"], words=True)
    where = ("your computer's keychain" if store == "keychain"
             else f"the file {recipes_mod.printable(env_file)}")
    if stdin_key:
        return f"This will read the {name} key from the pipe, test it and save it in {where}."
    if via_cli:
        return f"This will sign in with {name}'s own tool, test the key and save it in {where}."
    page = "open the key page, " if not no_browser else ""
    take = "wait for you to copy the key" if clipboard else "ask you to paste the key"
    test = "save it" if recipe.get("untested") else "test it and save it"
    return f"This will {page}{take}, {test} in {where}."


def connect_service(recipe: dict, env_file: str = ".env", store: str = "env",
                    no_browser: bool = False, clipboard: bool = False,
                    via_cli: bool = False, rotate: bool = False,
                    allow_history: bool = False, open_url: str | None = None,
                    key_lines: list[str] | None = None) -> int:
    """The connect flow plus the local record of when the key was added.
    `open_url` opens that page instead of the recipe's key page. `key_lines`
    (scripts and tests only) are the values to use instead of the clipboard
    or the hidden prompt, one per field."""
    import webbrowser
    stdin_key = key_lines is not None
    if stdin_key:
        no_browser, clipboard = True, False
    opener = ((lambda url: None) if no_browser
              else (lambda url: webbrowser.open(open_url or url)))
    store_fn = keychain_store(recipe, env_file) if store == "keychain" else None
    print(f"\n  {_what_will_happen(recipe, store, env_file, no_browser, clipboard, via_cli, stdin_key)}")
    clip = None
    if clipboard:
        from . import clipboard as clipboard_mod
        try:
            clip = clipboard_mod.backend()
            warning = clipboard_mod.history_warning()
            if warning and not allow_history:
                print(f"  {warning}")
                print("  So I will ask you to paste the key (hidden) instead. "
                      "Pass --allow-clipboard-history to use copy-and-go anyway.")
                clip = None
        except clipboard_mod.Unavailable as e:
            print(f"  (copy-and-go unavailable: {recipes_mod.printable(e)} - "
                  f"using the hidden paste instead)")
    extra = {}
    if stdin_key:
        pending = iter(key_lines)

        def _next_line(_text: str) -> str:
            try:
                return next(pending)
            except StopIteration:
                raise EOFError from None
        extra["prompt"] = _next_line
    if no_browser:
        extra["opens_browser"] = False
    had_key = store == "keychain" and not rotate and _keychain_has(recipe)
    code = connect_mod.connect(recipe, env_file=env_file, browser_open=opener,
                               store_fn=store_fn, clipboard=clip, via_cli=via_cli,
                               **extra)
    if code == 0:
        from . import ledger as ledger_mod
        ledger_mod.record(_project_root(), recipe["service"], store, rotated=rotate)
        if store == "keychain" and not rotate and not had_key:
            _note_for_undo(recipe)          # `stuntkey undo` can take this key out again
    return code


def _keychain_has(recipe: dict) -> bool:
    try:
        backend = keychain_mod.detect_backend()
        return bool(backend) and any(keychain_mod.read(recipe["service"], v, backend)
                                     for v in recipes_mod.env_vars(recipe))
    except Exception:           # noqa: BLE001 - not knowing means: do not offer to undo
        return True


def _note_for_undo(recipe: dict) -> None:
    try:
        from . import undo
        change = undo.begin("get")
        change.note_key(recipe["service"], list(recipes_mod.env_vars(recipe)))
        change.commit()
    except Exception:           # noqa: BLE001 - the key is saved; the note is a bonus
        pass


def _project_env_file() -> str | None:
    """The .env file for this project: the manifest's env_file (checked), else
    .env in the current folder. None, after saying why, when the manifest
    cannot be used."""
    from . import manifest as manifest_mod
    found = manifest_mod.find()
    if not found:
        return ".env"
    try:
        return manifest_mod.env_file_in(os.path.dirname(found), manifest_mod.load(found))
    except manifest_mod.ManifestError as e:
        print(f"error: {recipes_mod.printable(e)}", file=sys.stderr)
        return None


def _project_root() -> str:
    """The folder holding stuntkey.json (found from here upward), else here:
    the key `status` looks the record up by."""
    from . import manifest as manifest_mod
    return manifest_mod.project_root()


if __name__ == "__main__":
    sys.exit(main())
