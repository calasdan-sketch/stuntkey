"""`stuntkey hook`: stop an AI agent reading your .env files.

Claude Code can run a small program before every tool call (a "PreToolUse
hook") and that program can say no. `hook install` adds one to Claude Code's
settings; `hook check` is that program. When the agent tries to Read, Grep,
or run a Bash, PowerShell or Monitor command that touches a .env file, or
tries to Edit, Write, MultiEdit or NotebookEdit one, the answer is "deny" and
the reason is handed back to the agent in plain words.

This is a guardrail, not a sandbox. It catches the direct ways (cat .env,
Read .env, grep KEY .env, source .env). A determined or confused program can
still build a file name out of pieces, sweep a folder (`grep -r KEY .`) or go
through a tool this hook is not attached to; keep keys out of the files too
(`stuntkey connect <service> --store keychain`). The README lists what it
does NOT stop.

Two safety rules for the code below:
* Nothing read from a settings file is ever executed. `hook status` runs only
  the command THIS install would generate, never one it found in a file (a
  cloned repository's .claude/settings.json is not trusted).
* Our own entry is recognised by a marker or by an exact command, never by
  "it looks like ours", and `install` always writes into a group of its own.

The hook format lives in decision_json() and the settings shape in
hook_handler() / hook_entry(): the places to change if Claude Code changes
either. Checked against https://code.claude.com/docs/en/hooks (see the
README for what could not be confirmed).
"""

from __future__ import annotations

import datetime
import difflib
import hashlib
import json
import os
import fnmatch
import re
import shlex
import shutil
import subprocess
import sys
import sysconfig
import tempfile

from . import recipes as recipes_mod

# Tools that can show a file's contents or run a command that does:
#   Read, Grep      - the file tools (tool_input: file_path / path / glob)
#   Bash, PowerShell - shell commands (tool_input.command)
#   Monitor         - runs a command in the background and streams its output
# Tools that would put a key INTO a file (0.5.2):
#   Edit, Write, MultiEdit, NotebookEdit - refused for a real .env file, because
#   a key typed by the agent has passed through the agent, and a Write can
#   overwrite the person's keys. Templates (.env.example) stay writable, and
#   STUNTKEY_HOOK_ALLOW_WRITE=1 turns the write check off. Glob (names
#   only) is not matched.
MATCHER = "Read|Grep|Bash|PowerShell|Monitor|Edit|Write|MultiEdit|NotebookEdit|mcp__.*"
# what earlier versions wrote; still recognised (is_ours goes by the marker), and
# `hook install` rewrites it in place
LEGACY_MATCHERS = ("Read|Grep|Bash|PowerShell|Monitor|Edit|Write|MultiEdit|NotebookEdit",
                   "Read|Grep|Bash|PowerShell|Monitor")
SHELL_TOOLS = frozenset({"Bash", "PowerShell", "Monitor"})
KNOWN_TOOLS = frozenset({"Read", "Grep", "Edit", "Write", "MultiEdit", "NotebookEdit"}) | SHELL_TOOLS
# A command longer than this is refused unread: the checks below are regexes,
# and a huge command could keep them busy until the hook times out. Other
# text (an MCP tool's arguments) is checked in overlapping windows.
MAX_COMMAND = 100_000
CHUNK = 20_000
OVERLAP = 2_000
SCAN_BUDGET = 600_000        # characters of non-shell text checked per call
WRITE_SCAN_BUDGET = 2_000_000  # code an agent writes is scanned whole, up to this
MAX_STRINGS = 2_000
MAX_DEPTH = 20
WRITE_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
ALLOW_WRITE_VAR = "STUNTKEY_HOOK_ALLOW_WRITE"
MARKER = "stuntkey hook"      # the statusMessage that marks our handler
LEGACY_MARKERS = ("oathkey hook",)   # what 0.8 (oathkey) wrote: replaced by `hook install`
OUR_FOLDERS = (".stuntkey", ".oathkey")   # the store, and the 0.8 copy migration leaves behind
HOOK_TIMEOUT = 10            # seconds (Claude Code's own default is 600)
MAX_STDIN = 64 * 1024 * 1024  # read this much of Claude Code's JSON, no less
BACKUPS_TO_KEEP = 20
TEMPLATE_SUFFIXES = frozenset({"example", "sample", "template", "dist",
                               "defaults", "default", "tpl", "schema"})
_ON_WINDOWS = os.name == "nt"

# .env, .env.local, .env.production, prod.env, .envrc - not a word that
# merely contains "env" (environment.py, my.environment). A match must start
# at the beginning of a path part, and end the name.
ENV_NAME_RE = re.compile(
    r"(?<![\w.\-])(?P<name>(?:\.env(?:rc)?(?P<suffix>(?:\.[\w\-]+)*)|[\w\-]+(?:\.[\w\-]+)*\.env))"
    r"(?![\w\-]|\.\w)", re.IGNORECASE)

REASON = (
    "stuntkey blocked this because {what} is a .env file, which holds "
    "secret API keys. Anything you read goes into your memory and the "
    "conversation log. Do not try another way to read it. If you need a key, call "
    "the stuntkey tool `capture_key` (service name): you click the vendor's "
    "Copy button in the browser and stuntkey takes the key from the clipboard "
    "without showing it to you (`needs_keys` lists which keys are missing). Only "
    "if capture_key is unavailable, tell the person to run `stuntkey connect "
    "<service>`; never ask for the key in chat. "
    "If a command needs the key to run, ask the person to run it themselves "
    "(`stuntkey run <service> -- <command>`) - do not run it for them. If "
    "you only need to know which variables exist, read .env.example instead.")

WRITE_REASON = (
    "Claude can't write to {what} - your keys stay out of the chat. "
    "Call the stuntkey tool `capture_key` (or `needs_keys` to see which key is "
    "missing) - or, if capture is unavailable, tell the person to run: "
    "stuntkey connect <service>  (or edit the file yourself).")


OVERSIZE_REASON = (
    "stuntkey blocked this because the command is {n} characters long, more than "
    "the {limit} the hook can check safely. Put the long part in a file with the "
    "Write tool and run a short command, or ask the person to run it.")

PROTECTED_REASON = (
    "stuntkey blocked this because {what} decides which hooks and tools your AI "
    "may run, so only the person should change it. Do not try another way. Tell "
    "the person what change you need and let them make it.")

STEAL_REASON = (
    "stuntkey blocked this because it would {what}. Stored keys must stay "
    "out of the chat. Do not try another way. Call the stuntkey tool "
    "`capture_key` (or `needs_keys`); if capture is unavailable, ask the person "
    "to run the command themselves.")

CODE_REASON = (
    "stuntkey blocked this write because the code would {what} once it runs - "
    "even though you are only writing it now, not running it. A file's output "
    "cannot be masked after the fact the way a command's can, so this is "
    "caught before it is saved. Do not try another way or write it somewhere "
    "else. If you need a key, call the stuntkey tool `capture_key`, or ask "
    "the person to run `stuntkey run <service> -- <command>`.")

BIG_WRITE_REASON = (
    "stuntkey blocked this write because it is too large to check whole for "
    "code that would print secret keys. Write it in smaller parts.")

_WRITE_TOOL_RE = re.compile(r'"tool_name"\s*:\s*"(?:Write|Edit|MultiEdit|NotebookEdit)"')

CODE_ENV_REASON = (
    "stuntkey blocked this write because the code names {what}, a .env file "
    "that holds secret API keys, and would read it once it runs. Do not "
    "write code that opens a .env file. If you only need to know which "
    "variables exist, read .env.example instead; if you need a key, call "
    "the stuntkey tool `capture_key`.")

# Ways a shell can pull a stored key out, or print it unredacted. Each is
# (regex, what it does). They are matched against the whole command text.
_SAFE = r"(?:^|[\s;&|`(\"'])"
# the start of a command (not a word in the middle of one), and its end
_CMD = (r"(?:^|[\n;&|(`{]|\bthen\b|\bdo\b|\bcmd(?:\.exe)?\s+/[ck]|\s-c)\s*(?:[\"']\s*)?"
        r"(?:sudo\s+|command\s+|builtin\s+)?")
_END = r"(?=$|\s*[\n|;&>)`}\"'])"
# upper case only: `for key in ...; do echo $key` is not a key
_SECRET_WORD = r"(?-i:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)"
# private keys and the credentials files tools keep in your home folder
_CRED_FILE = (r"(?:[\w.\-]*\.(?:pem|key|p12|pfx|jks|keystore)|id_(?:rsa|dsa|ecdsa|ed25519)|"
              r"\.netrc|_netrc|\.git-credentials|\.npmrc|\.pypirc|\.pgpass|"
              r"\.aws[/\\](?:credentials|config)|\.docker[/\\]config\.json|"
              r"\.kube[/\\]config|credentials\.json|application_default_credentials\.json|"
              r"service[-_]account[\w.\-]*\.json)(?=$|[\s\"'`;&|)>*])")
# Bash text that writes, edits or removes the files that decide which hooks
# and MCP servers run. Pattern-based: a script (python -c ...) gets past it.
# The one STEAL_RULE also applied to an MCP tool's arguments (decide_steal).
_SETTINGS_WRITE_RULE = (
    re.compile(r"(?:>>?|\btee\b|\b(?:cp|mv|rm)\b|\bsed\b[^\n;&|]*?\s(?:-[A-Za-z]*i\b|--in-place))"
               r"[^\n;&|]*?(?:\.claude[/\\]settings(?:\.local)?\.json|\.mcp\.json|\.claude\.json)"
               r"(?![\w.-])", re.I),
    "change the Claude settings files that decide which hooks and tools run "
    "(only the person may)")
STEAL_RULES = (
    (re.compile(r"(?:stuntkey|oathkey)\b(?:(?!\s--\s)[^\n;&|]){0,300}\s--no-r\w*", re.I),
     "run a command with the key and turn output hiding off"),
    (re.compile(r"(?:(?:^|[\s;&|`(\"'/\\])(?:stuntkey|oathkey)(?:\.exe)?|\s-\w*m\s+(?:stuntkey|oathkey)(?:\.(?:cli|__main__))?)"
                r"(?:\s+--project-dir(?:\s+|=)\S+)*\s+"
                r"(?:remote|deploy|trust-server|export|run|serve|call|forget|stop|resume|rotate|"
                r"caps\s+(?:set|--clear)|policy\s+approve|(?:hook\s+)?uninstall|"
                r"install\s+(?:[^\n;&|]*\s)?--uninstall)(?![\w-])", re.I),
     "run a stuntkey command that uses, sends or removes a stored key, or switches "
     "its protection off (remote, deploy, trust-server, export, run, serve, call, "
     "forget, stop, resume, rotate, caps set/--clear, policy approve, uninstall, hook uninstall: "
     "only the person runs those)"),
    _SETTINGS_WRITE_RULE,
    (re.compile(_SAFE + r"secret-tool\s+(?:lookup|search)\b", re.I), "read the Linux keyring"),
    (re.compile(_SAFE + r"security\s+(?:find-\w+-password|dump-keychain|export)\b", re.I),
     "read the macOS keychain"),
    (re.compile(_SAFE + r"cmdkey(?:\.exe)?\b", re.I), "read Windows stored credentials"),
    (re.compile(r"\b(?:Get-Secret|Get-SecretInfo|Get-StoredCredential|PasswordVault|CredRead|CredEnumerate|vaultcmd)\b", re.I),
     "read Windows stored credentials"),
    (re.compile(_SAFE + r"(?:kwallet-query|gnome-keyring-query|keyring\s+(?:get|--list)|pass\s+show)\b", re.I),
     "read a password store"),
    (re.compile(r"\b(?:import|from)\s+keyring\b|\bkeyring\.get_password\b", re.I), "read the keyring from code"),
    (re.compile(r"/proc/[\w$*{}/-]*/environ", re.I), "read another program's environment"),
    (re.compile(r"(?:^|[\s/\\~=:;&|(<>])\.(?:stuntkey|oathkey)(?![\w])", re.I), "read stuntkey's own store"),
    (re.compile(r"consent\.key|agent-consent|\.safe\W*easy", re.I), "touch stuntkey's consent files"),
    (re.compile(_SAFE + r"(?:pbpaste|wl-paste|Get-Clipboard|xclip\b[^\n;&|]*\s-(?:o\b|out\b)|xsel\b[^\n;&|]*\s(?:-o\b|--output\b))", re.I),
     "read the clipboard"),
    (re.compile(r"\b(?:Windows\.Forms\.Clipboard|GetClipboardData|pyperclip|clipboard_get)\b", re.I),
     "read the clipboard from code"),
)

# Shell commands (Bash, PowerShell, Monitor only: an MCP tool's text is not a
# command) that print the whole environment, where `stuntkey run` and many dev
# setups put keys, or show a private key / credentials file. `env FOO=1 cmd`,
# `set -e`, `export X=1`, `python -m venv env` and `printenv PATH` stay allowed:
# only the dumping forms count.
DUMP_RULES = (
    (re.compile(_CMD + r"(?:(?:env|printenv)(?:\s+-[0-9A-Za-z]+)*|set|export(?:\s+-p)?|"
                r"(?:declare|typeset)\s+-[a-z]*[px][a-z]*)\s*" + _END, re.I),
     "print every environment variable (that is where keys live)"),
    (re.compile(r"\b(?:exec|ssh|run)\b[^\n;&|]{0,300}\s(?:env|printenv)\s*" + _END, re.I),
     "print every environment variable of a container or remote machine"),
    (re.compile(r"\bprintenv\s+\w*" + _SECRET_WORD + r"\w*|"
                r"(?:^|[\s;&|(`])(?:echo|printf|Write-Output|Write-Host)\b[^\n;&|]{0,300}"
                r"\$(?:\{|env:)?\w*" + _SECRET_WORD + r"|"
                r"(?:^|[\s;&|(`(])\$env:\w*" + _SECRET_WORD + r"\w*\s*" + _END, re.I),
     "print a key from an environment variable"),
    (re.compile(r"\b(?:Get-ChildItem|gci|ls|dir|Get-Item|gi|Get-Content|gc|cat|type)\s+"
                r"(?:-\w+\s+)*Env::?(?:(?!\w)|\w*\*|\w*" + _SECRET_WORD + r")|"
                r"GetEnvironmentVariables\b", re.I),
     "list the environment variables (that is where keys live)"),
    (re.compile(r"\bdocker(?:-compose|\s+compose)\b[^\n;&|]{0,300}\sconfig\b", re.I),
     "print the compose file with every variable filled in (keys included)"),
    (re.compile(r"\bdocker\s+(?:container\s+|image\s+)?inspect\b(?![^\n;&|]{0,300}\s(?:--format|-f)\b)|"
                r"\bdocker\s+(?:container\s+|image\s+)?inspect\b[^\n;&|]{0,300}"
                r"(?:\bEnv\b|\.Config\s*\}\}|\{\{\s*json\s+\.\s*\}\})", re.I),
     "print a container's settings, its environment (keys) among them"),
    (re.compile(
        # Python: print/pprint/logging of os.environ or a bare `environ`,
        # whole or as .items()/.values()/.copy() - not os.environ["X"]/.get()
        r"\b(?:p?print|pp|json\.dumps|log(?:ging|ger)?\.\w+|sys\.std(?:out|err)\.write)"
        r"\s*\(\s*(?:\*\s*|(?:dict|str|repr|list|sorted)\s*\(\s*)?(?:os\.)?environ\b"
        r"(?:\s*\.\s*(?:items|values|copy)\s*\(\s*\))?\s*[),]|"
        # JS: console.* / JSON.stringify of process.env, process["env"], Deno.env
        r"\b(?:console\.\w+|JSON\.stringify|process\.stdout\.write)\s*\(\s*"
        r"(?:JSON\.stringify\s*\(\s*|Object\.(?:entries|values)\s*\(\s*)?"
        r"(?:process\s*(?:\.\s*env|\[\s*['\"]env['\"]\s*\])|Deno\.env\.toObject\s*\(\s*\))\s*[),]|"
        # Go: fmt.Print*(os.Environ())
        r"\bfmt\.\w*Print\w*\s*\([^)\n]*os\.Environ\s*\(\s*\)|"
        # Ruby: puts/p/pp ENV (whole)
        r"(?:^|[\s;(])(?:puts|pp?|print)\s*\(?\s*ENV(?:\.to_h)?\s*(?:\)|$|;)|"
        # running env/printenv/set from code
        r"\b(?:system|popen|run|call|check_output|getoutput|exec\w*|spawn\w*)\s*\(\s*\[?\s*"
        r"['\"](?:env|printenv|set|Get-ChildItem\s+Env:)['\"]", re.I | re.M),
     "print every environment variable from code"),
    (re.compile(_CMD + r"(?:sudo\s+)?(?:cat|type|Get-Content|gc|less|more|head|tail|grep|egrep|"
                r"fgrep|rg|ag|sed|awk|bat|nl|xxd|od|strings|base64|tac|cut|sort|uniq|"
                r"Select-String|sls)\b[^\n;&|]{0,300}?" + _CRED_FILE, re.I),
     "show a private key or a credentials file"),
)


# What only the person may do (grant an agent the right to capture keys), and
# the files that record it. Matched against the command with quotes, carets,
# backslashes and shell variables taken out (STEAL_RULES are matched that way
# too), so allow""-agent, sec""ret-tool and a${x}llow-agent do not slip through.
# A SPEED BUMP, not a lock: it catches the plain and the lightly disguised
# forms only. See consent.py for what protects the grant itself.
CONSENT_RULES = (
    (re.compile(r"allow[-_]agent|agent[-_]consent|allowcmd|(?:stuntkey|oathkey)\.(?:consent|capture)\b|"
                r"(?:consent|capture)_mod\b|consent\.(?:grant|_save_grants)|capture\.grant", re.I),
     "give itself permission to capture keys (only the person may)"),
)


def _squash(text: str) -> tuple[str, str]:
    """`text` without quotes, carets, backticks and backslashes; and also
    without shell variables."""
    plain = re.sub(r"[\'\"`^\\]", "", text)
    return plain, re.sub(r"\$\{[^}]*\}|\$\w+|\$\(\)", "", plain)


_DOT_TOKEN = re.compile(r"(?:^|[\s/\\~=:;&|(<>'\"`])(\.[^\s/\\;&|<>()'\"`=]*)")


_DOT_WILD_PATH = re.compile(
    r"(?:^|[\s/\\~=:;&|(<>'\"`])(\.[^\s/\\;&|<>()'\"`=]*)[/\\][^\s/\\;&|<>()'\"`=]")


def _wild_dot_into_path(text: str) -> bool:
    """A word of only dots and wildcards that could be `.stuntkey`, followed by
    a path into it: `~/.*/x`, `~/.???????/keys/*`, `~\\.*\\http.token`. A bare
    `.*` (no path after it) is left alone so `ls -a` and `ls .*` still work."""
    for word in _DOT_WILD_PATH.findall(text):
        if not re.search(r"[*?\[]", word):
            continue
        if re.search(r"[A-Za-z0-9_]", re.sub(r"\[[^\]]*\]", "", word)):
            continue                                 # has literal letters: the check below
        try:
            if any(fnmatch.fnmatchcase(n, word) for n in OUR_FOLDERS):
                return True
        except re.error:
            continue
    return False


def globs_to_our_folder(text: str) -> bool:
    """Does a path word in `text` use wildcards that could expand to the
    `.stuntkey` folder? (`~/.safe*/*`, `.s*/c*`, `.saf?easyapi/*`,
    `tar c ~/.safe*`.) A word that is only wildcards (`.*`) is left alone: that
    would stop every `ls -a`. Known false positive: `ls .s*` (and any `.s*`
    style word) is refused, because it could expand to the folder. A word of
    only dots and wildcards counts when a path into the folder follows it
    (`~/.*/keys/x`)."""
    if _wild_dot_into_path(text):
        return True
    for word in _DOT_TOKEN.findall(text):
        if not re.search(r"[*?\[]", word):
            continue
        if not re.search(r"[A-Za-z]", re.sub(r"\[[^\]]*\]", "", word)):
            continue                                 # no literal letter: too general to mean us
        try:
            if any(fnmatch.fnmatchcase(n, word) for n in OUR_FOLDERS):
                return True
        except re.error:
            continue
    return False


def steals_key(text: str, shell: bool = False) -> str | None:
    """What a shell command / path would do to a stored key, or None. A speed
    bump, not a lock: it reads the text of the call, and a program that builds
    its command at run time gets past it. `shell`: the text is a shell
    command, so DUMP_RULES apply too."""
    flat = text.replace("\\", "/") if "stuntkey" in text else text
    variants = (text, flat, *_squash(text))
    if any(globs_to_our_folder(v) for v in variants):
        return "touch stuntkey's own store (a wildcard that matches its folder)"
    for rx, what in STEAL_RULES + (DUMP_RULES if shell else ()):
        if any(rx.search(v) for v in variants):
            return what
    for variant in variants:
        for rx, what in CONSENT_RULES:
            if rx.search(variant):
                return what
    return None


# ------------------------------------------------------------------ the check

def is_env_name(name: str) -> bool:
    """Is this file name a real .env file (not a template like .env.example)?"""
    m = ENV_NAME_RE.fullmatch(name.strip())
    if not m:
        return False
    return not _is_template(m)


def _is_template(m: re.Match) -> bool:
    suffix = (m.group("suffix") or "")
    parts = [p for p in suffix.split(".") if p]
    return bool(parts) and parts[-1].lower() in TEMPLATE_SUFFIXES


def find_env_files(text: str) -> list[str]:
    """Every .env-style file name mentioned in a path or a shell command that
    is not a template."""
    found = []
    for m in ENV_NAME_RE.finditer(text.replace("\\", "/")):
        if not _is_template(m):
            found.append(m.group("name"))
    return found


def _strings(value) -> list[str]:
    return [value] if isinstance(value, str) else []


def touched_text(payload: dict) -> list[str]:
    """The strings of a tool call that name files or run commands. One small
    function so the tool field names are in one place (Read: file_path, path;
    Grep: path, glob; Bash and PowerShell: command; Monitor: command)."""
    tool = payload.get("tool_name")
    args = payload.get("tool_input")
    if not isinstance(args, dict):
        return []
    if tool in WRITE_TOOLS:
        # the one place for the write tools' field names: Edit, Write and
        # MultiEdit use file_path; NotebookEdit uses notebook_path. All three
        # names are read for every one of them so a rename cannot slip past.
        return [v for k in ("file_path", "notebook_path", "path")
                for v in _strings(args.get(k))]
    if tool == "Read":
        return _strings(args.get("file_path")) + _strings(args.get("path"))
    if tool == "Grep":
        return _strings(args.get("path")) + _strings(args.get("glob"))
    if tool in ("Bash", "PowerShell"):
        return _strings(args.get("command"))
    if tool == "Monitor":
        # the Monitor input is not documented field by field: look at every
        # text it carries (a command, or a WebSocket address) except the note
        return [v for k, v in args.items()
                if isinstance(v, str) and k != "description"]
    if isinstance(tool, str) and tool.startswith("mcp__"):
        # an MCP tool (mcp__server__tool): its arguments are arbitrary, so look
        # at every string in them, however deeply nested
        return _all_strings(args)
    return []


def _all_strings(value, depth: int = 0, out: list | None = None) -> list[str]:
    """Every string (keys too) inside nested dicts and lists, with a cap on
    depth and on how many are collected."""
    out = [] if out is None else out
    if len(out) >= MAX_STRINGS or depth > MAX_DEPTH:
        return out
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            _all_strings(k, depth + 1, out)
            _all_strings(v, depth + 1, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _all_strings(v, depth + 1, out)
    return out


def _pieces(text: str, budget: list):
    """`text` whole when short, else overlapping windows, so no check ever runs
    over more than CHUNK characters. `budget` (a one-item list) is the
    characters still allowed to be checked in this call."""
    if len(text) <= CHUNK:
        budget[0] -= len(text)
        yield text
        return
    step = CHUNK - OVERLAP
    for i in range(0, len(text), step):
        if budget[0] <= 0:
            return
        piece = text[i:i + CHUNK]
        budget[0] -= len(piece)
        yield piece


def too_long(payload) -> int | None:
    """The length of a shell command that is too long to check, else None."""
    if not isinstance(payload, dict) or payload.get("tool_name") not in SHELL_TOOLS:
        return None
    for text in touched_text(payload):
        if len(text) > MAX_COMMAND:
            return len(text)
    return None


def _is_mcp(payload) -> bool:
    tool = payload.get("tool_name") if isinstance(payload, dict) else None
    return isinstance(tool, str) and tool.startswith("mcp__")


def decide(payload) -> str | None:
    """None to stay out of the way, or the name of the .env file refused.
    An MCP tool's arguments are data (a memory note that says ".env" opens
    no file), so they get only the stored-key check (decide_mcp_key)."""
    if not isinstance(payload, dict) or _is_mcp(payload):
        return None
    if payload.get("tool_name") in WRITE_TOOLS and writes_allowed():
        return None
    for text in touched_text(payload):
        hits = find_env_files(text)
        if hits:
            return hits[0]
        if re.search(r"[\'\"`^]", text):
            # c''at .e''nv: the shell joins the pieces, so look at the joined text too
            for variant in _squash(text):
                hits = find_env_files(variant)
                if hits:
                    return hits[0]
    return None


def decide_steal(payload) -> str | None:
    """None, or what a Bash / PowerShell / Monitor / Read / Grep call would
    do to a stored key (see STEAL_RULES)."""
    if not isinstance(payload, dict):
        return None
    budget = [SCAN_BUDGET]
    shell = payload.get("tool_name") in SHELL_TOOLS
    mcp = _is_mcp(payload)
    settings_rx, settings_what = _SETTINGS_WRITE_RULE
    for text in touched_text(payload):
        for piece in _pieces(text, budget):
            if mcp:
                # an MCP tool's arguments are data, not a command: a note that
                # mentions `stuntkey run` or ~/.stuntkey/ is fine. Only the
                # settings-file rule still applies; stored keys are
                # decide_mcp_key's job.
                if any(settings_rx.search(v) for v in (piece, *_squash(piece))):
                    return settings_what
                continue
            what = steals_key(piece, shell)
            if what:
                return what
    return None


# Files whose text is never run: prose and ignore lists. A .gitignore that
# lists .env, or a README that says "copy .env.example to .env", must stay
# writable - blocking them would push people away from the safe setup.
# ponytail: by file name only; `python notes.md` would still run unscanned
# text, but its output goes through the Bash PostToolUse masking.
_NOT_CODE_RE = re.compile(
    r"(?:\.(?:md|markdown|mdx|rst|adoc)|(?:^|/)\.[a-z]*ignore|(?:^|/)\.gitattributes)\Z",
    re.I)

# Code names .env files all the time for safe reasons: load_dotenv('.env'),
# `cp .env.example .env`, `COPY .env .`, `env_file: .env`. The leak is OUTPUT,
# so a .env name counts only on a line that also prints or dumps a file, or
# when it is read into a variable that another line prints.
# ponytail: one hop of data flow only; passing the text through a second
# variable or a function gets past this, and the Bash PostToolUse mask is
# what still covers that run.
_OUTPUTS_RE = re.compile(
    r"print|console\.|\bputs\b|\bp\s|Write-(?:Host|Output)|stdout|"
    r"\b(?:cat|head|tail|more|less|Get-Content|log(?:ger|ging)?\.\w+)\b", re.I)

# `name = <read of a file>` (Python, JS, PowerShell, Ruby, Go, shell).
_READ_INTO_RE = re.compile(
    r"^\s*(?:(?:const|let|var|my|local)\s+)?\$?(\w+)\s*:?=\s*.*?"
    r"(?:\bopen\b|read|Get-Content|\bcat\b|\bgc\b|File\.)", re.I)

# JavaScript objects that look like a `<name>.env` file name.
_CODE_ENV_OBJECTS = {"process.env", "meta.env", "import.meta.env", "deno.env", "bun.env", "os.env"}


def _env_names(line: str) -> list[str]:
    return [n for n in find_env_files(line) if n.lower() not in _CODE_ENV_OBJECTS]


def _printed_env_files(text: str) -> list[str]:
    """.env-style names in written code that end up printed: on a line that
    also outputs, or read into a variable that a later line outputs."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        names = _env_names(line)
        if not names:
            continue
        if _OUTPUTS_RE.search(line):
            return names
        m = _READ_INTO_RE.match(line)
        if m:
            var = re.compile(r"(?<![\w.])\$?" + re.escape(m.group(1)) + r"\b")
            if any(_OUTPUTS_RE.search(ln) and var.search(ln) for ln in lines[i + 1:]):
                return names
    return []


def _write_content_strings(payload: dict) -> list[str]:
    """The new text a Write / Edit / MultiEdit / NotebookEdit call is about to
    put on disk - not the path (touched_text's job), the content itself.
    Nothing is written yet when this runs (PreToolUse): this is the one
    chance to see it before it lands. Only the NEW text matters - Edit's
    old_string and MultiEdit's old_string are what is already on disk, not
    what the agent is adding, so they are left out."""
    if not isinstance(payload, dict):
        return []
    tool = payload.get("tool_name")
    args = payload.get("tool_input")
    if tool not in WRITE_TOOLS or not isinstance(args, dict):
        return []
    target = args.get("file_path") or args.get("notebook_path")
    if isinstance(target, str) and _NOT_CODE_RE.search(target.replace("\\", "/")):
        return []
    if tool == "Write":
        return _strings(args.get("content"))
    if tool == "Edit":
        return _strings(args.get("new_string"))
    if tool == "MultiEdit":
        edits = args.get("edits")
        out = []
        if isinstance(edits, list):
            for e in edits:
                if isinstance(e, dict):
                    out += _strings(e.get("new_string"))
        return out
    if tool == "NotebookEdit":
        return _strings(args.get("new_source"))
    return []


def decide_code_leak(payload) -> tuple[str, str] | None:
    """Would the CODE an agent is about to write leak a secret once it runs
    LATER, as its own separate command? ("kind", "what"): kind "env" means
    the code names a .env-style file (`what` is that name, CODE_ENV_REASON
    fits); kind "dump" means it matches one of the DUMP_RULES/STEAL_RULES
    patterns, such as `print(os.environ)` or `console.log(process.env)`
    (`what` is the rule's own words, CODE_REASON fits). None otherwise.

    This exists because a Write/Edit/MultiEdit/NotebookEdit call has no
    documented PostToolUse output shape (only Bash does - see post_check), so
    a secret a saved script would print cannot be masked after the fact the
    way a Bash command's output can. The file path is checked by decide()
    and decide_protected_write() already; this is the one place the CONTENT
    being written is scanned too, so a script that merely dumps the
    environment or opens a .env file is caught before it is ever saved, not
    only when something later happens to run it under a wrapped shell."""
    texts = _write_content_strings(payload)
    if not texts:
        return None
    total = sum(len(t) for t in texts)
    if total > WRITE_SCAN_BUDGET:
        # padding a file past what is scanned must not be a way around it
        return "big", str(total)
    budget = [WRITE_SCAN_BUDGET]
    for text in texts:
        hits = _printed_env_files(text)
        if hits:
            return "env", hits[0]
        for piece in _pieces(text, budget):
            what = steals_key(piece, shell=True)
            if what:
                return "dump", what
    return None


_PROTECTED_RE = re.compile(
    r"(?:^|/)(?:\.claude/settings(?:\.local)?\.json|\.mcp\.json|\.claude\.json)\Z", re.I)


def decide_protected_write(payload) -> str | None:
    """The settings file an Edit / Write / MultiEdit / NotebookEdit call would
    change, if it is one that controls hooks and MCP servers
    (.claude/settings.json, .claude/settings.local.json, .mcp.json,
    ~/.claude.json), else None. STUNTKEY_HOOK_ALLOW_WRITE=1 turns it off."""
    if not isinstance(payload, dict) or payload.get("tool_name") not in WRITE_TOOLS:
        return None
    if writes_allowed():
        return None
    for text in touched_text(payload):
        norm = re.sub(r"/+", "/", text.strip().replace("\\", "/"))
        norm = re.sub(r"::\$DATA\Z", "", norm, flags=re.I).rstrip(" .")
        if _PROTECTED_RE.search(norm):
            return norm.rsplit("/", 1)[-1] if "/" in norm else norm
    return None


# Read's output has no documented shape for PostToolUse updatedToolOutput, so
# a Read cannot be masked after it runs: the secret-by-nature files are refused
# before it. A .pem/.key file counts only when it holds a private key (a
# certificate is public). Any other Read is refused only when the file holds
# one of YOUR stored keys (by fingerprint: no false alarms on key-like text),
# and an MCP config also when a key in a known format is written in it.
_CRED_PATH_RE = re.compile(r"(?:^|[/\\])" + _CRED_FILE, re.I)
_MCP_CONFIG_RE = re.compile(r"(?:^|[/\\])\.(?:mcp|claude)\.json\Z", re.I)


def _file_head(path: str) -> str | None:
    """The first SCAN_BUDGET characters of a file, or None if unreadable."""
    try:
        with open(os.path.expanduser(path), encoding="utf-8", errors="replace") as f:
            return f.read(SCAN_BUDGET)
    except (OSError, ValueError):
        return None


def decide_secret_read(payload) -> str | None:
    """What a Read (or a Grep on one file) would show that must stay out of
    the chat, or None."""
    if not isinstance(payload, dict) or payload.get("tool_name") not in ("Read", "Grep"):
        return None
    args = payload.get("tool_input")
    key = "file_path" if payload.get("tool_name") == "Read" else "path"
    path = args.get(key) if isinstance(args, dict) else None
    if not isinstance(path, str) or not path.strip():
        return None
    path = path.strip()
    text = _file_head(path)
    if _CRED_PATH_RE.search(path):
        from .scan import PRIVATE_KEY_RE
        if not (re.search(r"\.(?:pem|key)\Z", path, re.I)
                and text is not None and not PRIVATE_KEY_RE.search(text)):
            return "show a private key or a credentials file"
    if payload.get("tool_name") != "Read" or text is None:
        return None
    from . import scrub as scrub_mod
    try:
        prints = scrub_mod.load_fingerprints()
    except (OSError, ValueError):
        prints = (b"", frozenset())
    if scrub_mod.has_stored_key(text, prints):
        return "show a file that holds one of your stored keys"
    if _MCP_CONFIG_RE.search(path) and scrub_mod.mask_secrets(text, (b"", frozenset()))[1]:
        return "show an MCP config with a key written in it"
    return None


def decide_mcp_key(payload) -> str | None:
    """An MCP tool call whose arguments carry one of your stored keys."""
    tool = payload.get("tool_name") if isinstance(payload, dict) else None
    if not (isinstance(tool, str) and tool.startswith("mcp__")):
        return None
    from . import scrub as scrub_mod
    try:
        prints = scrub_mod.load_fingerprints()
    except (OSError, ValueError):
        return None
    if any(scrub_mod.has_stored_key(s, prints) for s in touched_text(payload)):
        return "send one of your stored keys to an MCP tool"
    return None


def writes_allowed(environ=None) -> bool:
    return (environ if environ is not None else os.environ).get(ALLOW_WRITE_VAR, "").strip() == "1"


def decision_json(reason: str) -> dict:
    """The answer Claude Code expects from a PreToolUse hook that says no
    (exit status 0 and this on stdout)."""
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}




def _read_all(stdin) -> str:
    """Everything Claude Code sent (up to MAX_STDIN), as text. Bytes that are
    not UTF-8 are replaced, never an error."""
    source = getattr(stdin, "buffer", None) or stdin
    data = source.read(MAX_STDIN)
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def check(stdin_text: str) -> tuple[int, str]:
    """The hook program: (exit status, stdout text). Only ever answers "deny";
    for everything else it says nothing, so Claude Code's normal permission
    rules still apply (an "allow" here would skip them).

    Input that is not the JSON Claude Code sends (too big to parse, cut off,
    nested too deeply) is NOT waved through: the raw text is searched for a
    .env file name and, if one is there, the call is refused. Only when that
    finds nothing is it a non-blocking error (status 1): a broken hook must
    not stop all work unless you installed it with --fail-closed."""
    oversized_write = False
    if len(stdin_text) > 2 * WRITE_SCAN_BUDGET:
        # only ever look at a bounded amount: the start and the end. A write
        # this big cannot be scanned whole, so it is refused below rather
        # than let padding carry code past the scan.
        oversized_write = bool(_WRITE_TOOL_RE.search(stdin_text[:SCAN_BUDGET]))
        stdin_text = stdin_text[:SCAN_BUDGET] + " " + stdin_text[-SCAN_BUDGET:]
    try:
        payload = json.loads(stdin_text)
    except (ValueError, RecursionError):
        # undo JSON's escapes so that "cat\t.env" or "...\\.env" still shows its name
        flat = re.sub(r'\\[nrtbf"]', " ", stdin_text.replace("\\\\", "/"))
        hits = find_env_files(flat)
        if hits:
            what = recipes_mod.printable(hits[0])
            return 0, json.dumps(decision_json(REASON.format(what=f"'{what}'"))) + "\n"
        budget = [SCAN_BUDGET]
        for piece in _pieces(flat, budget):
            what = steals_key(piece)
            if what:
                return 0, json.dumps(decision_json(STEAL_REASON.format(what=what))) + "\n"
        if oversized_write:
            return 0, json.dumps(decision_json(BIG_WRITE_REASON)) + "\n"
        return 1, ""
    if isinstance(payload, dict) and not isinstance(payload.get("tool_name", ""), str):
        return 1, ""  # not a shape Claude Code sends; a list would crash the set lookups
    if isinstance(payload, dict) and payload.get("hook_event_name") == "PostToolUse":
        return 0, post_check(payload)
    size = too_long(payload)
    if size is not None:
        return 0, json.dumps(decision_json(
            OVERSIZE_REASON.format(n=size, limit=MAX_COMMAND))) + "\n"
    name = decide(payload)
    if name is None:
        target = decide_protected_write(payload)
        if target:
            what = recipes_mod.printable(target)
            return 0, json.dumps(decision_json(
                PROTECTED_REASON.format(what=f"'{what}'"))) + "\n"
        leak = decide_code_leak(payload)
        if leak:
            kind, what = leak
            if kind == "big":
                return 0, json.dumps(decision_json(BIG_WRITE_REASON)) + "\n"
            if kind == "env":
                what = recipes_mod.printable(what)
                return 0, json.dumps(decision_json(
                    CODE_ENV_REASON.format(what=f"'{what}'"))) + "\n"
            return 0, json.dumps(decision_json(CODE_REASON.format(what=what))) + "\n"
        what = decide_steal(payload) or decide_secret_read(payload) or decide_mcp_key(payload)
        if what:
            return 0, json.dumps(decision_json(STEAL_REASON.format(what=what))) + "\n"
        return 0, ""
    what = recipes_mod.printable(name)
    if payload.get("tool_name") in WRITE_TOOLS:
        reason = WRITE_REASON.format(what=f"'{what}'")
    else:
        reason = REASON.format(what=f"'{what}'")
    return 0, json.dumps(decision_json(reason)) + "\n"


# ------------------------------------------------- PostToolUse: mask the output
#
# Claude Code runs the same `hook check` after a tool call (PostToolUse) with
# the call's result in tool_response. The answer `hookSpecificOutput.
# updatedToolOutput` replaces what the model sees; it must have the tool's
# own output shape or Claude Code ignores it and uses the original. Bash has
# a documented shape ({stdout, stderr, interrupted, isImage}); MCP tool output
# is "passed through without schema validation", so it is masked string by
# string in whatever shape it came. Read, Grep and every other tool are left
# alone (https://code.claude.com/docs/en/hooks).
# Fail-OPEN by Claude Code's design: a PostToolUse hook that breaks or times
# out cannot hold the output back, so an error here means the model sees the
# original output.

# Claude Code reads a matcher with anything beyond letters, digits, "_" and "|"
# as a regular expression, so this is anchored: Bash, or a tool named mcp__*.
POST_MATCHER = "^(Bash|mcp__.*)$"
POST_FIELDS = ("stdout", "stderr")
POST_NOTE = ("stuntkey hid {n} secret value(s) in this output as [REDACTED]. "
             "Do not try to recover them; if a command needs a key, ask the "
             "person to run `stuntkey run <service> -- <command>`.")


def post_check(payload: dict, err=None) -> str:
    """The PostToolUse answer for one tool call: "" (show the output as it
    is) or the JSON that replaces it with the secrets masked."""
    try:
        if _is_mcp(payload):
            return _post_mcp(payload.get("tool_response"))
        if payload.get("tool_name") != "Bash":
            return ""
        resp = payload.get("tool_response")
        if not isinstance(resp, dict):
            return ""
        from . import scrub as scrub_mod
        prints = scrub_mod.load_fingerprints()
        new, total = dict(resp), 0
        for field in POST_FIELDS:
            value = resp.get(field)
            if isinstance(value, str) and value:
                new[field], n = scrub_mod.mask_secrets(value, prints)
                total += n
        if not total:
            return ""
        return json.dumps({"hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": new,
            "additionalContext": POST_NOTE.format(n=total)}}) + "\n"
    except Exception as e:                      # fail open, but say so
        (err or sys.stderr).write(f"stuntkey hook: could not check the output "
                                  f"({type(e).__name__}); it is shown unmasked.\n")
        return ""


def _mask_all(value, prints, depth: int = 0):
    """(a copy of value with every string in it masked, how many were
    hidden). The shape stays: dicts, lists, numbers and keys as they were."""
    from . import scrub as scrub_mod
    if isinstance(value, str):
        return scrub_mod.mask_secrets(value, prints)
    if depth > MAX_DEPTH:
        return value, 0
    if isinstance(value, dict):
        done = {k: _mask_all(v, prints, depth + 1) for k, v in value.items()}
        return {k: v for k, (v, _n) in done.items()}, sum(n for _v, n in done.values())
    if isinstance(value, list):
        done = [_mask_all(v, prints, depth + 1) for v in value]
        return [v for v, _n in done], sum(n for _v, n in done)
    return value, 0


def _post_mcp(resp) -> str:
    """An MCP tool's result (a string, content blocks or an object) with your
    stored keys masked. Sent as updatedToolOutput (the field the docs prefer)
    and as updatedMCPToolOutput (the MCP-only field)."""
    from . import scrub as scrub_mod
    new, total = _mask_all(resp, scrub_mod.load_fingerprints())
    if not total:
        return ""
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedToolOutput": new,
        "updatedMCPToolOutput": new,
        "additionalContext": POST_NOTE.format(n=total)}}) + "\n"


def cmd_check(stdin=None, out=None, err=None) -> int:
    stdin = stdin or sys.stdin
    out = out or sys.stdout
    err = err or sys.stderr
    try:
        text = _read_all(stdin)
    except (OSError, ValueError):
        err.write("stuntkey hook check: could not read its input.\n")
        return 1
    status, answer = check(text)
    if status:
        err.write("stuntkey hook check: the input was not the JSON "
                  "Claude Code sends; nothing was blocked.\n")
        return status
    out.write(answer)
    return 0


# ----------------------------------------------------------------- the settings

def user_settings_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".claude", "settings.json")


def project_settings_path(cwd: str | None = None) -> str:
    return os.path.join(cwd or os.getcwd(), ".claude", "settings.json")


def _in_current_folder(path: str) -> bool:
    """Is `path` a file of the folder we are running in? Compared as the
    folders themselves, not as text: the same folder has more than one
    spelling (/var/... and /private/var/... on macOS, a link, 8.3 names or a
    different case on Windows), and getcwd() gives only one of them."""
    here = os.getcwd()
    folder = os.path.dirname(os.path.abspath(path))
    try:
        if os.path.samefile(folder, here):
            return True
    except OSError:
        pass
    def norm(p):
        return os.path.normcase(os.path.realpath(p))
    return norm(folder) == norm(here)


def console_script() -> str | None:
    """Absolute path of this install's `stuntkey` program, or None."""
    name = "stuntkey.exe" if _ON_WINDOWS else "stuntkey"
    candidates = [os.path.join(os.path.dirname(os.path.abspath(sys.executable)), name)]
    try:
        candidates.append(os.path.join(sysconfig.get_path("scripts"), name))
    except (KeyError, OSError):
        pass
    found = shutil.which("stuntkey")
    # never a program that sits in the current folder (Windows looks there first)
    if found and not _in_current_folder(found):
        candidates.append(found)
    for path in candidates:
        path = os.path.abspath(path)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def hook_argv() -> list[str]:
    """The program and arguments Claude Code will start: the installed program
    by its full path, so nothing is looked up on a search path an agent could
    change; or, where there is no such program, this Python in isolated mode
    (-I: ignores the current folder and PYTHON* variables)."""
    from . import clients
    me = clients.self_args()        # ["-m", "stuntkey"], or [path of stuntkey.pyz]
    script = console_script() if me[0] == "-m" else None
    if script:
        return [script, "hook", "check"]
    return [os.path.abspath(sys.executable), "-I", *me, "hook", "check"]


def _shell_quote(arg: str) -> str:
    if _ON_WINDOWS:
        # forward slashes: a backslash path is eaten by Git Bash
        arg = arg.replace("\\", "/")
        return '"' + arg + '"' if re.search(r"[\s&()^%!]", arg) else arg
    return shlex.quote(arg)


def hook_command() -> str:
    """The command as ONE string, for Claude Code's shell form (`sh -c` on
    macOS and Linux, Git Bash on Windows). Used on POSIX and, on Windows, only
    with --shell-form (older Claude Code)."""
    return " ".join(_shell_quote(a) for a in hook_argv())


def hook_handler(shell_form: bool | None = None, fail_closed: bool = True) -> dict:
    """The handler Claude Code stores: on Windows the documented exec form
    (`command` is the program, `args` its arguments, no shell, so a backslash
    or a space in the path cannot be mangled); elsewhere the shell string,
    which every Claude Code version understands. `shell_form=True` forces the
    string on Windows too, for a Claude Code that predates `args`."""
    if shell_form is None:
        shell_form = not _ON_WINDOWS
    handler: dict = {"type": "command"}
    if shell_form:
        handler["command"] = hook_command()
    else:
        argv = hook_argv()
        handler["command"], handler["args"] = argv[0], argv[1:]
    handler["timeout"] = HOOK_TIMEOUT
    handler["statusMessage"] = MARKER
    if fail_closed:
        handler["onFailure"] = "block"      # Claude Code 2.1.295 or later
    return handler


def hook_entry(handler: dict | None = None) -> dict:
    """One matcher group in settings.json -> hooks -> PreToolUse."""
    return {"matcher": MATCHER, "hooks": [handler or hook_handler()]}


def post_entry(handler: dict) -> dict:
    """Our group in hooks -> PostToolUse: the same program, without
    onFailure (a PostToolUse hook cannot hold output back anyway)."""
    handler = {k: v for k, v in handler.items() if k != "onFailure"}
    return {"matcher": POST_MATCHER, "hooks": [handler]}


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _is_our_command_string(cmd: str) -> bool:
    """Exactly `<stuntkey program> hook check` or `<python> -I -m
    stuntkey hook check` - what 0.5.0 wrote - and nothing else: no extra
    words, no `&&`, no other program."""
    try:
        tokens = [_unquote(t) for t in shlex.split(cmd, posix=False)]
    except ValueError:
        return False
    if tokens[-2:] != ["hook", "check"]:
        return False
    if len(tokens) == 3:
        return re.split(r"[\\/]", tokens[0])[-1].lower() in ("stuntkey", "stuntkey.exe", "oathkey", "oathkey.exe")
    return len(tokens) == 6 and tokens[2] == "-m" and tokens[3] in ("stuntkey", "oathkey") and tokens[1] == "-I"


def is_ours(handler) -> bool:
    """Is this handler the one stuntkey wrote? Yes if it carries our
    marker, or if its command is exactly one that 0.5.0 wrote. A hook that
    merely mentions stuntkey (`stuntkey scan`, `... hook check; evil`)
    is not ours."""
    if not isinstance(handler, dict):
        return False
    if handler.get("statusMessage") in (MARKER, *LEGACY_MARKERS):
        return True
    cmd = handler.get("command")
    return (isinstance(cmd, str) and "args" not in handler
            and _is_our_command_string(cmd))


def is_legacy(handler) -> bool:
    """One of ours that oathkey (0.8) wrote: its marker, or a bare
    `oathkey hook check` command. `hook install` replaces it."""
    if not is_ours(handler):
        return False
    if handler.get("statusMessage") in LEGACY_MARKERS:
        return True
    cmd = handler.get("command")
    return (handler.get("statusMessage") != MARKER and isinstance(cmd, str)
            and re.search(r"(?:^|[\\/\s\"'])oathkey(?:\.exe)?[\"']?\s+hook\s+check|-m\s+oathkey\s", cmd) is not None)


def legacy_handlers(data: dict) -> list:
    """The old handlers of ours in a settings dict (both events)."""
    found = []
    for event in ("PreToolUse", "PostToolUse"):
        try:
            groups = _pretool_list(data, create=False, event=event) or []
        except SettingsError:
            continue
        found += [h for _g, h in _our_handlers(groups) if is_legacy(h)]
    return found


def _confirm_legacy(data: dict, handler: dict, args, out) -> bool:
    """Show what replacing 0.8's hook changes and ask. True to go ahead."""
    old = legacy_handlers(data)
    if not old:
        return True
    diff = difflib.unified_diff(
        json.dumps(old, indent=2).splitlines(), json.dumps([handler], indent=2).splitlines(),
        "old (oathkey 0.8)", "new (stuntkey)", lineterm="")
    out.write("  Found the hook oathkey 0.8 installed. It will be replaced:\n"
              + "".join(f"    {recipes_mod.printable(line)}\n" for line in diff))
    if getattr(args, "yes", False):
        return True
    if not sys.stdin or not sys.stdin.isatty():
        out.write("  Not changed: run this in a terminal to answer, or add --yes.\n")
        return False
    out.write("  Replace it? [y/N] ")
    out.flush()
    try:
        return input("").strip().lower() in ("y", "yes")
    except EOFError:
        return False


class SettingsError(Exception):
    """The settings file cannot be safely changed. The text is for a person."""


def load_settings(path: str) -> dict:
    try:
        with open(path, encoding="utf-8-sig") as f:
            raw = f.read()
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise SettingsError(f"{path} could not be read ({e.strerror or e})")
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        raise SettingsError(f"{path} is not valid JSON, so I left it alone. "
                            f"Fix it (or move it aside) and run this again.")
    if not isinstance(data, dict):
        raise SettingsError(f"{path} does not hold a JSON object, so I left it alone.")
    return data


def _pretool_list(data: dict, create: bool, event: str = "PreToolUse") -> list | None:
    hooks = data.get("hooks")
    if hooks is None:
        if not create:
            return None
        hooks = data["hooks"] = {}
    if not isinstance(hooks, dict):
        raise SettingsError("the \"hooks\" part of the settings is not an "
                            "object, so I left the file alone.")
    groups = hooks.get(event)
    if groups is None:
        if not create:
            return None
        groups = hooks[event] = []
    if not isinstance(groups, list):
        raise SettingsError(f"\"hooks.{event}\" in the settings is not a "
                            "list, so I left the file alone.")
    return groups


def _inner(group):
    inner = group.get("hooks") if isinstance(group, dict) else None
    return inner if isinstance(inner, list) else None


def _our_handlers(groups: list):
    for group in groups:
        for handler in _inner(group) or ():
            if is_ours(handler):
                yield group, handler


def _is_our_own_group(group) -> bool:
    inner = _inner(group)
    return bool(inner) and all(is_ours(h) for h in inner)


def merge_install(data: dict, handler: dict | str) -> str:
    """Put our hook into `data` in place without touching anyone else's.
    It always lives in a matcher group of its own. A group that holds other
    people's handlers is never edited, except that OUR handler is taken out
    of it (an older install may have put it there). Returns "added",
    "updated" or "unchanged"."""
    if isinstance(handler, str):                    # a bare command string
        handler = dict(hook_handler(shell_form=True), command=handler)
    _pretool_list(data, create=False)               # check both shapes first
    _pretool_list(data, create=False, event="PostToolUse")
    pre = _merge_group(_pretool_list(data, create=True), hook_entry(handler))
    post = _merge_group(_pretool_list(data, create=True, event="PostToolUse"),
                        post_entry(handler))
    if pre == "added":
        return "added"
    return "unchanged" if pre == post == "unchanged" else "updated"


def _merge_group(groups: list, desired: dict) -> str:
    changed = False
    for group in list(groups):                      # our handler in a shared group
        inner = _inner(group)
        if inner and not _is_our_own_group(group) and any(is_ours(h) for h in inner):
            group["hooks"] = [h for h in inner if not is_ours(h)]
            changed = True
    own = [g for g in groups if _is_our_own_group(g)]
    if not own:
        groups.append(desired)
        return "added"
    first = own[0]
    for extra in own[1:]:
        groups.remove(extra)
        changed = True
    if first.get("matcher") != desired["matcher"] or first.get("hooks") != desired["hooks"]:
        first["matcher"], first["hooks"] = desired["matcher"], desired["hooks"]
        changed = True
    return "updated" if changed else "unchanged"


def merge_uninstall(data: dict) -> int:
    """Remove only our handlers (and groups left empty by that). Returns how
    many handlers were removed."""
    return sum(_uninstall_event(data, event) for event in ("PreToolUse", "PostToolUse"))


def _uninstall_event(data: dict, event: str) -> int:
    groups = _pretool_list(data, create=False, event=event)
    if not groups:
        return 0
    removed = 0
    for group in list(groups):
        inner = _inner(group)
        if inner is None:
            continue
        keep = [h for h in inner if not is_ours(h)]
        if len(keep) != len(inner):
            removed += len(inner) - len(keep)
            if keep:
                group["hooks"] = keep
            else:
                groups.remove(group)
    if removed and not groups:
        del data["hooks"][event]
        if not data["hooks"]:
            del data["hooks"]
    return removed


def backup_dir() -> str:
    """Where copies of changed settings files go: under the user's home, never
    inside a project (a project's .claude/ folder is often committed)."""
    return os.path.join(os.path.expanduser("~"), ".stuntkey", "backups")


def _backup(target: str) -> str:
    folder = backup_dir()
    os.makedirs(folder, mode=0o700, exist_ok=True)
    tag = hashlib.sha256(target.encode("utf-8", "replace")).hexdigest()[:8]
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    dest = os.path.join(folder, f"{tag}-{os.path.basename(target)}-{stamp}.bak")
    shutil.copy2(target, dest)
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    old = sorted(n for n in os.listdir(folder)
                 if n.startswith(tag + "-") and n.endswith(".bak"))
    for name in old[:-BACKUPS_TO_KEEP]:
        try:
            os.unlink(os.path.join(folder, name))
        except OSError:
            pass
    return dest


def save_settings(path: str, data: dict, had_file: bool) -> str | None:
    """Write atomically. A symbolic link is followed, so the file it points to
    is changed and the link stays a link. Every change first copies the old
    file to a new backup under ~/.stuntkey/backups (the last 20 per file are
    kept); returns the backup's path, or None for a new file."""
    target = os.path.realpath(path)
    folder = os.path.dirname(target)
    os.makedirs(folder, exist_ok=True)
    backup = _backup(target) if had_file and os.path.isfile(target) else None
    fd, tmp = tempfile.mkstemp(prefix=".settings-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        if had_file:
            try:
                os.chmod(tmp, os.stat(target).st_mode & 0o777)
            except OSError:
                pass
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return backup


def self_test(handler: dict | str, run=subprocess.run) -> bool:
    """Start the hook the way Claude Code does - exec form: the program with
    its arguments, no shell; shell form: `sh -c <string>` - on a made-up Read
    of .env and see that it says no. `handler` is always one THIS install
    generated, never one read from a file."""
    if isinstance(handler, str):
        handler = {"command": handler}
    sample = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read",
                         "tool_input": {"file_path": "/tmp/.env"}})
    if "args" in handler:
        argv = [handler["command"], *handler["args"]]
    elif _ON_WINDOWS:
        argv = hook_argv()          # Git Bash cannot be started faithfully here
    else:
        argv = ["/bin/sh", "-c", handler["command"]]
    try:
        done = run(argv, input=sample.encode(), capture_output=True,
                   shell=False, timeout=30, cwd=tempfile.gettempdir())
        answer = json.loads(done.stdout.decode("utf-8", "replace"))
        return answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    except Exception:
        return False


def _resolve_path(args) -> str:
    if getattr(args, "settings", None):
        return args.settings
    return project_settings_path() if args.project else user_settings_path()


def _backup_note(backup: str | None, project: bool) -> str:
    text = ""
    if backup:
        text += f"  The old file was copied to {recipes_mod.printable(backup)}\n"
    return text


def cmd_hook(args, out=None, err=None, run=subprocess.run) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    action = args.hook_cmd
    if action == "check":
        return cmd_check()
    path = _resolve_path(args)
    shown = recipes_mod.printable(path)
    try:
        if action == "status":
            return _status(args, out, run)
        data = load_settings(path)
        had_file = os.path.exists(path)
        if action == "install":
            handler = hook_handler(shell_form=True if getattr(args, "shell_form", False) else None,
                                   fail_closed=not getattr(args, "fail_open", False))
            if not _confirm_legacy(data, handler, args, out):
                out.write("  Left the old hook as it was.\n")
                return 1
            result = merge_install(data, handler)
            backup = None
            if result != "unchanged":
                backup = save_settings(path, data, had_file)
            out.write(f"  {'Already installed' if result == 'unchanged' else result.capitalize()}"
                      f": the stuntkey hook in {shown}\n")
            out.write(_backup_note(backup, getattr(args, "project", False)))
            out.write("  From now on Claude Code asks it before every Read, Grep, Bash, "
                      "PowerShell, Monitor, Edit, Write, MultiEdit, NotebookEdit and MCP "
                      "tool call, and it refuses .env files, stuntkey's own store and "
                      "commands that would use a stored key or print the environment.\n"
                      "  After a Bash command it also hides stored keys, and text in a "
                      "known key format, in the output before Claude sees it (best effort; "
                      "if that check fails, the output is shown as it is).\n")
            out.write(_offer_agent_rules(args, out))
            if handler.get("onFailure") == "block":
                out.write("  If the hook itself breaks or times out, the call is blocked "
                          "(fail closed). Use --fail-open to let calls through instead.\n")
            if getattr(args, "project", False):
                out.write("  This is the project's settings file: commit it if you want the "
                          "team to have the hook. Your hook's backups are kept outside the "
                          "project, in ~/.stuntkey/backups.\n")
            out.write("  Restart Claude Code (or open /hooks) so it picks the change up.\n")
            if not self_test(handler, run):
                out.write("  Warning: a test run of the hook did not answer as expected, "
                          "so it may not be protecting you yet.\n"
                          f"  Command: {recipes_mod.printable(_describe(handler))}\n")
                return 1
            return 0
        removed = merge_uninstall(data)
        if getattr(args, "project", False) and remove_agent_rules(os.getcwd()):
            out.write("  Took stuntkey's block out of this project's agent rules files.\n")
        if removed:
            backup = save_settings(path, data, had_file)
            out.write(f"  Removed the stuntkey hook from {shown}. "
                      f"Your other hooks were not touched.\n")
            out.write(_backup_note(backup, False))
        else:
            out.write(f"  No stuntkey hook found in {shown}; nothing changed.\n")
        return 0
    except SettingsError as e:
        err.write(f"error: {recipes_mod.printable(e)}\n")
        return 2
    except OSError as e:
        err.write(f"error: could not change {shown}: {e.strerror or e}\n")
        return 2


# ------------------------------------------------ the agent rules files (0.9.x)

RULES_FILES = ("CLAUDE.md", "AGENTS.md", ".cursorrules")
RULES_BEGIN = ("<!-- stuntkey:begin (added by `stuntkey hook install --project`; "
               "`stuntkey hook uninstall --project` removes it) -->")
RULES_END = "<!-- stuntkey:end -->"
RULES_TEXT = (
    "## API keys (stuntkey)\n"
    "- Use stuntkey for API keys: the `capture_key` / `needs_keys` tools, or ask the "
    "person to run `stuntkey connect <service>`.\n"
    "- Never read .env files (read .env.example for the variable names).\n"
    "- Never print, echo or hard-code a key.\n"
    "- A command that needs a key: ask the person to run "
    "`stuntkey run <service> -- <cmd>`.\n")
_RULES_BLOCK_RE = re.compile(r"\n*<!-- (?:stuntkey|oathkey):begin[^\n]*\n.*?"
                             r"<!-- (?:stuntkey|oathkey):end -->\n?", re.S)
# the block 0.8 (oathkey) added: replaced by ours on install, removed on uninstall
_LEGACY_RULES_RE = re.compile(r"\n*<!-- oathkey:begin[^\n]*\n.*?<!-- oathkey:end -->\n?", re.S)


def _rules_targets(folder: str) -> list[str]:
    """The rules files the project has; CLAUDE.md when it has none."""
    found = [os.path.join(folder, n) for n in RULES_FILES
             if os.path.isfile(os.path.join(folder, n))]
    return found or [os.path.join(folder, RULES_FILES[0])]


def _read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", newline="") as f:
            return f.read()
    except FileNotFoundError:
        return None


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)


def add_agent_rules(folder: str) -> list[str]:
    """Add stuntkey's short block to the project's agent rules files (the
    ones it has, else a new CLAUDE.md). A file that already has the block is
    left alone. Returns the files changed."""
    changed = []
    for path in _rules_targets(folder):
        old = _read_text(path) or ""
        if RULES_END in old:
            continue
        nl = "\r\n" if "\r\n" in old else "\n"
        if "<!-- oathkey:end -->" in old:       # 0.8's block: ours replaces it
            old = _LEGACY_RULES_RE.sub("\n", old.replace("\r\n", "\n")).strip("\n")
            old = (old + "\n").replace("\n", nl) if old.strip() else ""
        block = (RULES_BEGIN + "\n" + RULES_TEXT + RULES_END + "\n").replace("\n", nl)
        sep = "" if not old else (nl if old.endswith(nl) else nl + nl)
        _write_text(path, old + sep + block)
        changed.append(path)
    return changed


def remove_agent_rules(folder: str) -> list[str]:
    """The undo: take our block (only ours) out again; a file left empty by
    that is removed. Returns the files changed."""
    changed = []
    for name in RULES_FILES:
        path = os.path.join(folder, name)
        old = _read_text(path)
        if old is None or (RULES_END not in old and "<!-- oathkey:end -->" not in old):
            continue
        nl = "\r\n" if "\r\n" in old else "\n"
        new = _RULES_BLOCK_RE.sub("\n", old.replace("\r\n", "\n")).strip("\n")
        if new.strip():
            _write_text(path, (new + "\n").replace("\n", nl))
        else:
            os.unlink(path)
        changed.append(path)
    return changed


def _offer_agent_rules(args, out, ask=None) -> str:
    """Only with --project: on a yes at the prompt (asked only on a
    terminal), add the rules block. `args.agent_rules` True / False, when a
    caller sets it, answers for the person. Returns what to print."""
    choice = getattr(args, "agent_rules", None)
    if not getattr(args, "project", False) or choice is False:
        return ""
    names = ", ".join(os.path.basename(p) for p in _rules_targets(os.getcwd()))
    if not choice:
        if ask is None:
            if not sys.stdin or not sys.stdin.isatty():
                return (f"  Tip: run `stuntkey hook install --project` in a terminal to add a "
                        f"short \"use stuntkey for keys\" block to {names}.\n")
            ask = input
        out.write(f"  Add a short \"use stuntkey for keys, never read .env\" block "
                  f"to {names}? [y/N] ")
        out.flush()
        try:
            if ask("").strip().lower() not in ("y", "yes"):
                return ""
        except EOFError:
            return ""
    done = add_agent_rules(os.getcwd())
    if not done:
        return f"  {names}: stuntkey's block is already there.\n"
    return (f"  Added stuntkey's block to {', '.join(os.path.basename(p) for p in done)}. "
            f"`stuntkey hook uninstall --project` takes it out again.\n")


def _describe(handler: dict) -> str:
    return " ".join([handler.get("command", ""), *handler.get("args", [])])


def is_installed() -> bool:
    """Is our hook in the user's settings or in this folder's? Read only;
    an unreadable file counts as not installed."""
    for path in (user_settings_path(), project_settings_path()):
        try:
            groups = _pretool_list(load_settings(path), create=False) or []
        except SettingsError:
            continue
        if any(True for _ in _our_handlers(groups)):
            return True
    return False


def _status(args, out, run) -> int:
    paths = ([args.settings] if getattr(args, "settings", None)
             else [user_settings_path(), project_settings_path()])
    expected = hook_handler()
    tested: bool | None = None
    installed = False
    problem = False
    for path in paths:
        shown = recipes_mod.printable(path)
        try:
            data = load_settings(path)
            groups = _pretool_list(data, create=False) or []
        except SettingsError as e:
            out.write(f"  {shown}: cannot tell - {recipes_mod.printable(e)}\n")
            continue
        mine = list(_our_handlers(groups))
        if not mine:
            out.write(f"  {shown}: not installed\n")
            continue
        installed = True
        group, handler = mine[0]
        # NOTHING in the file is run: only the command this install generates
        if tested is None:
            tested = self_test(expected, run)
        notes = []
        post = list(_our_handlers(_pretool_list(data, create=False, event="PostToolUse") or []))
        if not post:
            notes.append("it does not hide keys in Bash or MCP tool output yet "
                         "(`stuntkey hook install` adds that)")
        elif post[0][0].get("matcher") != POST_MATCHER:
            notes.append("OUTDATED: its output masking does not cover every tool "
                         "this version does (MCP tools among them; run "
                         "`stuntkey hook install` to update it)")
        if group.get("matcher") != MATCHER:
            notes.append("OUTDATED: it does not watch every tool this version does "
                         "(MCP tools among them; run `stuntkey hook install` to update it)")
        if handler.get("onFailure") != "block":
            notes.append("it fails open: if the hook breaks, calls go through "
                         "(`stuntkey hook install` makes it block)")
        same = (handler.get("command") == expected["command"]
                and handler.get("args") == expected.get("args"))
        if not same:
            notes.append("its command is not the one this installation would write "
                         "(not run; `stuntkey hook install` rewrites it)")
        if tested:
            result = "this install's hook blocks a test read of .env"
        else:
            result = "but a test run of this install's hook did NOT block - reinstall it"
            problem = True
        extra = ("; " + "; ".join(notes)) if notes else ""
        out.write(f"  {shown}: installed, {result}{extra}\n")
    if not installed:
        out.write("  Not installed. Run: stuntkey hook install\n")
    return 0 if installed and not problem else 1
