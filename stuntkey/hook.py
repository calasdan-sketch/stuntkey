"""`stuntkey hook`: stop an AI agent reading your .env files.

Claude Code can run a small program before every tool call (a "PreToolUse
hook") and that program can say no. `hook install` adds one to Claude Code's
settings; `hook check` is that program. When the agent tries to Read, Grep,
or run a Bash, PowerShell or Monitor command that touches a .env file, or
tries to Edit, Write, MultiEdit or NotebookEdit one, the answer is "deny" and
the reason is handed back to the agent in plain words. Since 0.10 it also
reads what an Edit / Write would put in a file (a stored key, a program that
prints the environment) and, as a UserPromptSubmit hook, stops a prompt with a
pasted key before the model gets it.

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

# Ways a shell can pull a stored key out, or print it unredacted. Each is
# (regex, what it does). They are matched against the whole command text.
_SAFE = r"(?:^|[\s;&|`(\"'])"
# the start of a command (not a word in the middle of one), and its end
# 0.12: programs that just run another program (nohup env, timeout 5 env,
# nice env, /usr/bin/env, bash -lc 'export -p') no longer hide it
_WRAPPERS = (r"(?:(?:(?:sudo|command|builtin|nohup|time|exec|setsid|chronic)(?:\s+(?:-[-\w=]+|--))*|"
             r"taskset(?:\s+-\w+)*\s+[\w,]+|busybox|"
             r"stdbuf(?:\s+-[A-Za-z]\w*)*|nice(?:\s+-n\s*-?\d+)?|ionice(?:\s+-[A-Za-z]\w*)*|"
             r"timeout(?:\s+-[-\w=]+)*\s+\d+\w*|env\s+-i|xargs(?:\s+(?:-[A-Za-z0-9]+|\{\}))*|"
             r"watch(?:\s+-[A-Za-z]\w*)*)\s+)*(?:/(?:usr/)?(?:local/)?s?bin/)?")
# (every option part starts with "-" or is a fixed word, so a long run of
# wrappers can be read only one way: no catastrophic backtracking)
_CMD = (r"(?:^|[\n;&|(`{]|\bthen\b|\bdo\b|\bcmd(?:\.exe)?\s+/[ck]|\s-[a-z]*c)\s*(?:[\"']\s*)?"
        + _WRAPPERS)
_END = r"(?=$|\s*[\n|;&>)`}\"'])"
# upper case only: `for key in ...; do echo $key` is not a key
_SECRET_WORD = r"(?-i:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)"
# private keys and the credentials files tools keep in your home folder
_CRED_FILE = (r"(?:[\w.\-]*\.(?:pem|key|p12|pfx|jks|keystore)|id_(?:rsa|dsa|ecdsa|ed25519)|"
              r"\.netrc|_netrc|\.git-credentials|\.npmrc|\.pypirc|\.pgpass|"
              r"\.aws[/\\](?:credentials|config)|\.docker[/\\]config\.json|"
              r"\.kube[/\\]config|credentials\.json|application_default_credentials\.json|"
              r"service[-_]account[\w.\-]*\.json)(?=$|[\s\"'`;&|)>*])")
STEAL_RULES = (
    (re.compile(r"(?:stuntkey|oathkey)\b(?:(?!\s--\s)[^\n;&|]){0,300}\s--no-r\w*", re.I),
     "run a command with the key and turn output hiding off"),
    (re.compile(r"(?:(?:^|[\s;&|`(\"'/\\])(?:stuntkey|oathkey)(?:\.exe)?|\s-\w*m\s+(?:stuntkey|oathkey)(?:\.(?:cli|__main__))?)"
                r"(?:\s+--project-dir(?:\s+|=)\S+)*\s+"
                r"(?:remote|deploy|trust-server|export|run|serve|call|adopt|guard)(?![\w-])", re.I),
     "run a stuntkey command that uses or sends a stored key (remote, deploy, "
     "trust-server, export, run, serve, call, adopt, guard: only the person runs those)"),
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
    (re.compile(r"\bprint\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b(?!\s*[\[.])|"
                r"\bconsole\.(?:log|dir)\s*\(\s*process\.env\s*\)|"
                r"\bjson\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b", re.I),
     "print every environment variable from code"),
    (re.compile(_CMD + r"(?:sudo\s+)?(?:cat|type|Get-Content|gc|less|more|head|tail|grep|egrep|"
                r"fgrep|rg|ag|sed|awk|bat|nl|xxd|od|strings|base64|tac|cut|sort|uniq|"
                r"Select-String|sls)\b[^\n;&|]{0,300}?" + _CRED_FILE, re.I),
     "show a private key or a credentials file"),
    # 0.12: other tools' "print my login token" commands, and secret managers
    (re.compile(_SAFE + r"(?:gh\s+auth\s+token|gh\s+auth\s+status\b[^\n;&|]{0,100}\s(?:-t\b|--show-token)|"
                r"gcloud\s+auth\s+(?:application-default\s+)?print-(?:access|identity|refresh)-token|"
                r"aws\s+configure\s+(?:get\s+(?:aws_)?(?:secret_access_key|access_key_id|session_token)|export-credentials)|"
                r"heroku\s+auth:token|fly(?:ctl)?\s+auth\s+token|az\s+account\s+get-access-token|"
                r"npm\s+config\s+get\s+\S*auth\S*|"
                r"git\s+credential(?:-\w+)?\s+(?:fill|get)|"
                r"op\s+(?:read|inject)\b|op\s+item\s+get\b[^\n;&|]{0,100}--reveal|"
                r"bw\s+get\s+(?:password|item|totp|notes)|vault\s+(?:kv\s+get|read)\b|"
                r"doppler\s+secrets\b|infisical\s+(?:export|secrets)\b|sops\s+(?:-d|--decrypt)\b|"
                r"kubectl\s+config\s+view\b[^\n;&|]{0,100}--raw|"
                r"kubectl\s+get\s+secrets?\b[^\n;&|]{0,200}-o\s*(?:yaml|json|jsonpath))", re.I),
     "print a login token or secret from another tool (stuntkey makes the call for you instead)"),
    # whole-environment enumeration in an inline program (python -c, node -e,
    # ruby -e, perl -e, php -r, awk, deno, R): only the forms that list EVERY
    # variable; os.environ["NAME"] stays allowed
    (re.compile(r"\bos\.environ\s*\[\s*(\w+)\s*\][^\n]{0,60}\bfor\s+\1\s+in\s+(?:sorted\s*\(\s*)?os\.environ\b|"
                r"\bos\.environ\.(?:items|values|copy)\s*\(|\bdict\s*\(\s*os\.environ\s*\)|"
                r"\bObject\.(?:entries|values)\s*\(\s*(?:process|Bun)\.env\s*\)|"
                r"\bJSON\.stringify\s*\(\s*process\.env\b|\bnode\b[^\n;&|]{0,40}\s-p\s+[\"']?process\.env[\"']?\s*(?:$|[;&|])|"
                r"\bconsole\.\w+\s*\(\s*Bun\.env\s*\)|"
                r"\bENV\.(?:to_h|to_a|each|map|inspect)\b|[\s{(;]p\s+ENV\.to_h\b|"
                r"\b(?:keys|each|values)\s*\(?\s*%ENV\b|\bfor\s*\(\s*\w+\s+in\s+ENVIRON\s*\)|"
                r"\b(?:print_r|var_dump|var_export)\s*\(\s*(?:getenv\s*\(\s*\)|\$_ENV|\$_SERVER)|"
                r"\bDeno\.env\.toObject\b|\bSys\.getenv\s*\(\s*\)|\bprintln\s*\(\s*ENV\s*\)|"
                r"\bos\.Environ\s*\(\s*\)|\bSystem\.getenv\s*\(\s*\)\s*(?:\)|\.)"),
     "print every environment variable from an inline program"),
    # printing ONE key variable from an inline program / cmd.exe / PowerShell
    (re.compile(r"(?:\b(?:print|puts|say|printf|console\.\w+|echo|(?i:Write-(?:Output|Host)))\b[^\n;&|]{0,120}"
                r"(?:os\.environ(?:\[\s*|\.get\s*\(\s*)|os\.getenv\s*\(\s*|process\.env(?:\.|\[\s*)|"
                r"\bENV(?:\[\s*|\.fetch\s*\(\s*)|\$ENV\{\s*|\bgetenv\s*\(\s*)[\"']?\w*" + _SECRET_WORD + r"|"
                r"%\w*" + _SECRET_WORD + r"\w*%|\$\{env:\w*" + _SECRET_WORD + r"|"
                r"GetEnvironmentVariable\s*\(\s*[\"']\w*" + _SECRET_WORD + r")"),
     "print a key from an environment variable"),
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


# '.e' + 'nv', ('.e','nv') -> pieces a program joins at run time (0.12)
_JOIN_RE = re.compile(r"""(?<=['"`])\s*[+.,]\s*(?=['"`])""")

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


_WS_RUN_RE = re.compile(r"\s{2,}")


def _collapse_ws(text: str) -> str:
    """Every run of whitespace as one character: a newline if the run held
    one, else a space. The rules only ever ask for "some whitespace" or "a
    newline", so this never hides a match; it stops a command padded with
    thousands of newlines from making the whitespace patterns take seconds (a hook
    that times out is a hook that fails, and a --fail-open hook lets the
    call through). (0.10)"""
    return _WS_RUN_RE.sub(lambda m: "\n" if ("\n" in m.group() or "\r" in m.group()) else " ", text)


def steals_key(text: str, shell: bool = False) -> str | None:
    """What a shell command / path would do to a stored key, or None. A speed
    bump, not a lock: it reads the text of the call, and a program that builds
    its command at run time gets past it. `shell`: the text is a shell
    command, so DUMP_RULES apply too."""
    flat = text.replace("\\", "/") if "stuntkey" in text else text
    # collapsed AFTER squashing: taking quotes out can join whitespace runs
    variants = tuple(_collapse_ws(v) for v in (text, flat, *_squash(text)))
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


# Windows' short (8.3) name for ".env" is ENV~1 (0.12)
_SHORT_ENV_RE = re.compile(r"(?<![\w.\-])ENV~\d(?![\w~])", re.I)

# names a wildcard word is tried against (0.12)
_GLOB_TARGETS = (".env", ".envrc", ".env.local", ".env.production", ".env.development",
                 ".env.staging", ".env.test", "prod.env", "production.env", "local.env")
_GLOB_CHARS = re.compile(r"[*?\[{]")
_READERS_RE = re.compile(
    r"(?:^|[\s;&|(`])(?:cat|tac|nl|head|tail|less|more|bat|grep|egrep|fgrep|rg|ag|sed|awk|"
    r"xargs|od|xxd|hexdump|strings|base64|cut|sort|uniq|tr|fold|paste|diff|cp|dd|tee|type|"
    r"gc|Get-Content|Select-String|sls|findstr|source|\.)\s", re.I)


def _brace_expand(word: str, limit: int = 64) -> list[str]:
    """Expand {a,b} groups (one level at a time, at most `limit` results)."""
    out = [word]
    for _ in range(4):
        nxt = []
        changed = False
        for w in out:
            m = re.search(r"\{([^{}]*,[^{}]*)\}", w)
            if not m:
                nxt.append(w)
                continue
            changed = True
            for alt in m.group(1).split(","):
                nxt.append(w[:m.start()] + alt + w[m.end():])
        out = nxt[:limit]
        if not changed:
            break
    return out


def glob_env_hit(text: str, reading: bool) -> str | None:
    """A wildcard word (`.?nv`, `.e{n,}v`, `.en[v]`, `.e*`) that could be a
    .env file. For a shell command it counts only when a reading program is
    in the command (`ls .e*` is fine); a Read / Grep path or glob is always
    read. A word that is only wildcards (`*`, `.*`) is left alone. (0.12)"""
    if not _GLOB_CHARS.search(text):
        return None
    if reading and not _READERS_RE.search(text):
        return None
    for raw in re.findall(r"[^\s\"'`;&|<>()=]+", text)[:200]:
        if not _GLOB_CHARS.search(raw) or len(raw) > 200:
            continue
        last = re.split(r"[/\\]", raw)[-1]
        if not last or not re.search(r"[A-Za-z]", re.sub(r"\[[^\]]*\]", "", last)):
            continue                                  # no literal letter: too general
        for cand in _brace_expand(last):
            if not cand.startswith("."):
                continue              # `*env*` is no more a .env than `environment.py` is
            try:
                if any(fnmatch.fnmatchcase(t, cand.lower()) for t in _GLOB_TARGETS):
                    return raw
            except re.error:
                continue
    return None


def find_env_files(text: str) -> list[str]:
    """Every .env-style file name mentioned in a path or a shell command that
    is not a template."""
    found = []
    for m in ENV_NAME_RE.finditer(text.replace("\\", "/")):
        if not _is_template(m):
            found.append(m.group("name"))
    m = _SHORT_ENV_RE.search(text)
    if m:
        found.append(m.group(0))
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
        # count only the characters this window adds (not the overlap again),
        # so a text of exactly the budget is checked to its last character
        budget[0] -= min(step, len(piece))
        yield piece


def too_long(payload) -> int | None:
    """The length of a shell command that is too long to check, else None."""
    if not isinstance(payload, dict) or payload.get("tool_name") not in SHELL_TOOLS:
        return None
    for text in touched_text(payload):
        if len(text) > MAX_COMMAND:
            return len(text)
    return None


def decide(payload) -> str | None:
    """None to stay out of the way, or the name of the .env file refused."""
    if not isinstance(payload, dict):
        return None
    if payload.get("tool_name") in WRITE_TOOLS and writes_allowed():
        return None
    for text in touched_text(payload):
        hits = find_env_files(text)
        if hits:
            return hits[0]
        if re.search(r"[\'\"`^\\]", text):
            # c''at .e''nv, cat .\env: the shell joins the pieces, so look at the joined text too
            for variant in _squash(text) + (_squash(_JOIN_RE.sub("", text))[0],):
                hits = find_env_files(variant)
                if hits:
                    return hits[0]
        shell = payload.get("tool_name") in SHELL_TOOLS
        if len(text) <= CHUNK and (shell or payload.get("tool_name") in ("Read", "Grep")):
            hit = glob_env_hit(text, reading=shell)
            if hit is None and (shell or payload.get("tool_name") in ("Read", "Grep")):
                hit = glob_env_hit(_squash(text)[0], reading=shell)
            if hit:
                return hit
    return None


def decide_steal(payload) -> str | None:
    """None, or what a Bash / PowerShell / Monitor / Read / Grep call would
    do to a stored key (see STEAL_RULES)."""
    if not isinstance(payload, dict):
        return None
    budget = [SCAN_BUDGET]
    shell = payload.get("tool_name") in SHELL_TOOLS
    for text in touched_text(payload):
        for piece in _pieces(text, budget):
            what = steals_key(piece, shell)
            if what:
                return what
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


# ------------------------------------- what an Edit / Write would put in a file
#
# 0.10: the write tools are judged by their CONTENT too, not only their path.
# Two things are refused (STUNTKEY_HOOK_ALLOW_WRITE=1 turns both off, like the
# .env write check):
#   * one of YOUR stored keys written into any file (by fingerprint only, so a
#     fake key in a test fixture is never a false alarm). Seen in the wild: an
#     agent copying .env.local's values into env.example and pushing it, or
#     hard-coding a key into a test file
#     (https://github.com/anthropics/claude-code/issues/25053).
#   * a program whose output would be the whole environment or a .env file
#     (`print(os.environ)`, `console.log(process.env)`, a print of what a
#     read of .env returns). The hook sees the Write, not the later run, so this is the
#     one moment to stop it. A speed bump: a program that builds the same
#     thing at run time is not recognised.
# The text being REPLACED (Edit's old_string) is never judged: taking a key
# out of a file must stay possible.

_WRITE_PATH_KEYS = frozenset({"file_path", "notebook_path", "path"})
_WRITE_OLD_KEYS = frozenset({"old_string", "old_source"})

WRITE_KEY_REASON = (
    "stuntkey blocked this because it would write one of your stored keys into "
    "{what}. A key in a file gets committed, shared and read back into the chat. "
    "Read it from the environment instead (for example os.environ[\"NAME\"]) and "
    "ask the person to run the program with `stuntkey run <service> -- <command>`, "
    "or write a placeholder such as YOUR_KEY_HERE.")

WRITE_SCAN = SCAN_BUDGET      # characters of Edit / Write text checked; more is refused
WRITE_OVERSIZE_REASON = (
    "stuntkey blocked this because the text to write is {n} characters long, more "
    "than the {limit} the hook can check. Write the file in smaller parts, or ask "
    "the person to write it (or to start Claude Code with STUNTKEY_HOOK_ALLOW_WRITE=1).")

WRITE_DUMP_REASON = (
    "stuntkey blocked this because the program written to {what} would {how}; "
    "when it runs, the keys land in the chat. Print only the names (for example "
    "sorted(os.environ) or Object.keys(process.env)), or check that one variable "
    "is set without printing its value.")

# Code that prints the WHOLE environment. A single named variable
# (os.environ["X"], process.env.X, ENV["X"]) is not matched.
CODE_DUMP_RULES = (
    (re.compile(r"\b(?:print|pprint|pp|logging\.\w+|log(?:ger)?\.\w+|sys\.std(?:out|err)\.write)"
                r"\s*\(\s*(?:f?[\"'][^\"'\n]{0,80}[\"']\s*[,%+]\s*)?(?:dict\s*\(\s*|str\s*\(\s*|repr\s*\(\s*)?"
                r"os\.environ(?:\.(?:items|copy|values)\s*\(\s*\))?\s*\)", re.I),
     "print every environment variable"),
    (re.compile(r"\bjson\.dumps?\s*\(\s*(?:dict\s*\(\s*)?os\.environ\b(?!\s*[\[.])"), "print every environment variable"),
    (re.compile(r"\bconsole\.(?:log|dir|info|warn|error|debug|table)\s*\(\s*"
                r"(?:[`\"'][^`\"'\n]{0,80}[`\"']\s*[,+]\s*)?(?:\{\s*\.\.\.\s*)?process\.env\s*\}?\s*\)|"
                r"\bJSON\.stringify\s*\(\s*process\.env\s*[,)]|"
                r"\bObject\.(?:entries|values)\s*\(\s*process\.env\s*\)\s*\)\s*;?\s*$", re.M),
     "print every environment variable"),
    (re.compile(r"(?m)^[ \t]*(?:puts|p|pp|print)[ \t]*\(?[ \t]*ENV(?:\.to_h|\.inspect)?[ \t]*\)?[ \t]*$"),
     "print every environment variable"),
    (re.compile(r"\bfmt\.(?:Print|Fprint)\w*\s*\([^\n)]{0,40}os\.Environ\s*\(\s*\)|"
                r"\bSystem\.(?:out|err)\.print\w*\s*\(\s*System\.getenv\s*\(\s*\)\s*\)|"
                r"\b(?:print_r|var_dump|var_export)\s*\(\s*(?:\$_ENV|\$_SERVER|getenv\s*\(\s*\))\s*[,)]"),
     "print every environment variable"),
)

# 0.10.0 (panel review): the easy rewrites of the above. An alias (e = os.environ; print(e)),
# an f-string, a loop that prints each value, process["env"]. Still a speed
# bump: code built at run time, or a name the alias search does not follow,
# gets past it.
_ALIAS_RE = re.compile(r"(?m)(?:^|;)[ \t]*(?:const|let|var)?[ \t]*([A-Za-z_]\w{0,40})[ \t]*=[ \t]*"
                       r"(?:dict[ \t]*\([ \t]*|\{[ \t]*\.\.\.[ \t]*)?"
                       r"(?:os\.environ|process\.env|process\[[\"']env[\"']\])(?:\.copy\(\))?[ \t]*[)}]?[ \t]*(?=;|$)")
_PRINT_CALL = (r"\b(?:print|pprint|pp|puts|logging\.\w+|log(?:ger)?\.\w+|sys\.std(?:out|err)\.write|"
               r"console\.(?:log|dir|info|warn|error|debug|table))\s*\(")
CODE_DUMP_EXTRA = (
    re.compile(_PRINT_CALL + r"\s*f[\"'][^\"'\n]{0,200}\{\s*(?:dict\s*\(\s*)?os\.environ\s*\)?\s*(?:![rsa])?\s*\}"),
    re.compile(_PRINT_CALL + r"[^\n]{0,40}`[^`\n]{0,200}\$\{\s*(?:JSON\.stringify\s*\(\s*)?process\.env\s*\)?\s*\}"),
    re.compile(_PRINT_CALL + r"\s*(?:\{\s*\.\.\.\s*)?process\[\s*[\"']env[\"']\s*\]\s*\}?\s*\)"),
    re.compile(_PRINT_CALL + r"[^\n)]{0,80}\*\s*os\.environ\.(?:items|values)\s*\("),
    # for k, v in os.environ.items(): print(k, v)   /   for k in os.environ: print(os.environ[k])
    re.compile(r"\bfor\s+(\w+)\s*,\s*(\w+)\s+in\s+(?:sorted\s*\(\s*)?os\.environ\.items\s*\(\s*\)\s*\)?\s*:"
               r"(?:[^\n]*\n){0,3}?[^\n]*" + _PRINT_CALL + r"[^\n]*\b\2\b"),
    re.compile(r"\bfor\s+(\w+)\s+in\s+(?:sorted\s*\(\s*)?os\.environ\s*\)?\s*:"
               r"(?:[^\n]*\n){0,3}?[^\n]*" + _PRINT_CALL + r"[^\n]*os\.environ\s*(?:\[\s*\1\s*\]|\.get\s*\(\s*\1\b)"),
    # for (const [k, v] of Object.entries(process.env)) console.log(k, v)
    re.compile(r"Object\.entries\s*\(\s*process\.env\s*\)[^\n]{0,80}?\[\s*\w+\s*,\s*(\w+)\s*\]"
               r"(?:[^\n]*\n){0,3}?[^\n]*" + _PRINT_CALL + r"[^\n]*\b\1\b"),
    re.compile(r"\[\s*\w+\s*,\s*(\w+)\s*\]\s+of\s+Object\.entries\s*\(\s*process\.env\s*\)"
               r"(?:[^\n]*\n){0,3}?[^\n]*" + _PRINT_CALL + r"[^\n]*\b\1\b"),
)


_PRINTED_NAME_RE = re.compile(_PRINT_CALL + r"\s*(?:dict\s*\(\s*|JSON\.stringify\s*\(\s*)?"
                              r"([A-Za-z_]\w{0,40})\s*(?:\.(?:items|copy)\s*\(\s*\))?\s*[),]")


def _env_dump_rewrite(text: str) -> bool:
    if any(rx.search(text) for rx in CODE_DUMP_EXTRA):
        return True
    names = {m.group(1) for m in _ALIAS_RE.finditer(text)}
    for m in re.finditer(r"\bfrom\s+os\s+import\s+([^\n;]{1,200})", text):
        for part in m.group(1).strip("() ").split(","):
            bits = part.split()
            if bits and bits[0] == "environ":
                names.add(bits[2] if len(bits) == 3 and bits[1] == "as" else "environ")
    if not names:
        return False
    # one pass over the print calls, whatever the number of aliases
    return any(m.group(1) in names for m in _PRINTED_NAME_RE.finditer(text))


# Shell and PowerShell scripts: the whole-environment dumps a Bash call is
# refused for (DUMP_RULES 0 and 3), checked line by line in the script text.
_SCRIPT_SUFFIX_RE = re.compile(r"\.(?:sh|bash|zsh|ksh|fish|ps1|psm1|bat|cmd)\Z", re.I)

# A line that prints and reads a real .env file (a print of a read of '.env'),
# console.log(fs.readFileSync('.env', 'utf8')), cat .env in a script.
_PRINT_WORD_RE = re.compile(
    r"\b(?:print|pprint|puts|echo|cat|type|console\.\w+|Write-(?:Output|Host)|"
    r"fmt\.(?:Print|Fprint)\w*|System\.(?:out|err)\.print\w*|logging\.\w+|logger\.\w+)\b", re.I)
# 0.10.0 (panel review): the .env name must be the ARGUMENT of the read, not just on the
# same line (`cp .env.example .env; cat <<EOF` and `console.error('no key in
# .env'); fs.readFileSync(p)` are not refused).
_CODE_READ_RE = re.compile(
    r"\b(?:open|readFile(?:Sync)?|File\.read|ReadAllText|ReadFile|file_get_contents|"
    r"io\.open|codecs\.open)\s*\(\s*(?:[rbuf]{0,2})[\"'`]([^\"'`\n]{1,300})[\"'`]|"
    r"\bPath\s*\(\s*[rbuf]{0,2}[\"'`]([^\"'`\n]{1,300})[\"'`]\s*\)\s*\.read_(?:text|bytes)\b", re.I)
_SHELL_READ_RE = re.compile(
    r"(?:^|[;&|(`]|\$\()\s*(?:sudo\s+)?(?:cat|type|Get-Content|gc|head|tail|less|more|bat|nl|tac)"
    r"(?:\s+-{1,2}[\w-]+)*\s+[\"']?([^\s\"';&|<>()`]{1,300})", re.I | re.M)


def _prints_env_file(line: str, script: bool) -> bool:
    """Does this line show a real .env file: a print of a read whose argument
    is .env, or (in a shell script) cat / type / Get-Content .env?"""
    if script:
        for m in _SHELL_READ_RE.finditer(line):
            if find_env_files(m.group(1)):
                return True
    if not _PRINT_WORD_RE.search(line):
        return False
    for m in _CODE_READ_RE.finditer(line):
        if find_env_files(m.group(1) or m.group(2) or ""):
            return True
    return False


def written_text(payload: dict) -> list[str]:
    """The text a write tool would put in a file: Write's content, Edit's
    new_string, MultiEdit's edits[].new_string, NotebookEdit's new_source.
    Read as every string in tool_input except the path and the text being
    replaced, so a renamed field cannot slip past."""
    args = payload.get("tool_input") if isinstance(payload, dict) else None
    if payload.get("tool_name") not in WRITE_TOOLS or not isinstance(args, dict):
        return []
    out: list[str] = []

    def walk(value, depth: int) -> None:
        if len(out) >= MAX_STRINGS or depth > MAX_DEPTH:
            return
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            for k, v in value.items():
                if k in _WRITE_OLD_KEYS or (depth == 0 and k in _WRITE_PATH_KEYS):
                    continue
                walk(v, depth + 1)
        elif isinstance(value, (list, tuple)):
            for v in value:
                walk(v, depth + 1)
    walk(args, 0)
    return out


def _target_name(payload: dict) -> str:
    paths = touched_text(payload)
    return recipes_mod.printable(paths[0]) if paths else "a file"


# docs, not programs (.md, .rst, ...): a README that shows `print(os.environ)`
# or `cat .env` is not refused. The stored-key check still applies to them.
# .txt is NOT treated as docs (`python notes.txt` runs it just as well).
_DOC_SUFFIX_RE = re.compile(r"\.(?:md|markdown|mdx|rst|adoc|org)\Z", re.I)


def _dump_in_code(text: str, script: bool, prose: bool = False) -> str | None:
    if prose:
        return None
    text = _collapse_ws(text)
    for rx, how in CODE_DUMP_RULES:
        if rx.search(text):
            return how
    if _env_dump_rewrite(text):
        return "print every environment variable"
    if script:
        for rx, how in (DUMP_RULES[0], DUMP_RULES[3]):
            if rx.search(text):
                return how
    if ".env" in text.lower():
        for line in text.splitlines():
            if len(line) <= 2000 and _prints_env_file(line, script):
                return "print a .env file (that is where keys live)"
    return None


def decide_write_content(payload) -> str | None:
    """The deny reason for a write whose content holds a stored key or is a
    program that prints the environment / a .env file, else None."""
    if not isinstance(payload, dict) or payload.get("tool_name") not in WRITE_TOOLS:
        return None
    if writes_allowed():
        return None
    texts = written_text(payload)
    if not texts:
        return None
    total = sum(len(t) for t in texts)
    if total > WRITE_SCAN:
        # 0.10.0 checked the first WRITE_SCAN characters and let the rest
        # through unread; a key past that point was written. Fail closed.
        return WRITE_OVERSIZE_REASON.format(n=total, limit=WRITE_SCAN)
    from . import scrub as scrub_mod
    try:
        prints = scrub_mod.load_fingerprints()
    except (OSError, ValueError):
        prints = (b"", frozenset())
    where = _target_name(payload)
    paths = [re.sub(r"::\$DATA\Z", "", p.strip(), flags=re.I).rstrip(" .")
             for p in touched_text(payload)]
    script = any(_SCRIPT_SUFFIX_RE.search(p) for p in paths)
    prose = bool(paths) and all(_DOC_SUFFIX_RE.search(p) for p in paths)
    budget = [SCAN_BUDGET]
    for text in texts:
        for piece in _pieces(text, budget):
            if scrub_mod.has_stored_key(piece, prints):
                return WRITE_KEY_REASON.format(what=f"'{where}'")
            how = _dump_in_code(piece, script, prose)
            if how:
                return WRITE_DUMP_REASON.format(what=f"'{where}'", how=how)
    return None


# ------------------------------------------- UserPromptSubmit: a pasted key
#
# A key pasted into a prompt goes to the AI company and into the chat log. The
# hook blocks the prompt (`decision: "block"`; Claude never gets it) and keeps
# the text out of the block message (`suppressOriginalPrompt`). What counts: one
# of YOUR stored keys (fingerprint), a key in a well-known vendor format, or a
# private key block - not the looser "NAME = value" guesses the Bash mask uses,
# so a prompt that talks ABOUT keys goes through. STUNTKEY_HOOK_ALLOW_PROMPT=1
# turns it off. Claude Code still keeps the typed text in its local transcript
# and history files; this only stops it reaching the model.
# https://code.claude.com/docs/en/hooks#userpromptsubmit

PROMPT_EVENT = "UserPromptSubmit"
_PROMPT_EVENT_RE = re.compile(r'(?<!\\)"hook_event_name"\s*:\s*"' + PROMPT_EVENT + '"')
PROMPT_SCAN = 4_000_000      # characters of a prompt checked in full (about a second)
ALLOW_PROMPT_VAR = "STUNTKEY_HOOK_ALLOW_PROMPT"
PROMPT_REASON = (
    "stuntkey stopped this message before it reached Claude: it holds an API key "
    "or a private key. Anything you send goes to the AI company and stays in the "
    "chat log. Take the key out and send it again. To give Claude access to a "
    "service, run `stuntkey get <service>` in a terminal instead. If this key is "
    "real and was pasted anywhere else, run `stuntkey panic <service>`. "
    "(Claude Code may still keep what you typed in its local history files.)")


def _prompt_fallback(raw: str) -> str:
    """A prompt too big (or too odd) to parse as JSON: look at the raw text."""
    return prompt_check({"prompt": raw.replace("\\n", "\n")})


def prompt_check(payload: dict, environ=None) -> str:
    """The UserPromptSubmit answer: "" (let it through) or the block JSON."""
    env = environ if environ is not None else os.environ
    if env.get(ALLOW_PROMPT_VAR, "").strip() == "1":
        return ""
    prompt = payload.get("prompt")
    if not isinstance(prompt, str) or not prompt:
        return ""
    from . import scrub as scrub_mod
    try:
        prints = scrub_mod.load_fingerprints()
    except (OSError, ValueError):
        prints = (b"", frozenset())
    # a prompt is checked whole up to PROMPT_SCAN characters (about a second);
    # past that, only its start and its end
    half = PROMPT_SCAN // 2
    parts = [prompt] if len(prompt) <= PROMPT_SCAN else [prompt[:half], prompt[-half:]]
    if not any(scrub_mod.has_pasted_secret(piece, prints)
               for part in parts for piece in _pieces(part, [len(part)])):
        return ""
    return json.dumps({
        "decision": "block",
        "reason": PROMPT_REASON,
        "hookSpecificOutput": {"hookEventName": PROMPT_EVENT,
                               "suppressOriginalPrompt": True},
    }) + "\n"


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
    # the event name anywhere at JSON level (an unescaped quote: inside a
    # string it would read \"hook_event_name\"), whatever the field order
    is_prompt = _PROMPT_EVENT_RE.search(stdin_text) is not None
    limit = PROMPT_SCAN if is_prompt else 2 * SCAN_BUDGET
    truncated = len(stdin_text) > limit
    if truncated:
        # only ever look at a bounded amount: the start and the end
        stdin_text = stdin_text[:limit // 2] + " " + stdin_text[-(limit // 2):]
    try:
        payload = json.loads(stdin_text)
    except (ValueError, RecursionError):
        if is_prompt:
            return 0, _prompt_fallback(stdin_text)
        if truncated and not re.search(r'(?<!\\)"hook_event_name"\s*:\s*"PostToolUse"', stdin_text):
            # too big to read whole and too big to parse once cut: nothing in
            # it was checked, so say no (before 0.10.0 this was a non-blocking
            # error, which a --fail-open install let through)
            return 0, json.dumps(decision_json(WRITE_OVERSIZE_REASON.format(
                n=len(stdin_text), limit=WRITE_SCAN).replace(
                    "the text to write is", "this tool call is"))) + "\n"
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
        return 1, ""
    if isinstance(payload, dict) and payload.get("hook_event_name") == "PostToolUse":
        return 0, post_check(payload)
    if isinstance(payload, dict) and payload.get("hook_event_name") == PROMPT_EVENT:
        return 0, prompt_check(payload)
    if truncated and isinstance(payload, dict) and payload.get("tool_name") in WRITE_TOOLS:
        # the middle was cut out yet the rest still parsed: what was dropped
        # is exactly what was never checked. Fail closed. (0.10.0)
        return 0, json.dumps(decision_json(WRITE_OVERSIZE_REASON.format(
            n=len(stdin_text), limit=WRITE_SCAN))) + "\n"
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
        what = decide_steal(payload) or decide_secret_read(payload) or decide_mcp_key(payload)
        if what:
            return 0, json.dumps(decision_json(STEAL_REASON.format(what=what))) + "\n"
        reason = decide_write_content(payload)
        if reason:
            return 0, json.dumps(decision_json(reason)) + "\n"
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
# own output shape or Claude Code ignores it and uses the original. Only Bash
# has a documented shape ({stdout, stderr, interrupted, isImage}); Read, Grep
# and every other tool are left alone (https://code.claude.com/docs/en/hooks).
# Fail-OPEN by Claude Code's design: a PostToolUse hook that breaks or times
# out cannot hold the output back, so an error here means the model sees the
# original output.

POST_MATCHER = "Bash"
# every event `hook install` writes a group of ours into (0.10 adds the prompt)
HOOK_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit")
POST_FIELDS = ("stdout", "stderr")
POST_NOTE = ("stuntkey hid {n} secret value(s) in this output as [REDACTED]. "
             "Do not try to recover them; if a command needs a key, ask the "
             "person to run `stuntkey run <service> -- <command>`.")


def post_check(payload: dict, err=None) -> str:
    """The PostToolUse answer for one tool call: "" (show the output as it
    is) or the JSON that replaces it with the secrets masked."""
    try:
        if payload.get("tool_name") != POST_MATCHER:
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


def prompt_entry(handler: dict) -> dict:
    """Our group in hooks -> UserPromptSubmit (no matcher: that event has
    none). Without onFailure: a broken hook must not stop you typing."""
    handler = {k: v for k, v in handler.items() if k != "onFailure"}
    return {"hooks": [handler]}


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
    for event in HOOK_EVENTS:
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
    for event in HOOK_EVENTS:                       # check every shape first
        _pretool_list(data, create=False, event=event)
    pre = _merge_group(_pretool_list(data, create=True), hook_entry(handler))
    post = _merge_group(_pretool_list(data, create=True, event="PostToolUse"),
                        post_entry(handler))
    prompt = _merge_group(_pretool_list(data, create=True, event=PROMPT_EVENT),
                          prompt_entry(handler))
    if pre == "added":
        return "added"
    return "unchanged" if pre == post == prompt == "unchanged" else "updated"


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
    if first.get("matcher") != desired.get("matcher") or first.get("hooks") != desired["hooks"]:
        if "matcher" in desired:
            first["matcher"] = desired["matcher"]
        else:
            first.pop("matcher", None)
        first["hooks"] = desired["hooks"]
        changed = True
    return "updated" if changed else "unchanged"


def merge_uninstall(data: dict) -> int:
    """Remove only our handlers (and groups left empty by that). Returns how
    many handlers were removed."""
    return sum(_uninstall_event(data, event) for event in HOOK_EVENTS)


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
                      "if that check fails, the output is shown as it is).\n"
                      "  It also stops a message you send to Claude if an API key is pasted "
                      "in it, and refuses an Edit or Write that would put a stored key in a "
                      "file or write a program that prints the environment.\n")
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
        if not list(_our_handlers(_pretool_list(data, create=False, event="PostToolUse") or [])):
            notes.append("it does not hide keys in Bash output yet (`stuntkey hook "
                         "install` adds that)")
        if not list(_our_handlers(_pretool_list(data, create=False, event=PROMPT_EVENT) or [])):
            notes.append("it does not stop keys pasted into a prompt yet (`stuntkey hook "
                         "install` adds that)")
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
