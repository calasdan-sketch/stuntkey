"""`stuntkey scan`: find API keys that leaked into files an AI agent reads.

An AI coding agent reads the instruction files and settings in your project
(CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, the .claude folder) and, if
you let it, your .env files. A key pasted into any of those is in the
agent's memory and in its conversation log. This module finds them.

What it does, in order of how careful it has to be:

1. It only ever READS regular files. A named pipe, a device, a symbolic link
   that leaves the folder, a file over 1 MB, a binary file, .git and
   node_modules are skipped and never opened, so a scan cannot hang.
2. It is OFFLINE. Detection is pattern matching only. Nothing leaves the
   computer unless you pass --validate and agree to the list of hosts.
3. It NEVER prints a whole key. A key is shown as its first 4 and last 2
   characters ("sk-p...Zk"), in every output format and every message.
4. It cannot be made to hang by a hostile file: every pattern runs on bounded
   pieces of a line, each file has a time budget, and your own recipes'
   patterns (which could be anything) are off unless you ask (--my-recipes)
   and are then run under a timer.
5. It never calls a clean result clean when it did not look at everything: a
   limit that was hit (too many files, too deep, a folder it could not open,
   out of time) is reported as INCOMPLETE and exits 2.

Detection uses (a) the key format of each built-in recipe, (b) a short list
of well-known key prefixes for services that have no recipe, (c) NAME=value
where NAME ends in KEY, TOKEN, SECRET or PASSWORD and the value looks random,
(d) `Bearer <token>`, (e) a password inside a connection URL, and (f) a line
that is nothing but one high-entropy token (a .token or .secret file, or a
credential pasted on a line of its own), which belongs to no known service
and is therefore reported as a guess.
Placeholders ("your_key_here", "xxxx", "<token>", "example") are ignored.
"""

from __future__ import annotations

import bisect
import collections
import contextlib
import dataclasses
import hashlib
import json
import math
import os
import re
import signal
import stat
import sys
import threading
import time
import urllib.parse

from . import __version__
from . import connect as connect_mod
from . import validate as validate_mod
from . import recipes as recipes_mod
from . import safeprompt
from .recipes import printable

MAX_FILE_BYTES = 1024 * 1024       # a bigger file is skipped, never read
CHUNK = 8192                       # a line is matched in pieces of this size ...
CHUNK_OVERLAP = 1024               # ... that overlap by this much
ASSIGN_WINDOW = 2000               # NAME=value is looked for in windows this big
ASSIGN_OVERLAP = 300
MAX_ENTRIES = 2_000_000            # raw folder entries looked at, then stop
MAX_DIRS = 20000                   # folders opened, then stop
MAX_CANDIDATES = 50000             # files to read (not every file: only these count)
MAX_DEPTH = 12
MAX_FINDINGS_PER_FILE = 500
MAX_VALIDATIONS = 50               # distinct keys sent per run
BINARY_PROBE = 8192
WALK_SECONDS = 60                  # time to find the files
FILE_SECONDS = 10.0                # time to scan one file
SCAN_SECONDS = 300.0               # time to scan all of them
USER_PATTERN_SECONDS = 0.25        # one of YOUR recipe patterns on one piece of a line

PRUNE_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
    # build output and dependency folders: huge, generated, never an agent's
    # instructions
    "target", "build", "dist", ".next", ".nuxt", ".svelte-kit", ".gradle",
    ".terraform", ".cache", ".parcel-cache", ".turbo", ".nx", "coverage",
    "site-packages", "bower_components", "Pods", ".eggs",
})
AGENT_FILES = frozenset({
    "claude.md", "claude.local.md", "agents.md", "gemini.md", ".cursorrules",
    ".windsurfrules", ".mcp.json",
})
# Files whose whole purpose is to hold a credential. An agent reads one of
# these as readily as CLAUDE.md, so the default scan looks at them too: a key
# in a file named .token is exactly what this tool exists to catch.
CREDENTIAL_FILES = frozenset({
    ".token", ".secret", ".secrets", ".netrc", "_netrc", ".npmrc", ".pypirc",
    ".pgpass", ".git-credentials", ".dockercfg", "credentials",
    "credentials.json", "client_secret.json", "service-account.json",
})
CREDENTIAL_SUFFIXES = (".token", ".secret", ".credentials")
AGENT_DIRS = frozenset({".claude"})

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/calasdan-sketch/stuntkey"

STATUSES = ("unchecked", "live", "dead", "unknown")


# ------------------------------------------------------------------ redaction

def redact(value: str) -> str:
    """First 4 and last 2 characters, nothing else. A short value shows even
    less. This is the ONLY way a key may appear in any output."""
    if len(value) < 12:
        return value[:2] + "..."
    return value[:4] + "..." + value[-2:]


# --------------------------------------------------------------- placeholders

# A stand-in is recognised by a WORD, never by a stretch of letters inside a
# key: "abc123" inside a real random key must not throw the key away. A word
# counts when it is a whole token (letters and digits between punctuation), or
# for the "prefix" words when a token starts with it (xxxxxxxx, yourkeyhere).
PLACEHOLDER_SYMBOLS = ("<", ">", "{", "}", "*", "...", "\u2026", "$(", "${", "%",
                       "process.env")
PLACEHOLDER_PREFIXES = (
    "your", "xxx", "changeme", "change_me", "change-me", "example", "placeholder",
    "dummy", "fake", "sample", "replace", "insert", "redacted", "paste",
    "generate", "openssl", "environ", "getenv", "abc123", "123456", "qwerty",
    "abcdef",
)
PLACEHOLDER_WHOLE = (
    "here", "todo", "fixme", "notreal", "not_real", "mykey", "my_key", "my-key",
    "test_key", "testkey",
)
PLACEHOLDER_WORD_RE = re.compile(
    r"(?<![a-z0-9])(?:" + "|".join(re.escape(w) for w in PLACEHOLDER_PREFIXES) + r")"
    r"|(?<![a-z0-9])(?:" + "|".join(re.escape(w) for w in PLACEHOLDER_WHOLE)
    + r")(?![a-z0-9])")
# Keys printed in vendors' own documentation: public, never secret.
DOC_KEYS = frozenset({"sk_" "test_4eC39HqLyjWDarjtT1zdp7dc",
                      # AWS's documented sample access key pair
                      "AKIA" "IOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" "EXAMPLEKEY"})
TRIVIAL_PASSWORDS = frozenset({
    "password", "passw0rd", "password1", "postgres", "admin", "administrator",
    "root", "secret", "changeme", "example", "test", "testing", "default",
    "mysql", "guest", "letmein", "welcome", "12345678", "123456789", "qwertyui",
    "pass", "user", "username", "redis", "mongo", "database", "dbpassword",
})


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    n = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    """Does this look like a stand-in rather than a real key?"""
    v = value.strip().strip("\"'`")
    low = v.lower()
    if not v or v in DOC_KEYS:
        return True
    if any(sym in low for sym in PLACEHOLDER_SYMBOLS):
        return True
    if PLACEHOLDER_WORD_RE.search(low):
        return True
    if re.search(r"(.)\1{5,}", v):          # xxxxxxx, 000000, aaaaaa
        return True
    if len(set(v)) < 6:
        return True
    return False


def looks_random(body: str, minimum: float = 3.0) -> bool:
    """A real key mixes letters and digits and is not a repeating word."""
    return (any(c.isdigit() for c in body) and any(c.isalpha() for c in body)
            and entropy(body) >= minimum)


# ------------------------------------------------------------------- patterns

@dataclasses.dataclass
class Rule:
    provider: str | None        # recipe slug, or None for a service without a recipe
    name: str                   # shown to people
    regex: re.Pattern
    kind: str                   # "recipe-pattern" | "known-prefix"
    confidence: str             # "known" | "guess"
    can_validate: bool = True   # False when the match cannot be proven by the recipe
    prefix_len: int = 0         # literal prefix length: longest wins an overlap
    check_body: bool = True
    literal: str | None = None  # text every match contains: a cheap pre-check
    trusted: bool = True        # False: a pattern from YOUR recipe, run under a timer
    disabled: bool = False


def _literal_prefix(pattern: str) -> int:
    n = 0
    for ch in pattern.lstrip("^("):
        if ch in "[\\(.*+?{|":
            break
        n += 1
    return n


_LITERAL_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-:/")


def _required_literal(pattern: str) -> str | None:
    """Text that every match of `pattern` must contain, when that is easy to
    see (the plain characters it starts with). Used only to skip a pattern on a
    piece of text that cannot match; None means "always run it"."""
    core = pattern[1:] if pattern.startswith("^") else pattern
    if "|" in core or core.startswith("(") or "(?" in pattern:
        return None
    run = ""
    for i, ch in enumerate(core):
        if ch not in _LITERAL_CHARS:
            if ch in "?*{" and run:
                run = run[:-1]             # the quantifier makes the last one optional
            break
        run += ch
    return run if len(run) >= 2 else None


def _wrap(pattern: str) -> re.Pattern | None:
    core = pattern
    if core.startswith("^"):
        core = core[1:]
    if core.endswith("$") and not core.endswith("\\$"):
        core = core[:-1]
    try:
        return re.compile(r"(?<![A-Za-z0-9_])(?:" + core + r")(?![A-Za-z0-9])")
    except re.error:
        return None


# Well-known prefixes. "known" = the format is documented or has been stable
# for years. "guess" = recent or lightly documented: such a finding says so.
# (provider slug or None, display name, pattern, confidence, can_validate)
KNOWN_PREFIXES = (
    ("google-gemini", "Google API key", r"AIza[0-9A-Za-z_-]{35}", "known", False),
    (None, "Slack token", r"xox[abprs]-[A-Za-z0-9-]{10,}", "known", False),
    (None, "Slack webhook URL",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
     "known", False),
    (None, "Discord webhook URL",
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{50,}",
     "known", False),
    (None, "Stripe webhook signing secret", r"whsec_[A-Za-z0-9+/=]{24,}", "known", False),
    (None, "npm token", r"npm_[A-Za-z0-9]{36}", "known", False),
    (None, "Shopify token", r"shp(?:at|ca|pa|ss)_[a-f0-9]{32}", "known", False),
    ("discord", "Discord bot token",
     r"[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}", "known", True),
    ("supabase", "Supabase access token", r"sbp_[a-f0-9]{40}", "guess", True),
    (None, "Supabase secret API key", r"sb_secret_[A-Za-z0-9_-]{20,}", "guess", False),
    ("notion", "Notion token", r"ntn_[A-Za-z0-9]{30,}", "guess", True),
    ("netlify", "Netlify token", r"nfp_[A-Za-z0-9]{30,}", "guess", True),
    ("pinecone", "Pinecone key", r"pcsk_[A-Za-z0-9_]{40,}", "guess", True),
)
# Fields whose "pattern" matches an identifier, not a secret.
IDENTIFIER_FIELDS = frozenset({("twilio", "sid")})

PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")
BASE64_LINE_RE = re.compile(r"^\s*[A-Za-z0-9+/=]{20,}\s*$")
# the same key written on ONE line inside JSON/YAML: ...-----\nMIIE...
ESCAPED_PEM_BODY_RE = re.compile(r"(?:\\r)?\\n[A-Za-z0-9+/=]{20,}")

ASSIGN_RE = re.compile(
    r"""(?<![A-Za-z0-9_.\-])(?P<name>[A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[=:]\s*["']?"""
    r"""(?P<value>[A-Za-z0-9_\-+/=.~]{8,})""")
SECRET_NAME_RE = re.compile(
    r"(?i)(?:^|[_.\-])(?:api_?key|key|token|secret)$|"
    r"(?:api|access|auth|private|client|secret|bearer)Key$|[a-z](?:Token|Secret)$")
PASSWORD_NAME_RE = re.compile(
    r"(?i)(?:^|[_.\-])(?:password|passwd|pwd|passphrase)$|[a-z](?:Password|Passwd|Passphrase)$")
NOT_SECRET_NAME_RE = re.compile(
    r"(?i)public|publishable|site_?key|sort_?key|primary_?key|foreign_?key|"
    r"cache_?key|partition_?key|key_?name|ssh_?key_?path|idempotency|file_?key|"
    r"object_?key|row_?key|record_?key|project_?key|issue_?key|lookup_?key|"
    r"translation_?key|node_?key|storage_?key|s3_?key|"
    r"password_?(?:hash|file|path|reset|policy|field|length|label|prompt|"
    r"confirm\w*|required|expir\w*)")
# A name that points at a public or non-vendor value: never mapped to a vendor
# (a Supabase anon JWT, a Google Maps key and a webhook URL are public by design
# or belong to another service than the name suggests).
NO_VENDOR_NAME_RE = re.compile(r"(?i)webhook|anon|maps|public")
HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
# A reference to a key, not a key: AUTH0_CLIENT_SECRET, settings.api_key
CODE_REF_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]*|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)$")
# a package file or version string, not a key: hf_xet-1.2.0-cp37-abi3.whl
VERSIONED_RE = re.compile(r"\d+\.\d+\.\d+")
# an identifier written in lower case: get_password_from_env, not a password
SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
# an MCP tool name in an allow-list: mcp__plugin_figma__get_screenshot
MCP_TOOL_RE = re.compile(r"^mcp__[A-Za-z0-9_-]+$")
BEARER_RE = re.compile(
    r"""(?i)(?<![A-Za-z0-9_])bearer[ \t]+["']?(?P<value>[A-Za-z0-9_\-+/=.~]{20,})""")
URL_PASSWORD_RE = re.compile(
    r"""(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{1,20}://"""
    r"""(?P<user>[^\s:/@'"<>]{1,100}):(?P<password>[^\s@/'"<>]{3,200})@""")
# A line holding ONE token and nothing else: the whole content of a .token or
# .secret file, or a credential pasted on a line of its own. There is no
# vendor prefix and no NAME= to go by, so such a finding is always a guess and
# can never be checked against a service.
BARE_MIN = 24
# "=" only as base64 padding at the END: with it allowed in the middle, a whole
# NAME=value line is one "token" and the rule above would be reported twice.
BARE_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/.~]{%d,400}={0,2}" % BARE_MIN)
# A lone line that is a FILE NAME, not a key. Lists of files on a line each
# (SOURCES.txt, MANIFEST.in, a .gitignore) are otherwise long, mixed-case
# enough and random-looking enough to pass for credentials. A real key may
# contain "/" (an AWS secret does), so the file extension is what decides.
BARE_PATH_RE = re.compile(
    r"(?i)\.(?:py[icdw]?|pyi|js|mjs|cjs|jsx|ts|tsx|json|jsonc|md|rst|txt|log|"
    r"ya?ml|toml|ini|cfg|conf|lock|properties|html?|css|scss|less|svg|xml|csv|"
    r"tsv|sh|bash|zsh|fish|bat|cmd|ps1|psm1|rs|go|java|kt|rb|php|pl|lua|swift|"
    r"[ch]|[ch]pp|cc|hh|cs|m|mm|sql|png|jpe?g|gif|ico|webp|pdf|zip|gz|tgz|bz2|"
    r"xz|tar|whl|egg|jar|so|dylib|dll|exe|bin|dat|db|sqlite3?|bak|tmp|orig|"
    r"patch|diff|in|cfn|tf|tfvars|proto|ipynb|map|min|d)$")


def build_rules(catalog: dict) -> list[Rule]:
    """Every recipe's key format plus the well-known prefixes, most specific
    first (so sk-ant-... is Anthropic, not just "sk-"). A pattern from a recipe
    of YOUR OWN (not shipped inside the package) is marked untrusted: it runs
    only under a timer, and only where a timer exists."""
    rules: list[Rule] = []
    for slug, recipe in catalog.items():
        trusted = recipe.get("_builtin") is True
        if not trusted and not user_patterns_usable():
            continue
        for field in recipes_mod.fields(recipe):
            pattern = field.get("detect")
            if not pattern or (slug, field["name"]) in IDENTIFIER_FIELDS:
                continue
            rx = _wrap(pattern)
            if rx is not None:
                rules.append(Rule(slug, recipe["display"], rx, "recipe-pattern",
                                  field.get("detect_confidence", "known"), True, _literal_prefix(pattern),
                                  check_body=",}" in pattern,
                                  literal=_required_literal(pattern),
                                  trusted=trusted))
    for provider, name, pattern, confidence, can_validate in KNOWN_PREFIXES:
        if provider is not None and provider not in catalog:
            provider_ok = None
        else:
            provider_ok = provider
        display = (catalog[provider_ok]["display"] if provider_ok else name)
        rx = _wrap(pattern)
        if rx is not None:
            rules.append(Rule(provider_ok, display if provider_ok else name, rx,
                              "known-prefix", confidence, can_validate,
                              _literal_prefix(pattern),
                              check_body=",}" in pattern,
                              literal=_required_literal(pattern)))
    rules.sort(key=lambda r: -r.prefix_len)
    return rules


# ------------------------------------------------- a timer for YOUR patterns

class _PatternTimeout(Exception):
    pass


def user_patterns_usable() -> bool:
    """Can a pattern from a recipe of your own be run safely here? Only where
    the operating system can interrupt it (a timer signal, main thread)."""
    return (hasattr(signal, "setitimer") and hasattr(signal, "SIGALRM")
            and threading.current_thread() is threading.main_thread())


@contextlib.contextmanager
def _pattern_timer(seconds: float):
    def fire(_signum, _frame):
        raise _PatternTimeout()
    old = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _name_tokens(catalog: dict) -> dict[str, str]:
    """Lower-case words in an environment-variable name -> recipe slug."""
    words: dict[str, str] = {}
    for slug, recipe in catalog.items():
        for var in recipes_mod.env_vars(recipe):
            if var.upper() == var:
                words.setdefault(var.lower(), slug)
        first = recipe["env_var"].split("_")[0].lower()
        words.setdefault(first, slug)
        words.setdefault(slug.lower(), slug)
        for part in slug.split("-"):
            if len(part) > 3:
                words.setdefault(part.lower(), slug)
    return words


def _provider_hint(name: str, catalog: dict, words: dict[str, str]) -> tuple[str | None, bool]:
    """(recipe slug, exact) a variable name points at. `exact` is True when the
    name IS one of the recipe's variable names (GROQ_API_KEY); False when only
    the service's name appears inside it (OPENAI_KEY). Names that are public by
    design or belong to a webhook are never mapped."""
    if NO_VENDOR_NAME_RE.search(name):
        return None, False
    upper = re.sub(r"[.\-]", "_", name).upper()
    for slug, recipe in catalog.items():
        if upper in (v.upper() for v in recipes_mod.env_vars(recipe)):
            return slug, True
    for token in re.split(r"[_]", upper.lower()):
        if token in words:
            return words[token], False
    return None, False


def provider_for_name(name: str, catalog: dict, words: dict[str, str]) -> str | None:
    """Which recipe does this variable name belong to? Exact variable name
    first (GROQ_API_KEY), then the service's name inside it (OPENAI_KEY)."""
    return _provider_hint(name, catalog, words)[0]


def _matches_recipe(recipe: dict, value: str) -> bool:
    """Does `value` have the key format this recipe says its key has?"""
    for field in recipes_mod.fields(recipe):
        pattern = field.get("detect")
        if not pattern or (recipe.get("service"), field["name"]) in IDENTIFIER_FIELDS:
            continue
        try:
            if recipe.get("_builtin") is True:
                if re.fullmatch(pattern, value):
                    return True
            elif user_patterns_usable():
                with _pattern_timer(USER_PATTERN_SECONDS):
                    if re.fullmatch(pattern, value):
                        return True
        except (re.error, _PatternTimeout):
            continue
    return False


# -------------------------------------------------------------------- finding

@dataclasses.dataclass
class Finding:
    file: str
    line: int
    column: int
    provider: str | None
    provider_name: str
    rule: str
    confidence: str
    redacted: str
    status: str = "unchecked"
    detail: str = ""
    key_url: str | None = None
    can_validate: bool = True
    skip_reason: str = ""       # why it can never be sent, when can_validate is False
    fix: str = ""               # a better next step than the default (MCP configs, bundles)
    _value: str = dataclasses.field(default="", repr=False, compare=False)

    @property
    def next_step(self) -> str:
        return next_step_text(self)


def next_step_text(f: Finding) -> str:
    """Plain words: what to do about this one."""
    if f.fix:
        return f.fix
    if f.skip_reason.startswith("it is a password"):
        return ("Change this password where it is set (the database or service "
                "that uses it), then keep the new one out of files an AI agent reads.")
    if f.provider and f.key_url:
        base = (f"Rotate it at {printable(f.key_url)}, then run "
                f"`stuntkey connect {f.provider}` to save the new one safely.")
    elif f.provider:
        base = (f"Rotate it in your {printable(f.provider_name, words=True)} "
                f"account, then run `stuntkey connect {f.provider}`.")
    else:
        base = (f"Rotate it in the account of the service that issued it "
                f"(make a new key, then revoke this one). "
                f"`stuntkey list` shows the services that have a guided setup.")
    if f.status == "dead":
        who = printable(f.provider_name, words=True) if f.provider else "the service"
        return (f"Rejected by {who}: it may be revoked, or it may not be a "
                f"{who} key at all. Rotate it if you are unsure. " + base)
    if f.status == "unchecked" and f.can_validate:
        base += " Add --validate to see whether it still works."
    return base


# ------------------------------------------------------------------- scanning

class Budget:
    """A time allowance. `hit` becomes True once it ran out; `notes` collects
    reasons a scan is incomplete."""

    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + seconds
        self.hit = False
        self.notes: list[str] = []

    def expired(self) -> bool:
        if time.monotonic() > self.deadline:
            self.hit = True
        return self.hit


def _secret_value_ok(value: str) -> bool:
    return not (is_placeholder(value) or value[0] in "/~." or ".." in value
                or value.isdigit() or HOSTNAME_RE.match(value)
                or (CODE_REF_RE.match(value) and not value.startswith("eyJ"))
                or not looks_random(value, 3.5))


def _password_value_ok(value: str) -> bool:
    low = value.lower()
    if (is_placeholder(value) or value[0] in "/~." or ".." in value
            or low in TRIVIAL_PASSWORDS or HOSTNAME_RE.match(value)
            or CODE_REF_RE.match(value) or SNAKE_RE.match(value)):
        return False
    if value[0] == "_" or not (any(c.isdigit() for c in value) or any(c in "-+/=~" for c in value)):
        return False            # letters only: a class or function name, not a password
    return len(set(value)) >= 4 and entropy(value) >= 2.5


def scan_text(text: str, rel: str, rules: list[Rule], catalog: dict,
              words: dict[str, str] | None = None,
              budget: Budget | None = None) -> list[Finding]:
    """Find keys in one file's text. Pure: no files, no network. Every pattern
    runs on a piece of a line of at most CHUNK characters (or ASSIGN_WINDOW),
    so the time is proportional to the size; `budget` stops it early."""
    words = words if words is not None else _name_tokens(catalog)
    budget = budget or Budget(FILE_SECONDS)
    findings: list[Finding] = []
    lines = text.splitlines()
    # A PEM block's body is line after line of base64; it is already reported
    # once by its header, so bare-token lines are not looked for in such a file.
    # ponytail: whole file, not the block's line range - a certificate would
    # otherwise be reported once per body line. The cost is that a bare token
    # sitting beside a PEM block in the same file is missed; track the BEGIN/END
    # range per line if that turns up in practice.
    pem = "-----BEGIN " in text
    for number, raw in enumerate(lines, 1):
        if budget.expired():
            break
        nxt = lines[number] if number < len(lines) else ""
        room = MAX_FINDINGS_PER_FILE - len(findings)
        found = _scan_line(raw, nxt, number, rel, rules, catalog, words, budget, room,
                           pem=pem)
        findings.extend(found)
        if len(found) >= room:
            budget.notes.append(f"more than {MAX_FINDINGS_PER_FILE} keys in this "
                                f"file; the rest were not listed")
            break
    return findings


def _scan_line(raw: str, nxt: str, number: int, rel: str, rules: list[Rule],
               catalog: dict, words: dict[str, str], budget: Budget,
               room: int = MAX_FINDINGS_PER_FILE, pem: bool = False) -> list[Finding]:
    out: list[Finding] = []
    n = len(raw)
    if n < 8:
        return out
    starts: list[int] = []
    ends: dict[int, int] = {}

    def free(a: int, b: int) -> bool:
        i = bisect.bisect_left(starts, a)
        if i > 0 and ends[starts[i - 1]] > a:
            return False
        return not (i < len(starts) and starts[i] < b)

    def take(a: int, b: int) -> None:
        bisect.insort(starts, a)
        ends[a] = b

    def add(rule_name, confidence, provider, display, start, end, can_validate,
            skip_reason=""):
        if len(out) >= room:
            return
        value = raw[start:end]
        trimmed = value.rstrip(".-_")           # "key sk-...abc." is the key without the "."
        if trimmed and trimmed != value:
            end = start + len(trimmed)
            value = trimmed
        take(start, end)
        recipe = catalog.get(provider) if provider else None
        out.append(Finding(
            file=rel, line=number, column=start + 1, provider=provider,
            provider_name=display, rule=rule_name, confidence=confidence,
            redacted=redact(value),
            key_url=recipe["key_url"] if recipe else None,
            can_validate=can_validate, skip_reason=skip_reason, _value=value))

    pieces = [(0, n)] if n <= CHUNK else [
        (off, min(n, off + CHUNK)) for off in range(0, n, CHUNK - CHUNK_OVERLAP)]

    # a private key: its header, followed by the key body
    for off, end in pieces:
        if raw.find("PRIVATE KEY-----", off, end) < 0:
            continue
        m = PRIVATE_KEY_RE.search(raw, off, end)
        if m and free(m.start(), m.end()):
            tail = raw[m.end():m.end() + 80]
            if (BASE64_LINE_RE.match(nxt) or nxt.startswith("Proc-Type")
                    or ESCAPED_PEM_BODY_RE.match(tail)
                    or tail.startswith("\\nProc-Type")):
                take(m.start(), m.end())
                out.append(Finding(
                    file=rel, line=number, column=m.start() + 1, provider=None,
                    provider_name="Private key", rule="private-key-block",
                    confidence="known", redacted="(private key)",
                    can_validate=False, _value=""))

    # the key formats
    for off, end in pieces:
        if budget.expired():
            return out
        last = end == n
        for rule in rules:
            if rule.disabled or (rule.literal and raw.find(rule.literal, off, end) < 0):
                continue
            try:
                if rule.trusted:
                    matches = list(rule.regex.finditer(raw, off, end))
                else:
                    with _pattern_timer(USER_PATTERN_SECONDS):
                        matches = list(rule.regex.finditer(raw, off, end))
            except _PatternTimeout:
                rule.disabled = True
                budget.notes.append(
                    "a pattern in one of your own recipes took too long and was "
                    "switched off for the rest of this scan")
                continue
            for m in matches:
                if len(out) >= room:
                    return out
                if not last and m.end() == end and m.start() >= end - CHUNK_OVERLAP:
                    continue                    # the next piece sees all of it
                value = m.group(0)
                if (not free(m.start(), m.end()) or is_placeholder(value)
                        or VERSIONED_RE.search(value)):
                    continue
                body = value[rule.prefix_len:] or value
                if rule.check_body and not looks_random(
                        body, 2.5 if rule.confidence == "known" else 3.2):
                    continue
                add(rule.kind, rule.confidence, rule.provider, rule.name,
                    m.start(), m.end(), rule.can_validate)

    # Bearer <token>
    for off, end in pieces:
        if "earer" not in raw[off:end] and "EARER" not in raw[off:end]:
            continue
        for m in BEARER_RE.finditer(raw, off, end):
            if (free(m.start("value"), m.end("value"))
                    and _secret_value_ok(m.group("value"))):
                add("bearer-token", "name-and-randomness", None, "Bearer token",
                    m.start("value"), m.end("value"), False,
                    "the service it belongs to is not known")

    # a password inside a connection URL
    for off, end in pieces:
        if raw.find("://", off, end) < 0:
            continue
        for m in URL_PASSWORD_RE.finditer(raw, off, end):
            pw = m.group("password")
            plain = urllib.parse.unquote(pw)
            if (not free(m.start("password"), m.end("password"))
                    or plain.lower() in TRIVIAL_PASSWORDS
                    or plain == m.group("user") or is_placeholder(plain)):
                continue
            add("url-password", "name-and-randomness", None,
                "Password in a connection URL", m.start("password"),
                m.end("password"), False, "it is a password, not an API key")

    # NAME=value where the name says it is secret
    if "=" in raw or ":" in raw:
        step = ASSIGN_WINDOW - ASSIGN_OVERLAP
        for woff in range(0, n, step):
            if budget.expired():
                return out
            wend = min(n, woff + ASSIGN_WINDOW)
            for m in ASSIGN_RE.finditer(raw, woff, wend):
                if len(out) >= room:
                    return out
                name, value = m.group("name"), m.group("value")
                is_pw = bool(PASSWORD_NAME_RE.search(name))
                if (NOT_SECRET_NAME_RE.search(name)
                        or not (is_pw or SECRET_NAME_RE.search(name))
                        or not free(m.start("value"), m.end("value"))):
                    continue
                if is_pw:
                    if not _password_value_ok(value):
                        continue
                    add("named-assignment", "name-and-randomness", None,
                        f"Password ({printable(name)})", m.start("value"),
                        m.end("value"), False, "it is a password, not an API key")
                    continue
                if len(value) < 20 or not _secret_value_ok(value):
                    continue
                provider, exact = _provider_hint(name, catalog, words)
                recipe = catalog.get(provider) if provider else None
                matches_format = bool(recipe) and _matches_recipe(recipe, value)
                if provider and not exact and not matches_format:
                    provider = None             # a guess from a word in the name: say nothing
                if provider:
                    display = catalog[provider]["display"]
                    if not matches_format:
                        display = f"Possibly {display} (named {printable(name)})"
                else:
                    display = f"Unrecognised key ({printable(name)})"
                add("named-assignment", "name-and-randomness", provider, display,
                    m.start("value"), m.end("value"), matches_format,
                    "" if matches_format else
                    "it does not have this service's key format, so it was not sent")

    # Last: a line that is nothing but one high-entropy token. Every rule
    # above had its chance, so this only fires on a credential that matches no
    # vendor format and has no name beside it - a .token file, a bare bearer
    # token. Without a name or a prefix the service cannot be known, so it is
    # reported as a guess and is never sent anywhere.
    if not pem and len(out) < room:
        value = raw.strip().strip("\"'`,;")
        start = raw.find(value) if value else -1
        if (start >= 0 and BARE_TOKEN_RE.fullmatch(value)
                and free(start, start + len(value))
                and not VERSIONED_RE.search(value)
                and not HOSTNAME_RE.match(value)
                and not MCP_TOOL_RE.match(value)
                and not BARE_PATH_RE.search(value)
                and _secret_value_ok(value)):
            add("bare-token", "guess", None,
                "Unrecognised key (a line with nothing else on it)",
                start, start + len(value), False,
                "the service it belongs to is not known, so it cannot be checked")
    return out


@dataclasses.dataclass
class Skipped:
    path: str
    reason: str
    incomplete: bool = False     # True: this leaves part of the folder unchecked


def _is_agent_name(name: str) -> bool:
    return name in AGENT_FILES or name in CREDENTIAL_FILES or name == ".env" \
        or name.startswith(".env.") or name.endswith(".env") \
        or name.endswith(CREDENTIAL_SUFFIXES)


def _is_agent_path(parts: tuple[str, ...]) -> bool:
    name = parts[-1].lower()
    if _is_agent_name(name):
        return True
    return any(p in AGENT_DIRS for p in parts[:-1])


def _within(real: str, root_real: str) -> bool:
    try:
        return os.path.commonpath([real, root_real]) == root_real
    except ValueError:
        return False


def _utf16_guess(data: bytes) -> str | None:
    """UTF-16 text without a byte-order mark: every other byte is zero."""
    sample = data[:BINARY_PROBE]
    even, odd = sample[0::2], sample[1::2]
    if len(odd) >= 4 and odd.count(0) >= 0.9 * len(odd) and even.count(0) == 0:
        return "utf-16-le"
    if len(even) >= 4 and even.count(0) >= 0.9 * len(even) and odd.count(0) == 0:
        return "utf-16-be"
    return None


def read_text_safely(path: str, root_real: str,
                     limit: int = MAX_FILE_BYTES) -> tuple[str | None, str | None]:
    """(text, None) or (None, why-it-was-skipped). Opens only a regular file
    of at most MAX_FILE_BYTES, without blocking and without following a link
    that leaves `root_real`. UTF-8 (with or without a byte-order mark) and
    UTF-16 (what PowerShell's `>` writes) are both read."""
    try:
        st = os.lstat(path)
        real = path
        if stat.S_ISLNK(st.st_mode):
            real = os.path.realpath(path)
            if not _within(real, root_real):
                return None, "a link that leads outside the folder"
            st = os.stat(real)
        if not stat.S_ISREG(st.st_mode):
            return None, "not a regular file (pipe, device or folder)"
        if st.st_size > limit:
            return None, f"bigger than {limit // (1024 * 1024)} MB"
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        fd = os.open(real, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None, "not a regular file (pipe, device or folder)"
            chunks, total = [], 0
            while total <= limit:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            os.close(fd)
    except OSError as e:
        return None, f"could not be read ({e.strerror or 'error'})"
    data = b"".join(chunks)
    if len(data) > limit:
        return None, f"bigger than {limit // (1024 * 1024)} MB"
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace"), None
    guess = _utf16_guess(data)
    if guess:
        return data.decode(guess, errors="replace"), None
    if b"\0" in data[:BINARY_PROBE]:
        return None, "a binary file"
    return data.decode("utf-8-sig", errors="replace"), None


def collect_files(root: str, everything: bool = False
                  ) -> tuple[list[str], list[Skipped], int]:
    """(files worth reading under `root`, notes, how many files were passed
    over), nearest first. Only files that will be READ count toward the limits
    (an agent file hidden behind 50,000 empty files is still found). Folders
    that are links, or that lead outside the root (a Windows junction), are
    never entered. Every limit that stops the walk early is reported as an
    incomplete Skipped note.

    Without `everything` only an agent's instruction, settings and credential
    files are queued; the third value counts the rest, so a caller can say how
    much it did not look at instead of calling the result clean."""
    files: list[str] = []
    notes: list[Skipped] = []
    passed_over = 0
    root_real = os.path.realpath(root)
    seen_dirs = {root_real}
    deadline = time.monotonic() + WALK_SECONDS
    raw_entries = 0
    dirs_opened = 0
    queue = collections.deque([(root, 0, False)])
    while queue:
        directory, depth, in_agent = queue.popleft()
        if time.monotonic() > deadline:
            notes.append(Skipped(".", f"stopped after {WALK_SECONDS} seconds of looking "
                                      f"for files", True))
            return files, notes, passed_over
        dirs_opened += 1
        if dirs_opened > MAX_DIRS:
            notes.append(Skipped(".", f"stopped after opening {MAX_DIRS} folders", True))
            return files, notes, passed_over
        try:
            entries = []
            with os.scandir(directory) as it:
                for entry in it:
                    raw_entries += 1
                    if raw_entries > MAX_ENTRIES:
                        notes.append(Skipped(".", f"stopped after looking at {MAX_ENTRIES} entries", True))
                        return files, notes, passed_over
                    if raw_entries % 20000 == 0 and time.monotonic() > deadline:
                        notes.append(Skipped(".", f"stopped after {WALK_SECONDS} seconds of "
                                                  f"looking for files", True))
                        return files, notes, passed_over
                    entries.append(entry)
            entries.sort(key=lambda e: e.name)
        except OSError:
            notes.append(Skipped(os.path.relpath(directory, root),
                                 "a folder that could not be opened", True))
            continue
        for entry in entries:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir:
                if entry.name in PRUNE_DIRS:
                    continue
                if depth >= MAX_DEPTH:
                    notes.append(Skipped(os.path.relpath(entry.path, root),
                                         "too many folders deep", True))
                    continue
                real = os.path.realpath(entry.path)
                if not _within(real, root_real):
                    notes.append(Skipped(os.path.relpath(entry.path, root),
                                         "a folder link that leads outside the folder"))
                    continue
                if real in seen_dirs:
                    continue
                seen_dirs.add(real)
                queue.append((entry.path, depth + 1,
                              in_agent or entry.name.lower() in AGENT_DIRS))
                continue
            if everything or in_agent or _is_agent_name(entry.name.lower()):
                if len(files) >= MAX_CANDIDATES:
                    notes.append(Skipped(".", f"stopped after queueing {MAX_CANDIDATES} "
                                              f"files to read", True))
                    return files, notes, passed_over
                files.append(entry.path)
            else:
                passed_over += 1
    return files, notes, passed_over


@dataclasses.dataclass
class ScanResult:
    root: str
    files_scanned: int
    findings: list[Finding]
    skipped: list[Skipped]
    validated: bool = False
    kind: str = "agent"         # "agent" files, or a web "bundle"
    not_considered: int = 0     # files the default scan never queued (no --all)

    @property
    def incomplete(self) -> bool:
        return any(s.incomplete for s in self.skipped)


def _display_path(path: str, real: str, root: str, root_real: str) -> str:
    """The real file's path when `path` is a link inside the folder, so the
    same file reached twice is reported under one name."""
    base, where = (real, root_real) if _within(real, root_real) else (path, root)
    return os.path.relpath(base, where).replace("\\", "/")


def scan_path(target: str, catalog: dict, everything: bool = False) -> ScanResult:
    """Scan a folder (the agent-readable files in it) or one file."""
    target = os.path.abspath(target)
    if os.path.isdir(target):
        root = target
        files, skipped, not_considered = collect_files(root, everything)
    else:
        root = os.path.dirname(target)
        files, skipped, not_considered = [target], [], 0
    root_real = os.path.realpath(root)
    rules = build_rules(catalog)
    words = _name_tokens(catalog)
    findings: list[Finding] = []
    scanned = 0
    done: set[str] = set()
    total = Budget(SCAN_SECONDS)
    for index, path in enumerate(files):
        if total.expired():
            skipped.append(Skipped(".", f"stopped after {int(SCAN_SECONDS)} seconds; "
                                        f"{len(files) - index} files were not read", True))
            break
        real = os.path.realpath(path)
        if real in done:
            continue
        done.add(real)
        rel = _display_path(path, real, root, root_real)
        text, why = read_text_safely(path, root_real)
        if text is None:
            why = why or "skipped"
            parts = tuple(rel.split("/"))
            gap = why.startswith("could not be read") or (
                why.startswith("bigger than") and _is_agent_path(parts))
            skipped.append(Skipped(rel, why, gap))
            continue
        scanned += 1
        budget = Budget(FILE_SECONDS)
        findings.extend(scan_text(text, rel, rules, catalog, words, budget))
        if budget.hit:
            skipped.append(Skipped(rel, f"scanning stopped after {FILE_SECONDS:g} "
                                        f"seconds; the rest of this file was not looked at", True))
        for note in dict.fromkeys(budget.notes):
            skipped.append(Skipped(rel, note, True))
    return ScanResult(root, scanned, findings, skipped,
                      not_considered=not_considered)


# ----------------------------------------------------------------- validation

def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def plan_validation(findings: list[Finding], catalog: dict):
    """Which findings can be checked, grouped by recipe, and which cannot
    (with the reason). Returns (plan, impossible): plan maps slug -> {value:
    [findings]}; impossible is a list of (finding, reason)."""
    plan: dict[str, dict[str, list[Finding]]] = {}
    impossible: list[tuple[Finding, str]] = []
    for f in findings:
        recipe = catalog.get(f.provider) if f.provider else None
        if recipe is None or not f._value:
            impossible.append((f, f.skip_reason or "no check is known for this kind of key"))
        elif not f.can_validate:
            impossible.append((f, f.skip_reason or "this key format is shared by several "
                                                   "services, so one check cannot prove it"))
        elif len(recipes_mod.fields(recipe)) != 1:
            impossible.append((f, "this service needs a second value "
                                  "(a secret) to check the key"))
        else:
            plan.setdefault(f.provider, {}).setdefault(f._value, []).append(f)
    return plan, impossible


def _quiet(ask):
    """The default terminal reader echoes what is typed: use the quiet one."""
    return None if ask is _ask_stderr else ask


_KEY_HERE = "That looked like a key. Do not paste it here. Type y or n."


def _ask_stderr(prompt: str) -> str:
    sys.stderr.write(prompt)
    sys.stderr.flush()
    line = sys.stdin.readline()
    if not line:
        raise EOFError
    return line.rstrip("\r\n")


def _stdin_is_terminal() -> bool:
    try:
        return bool(sys.stdin and sys.stdin.isatty())
    except (OSError, ValueError):
        return False


def _mark(values: dict, status: str, detail: str) -> None:
    for group in values.values():
        for f in group:
            f.status, f.detail = status, detail


def run_validation(findings: list[Finding], catalog: dict, *, yes: bool,
                   err, ask=_ask_stderr, interactive=_stdin_is_terminal,
                   validate_fn=validate_mod.validate_key) -> str | None:
    """Check keys against their own service. Returns None when done, or a
    message when nothing was sent because there was no consent (the findings
    are then left `unchecked`, so the report can still be printed). Statuses
    are written onto the findings.

    Keys go only to the hosts of recipes shipped inside the package, after a
    `y` (or --yes). A recipe of your own (--my-recipes) decides where a key is
    sent, so it needs its own typed `y` EVERY time: --yes never covers it."""
    plan, impossible = plan_validation(findings, catalog)
    for f, why in impossible:
        f.status, f.detail = "unknown", why
    if not plan:
        return None
    sendable: dict[str, dict[str, list[Finding]]] = {}
    err.write("\n  --validate will send keys to the services below, one "
              "read-only request each,\n  over https, to that host only. "
              "Nothing is saved or changed.\n\n")
    for slug, values in plan.items():
        recipe = catalog[slug]
        urls = connect_mod.destinations(recipe)
        if any(urllib.parse.urlsplit(u).scheme.lower() != "https" for u in urls):
            _mark(values, "unknown", "not sent: the check is not https")
            continue
        hosts = ", ".join(sorted({_host(u) for u in urls}))
        mine = "" if recipe.get("_builtin") is True else "   [from YOUR recipe]"
        err.write(f"    {printable(recipe['display'], words=True)}: "
                  f"{len(values)} key{'s' if len(values) != 1 else ''} "
                  f"-> {printable(hosts)}  ({printable(urls[-1])}){mine}\n")
        sendable[slug] = values
    err.write("\n")
    if not sendable:
        return None
    builtin = {s: v for s, v in sendable.items() if catalog[s].get("_builtin") is True}
    custom = {s: v for s, v in sendable.items() if s not in builtin}
    can_ask = interactive()
    refusal = None
    if (builtin and not yes) or custom:
        if not can_ask:
            refusal = ("--validate sends keys over the internet, so it needs your "
                       "OK and there is no terminal to ask on. Add --yes to agree "
                       "(recipes of your own always need a terminal), or leave out "
                       "--validate. The report below shows every key as not checked.")
            for values in sendable.values():
                _mark(values, "unchecked", "not sent: no terminal to ask on")
            return refusal
    if builtin and not yes:
        if not safeprompt.ask("  Send these keys to those hosts? [y/N]: ", err,
                              enter_means=False, reader=_quiet(ask), if_key=_KEY_HERE):
            err.write("  Nothing was sent.\n")
            for values in builtin.values():
                _mark(values, "unchecked", "you chose not to send it")
            builtin = {}
    if custom:
        if not safeprompt.ask("  The keys marked [from YOUR recipe] go to hosts that recipe "
                              "chose, not stuntkey. Send them? [y/N]: ", err,
                              enter_means=False, reader=_quiet(ask), if_key=_KEY_HERE):
            err.write("  Nothing was sent for your own recipes.\n")
            for values in custom.values():
                _mark(values, "unchecked", "you chose not to send it")
            custom = {}
    sendable = {**builtin, **custom}

    def deny(_prompt):                      # no one to ask: that is a "no"
        raise EOFError
    confirm = ask if can_ask else deny
    budget = MAX_VALIDATIONS
    for slug, values in sendable.items():
        recipe = catalog[slug]
        # the existing cross-domain warning: a check on another domain than the
        # key page needs a typed "yes", which --yes does not replace
        if not connect_mod._require_cross_domain_confirmation(recipe, err, confirm):
            _mark(values, "unknown", "not sent: the check is on a different domain")
            continue
        # only a 401 means "this key is rejected"; a 403 can mean "valid key,
        # no permission", so it stays "could not be checked"
        spec = dict(recipe["validate"], reject=[401])
        for value, group in values.items():
            if budget <= 0:
                status, detail = "unknown", "not checked: too many keys in one run"
            else:
                budget -= 1
                try:
                    ok = validate_fn(spec, value)
                    status, detail = ("live", "") if ok else ("dead", "")
                except validate_mod.ValidationError as e:
                    status, detail = "unknown", f"could not check: {printable(e)}"
                except Exception as e:      # never let one check stop the rest
                    status, detail = "unknown", f"could not check ({type(e).__name__})"
            for f in group:
                f.status, f.detail = status, detail
    return None


# -------------------------------------------------------------------- reports

STATUS_WORDS = {
    "unchecked": "not checked",
    "live": "STILL WORKS",
    "dead": "rejected by the service",
    "unknown": "could not be checked",
}


def _confidence_note(f: Finding) -> str:
    return "  (format is a guess)" if f.confidence == "guess" else ""


def _incomplete_reasons(result: ScanResult) -> list[str]:
    reasons = []
    for s in result.skipped:
        if s.incomplete:
            where = "" if s.path == "." else f"{printable(s.path)}: "
            reasons.append(where + printable(s.reason, words=True))
    return reasons


def render_text(result: ScanResult) -> str:
    out = []
    n = len(result.findings)
    out.append(f"\n  stuntkey scan: looked at {result.files_scanned} "
               f"file{'s' if result.files_scanned != 1 else ''} in "
               f"{printable(result.root)}")
    if result.incomplete:
        reasons = _incomplete_reasons(result)
        out.append("\n  INCOMPLETE: this scan did NOT look at everything, so "
                   "\"no keys found\" below does NOT mean there are none.")
        for r in reasons[:8]:
            out.append(f"      - {r}")
        if len(reasons) > 8:
            out.append(f"      - ... and {len(reasons) - 8} more (--json lists them)")
    bundle = result.kind == "bundle"
    if n == 0:
        out.append("  No keys found in the files that were scanned."
                   if result.incomplete else
                   "  No secret keys found in the files a browser downloads."
                   if bundle else
                   "  No keys found in the agent instruction, settings, .env "
                   "and credential files that were scanned.")
    elif bundle:
        out.append(f"  Found {n} key{'s' if n != 1 else ''} in the files your "
                   f"site sends to every visitor's browser.")
    else:
        out.append(f"  Found {n} key{'s' if n != 1 else ''} an AI agent can "
                   f"read. Anything it reads can end up in its memory and logs.")
    if result.not_considered:
        out.append(f"  {result.not_considered} other file"
                   f"{'s were' if result.not_considered != 1 else ' was'} NOT "
                   f"looked at: by default only an AI agent's instruction, "
                   f"settings, .env and credential files are scanned. "
                   f"Run with --all to scan every file.")
    for f in result.findings:
        out.append(f"\n  {printable(f.file)}:{f.line}   "
                   f"{printable(f.provider_name, words=True)}   {f.redacted}   "
                   f"{STATUS_WORDS[f.status]}{_confidence_note(f)}")
        if f.detail:
            out.append(f"      note: {f.detail}")
        out.append(f"      next: {f.next_step}")
    quiet = [s for s in result.skipped if not s.incomplete]
    if quiet:
        counts = collections.Counter(s.reason for s in quiet)
        parts = [f"{c} {printable(r, words=True)}" for r, c in counts.most_common(4)]
        if len(counts) > 4:
            parts.append(f"{sum(counts.values()) - sum(c for _r, c in counts.most_common(4))} other")
        out.append(f"\n  Skipped {len(quiet)} item{'s' if len(quiet) != 1 else ''} "
                   f"({'; '.join(parts)}); --json lists them.")
    if n and not bundle:
        out.append("\n  To stop an agent reading .env files, run: "
                   "stuntkey hook install")
    out.append("")
    return "\n".join(out) + "\n"


def to_json(result: ScanResult) -> dict:
    return {
        "tool": "stuntkey",
        "version": __version__,
        "root": result.root,
        "files_scanned": result.files_scanned,
        "files_not_considered": result.not_considered,
        "validated": result.validated,
        "incomplete": result.incomplete,
        "findings": [{
            "file": f.file, "line": f.line, "column": f.column,
            "provider": f.provider, "provider_name": f.provider_name,
            "rule": f.rule, "confidence": f.confidence,
            "redacted": f.redacted, "status": f.status, "status_detail": f.detail,
            "next_step": f.next_step, "key_url": f.key_url,
        } for f in result.findings],
        "skipped": [{"path": s.path, "reason": s.reason, "incomplete": s.incomplete}
                    for s in result.skipped],
    }


def to_sarif(result: ScanResult) -> dict:
    """SARIF 2.1.0. The message holds the redacted key only."""
    rule_ids: list[str] = []
    rules = []
    results = []
    for f in result.findings:
        rid = f"leaked-key/{f.provider or 'other'}"
        if rid not in rule_ids:
            rule_ids.append(rid)
            rules.append({
                "id": rid,
                "name": "LeakedKey",
                "shortDescription": {"text": f"A {f.provider_name if f.provider else 'service'} key is stored in a file an AI agent can read"},
                "fullDescription": {"text": "A secret key written into an instruction, settings or .env file is read by AI agents and can end up in their memory and logs. Rotate it and keep it out of files."},
                "helpUri": INFO_URI,
                "defaultConfiguration": {"level": "warning"},
            })
        fingerprint = hashlib.sha256(
            f"{f.file}:{f.line}:{rid}:{f.redacted}".encode()).hexdigest()
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_ids.index(rid),
            "level": "error" if f.status == "live" else "warning",
            "message": {"text": (f"{f.provider_name} key {f.redacted} found "
                                 f"({STATUS_WORDS[f.status]}). {f.next_step}")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": urllib.parse.quote(f.file)},
                "region": {"startLine": f.line, "startColumn": f.column},
            }}],
            "partialFingerprints": {"stuntkeyKey/v1": fingerprint},
            "properties": {"status": f.status, "confidence": f.confidence},
        })
    run = {
        "tool": {"driver": {"name": "stuntkey", "version": __version__,
                            "informationUri": INFO_URI, "rules": rules}},
        "results": results,
    }
    if result.incomplete:
        run["invocations"] = [{
            "executionSuccessful": False,
            "toolExecutionNotifications": [
                {"level": "warning", "message": {"text": "INCOMPLETE: " + r}}
                for r in _incomplete_reasons(result)],
        }]
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def exit_code(result: ScanResult, fail_on: str) -> int:
    """0 clean, 1 keys found (with --fail-on live: a key that still works),
    2 the scan was incomplete and found nothing to fail on. An incomplete scan
    is never a clean 0."""
    if fail_on == "live":
        bad = any(f.status == "live" for f in result.findings)
    else:
        bad = bool(result.findings)
    if bad:
        return 1
    return 2 if result.incomplete else 0


def cmd_scan(args, catalog: dict, out=None, err=None, **hooks) -> int:
    """Entry point for `stuntkey scan`. Exit 0 clean, 1 keys found, 2 could
    not run or the scan was incomplete."""
    out = out or sys.stdout
    err = err or sys.stderr
    target = args.path
    bundle = getattr(args, "bundle", None)
    if not bundle and not os.path.exists(target):
        err.write(f"error: {printable(target)} does not exist.\n")
        return 2
    mine = [s for s, r in catalog.items() if r.get("_builtin") is not True]
    if mine and not user_patterns_usable():
        err.write("note: the key formats in your own recipes were not used: this "
                  "system cannot time-limit them, and a bad pattern could hang the scan.\n")
    # the host list and the questions go to stderr: stdout is the report
    # (and is pure JSON or SARIF when asked for)
    try:
        if bundle:
            from . import bundle as bundle_mod
            result = bundle_mod.scan_bundle(bundle, catalog)
        else:
            result = scan_path(target, catalog, everything=args.all)
            if not getattr(args, "no_mcp", False):
                from . import mcpwrap
                mcpwrap.add_to_scan(result, catalog, root=target)
    except OSError as e:
        err.write(f"error: could not scan {printable(bundle or target)}: "
                  f"{printable(e.strerror or e)}\n")
        return 2
    except ValueError as e:              # a refused --bundle address, said plainly
        err.write(f"error: {printable(e)}\n")
        return 2

    if args.fail_on == "live" and not args.validate:
        err.write("note: --fail-on live needs --validate; without it no key "
                  "is checked, so none counts as live.\n")
    if args.validate and result.findings:
        refusal = run_validation(result.findings, catalog, yes=args.yes, err=err,
                                 **hooks)
        if refusal:
            # nothing was sent; the report is still printed, every key "not checked"
            err.write(f"note: {refusal}\n")
        else:
            result.validated = True
        if args.fail_on == "live":
            unsure = sum(1 for f in result.findings if f.status in ("unchecked", "unknown"))
            if unsure:
                err.write(f"note: {unsure} key{'s' if unsure != 1 else ''} could not be "
                          f"checked, so --fail-on live does not count "
                          f"{'them' if unsure != 1 else 'it'} (exit 0 unless another key is live).\n")
    if args.json:
        out.write(json.dumps(to_json(result), indent=2) + "\n")
    elif args.sarif:
        out.write(json.dumps(to_sarif(result), indent=2) + "\n")
    else:
        out.write(render_text(result))
    if result.incomplete:
        err.write("INCOMPLETE: not every file was looked at (see the report); "
                  "exit status 2 unless keys were found.\n")
    return exit_code(result, args.fail_on)
