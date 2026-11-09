"""`stuntkey scan-git` and `stuntkey doctor` (the broker line's checks).

scan: look for API keys lying around in places an AI assistant (or a thief)
can read: project files, .env files, AI-tool config and settings files, shell
history. It NEVER prints a secret: a finding shows the file, the line, the kind
of key and a masked hint (first 4 characters + length) only.

doctor: a one-paste health check (keychain, ssh, git, proxy, file permissions).
Both support --json and use exit codes: 0 clean, 1 findings/problems, 2 usage.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import sys

# (kind, regex). Specific shapes only, so false alarms stay rare.
PATTERNS = [
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,251})\b")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Stripe secret key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("Twilio auth/api key", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Database URL with password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/@]+:[^\s@]{3,}@")),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             ".mypy_cache", ".pytest_cache", ".idea", ".vscode-test"}
MAX_BYTES = 20_000_000

# where AI tools keep things an assistant can read or that get committed
AGENT_FILES = [".claude/settings.local.json", ".claude/settings.json", ".mcp.json",
               ".cursor/mcp.json", ".vscode/mcp.json", ".codex/config.toml"]
HOME_FILES = [".bash_history", ".zsh_history", ".claude.json",
              os.path.join(".claude", "settings.json"),
              os.path.join(".claude", "settings.local.json"),
              os.path.join(".cursor", "mcp.json"), os.path.join(".codex", "config.toml"),
              os.path.join("AppData", "Roaming", "Microsoft", "Windows", "PowerShell",
                           "PSReadLine", "ConsoleHost_history.txt")]


def mask(value: str) -> str:
    return f"{value[:4]}... ({len(value)} chars)"


def _is_text(sample: bytes) -> bool:
    return b"\0" not in sample


def _pattern_hits(line: str) -> list[tuple[str, str]]:
    return [(kind, mask(m.group(0))) for kind, rx in PATTERNS
            for m in [rx.search(line)] if m]


def scan_file(path: str, matcher=_pattern_hits) -> list[dict]:
    """`matcher(line) -> [(kind, masked hint)]`; default: the key shapes."""
    out: list[dict] = []
    try:
        if os.path.islink(path) or not stat.S_ISREG(os.stat(path).st_mode):
            return out                      # links, pipes, devices: never open
        if os.path.getsize(path) > MAX_BYTES:
            return [{"file": path, "line": 0, "kind": "skipped (too large)",
                     "hint": "not checked", "skipped": True}]
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return out
    if not _is_text(raw[:4096]):
        return out
    text = raw.decode("utf-8", "replace")
    for n, line in enumerate(text.splitlines(), 1):
        if len(line) > 300_000:
            continue
        for kind, hint in matcher(line):
            out.append({"file": path, "line": n, "kind": kind, "hint": hint})
    return out


def _walk(root: str):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            yield os.path.join(dirpath, name)


def scan(paths: list[str], home: str | None = None, include_home: bool = True,
         matcher=_pattern_hits) -> dict:
    findings: list[dict] = []
    warnings: list[dict] = []
    seen: set = set()
    targets: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            targets.extend(_walk(p))
        elif os.path.isfile(p):
            targets.append(p)
    if include_home:
        home = home or os.path.expanduser("~")
        for rel in HOME_FILES:
            f = os.path.join(home, rel)
            if os.path.isfile(f):
                targets.append(f)
    for f in targets:
        real = os.path.realpath(f)
        if real in seen:
            continue
        seen.add(real)
        found = scan_file(f, matcher)
        skipped = [x for x in found if x.get("skipped")]
        found = [x for x in found if not x.get("skipped")]
        for x in skipped:
            warnings.append({"file": f, "why": "too large to check (over "
                             f"{MAX_BYTES // 1_000_000} MB); not scanned."})
        findings.extend(found)
        base = os.path.basename(f)
        norm = f.replace("\\", "/")
        if found and any(norm.endswith(a) for a in AGENT_FILES):
            warnings.append({"file": f, "why": "an AI-tool settings/config file holds a "
                             "key. Keys saved here are readable by the assistant and often "
                             "get committed. Move it to the keychain: `stuntkey connect`."})
        if base == ".env" or base.startswith(".env."):
            if os.name != "nt":
                try:
                    if os.stat(f).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                        warnings.append({"file": f, "why": "this .env file is readable by "
                                         "other users (run: chmod 600)."})
                except OSError:
                    pass
            else:
                pass
            if found:
                warnings.append({"file": f, "why": "some AI coding tools read .env files "
                                 "automatically. Keep real keys in the keychain instead."})
    return {"scanned": len(seen), "findings": findings, "warnings": warnings}


def format_report(result: dict) -> str:
    lines = [f"  scanned {result['scanned']} files; "
             f"{len(result['findings'])} key(s) found, "
             f"{len(result['warnings'])} warning(s)."]
    for f in result["findings"]:
        lines.append(f"    ! {f['kind']}  {f['file']}:{f['line']}  {f['hint']}")
    for w in result["warnings"]:
        lines.append(f"    - {w['file']}: {w['why']}")
    if result["findings"]:
        lines.append("\n  What to do: treat each key above as exposed - make a new one "
                     "(`stuntkey rotate <service>`), delete the old one at the "
                     "vendor, and keep the new one out of files.")
    else:
        lines.append("  Nothing key-shaped found. (This cannot see inside git history, "
                     "encoded values, or places not scanned.)")
    return "\n".join(lines)


def doctor(env=None, which=shutil.which) -> dict:
    env = os.environ if env is None else env
    from . import keychain as keychain_mod
    checks = []

    def add(name: str, ok: bool, detail: str, fix: str = "", info: bool = False):
        # info: shown as [info], never makes the result "not ready"
        checks.append({"check": name, "ok": ok or info, "detail": detail, "fix": fix,
                       "info": info})

    add("python", sys.version_info >= (3, 10), platform.python_version(),
        "stuntkey needs Python 3.10 or newer.")
    backend = keychain_mod.detect_backend()
    add("keychain", backend is not None, keychain_mod.label(backend) if backend else "none",
        "Without an OS keychain, keys are kept in a .env file (owner-only).")
    if keychain_mod.test_backend():
        add("keychain", True, f"test backend {env.get(keychain_mod.TEST_ENV, '')}", info=True)
    add("ssh", bool(which("ssh")), "found" if which("ssh") else "missing",
        "Needed for `remote`/`deploy`. Windows: Settings > Apps > Optional features > OpenSSH Client.")
    add("git", bool(which("git")), "found" if which("git") else "missing",
        "Needed for `deploy` and git-based updates.")
    proxy = env.get("HTTPS_PROXY") or env.get("https_proxy")
    if proxy:           # only worth a line when set; stuntkey ignores it for AI calls
        add("proxy", True, "set (stuntkey ignores it for AI calls)", "")
    cafile = env.get("SSL_CERT_FILE") or env.get("REQUESTS_CA_BUNDLE")
    if cafile:
        add("custom CA bundle", True, "set", "")
    _doctor_stuntkey_checks(add)
    from . import migrate
    migrate.doctor_checks(add)
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


def _doctor_stuntkey_checks(add) -> None:
    """Checks about stuntkey itself. Each is wrapped so one failure never
    hides the others."""
    try:
        from . import broker, remote
        log = broker.AuditLog(os.path.join(remote.home_dir(), "audit.log"))
        ok, n = log.verify()
        add("activity log", ok,
            f"{n} entries, chain intact" if ok else
            f"check failed ({log.broken_reason() or 'broken after entry ' + str(n)})",
            "Keep a copy, run `stuntkey audit show`, then `stuntkey audit reset` to start a fresh log.")
    except Exception as e:                                   # noqa: BLE001
        add("activity log", False, f"could not check ({type(e).__name__})", "")
    try:
        from . import clients
        plugged = clients.plugged()
        add("AI tools", True, ("plugged into " + ", ".join(clients.where(n) for n in plugged)) if plugged
            else "none yet", "" if plugged else "Run `stuntkey install` to plug it into Claude, Cursor or VS Code.")
        from . import hook
        if "claude-code" in plugged and not hook.is_installed():
            add("Claude Code hook", True, "not installed (agent can still read .env). "
                "Fix: stuntkey hook install", info=True)
    except Exception as e:                                   # noqa: BLE001
        add("AI tools", False, f"could not check ({type(e).__name__})", "")
    try:
        from . import selftest
        res = selftest.run_all()
        passed = sum(1 for r in res if r["pass"])
        add("self-attack test", passed == len(res), f"{passed} of {len(res)} attacks stopped",
            "Run `stuntkey selftest` to see which attack got through, and report it (see https://github.com/calasdan-sketch/stuntkey/blob/main/SECURITY.md).")
    except Exception as e:                                   # noqa: BLE001
        add("self-attack test", False, f"could not run ({type(e).__name__})", "")


def format_doctor(result: dict) -> str:
    lines = []
    for c in result["checks"]:
        mark = "info" if c.get("info") else "ok " if c["ok"] else "FIX"
        lines.append(f"  [{mark}] {c['check']}: {c['detail']}" +
                     (f"  -> {c['fix']}" if (not c["ok"] and c["fix"]) else ""))
    lines.append("")
    lines.append("  Ready. Next: stuntkey get github" if result["ok"]
                 else "  Fix the items marked FIX, then run `stuntkey doctor` again.")
    from .selftest import BETA_NOTICE
    lines.append("  " + BETA_NOTICE)
    return "\n".join(lines)


# ---- git history and pre-commit hook ----------------------------------------------

def scan_git(repo: str = ".", staged: bool = False, max_lines: int = 5_000_000,
             matcher=_pattern_hits) -> dict:
    """Look for keys in what git remembers: every added line in every
    commit (or only the staged change). A key that was ever committed is
    still readable in history even after the file is cleaned."""
    import subprocess
    # never run anything the repository's own config asks for
    cmd = ["git", "--no-pager", "-C", repo, "-c", "core.quotepath=off",
           "-c", "core.fsmonitor=false", "-c", "core.pager=cat",
           "-c", "log.showSignature=false", "-c", "gpg.program=false",
           "-c", "diff.external=", "-c", "core.attributesFile="]
    cmd += (["diff", "--cached", "-U0", "--no-color", "--no-textconv", "--no-ext-diff"]
            if staged else
            ["log", "--all", "-p", "-U0", "--no-color", "--no-textconv",
             "--no-ext-diff", "--format=commit %H"])
    findings: list[dict] = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return {"error": "git not found", "findings": []}
    commit, fname, n = ("staged" if staged else ""), "", 0
    for raw in proc.stdout:
        n += 1
        if n > max_lines:
            break
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("commit "):
            commit = line[7:15]
        elif line.startswith("+++ b/"):
            fname = line[6:]
        elif line.startswith("+") and not line.startswith("+++ ") and len(line) < 200_000:
            for kind, hint in matcher(line):
                findings.append({"file": fname, "commit": commit, "kind": kind,
                                 "hint": hint})
    proc.stdout.close()
    code = proc.wait()
    if code not in (0, None) and not findings:
        return {"error": f"git exited with {code} (is this a repository?)", "findings": []}
    return {"findings": findings, "error": None}


def format_git(res: dict) -> str:
    if res.get("error"):
        return f"  git scan problem: {res['error']}"
    if not res["findings"]:
        return "  git history: no keys found."
    seen, lines = set(), [f"  git history: {len(res['findings'])} key(s) found "
                          "(still readable by anyone with the repo):"]
    for f in res["findings"]:
        k = (f["file"], f["commit"], f["kind"])
        if k in seen:
            continue
        seen.add(k)
        lines.append(f"    ! {f['kind']}  {f['file']}  commit {f['commit']}  {f['hint']}")
    lines.append("    Fix: treat these keys as leaked - replace them at the provider "
                 "(`stuntkey rotate`), then clean history if the repo is shared.")
    return "\n".join(lines)


HOOK_MARK = "# stuntkey pre-commit"


def install_hook(repo: str = ".") -> str:
    import sys as _sys
    hooks = os.path.join(repo, ".git", "hooks")
    if not os.path.isdir(hooks):
        raise OSError("not a git repository (no .git/hooks)")
    path = os.path.join(hooks, "pre-commit")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            if HOOK_MARK not in f.read():
                raise OSError("a pre-commit hook already exists; not overwriting it")
    from . import clients
    py = _sys.executable.replace("\\", "/")
    me = [a.replace("\\", "/") for a in clients.self_args()]
    if any(c in a for a in (py, *me) for c in '"$`'):
        raise OSError("the Python path has a character that is unsafe in a hook")
    me = f'"{me[0]}"' if len(me) == 1 else " ".join(me)     # the .pyz path, quoted
    _flag = "-P" if _sys.version_info >= (3, 11) else "-I"
    body = (f"#!/bin/sh\n{HOOK_MARK}\n"
            f"# blocks the commit if a key is staged, and if the scanner itself fails\n"
            f"\"{py}\" {_flag} {me} scan-git --staged || {{ echo 'commit blocked by stuntkey' >&2; exit 1; }}\n")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass
    return path
