"""`stuntkey remote` / `trust-server` / `deploy`: use a stored key on ANOTHER
machine, over ssh.

    stuntkey trust-server root@203.0.113.7            # once per server
    stuntkey remote --as calas github root@203.0.113.7 -- git -C /opt/app pull
    stuntkey deploy --dir /opt/app --as calas root@203.0.113.7

The key is read here (OS keychain first, then the .env file), sent to the
other machine on ssh's standard input, turned into an environment variable
for that one command, and forgotten. It is never put in a command line
(so never in `ps`, shell history or a log), never printed, and never written
to a file on the other machine.

For `github` the token is also turned into git's HTTP header - scoped to
https://github.com/ only - so a plain `git pull` just works on the far side.

Safety rules: a server must be confirmed by a person (on a real terminal)
before a key is ever sent to it; ssh never waits for a password during
`remote`; variable names that can change how a program runs (LD_PRELOAD,
BASH_ENV, PATH...) are refused.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys

from . import fsutil
from . import dialog as dialog_mod
from . import keychain as keychain_mod
from . import recipes as recipes_mod
from . import store as store_mod

# user@host, host, [v6]: letters, digits and . _ - @ : [ ] only. fullmatch, not
# `$`, so a trailing newline cannot slip through.
_HOST = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]*")
_USER = re.compile(r"[a-z_][a-z0-9_-]*")
_VAR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# names that change how a program starts or which program runs
_DANGEROUS = re.compile(
    r"(LD_.*|DYLD_.*|BASH_ENV|ENV|PATH|IFS|SHELL|HOME|USER|LOGNAME|PS4|PROMPT_COMMAND|"
    r"GIT_(SSH|SSH_COMMAND|ASKPASS|EXEC_PATH|CONFIG.*|DIR|WORK_TREE|PROXY_COMMAND)|"
    r"SSH_ASKPASS|NODE_OPTIONS|NODE_PATH|PYTHON.*|PERL5?LIB|PERL5?OPT|RUBYOPT|RUBYLIB|"
    r"JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|CLASSPATH)", re.IGNORECASE)

# git on the far side: token -> HTTP header for github.com ONLY, appended after
# any config the server already has, no prompt, no stored credential.
_GITHUB_PRELUDE = (
    'export GIT_TERMINAL_PROMPT=0; _sea_n=${GIT_CONFIG_COUNT:-0}; '
    'export "GIT_CONFIG_KEY_${_sea_n}=http.https://github.com/.extraHeader" '
    '"GIT_CONFIG_VALUE_${_sea_n}=Authorization: Basic '
    '$(printf "x-access-token:%s" "$GITHUB_TOKEN" | base64 | tr -d "\\n")"; '
    'GIT_CONFIG_COUNT=$((_sea_n+1)); export GIT_CONFIG_COUNT; unset _sea_n; ')


class RemoteError(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def home_dir() -> str:
    return os.path.join(os.path.expanduser("~"), ".stuntkey")


def private_dir(path: str) -> None:
    """Make the folder (owner-only where the OS has such modes)."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def check_host(host: str) -> str:
    if not _HOST.fullmatch(host or ""):
        raise RemoteError(f"'{host}' is not a plain user@host address.", 2)
    return host


def check_var(var: str) -> str:
    if not _VAR.fullmatch(var) or _DANGEROUS.fullmatch(var):
        raise RemoteError(f"the variable name '{var}' is not allowed on a remote "
                          "machine (it could change how programs start).", 1)
    return var


# --- which servers a person has confirmed -----------------------------------

def _hosts_path() -> str:
    return os.path.join(home_dir(), "hosts.json")


def known_hosts() -> dict:
    try:
        with open(_hosts_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def remember_host(host: str, service: str) -> None:
    data = known_hosts()
    data.setdefault(host, [])
    if service not in data[host]:
        data[host].append(service)
    private_dir(home_dir())
    tmp = _hosts_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    fsutil.replace(tmp, _hosts_path())


def ssh_port(ssh_args: list[str] | None) -> str | None:
    """The port named in the extra ssh arguments (-p N, -oPort=N), if any."""
    args = list(ssh_args or [])
    for i, a in enumerate(args):
        if a == "-p" and i + 1 < len(args) and args[i + 1].isdigit():
            return args[i + 1]
        value = a[2:] if a.startswith("-o") and len(a) > 2 else (
            args[i + 1] if a == "-o" and i + 1 < len(args) else "")
        name, _, val = value.partition("=")
        if name.strip().lower() == "port" and val.strip().isdigit():
            return val.strip()
    return None


def scan_host_key(host: str, port: str | None = None, runner=subprocess.run):
    """(fingerprints text or None, known_hosts lines or None): what the server
    at `host` shows right now, as `ssh-keyscan` sees it."""
    name = host.rsplit("@", 1)[-1].strip("[]")
    cmd = ["ssh-keyscan", "-T", "10", "-t", "ed25519,ecdsa,rsa"]
    if port:
        cmd += ["-p", port]
    try:
        done = runner(cmd + [name], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None, None
    lines = [ln for ln in done.stdout.decode("utf-8", "replace").splitlines()
             if ln.strip() and not ln.startswith("#")]
    if done.returncode != 0 or not lines:
        return None, None
    keytext = "\n".join(lines) + "\n"
    try:
        fp = runner(["ssh-keygen", "-l", "-f", "-"], input=keytext.encode("utf-8"),
                    capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None, keytext
    shown = []
    for ln in fp.stdout.decode("utf-8", "replace").splitlines():
        m = re.search(r"(SHA256:\S+)\s.*\((\w+)\)\s*$", ln)
        if m:
            shown.append(f"{m.group(2)} {m.group(1)}")
    return ("; ".join(shown[:3]) or None), keytext


def pin_host_key(keytext: str | None, runner=subprocess.run, known_hosts_path=None) -> None:
    """Put the keys the person just confirmed into ~/.ssh/known_hosts (unless
    that server is already there), so ssh can then be told to accept ONLY
    them (StrictHostKeyChecking=yes)."""
    if not keytext:
        return
    path = known_hosts_path or os.path.join(os.path.expanduser("~"), ".ssh", "known_hosts")
    name = keytext.split(None, 1)[0]
    try:
        found = runner(["ssh-keygen", "-F", name, "-f", path], capture_output=True, timeout=15)
        if found.returncode == 0 and found.stdout.strip():
            return
    except (OSError, subprocess.SubprocessError):
        pass
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    existing = ""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            existing = f.read()
    except OSError:
        pass
    with open(path, "a", encoding="utf-8") as f:
        f.write(("\n" if existing and not existing.endswith("\n") else "") + keytext)


def confirm_host(host: str, service: str, ask=input, isatty=None, window=None,
                 scan=None, pin=None, ssh_args: list[str] | None = None) -> None:
    """A person must say yes before a key goes to a server for the first time:
    in a pop-up window when one can be shown (it names the server and its key
    fingerprint), otherwise on a real terminal. An agent or script cannot
    answer either. The keys the person saw are then pinned, and the key-bearing
    ssh connection accepts only those."""
    if service in known_hosts().get(host, []):
        return
    fingerprint, keytext = (scan or scan_host_key)(host, ssh_port(ssh_args))
    seen = (f"The server's key fingerprint: {fingerprint}" if fingerprint
            else "The server's key fingerprint could not be read.")
    window = window or dialog_mod.confirm
    answer = window("stuntkey - send a key to a server?",
                    f"Send your '{service}' key to {host}?\n\n{seen}\n\n"
                    "Say Yes only if this is your own server.")
    if answer is True:
        pass
    elif answer is not None:                 # No, closed, or nobody answered
        raise RemoteError("cancelled - nothing was sent.", 1)
    else:                                    # no window can be shown here
        tty = sys.stdin.isatty() if isatty is None else isatty
        if not tty:
            raise RemoteError(
                f"'{host}' has not been confirmed for '{service}' yet. Run "
                f"`stuntkey trust-server {host}` yourself in a terminal first "
                "(a key is never sent to a server nobody confirmed).", 1)
        shown = recipes_mod.printable(seen)
        reply = ask(f"  {shown}\n  Send your '{service}' key to {host}? [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            raise RemoteError("cancelled - nothing was sent.", 1)
    (pin or pin_host_key)(keytext)
    remember_host(host, service)


# --- the key itself ---------------------------------------------------------

def collect_values(recipe: dict, env_file: str, backend=None) -> dict:
    """The stored value for every variable of the recipe. Never printed."""
    values: dict = {}
    if backend is None:
        backend = keychain_mod.detect_backend()
    env_values: dict = {}
    for var in recipes_mod.env_vars(recipe):
        check_var(var)
        value = None
        if backend:
            try:
                value = keychain_mod.read(recipe["service"], var, backend)
            except keychain_mod.KeychainUnavailable as e:
                raise RemoteError(f"the OS keychain did not answer ({e}); unlock "
                                  "it and try again.", 1)
            except keychain_mod.KeychainError:
                value = None            # simply not stored there
        if not value:
            if not env_values and os.path.exists(env_file):
                try:
                    store_mod.refuse_link(env_file)
                    env_values = store_mod.load_env(env_file)
                except OSError as e:
                    raise RemoteError(f"will not read {env_file}: {e}", 1)
            value = env_values.get(var)
        if not value:
            raise RemoteError(
                f"no stored key for '{recipe['service']}' ({var}). Run "
                f"`stuntkey get {recipe['service']}` first.", 1)
        if "\n" in value or "\r" in value or "\0" in value:
            raise RemoteError(f"the stored {var} has a line break in it; "
                              "run `stuntkey rotate` to replace it.", 1)
        values[var] = value
    return values


def build_script(recipe: dict, command: list[str], run_as: str | None = None) -> str:
    """The shell text that runs on the far side. Contains NO secret: it only
    reads the values from its own standard input, one per line."""
    if not command:
        raise RemoteError("no command: stuntkey remote <service> <host> "
                          "-- <command>", 2)
    parts = []
    for i, var in enumerate(recipes_mod.env_vars(recipe)):
        check_var(var)
        parts.append(f'IFS= read -r _sea_{i}; export {var}="$_sea_{i}"; '
                     f'unset _sea_{i}; ')
    prelude = "".join(parts)
    if recipe["service"] == "github":
        prelude += _GITHUB_PRELUDE
    if len(command) == 1 and " " in command[0]:
        # "cd /opt && git pull" as ONE word: run it as a shell line
        cmd = "sh -c " + shlex.quote(command[0])
    else:
        cmd = " ".join(shlex.quote(c) for c in command)
    if run_as:
        if not _USER.fullmatch(run_as):
            raise RemoteError(f"'{run_as}' is not a plain user name.", 2)
        # runuser keeps the environment; only root on Linux may use it.
        cmd = (f"command -v runuser >/dev/null 2>&1 || {{ echo 'error: --as needs "
               f"a root login on a Linux server' >&2; exit 126; }}; "
               f"exec runuser -u {run_as} -- {cmd}")
    else:
        cmd = "exec " + cmd
    return prelude + cmd


def key_for(host: str) -> str | None:
    """The key trust-server made for this host, if there is one."""
    p = os.path.join(home_dir(), "keys", _safe_name(host) + "_ed25519")
    return p if os.path.exists(p) else None


def _safe_name(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", host)


_SAFE_SSH_OPTS = {"port", "connecttimeout", "serveraliveinterval",
                  "serveralivecountmax", "compression", "ipqos"}


def check_ssh_args(extra: list[str] | None) -> list[str]:
    """Only a few harmless ssh options may be passed through. `-o
    ProxyCommand=...`, `LocalCommand`, `-F`, `-J` and friends run programs
    or change who we trust, so an AI that can pick them can run anything."""
    args = list(extra or [])
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-p" and i + 1 < len(args) and args[i + 1].isdigit():
            i += 2
            continue
        glued = a.startswith("-o") and len(a) > 2
        if glued or (a == "-o" and i + 1 < len(args)):
            name, _, val = (a[2:] if glued else args[i + 1]).partition("=")
            name = name.strip().lower()
            ok = ((name in _SAFE_SSH_OPTS
                   or (name == "stricthostkeychecking" and val in ("yes", "ask")))
                  and "\n" not in val)
            if ok:
                i += 1 if glued else 2
                continue
        raise RemoteError(f"ssh option not allowed: {a!r}. Only -p and "
                          "-o with Port, ConnectTimeout, ServerAliveInterval, "
                          "ServerAliveCountMax, Compression are accepted.", 2)
    return args


def ssh_command(host: str, script: str, extra: list[str] | None = None,
                identity: str | None = None) -> list[str]:
    extra = check_ssh_args(extra)
    ident = ["-i", identity, "-o", "IdentitiesOnly=yes"] if identity else []
    # user-supplied options come FIRST: ssh keeps the first value it sees
    return (["ssh", "-T"] + list(extra or []) + ident
            + ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
               # the server was confirmed by a person and its key pinned
               # (confirm_host), so the key-bearing connection accepts only that
               "-o", "StrictHostKeyChecking=yes"]
            + ["--", host, "sh -c " + shlex.quote(script)])


def explain_failure(code: int, host: str) -> None:
    if code == 255:
        print(f"error: ssh could not connect or log in to {host}. Likely causes: "
              "the server does not trust this PC yet (run `stuntkey "
              f"trust-server {host}`), this server's key is not in your known_hosts "
              "(trust-server adds it), wrong address or port, a firewall, or the "
              f"server's key changed. Run `ssh {host} true` to see ssh's own "
              "message.", file=sys.stderr)
    elif code == 127:
        print("error: the server could not find that program. Put the whole "
              "command after `--` (for example `-- git -C /opt/app pull`). "
              "`cd`, `&&` and `|` are not programs: quote the whole line.",
              file=sys.stderr)


def run_remote(recipe: dict, host: str, command: list[str], env_file: str = ".env",
               run_as: str | None = None, ssh_args: list[str] | None = None,
               runner=subprocess.run, backend=None, ask=input, isatty=None,
               window=None, scan=None, pin=None) -> int:
    check_host(host)
    if command and command[0] == "--":
        command = command[1:]
    script = build_script(recipe, command, run_as)
    confirm_host(host, recipe["service"], ask=ask, isatty=isatty, window=window,
                 scan=scan, pin=pin, ssh_args=ssh_args)
    values = collect_values(recipe, env_file, backend)
    payload = "".join(values[v] + "\n" for v in recipes_mod.env_vars(recipe))
    argv = ssh_command(host, script, ssh_args, key_for(host))
    try:
        done = runner(argv, input=payload.encode("utf-8"))
    except FileNotFoundError:
        raise RemoteError("ssh is not installed here (on Windows: Settings > "
                          "Apps > Optional features > OpenSSH Client).", 1)
    explain_failure(done.returncode, host)
    return done.returncode


# --- trust-server: one command instead of five ------------------------------

def ensure_ssh_access(host: str, runner=subprocess.run, out=print) -> str:
    """Make this PC trusted by `host`: make a dedicated key, install it (one
    password prompt in the person's own terminal), and prove it works."""
    check_host(host)
    keydir = os.path.join(home_dir(), "keys")
    private_dir(home_dir())
    private_dir(keydir)
    key = os.path.join(keydir, _safe_name(host) + "_ed25519")

    def works() -> bool:
        r = runner(["ssh", "-T", "-i", key, "-o", "IdentitiesOnly=yes", "-o",
                    "BatchMode=yes", "-o", "ConnectTimeout=15", "-o",
                    "StrictHostKeyChecking=accept-new", "--", host, "true"],
                   capture_output=True)
        return r.returncode == 0

    if os.path.exists(key) and works():
        out(f"  {host} already trusts this PC.")
        return key
    if not os.path.exists(key):
        r = runner(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "stuntkey-" + _safe_name(host), "-f", key])
        if r.returncode != 0:
            raise RemoteError("could not make an ssh key (is the OpenSSH client "
                              "installed?).", 1)
    pub = open(key + ".pub", encoding="utf-8").read().strip()
    install = ("umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys "
               "&& chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys")
    out(f"  Installing a key on {host} - if it asks, type that server's login "
        "password (it is typed into ssh, not into this tool).")
    r = runner(["ssh", "-o", "StrictHostKeyChecking=accept-new", "--", host,
                install], input=(pub + "\n").encode("utf-8"))
    if r.returncode != 0 or not works():
        out("  Could not install it automatically. Paste this ONE line into the "
            f"server's own console (typing works even where pasting does not):\n\n"
            f"    mkdir -p ~/.ssh && echo '{pub}' >> ~/.ssh/authorized_keys\n\n"
            f"  then run `stuntkey trust-server {host}` again.")
        raise RemoteError("the server does not trust this PC yet.", 1)
    out(f"  {host} now trusts this PC.")
    return key
