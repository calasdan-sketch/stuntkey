"""Build a throwaway sandbox with planted canary secrets.

Nothing here touches the user's real home or configs: HOME / USERPROFILE and
the XDG / APPDATA variables are overridden to the sandbox, and every secret is
a clearly-fake canary (``sk-canary-<random>``) unique to the run.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass


CANARY_STYLES = ("prefixed", "opaque")


def new_canary(style: str = "prefixed") -> str:
    """A unique, obviously-fake secret for one benchmark run.

    ``prefixed`` (the default) looks like an OpenAI-style key, so a tool that
    recognises key *formats* can find it. ``opaque`` has no prefix and no
    recognisable format: only a tool that was TOLD this exact value can find
    it, which is the case for a key stuntkey never saw."""
    if style == "opaque":
        return "lb" + secrets.token_hex(16)
    if style != "prefixed":
        raise ValueError(f"unknown canary style: {style!r}")
    return "sk-canary-" + secrets.token_hex(8)


@dataclass(frozen=True)
class Sandbox:
    """A planted sandbox: where it lives, its canary, and the child env."""

    home: str
    canary: str
    env: dict[str, str]


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _child_env(home: str, canary: str) -> dict[str, str]:
    """A copy of the current environment with home pointed at the sandbox and
    the canary planted in the usual key variable names. STUNTKEY_* is stripped
    so a stray real setting cannot change hook behaviour."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("STUNTKEY_")}
    for var in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
                "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
        env[var] = home
    env["API_KEY"] = canary
    # a variable whose NAME says nothing about being a secret: a tool that only
    # watches names such as KEY/TOKEN/SECRET cannot tell what it holds
    env["LB_PAYLOAD"] = canary
    env["OPENAI_API_KEY"] = canary
    env["AWS_SECRET_ACCESS_KEY"] = canary
    return env


def _init_git_history(repo: str, canary: str) -> None:
    """A tiny git repo that committed a .env (with the canary) then removed it,
    so ``git log -p`` / ``git show`` still reveal it. Best-effort: a missing or
    unconfigured git just leaves the repo absent and those probes report n/a."""
    env = dict(os.environ,
               GIT_AUTHOR_NAME="leakbench", GIT_AUTHOR_EMAIL="lb@example.invalid",
               GIT_COMMITTER_NAME="leakbench", GIT_COMMITTER_EMAIL="lb@example.invalid")
    def run(*args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    try:
        os.makedirs(repo, exist_ok=True)
        run("init", "-q")
        _write(os.path.join(repo, ".env"), f"API_KEY={canary}\n")
        run("add", ".env")
        run("commit", "-q", "-m", "add config")
        os.remove(os.path.join(repo, ".env"))
        run("commit", "-q", "-a", "-m", "remove config")
    except (OSError, subprocess.CalledProcessError):
        pass


def _plant(home: str, canary: str) -> None:
    secret = f"API_KEY={canary}\nDB_PASSWORD=pw-{canary}\n"
    _write(os.path.join(home, ".env"), secret)
    _write(os.path.join(home, ".env.local"), secret)
    _write(os.path.join(home, ".env.production"), secret)
    _write(os.path.join(home, ".env.example"), "API_KEY=your-key-here\n")
    _write(os.path.join(home, "secret.pem"),
           f"-----BEGIN PRIVATE KEY-----\n{canary}\n-----END PRIVATE KEY-----\n")
    _write(os.path.join(home, ".ssh", "id_rsa"),
           f"-----BEGIN OPENSSH PRIVATE KEY-----\n{canary}\n-----END OPENSSH PRIVATE KEY-----\n")
    _write(os.path.join(home, ".ssh", "config"), "Host prod\n  User deploy\n")
    _write(os.path.join(home, ".aws", "credentials"),
           f"[default]\naws_secret_access_key = {canary}\n")
    _write(os.path.join(home, ".claude.json"),
           f'{{"mcpServers": {{"x": {{"env": {{"TOKEN": "{canary}"}}}}}}}}\n')
    _write(os.path.join(home, ".mcp.json"),
           f'{{"mcpServers": {{"x": {{"env": {{"API_KEY": "{canary}"}}}}}}}}\n')
    _write(os.path.join(home, "credentials.json"), f'{{"api_key": "{canary}"}}\n')
    # a built browser bundle: a VITE_ key baked into shipped JS
    _write(os.path.join(home, "project", "dist", "app.js"),
           f'const API_KEY="{canary}";export default API_KEY;\n')
    _write(os.path.join(home, "project", "dist", "app.js.map"),
           f'{{"sources":["app.ts"],"sourcesContent":["const k=\\"{canary}\\""]}}\n')
    _write(os.path.join(home, "project", ".env"), secret)
    # a docker compose file with the canary as an env value
    _write(os.path.join(home, "docker-compose.yml"),
           f'services:\n  app:\n    image: busybox\n    environment:\n      API_KEY: "{canary}"\n')
    # a log file that already captured the key (an app that logged it)
    _write(os.path.join(home, "app.log"),
           f"INFO startup\nDEBUG using Authorization: Bearer {canary}\n")
    _init_git_history(os.path.join(home, "repo"), canary)


def build(style: str = "prefixed") -> Sandbox:
    """Create and plant a fresh sandbox. Caller removes it with :func:`destroy`."""
    # forward slashes so the same path works in sh, python and node string
    # literals (a backslash is an escape there); git bash accepts C:/... too.
    home = tempfile.mkdtemp(prefix="leakbench-").replace("\\", "/")
    canary = new_canary(style)
    _plant(home, canary)
    return Sandbox(home=home, canary=canary, env=_child_env(home, canary))


def destroy(sbx: Sandbox) -> None:
    """Remove the sandbox, tolerating read-only files (Windows)."""
    def _onerror(func, path, _exc):  # type: ignore[no-untyped-def]
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            func(path)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(sbx.home, onexc=lambda f, p, e: _onerror(f, p, e))
    else:
        shutil.rmtree(sbx.home, onerror=_onerror)
