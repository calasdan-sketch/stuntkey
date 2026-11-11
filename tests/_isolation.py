"""Test-environment isolation shared by every test module.

Importing this module points HOME / USERPROFILE / APPDATA / LOCALAPPDATA /
XDG_* at a throwaway directory for the whole test process, so no test can
read or write the real user's ~/.stuntkey (user recipes, directory
cache) or their real .env. The directory is removed at exit with a
cleanup that tolerates read-only files (Windows).
"""

import atexit
import contextlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile

ENV_VARS = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
            "XDG_CONFIG_HOME", "XDG_DATA_HOME")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rmtree(path: str) -> None:
    """shutil.rmtree that copes with read-only files."""
    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: _onerror(f, p, e))
    else:
        shutil.rmtree(path, onerror=_onerror)


def mktemp() -> str:
    """Short-pathed temp dir, removed at exit."""
    d = tempfile.mkdtemp(prefix="se")
    _TEMP_DIRS.append(d)
    return d


# What tools leave in a project folder: not source, never packaged.
BUILD_LEFTOVERS = ("build", "dist", ".git", ".venv", "venv", ".tox",
                   ".pytest_cache", ".mypy_cache")


def have_setuptools(minimum: int = 77) -> bool:
    """Is a setuptools of at least this major version installed here, with a
    `packaging` new enough for it? (A build that needs no network can only use
    what is installed. setuptools 77 reads `license = "MIT"` through
    packaging.licenses, which a `packaging` older than 24.2 does not have.)"""
    try:
        import setuptools
        if int(setuptools.__version__.split(".")[0]) < minimum:
            return False
        import packaging.licenses  # noqa: F401
        return True
    except (ImportError, ValueError):
        return False


def clean_source_copy(src: str | None = None, use_git: bool = True) -> str:
    """A throwaway copy of the project with nothing a build left behind.

    Building the working tree in place reuses what an earlier build left in
    it: setuptools copies a source file into build/lib/ only when it is newer
    than the copy there, and packs EVERYTHING it finds in build/lib - a
    module since deleted or renamed included - into the wheel. So packaging
    tests build this copy instead: the files git would commit (tracked, plus
    untracked and not ignored) when `src` is a git checkout of its own and git
    can say, otherwise everything except the usual build and tool folders at
    the top level, caches and *.pyc."""
    src = src or REPO
    dest = mktemp()
    names = None
    if (use_git and shutil.which("git")
            and os.path.exists(os.path.join(src, ".git"))):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        proc = subprocess.run(
            ["git", "-C", src, "ls-files", "-z", "--cached", "--others",
             "--exclude-standard"], capture_output=True, env=env)
        if proc.returncode == 0 and proc.stdout:
            names = [n for n in proc.stdout.decode("utf-8", "surrogateescape")
                     .split("\0") if n]
    if names is None:
        names = []
        for root, dirs, files in os.walk(src):
            top = os.path.relpath(root, src) == "."
            dirs[:] = [d for d in dirs if d != "__pycache__"
                       and not (top and (d in BUILD_LEFTOVERS
                                         or d.endswith(".egg-info")))]
            names += [os.path.relpath(os.path.join(root, f), src)
                      for f in files if not f.endswith((".pyc", ".pyo"))]
    for name in names:
        source = os.path.join(src, name)
        if os.path.isfile(source):
            target = os.path.join(dest, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(source, target)
    return dest


def _cleanup() -> None:
    for d in _TEMP_DIRS + [FAKE_HOME]:
        try:
            rmtree(d)
        except OSError:
            pass


def real_stuntkey_state(home: str) -> dict:
    """Read-only fingerprint of a real ~/.stuntkey: name -> (size, mtime_ns), plus
    the sha256 of index.json. Never writes, never opens a log for append."""
    import hashlib
    state: dict = {}
    base = os.path.join(home, ".stuntkey")
    for root, _dirs, files in os.walk(base):
        for f in files:
            p = os.path.join(root, f)
            try:
                st = os.stat(p)
            except OSError:
                continue
            state[os.path.relpath(p, base)] = (st.st_size, st.st_mtime_ns)
    try:
        with open(os.path.join(base, "index.json"), "rb") as fh:
            state["index.json#sha256"] = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        pass
    return state


# the real user's folder, fingerprinted BEFORE HOME is pointed elsewhere
REAL_HOME = os.path.expanduser("~")
REAL_STATE_AT_START = real_stuntkey_state(REAL_HOME)


def scrub_env() -> None:
    """Remove every STUNTKEY_* variable the caller exported (STUNTKEY_KEYCHAIN=memory
    and friends) so none can leak INTO a test. The test-home variable is kept."""
    for k in [k for k in os.environ
              if k.startswith("STUNTKEY_") and k != "STUNTKEY_TEST_HOME"]:
        del os.environ[k]


def snapshot_env() -> dict:
    return {k: v for k, v in os.environ.items() if k.startswith("STUNTKEY_")}


def restore_env(snap: dict) -> None:
    """Put the STUNTKEY_* variables back exactly as they were: nothing a test set
    stays set, nothing it removed stays removed (nothing leaks OUT)."""
    for k in [k for k in os.environ if k.startswith("STUNTKEY_") and k not in snap]:
        del os.environ[k]
    os.environ.update(snap)


scrub_env()

_TEMP_DIRS: list = []
FAKE_HOME = os.environ.get("STUNTKEY_TEST_HOME") or tempfile.mkdtemp(prefix="seh")
for _var in ENV_VARS:
    os.environ[_var] = FAKE_HOME
os.environ["STUNTKEY_TEST_HOME"] = FAKE_HOME  # subprocesses share it
atexit.register(_cleanup)

# the consent folder comes from the system's user database, not from $HOME:
# keep tests out of the real one
from stuntkey import consent as _consent  # noqa: E402
_consent.home_dir = lambda: FAKE_HOME


# No test may reach the real network: a connect to anything but this machine
# fails the test (unix sockets and 127.0.0.1 / ::1 stub servers are fine).
import socket as _socket

_real_connect = _socket.socket.connect


def _local_only_connect(self, address):
    if self.family in (_socket.AF_INET, _socket.AF_INET6):
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise AssertionError(f"a test tried to reach the real network: {host!r}")
    return _real_connect(self, address)


_socket.socket.connect = _local_only_connect


@contextlib.contextmanager
def custom_patterns_allowed():
    """Where the system has no timer signal (Windows) a recipe of your own is
    never run, by design (scan.user_patterns_usable). Tests of the CONSENT rules
    around such recipes (what is asked, what is sent) are about something else,
    so they run with a no-op timer there; elsewhere nothing is changed."""
    from unittest import mock
    from stuntkey import scan as scan_mod
    if scan_mod.user_patterns_usable():
        yield
        return

    @contextlib.contextmanager
    def no_timer(_seconds):
        yield
    with mock.patch.object(scan_mod, "user_patterns_usable", lambda: True), \
            mock.patch.object(scan_mod, "_pattern_timer", no_timer):
        yield
