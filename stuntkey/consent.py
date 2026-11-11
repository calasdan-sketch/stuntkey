"""The terminal route's permission for agent-driven key capture, signed so that a file edit cannot forge it.

IMPORTANT - what this is and is not. The permission a person gives in the
confirmation WINDOW (dialog.py) is kept only in the memory of the running MCP
server, for that session, and is never written here. This file holds only the
permission given with the terminal command `stuntkey allow-agent`, which
survives restarts. It is ADVISORY: a program running as the same user can read
the secret that signs it (DPAPI and the keychain protect against other users
and other machines, not against another process of yours) and a terminal can
be faked by a pseudo-terminal. The window is a real gate only against an agent
that cannot run code as the same user; nothing here stops one that can.

Where: ~/.stuntkey/agent-consent.json, in the home folder from the system's
user database (not $HOME, which a launcher can change). What: the list of
(project, service) grants, a counter and an HMAC-SHA256 over both. The key is
a random per-user secret kept in the best place the system offers: a
DPAPI-protected blob, the macOS keychain, the Linux Secret Service
(secret-tool), else a 0600 file marked ADVISORY. The counter is kept next to
the key and goes up on every grant and revoke, so an OLD copy of the file (an
undone grant put back) does not verify. A file that does not verify counts as
NO grants (fail closed).
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

from . import safeexec
from . import schema

VERSION = 3
# {old_version: fn(doc) -> doc in old_version + 1}. A file in an older format is read
# through these steps (schema.load_versioned); with no step on hand it is reported
# as "old" in plain words and never overwritten. Add a step here when VERSION moves.
MIGRATIONS: dict = {}
PROBLEM_WORDS = {
    "newer": "The agent permission list was made by a newer StuntKey. Update StuntKey "
             "(pipx upgrade stuntkey); until then no agent permission counts.",
    "old": "The agent permission list is in an older format this StuntKey cannot bring "
           "forward. Run `stuntkey allow-agent` again for the projects you want to allow.",
    "corrupt": "The agent permission list is damaged, so no agent permission counts.",
    "forged": "The agent permission list does not match its signature, so no agent "
              "permission counts.",
    "stale": "The agent permission list is an older copy than the one StuntKey last "
             "saved, so no agent permission counts.",
    "no secret": "The key that signs the agent permission list is missing, so no agent "
                 "permission counts.",
}
DIR_NAME = ".stuntkey"
FILE_NAME = "agent-consent.json"
SECRET_FILE = "consent.key"
LABEL = "stuntkey-consent"
LEGACY_LABEL = "oathkey-consent"   # 0.8's keychain entry: read when ours is missing


def home_dir() -> str:
    """The user's home folder from the system's user database, not from
    environment variables an agent's launcher may have changed."""
    if os.name == "posix":
        try:
            import pwd
            return pwd.getpwuid(os.getuid()).pw_dir
        except (ImportError, KeyError, OSError):
            pass
    return os.path.expanduser("~")


def consent_dir() -> str:
    return os.path.join(home_dir(), DIR_NAME)


def consent_path() -> str:
    return os.path.join(consent_dir(), FILE_NAME)


# ------------------------------------------------------ owner-only on Windows (round 13)
#
# `os.makedirs(mode=0o700)` and `chmod 0o600` do nothing on Windows. The files in
# ~/.stuntkey are protected there only by what the profile folder hands down. This
# makes the store's own folder (and the files in it) readable by this user and the
# system only: `icacls <path> /inheritance:r /grant:r *<my SID>:F *S-1-5-18:F`
# (the first one with (OI)(CI) for a folder, so files made later inherit it). It
# runs once per path per program, never opens a window, never touches a folder that
# is not named .stuntkey, and failing is quiet (best effort). A person who wants the
# old behaviour sets STUNTKEY_NO_ACL=1. Honest limit: another program running as the
# SAME user can still read these files; this stops other accounts and a loose
# profile ACL, nothing more.
_HARDENED: set = set()
SYSTEM_SID = "S-1-5-18"


def _current_sid() -> str | None:
    """The SID text of the user running this program (Windows), else None."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.POINTER(wintypes.DWORD)]
        advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        token = wintypes.HANDLE()
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):   # TOKEN_QUERY
            return None
        try:
            size = wintypes.DWORD(0)
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))                    # TokenUser
            buf = ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
                return None
            psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            out = ctypes.c_void_p()
            if not advapi.ConvertSidToStringSidW(psid, ctypes.byref(out)):
                return None
            try:
                return ctypes.wstring_at(out.value)
            finally:
                kernel.LocalFree(out)
        finally:
            kernel.CloseHandle(token)
    except Exception:
        return None


def harden_acl(path: str, run=subprocess.run) -> bool:
    """Make `path` (the .stuntkey folder, or a file in it) owner-only on Windows.
    True when it was done (or already done this run); False when not applicable or
    it could not be done. Never raises, never opens a window."""
    if os.name != "nt" or os.environ.get("STUNTKEY_NO_ACL") == "1":
        return False
    path = os.path.abspath(path)
    parts = os.path.normcase(path).split(os.sep)
    if DIR_NAME not in parts[-2:]:
        return False
    if path in _HARDENED:
        return True
    sid = _current_sid()
    if not sid or not sid.startswith("S-1-"):
        return False
    try:
        root = os.environ.get("SystemRoot") or r"C:\Windows"
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(260)
            if ctypes.windll.kernel32.GetSystemDirectoryW(buf, 260):
                root = os.path.dirname(buf.value)
        except Exception:
            pass
        icacls = os.path.join(root, "System32", "icacls.exe")
        if not os.path.isfile(icacls):
            return False
        flags = "(OI)(CI)F" if os.path.isdir(path) else "F"
        done = run([icacls, path, "/inheritance:r", "/grant:r", f"*{sid}:{flags}",
                    "/grant:r", f"*{SYSTEM_SID}:{flags}"],
                   capture_output=True, timeout=20, env={"SystemRoot": root, "PATH": os.path.join(root, "System32")},
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if done.returncode == 0:
            _HARDENED.add(path)
            return True
    except Exception:
        pass
    return False


def _is_link(path: str) -> bool:
    """A symbolic link, or on Windows any reparse point (a junction too)."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    import stat as stat_mod
    if stat_mod.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & 0x400)      # FILE_ATTRIBUTE_REPARSE_POINT


# ------------------------------------------------------------- the secret

class FileSecret:
    kind = "file"
    advisory = True

    def __init__(self, path: str | None = None):
        self.path = path

    def _p(self) -> str:
        return self.path or os.path.join(consent_dir(), SECRET_FILE)

    def load(self) -> bytes | None:
        if _is_link(self._p()):
            return None          # a link planted where the secret should be is not the secret
        try:
            with open(self._p(), "rb") as f:
                data = f.read(256)
        except OSError:
            return None
        return data if len(data) >= 16 else None

    def save(self, secret: bytes) -> None:
        path = self._p()
        _private_dir(os.path.dirname(path))
        _write_private(path, secret)

    def delete(self) -> None:
        try:
            os.unlink(self._p())
        except FileNotFoundError:
            pass


def _private_dir(path: str) -> None:
    """The consent folder, created owner-only (0700)."""
    if not os.path.isdir(path):
        os.makedirs(path, mode=0o700, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    harden_acl(path)


def _write_private(path: str, data: bytes) -> None:
    """Create `path` private (0600) without a window in which another process
    could have made it first: O_EXCL when it is new, else a private temporary
    file moved over it."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    except FileExistsError:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".key-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            _replace(tmp, path)
            harden_acl(path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    harden_acl(path)


class DpapiSecret(FileSecret):
    """The secret in a file, encrypted for this Windows user (DPAPI)."""
    kind = "dpapi"
    advisory = False

    def _p(self) -> str:
        return self.path or os.path.join(consent_dir(), SECRET_FILE + ".dpapi")

    @staticmethod
    def _crypt(data: bytes, protect: bool) -> bytes:
        import ctypes
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        # a fixed constant, kept from 0.8 (oathkey): a new one would make the
        # secret copied over from ~/.oathkey unreadable
        entropy_bytes = b"oathkey-consent"
        buf = ctypes.create_string_buffer(data, len(data))
        ent = ctypes.create_string_buffer(entropy_bytes, len(entropy_bytes))
        blob_in = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_ent = Blob(len(entropy_bytes), ctypes.cast(ent, ctypes.POINTER(ctypes.c_char)))
        blob_out = Blob()
        fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
        if not fn(ctypes.byref(blob_in), None, ctypes.byref(blob_ent), None, None, 0,
                  ctypes.byref(blob_out)):
            raise OSError("DPAPI refused")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)

    def load(self) -> bytes | None:
        try:
            with open(self._p(), "rb") as f:
                blob = f.read(4096)
            return self._crypt(blob, False)
        except (OSError, ValueError):
            return None

    def save(self, secret: bytes) -> None:
        path = self._p()
        _private_dir(os.path.dirname(path))
        _write_private(path, self._crypt(secret, True))


class CommandSecret:
    """The secret in the OS keychain (macOS `security`) or the Secret Service
    (`secret-tool`), reached through its command line tool, found only in
    system folders and run with a fixed environment (safeexec.py)."""
    advisory = False

    def __init__(self, kind: str, run=safeexec.run, find=safeexec.find):
        self.kind = kind
        self.run = run
        self.find = find

    def _tool(self) -> str:
        name = "security" if self.kind == "keychain" else "secret-tool"
        path = self.find(name)
        if not path:
            raise OSError(safeexec.explain(name) or "the keychain tool is not available in a trusted place")
        return path

    def load(self) -> bytes | None:
        return self._load(LABEL) or self._load(LEGACY_LABEL)

    def _load(self, label: str) -> bytes | None:
        try:
            tool = self._tool()
            argv = ([tool, "find-generic-password", "-a", label, "-s", label, "-w"]
                    if self.kind == "keychain" else
                    [tool, "lookup", "service", label, "kind", "consent"])
            done = self.run(argv, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if done.returncode != 0:
            return None
        try:
            return bytes.fromhex(done.stdout.decode("ascii", "replace").strip())
        except ValueError:
            return None

    def save(self, secret: bytes) -> None:
        text = secret.hex()
        tool = self._tool()
        if self.kind == "keychain":
            # `security -i` reads its commands from stdin, so the secret never
            # appears in the argument list of a process anyone can list (ps)
            argv, data = [tool, "-i"], (
                f"add-generic-password -U -a {LABEL} -s {LABEL} -w {text}\n").encode("ascii")
        else:
            argv, data = [tool, "store", "--label=" + LABEL, "service", LABEL,
                          "kind", "consent"], text.encode("ascii")
        done = self.run(argv, input=data, capture_output=True, timeout=30)
        if done.returncode != 0:
            raise OSError("the keychain refused the consent secret")


class ChainSecret:
    """A keychain first; the 0600 file only where the keychain does not work.

    The keychain is the authority. The file is read ONLY when the keychain
    returns nothing (unavailable, locked, no entry) - never because it holds a
    "newer" counter, or a program that can write files could take over by
    writing its own file and counter. When the keychain saves successfully the
    fallback file is deleted, so no stale second authority is left behind.

    Known limit: where the keychain is empty or absent, a file planted by a
    program that can write files is accepted. That is the no-window route,
    which is advisory anyway (see the module docstring)."""

    def __init__(self, primary, fallback):
        self.primary, self.fallback, self.used = primary, fallback, primary

    @property
    def kind(self) -> str:
        return self.used.kind

    @property
    def advisory(self) -> bool:
        return self.used.advisory

    def load(self) -> bytes | None:
        try:
            blob = self.primary.load()
        except Exception:
            blob = None
        if blob:
            self.used = self.primary
            return blob
        try:
            blob = self.fallback.load()
        except Exception:
            blob = None
        if blob:
            self.used = self.fallback
        return blob

    def save(self, secret: bytes) -> None:
        try:
            self.primary.save(secret)
            # a keychain tool that exits 0 and stored nothing is a failed save:
            # read it back before trusting it (and before deleting the file)
            if self.primary.load() != secret:
                raise OSError("the keychain did not keep the consent secret")
            self.used = self.primary
        except Exception:
            self.fallback.save(secret)
            self.used = self.fallback
            return
        try:
            self.fallback.delete()
        except Exception:
            pass


def pick_secret_store(platform: str | None = None, which=safeexec.find):
    platform = platform or sys.platform
    if platform == "win32":
        return DpapiSecret()
    if platform == "darwin" and which("security"):
        return ChainSecret(CommandSecret("keychain", find=which), FileSecret())
    if which("secret-tool"):
        return ChainSecret(CommandSecret("secret-tool", find=which), FileSecret())
    return FileSecret()


_STORE = None


def secret_store():
    global _STORE
    if _STORE is None:
        _STORE = pick_secret_store()
    return _STORE


def set_secret_store(store) -> None:
    """For tests (and callers that know better)."""
    global _STORE
    _STORE = store


def integrity() -> str:
    """How well the consent file is protected here, in a few words."""
    store = secret_store()
    return store.kind + (" (advisory: a plain file)" if store.advisory else "")


# ---------------------------------------------------------------- the file

def split(blob: bytes) -> tuple[bytes, int]:
    """(HMAC key, counter) from what the secret store holds: 32 key bytes then
    an 8-byte counter. A shorter blob has counter 0."""
    if len(blob) >= 40:
        return blob[:32], int.from_bytes(blob[32:40], "big")
    return blob, 0


def pack(key: bytes, counter: int) -> bytes:
    return key[:32].ljust(32, b"\0") + counter.to_bytes(8, "big")


def _canonical(grants: list, counter: int, version: int = VERSION) -> bytes:
    return json.dumps({"version": version, "counter": counter, "grants": grants},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _mac(grants: list, counter: int, key: bytes, version: int = VERSION) -> str:
    return hmac.new(key, _canonical(grants, counter, version), hashlib.sha256).hexdigest()


def problem_words(problem: str) -> str:
    """Plain words for a read_grants problem ("" for none)."""
    return PROBLEM_WORDS.get(problem, "")


def read_grants(path: str | None = None, store=None) -> tuple[list[dict], str]:
    """(grants, problem). `problem` is "" when the file is fine, "missing" when
    there is none, else "corrupt" / "forged" / "stale" / "no secret". Anything
    wrong gives NO grants: a file that does not verify is not consent."""
    store = store or secret_store()
    try:
        with open(path or consent_path(), encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return [], "missing"
    except (OSError, ValueError, RecursionError):
        return [], "corrupt"
    if not isinstance(data, dict) \
            or not isinstance(data.get("grants"), list) or not isinstance(data.get("mac"), str) \
            or not isinstance(data.get("counter"), int) or isinstance(data.get("counter"), bool):
        return [], "corrupt"
    signed_version = schema.version_of(data)       # the signature covers the file's OWN version
    try:
        data = schema.load_versioned(data, VERSION, MIGRATIONS, "The agent permission list",
                                     path or consent_path())
    except schema.SchemaError as e:
        return [], e.kind                          # "newer" or "old": never read, never overwritten
    blob = store.load()
    if not blob:
        return [], "no secret"
    key, counter = split(blob)
    if not hmac.compare_digest(_mac(data["grants"], data["counter"], key, signed_version), data["mac"]):
        return [], "forged"
    if data["counter"] != counter:
        return [], "stale"                      # an older (or newer) copy of the file
    return [g for g in data["grants"] if isinstance(g, dict)
            and isinstance(g.get("project"), str) and isinstance(g.get("service"), str)
            and not _expired(g)], ""


def _expired(grant: dict, now: datetime.datetime | None = None) -> bool:
    """A grant with an "expires" date in the past (round 13). A grant without one lasts
    until it is revoked, as before; an "expires" that cannot be read counts as expired
    (the safe answer)."""
    stamp = grant.get("expires")
    if stamp is None:
        return False
    try:
        end = datetime.datetime.fromisoformat(str(stamp))
        if end.tzinfo is None:
            end = end.replace(tzinfo=datetime.timezone.utc)
        return end <= (now or datetime.datetime.now(datetime.timezone.utc))
    except (ValueError, TypeError, OverflowError):
        return True


def _replace(src: str, dst: str) -> None:
    for attempt in range(8):                    # Windows: a scanner may hold the file a moment
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == 7:
                raise
            time.sleep(0.05 * (attempt + 1))


def _write(grants: list, path: str, key: bytes, counter: int) -> None:
    folder = os.path.dirname(path)
    _private_dir(folder)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".consent-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": VERSION, "counter": counter, "grants": grants,
                       "mac": _mac(grants, counter, key)}, f, indent=2)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        _replace(tmp, path)
        harden_acl(path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _same(a: str, b: str) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def project_key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def consent_for(project: str, service: str, path: str | None = None, store=None) -> dict | None:
    grants, _ = read_grants(path, store)
    for g in grants:
        if g["service"] == service and _same(g["project"], project):
            return g
    return None


def grants_for(project: str, path: str | None = None, store=None) -> list[dict]:
    return [g for g in read_grants(path, store)[0] if _same(g["project"], project)]


_LOCK = threading.RLock()


def _pid_alive(pid: int) -> bool:
    """Is a process with this id running? Unsure counts as yes."""
    if pid <= 0 or pid == os.getpid():
        return True
    try:
        if os.name == "nt":
            import ctypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel.OpenProcess(0x1000, False, pid)   # QUERY_LIMITED_INFORMATION
            if not handle:
                return ctypes.get_last_error() != 87          # 87: no such process
            try:
                code = ctypes.c_ulong()
                if kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return code.value == 259                  # STILL_ACTIVE
                return True
            finally:
                kernel.CloseHandle(handle)
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except Exception:
        return True


def _lock_is_stale(path: str, limit: float) -> bool:
    """A lock is stale when it is older than `limit` seconds, or (after a short
    grace) when the process that made it is gone - a crash must not block the
    next run for minutes."""
    try:
        age = time.time() - os.stat(path).st_mtime
    except OSError:
        return False
    if age > limit:
        return True
    if age < 2:
        return False
    try:
        with open(path, encoding="ascii") as f:
            pid = int(f.read(32).split()[0])
    except (OSError, ValueError, IndexError, UnicodeDecodeError):
        return False
    return not _pid_alive(pid)


class _FolderLock:
    """One writer at a time, across threads and processes: an O_EXCL lock
    file next to the consent file. A lock is stale after STALE_LOCK seconds
    (longer than two keychain calls at their 30 s limit each); a stale lock is
    taken over by renaming it away first, so two waiters cannot both break it."""

    STALE_LOCK = 180
    WAIT = 10

    def __init__(self, folder: str):
        self.path = os.path.join(folder, ".lock")

    def __enter__(self):
        _LOCK.acquire()
        _private_dir(os.path.dirname(self.path))
        end = time.monotonic() + self.WAIT
        while True:
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(fd, f"{os.getpid()}\n".encode("ascii"))   # who holds it
                except OSError:
                    pass
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if _lock_is_stale(self.path, self.STALE_LOCK):
                        aside = f"{self.path}.stale-{os.getpid()}-{time.monotonic_ns()}"
                        os.rename(self.path, aside)         # only one waiter wins the rename
                        if not _lock_is_stale(aside, self.STALE_LOCK):
                            # what was renamed is a FRESH lock (it was replaced between our
                            # look and our rename): put it back if the name is free, else
                            # drop it, and back off either way
                            try:
                                os.link(aside, self.path)
                            except OSError:
                                pass
                            try:
                                os.unlink(aside)
                            except OSError:
                                pass
                            time.sleep(0.02)
                            continue
                        try:
                            os.unlink(aside)
                        except OSError:
                            pass
                        continue
                except OSError:
                    pass
                if time.monotonic() > end:
                    _LOCK.release()
                    raise OSError("the consent file is locked by another process")
                time.sleep(0.02)
            except BaseException:
                _LOCK.release()
                raise

    def __exit__(self, *exc):
        try:
            os.unlink(self.path)
        except OSError:
            pass
        _LOCK.release()


def _commit(grants: list, path: str, store) -> None:
    """Save the new counter with the key FIRST, then the file: a crash in
    between leaves a file that does not verify (no consent), never a stale
    one that does."""
    blob = store.load()
    key = split(blob)[0] if blob else os.urandom(32)
    counter = (split(blob)[1] if blob else 0) + 1
    store.save(pack(key, counter))
    _write(grants, path, key, counter)
    try:
        os.unlink(path + ".bak")                # no old copies lying around
    except OSError:
        pass


def grant(project: str, service: str, history_ok: bool = False, path: str | None = None,
          env_file: str | None = None, store=None,
          now: datetime.datetime | None = None, days: int | None = None) -> None:
    path = path or consent_path()
    store = store or secret_store()
    with _FolderLock(os.path.dirname(path)):
        grants, _problem = read_grants(path, store)     # a file that does not verify starts clean
        _keep_unreadable_format(_problem, path)
        grants = [g for g in grants if not (g["service"] == service and _same(g["project"], project))]
        stamp = (now or datetime.datetime.now(datetime.timezone.utc)).replace(microsecond=0)
        entry = {"project": os.path.realpath(project), "service": service,
                 "clipboard_history_ok": bool(history_ok), "granted": stamp.isoformat()}
        if env_file:
            entry["env_file"] = env_file
        if days is not None and days > 0:
            entry["expires"] = (stamp + datetime.timedelta(days=int(days))).isoformat()
        grants.append(entry)
        _commit(grants, path, store)


def _keep_unreadable_format(problem: str, path: str) -> None:
    """A file in a NEWER (or an old, unmigratable) format is not "a file that does not
    verify": it is a real list this StuntKey cannot read, and saving over it would destroy
    it. Say so in plain words instead."""
    if problem in ("newer", "old"):
        raise schema.SchemaError(PROBLEM_WORDS[problem] + " Nothing was changed.", path, problem)


def revoke(project: str, service: str | None = None, path: str | None = None, store=None) -> int:
    path = path or consent_path()
    store = store or secret_store()
    with _FolderLock(os.path.dirname(path)):
        grants, _problem = read_grants(path, store)
        _keep_unreadable_format(_problem, path)
        keep = [g for g in grants if not (_same(g["project"], project)
                                          and (service is None or g["service"] == service))]
        if len(keep) != len(grants):
            _commit(keep, path, store)
        return len(grants) - len(keep)
