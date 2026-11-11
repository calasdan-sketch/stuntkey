"""Proxy sessions: a `stuntkey proxy` run that can expire and be switched off.

Each proxy run writes one small signed file, <home>/sessions/<pid>.json. It
holds NO key and NO placeholder token, only: the service names, a one-way
fingerprint (SHA-256) of each placeholder, when the run ends (or "never"), the
process number and a counter. The file is signed with the same kind of secret
that signs the activity log (the keychain integrity key, purpose "session"), so
a program that can only write into the folder cannot forge a file that says
"this run is fine" or "this key is not revoked".

The proxy looks at the file on EVERY request, cheaply (one stat; the file is
read again only when it changed). A run stops serving at once when:
  * its time is up (the clock check needs no file),
  * its file is gone (`stuntkey revoke --all` deletes them),
  * its file changed and the signature is wrong, or the counter went BACK
    (someone put an old copy back to undo a revoke): treated as ended,
  * the service is on the file's revoked list (`stuntkey revoke <service>`).

What this does NOT do (plain list): a program running as the same Windows user
can still ask the Windows password vault for a key directly, so a placeholder
or a session is not a lock against it, and a same-user program can delete the
folder to end a session (that only ever makes things stricter). What it does
give: the key never sits in the program's environment, a placeholder leaked
from an environment dump works for one service only, only until the run ends,
and a person can cut a run off from outside.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time

DIR = "sessions"
VERSION = 1
DEFAULT_TTL = 8 * 3600.0          # proxy runs: eight hours unless `--ttl` says otherwise
TUNNEL = "*tunnel"                # the name the tunnel's password is filed under
PURPOSE = "session"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_FILE = re.compile(r"\d{1,10}(-\d{1,4})?\.json\Z")


class SessionError(Exception):
    """Plain words for a person. Never contains a key or a token."""


def ended_text(why: str) -> str:
    return (f"This stuntkey session has ended ({why}). Run your program again "
            "through `stuntkey proxy` to get a fresh one.")


class SessionEnded(SessionError):
    def __init__(self, why: str):
        super().__init__(ended_text(why))
        self.why = why


# ---- small helpers ------------------------------------------------------------------

def parse_ttl(text) -> float:
    """'30m', '2h', '90s', '1d', or a bare number of minutes -> seconds.
    '0' (or 'none'/'off') means no time limit -> 0.0. Raises ValueError with a
    plain message."""
    raw = str(text if text is not None else "").strip().lower()
    if raw in ("none", "off", "never"):
        return 0.0
    m = re.fullmatch(r"(\d{1,6})\s*([smhd]?)", raw)
    if not m:
        raise ValueError("--ttl wants a time like 30m, 2h, 90s or 1d (or 0 for no limit), "
                         f"not {str(text)[:20]!r}")
    n, unit = int(m.group(1)), m.group(2) or "m"
    return float(n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit])


def fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def sessions_dir(home: str) -> str:
    return os.path.join(home, DIR)


def _key(home: str, create: bool):
    from . import keychain
    try:
        return keychain.integrity_key(home, create=create, purpose=PURPOSE)[0]
    except Exception:
        return None


def _body(doc: dict) -> bytes:
    plain = {k: v for k, v in doc.items() if k != "mac"}
    return json.dumps(plain, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(doc: dict, key: bytes) -> str:
    return hmac.new(key, _body(doc), hashlib.sha256).hexdigest()


def _signed(doc: dict, key: bytes) -> dict:
    out = {k: v for k, v in doc.items() if k != "mac"}
    out["mac"] = _sign(out, key)
    return out


def load_file(path: str, key: bytes | None):
    """The document in `path` when it is there, well formed and correctly
    signed; else None. (A missing key means nothing can be trusted: None.)"""
    if key is None:
        return None
    try:
        if os.path.islink(path) or os.path.getsize(path) > 65536:
            return None
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        mac = doc.get("mac")
        if (not isinstance(doc, dict) or not isinstance(mac, str)
                or doc.get("v") != VERSION
                or not hmac.compare_digest(mac, _sign(doc, key))):
            return None
        if (not isinstance(doc.get("pid"), int) or not isinstance(doc.get("gen"), int)
                or not isinstance(doc.get("services"), list)
                or not isinstance(doc.get("hashes"), dict)
                or not isinstance(doc.get("revoked"), list)):
            return None
        return doc
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _put(path: str, doc: dict) -> None:
    tmp = f"{path}.{secrets.token_hex(4)}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, sort_keys=True)
    last = None
    for _ in range(8):                  # a reader may hold the file for a moment (Windows)
        try:
            os.replace(tmp, path)
            return
        except PermissionError as e:
            last = e
            time.sleep(0.05)
    try:
        os.remove(tmp)
    except OSError:
        pass
    raise last or OSError("could not replace the session file")


def pid_alive(pid: int) -> bool:
    """Is a process with this number running? (Never os.kill on Windows: it
    would END the process.)"""
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.OpenProcess.restype = ctypes.c_void_p
            h = k32.OpenProcess(0x1000, False, pid)         # QUERY_LIMITED_INFORMATION
            if not h:
                return ctypes.windll.kernel32.GetLastError() == 5   # 5 = access denied: exists
            code = ctypes.c_ulong()
            ok = k32.GetExitCodeProcess(ctypes.c_void_p(h), ctypes.byref(code))
            k32.CloseHandle(ctypes.c_void_p(h))
            return bool(ok) and code.value == 259           # STILL_ACTIVE
        except Exception:
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


# ---- starting and ending a run ------------------------------------------------------

def create(home: str, tokens: dict, ttl: float = DEFAULT_TTL, max_calls: int = 0,
           pid: int | None = None, clock=time.time) -> "Guard":
    """Write the session file for a new proxy run and return the Guard the
    proxy checks on every request. `tokens`: {service: placeholder} (the
    tunnel's under TUNNEL). Raises SessionError when the signing secret cannot
    be reached (no run starts without a way to switch it off)."""
    key = _key(home, create=True)
    if key is None:
        raise SessionError("stuntkey cannot reach its signing secret (the Windows password "
                           "vault did not answer), so it cannot start a run that can be "
                           "ended later. Unlock the vault and try again.")
    pid = os.getpid() if pid is None else pid
    now = clock()
    expires = now + ttl if ttl and ttl > 0 else 0.0
    doc = {"v": VERSION, "pid": pid, "gen": 1, "started": now, "expires": expires,
           "max_calls": int(max_calls or 0), "revoked": [],
           "services": sorted(s for s in tokens if s != TUNNEL and _NAME.match(s)),
           "hashes": {s: fingerprint(t) for s, t in tokens.items()}}
    folder = sessions_dir(home)
    from . import remote
    remote.private_dir(folder)
    signed = _signed(doc, key)
    path = None
    for n in range(1, 200):
        cand = os.path.join(folder, f"{pid}.json" if n == 1 else f"{pid}-{n}.json")
        if os.path.lexists(cand):
            old = load_file(cand, key)
            if old is not None and pid_alive(old["pid"]) and not _expired(old, now):
                continue                # a live run of this process: take the next name
            try:
                os.remove(cand)         # stale (dead, ended, or not signed by us)
            except OSError:
                continue
        try:
            with open(cand, "x", encoding="utf-8") as f:
                json.dump(signed, f, sort_keys=True)
            path = cand
            break
        except FileExistsError:
            continue
    if path is None:
        raise SessionError("stuntkey could not write its session file in ~/.stuntkey/sessions.")
    return Guard(home, path, doc, tokens, key, clock)


def _expired(doc: dict, now: float) -> bool:
    exp = doc.get("expires") or 0
    return bool(exp) and now >= exp


class Guard:
    """What the proxy asks before serving a request."""

    def __init__(self, home, path, doc, tokens, key, clock=time.time):
        self.home, self.path, self.key, self.clock = home, path, key, clock
        self.expires = doc.get("expires") or 0.0
        self.pid = doc["pid"]
        self.max_calls = doc.get("max_calls", 0)
        self._hashes = dict(doc["hashes"])
        self._gen = doc["gen"]
        self._revoked = set()
        self._sig = None                    # (mtime_ns, size) of the last file we verified
        self._dead = None
        try:
            st = os.stat(path)
            self._sig = (st.st_mtime_ns, st.st_size)
        except OSError:
            pass

    def _end(self, why: str):
        self._dead = why                    # once ended, always ended
        raise SessionEnded(why)

    def ended(self) -> str | None:
        """Why this run is over, or None. Never raises."""
        try:
            self.check(None)
        except SessionEnded as e:
            return e.why
        return None

    def check(self, service: str | None = None) -> None:
        """Raise SessionEnded when the run is over (or `service` was cut off)."""
        if self._dead:
            raise SessionEnded(self._dead)
        if self.expires and self.clock() >= self.expires:
            self._end("its time ran out")
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._end("it was switched off with `stuntkey revoke`")
        except OSError:
            self._end("its session record cannot be read")
        sig = (st.st_mtime_ns, st.st_size)
        if sig != self._sig:
            doc = load_file(self.path, self.key)
            for _ in range(3):          # a revoke may be swapping the file this instant
                if doc is not None:
                    break
                time.sleep(0.03)
                doc = load_file(self.path, self.key)
            if (doc is None or doc["pid"] != self.pid or doc["gen"] < self._gen
                    or doc["hashes"] != self._hashes):
                self._end("its session record was changed from outside")
            self._gen = doc["gen"]
            self._revoked = {str(s) for s in doc["revoked"]}
            self._sig = sig
        if service is not None and service in self._revoked:
            raise SessionEnded(f"the key for '{service}' was switched off with "
                               "`stuntkey revoke`")
        if service is None and "*" in self._revoked:
            self._end("it was switched off with `stuntkey revoke`")

    def close(self) -> None:
        """The run is over: remove its file (best effort)."""
        try:
            os.remove(self.path)
        except OSError:
            pass


# ---- listing and revoking (for the command line) ------------------------------------

def _files(home: str) -> list:
    folder = sessions_dir(home)
    try:
        names = sorted(n for n in os.listdir(folder) if _FILE.match(n))
    except OSError:
        return []
    return [os.path.join(folder, n) for n in names]


def list_sessions(home: str, clock=time.time, prune: bool = True) -> list:
    """[{file, pid, services, revoked, expires, left, max_calls, state}] for each
    session file. state: "active", "ended" (time up or its process is gone;
    pruned when `prune`), or "not-trusted" (signature wrong: never believed,
    left for `revoke --all` to remove). No tokens, ever."""
    key = _key(home, create=False)
    now, out = clock(), []
    for path in _files(home):
        doc = load_file(path, key)
        if doc is None:
            out.append({"file": os.path.basename(path), "state": "not-trusted"})
            continue
        gone = _expired(doc, now) or not pid_alive(doc["pid"])
        if gone and prune:
            try:
                os.remove(path)
            except OSError:
                pass
            continue
        exp = doc.get("expires") or 0
        out.append({"file": os.path.basename(path), "pid": doc["pid"],
                    "services": [s for s in doc["services"] if s not in doc["revoked"]],
                    "revoked": list(doc["revoked"]), "expires": exp,
                    "left": (exp - now) if exp else None,
                    "max_calls": doc.get("max_calls", 0),
                    "state": "ended" if gone else "active"})
    return out


def revoke(home: str, service: str | None = None) -> int:
    """`service` None: delete every session file (every running proxy stops
    serving at its next request). Else: mark that one service revoked in each
    session that carries it (files we cannot verify are deleted: fail closed).
    Returns how many sessions were changed."""
    key = _key(home, create=False)
    n = 0
    for path in _files(home):
        if service is None:
            try:
                os.remove(path)
                n += 1
            except OSError:
                pass
            continue
        doc = load_file(path, key)
        if doc is None:
            try:
                os.remove(path)
                n += 1
            except OSError:
                pass
            continue
        if service in doc["services"] and service not in doc["revoked"]:
            new = dict(doc, gen=doc["gen"] + 1, revoked=sorted(doc["revoked"] + [service]))
            _put(path, _signed(new, key))
            n += 1
    return n


def span_text(seconds: float) -> str:
    m = max(1, int(seconds // 60))
    return f"{m // 60}h {m % 60}m" if m >= 60 else f"{m}m"


def _left_text(left) -> str:
    if left is None:
        return "no time limit"
    if left <= 0:
        return "time is up"
    return span_text(left) + " left"


def cmd_sessions(args, home: str, clock=time.time) -> int:
    rows = list_sessions(home, clock)
    if not rows:
        print("No proxy runs are open right now.")
        return 0
    for r in rows:
        if r["state"] == "not-trusted":
            print(f"  {r['file']:16} NOT TRUSTED (signature wrong; ignored. "
                  "`stuntkey revoke --all` removes it)")
            continue
        names = ", ".join(r["services"]) or "(none left)"
        extra = f"  switched off: {', '.join(r['revoked'])}" if r["revoked"] else ""
        cap = f"  max {r['max_calls']} calls" if r["max_calls"] else ""
        print(f"  pid {r['pid']:<7} {_left_text(r['left']):16} {names}{cap}{extra}")
    print("(Placeholders are never shown. `stuntkey revoke --all` ends every run; "
          "`stuntkey revoke <service>` cuts one service off.)")
    return 0


def cmd_revoke(args, home: str) -> int:
    service = getattr(args, "service", None)
    everything = getattr(args, "all", False) is True
    if bool(service) == everything:
        print("error: say what to switch off: `stuntkey revoke --all` or "
              "`stuntkey revoke <service>`.", file=sys.stderr)
        return 2
    if service and not _NAME.match(str(service)):
        print("error: that is not a service name.", file=sys.stderr)
        return 2
    try:
        n = revoke(home, None if everything else str(service))
    except (OSError, SessionError) as e:
        print(f"error: could not switch it off: {e}", file=sys.stderr)
        return 1
    what = "every run" if everything else f"'{service}'"
    print(f"Switched off {what}: {n} proxy run(s) changed. They stop serving at their "
          "next request; a program that still holds an old placeholder gets a plain "
          "'session ended' message.")
    return 0
