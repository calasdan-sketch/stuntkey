"""The broker: let an AI call an API without the key entering its environment.

The AI says only: service, method, path, query, body. The broker picks the
host (from the recipe, never from the AI), adds the credential itself,
refuses private/internal addresses, does not follow redirects, hides the key
(in many encodings) from whatever comes back, and writes a tamper-evident
log line (never the query string, body or headers).

What it cannot do: stop a prompt-injected AI from using an allowed API for
something harmful within its permissions. That is why writes need a person's
approval and why the log exists. See SECURITY.md.
"""
from __future__ import annotations

import contextlib
import functools
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import validate as _v
from .scrub import Scrubber, loosely_contains, scrub_text

MAX_BODY_OUT = 1_000_000      # most we read back
RETURN_CAP = 24_000           # default most the MCP call_api hands to the AI
CUT_NOTE = ("\n[cut to save the AI's context; ask for less with the service's "
            "limit or fields parameters, or pass a larger max_chars]")
MAX_BODY_IN = 256_000         # most the AI may send
READ_METHODS = {"GET", "HEAD"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_PATH_OK = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*")
_EXPOSED_HEADERS = ("content-type", "content-length", "retry-after",
                    "x-ratelimit-remaining", "x-ratelimit-reset", "location")

MAX_QUERY_PART = 200    # longest query name or value shown in full
MAX_BODY_SHOWN = 400    # longest body shown in full; bigger is refused
TOO_LONG = ("This request is too long for you to review safely, so it was "
            "refused. Ask for something smaller.")
MAX_REVIEW = 900     # longest request description a person can really read

# AWS "GET" requests can still mint new credentials (GetSessionToken,
# AssumeRole, ...). For signed AWS services only plain look-ups are allowed.
_SIGV4_STS_OK = {"GetCallerIdentity"}
_SIGV4_OK_PREFIX = ("Describe", "List")
_SIGV4_OK_EXACT = {"GetCallerIdentity", "GetAccountSummary"}


def check_sigv4_action(recipe: dict, url: str) -> None:
    spec = (recipe.get("validate") or {}).get("auth", {})
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True)
    actions = q.get("Action", [])
    if len(actions) > 1:
        raise BrokerError("more than one Action; refused", 5)
    action = actions[0] if actions else ""
    if spec.get("service") == "sts":
        if action not in _SIGV4_STS_OK:
            raise BrokerError("through this tool, AWS STS may only be asked "
                              "'GetCallerIdentity' (other STS actions create new "
                              "keys); refused", 5)
    elif action and not (action in _SIGV4_OK_EXACT or action.startswith(_SIGV4_OK_PREFIX)):
        raise BrokerError(f"AWS action '{action[:40]}' is not a plain look-up; refused", 5)


def _clean(text, limit=80) -> str:
    return "".join(c if c.isprintable() else "?" for c in str(text))[:limit]


class BrokerError(Exception):
    """A refusal or failure. The text never contains the key."""

    def __init__(self, message: str, code: int = 5):
        super().__init__(message)
        self.code = code        # 5 = refused by policy, 7 = network, 4 = auth


class Policy:
    """What this session may do. Defaults are the safe ones."""

    def __init__(self, allow_write: bool = False, max_calls: int = 100,
                 max_per_minute: int = 30, approve=None, home: str | None = None,
                 project_dir: str | None = None):
        self.allow_write = allow_write
        self.home = home                # None: ~/.stuntkey (caps, STOP, policy)
        self.project_dir = project_dir  # None: the current folder
        self.service_calls: dict[str, int] = {}
        self.max_calls = max_calls
        self.max_per_minute = max_per_minute
        self.approve = approve          # callable(summary) -> bool, or None
        self._stamps: list[float] = []
        self.calls = 0
        self.denials = 0
        self.approved_hosts: set[tuple[str, str]] = set()
        self.lock = threading.RLock()           # one decision at a time

    def count(self, now: float | None = None) -> None:
        with self.lock:
            now = time.monotonic() if now is None else now
            self._stamps = [t for t in self._stamps if now - t < 60]
            if self.calls >= self.max_calls:
                raise BrokerError(f"Limit of {self.max_calls} calls reached for "
                                  "this session. Restart the AI app to reset.", 5)
            if len(self._stamps) >= self.max_per_minute:
                raise BrokerError("Too many calls per minute; wait a minute "
                                  "and retry.", 5)
            self.calls += 1
            self._stamps.append(now)

    def gate(self, service: str, method: str, path: str) -> None:
        """Route policy, kill switch and caps: checked before every call."""
        from . import caps, policy as route
        home = self.limits_home()
        route.check(route.load(home, self.project_dir or os.getcwd()),
                    service, method, path)
        with self.lock:
            caps.begin(home, service, self.service_calls.get(service, 0))
            self.service_calls[service] = self.service_calls.get(service, 0) + 1

    def add_tokens(self, service: str, n: int) -> None:
        from . import caps
        caps.add_tokens(self.limits_home(), service, n)

    def limits_home(self) -> str:
        return self.home or os.path.join(os.path.expanduser("~"), ".stuntkey")

    def ask(self, summary: str) -> bool:
        """Ask the person, one prompt at a time; after 3 refusals stop asking."""
        with self.lock:
            if self.approve is None:
                return False
            if self.denials >= 3:
                raise BrokerError("The person said no three times; no more "
                                  "requests this session.", 5)
            yes = bool(self.approve(summary))
            if not yes:
                self.denials += 1
            return yes


# ---- address safety ----------------------------------------------------------

def is_public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        # IPv6 forms that carry an IPv4 address inside: judge that one too
        inner = []
        if ip.ipv4_mapped:
            inner.append(ip.ipv4_mapped)
        if ip.sixtofour:
            inner.append(ip.sixtofour)
        if ip.teredo:
            inner.extend(ip.teredo)
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            inner.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if inner:
            return all(is_public_ip(str(i)) for i in inner)
    return ip.is_global and not ip.is_multicast


def resolve_public(host: str, port: int = 443, resolver=None) -> str:
    """One public IP for host, or refuse. Every address it resolves to must
    be public, so a name that also points inside is not accepted."""
    infos = (resolver or socket.getaddrinfo)(host, port, type=socket.SOCK_STREAM)
    ips = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if not is_public_ip(ip):
            raise BrokerError(f"{host} resolves to a private or internal "
                              "address; refused", 5)
        ips.append(ip)
    if not ips:
        raise BrokerError(f"could not resolve {host}", 7)
    return ips[0]


class _Pinned(http.client.HTTPSConnection):
    """Connect to the IP we already checked, but verify the certificate for
    the real name (so DNS cannot change its answer between check and use)."""

    def __init__(self, host, ip=None, **kw):
        super().__init__(host, **kw)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _real_send(req: urllib.request.Request, ip: str, timeout: float):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    class Pin(urllib.request.HTTPSHandler):
        def https_open(self, r):
            return self.do_open(functools.partial(_Pinned, ip=ip), r)

    # ProxyHandler({}) ignores HTTP(S)_PROXY: a proxy would defeat the pin
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         Pin(), NoRedirect())
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    except (urllib.error.URLError, OSError, http.client.HTTPException):
        raise BrokerError("network error talking to the API", 7) from None
    except ValueError:
        raise BrokerError("the HTTP library refused the request", 7) from None
    with resp:
        body = resp.read(MAX_BODY_OUT + 1)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return getattr(resp, "status", None) or resp.code, headers, body


def open_stream(host: str, ip: str, method: str, target: str, headers: dict,
                body, timeout: float, connect=None):
    """Send one request over the pinned connection and hand back the open
    response, so a caller can stream it (the proxy). http.client never
    follows redirects and ignores HTTP(S)_PROXY. `connect(host, timeout=)`
    is for tests only."""
    conn = (connect or functools.partial(_Pinned, ip=ip))(host, timeout=timeout)
    try:
        conn.request(method, target, body=body, headers=headers)
        return conn, conn.getresponse()
    except (OSError, http.client.HTTPException):
        conn.close()
        raise BrokerError("network error talking to the API", 7) from None


# ---- the call ------------------------------------------------------------------

def allowed_host(recipe: dict) -> str:
    url = (recipe.get("validate") or {}).get("url", "")
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or not p.hostname:
        raise BrokerError(f"recipe '{recipe.get('service')}' has no https "
                          "host to call", 5)
    return p.hostname.lower()


def check_path(path: str) -> str:
    if not isinstance(path, str) or not _PATH_OK.fullmatch(path):
        raise BrokerError("path must start with / and use only URL path "
                          "characters", 5)
    if path.startswith("//"):
        raise BrokerError("path may not start with //", 5)
    low = path.lower()
    if (";" in path or "%25" in low or "%00" in low or "%2f" in low or "//" in path
            or "%u" in low or "%c0" in low or "%c1" in low):
        raise BrokerError("path contains an encoding or character that "
                          "servers read differently; refused", 5)
    decoded = path
    for _ in range(4):                       # decode to a fixed point
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    segments = decoded.split("/")
    if ".." in segments or "." in segments[1:-1] or "\\" in decoded or "\x00" in decoded:
        raise BrokerError("path may not contain . or .. segments", 5)
    return path


# query names that turn a harmless GET into an action on some servers
_OVERRIDE_KEYS = {"method", "_method", "$httpmethod", "x-http-method-override",
                  "http_method", "httpmethod"}


def build_url(recipe: dict, path: str, query: dict | None) -> tuple[str, str]:
    host = allowed_host(recipe)
    auth = (recipe.get("validate") or {}).get("auth", {})
    query = dict(query or {})
    if auth.get("type") == "query" and auth.get("param") in query:
        raise BrokerError("the credential parameter is set by the broker", 5)
    if len(query) > 50:
        raise BrokerError("too many query parameters", 5)
    for k, v in query.items():
        if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
            raise BrokerError("query values must be plain text or numbers", 5)
        if k.strip().lower() in _OVERRIDE_KEYS:
            raise BrokerError(f"query parameter '{k}' can change what a GET "
                              "does on some servers; refused", 5)
        if auth.get("type") == "query" and k.strip().lower() == str(auth.get("param", "")).lower():
            raise BrokerError("the credential parameter is set by the broker", 5)
    q = urllib.parse.urlencode(query)
    url = f"https://{host}{check_path(path)}" + (f"?{q}" if q else "")
    if urllib.parse.urlsplit(url).hostname != host:       # belt and braces
        raise BrokerError("host mismatch; refused", 5)
    return host, url


NO_APPROVAL = ("The person did not approve this (or no approval window could "
               "be shown). Do not retry; tell the person to allow it, then ask "
               "again.")


def describe(recipe: dict, method: str, host: str, url: str, data) -> str:
    """What the person is asked to approve. Shows everything that matters."""
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    text = f"{method} https://{host}{parts.path}"
    if q:
        for k, v in q:
            if len(k) > MAX_QUERY_PART or len(v) > MAX_QUERY_PART:
                raise BrokerError(TOO_LONG, 5)      # never show a cut-off value
        text += "  query: " + ", ".join(f"{_clean(k, 999)!r}={_clean(v, 999)!r}"
                                         for k, v in q)
    if data:
        if len(data) > MAX_BODY_SHOWN:
            raise BrokerError(TOO_LONG, 5)          # never show a cut-off body
        text += (f"  body: {len(data)} bytes, sha256 "
                 f"{hashlib.sha256(data).hexdigest()[:12]}, text: "
                 f"{data.decode('utf-8', 'replace')!r}")
    return f"Using your '{recipe['service']}' key:  " + text


def credentials(recipe: dict, values: dict):
    from .recipes import fields
    flds = fields(recipe)
    if len(flds) == 1:
        return values[flds[0]["env_var"]]
    return {f["name"]: values[f["env_var"]] for f in flds}


def call(recipe: dict, values: dict, method: str, path: str,
         query: dict | None = None, body=None, policy: Policy | None = None,
         audit=None, send=None, resolver=None, timeout: float = 20.0,
         max_chars: int | None = None) -> dict:
    """One brokered API call. `values` = {env_var: key}. Returns a dict that
    is safe to hand to an AI: status, a few headers, the (scrubbed) body."""
    policy = policy or Policy()
    method = str(method).upper()
    if method not in READ_METHODS | WRITE_METHODS:
        _log(audit, recipe, values, method, "?", _clean(path), 0, 0, "refused")
        raise BrokerError("method not supported", 5)
    policy.count()          # every attempt counts, refused ones included
    try:
        host, url = build_url(recipe, path, query)
        policy.gate(recipe["service"], method, path)
    except BrokerError:
        _log(audit, recipe, values, method, "?", _clean(path), 0, 0, "refused")
        raise
    auth_type = (recipe.get("validate") or {}).get("auth", {}).get("type", "bearer")
    if method in WRITE_METHODS and auth_type == "aws_sigv4":
        raise BrokerError("this service signs requests; only reads are "
                          "supported through the broker", 5)
    if auth_type == "aws_sigv4":
        try:
            check_sigv4_action(recipe, url)
        except BrokerError:
            _log(audit, recipe, values, method, host, _clean(path), 0, 0, "refused")
            raise

    data = None
    if body is not None:
        if method in READ_METHODS:
            _log(audit, recipe, values, method, host, path, 0, 0, "refused")
            raise BrokerError("GET/HEAD may not have a body", 5)
        if isinstance(body, bytes):
            data = body
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = json.dumps(body).encode()
        if len(data) > MAX_BODY_IN:
            _log(audit, recipe, values, method, host, path, 0, 0, "refused")
            raise BrokerError("request body too large", 5)

    # permission: writes need a grant or a person's yes
    with policy.lock:
        if method in WRITE_METHODS and not policy.allow_write:
            try:
                summary = describe(recipe, method, host, url, data)
            except BrokerError:
                _log(audit, recipe, values, method, host, path, 0, 0, "refused")
                raise
            if len(summary) > MAX_REVIEW:
                _log(audit, recipe, values, method, host, path, 0, 0, "refused")
                raise BrokerError(TOO_LONG, 5)
            if not policy.ask(summary):
                _log(audit, recipe, values, method, host, path, 0, 0, "denied")
                raise BrokerError(NO_APPROVAL, 5)
        elif (recipe["service"], host) not in policy.approved_hosts:
            if policy.approve is not None:
                if not policy.ask(f"First use of '{recipe['service']}' "
                                  f"(talks to {host}). Read-only requests will "
                                  "then be allowed this session."):
                    _log(audit, recipe, values, method, host, path, 0, 0, "denied")
                    raise BrokerError(NO_APPROVAL, 5)
            policy.approved_hosts.add((recipe["service"], host))

    if audit is not None:
        audit.ready()
    creds = credentials(recipe, values)
    spec = dict(recipe["validate"])
    spec["url"] = url
    token = None
    if auth_type == "oauth2_client_credentials":
        try:
            th = urllib.parse.urlsplit(str(spec["auth"].get("token_url", "")))
            if th.scheme != "https" or not th.hostname:
                raise BrokerError("the token address must be https", 5)
            resolve_public(th.hostname, th.port or 443, resolver)
            token = _v._fetch_token(spec, _v._creds(creds), timeout, no_proxy=True)
        except BrokerError:
            _log(audit, recipe, values, method, host, path, 0, 0, "refused")
            raise
        except _v.ValidationError as e:
            _log(audit, recipe, values, method, host, path, 0, 0, "network-error")
            # validate.validate_key scrubs its own errors, but this calls
            # _fetch_token directly, so do it here: a BrokerError reaches the
            # AI, and its text must never hold the key (see BrokerError).
            why = Scrubber([v for v in values.values()
                            if isinstance(v, str)]).text(str(e))
            raise BrokerError(f"could not get a sign-in token: {why}", 5) from None
    req = _v._build_request(spec, creds, token)       # builds GET + credential
    req.method = method
    if data is not None:
        req.data = data
        req.add_header("Content-Type", "application/json")
    try:
        ip = resolve_public(host, 443, resolver)
    except BrokerError:
        _log(audit, recipe, values, method, host, path, 0, 0, "refused")
        raise

    started = time.time()
    try:
        status, headers, raw = (send or _real_send)(req, ip, timeout)
    except BrokerError:
        _log(audit, recipe, values, method, host, path, 0, 0, "network-error")
        raise

    from .caps import tokens_in
    policy.add_tokens(recipe["service"], tokens_in(headers.get("content-type", ""), raw))
    secrets = [v for v in values.values() if isinstance(v, str)]
    if token:
        secrets.append(token)           # the OAuth token we minted is a secret too
    sc = Scrubber(secrets)
    ctype = headers.get("content-type", "")
    textual = any(t in ctype for t in ("json", "text", "xml", "html", "x-www-form"))
    if textual and headers.get("content-encoding", "").lower() not in ("", "identity"):
        shown = "[response is compressed; not shown]"
    elif textual:
        # scrub everything we read, then clip (a key at the cut line is caught)
        whole = (sc.feed(raw) + sc.flush())
        if loosely_contains(whole.decode("utf-8", "replace"), secrets):
            shown = "[response withheld: it appears to contain the key in a disguised form]"
        else:
            shown = whole[:MAX_BODY_OUT].decode("utf-8", "replace")
    else:
        shown = f"[binary {len(raw)} bytes sha256 {hashlib.sha256(raw).hexdigest()[:16]}]"
    cut = False
    if max_chars is not None and len(shown) > max_chars:   # after the full scrub
        room = max_chars - len(CUT_NOTE)
        shown = shown[:room] + CUT_NOTE if room > 0 else shown[:max_chars]
        cut = True
    keep = {}
    for k in _EXPOSED_HEADERS:
        if k in headers:
            hs = Scrubber(secrets)
            val = (hs.feed(headers[k].encode()) + hs.flush()).decode("utf-8", "replace")
            if loosely_contains(val, secrets):
                val = "[header withheld: it appears to contain the key in a disguised form]"
            keep[k] = val
    _log(audit, recipe, values, method, host, path, status, len(raw), "ok",
         ms=int((time.time() - started) * 1000))
    return {"status": status, "headers": keep, "body": shown,
            "truncated": cut or len(raw) > MAX_BODY_OUT}


# ---- audit log (hash chained) -------------------------------------------------

def _log(audit, recipe, values, method, host, path, status, size, result, ms=0):
    if audit is None:
        return
    # The path is scrubbed like everything else that leaves this module. Query
    # strings and bodies are excluded from the log and headers are scrubbed, so
    # the path was the one field a secret could ride into ~/.stuntkey/audit.log
    # on -- e.g. GET /user/<token> after a key leaked into a file the agent read,
    # which is exactly the case `stuntkey scan` exists for. Writing it there put
    # the secret in a NEW persistent place that owners are told to open and share
    # when investigating an incident.
    safe_path = _clean(path.split("?")[0], 200)
    try:
        secrets = [v for v in (values or {}).values() if isinstance(v, str) and v]
        if secrets:
            # Same two layers the response body gets: remove the known forms,
            # and withhold entirely if a disguised form is still in there.
            safe_path = scrub_text(safe_path, secrets)
            if loosely_contains(safe_path, secrets):
                safe_path = "[path withheld]"
    except Exception:
        safe_path = "[path withheld]"   # a scrubbing failure must never log the raw path
    try:
        audit.write({"service": recipe.get("service"), "method": method,
                     "host": host, "path": safe_path, "status": status,
                     "bytes": size, "result": result, "ms": ms})
    except (OSError, BrokerError):
        pass            # ready() already refused to act when the log is unwritable or busy


LOCK_WAIT = 30.0      # seconds a writer waits for the log before giving up
BUSY_TEXT = ("The activity log is busy (another StuntKey program is writing to "
             "it right now). Wait a few seconds and try again")


def _lock_pause(attempt: int) -> float:
    """Seconds to wait before the next try: short at first, growing to a quarter
    second, with a little jitter so waiting writers do not move in step."""
    import random
    return min(0.01 * (1.5 ** attempt), 0.25) * (0.5 + random.random() / 2)


@contextlib.contextmanager
def _file_lock(path: str, timeout: float | None = None):
    """One writer at a time across processes (MCP + serve + call may all run).
    Yields True when the lock is held; callers fail closed when it is not.
    Waits up to LOCK_WAIT seconds (backing off) before giving up."""
    fd = None
    locked = False
    deadline = time.monotonic() + (LOCK_WAIT if timeout is None else timeout)
    try:
        fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        attempt = 0
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(_lock_pause(attempt))
                attempt += 1
    except OSError:
        pass
    try:
        yield locked
    finally:
        if fd is not None:
            try:
                if locked and os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            os.close(fd)


_BAD = object()      # an end-marker file that exists but cannot be read

UNKEYED_NOTE = ("This log is not signed with a secret key on this computer "
                "(the keychain could not keep one). It still catches mistakes "
                "and clumsy edits, but not someone who rewrites the whole log.")


LOST_KEY_WHY = ("the signing key was lost (it was kept in the keychain), so the "
                "older entries can no longer be checked - this is not the same "
                "as someone changing them. Run `stuntkey audit reset` to start "
                "a new log; the old one is kept beside it")

NO_KEY_YET_NOTE = ("The entries so far were written before log signing existed. "
                   "The signing key will be created with the next entry "
                   "(`stuntkey doctor` can create it now).")

TAIL_BYTES = 65536            # how much of the end of the log a write re-checks
MAX_GAP_BYTES = 8 * 1024 * 1024
_ROTATED = re.compile(r"\.(\d{4}-\d{2})(-\d+)?$")


OLDER_ENTRIES_NOTE = ("The entries so far were written before log signing existed, so they are "
                      "not signed. The signing key is ready: every new entry will be signed.")


def _test_redirect(path: str) -> str:
    """While STUNTKEY_KEYCHAIN names a test keychain, the log that would sit in
    the real ~/.stuntkey goes to the test folder (file:<folder>) or to a
    scratch folder in the system temp folder (memory): a test or trial must
    never write to the real activity log."""
    from . import keychain, remote
    try:
        test = keychain.test_backend()
        if not test:
            return path
        here = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(path))))
        if here != os.path.normcase(os.path.realpath(remote.home_dir())):
            return path
    except (keychain.KeychainError, OSError):
        return path
    if test.startswith(keychain.TEST_FILE):
        folder = test[len(keychain.TEST_FILE):]
    else:
        folder = os.path.join(tempfile.gettempdir(), "stuntkey-test-activity")
    return os.path.join(folder, os.path.basename(path))


class AuditLog:
    """Append-only JSON lines; each line holds the hash of the line before.
    Change or remove any line and verify() says so. Never records query
    strings, bodies or headers.

    The chain is keyed: each hash is an HMAC-SHA256 made with a random secret
    kept in the OS keychain (a file beside the log for a log kept anywhere but
    ~/.stuntkey), so rewriting the whole log needs that secret. Entries from
    before the key existed (plain SHA-256) still verify; a marker line says
    where the signed part starts. When no key can be kept, the log is written
    plain with a CHAIN-UNKEYED marker and verify says "unkeyed" - never
    silently.

    A second small file (.head) remembers how many entries there should be
    and the last hash (signed too), so cutting off the end or deleting the log
    shows. Once a problem is seen, a flag file (.broken) is written and stays
    until the person runs `stuntkey audit reset`; later writes never lower the
    count and never make the log look healthy again. Deleting the flag shows
    too: the problem line stays in the chain."""

    def __init__(self, path: str):
        self.path = _test_redirect(path)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)

    _lock = threading.Lock()

    # The log must be a real file, never a link.
    #
    # os.open(O_WRONLY|O_APPEND|O_CREAT) FOLLOWS a symlink, so anything able to
    # write one file in ~/.stuntkey could point the log at /dev/null before the
    # first call. An empty log yields n=0, no anchor is expected, and verify()
    # returns (True, 0) -- it cannot tell "this log is a sink" from "this log is
    # fine", which defeats "every call goes to a hash-chained append-only log".
    # On Windows a JUNCTION (or any reparse point) on the folder does the same
    # and os.path.islink() does not see it: store.private_path_problem looks for
    # links, junctions and reparse points on the file and its folder, and checks
    # the real location with realpath. O_NOFOLLOW closes the check-to-open race
    # where the platform has it.
    _OPEN_FLAGS = (os.O_WRONLY | os.O_APPEND | os.O_CREAT
                   | getattr(os, "O_NOFOLLOW", 0))

    def _open_for_append(self) -> int:
        from . import store as store_mod
        problem = store_mod.private_path_problem(self.path)
        if problem:
            raise BrokerError("The activity log cannot be trusted "
                              f"({problem}), so nothing was sent. "
                              "Remove the link and try again.", 5)
        return os.open(self.path, self._OPEN_FLAGS, 0o600)

    @property
    def anchor_path(self) -> str:
        return self.path + ".head"

    @property
    def broken_path(self) -> str:
        return self.path + ".broken"

    def ready(self) -> None:
        """Refuse to act if we could not record it afterwards."""
        try:
            fd = self._open_for_append()
            os.close(fd)
        except OSError:
            raise BrokerError("The activity log cannot be written, so "
                              "nothing was sent.", 5) from None
        with _file_lock(self.path) as got:
            if not got:
                raise BrokerError(BUSY_TEXT + ", so nothing was sent.", 5)

    # ---- the signing key

    def _key_info(self, create: bool = False):
        """(key or None, where): where is "keychain" or "file" when that place
        can be reached (key None then means "none made yet"), "unavailable"
        when it cannot. The key lives in the keychain only for a log in the
        folder this program uses as its home (~/.stuntkey); a log anywhere
        else, or seen from a program run with another HOME, uses a key file
        beside the log - so a different HOME sees a different (or no) key."""
        from . import keychain
        return keychain.integrity_key(
            os.path.dirname(os.path.abspath(self.path)), create=create)

    def _key(self, create: bool = False):
        return self._key_info(create)[0]

    def key_state(self) -> str:
        """"present", "none_yet" (the keychain works; the key will be made with
        the next entry) or "unavailable" (no key can be kept here)."""
        try:
            key, where = self._key_info()
        except Exception:
            return "unavailable"
        if key is not None:
            return "present"
        return "none_yet" if where in ("keychain", "file") else "unavailable"

    def ensure_key(self) -> dict:
        """Make the signing key now (best effort, never raises). Call it from
        `install` / `doctor` so a log that has not been written since signing
        began does not look unsigned. Returns {"state": "ready" (already
        there) | "created" | "unavailable" | "busy", "where": ...,
        "note": plain words}. An older unsigned log gets its CHAIN-NOW-SIGNED
        marker here, exactly as a first write would add it."""
        try:
            with AuditLog._lock, _file_lock(self.path, timeout=5.0) as got:
                if not got:
                    return {"state": "busy", "where": "", "note": BUSY_TEXT + "."}
                key, where = self._key_info()
                if key is not None:
                    return {"state": "ready", "where": where, "note": "The signing key is in place."}
                key, where = self._key_info(create=True)
                if key is None:
                    return {"state": "unavailable", "where": where, "note": UNKEYED_NOTE}
                s = self._scan_full(key)
                a = self._read_anchor()
                if (s["n"] > 0 and s["keyed_n"] == 0 and self.broken_reason() is None
                        and self._problem(s, a, key, migrating=True) is None):
                    last = self._append(self._marker(
                        "CHAIN-NOW-SIGNED",
                        "lines from here on are signed with a secret key; "
                        "older lines were not"), s["last"], key)
                    self._save_anchor(s["n"] + 1, last, key)
                return {"state": "created", "where": where,
                        "note": "A signing key was created for the activity log."}
        except (OSError, BrokerError, ValueError):
            return {"state": "unavailable", "where": "", "note": UNKEYED_NOTE}

    def _digest(self, entry: dict, key: bytes | None = None) -> str:
        data = json.dumps(entry, sort_keys=True).encode()
        if entry.get("k") == 1:
            if key is None:
                raise ValueError("signed entry, no key")
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _mac(key: bytes, count: int, h: str) -> str:
        return hmac.new(key, f"{count} {h}".encode(), hashlib.sha256).hexdigest()

    # ---- reading

    def _missing_key_why(self) -> str:
        try:
            where = self._key_info()[1]
        except Exception:
            where = "unavailable"
        if where == "file":
            return ("this log is signed, but the signing key is not in this "
                    "program's key folder (it was signed under a different "
                    "home folder, or the key file was lost)")
        return LOST_KEY_WHY

    def _scan_full(self, key: bytes | None, path: str | None = None) -> dict:
        """Read and check every line (slow on a big log: used by `audit
        verify`, the first write, and whenever the quick tail check cannot
        vouch for the end)."""
        s = {"n": 0, "last": "0" * 64, "ok": True, "exists": False,
             "anchored": False, "keyed_n": 0, "problem_seen": False,
             "unkeyed_marked": False, "why": None, "keyed_seen": False,
             "link": None, "rotated_file": None, "last_ts": None}
        try:
            with open(path or self.path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return s
        except OSError:
            s.update(ok=False, exists=True)
            return s
        s["exists"] = True
        lines = data.splitlines()
        if data and not data.endswith(b"\n") and lines:
            lines = lines[:-1]           # a write in progress: not a problem yet
        prev, n = s["last"], 0
        for line in lines:
            try:
                e = json.loads(line)
                h = e.pop("hash")
                keyed = e.get("k") == 1
                if keyed:
                    s["keyed_seen"] = True
                if (n == 0 and keyed and key is not None
                        and e.get("result") == "LOG-ROTATED"
                        and isinstance(e.get("prev"), str)):
                    # a monthly log starts by pointing at the last line of the
                    # one before it; the signature covers that pointer
                    prev = e["prev"]
                    s["link"] = prev
                    s["rotated_file"] = e.get("rotated_file")
                if keyed and key is None:
                    s["why"] = self._missing_key_why()
                    good = False
                elif not keyed and s["keyed_n"] > 0:
                    s["why"] = "a signed line is followed by an unsigned one"
                    good = False
                else:
                    good = e.get("prev") == prev and h == self._digest(e, key)
                if n == 0:
                    s["anchored"] = e.get("anchored") is True
                if good:
                    s["last_ts"] = e.get("ts") if isinstance(e.get("ts"), int) else None
                    s["keyed_n"] += 1 if keyed else 0
                    if e.get("result") == "LOG-PROBLEM-FOUND":
                        s["problem_seen"] = True
                    if e.get("result") == "CHAIN-UNKEYED":
                        s["unkeyed_marked"] = True
            except (ValueError, KeyError, TypeError, AttributeError):
                good = False
            if not good:
                s.update(n=n, last=prev, ok=False)
                return s
            prev, n = h, n + 1
        s.update(n=n, last=prev)
        return s

    def _scan_tail(self, key: bytes | None, a):
        """The log's state from the signed end-marker plus only the END of the
        file, or None when that cannot vouch for it (the caller then reads the
        whole log). Finds the line the end-marker names in the last
        TAIL_BYTES, checks every line from there to the end chains and is
        signed, and counts them. Cutting the end off, replacing the last lines
        or rewinding the marker all make the named line vanish or the chain
        break, so None comes back and the full check decides. A change in the
        MIDDLE of a long log is found by `audit verify`, not by each write."""
        if key is None or a is None or a is _BAD or a[2] is None:
            return None
        count, want, mac = a
        if not hmac.compare_digest(mac, self._mac(key, count, want)):
            return None
        try:
            total = os.path.getsize(self.path)
            start = max(0, total - TAIL_BYTES)
            with open(self.path, "rb") as f:
                f.seek(start)
                data = f.read()
        except OSError:
            return None
        if not data.endswith(b"\n"):
            data = data[:data.rfind(b"\n") + 1]      # a write in progress
        lines = data.split(b"\n")[:-1]
        pos = start
        if start > 0 and lines:
            pos += len(lines[0]) + 1
            lines = lines[1:]                          # the first may be cut in half
        prev, found, after, last_ts = None, False, 0, None
        for line in lines:
            at, pos = pos, pos + len(line) + 1
            try:
                e = json.loads(line)
                h = e.pop("hash")
                if e.get("k") != 1 or h != self._digest(e, key):
                    return None
                if prev is not None and e.get("prev") != prev:
                    return None
                if e.get("result") == "LOG-PROBLEM-FOUND":
                    return None
                if "off" in e and e["off"] != at:
                    return None                        # something was cut out before here
                if h == want and "off" not in e:
                    return None                        # written before offsets: read it all once
            except (ValueError, KeyError, TypeError, AttributeError):
                return None
            prev = h
            last_ts = e.get("ts") if isinstance(e.get("ts"), int) else None
            if found:
                after += 1
            elif h == want:
                found = True
        if not found or len(data) > MAX_GAP_BYTES:
            return None
        return {"n": count + after, "last": prev, "ok": True, "exists": True,
                "anchored": True, "keyed_n": 1, "problem_seen": False,
                "unkeyed_marked": False, "why": None, "keyed_seen": True,
                "link": None, "rotated_file": None, "last_ts": last_ts}

    def _scan(self):
        """(entries, last good hash, chain intact, file exists, first entry
        says an end-marker file should exist)."""
        s = self._scan_full(self._key())
        return s["n"], s["last"], s["ok"], s["exists"], s["anchored"]

    def _last_hash(self) -> str:
        return self._scan()[1]

    def _count(self) -> int:
        return self._scan()[0]

    def _read_anchor(self):
        """None = no marker file; _BAD = unreadable; else (count, hash, mac|None)."""
        try:
            with open(self.anchor_path, encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            return None
        except OSError:
            return _BAD
        try:
            parts = text.split()
            if len(parts) == 2:
                return int(parts[0]), parts[1], None
            count, h, mac = parts
            return int(count), h, mac
        except ValueError:
            return _BAD

    def _save_anchor(self, count: int, h: str, key: bytes | None = None) -> None:
        tmp = self.anchor_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(f"{count} {h}" + (f" {self._mac(key, count, h)}" if key else "") + "\n")
            os.replace(tmp, self.anchor_path)
        except OSError:
            pass

    def _problem(self, s: dict, a, key: bytes | None, migrating: bool = False):
        if not s["ok"]:
            return s["why"] or "a line was changed, removed or damaged"
        if a is _BAD:
            return "the end-marker file is unreadable"
        n, last = s["n"], s["last"]
        if key is not None and n > 0 and s["keyed_n"] == 0 and not migrating:
            return "the log was rewritten without its secret signature"
        if a is None and n > 0 and (s["anchored"] or s["keyed_n"] > 0):
            return "the end-marker file was deleted"
        if a is not None:
            if a[2] is not None:
                if key is None:
                    return "the end-marker file is signed but the secret key is missing"
                if not hmac.compare_digest(a[2], self._mac(key, a[0], a[1])):
                    return "the end-marker file was changed"
            elif key is not None and s["keyed_n"] > 0:
                return "the end-marker file lost its signature"
            if n < a[0] or (n == a[0] and last != a[1]):
                return "entries were cut off or replaced"
        return None

    def broken_reason(self):
        try:
            with open(self.broken_path, encoding="utf-8") as f:
                return f.read().strip() or "a problem was found earlier"
        except FileNotFoundError:
            return None
        except OSError:
            return "a problem was found earlier"

    # ---- writing

    def _append(self, entry: dict, prev: str, key: bytes | None = None,
                first: bool = False) -> str:
        entry = dict(entry, ts=int(time.time()), prev=prev)
        if first:
            entry["anchored"] = True       # this log has a .head file
        fd = self._open_for_append()
        try:
            if key is not None:
                entry["k"] = 1
                # where in the file this line starts (signed with the line): a
                # write checks it on the last lines it re-reads, so a line cut
                # out of the front or middle of a long log shifts it and shows
                entry["off"] = os.fstat(fd).st_size
            entry["hash"] = self._digest({k: v for k, v in entry.items() if k != "hash"}, key)
            os.write(fd, (json.dumps(entry, sort_keys=True) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return entry["hash"]

    @staticmethod
    def _marker(result: str, note: str) -> dict:
        return {"service": None, "method": "-", "host": "-", "path": "-",
                "status": 0, "bytes": 0, "ms": 0, "result": result, "note": note}

    def _rotate_if_due(self, s: dict, key: bytes):
        """On the first write of a new month, move last month's log aside
        (audit.log.YYYY-MM) and start a new file whose first line is a signed
        LOG-ROTATED marker pointing at the last hash of the old file, so the
        pieces still verify as one chain. Returns (1, marker hash) when it
        rotated, else None. Never loses the old file: any failure puts it back."""
        ts = s.get("last_ts")
        if not isinstance(ts, int) or s["n"] == 0:
            return None
        old_month = time.strftime("%Y-%m", time.gmtime(ts))
        if old_month == time.strftime("%Y-%m", time.gmtime(time.time())):
            return None
        base = f"{self.path}.{old_month}"
        target, i = base, 1
        while os.path.exists(target):
            i += 1
            target = f"{base}-{i}"
        try:
            os.replace(self.path, target)
        except OSError:
            return None                  # in use right now: try again next write
        marker = self._marker("LOG-ROTATED", "a new monthly log starts here; "
                              "the lines before it are in the file named in rotated_file")
        marker.update(rotated_file=os.path.basename(target), rotated_entries=s["n"])
        try:
            h = self._append(marker, s["last"], key, first=True)
        except (OSError, BrokerError):
            try:
                if os.path.exists(self.path):
                    os.remove(self.path)
                os.replace(target, self.path)
            except OSError:
                pass
            return None
        self._save_anchor(1, h, key)
        return 1, h

    def write(self, entry: dict) -> None:
        with AuditLog._lock, _file_lock(self.path) as got:   # one writer at a time
            if not got:
                raise BrokerError(BUSY_TEXT + ".", 5)
            key0 = self._key()
            fresh = key0 is None                 # no key yet: this write starts signing
            a = self._read_anchor()
            s = None
            if not fresh and self.broken_reason() is None:
                s = self._scan_tail(key0, a)     # quick: only the end of the log
            lost = False
            if fresh:
                try:                              # a signed log but no key at all: lost
                    lost = self._scan_full(None)["keyed_seen"]
                except Exception:
                    lost = False
            key = key0 if s is not None else self._key(create=True)
            if s is None:
                s = self._scan_full(key)
                a = self._read_anchor()
            reason = self._problem(s, a, key, migrating=fresh)
            if lost and reason:
                reason = LOST_KEY_WHY
            if (reason is None and s["problem_seen"]
                    and self.broken_reason() is None):
                reason = "the problem flag was deleted"
            n, last = s["n"], s["last"]
            flagged = self.broken_reason() is not None
            if (reason is None and not flagged and key is not None
                    and not fresh and s["keyed_n"] > 0):
                rotated = self._rotate_if_due(s, key)
                if rotated:
                    n, last = rotated
            if reason and not flagged:
                try:
                    with open(self.broken_path, "w", encoding="utf-8") as f:
                        f.write(reason + "\n")
                except OSError:
                    pass
                last = self._append(self._marker("LOG-PROBLEM-FOUND", reason),
                                    last, key, first=(n == 0))
                n += 1
                flagged = True
            if not flagged:
                if key is not None and s["keyed_n"] == 0 and n > 0:
                    last = self._append(self._marker(
                        "CHAIN-NOW-SIGNED",
                        "lines from here on are signed with a secret key; "
                        "older lines were not"), last, key)
                    n += 1
                elif key is None and not s["unkeyed_marked"]:
                    last = self._append(self._marker(
                        "CHAIN-UNKEYED", UNKEYED_NOTE), last, None, first=(n == 0))
                    n += 1
            h = self._append(entry, last, key, first=(n == 0))
            if not flagged:
                self._save_anchor(n + 1, h, key)     # a flagged log never re-anchors

    # ---- checking

    def verify_detail(self) -> dict:
        """{"ok", "n", "mode": "signed"|"unkeyed", "reason", "note"}."""
        key = self._key()
        a = self._read_anchor()                  # read first: a write landing
        s = self._scan_full(key)                 # in between can only add entries
        mode = "signed" if (s["keyed_n"] > 0 or (key is not None and s["n"] == 0)) else "unkeyed"
        broken = self.broken_reason()
        reason = None
        if broken is not None:
            reason = broken
        else:
            reason = self._problem(s, a, key)
            if reason is None and s["problem_seen"]:
                reason = "the problem flag was deleted"
        rotated = []
        if reason is None and s["link"] is not None:
            reason, rotated = self._check_rotated(s, key)
        if key is not None:
            note = OLDER_ENTRIES_NOTE
        else:
            note = (NO_KEY_YET_NOTE if (not s["unkeyed_marked"] and self.key_state() == "none_yet")
                    else UNKEYED_NOTE)
        return {"ok": reason is None, "n": s["n"], "mode": mode, "reason": reason,
                "note": note if mode == "unkeyed" else "",
                "key": "present" if key is not None else self.key_state(),
                "rotated_files": rotated}

    def _check_rotated(self, s: dict, key: bytes | None):
        """Follow the signed links back through the monthly files. Returns
        (problem text or None, names of the files that checked out)."""
        folder = os.path.dirname(os.path.abspath(self.path))
        seen, link, name = [], s["link"], s["rotated_file"]
        for _ in range(600):
            if not isinstance(name, str) or not name:
                return "an older monthly log is not named in the chain", seen
            name = os.path.basename(name)
            p = os.path.join(folder, name)
            old = self._scan_full(key, p) if os.path.isfile(p) else None
            if old is None:
                return f"the older monthly log {name} is missing", seen
            if not old["ok"] or old["last"] != link:
                return f"the older monthly log {name} was changed or does not match", seen
            seen.append(name)
            if old["link"] is None:
                return None, seen
            link, name = old["link"], old["rotated_file"]
        return "too many monthly logs to follow", seen

    def rotated_files(self) -> list:
        """Names of the monthly files kept beside the log, oldest first."""
        folder = os.path.dirname(os.path.abspath(self.path))
        base = os.path.basename(self.path)
        try:
            names = os.listdir(folder)
        except OSError:
            return []
        out = [n for n in names if n.startswith(base + ".")
               and _ROTATED.search(n[len(base):]) and not n.endswith((".lock", ".head", ".tmp"))]
        return sorted(out)

    def stats(self) -> dict:
        """{"entries", "bytes", "last_write" (seconds since 1970, or None),
        "rotated_files" (names), "key"} - cheap, nothing is verified. For the
        status command."""
        size, last_write = 0, None
        try:
            st = os.stat(self.path)
            size, last_write = st.st_size, int(st.st_mtime)
        except OSError:
            pass
        entries = None
        a = self._read_anchor()
        if a not in (None, _BAD):
            entries = a[0]                       # kept up to date by every write
        if entries is None or (a not in (None, _BAD) and not os.path.exists(self.path)):
            entries = 0
            try:
                with open(self.path, "rb") as f:
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk:
                            break
                        entries += chunk.count(b"\n")
            except OSError:
                pass
        return {"entries": entries, "bytes": size, "last_write": last_write,
                "rotated_files": self.rotated_files(), "key": self.key_state()}

    def verify(self) -> tuple[bool, int]:
        d = self.verify_detail()
        return d["ok"], d["n"]

    def describe(self) -> str:
        """One plain line for `status` / `audit` to print: empty when the log
        is signed, the 'unkeyed' warning when it is not."""
        d = self.verify_detail()
        return d["note"] if d["n"] else ""      # a brand-new empty log has nothing to warn about

    def reset(self):
        """Start a fresh log. The old one is kept beside it, never deleted."""
        with AuditLog._lock, _file_lock(self.path):
            kept = None
            if os.path.exists(self.path):
                base = f"{self.path}.problem-{int(time.time())}"
                kept, i = base, 1
                while os.path.exists(kept):          # never overwrite an earlier one
                    kept, i = f"{base}-{i}", i + 1
                try:
                    os.replace(self.path, kept)
                except OSError as e:
                    raise BrokerError("could not move the old log aside "
                                      f"({e.strerror or 'in use'}); close other "
                                      "stuntkey programs and try again", 1) from None
            stuck = []
            for p in (self.anchor_path, self.broken_path):
                try:
                    os.remove(p)
                except FileNotFoundError:
                    pass
                except OSError:
                    stuck.append(os.path.basename(p))
            if stuck:
                raise BrokerError("the old log was moved aside but could not "
                                  f"remove {', '.join(stuck)}; remove it by hand", 1)
            return kept
