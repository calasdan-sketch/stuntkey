"""`stuntkey proxy -- <command>`: run a program that talks to AI APIs through
the broker, without ever giving it a key.

The program gets base-URL variables pointing at a loopback server
(OPENAI_BASE_URL=http://127.0.0.1:P/openai/v1, ...) and *_API_KEY set to a
random session token. That token is only the proxy's password; the real key
is added by the proxy and never enters the program's environment. There is
no TLS interception: the program speaks plain HTTP to 127.0.0.1, the proxy
speaks HTTPS to the recipe's own host.

Per request: /<service>/<path> picks the recipe (the host comes from the
recipe); the route policy, kill switch and caps are checked; POST and other
writes go only to the usual LLM endpoints unless stuntkey.policy allows more;
the client's
own credential headers are dropped and only a short list of headers passes
either way; the answer is streamed back through the Scrubber; one line goes
to the activity log. If the proxy dies, the program's calls fail (its base
URL points at a closed port): fail closed.

WHEN THE PERSON IS ASKED (round 12; this closes the hole where the proxy
returned `GET /github/user` with the real key and no question, bypassing the
MCP "first use" window and the "3 refusals" stop):
  * AI-model calls stay prompt-free, as documented: the usual POST endpoints
    (SAFE_WRITES: chat, responses, messages, embeddings) and reading the model
    list (MODEL_READS). A consent window cannot show a long prompt, and these
    are the whole point of the proxy.
  * Everything else is NOT prompt-free:
      - the first READ (GET/HEAD) to any other path of a service asks ONCE per
        service+host, like the MCP path ("First use of ..."). A yes is
        remembered for this proxy run only (Policy.approved_hosts, in memory,
        never written to disk), and covers reads only;
      - a WRITE to any other path (only possible when a policy file allows it)
        asks for EVERY request and shows the body, like the MCP path.
  * Asking goes through Policy.ask, so the same stop applies: after 3 refusals
    no more windows open and every such request is refused for the rest of
    the run. With no way to ask (no window, STUNTKEY_NO_WINDOW=1) the answer is
    NO. A refusal does not spend any cap.
  * The first-time host and every refusal leave a plain line in the notices
    file (caps.notice) that `stuntkey caps show` prints.

What the program gets in its environment: an ALLOW-LIST (see ALLOW_ENV), not a
copy of yours. PATH, Windows system folders, home and temp folders, language
and terminal settings, Python/Node basics and certificate-file settings pass;
every other name stays behind, and a secret-looking name (*_TOKEN, *_KEY,
*_SECRET, *_PASSWORD, AWS_*, GITHUB_*, ...) passes only if a person names it
with `--keep-env NAME` (function: keep_names / child_env(keep=...)) or
STUNTKEY_KEEP_ENV. A key for a brokered service never passes, named or not.

What is and is not covered (honest list):
  * Covered, no key in the program: any program that can be pointed at a plain
    http://127.0.0.1 base URL. The four SDKs with known variables get them
    automatically; `--map NAME=service[/path]` does it for any other program
    that reads its address from a variable; `--generic` hands out a placeholder
    key plus STUNTKEY_URL_<SERVICE> for every carryable service. The proxy swaps
    the placeholder for the real key, only for that service's own host, and the
    route policy, kill switch and spending caps apply to every call.
  * Not covered: a program that talks HTTPS straight to a vendor with its own
    key. That needs a stuntkey-made certificate installed on your machine (a
    man-in-the-middle), which is a bigger risk than the problem; it is
    deliberately NOT built. `--tunnel` / `--allow-host` set HTTPS_PROXY to a
    tunnel that connects only to a fixed host list (the AI services plus hosts
    you add) and refuses everything else, which limits where a program that
    honours HTTPS_PROXY can send things; it cannot add a key, scrub, or count
    tokens inside the encrypted stream (each tunnel counts as one call against
    the call caps). A program that ignores HTTPS_PROXY is not stopped by it.
"""
from __future__ import annotations

import base64
import contextlib
import hmac
import http.client
import json
import os
import re
import secrets
import selectors
import socket
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler

from . import broker, caps, httpd
from . import policy as route
from . import recipes as recipes_mod
from . import validate as _v
from .scrub import Scrubber, loosely_contains

# SDK base-URL variables checked against each official SDK's _client.py
# (openai-python, anthropic-sdk-python, groq-python, together-py), with the
# suffix that makes the SDK's own paths land on the recipe host's paths.
# Other recipes (openrouter, mistral, ...) still work at /<service>/... with
# --print-env, but no base-URL variable is set for them.
ENV = {"openai": ("OPENAI_BASE_URL", "/openai/v1"),
       "anthropic": ("ANTHROPIC_BASE_URL", "/anthropic"),
       "groq": ("GROQ_BASE_URL", "/groq"),
       "together": ("TOGETHER_BASE_URL", "/together")}
EXTRA_DROP = ("ANTHROPIC_AUTH_TOKEN",)     # makes the Anthropic SDK send its own Bearer

SAFE_WRITES = {"/v1/chat/completions", "/v1/completions", "/v1/responses",
               "/v1/messages", "/v1/messages/count_tokens", "/v1/embeddings",
               "/openai/v1/chat/completions", "/openai/v1/embeddings",
               "/api/v1/chat/completions"}
# reading the list of AI models is also prompt-free (the SDKs do it on start)
MODEL_READS = ("/v1/models", "/openai/v1/models", "/api/v1/models")
REQ_HEADERS = {"content-type", "accept", "anthropic-version", "anthropic-beta",
               "openai-beta", "idempotency-key"}
RESP_HEADERS = {"content-type", "retry-after", "request-id", "x-request-id"}
RESP_PREFIXES = ("x-ratelimit-", "anthropic-ratelimit-")
NO_PROXY_AUTH = {"oauth2_client_credentials", "aws_sigv4"}
MAX_BODY = 16_000_000          # a long chat history; nobody reviews it
MAX_CALLS = 5_000              # per run; per-key caps (caps.py defaults) are tighter
PER_MINUTE = 300
TUNNEL_IDLE = 300.0            # a tunnel with no bytes either way this long is closed
TUNNEL_SEND_TIMEOUT = 30.0     # one stuck write (peer not reading) cannot hold a thread
TUNNEL_MAX_SECONDS = 3600.0    # no tunnel lives longer than an hour
UPSTREAM_TIMEOUT = 300.0       # long model answers


# ---- the environment an AI-run program gets ---------------------------------------
#
# ALLOW-LIST, not block-list. The program starts with ONLY the names below
# (plus the proxy settings stuntkey itself sets, plus anything the person adds
# with STUNTKEY_KEEP_ENV or `--keep-env NAME`). Everything else in the parent
# environment is left behind, so a token the parent happens to hold
# (GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY, NPM_TOKEN, DATABASE_PASSWORD, ...) never
# reaches the program by accident. A name that looks secret (*_TOKEN, *_KEY,
# *_SECRET, *_PASSWORD, AWS_*, GITHUB_*, ...) passes only when the person names
# it exactly. A key for a service stuntkey brokers never passes at all (the
# program gets the proxy's session password in its place). Allowed names whose
# VALUE holds a stored key or a text in a known key format are dropped too.
#
# Common developer tools keep working: git, python, pip, node and npm need
# PATH, the Windows system folders, HOME/USERPROFILE/APPDATA and temp folders,
# which are all on the list.
ALLOW_ENV = frozenset("""
PATH PATHEXT SYSTEMROOT SYSTEMDRIVE WINDIR COMSPEC OS
TEMP TMP TMPDIR HOME HOMEDRIVE HOMEPATH USERPROFILE APPDATA LOCALAPPDATA
PROGRAMDATA PROGRAMFILES PROGRAMFILES(X86) PROGRAMW6432
COMMONPROGRAMFILES COMMONPROGRAMFILES(X86) COMMONPROGRAMW6432
ALLUSERSPROFILE PUBLIC USERNAME USERDOMAIN COMPUTERNAME USER LOGNAME
PROCESSOR_ARCHITECTURE PROCESSOR_IDENTIFIER PROCESSOR_LEVEL PROCESSOR_REVISION
NUMBER_OF_PROCESSORS DRIVERDATA
LANG LANGUAGE LC_ALL LC_CTYPE LC_MESSAGES LC_COLLATE LC_TIME LC_NUMERIC LC_MONETARY
TERM COLORTERM NO_COLOR FORCE_COLOR SHELL PWD TZ
PYTHONIOENCODING PYTHONUTF8 PYTHONPATH PYTHONHOME PYTHONDONTWRITEBYTECODE
PYTHONUNBUFFERED PYTHONPYCACHEPREFIX VIRTUAL_ENV
NODE_PATH NODE_ENV
XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME XDG_STATE_HOME XDG_RUNTIME_DIR
SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS
""".split())
# proxy settings of the parent: passed on only when they carry no password
PARENT_PROXY = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
LOOPBACK = "127.0.0.1,localhost,::1"
KEEP_ENV_VAR = "STUNTKEY_KEEP_ENV"      # NAME,NAME (or ;-separated): extra names to pass
NEVER_ENV_PREFIX = ("STUNTKEY_",)       # stuntkey's own settings are not for the program
_SECRET_NAME = None


def looks_secret(name: str) -> bool:
    """Does the NAME look like it holds a secret? (A plain-words guard: such a
    name is passed on only when the person names it exactly.)"""
    global _SECRET_NAME
    if _SECRET_NAME is None:
        import re
        _SECRET_NAME = re.compile(
            r"(TOKEN|KEY|SECRET|PASSWORD|PASSWD|_PWD$|CREDENTIAL|AUTH|COOKIE|SESSION|"
            r"PRIVATE|CERT_PASS|SIGNATURE)|^(AWS|AZURE|GCP|GOOGLE|GITHUB|GH|GITLAB|NPM|"
            r"DOCKER|STRIPE|OPENAI|ANTHROPIC|SLACK|TWILIO|SENDGRID|DATABASE|DB|REDIS|"
            r"MONGO|POSTGRES|MYSQL|PG|HF|HUGGINGFACE|SSH)_", re.IGNORECASE)
    return bool(_SECRET_NAME.search(name))


def keep_names(extra=()) -> set:
    """Names the person allowed: STUNTKEY_KEEP_ENV plus `extra` (the
    `--keep-env NAME` flag). Upper-cased: Windows names ignore case."""
    names = []
    for item in list(extra or ()) + [os.environ.get(KEEP_ENV_VAR, "")]:
        names += [n.strip() for n in str(item).replace(";", ",").split(",")]
    return {n.upper() for n in names if n and "*" not in n and "=" not in n}


def _has_password(url: str) -> bool:
    return "@" in url.split("://", 1)[-1].split("/", 1)[0]


def _stored_key_inside(value: str) -> bool:
    """True when `value` holds a stored key or a known key format."""
    try:
        from .scrub import mask_secrets
        return mask_secrets(value)[1] > 0
    except Exception:
        return True         # cannot check: keep it out (fail closed)


def _slug_var(service: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in service).upper()


def proxyable(recipe: dict) -> bool:
    """Can the proxy carry this service? Plain header/bearer credentials only
    (not signed requests or sign-in tokens), one secret field."""
    auth = (recipe.get("validate") or {}).get("auth", {}).get("type", "bearer")
    return auth not in NO_PROXY_AUTH and len(recipes_mod.env_vars(recipe)) == 1


def parse_map(items, catalog: dict) -> dict:
    """`--map VAR=service[/suffix]` -> {VAR: (service, suffix)}. Makes any SDK
    that reads its base URL from an environment variable use the proxy."""
    import re
    out = {}
    for item in items or ():
        var, sep, target = str(item).partition("=")
        service, _, suffix = target.partition("/")
        suffix = ("/" + suffix) if suffix else ""
        if (not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", var)
                or re.search(r"(KEY|TOKEN|SECRET|PASSWORD)$", var, re.I)
                or service not in catalog or not proxyable(catalog[service])
                or (suffix and not re.fullmatch(r"/[A-Za-z0-9_./-]{0,100}", suffix))
                or ".." in suffix):
            raise ValueError(f"--map wants NAME=service or NAME=service/path, with a "
                             f"service stuntkey can carry, not {str(item)[:40]!r}")
        out[var] = (service, suffix)
    return out


def tunnel_hosts(catalog: dict, extra=(), only_services=None) -> dict:
    """{host: service-or-None}: the only hosts a CONNECT tunnel may reach.

    `only_services`: when given (a set of service names), only the hosts of
    those services are included: cmd_proxy passes the services that have a
    stored key right now, so a run does not get a hole to all ~38 recipe
    hosts. None keeps every recipe host (tests, library use). Hosts named
    with --allow-host (`extra`) are always added."""
    import re
    hosts = {}
    for recipe in catalog.values():
        if only_services is not None and recipe["service"] not in only_services:
            continue
        try:
            hosts[broker.allowed_host(recipe)] = recipe["service"]
        except broker.BrokerError:
            pass
    for h in extra or ():
        h = str(h).strip().lower()
        if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?", h) or "." not in h:
            raise ValueError(f"--allow-host wants a plain host name like api.example.com, "
                             f"not {h[:40]!r}")
        hosts.setdefault(h, None)
    return hosts


def _pop_names(env: dict, name: str) -> str:
    """Remove every spelling of `name` (Windows names ignore case) and return
    the first value found."""
    found = ""
    for k in [k for k in env if k.upper() == name]:
        found = found or env[k]
        del env[k]
    return found


def _set_name(env: dict, name: str, value: str) -> None:
    env[name] = value
    if os.name != "nt":
        env[name.lower()] = value       # curl and friends read the lower-case one


def child_env(catalog: dict, base: str, token: str, environ=None, keep=(),
              generic: bool = False, maps=None, tunnel: bool = False) -> dict:
    """The environment for the AI-run program (see the block comment above).

    keep    extra names to pass on (`--keep-env NAME`), on top of STUNTKEY_KEEP_ENV
    generic every service stuntkey can carry gets a placeholder key and a
            STUNTKEY_URL_<SERVICE> variable holding its proxy address, for
            programs you point at it yourself (base-URL style only)
    maps    {VAR: (service, suffix)} from parse_map: VAR becomes the proxy address
    tunnel  HTTPS_PROXY points at the proxy's host-allow-list tunnel
    """
    src = dict(os.environ if environ is None else environ)
    allowed = keep_names(keep)
    catalog_vars = {v.upper() for r in catalog.values() for v in recipes_mod.env_vars(r)}
    env: dict = {}
    for name, value in src.items():
        up = name.upper()
        if not isinstance(value, str) or up.startswith(NEVER_ENV_PREFIX) or up in catalog_vars:
            continue                    # a brokered key never passes, even if "kept"
        if up in PARENT_PROXY:
            if not _has_password(value):
                env[name] = value
            continue
        if up in allowed:
            env[name] = value           # named by the person: no further checks
        elif up in ALLOW_ENV or up.startswith("LC_"):
            if not looks_secret(name) and not _stored_key_inside(value):
                env[name] = value
    # the program talks to 127.0.0.1 directly, never through an outside proxy
    old = _pop_names(env, "NO_PROXY")
    if tunnel:
        # With the tunnel on, the parent's own proxy settings must not decide
        # where traffic goes: ALL_PROXY / HTTP_PROXY would send it round the
        # tunnel, and a parent NO_PROXY ("*", ".com", ...) would let hosts
        # bypass it. Only loopback is exempt.
        for name in ("ALL_PROXY", "HTTP_PROXY"):
            _pop_names(env, name)
        old = ""
    _set_name(env, "NO_PROXY", old if "127.0.0.1" in old
              else (old + "," if old else "") + LOOPBACK)
    for service, (var, suffix) in ENV.items():
        if service in catalog:
            env[var] = base + suffix
            for key_var in recipes_mod.env_vars(catalog[service]):
                env[key_var] = token
    for var, (service, suffix) in (maps or {}).items():
        env[var] = f"{base}/{service}{suffix}"
        for key_var in recipes_mod.env_vars(catalog[service]):
            env[key_var] = token
    if generic:
        for service, recipe in catalog.items():
            if proxyable(recipe):
                env[f"STUNTKEY_URL_{_slug_var(service)}"] = f"{base}/{service}"
                for key_var in recipes_mod.env_vars(recipe):
                    env[key_var] = token
    if tunnel:
        port = base.rsplit(":", 1)[-1]
        _pop_names(env, "HTTPS_PROXY")
        _set_name(env, "HTTPS_PROXY", f"http://stuntkey:{token}@127.0.0.1:{port}")
    return env


def _clean_host(host: str) -> str:
    return host if re.fullmatch(r"[a-z0-9.-]{1,80}", host) else "(that host)"


def _dial(ip: str, port: int):
    return socket.create_connection((ip, port), 30)


def _splice(a, b, idle: float = TUNNEL_IDLE, send_timeout: float = TUNNEL_SEND_TIMEOUT,
            max_seconds: float = TUNNEL_MAX_SECONDS) -> int:
    """Copy bytes both ways between two sockets until either side closes,
    nothing moves for `idle` seconds, one write is stuck for `send_timeout`
    seconds (the other end is not reading), or `max_seconds` have passed in
    all. Both sockets are always closed. Returns how many bytes were copied."""
    total = 0
    sel = selectors.DefaultSelector()
    started = time.monotonic()
    try:
        for s, other in ((a, b), (b, a)):
            s.setblocking(False)
            sel.register(s, selectors.EVENT_READ, other)
        while True:
            left = max_seconds - (time.monotonic() - started)
            if left <= 0:
                break
            events = sel.select(min(idle, left))
            if not events:
                break
            done = False
            for key, _ in events:
                try:
                    data = key.fileobj.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    done = True
                    continue
                if not data:
                    done = True
                    continue
                total += len(data)
                # A write must not block for ever when the far end stopped
                # reading: give it `send_timeout`, then give up on the tunnel.
                try:
                    key.data.settimeout(send_timeout)
                    key.data.sendall(data)
                    key.data.setblocking(False)
                except OSError:             # includes socket.timeout
                    done = True
            if done:
                break
    finally:
        sel.close()
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass
    return total


def prompt_free(method: str, path: str) -> bool:
    """True for the calls the proxy exists for, which never open a window: the
    usual AI POST endpoints and reading the model list. Anything else asks."""
    if method in broker.WRITE_METHODS:
        return path in SAFE_WRITES
    plain = urllib.parse.unquote(path.split("?")[0])
    if ".." in plain.split("/") or "//" in plain:
        return False
    return method in broker.READ_METHODS and any(
        plain == p or plain.startswith(p + "/") for p in MODEL_READS)


def _given_token(headers) -> str:
    auth = headers.get("Authorization") or ""
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return (headers.get("x-api-key") or headers.get("api-key") or "").strip()


def make_proxy(catalog: dict, get_values, token: str, policy: broker.Policy,
               audit=None, port: int = 0, resolver=None, connect=None,
               timeout: float = UPSTREAM_TIMEOUT, tunnel=None, tunnel_connect=None):
    """`tunnel`: {host: service-or-None} turns on the CONNECT tunnel for exactly
    those hosts (see tunnel_hosts); None leaves it off. `tunnel_connect(ip, port)`
    is for tests only."""
    class Handler(BaseHTTPRequestHandler):
        server_version = "stuntkey"
        sys_version = ""
        timeout = 60

        def log_message(self, *a):
            pass

        def _fail(self, code: int, message: str) -> None:
            data = json.dumps({"error": {"type": "stuntkey", "message": message}}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _handle(self):
            if not httpd.local_only(self.headers, self.server.server_address[1]):
                return self._fail(403, "forbidden")
            if not hmac.compare_digest(_given_token(self.headers).encode(), token.encode()):
                return self._fail(401, "unauthorized: use the key stuntkey proxy gave you")
            service, _, rest = self.path.lstrip("/").partition("/")
            recipe = catalog.get(service)
            if not recipe:
                return self._fail(404, "unknown service; the path starts with /<service>/")
            path, _, query = ("/" + rest).partition("?")
            try:
                self._forward(recipe, self.command, path, query)
            except broker.BrokerError as e:
                self._fail(403 if e.code == 5 else 502, str(e))
            except (ValueError, KeyError):
                self._fail(400, "bad request")
            except TypeError:
                # A TypeError here is almost always OUR bug (a wrong call
                # signature), not a malformed request. Catching it as 400 "bad
                # request" is how a broken proxy ships looking healthy: a
                # signature change once made every call -- including STOP
                # kill-switch refusals -- return a generic 400, and the client
                # blamed itself. Fail loudly as a server error instead, and say
                # where to look.
                self._fail(500, "stuntkey internal error; run `stuntkey selftest`")
                raise

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

        def do_CONNECT(self):
            """Host-allow-list tunnel. The bytes are NOT looked at (they are TLS
            between the program and the host): no key is added, nothing is
            scrubbed. What it gives is control over WHERE the program can go."""
            host, _, port = self.path.rpartition(":")
            host = host.strip("[]").lower()
            # Same guard as every other route (no web page via Origin, and the
            # request must be meant for the target it names). A CONNECT's Host
            # is the target, not us, so httpd.local_only is told the target.
            # The peer must also be this computer.
            if (not httpd.local_only(self.headers, self.server.server_address[1],
                                     connect_target=self.path)
                    or self.client_address[0] not in ("127.0.0.1", "::1")):
                return self._fail(403, "forbidden")
            if tunnel is None:
                return self._fail(403, "the tunnel is off; start with --tunnel")
            try:
                scheme, _, blob = (self.headers.get("Proxy-Authorization") or "").partition(" ")
                given = base64.b64decode(blob.strip(), validate=True).decode("utf-8").partition(":")[2]
                if scheme.lower() != "basic" or not hmac.compare_digest(given.encode(), token.encode()):
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                self.send_response(407)
                self.send_header("Proxy-Authenticate", 'Basic realm="stuntkey"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            def note(result: str) -> None:
                # refused or failed attempts are written down too (best effort:
                # a broken log must not turn a refusal into a crash)
                if audit is not None:
                    try:
                        audit.write({"service": (tunnel.get(host) if isinstance(tunnel, dict)
                                                 else None) or "(tunnel)",
                                     "method": "CONNECT", "host": _clean_host(host),
                                     "path": "", "status": 0, "bytes": 0,
                                     "result": result, "ms": 0})
                    except Exception:
                        pass
            if port != "443" or host not in tunnel:
                note("refused")
                return self._fail(403, f"{_clean_host(host)} is not on this run's allowed "
                                       "host list, so the connection was not made. A person "
                                       "can add it with --allow-host.")
            service = tunnel[host]
            try:
                if os.path.lexists(caps.stop_path(policy.limits_home())):
                    raise broker.BrokerError(caps.STOPPED, 5)
                policy.count()
                if service:
                    with policy.lock:
                        caps.begin(policy.limits_home(), service,
                                   policy.service_calls.get(service, 0))
                        policy.service_calls[service] = policy.service_calls.get(service, 0) + 1
                ip = broker.resolve_public(host, 443, resolver)
                if audit is not None:
                    audit.ready()
                upstream = (tunnel_connect or _dial)(ip, 443)
            except broker.BrokerError as e:
                note("refused" if e.code == 5 else "network-error")
                return self._fail(403 if e.code == 5 else 502, str(e))
            except OSError:
                note("network-error")
                return self._fail(502, "could not connect to the host")
            started = time.time()
            self.send_response(200, "Connection established")
            self.end_headers()
            self.wfile.flush()
            moved = _splice(self.connection, upstream)
            if audit is not None:
                try:
                    audit.write({"service": service or "(tunnel)", "method": "CONNECT",
                                 "host": host, "path": "", "status": 200, "bytes": moved,
                                 "result": "ok", "ms": int((time.time() - started) * 1000)})
                except (OSError, broker.BrokerError):
                    pass
            self.close_connection = True

        def _forward(self, recipe, method, path, query):
            service = recipe["service"]
            # Bound before the lambda so the closure can see it, and rebound at
            # the get_values() call below. _log scrubs the path with these, so
            # refusals that happen before a key is fetched log with none (there
            # is no secret in play yet), and everything after logs scrubbed.
            values = None
            log = lambda result, host="?", status=0, size=0, ms=0: broker._log(
                audit, recipe, values, method, host, path, status, size, result, ms=ms)
            try:
                host, url, body = self._check(recipe, method, path, query)
            except broker.BrokerError:
                log("refused")
                raise
            try:
                values = get_values(recipe)
            except Exception as e:
                log("refused")
                if "did not answer" in str(e):
                    raise broker.BrokerError(
                        "The computer's password vault did not answer, so no call was "
                        "made. Unlock it (sign in to Windows again) and retry.", 5) from None
                raise broker.BrokerError(f"no key is stored for '{service}'. Run "
                                         f"`stuntkey get {service}` first.", 5) from None
            spec = dict(recipe["validate"], url=url)
            req = _v._build_request(spec, broker.credentials(recipe, values))
            headers = {k: v for k, v in self.headers.items() if k.lower() in REQ_HEADERS}
            for k, v in req.header_items():          # static + credential headers win
                headers = {h: x for h, x in headers.items() if h.lower() != k.lower()}
                headers[k] = v
            parts = urllib.parse.urlsplit(req.full_url)
            target = parts.path + (f"?{parts.query}" if parts.query else "")
            try:
                ip = broker.resolve_public(host, 443, resolver)
                if audit is not None:
                    audit.ready()
            except broker.BrokerError:
                log("refused", host)
                raise
            started = time.time()
            try:
                conn, resp = broker.open_stream(host, ip, method, target, headers,
                                                body, timeout, connect)
            except broker.BrokerError:
                log("network-error", host)
                raise
            with contextlib.closing(conn):
                secrets_ = [v for v in values.values() if isinstance(v, str)]
                size, result = self._relay(resp, secrets_, service)
            log(result, host, resp.status, size, int((time.time() - started) * 1000))

        def _check(self, recipe, method, path, query):
            service = recipe["service"]
            if method not in broker.READ_METHODS | broker.WRITE_METHODS:
                raise broker.BrokerError("method not supported", 5)
            auth = (recipe.get("validate") or {}).get("auth", {}).get("type", "bearer")
            if auth in NO_PROXY_AUTH:
                raise broker.BrokerError(f"'{service}' signs its requests or needs a "
                                         "sign-in token; the proxy cannot carry it.", 5)
            policy.count()
            host, url = broker.build_url(
                recipe, path, dict(urllib.parse.parse_qsl(query, keep_blank_values=True)))
            if method in broker.WRITE_METHODS and path not in SAFE_WRITES:
                rules = route.load(policy.limits_home(), policy.project_dir or os.getcwd())
                if service not in rules:
                    raise broker.BrokerError(
                        f"The proxy only sends {method} to the usual AI endpoints (chat, "
                        f"responses, messages, embeddings), so {path[:80]} was not sent. A "
                        "person can allow it in stuntkey.policy and run `stuntkey policy "
                        "approve`.", 5)
            try:
                n = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                raise broker.BrokerError("request body missing a length or too large", 5)
            if n and method in broker.READ_METHODS:
                raise broker.BrokerError("GET/HEAD may not have a body", 5)
            body = self.rfile.read(n) if n else None
            self._ask_person(recipe, method, host, url, path, body)
            policy.gate(service, method, path)
            return host, url, body

        def _ask_person(self, recipe, method, host, url, path, body) -> None:
            """Ask the person when this request is not a plain AI-model call
            (see "WHEN THE PERSON IS ASKED" at the top of this file). Raises
            BrokerError when the answer is no. Runs BEFORE policy.gate so a
            refusal spends no cap."""
            service = recipe["service"]
            if prompt_free(method, path):
                return
            # a route policy that forbids it is a plain refusal: no window
            route.check(route.load(policy.limits_home(),
                                   policy.project_dir or os.getcwd()),
                        service, method, path)
            with policy.lock:
                if method in broker.WRITE_METHODS:
                    # a write the policy file allowed: every one is shown, with its body
                    summary = broker.describe(recipe, method, host, url, body)
                    if len(summary) > broker.MAX_REVIEW:
                        raise broker.BrokerError(broker.TOO_LONG, 5)
                    asked = summary
                elif (service, host) in policy.approved_hosts:
                    return                      # said yes earlier in this run
                else:
                    asked = (f"A program run through `stuntkey proxy` wants to use your "
                             f"'{service}' key to read from {host} (first request: "
                             f"{method} {broker._clean(path, 120)}). If you allow it, more "
                             "reads like this to this service are allowed until the "
                             "proxy closes. AI chat and message calls never ask.")
                    caps.notice(policy.limits_home(),
                                f"First use of '{service}' ({host}) through the proxy "
                                "outside the AI endpoints: asking you.")
                try:
                    yes = policy.ask(asked)
                except broker.BrokerError as e:
                    caps.notice(policy.limits_home(), str(e))
                    raise
                if not yes:
                    caps.notice(policy.limits_home(),
                                f"You said no (or no window could open) to a proxy "
                                f"request for '{service}'; it was refused.")
                    raise broker.BrokerError(broker.NO_APPROVAL, 5)
                if method in broker.READ_METHODS:
                    policy.approved_hosts.add((service, host))

        def _relay(self, resp, secrets_, service):
            enc = (resp.getheader("content-encoding") or "").lower()
            if enc not in ("", "identity"):
                raise broker.BrokerError("the API sent a compressed answer; not passed on", 7)
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                low = k.lower()
                if low in RESP_HEADERS or low.startswith(RESP_PREFIXES):
                    hs = Scrubber(secrets_)
                    val = (hs.feed(v.encode()) + hs.flush()).decode("utf-8", "replace")
                    if not loosely_contains(val, secrets_):
                        self.send_header(k, val)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            # ponytail: streamed bodies get the streaming Scrubber only, not the
            # whole-body disguise check (loosely_contains) broker.call adds.
            sc, meter, size, result = Scrubber(secrets_), caps.TokenMeter(
                resp.getheader("content-type") or ""), 0, "ok"
            try:
                while True:
                    chunk = resp.read1(8192)
                    if not chunk:
                        break
                    size += len(chunk)
                    meter.feed(chunk)
                    out = sc.feed(chunk)
                    if out:
                        self.wfile.write(out)
                        self.wfile.flush()
                self.wfile.write(sc.flush())
            except (OSError, http.client.HTTPException):
                result = "network-error"
            policy.add_tokens(service, meter.total())
            return size, result

    srv = httpd.DoorServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv


# ---- commands --------------------------------------------------------------------

def add_parsers(sub) -> None:
    import argparse
    pr = sub.add_parser("proxy", help="Run a program with AI base URLs pointing at a "
                                      "local proxy; it never gets the real key.",
                        usage="stuntkey proxy [--env-file F] [--print-env] [-- COMMAND ...]")
    pr.add_argument("--env-file", default=".env")
    pr.add_argument("--print-env", action="store_true",
                    help="Print the variables to set and keep the proxy open "
                         "(for tools you start yourself).")
    pr.add_argument("--keep-env", dest="keep_env", action="append", metavar="NAME",
                    help="Also pass this one environment variable to the program "
                         "(it gets only a short safe list otherwise). Repeat for more; "
                         "or set STUNTKEY_KEEP_ENV=NAME,NAME.")
    pr.add_argument("--generic", action="store_true",
                    help="Give the program a stand-in key and a proxy address "
                         "(STUNTKEY_URL_<SERVICE>) for every service stuntkey can carry.")
    pr.add_argument("--map", action="append", metavar="NAME=service[/path]",
                    help="Make the variable NAME hold the proxy address of a service, "
                         "for a program that reads its web address from NAME.")
    pr.add_argument("--tunnel", action="store_true",
                    help="Also set HTTPS_PROXY to a tunnel that only reaches the AI "
                         "services' hosts (it adds no key and sees nothing inside).")
    pr.add_argument("--allow-host", dest="allow_host", action="append", metavar="HOST",
                    help="With the tunnel: one more host the program may reach "
                         "(for example api.github.com). Repeat for more.")
    pr.add_argument("--port", type=int, default=0,
                    help="Use this port for the proxy (default: any free one).")
    pr.add_argument("command", nargs=argparse.REMAINDER)
    cp = sub.add_parser("caps", help="Show or set per-key call and token caps.")
    cps = cp.add_subparsers(dest="caps_cmd", required=True)
    cps.add_parser("show", help="Caps and today's usage.")
    cs = cps.add_parser("set", help="Set caps for one service (asks you first).")
    cs.add_argument("service")
    cs.add_argument("--calls-session", dest="calls_session", type=int)
    cs.add_argument("--calls-hour", dest="calls_hour", type=int)
    cs.add_argument("--calls-day", dest="calls_day", type=int)
    cs.add_argument("--tokens-day", dest="tokens_day", type=int)
    cs.add_argument("--clear", action="store_true", help="Remove this service's caps.")
    sub.add_parser("stop", help="Kill switch: no API call is made through stuntkey "
                                "until `stuntkey resume`.")
    sub.add_parser("resume", help="Undo `stuntkey stop` (asks you first).")
    po = sub.add_parser("policy", help="Show or approve the route policy (stuntkey.policy).")
    po.add_argument("policy_cmd", choices=["show", "approve"])


COMMANDS = {"proxy", "caps", "stop", "resume", "policy"}


def dispatch(args, catalog: dict):
    if args.cmd not in COMMANDS:
        return None
    from . import approve as approve_mod
    from . import remote
    home = remote.home_dir()
    try:
        if args.cmd == "caps":
            return caps.cmd_caps(args, home, approve_mod.ask_person)
        if args.cmd == "stop":
            return caps.cmd_stop(home)
        if args.cmd == "resume":
            return caps.cmd_resume(home, approve_mod.ask_person)
        if args.cmd == "policy":
            return _cmd_policy(args.policy_cmd, home, approve_mod.ask_person)
    except broker.BrokerError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    return cmd_proxy(catalog, args, home)


EXAMPLE = '{"openai": {"methods": ["GET", "POST"], "paths": ["/v1/chat/completions", "/v1/models"]}}'


def _cmd_policy(action: str, home: str, ask) -> int:
    if action == "approve":
        n = route.approve(home, os.getcwd(), ask)
        print(f"approved {n} policy file(s).")
        return 0
    rules = route.load(home, os.getcwd())
    if not rules:
        print(f"no route policy. To add one, write {route.user_file(home)} "
              f"(or ./{route.FILE}, which can only narrow it), e.g.\n  {EXAMPLE}\n"
              "then run `stuntkey policy approve`.")
    for service, (methods, paths) in sorted(rules.items()):
        print(f"  {service:14} {' '.join(sorted(methods)) or '(nothing)'}  "
              f"{' '.join(paths) or '(no paths)'}")
    return 0


def cmd_proxy(catalog: dict, args, home: str) -> int:
    from . import remote
    command = list(args.command or [])
    if command[:1] == ["--"]:
        command = command[1:]
    def listed(name):
        v = getattr(args, name, None)
        return list(v) if isinstance(v, (list, tuple)) else []
    keep, extra_hosts = listed("keep_env"), listed("allow_host")
    generic = getattr(args, "generic", False) is True
    use_tunnel = getattr(args, "tunnel", False) is True or bool(extra_hosts)
    from . import approve as approve_mod
    try:
        maps = parse_map(listed("map"), catalog)
        hosts = None
        if use_tunnel:
            # only services that have a key stored right now (plus --allow-host)
            stored = set()
            for s, r in catalog.items():
                try:
                    remote.collect_values(r, args.env_file)
                    stored.add(s)
                except Exception:
                    pass
            hosts = tunnel_hosts(catalog, extra_hosts, only_services=stored)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    token = "ok-" + secrets.token_urlsafe(24)
    # approve=ask_person: non-AI reads and writes ask (see _ask_person)
    policy = broker.Policy(max_calls=MAX_CALLS, max_per_minute=PER_MINUTE,
                           approve=approve_mod.ask_person)
    audit = broker.AuditLog(os.path.join(home, "audit.log"))
    port = getattr(args, "port", 0)
    port = port if isinstance(port, int) and not isinstance(port, bool) else 0
    try:
        srv = make_proxy(catalog, lambda r: remote.collect_values(r, args.env_file),
                         token, policy, audit, port=port, tunnel=hosts)
    except httpd.PortBusy as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    env = child_env(catalog, base, token, keep=keep, generic=generic, maps=maps,
                    tunnel=use_tunnel)
    if args.print_env or not command:
        # only what stuntkey itself sets: the proxy address and the session password
        # flush=True: when piped, Python buffers stdout, so the variables would
        # never appear while the proxy keeps running
        for var, value in env.items():
            if base in value or token in value:
                print(f"{var}={value}", flush=True)
        print("stuntkey proxy is open (other services: /<service>/...). These "
              "values are not your keys. Ctrl+C to close.\n"
              "NOTICE: AI chat/message calls and the model list go through without a "
              "question. Anything else (for example GET /github/user) opens a "
              "permission window the first time for each service, and after 3 'no' "
              "answers nothing more is allowed. If no window can open, it is refused.",
              file=sys.stderr, flush=True)
        httpd.serve_forever(srv)
        return 0
    httpd.start_background(srv)
    try:
        return subprocess.call(command, env=env)
    except OSError as e:
        name = command[0] if re.fullmatch(r"[\w.:\\/ -]{1,80}", command[0]) else "the program"
        print(f"error: could not start {name!r}: {e.strerror or e}", file=sys.stderr)
        return 127
    finally:
        srv.shutdown()
        srv.server_close()
