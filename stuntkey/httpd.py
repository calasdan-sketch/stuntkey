"""A tiny local web door for AIs that have no MCP and no shell
(OpenAI-style function calling, Ollama wrappers, scripts).

Same broker underneath, so the same rules: the AI never gets the key, the
host is fixed by the recipe, writes ask the person on the real terminal.

Safety of the door itself:
- listens on 127.0.0.1 only
- every API request needs the secret token (random, kept in an owner-only file)
- the one exception is the page at `/`: a browser cannot send the token, so it
  opens with a ONE-TIME link (`/?c=CODE`, good for 2 minutes, used once) that is
  swapped for a cookie made from the token (never the token itself) and opens
  the page only. The page holds names, never keys.
- the Host header must be exactly us (blocks DNS-rebinding tricks)
- any request with an Origin header is refused (blocks web pages)
- no CORS headers are ever sent; bodies are size-limited
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "index.html")
LAUNCH_SECONDS = 120            # a one-time page link works for two minutes, once
PAGE_COOKIE = "sk_page"
PAGE_CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "img-src data:; font-src data:; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'")


def render_page(version: str, status: dict, template: str | None = None) -> bytes:
    """The local page with its two placeholders filled in. The status is JSON
    inside <script type="application/json">, so '<', '>' and '&' are written
    as unicode escapes (nothing in it can close the tag or start a comment).
    It holds names and counts only, never a key or the token."""
    if template is None:
        with open(PAGE_FILE, encoding="utf-8") as f:
            template = f.read()
    blob = (json.dumps(status, separators=(",", ":"), ensure_ascii=True)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))
    return (template.replace("{{status_json}}", blob)
            .replace("{{version}}", html.escape(str(version), quote=True))).encode("utf-8")


PAGE_COOKIE_SECONDS = 3600      # the page cookie lives one hour (Max-Age) and then it is gone


def _cookie_value(secret: bytes, port: int, nonce: str) -> str:
    """What the page cookie holds: an HMAC made with a random secret that only
    this running server knows (new at every start), bound to this port and to
    a fresh random nonce chosen at each one-time-link exchange. It is NOT
    derived from the long-lived token, so it cannot be recomputed from it, is
    not shared between two servers on different ports, and the previous cookie
    stops working when a new link is used. It opens the page only; every API
    route still needs the Bearer token."""
    return hmac.new(secret, f"stuntkey page cookie|{port}|{nonce}".encode(),
                    hashlib.sha256).hexdigest()

from . import broker

MAX_REQUEST = 300_000

TOOLS = [
    {"type": "function", "function": {
        "name": "call_api",
        "description": ("Call a connected service's API; the key is added for you and never placed in your "
                        "environment. Host and credential are added for you."),
        "parameters": {"type": "object", "properties": {
            "service": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]},
            "path": {"type": "string", "description": "like /user"},
            "query": {"type": "object"},
            "body": {"type": "object"}},
            "required": ["service", "method", "path"]}}},
    {"type": "function", "function": {
        "name": "list_services",
        "description": "Services that have a saved connection recipe.",
        "parameters": {"type": "object", "properties": {}}}},
]


def load_or_make_token(path: str) -> str:
    try:
        with open(path, encoding="ascii") as f:
            tok = f.read().strip()
        if len(tok) >= 40:
            return tok
    except OSError:
        pass
    from . import store as store_mod
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(folder, 0o700)
        except OSError:
            pass
    # Under the file lock, so two servers started together agree on ONE token,
    # and replaced whole (a crash leaves the old file or the new, never half),
    # owner-only from the start (the old plain file open ignored the mode on Windows).
    with store_mod.file_lock(path):
        try:
            with open(path, encoding="ascii") as f:
                tok = f.read().strip()
            if len(tok) >= 40:
                return tok
        except (OSError, ValueError):
            pass
        tok = secrets.token_urlsafe(32)
        store_mod.write_private(path, tok + "\n")
    return tok


def local_only(headers, port: int, connect_target: str | None = None) -> bool:
    """Host must be exactly us (no DNS rebinding) and no web page (Origin).

    `connect_target`: for a proxy CONNECT request. A CONNECT's Host header
    names the site the program wants to reach, not us (every client sends it
    that way), so there the rule is: no Origin, and Host (when present) must
    be the very target named in the request line."""
    if headers.get("Origin") is not None:
        return False
    host = (headers.get("Host") or "").lower()
    if connect_target is not None:
        return host in ("", str(connect_target).lower())
    return host in (f"127.0.0.1:{port}", f"localhost:{port}")


class PortBusy(OSError):
    """The port is taken by something else. The text is plain words for a person."""


_BUSY_ERRNOS = {98, 48, 10048, 10013}    # Linux, macOS, Windows in use, Windows no access


class DoorServer(ThreadingHTTPServer):
    """On Windows, SO_REUSEADDR lets another program bind the very same port
    and take the door's connections; ask for the port exclusively instead."""
    allow_reuse_address = os.name != "nt"
    MAX_CONNECTIONS = 128      # a runaway client cannot start threads without end

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(self.MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                b"Connection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def server_bind(self):
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if os.name == "nt" and exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        try:
            super().server_bind()
        except OSError as e:
            port = self.server_address[1]
            if port and (e.errno in _BUSY_ERRNOS or getattr(e, "winerror", 0) in _BUSY_ERRNOS):
                try:
                    self.server_close()
                except OSError:
                    pass
                raise PortBusy(f"Something else is using port {port}. Pick another with "
                               f"--port {port + 1}, or close the other program.") from None
            raise


def make_server(catalog: dict, get_values, token: str, policy, audit=None,
                port: int = 0, call_fn=None, page_status=None,
                version: str = "") -> ThreadingHTTPServer:
    call_fn = call_fn or broker.call
    launch = {}                      # one-time page links: code -> expiry time
    launch_lock = threading.Lock()

    def new_launch_code() -> str:
        code = secrets.token_urlsafe(24)
        with launch_lock:
            now = time.time()
            for old in [c for c, t in launch.items() if t < now]:
                del launch[old]
            launch[code] = now + LAUNCH_SECONDS
        return code

    session = {"secret": secrets.token_bytes(32), "nonce": None, "until": 0.0}
    session_lock = threading.Lock()

    def rotate_cookie(port: int) -> str:
        """A new cookie for the page; the one before it stops working."""
        with session_lock:
            session["nonce"] = secrets.token_urlsafe(16)
            session["until"] = time.time() + PAGE_COOKIE_SECONDS
            return _cookie_value(session["secret"], port, session["nonce"])

    def cookie_ok(given: str, port: int) -> bool:
        with session_lock:
            nonce, until = session["nonce"], session["until"]
            if nonce is None or time.time() > until:
                return False
            want = _cookie_value(session["secret"], port, nonce)
        return hmac.compare_digest(given.encode(), want.encode())

    def use_launch_code(code: str) -> bool:
        with launch_lock:
            expiry = launch.pop(code, None)      # once: a second use finds nothing
        return expiry is not None and expiry >= time.time()

    class Handler(BaseHTTPRequestHandler):
        server_version = "stuntkey"
        sys_version = ""
        timeout = 15                       # a stalled client cannot hold a thread forever

        def log_message(self, *a):          # never log request lines
            pass

        def _send(self, code: int, obj) -> None:
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _guard(self) -> bool:
            if not local_only(self.headers, self.server.server_address[1]):
                self._send(403, {"error": "forbidden"})
                return False
            given = (self.headers.get("Authorization") or "")
            want = "Bearer " + token
            if not hmac.compare_digest(given.encode(), want.encode()):
                self._send(401, {"error": "unauthorized"})
                return False
            return True

        def _page(self) -> bool:
            """GET / : the local page. A browser sends no Authorization header,
            so it gets in with a one-time link (?c=CODE, from `stuntkey serve`)
            that is swapped at once for a session cookie, then the address is
            cleaned. Nothing here is logged, and the long-lived token never
            appears in a URL. Returns False when this is not a page request."""
            from urllib.parse import urlsplit, parse_qs
            parts = urlsplit(self.path)
            if parts.path not in ("/", "/index.html") or page_status is None:
                return False
            port = self.server.server_address[1]
            # cookies are shared between ports of the same host, so the NAME
            # carries the port: two stuntkey servers do not trample each other
            cookie_name = f"{PAGE_COOKIE}_{port}"
            if not local_only(self.headers, self.server.server_address[1]):
                self._send(403, {"error": "forbidden"})
                return True
            safe = [("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Content-Security-Policy", PAGE_CSP)]
            code = (parse_qs(parts.query).get("c") or [""])[0]
            if code:
                if use_launch_code(code):
                    self.send_response(303)
                    self.send_header("Location", "/")
                    self.send_header("Set-Cookie", f"{cookie_name}={rotate_cookie(port)}; "
                                     f"HttpOnly; SameSite=Strict; Path=/; "
                                     f"Max-Age={PAGE_COOKIE_SECONDS}")
                    for k, v in safe:
                        self.send_header(k, v)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return True
                self._text(401, "That link was already used or has run out. Run "
                                "`stuntkey serve` again for a new one.")
                return True
            cookies = {}
            for item in (self.headers.get("Cookie") or "").split(";"):
                name, _, value = item.strip().partition("=")
                cookies[name] = value
            if not cookie_ok(cookies.get(cookie_name, ""), port):
                self._text(401, "Open the link that `stuntkey serve` printed.")
                return True
            try:
                body = render_page(version, page_status())
            except Exception:
                self._text(500, "The page could not be built. Run `stuntkey doctor`.")
                return True
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in safe:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            return True

        def _text(self, code: int, text: str) -> None:
            data = text.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self._page():
                return
            if not self._guard():
                return
            if self.path == "/tools":
                return self._send(200, TOOLS)
            if self.path == "/services":
                return self._send(200, [
                    {"service": r["service"], "display": r["display"]}
                    for r in catalog.values()])
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._guard():
                return
            if self.path != "/call":
                return self._send(404, {"error": "not found"})
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                return self._send(415, {"error": "send application/json"})
            try:
                n = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                n = -1
            if n < 0 or n > MAX_REQUEST:
                return self._send(413, {"error": "request too large"})
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
                recipe = catalog.get(req["service"])
                if not recipe:
                    return self._send(404, {"error": "unknown service"})
                values = get_values(recipe)
                out = call_fn(recipe, values, req["method"], req["path"],
                              req.get("query"), req.get("body"),
                              policy=policy, audit=audit)
                return self._send(200, out)
            except broker.BrokerError as e:
                return self._send(403 if e.code == 5 else 502, {"error": str(e)})
            except (ValueError, KeyError, TypeError):
                return self._send(400, {"error": "bad request"})
            except Exception as e:
                from . import remote
                if isinstance(e, remote.RemoteError):
                    # no key stored, or the password vault is locked: say which,
                    # and that no call was made (fail closed, plain words)
                    if "did not answer" in str(e):
                        return self._send(503, {"error": "The computer's password vault "
                                                "did not answer, so no call was made. "
                                                "A person needs to unlock it and retry."})
                    return self._send(404, {"error": "No key is saved for that service, "
                                            "so no call was made. A person can run "
                                            "`stuntkey get <service>` in a terminal."})
                return self._send(500, {"error": "internal error"})

    srv = DoorServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    srv.new_launch_code = new_launch_code
    return srv


def _stop_on_signals():
    """Make a plain stop request (SIGTERM, or Ctrl+Break / closing the console
    on Windows) end the server like Ctrl+C does, so it closes its port and
    returns normally. Only possible from the main thread; returns a function
    that puts the old handlers back."""
    import signal
    if threading.current_thread() is not threading.main_thread():
        return lambda: None
    def stop(signum, frame):
        raise KeyboardInterrupt
    old = {}
    for name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            old[sig] = signal.signal(sig, stop)
        except (ValueError, OSError):
            pass

    def restore():
        for sig, handler in old.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError, TypeError):
                pass
    return restore


def serve_forever(srv) -> None:
    restore = _stop_on_signals()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        restore()
        srv.server_close()


def start_background(srv) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
