"""Round 12, proxy / approval / door / caps / runner / MCP fixes.

Safety rules for this file:
  * every key is a synthetic canary built at run time;
  * HOME and friends are redirected by `import _isolation`, the keychain is the
    in-memory one, and the audit log lives in a temp folder;
  * NO real Windows pop-up can open: `approve.dialog` and `approve.console` are
    replaced with stubs that FAIL THE TEST if called, and the tests of the real
    `approve.dialog` replace `subprocess.run` and `_tool` first.
"""
import argparse
import http.client
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE/APPDATA for the whole run)
from stuntkey import approve, broker, caps, httpd, mcp, proxy, recipes, runner

CATALOG = recipes.load_recipes()
CANARY = "sk-" + "FAKE0000TEST1111CANARY2222abcd3333"
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("104.18.6.192", port))]
TOKEN = "ok-test-token-r12-0000000000"


def _no_real_window(*a, **k):
    raise AssertionError("a REAL approval window / console prompt was requested")


class _Base(unittest.TestCase):
    stub_dialog = True       # tests of the real approve.dialog switch this off and
                             # replace subprocess.run + _tool themselves
    def setUp(self):
        os.environ["STUNTKEY_KEYCHAIN"] = "memory"
        patches = [mock.patch.object(approve, "console", _no_real_window)]
        if self.stub_dialog:
            patches.append(mock.patch.object(approve, "dialog", _no_real_window))
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        approve._shown.clear()
        self.addCleanup(approve._shown.clear)


class Upstream(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def _answer(self):
        Upstream.hits.append((self.command, self.path))
        data = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _answer

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._answer()


class ProxyAsks(_Base):
    """Finding 1: a read outside the AI endpoints must ask, once per service."""

    def start(self, approve_fn):
        Upstream.hits = []
        self.up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.home = _isolation.mktemp()
        self.asked = []

        def ask(summary):
            self.asked.append(summary)
            return approve_fn(len(self.asked))
        self.pol = broker.Policy(home=self.home, project_dir=self.home, max_calls=100,
                                 approve=ask if approve_fn else None)
        self.audit = broker.AuditLog(os.path.join(self.home, "audit.log"))
        connect = lambda host, timeout: http.client.HTTPConnection(
            "127.0.0.1", self.up.server_address[1], timeout=timeout)
        names = {s: recipes.env_vars(r)[0] for s, r in CATALOG.items()
                 if proxy.proxyable(r)}
        self.srv = proxy.make_proxy(CATALOG, lambda r: {recipes.env_vars(r)[0]: CANARY},
                                    TOKEN, self.pol, self.audit, resolver=PUBLIC,
                                    connect=connect)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self._stop)

    def _stop(self):
        for s in (self.srv, self.up):
            s.shutdown()
            s.server_close()

    def req(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Authorization": "Bearer " + TOKEN}
        if body is not None:
            h["Content-Type"] = "application/json"
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read().decode()

    def test_github_user_asks_and_a_no_sends_nothing(self):
        self.start(lambda n: False)
        status, text = self.req("GET", "/github/user")
        self.assertEqual(status, 403)
        self.assertEqual(len(self.asked), 1)
        self.assertEqual(Upstream.hits, [])               # the real key never left
        self.assertNotIn(CANARY, text)

    def test_no_way_to_ask_means_no(self):
        self.start(None)                                  # Policy.approve is None
        self.assertEqual(self.req("GET", "/github/user")[0], 403)
        self.assertEqual(self.req("GET", "/github/user/keys")[0], 403)
        self.assertEqual(Upstream.hits, [])

    def test_a_yes_is_asked_once_per_service_and_remembered(self):
        self.start(lambda n: True)
        self.assertEqual(self.req("GET", "/github/user")[0], 200)
        self.assertEqual(self.req("GET", "/github/user/keys")[0], 200)
        self.assertEqual(len(self.asked), 1)
        self.assertIn("github", self.asked[0])
        self.assertEqual(len(Upstream.hits), 2)
        # another service asks on its own
        self.assertEqual(self.req("GET", "/openai/v1/files")[0], 200)
        self.assertEqual(len(self.asked), 2)

    def test_the_yes_is_in_memory_only(self):
        self.start(lambda n: True)
        self.req("GET", "/github/user")
        for root, _d, files in os.walk(self.home):
            for f in files:
                with open(os.path.join(root, f), "rb") as fh:
                    self.assertNotIn(b"approved_hosts", fh.read())

    def test_three_refusals_stop_the_asking(self):
        self.start(lambda n: False)
        for _ in range(3):
            self.assertEqual(self.req("GET", "/github/user")[0], 403)
        status, text = self.req("GET", "/github/user")
        self.assertEqual(status, 403)
        self.assertIn("three times", text)
        self.assertEqual(len(self.asked), 3)              # the fourth never opened a window

    def test_a_refusal_spends_no_cap(self):
        self.start(lambda n: False)
        self.req("GET", "/github/user")
        self.assertEqual(caps.usage(self.home, "github")["calls"], 0)

    def test_ai_calls_stay_prompt_free(self):
        self.start(lambda n: False)
        self.assertEqual(self.req("POST", "/openai/v1/chat/completions", b"{}")[0], 200)
        self.assertEqual(self.req("POST", "/anthropic/v1/messages", b"{}")[0], 200)
        self.assertEqual(self.req("GET", "/openai/v1/models")[0], 200)
        self.assertEqual(self.req("GET", "/openai/v1/models/gpt-x")[0], 200)
        self.assertEqual(self.asked, [])

    def test_models_path_trickery_still_asks(self):
        self.start(lambda n: False)
        self.assertEqual(self.req("GET", "/openai/v1/models/../files")[0], 403)
        self.assertEqual(Upstream.hits, [])

    def test_prompt_free_rules(self):
        self.assertTrue(proxy.prompt_free("POST", "/v1/messages"))
        self.assertTrue(proxy.prompt_free("GET", "/v1/models"))
        self.assertFalse(proxy.prompt_free("GET", "/user"))
        self.assertFalse(proxy.prompt_free("GET", "/v1/modelsX"))
        self.assertFalse(proxy.prompt_free("DELETE", "/v1/messages/x"))

    def test_refusal_leaves_a_notice(self):
        self.start(lambda n: False)
        self.req("GET", "/github/user")
        self.assertTrue(any("github" in n for n in caps.recent_notices(self.home)))


class Tunnel(_Base):
    def setUp(self):
        super().setUp()
        self.home = _isolation.mktemp()
        self.audit = broker.AuditLog(os.path.join(self.home, "audit.log"))
        self.pol = broker.Policy(home=self.home, project_dir=self.home, max_calls=100)
        self.hosts = proxy.tunnel_hosts(CATALOG, ["api.example.com"], only_services={"github"})
        self.srv = proxy.make_proxy(CATALOG, lambda r: {}, TOKEN, self.pol, self.audit,
                                    resolver=PUBLIC, tunnel=self.hosts,
                                    tunnel_connect=lambda ip, port: socket.create_connection(
                                        ("127.0.0.1", 9), 1))
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (self.srv.shutdown(), self.srv.server_close()))

    def connect(self, target, extra_headers=""):
        import base64
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        auth = "Proxy-Authorization: Basic " + base64.b64encode(
            f"stuntkey:{TOKEN}".encode()).decode() + "\r\n"
        s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}"
                  f"{extra_headers}\r\n".encode())
        s.settimeout(5)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            if not chunk:
                break
            head += chunk
        s.close()
        return head

    def test_only_hosts_of_stored_services_plus_explicit_ones(self):
        self.assertEqual(set(self.hosts), {"api.github.com", "api.example.com"})
        self.assertNotIn("api.openai.com", self.hosts)
        self.assertGreater(len(proxy.tunnel_hosts(CATALOG)), 10)   # default: all (library use)
        self.assertEqual(proxy.tunnel_hosts(CATALOG, [], only_services=set()), {})

    def test_a_host_of_a_service_without_a_key_is_refused_and_logged(self):
        head = self.connect("api.openai.com:443")
        self.assertIn(b" 403 ", head.split(b"\r\n")[0])
        with open(self.audit.path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("api.openai.com", text)
        self.assertIn("refused", text)
        self.assertIn("CONNECT", text)

    def test_a_failed_connection_is_logged_too(self):
        head = self.connect("api.github.com:443")
        self.assertIn(b" 502 ", head.split(b"\r\n")[0])
        with open(self.audit.path, encoding="utf-8") as f:
            self.assertIn("network-error", f.read())

    def test_connect_with_an_origin_header_is_refused(self):
        head = self.connect("api.github.com:443", "Origin: http://evil.example\r\n")
        self.assertIn(b" 403 ", head.split(b"\r\n")[0])

    def test_connect_whose_host_is_not_its_target_is_refused(self):
        import base64
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        auth = base64.b64encode(f"stuntkey:{TOKEN}".encode()).decode()
        s.sendall(("CONNECT api.github.com:443 HTTP/1.1\r\nHost: evil.example:443\r\n"
                   f"Proxy-Authorization: Basic {auth}\r\n\r\n").encode())
        s.settimeout(5)
        self.assertIn(b" 403 ", s.recv(4096).split(b"\r\n")[0])
        s.close()

    def test_local_only_connect_rules(self):
        class H(dict):
            def get(self, k, d=None):
                return dict.get(self, k, d)
        self.assertTrue(httpd.local_only(H(Host="a.com:443"), 1, connect_target="a.com:443"))
        self.assertFalse(httpd.local_only(H(Host="b.com:443"), 1, connect_target="a.com:443"))
        self.assertFalse(httpd.local_only(H(Host="a.com:443", Origin="x"), 1,
                                          connect_target="a.com:443"))


class Splice(_Base):
    def test_a_peer_that_never_reads_cannot_hold_the_tunnel_for_ever(self):
        a_out, a_in = socket.socketpair()      # data enters at a_out, read from a_in
        b_in, b_out = socket.socketpair()      # written to b_in, nobody reads b_out
        for s in (b_in, a_in):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        result = {}

        def run():
            result["n"] = proxy._splice(a_in, b_in, idle=30, send_timeout=0.5, max_seconds=30)
        t = threading.Thread(target=run, daemon=True)
        t.start()

        def flood():
            try:
                for _ in range(2000):
                    a_out.sendall(b"x" * 65536)
            except OSError:
                pass
        threading.Thread(target=flood, daemon=True).start()
        t.join(20)
        self.assertFalse(t.is_alive(), "the tunnel blocked for ever on a stuck write")
        self.assertIn("n", result)
        for s in (a_in, b_in):
            self.assertEqual(s.fileno(), -1)             # both sides closed
        for s in (a_out, b_out):
            s.close()

    def test_an_idle_tunnel_is_closed(self):
        a1, a2 = socket.socketpair()
        b1, b2 = socket.socketpair()
        started = time.monotonic()
        self.assertEqual(proxy._splice(a2, b1, idle=0.3, send_timeout=1, max_seconds=5), 0)
        self.assertLess(time.monotonic() - started, 4)
        for s in (a1, b2):
            s.close()

    def test_the_total_time_is_capped(self):
        a1, a2 = socket.socketpair()
        b1, b2 = socket.socketpair()
        started = time.monotonic()
        proxy._splice(a2, b1, idle=30, send_timeout=1, max_seconds=0.4)
        self.assertLess(time.monotonic() - started, 5)
        for s in (a1, b2):
            s.close()


class ChildEnvTunnel(_Base):
    def test_outside_proxy_settings_do_not_survive_the_tunnel(self):
        src = {"ALL_PROXY": "http://other:1", "all_proxy": "http://other:1",
               "HTTP_PROXY": "http://other:1", "NO_PROXY": "*", "no_proxy": ".com",
               "HTTPS_PROXY": "http://other:1", "PATH": "p"}
        env = proxy.child_env(CATALOG, "http://127.0.0.1:5", TOKEN, src, tunnel=True)
        up = {k.upper(): v for k, v in env.items()}
        self.assertNotIn("ALL_PROXY", up)
        self.assertNotIn("HTTP_PROXY", up)
        self.assertEqual(up["NO_PROXY"], proxy.LOOPBACK)
        self.assertIn("@127.0.0.1:5", up["HTTPS_PROXY"])

    def test_without_the_tunnel_the_parent_proxy_is_still_passed(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:5", TOKEN,
                              {"HTTP_PROXY": "http://other:1", "PATH": "p"})
        self.assertEqual({k.upper(): v for k, v in env.items()}["HTTP_PROXY"], "http://other:1")


class PrintEnv(_Base):
    def test_print_env_is_flushed_when_piped(self):
        class Counting(io.StringIO):
            flushes = 0

            def flush(self):
                Counting.flushes += 1
                super().flush()
        home = _isolation.mktemp()
        args = argparse.Namespace(command=[], print_env=True, env_file=".env",
                                  keep_env=None, generic=False, map=None, tunnel=False,
                                  allow_host=None, port=0)
        out, err = Counting(), io.StringIO()
        seen = {}

        def fake_serve(srv):
            seen["flushed_before_serving"] = Counting.flushes
            srv.server_close()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err), \
                mock.patch.object(httpd, "serve_forever", fake_serve):
            self.assertEqual(proxy.cmd_proxy(CATALOG, args, home), 0)
        self.assertIn("OPENAI_BASE_URL=", out.getvalue())
        self.assertGreaterEqual(seen["flushed_before_serving"], 1)
        self.assertIn("permission window", err.getvalue())    # the clear notice
        self.assertNotIn(CANARY, out.getvalue())

    def test_port_in_use_is_plain_words(self):
        blocker = httpd.DoorServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        self.addCleanup(blocker.server_close)
        port = blocker.server_address[1]
        home = _isolation.mktemp()
        args = argparse.Namespace(command=[], print_env=True, env_file=".env",
                                  keep_env=None, generic=False, map=None, tunnel=False,
                                  allow_host=None, port=port)
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            self.assertEqual(proxy.cmd_proxy(CATALOG, args, home), 1)
        self.assertIn(f"Something else is using port {port}", err.getvalue())
        self.assertIn("--port", err.getvalue())

    def test_door_port_in_use_raises_the_plain_error(self):
        blocker = httpd.DoorServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        self.addCleanup(blocker.server_close)
        port = blocker.server_address[1]
        with self.assertRaises(httpd.PortBusy) as cm:
            httpd.make_server(CATALOG, lambda r: {}, "t" * 43, broker.Policy(), port=port)
        self.assertIn(f"Something else is using port {port}", str(cm.exception))


class ApproveGuards(_Base):
    stub_dialog = False

    def fake_run_ok(self):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "button returned:Yes", "")
        return calls, run

    def test_no_window_setting_is_honoured(self):
        calls, run = self.fake_run_ok()
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"STUNTKEY_NO_WINDOW": "1"}), \
                mock.patch.object(approve.subprocess, "run", run), \
                mock.patch.object(approve, "_tool", lambda *p: "/fake/tool"), \
                mock.patch.object(sys, "stderr", err):
            self.assertIs(approve.dialog("do something"), False)
            self.assertIs(approve.ask_person("do something"), False)   # no console fall-back
        self.assertEqual(calls, [])
        self.assertIn("STUNTKEY_NO_WINDOW", err.getvalue())

    def test_too_many_windows_in_a_minute_are_refused_unseen(self):
        calls, run = self.fake_run_ok()
        err = io.StringIO()
        with mock.patch.object(approve.subprocess, "run", run), \
                mock.patch.object(approve, "_tool", lambda *p: "/fake/tool"), \
                mock.patch.object(sys, "stderr", err):
            results = [approve.dialog(f"ask {i}") for i in range(approve.MAX_WINDOWS_PER_MINUTE + 3)]
        self.assertEqual(len(calls), approve.MAX_WINDOWS_PER_MINUTE)
        self.assertEqual(results[:approve.MAX_WINDOWS_PER_MINUTE],
                         [True] * approve.MAX_WINDOWS_PER_MINUTE)
        self.assertEqual(results[approve.MAX_WINDOWS_PER_MINUTE:], [False] * 3)
        self.assertIn("too many permission windows", err.getvalue())

    def test_the_window_count_forgets_after_a_minute(self):
        with approve._shown_lock:
            approve._shown[:] = [time.monotonic() - 120] * approve.MAX_WINDOWS_PER_MINUTE
        self.assertFalse(approve._too_many_windows())


class PageCookie(_Base):
    def make(self):
        srv = httpd.make_server(CATALOG, lambda r: {}, "t" * 43, broker.Policy(),
                                page_status=lambda: {"keys": []}, version="1")
        httpd.start_background(srv)
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close()))
        return srv

    def get(self, srv, path, cookie=None):
        port = srv.server_address[1]
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        h = {"Cookie": cookie} if cookie else {}
        c.request("GET", path, headers=h)
        r = c.getresponse()
        r.read()
        return r

    def exchange(self, srv):
        r = self.get(srv, "/?c=" + srv.new_launch_code())
        self.assertEqual(r.status, 303)
        setc = r.getheader("Set-Cookie")
        return setc, setc.split(";")[0]

    def test_cookie_has_max_age_and_a_port_bound_name(self):
        srv = self.make()
        setc, pair = self.exchange(srv)
        self.assertIn("Max-Age=", setc)
        self.assertTrue(pair.startswith(f"sk_page_{srv.server_address[1]}="))
        self.assertEqual(self.get(srv, "/", pair).status, 200)

    def test_each_link_exchange_rotates_the_cookie(self):
        srv = self.make()
        _, first = self.exchange(srv)
        _, second = self.exchange(srv)
        self.assertNotEqual(first, second)
        self.assertEqual(self.get(srv, "/", second).status, 200)
        self.assertEqual(self.get(srv, "/", first).status, 401)      # the old one is dead

    def test_a_cookie_from_another_server_is_not_accepted(self):
        a, b = self.make(), self.make()
        _, pair_a = self.exchange(a)
        value = pair_a.split("=", 1)[1]
        self.assertEqual(self.get(b, "/", f"sk_page_{b.server_address[1]}={value}").status, 401)
        self.assertEqual(self.get(b, "/", f"sk_page={value}").status, 401)

    def test_the_cookie_is_not_derived_from_the_token(self):
        import hashlib
        import hmac
        srv = self.make()
        _, pair = self.exchange(srv)
        old_style = hmac.new(("t" * 43).encode(), b"stuntkey page cookie",
                             hashlib.sha256).hexdigest()
        self.assertNotIn(old_style, pair)

    def test_it_expires(self):
        srv = self.make()
        _, pair = self.exchange(srv)
        real = time.time
        with mock.patch.object(httpd.time, "time", lambda: real() + httpd.PAGE_COOKIE_SECONDS + 5):
            self.assertEqual(self.get(srv, "/", pair).status, 401)


class CapDefaults(_Base):
    def setUp(self):
        super().setUp()
        self.home = _isolation.mktemp()

    def test_defaults_exist_without_a_caps_file(self):
        self.assertFalse(os.path.exists(caps.caps_path(self.home)))
        eff = caps.effective_caps(self.home, "github")
        self.assertEqual(eff["calls_hour"], 300)
        self.assertEqual(eff["calls_day"], 5000)

    def test_the_hourly_default_stops_the_301st_call_and_leaves_a_notice(self):
        for i in range(300):
            caps.begin(self.home, "github", i)
        with self.assertRaises(broker.BrokerError) as cm:
            caps.begin(self.home, "github", 300)
        self.assertIn("300 calls this hour", str(cm.exception))
        self.assertTrue(any("300 calls this hour" in n for n in caps.recent_notices(self.home)))
        caps.begin(self.home, "openai", 0)               # other services are not touched

    def test_caps_json_overrides_a_default(self):
        with open(caps.caps_path(self.home), "w", encoding="utf-8") as f:
            json.dump({"github": {"calls_hour": 2}}, f)
        caps.begin(self.home, "github", 0)
        caps.begin(self.home, "github", 1)
        with self.assertRaises(broker.BrokerError):
            caps.begin(self.home, "github", 2)

    def test_notices_are_deduplicated_and_trimmed(self):
        caps.notice(self.home, "same", now=1000.0)
        caps.notice(self.home, "same", now=1001.0)
        self.assertEqual(len(caps.recent_notices(self.home)), 1)
        for i in range(80):
            caps.notice(self.home, f"n{i}", now=2000.0 + i)
        self.assertLessEqual(len(caps.recent_notices(self.home, 500)), caps.MAX_NOTICES)

    def test_caps_show_prints_the_standard_caps_and_notices(self):
        caps.begin(self.home, "github", 0)
        caps.notice(self.home, "a plain notice")
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out):
            caps.cmd_caps(argparse.Namespace(caps_cmd="show"), self.home, lambda s: False)
        self.assertIn("calls_hour=300", out.getvalue())
        self.assertIn("a plain notice", out.getvalue())

    def test_the_cli_knows_calls_hour(self):
        p = argparse.ArgumentParser()
        sub = p.add_subparsers(dest="cmd")
        proxy.add_parsers(sub)
        a = p.parse_args(["caps", "set", "github", "--calls-hour", "50"])
        self.assertEqual(a.calls_hour, 50)
        self.assertEqual(p.parse_args(["proxy", "--port", "9123"]).port, 9123)


class RunnerSinks(_Base):
    def test_a_text_only_stream_gets_the_output(self):
        sink = io.StringIO()
        code = runner.run_redacted(
            [sys.executable, "-c", "print('hello from child')"], dict(os.environ),
            [CANARY], stdout=sink, stderr=io.StringIO())
        self.assertEqual(code, 0)
        self.assertIn("hello from child", sink.getvalue())

    def test_a_secret_is_still_scrubbed_on_a_text_stream(self):
        sink = io.StringIO()
        runner.run_redacted([sys.executable, "-c", f"print({CANARY!r})"],
                            dict(os.environ), [CANARY], stdout=sink, stderr=io.StringIO())
        self.assertNotIn(CANARY, sink.getvalue())

    def test_a_bug_in_the_copy_loop_is_loud_not_hidden(self):
        class Broken:
            def write(self, data):
                raise TypeError("boom")

            def flush(self):
                pass
        with self.assertRaises(TypeError):
            runner.run_redacted([sys.executable, "-c", "print('x')"], dict(os.environ),
                                [CANARY], stdout=Broken(), stderr=io.StringIO())

    def test_a_byte_stream_is_used_as_is(self):
        sink = io.BytesIO()
        runner.run_redacted([sys.executable, "-c", "print('bytes ok')"], dict(os.environ),
                            [CANARY], stdout=sink, stderr=io.BytesIO())
        self.assertIn(b"bytes ok", sink.getvalue())


class OutgoingKeyCheck(_Base):
    def test_reversed_and_partial_and_encoded_keys_are_caught(self):
        values = {"X_API_KEY": CANARY}
        has = mcp._outgoing_has_key
        self.assertTrue(has(values, "/v1/x/" + CANARY))
        self.assertTrue(has(values, "/v1/x", None, json.dumps({"k": CANARY[::-1]})))
        self.assertTrue(has(values, "/v1/x/" + CANARY[:34]))                 # a long piece
        self.assertTrue(has(values, "/v1/x", json.dumps({"q": CANARY.replace("-", " - ")})))
        import urllib.parse
        self.assertTrue(has(values, "/v1/x/" + urllib.parse.quote(CANARY, safe="")))
        self.assertTrue(has(values, "/v1/x/" + CANARY[::-1][:34]))            # reversed piece

    def test_a_normal_request_passes(self):
        values = {"X_API_KEY": CANARY}
        self.assertFalse(mcp._outgoing_has_key(values, "/user/repos",
                                               '{"per_page": 5}', '{"title": "hello"}'))
        self.assertFalse(mcp._outgoing_has_key(values, "/v1/x", None, None))

    def test_a_key_shaped_text_is_caught_even_when_not_stored(self):
        ghp = "ghp_" + "Ab1" * 12
        self.assertTrue(mcp._outgoing_has_key({}, "/x", None, json.dumps({"t": ghp})))
        self.assertTrue(mcp._outgoing_has_key({}, "/x", None, json.dumps({"t": ghp[::-1]})))

    def test_call_api_refuses_before_any_network_call(self):
        recipe = CATALOG["github"]
        values = {recipes.env_vars(recipe)[0]: CANARY}
        with mock.patch("stuntkey.remote.collect_values", lambda r, f: values), \
                mock.patch.object(broker, "call", _no_real_window):
            out = mcp._call_api(CATALOG, {"service": "github", "method": "GET",
                                          "path": "/user/" + CANARY[::-1]})
        self.assertTrue(out["isError"])
        text = out["content"][0]["text"]
        self.assertIn("no call was made", text)
        self.assertNotIn(CANARY, text)


if __name__ == "__main__":
    unittest.main()
