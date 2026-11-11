"""Round 11, proxy/environment seat: allow-list child environment, generic
mode and the host-allow-list tunnel, canary keys that must never leak, caps
and MCP failing closed with plain words, tool output scrubbed.

Every key here is a synthetic canary built at run time."""
import base64
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE/APPDATA for the whole run)
from stuntkey import broker, caps, mcp, proxy, recipes, remote, scrub

CATALOG = recipes.load_recipes()
CANARY = "sk-" + "FAKE0000TEST1111CANARY2222abcd3333"
GH = "ghp_" + "FAKE0000TEST1111CANARY2222abcd3333wxyz"
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("104.18.6.192", port))]
TOKEN = "ok-test-token-r11-0000000000"


def parent_env(**extra):
    env = dict(os.environ)
    env.update(extra)
    return env


class AllowListEnv(unittest.TestCase):
    def test_secret_looking_names_never_pass(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:1", TOKEN, parent_env(
            GITHUB_TOKEN=CANARY, AWS_SECRET_ACCESS_KEY=CANARY, NPM_TOKEN=CANARY,
            DATABASE_PASSWORD=CANARY, MY_APP_SECRET=CANARY, RANDOM_THING=CANARY,
            SLACK_BOT_TOKEN=CANARY, OPENAI_API_KEY=CANARY, ANTHROPIC_AUTH_TOKEN=CANARY))
        self.assertNotIn(CANARY, json.dumps(env))
        self.assertNotIn("RANDOM_THING", env)             # allow-list, not block-list
        self.assertTrue(env["OPENAI_API_KEY"].startswith("ok-"))

    def test_basics_pass(self):
        src = {"PATH": "p", "SystemRoot": r"C:\Windows", "TEMP": "t", "HOME": "h",
               "USERPROFILE": "u", "LANG": "C", "LC_FOO": "x", "PYTHONUTF8": "1"}
        env = proxy.child_env(CATALOG, "http://127.0.0.1:1", TOKEN, src)
        for name, value in src.items():
            self.assertEqual(env.get(name), value, name)

    def test_keep_env_is_exact_and_explicit(self):
        src = {"MY_DEPLOY_TOKEN": CANARY, "OTHER": "v", "OPENAI_API_KEY": CANARY}
        env = proxy.child_env(CATALOG, "http://127.0.0.1:1", TOKEN, src,
                              keep=["my_deploy_token", "OTHER", "OPENAI_API_KEY", "MY_*"])
        self.assertEqual(env["MY_DEPLOY_TOKEN"], CANARY)  # named: passes (any case)
        self.assertEqual(env["OTHER"], "v")
        self.assertNotEqual(env["OPENAI_API_KEY"], CANARY)  # a brokered key never passes

    def test_keep_env_from_the_environment_setting(self):
        with mock.patch.dict(os.environ, {proxy.KEEP_ENV_VAR: "FOO; BAR"}):
            env = proxy.child_env(CATALOG, "http://127.0.0.1:1", TOKEN,
                                  {"FOO": "1", "BAR": "2", "BAZ": "3"})
        self.assertEqual((env["FOO"], env["BAR"], "BAZ" in env), ("1", "2", False))

    def test_a_stored_key_format_in_an_allowed_name_is_dropped(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:1", TOKEN,
                              {"TEMP": GH, "TMP": "fine"})
        self.assertNotIn("TEMP", env)
        self.assertEqual(env["TMP"], "fine")

    def test_parent_proxy_with_a_password_is_not_passed(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:1", TOKEN,
                              {"HTTP_PROXY": "http://user:" + CANARY + "@corp:8080",
                               "HTTPS_PROXY": "http://corp:8080"})
        self.assertNotIn(CANARY, json.dumps(env))
        self.assertEqual(env["HTTPS_PROXY"], "http://corp:8080")
        self.assertIn("127.0.0.1", env["NO_PROXY"])       # loopback is never proxied

    def test_stuntkey_settings_stay_behind(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:1", TOKEN,
                              {"STUNTKEY_ENV_FILE": "x", "STUNTKEY_KEYCHAIN": "y"})
        self.assertFalse([k for k in env if k.startswith("STUNTKEY_")])

    def test_real_dev_tools_still_work_in_that_environment(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:1", TOKEN, parent_env(
            GITHUB_TOKEN=CANARY, AWS_ACCESS_KEY_ID=CANARY, NPM_TOKEN=CANARY))
        probes = [[sys.executable, "-c",
                   "import os,sys;sys.exit(1 if any('FAKE0000' in v for v in os.environ.values()) else 0)"],
                  # pip is only imported here (a test that RUNS pip must pass --no-build-isolation)
                  [sys.executable, "-c", "import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('pi'+'p') else 1)"]]
        for exe in ("git", "node"):
            if shutil.which(exe, path=env.get("PATH")):
                probes.append([exe, "--version"])
        for cmd in probes:
            done = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(done.returncode, 0, (cmd, done.stderr[-300:]))
            self.assertNotIn("FAKE0000", done.stdout + done.stderr)

    def test_cmd_proxy_real_child_sees_no_canary(self):
        out = os.path.join(_isolation.mktemp(), "env.json")
        code = "import os,json,sys; json.dump(dict(os.environ), open(sys.argv[1],'w'))"
        args = mock.Mock(command=["--", sys.executable, "-c", code, out],
                         env_file=".env", print_env=False, keep_env=None, map=None,
                         generic=False, tunnel=False, allow_host=None)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": CANARY, "GITHUB_TOKEN": CANARY,
                                          "FOO_SECRET": CANARY}), \
                mock.patch("stuntkey.remote.collect_values",
                           lambda r, f: {"OPENAI_API_KEY": CANARY}):
            self.assertEqual(proxy.cmd_proxy(CATALOG, args, _isolation.mktemp()), 0)
        with open(out, encoding="utf-8") as f:
            self.assertNotIn("FAKE0000", f.read())


class GenericMode(unittest.TestCase):
    def test_map_points_any_sdk_variable_at_the_proxy(self):
        svc = next(s for s, r in CATALOG.items() if proxy.proxyable(r))
        maps = proxy.parse_map([f"MY_BASE_URL={svc}/v1"], CATALOG)
        env = proxy.child_env(CATALOG, "http://127.0.0.1:9", TOKEN, {}, maps=maps)
        self.assertEqual(env["MY_BASE_URL"], f"http://127.0.0.1:9/{svc}/v1")
        for var in recipes.env_vars(CATALOG[svc]):
            self.assertEqual(env[var], TOKEN)             # a placeholder, never the key

    def test_map_refuses_bad_input(self):
        svc = next(s for s, r in CATALOG.items() if proxy.proxyable(r))
        for bad in ("NOEQUALS", "X_API_KEY=" + svc, "A B=" + svc, "A=nosuchservice",
                    f"A={svc}/../x", f"A={svc}/a b"):
            with self.assertRaises(ValueError, msg=bad):
                proxy.parse_map([bad], CATALOG)

    def test_generic_gives_placeholders_and_addresses(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:9", TOKEN,
                              {"GITHUB_TOKEN": CANARY}, generic=True)
        self.assertNotIn(CANARY, json.dumps(env))
        carried = [s for s, r in CATALOG.items() if proxy.proxyable(r)]
        self.assertTrue(carried)
        for s in carried:
            self.assertEqual(env[f"STUNTKEY_URL_{proxy._slug_var(s)}"],
                             f"http://127.0.0.1:9/{s}")

    def test_unsigned_services_are_never_carried(self):
        for s, r in CATALOG.items():
            if (r.get("validate") or {}).get("auth", {}).get("type") in proxy.NO_PROXY_AUTH:
                self.assertFalse(proxy.proxyable(r), s)

    def test_tunnel_hosts_validation(self):
        hosts = proxy.tunnel_hosts(CATALOG, ["API.Example.com"])
        self.assertIn("api.example.com", hosts)
        for bad in ("localhost", "a b.com", "http://x.com", "*.example.com", ""):
            with self.assertRaises(ValueError, msg=bad):
                proxy.tunnel_hosts(CATALOG, [bad])


class Upstream(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        data = json.dumps({"echo": CANARY, "auth": self.headers.get("Authorization", "")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Request-Id", CANARY)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class CanaryThroughTheProxy(unittest.TestCase):
    def setUp(self):
        self.up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.home = _isolation.mktemp()
        self.audit = broker.AuditLog(os.path.join(self.home, "audit.log"))
        pol = broker.Policy(home=self.home, project_dir=self.home, max_calls=100)
        connect = lambda host, timeout: http.client.HTTPConnection(
            "127.0.0.1", self.up.server_address[1], timeout=timeout)
        self.srv = proxy.make_proxy(CATALOG, lambda r: {"OPENAI_API_KEY": CANARY},
                                    TOKEN, pol, self.audit, resolver=PUBLIC, connect=connect)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        for s in (self.srv, self.up):
            s.shutdown()
            s.server_close()

    def test_key_echoed_by_the_api_or_put_in_the_path_never_gets_out(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", "/openai/v1/models/" + CANARY,
                  headers={"Authorization": "Bearer " + TOKEN})
        r = c.getresponse()
        raw = r.read().decode() + json.dumps(dict(r.getheaders()))
        self.assertNotIn(CANARY, raw)
        with open(self.audit.path, encoding="utf-8") as f:
            self.assertNotIn(CANARY, f.read())

    def test_unknown_service_error_does_not_echo_the_path(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request("GET", "/" + CANARY + "/x", headers={"Authorization": "Bearer " + TOKEN})
        self.assertNotIn(CANARY, c.getresponse().read().decode())


class Tunnel(unittest.TestCase):
    def setUp(self):
        self.echo = socket.socket()
        self.echo.bind(("127.0.0.1", 0))
        self.echo.listen(5)
        threading.Thread(target=self._serve_echo, daemon=True).start()
        self.home = _isolation.mktemp()
        self.audit = broker.AuditLog(os.path.join(self.home, "audit.log"))
        self.pol = broker.Policy(home=self.home, project_dir=self.home, max_calls=100)
        self.hosts = proxy.tunnel_hosts(CATALOG, ["api.example.com"])
        self.srv = proxy.make_proxy(
            CATALOG, lambda r: {}, TOKEN, self.pol, self.audit, resolver=PUBLIC,
            tunnel=self.hosts,
            tunnel_connect=lambda ip, port: socket.create_connection(
                ("127.0.0.1", self.echo.getsockname()[1]), 5))
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def _serve_echo(self):
        while True:
            try:
                conn, _ = self.echo.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data.upper())
        except OSError:
            pass
        finally:
            conn.close()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.echo.close()

    def connect(self, target, token=TOKEN):
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        auth = ""
        if token is not None:
            auth = "Proxy-Authorization: Basic " + base64.b64encode(
                f"stuntkey:{token}".encode()).decode() + "\r\n"
        s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n".encode())
        s.settimeout(5)
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            if not chunk:
                break
            head += chunk
        return s, head

    def test_allowed_host_is_tunnelled(self):
        s, head = self.connect("api.example.com:443")
        self.assertIn(b" 200 ", head.split(b"\r\n")[0])
        s.sendall(b"hello")
        self.assertEqual(s.recv(100), b"HELLO")
        s.close()

    def test_a_host_not_on_the_list_is_refused(self):
        s, head = self.connect("evil.example.net:443")
        self.assertIn(b" 403 ", head.split(b"\r\n")[0])
        s.close()

    def test_only_port_443(self):
        s, head = self.connect("api.example.com:22")
        self.assertIn(b" 403 ", head.split(b"\r\n")[0])
        s.close()

    def test_wrong_or_missing_password_is_refused(self):
        for token in (None, "wrong"):
            s, head = self.connect("api.example.com:443", token)
            self.assertIn(b" 407 ", head.split(b"\r\n")[0])
            s.close()

    def test_stop_switch_blocks_the_tunnel(self):
        caps.cmd_stop(self.pol.limits_home())
        s, head = self.connect("api.example.com:443")
        self.assertIn(b" 403 ", head.split(b"\r\n")[0])
        body = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                body += chunk
        except OSError:
            pass
        self.assertIn(b"stuntkey stop", head.partition(b"\r\n\r\n")[2] + body)
        s.close()

    def test_private_address_is_refused(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.srv = proxy.make_proxy(
            CATALOG, lambda r: {}, TOKEN, self.pol, self.audit,
            resolver=lambda h, p, **k: [(2, 1, 6, "", ("10.0.0.5", p))], tunnel=self.hosts)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        s, head = self.connect("api.example.com:443")
        self.assertIn(b" 403 ", head.split(b"\r\n")[0])
        s.close()

    def test_tunnel_off_by_default(self):
        pol = broker.Policy(home=self.home, project_dir=self.home)
        srv = proxy.make_proxy(CATALOG, lambda r: {}, TOKEN, pol)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            s = socket.create_connection(("127.0.0.1", srv.server_address[1]), 5)
            s.sendall(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n")
            self.assertIn(b" 403 ", s.recv(4096).split(b"\r\n")[0])
            s.close()
        finally:
            srv.shutdown()
            srv.server_close()


class CapsFailClosed(unittest.TestCase):
    def test_unwritable_usage_record_refuses_in_plain_words(self):
        home = _isolation.mktemp()
        with mock.patch.object(caps, "_write_usage", side_effect=OSError("disk full")):
            with self.assertRaises(broker.BrokerError) as e:
                caps.begin(home, "openai", 0)
        self.assertIn("no call was made", str(e.exception))
        self.assertNotIn("disk full", str(e.exception))
        self.assertEqual(e.exception.code, 5)

    def test_stop_that_cannot_be_written_says_so(self):
        with mock.patch("builtins.open", side_effect=OSError("denied")):
            self.assertNotEqual(caps.cmd_stop(_isolation.mktemp()), 0)

    def test_damaged_caps_file_refuses(self):
        home = _isolation.mktemp()
        with open(caps.caps_path(home), "w") as f:
            f.write("{not json")
        with self.assertRaises(broker.BrokerError):
            caps.begin(home, "openai", 0)


def call_tool(name, arguments, **kw):
    return mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}, CATALOG, **kw)


class McpFailsClosedAndScrubs(unittest.TestCase):
    def test_locked_keychain_is_not_reported_as_no_key(self):
        err = remote.RemoteError("the OS keychain did not answer (locked); unlock it.", 1)
        with mock.patch("stuntkey.remote.collect_values", side_effect=err):
            r = call_tool("call_api", {"service": "openai", "method": "GET", "path": "/v1/models"})
        text = r["result"]["content"][0]["text"]
        self.assertTrue(r["result"]["isError"])
        self.assertIn("password vault", text)
        self.assertNotIn("No key is saved", text)

    def test_directory_text_that_looks_like_a_key_is_masked(self):
        entry = {"name": "Evil API", "description": "use token " + GH + " now",
                 "auth": "No", "url": "https://example.com/?k=" + GH, "category": "x"}
        r = call_tool("get_public_api", {"name": "Evil API"}, pa_loader=lambda: [entry])
        text = r["result"]["content"][0]["text"]
        self.assertNotIn(GH, text)
        json.loads(text)                                   # still valid JSON

    def test_search_results_are_masked_too(self):
        entry = {"name": "Evil API", "description": GH, "auth": "No",
                 "url": "https://example.com", "category": "x"}
        r = call_tool("find_public_apis", {"query": "evil"}, pa_loader=lambda: [entry])
        self.assertNotIn(GH, r["result"]["content"][0]["text"])

    def test_a_stored_key_echoed_back_is_masked_by_fingerprint(self):
        odd = "Zq9-" + "fake-stored-canary-" + "7Xk2mP4wL8"
        scrub.remember_key("R11_CANARY", odd)
        try:
            entry = {"name": "Evil API", "description": "see " + odd, "auth": "No",
                     "url": "https://example.com", "category": "x"}
            r = call_tool("get_public_api", {"name": "Evil API"}, pa_loader=lambda: [entry])
            self.assertNotIn(odd, r["result"]["content"][0]["text"])
        finally:
            scrub.forget_key("R11_CANARY")

    def test_errors_are_masked(self):
        def boom():
            raise RuntimeError("failed with " + GH)
        r = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "find_public_apis", "arguments": {"query": "x"}}},
                       CATALOG, pa_loader=boom)
        self.assertNotIn(GH, json.dumps(r))

    def test_if_the_check_breaks_nothing_is_passed_on(self):
        with mock.patch.object(scrub, "load_fingerprints", side_effect=RuntimeError("x")):
            text = mcp._guard("anything", CATALOG)
        self.assertEqual(text, mcp.WITHHELD)


if __name__ == "__main__":
    unittest.main()
