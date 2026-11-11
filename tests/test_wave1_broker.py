"""Route policy, caps + kill switch, and the base-URL proxy."""
import hashlib
import http.client
import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import broker, caps, proxy, recipes
from stuntkey import policy as route

KEY = "sk-" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6"     # built at run time
CATALOG = recipes.load_recipes()
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("104.18.6.192", port))]
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def write(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        f.write(obj if isinstance(obj, str) else json.dumps(obj))


def approve_all(home, proj):
    route.approve(home, proj, lambda s: True)


def fake_send(body=b"{}", ctype="application/json"):
    return lambda req, ip, timeout: (200, {"content-type": ctype}, body)


def call(pol, path="/v1/models", method="GET", body=None, send=None):
    return broker.call(CATALOG["openai"], {"OPENAI_API_KEY": KEY}, method, path,
                       body=body, policy=pol, send=send or fake_send(),
                       resolver=PUBLIC)


class RoutePolicy(unittest.TestCase):
    def setUp(self):
        self.home, self.proj = _isolation.mktemp(), _isolation.mktemp()
        self.pol = broker.Policy(allow_write=True, home=self.home, project_dir=self.proj)

    def test_no_policy_changes_nothing(self):
        self.assertEqual(call(self.pol)["status"], 200)

    def test_deny_by_default_once_a_rule_exists(self):
        write(route.user_file(self.home), {"openai": {"methods": ["GET"], "paths": ["/v1/models"]}})
        approve_all(self.home, self.proj)
        self.assertEqual(call(self.pol, "/v1/models/gpt")["status"], 200)
        for path, method in (("/v1/files", "GET"), ("/v1/modelsX", "GET"),
                             ("/v1/models", "DELETE")):
            with self.assertRaises(broker.BrokerError, msg=path) as e:
                call(self.pol, path, method)
            self.assertIn("policy does not allow", str(e.exception))

    def test_project_file_only_narrows(self):
        write(route.user_file(self.home), {"openai": {"methods": ["GET"], "paths": ["/v1"]}})
        write(route.project_file(self.proj), {"openai": {
            "methods": ["GET", "POST", "DELETE"], "paths": ["/v1/models", "/v2", "/"]}})
        approve_all(self.home, self.proj)
        rules = route.load(self.home, self.proj)
        self.assertEqual(rules["openai"][0], {"GET"})
        self.assertEqual(call(self.pol, "/v1/models")["status"], 200)
        for path, method in (("/v2/x", "GET"), ("/v1/models", "DELETE")):
            with self.assertRaises(broker.BrokerError):
                call(self.pol, path, method)
        # "/" in the project file narrows back to the user's "/v1", not wider
        self.assertIn("/v1", rules["openai"][1])

    def test_unapproved_or_changed_file_refuses_everything(self):
        p = route.user_file(self.home)
        write(p, {"openai": {"methods": ["GET"], "paths": ["/"]}})
        with self.assertRaises(broker.BrokerError) as e:
            call(self.pol)
        self.assertIn("not approved", str(e.exception))
        approve_all(self.home, self.proj)
        call(self.pol)
        write(p, {"openai": {"methods": ["GET", "POST"], "paths": ["/"]}})   # an AI widens it
        with self.assertRaises(broker.BrokerError):
            call(self.pol)

    def test_approval_needs_the_person(self):
        write(route.user_file(self.home), {"openai": {"methods": ["GET"], "paths": ["/"]}})
        self.assertEqual(route.approve(self.home, self.proj, lambda s: False), 0)
        with self.assertRaises(broker.BrokerError):
            call(self.pol)


class Caps(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()
        self.pol = broker.Policy(home=self.home, project_dir=self.home)

    def set_caps(self, **c):
        write(caps.caps_path(self.home), {"openai": c})

    def test_session_cap(self):
        self.set_caps(calls_session=2)
        call(self.pol)
        call(self.pol)
        with self.assertRaises(broker.BrokerError) as e:
            call(self.pol)
        self.assertIn("reached its cap of 2 calls this session", str(e.exception))
        call(broker.Policy(home=self.home, project_dir=self.home))   # a new session

    def test_tokens_counted_from_usage(self):
        self.set_caps(tokens_day=30)
        body = json.dumps({"usage": {"prompt_tokens": 20, "completion_tokens": 15}}).encode()
        call(self.pol, send=fake_send(body))
        self.assertEqual(caps.usage(self.home, "openai")["tokens"], 35)
        with self.assertRaises(broker.BrokerError) as e:
            call(self.pol)
        self.assertIn("tokens today", str(e.exception))

    def test_token_meter_shapes(self):
        anthropic_sse = (b'event: message_start\ndata: {"type":"message_start","message":'
                         b'{"usage":{"input_tokens":25,"output_tokens":1}}}\n\n'
                         b'event: message_delta\ndata: {"type":"message_delta",'
                         b'"usage":{"output_tokens":15}}\n\n')
        responses_sse = (b'data: {"type":"response.completed","response":'
                         b'{"usage":{"input_tokens":7,"output_tokens":3}}}\n\n')
        m = caps.TokenMeter("text/event-stream")
        for i in range(0, len(anthropic_sse), 7):        # split anywhere
            m.feed(anthropic_sse[i:i + 7])
        self.assertEqual(m.total(), 40)
        self.assertEqual(caps.tokens_in("text/event-stream", responses_sse), 10)
        self.assertEqual(caps.tokens_in("application/json",
                                        b'{"usage":{"input_tokens":4,"output_tokens":2}}'), 6)
        self.assertEqual(caps.tokens_in("application/json", b"not json"), 0)

    def test_day_cap_is_shared_across_processes(self):
        self.set_caps(calls_day=5)
        code = ("import sys; from stuntkey import caps, broker\n"
                "ok = 0\n"
                "for _ in range(4):\n"
                "    try:\n"
                "        caps.begin(sys.argv[1], 'openai', 0); ok += 1\n"
                "    except broker.BrokerError: pass\n"
                "print(ok)\n")
        procs = [subprocess.Popen([sys.executable, "-c", code, self.home], cwd=REPO,
                                  stdout=subprocess.PIPE, text=True) for _ in range(2)]
        total = sum(int(p.communicate(timeout=60)[0]) for p in procs)
        self.assertEqual(total, 5)
        self.assertEqual(caps.usage(self.home, "openai")["calls"], 5)

    def test_stop_and_resume(self):
        caps.cmd_stop(self.home)
        with self.assertRaises(broker.BrokerError) as e:
            call(self.pol)
        self.assertIn("stuntkey stop", str(e.exception))
        self.assertEqual(caps.cmd_resume(self.home, lambda s: False), 5)  # person says no
        with self.assertRaises(broker.BrokerError):
            call(self.pol)
        self.assertEqual(caps.cmd_resume(self.home, lambda s: True), 0)
        call(self.pol)

    def test_damaged_caps_file_fails_closed(self):
        write(caps.caps_path(self.home), "{not json")
        with self.assertRaises(broker.BrokerError):
            call(self.pol)


# ---- proxy, end to end against a local pretend upstream ------------------------

class Upstream(BaseHTTPRequestHandler):
    seen = []
    release = threading.Event()

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        Upstream.seen.append((self.path, dict(self.headers), self.rfile.read(n)))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Set-Cookie", "session=abc")
        self.send_header("x-ratelimit-remaining", "99")
        self.end_headers()
        pad = "x" * 600
        self.wfile.write(f'data: {{"pad":"{pad}","echo":"{KEY[:10]}'.encode())
        self.wfile.flush()
        # True only if the client already got chunk 1: the proxy did not buffer
        Upstream.streamed = Upstream.release.wait(5)
        self.wfile.write(f'{KEY[10:]}"}}\n\ndata: {{"usage":{{"prompt_tokens":3,'
                         f'"completion_tokens":4}}}}\n\ndata: [DONE]\n\n'.encode())

    do_GET = do_POST


class Proxy(unittest.TestCase):
    TOKEN = "ok-test-token-1234567890"

    def setUp(self):
        Upstream.seen, Upstream.release = [], threading.Event()
        self.up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=self.up.serve_forever, daemon=True).start()
        self.home = _isolation.mktemp()
        self.hosts = []

        def connect(host, timeout):
            self.hosts.append(host)
            return http.client.HTTPConnection("127.0.0.1", self.up.server_address[1],
                                              timeout=timeout)
        self.pol = broker.Policy(home=self.home, project_dir=self.home, max_calls=1000)
        self.audit = broker.AuditLog(os.path.join(self.home, "audit.log"))
        self.srv = proxy.make_proxy(CATALOG, lambda r: {"OPENAI_API_KEY": KEY,
                                                        "ANTHROPIC_API_KEY": KEY},
                                    self.TOKEN, self.pol, self.audit,
                                    resolver=PUBLIC, connect=connect)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        Upstream.release.set()
        for s in (self.srv, self.up):
            s.shutdown()
            s.server_close()

    def open(self, path, method="POST", headers=None, body=b'{"model":"m"}'):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Authorization": f"Bearer {self.TOKEN}", "Content-Type": "application/json"}
        h.update(headers or {})
        c.request(method, path, body=body, headers={k: v for k, v in h.items() if v is not None})
        return c.getresponse()

    def test_end_to_end_streaming_and_scrubbed(self):
        r = self.open("/openai/v1/chat/completions",
                      headers={"Cookie": "a=b", "OpenAI-Organization": "org-x"})
        self.assertEqual(r.status, 200)
        first = b""
        while b'"pad"' not in first:           # chunk 1 arrives before chunk 2 exists
            first += r.read1(4096)
        Upstream.release.set()
        body = (first + r.read()).decode()
        self.assertTrue(Upstream.streamed)
        self.assertNotIn(KEY, body)
        self.assertIn("[REDACTED]", body)
        self.assertIn("[DONE]", body)
        self.assertIsNone(r.getheader("Set-Cookie"))
        self.assertEqual(r.getheader("x-ratelimit-remaining"), "99")
        path, headers, sent = Upstream.seen[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(self.hosts, ["api.openai.com"])
        low = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(low["authorization"], f"Bearer {KEY}")     # real key, added here
        self.assertNotIn("cookie", low)
        self.assertNotIn("openai-organization", low)
        self.assertEqual(sent, b'{"model":"m"}')
        self.assertEqual(caps.usage(self.home, "openai")["tokens"], 7)
        ok, n = self.audit.verify()
        self.assertTrue(ok)
        with open(self.audit.path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("/v1/chat/completions", text)
        self.assertNotIn(KEY, text)

    def test_anthropic_route_uses_x_api_key(self):
        Upstream.release.set()
        r = self.open("/anthropic/v1/messages",
                      headers={"Authorization": None, "x-api-key": self.TOKEN,
                               "anthropic-version": "2023-06-01"})
        r.read()
        self.assertEqual(r.status, 200)
        low = {k.lower(): v for k, v in Upstream.seen[0][1].items()}
        self.assertEqual(low["x-api-key"], KEY)
        self.assertEqual(self.hosts, ["api.anthropic.com"])

    def test_refusals(self):
        Upstream.release.set()
        cases = [("/openai/v1/chat/completions", {"Authorization": "Bearer wrong"}, 401),
                 ("/openai/v1/chat/completions", {"Host": "evil.example"}, 403),
                 ("/openai/v1/chat/completions", {"Origin": "https://evil.example"}, 403),
                 ("/openai/v1/files", {}, 403),                  # not an LLM endpoint
                 ("/openai/v1/a/../b", {}, 403),
                 ("/nosuch/v1/x", {}, 404)]
        for path, h, want in cases:
            r = self.open(path, headers=h)
            r.read()
            self.assertEqual(r.status, want, path)
        self.assertEqual(Upstream.seen, [])

    def test_policy_can_allow_more_writes(self):
        Upstream.release.set()
        # round 12: a policy-allowed non-AI write now asks the person; a stub says yes
        self.pol.approve = lambda *a, **k: True
        write(route.user_file(self.home), {"openai": {"methods": ["POST"], "paths": ["/v1/files"]}})
        approve_all(self.home, self.home)
        r = self.open("/openai/v1/files")
        r.read()
        self.assertEqual(r.status, 200)
        r = self.open("/openai/v1/chat/completions")    # the rule now denies the rest
        r.read()
        self.assertEqual(r.status, 403)

    def test_stop_switch_applies(self):
        caps.cmd_stop(self.home)
        r = self.open("/openai/v1/chat/completions")
        self.assertIn(b"stuntkey stop", r.read())
        self.assertEqual(r.status, 403)

    def test_fails_closed_when_the_proxy_dies(self):
        self.srv.shutdown()
        self.srv.server_close()
        with self.assertRaises(OSError):
            self.open("/openai/v1/chat/completions")


class ChildEnv(unittest.TestCase):
    def test_real_keys_never_reach_the_child(self):
        env = proxy.child_env(CATALOG, "http://127.0.0.1:1", "ok-x",
                              {"OPENAI_API_KEY": KEY, "ANTHROPIC_AUTH_TOKEN": KEY,
                               "GITHUB_TOKEN": KEY, "PATH": "p"})
        self.assertNotIn(KEY, json.dumps(env))
        self.assertEqual(env["OPENAI_BASE_URL"], "http://127.0.0.1:1/openai/v1")
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:1/anthropic")
        self.assertEqual(env["OPENAI_API_KEY"], "ok-x")
        self.assertEqual(env["PATH"], "p")

    def test_cmd_proxy_runs_child_without_key(self):
        out = os.path.join(_isolation.mktemp(), "env.json")
        code = "import os,json,sys; json.dump(dict(os.environ), open(sys.argv[1],'w'))"
        args = mock.Mock(command=["--", sys.executable, "-c", code, out],
                         env_file=".env", print_env=False)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": KEY}), \
                mock.patch("stuntkey.remote.collect_values", lambda r, f: {"OPENAI_API_KEY": KEY}):
            self.assertEqual(proxy.cmd_proxy(CATALOG, args, _isolation.mktemp()), 0)
        with open(out, encoding="utf-8") as f:
            child = json.load(f)
        self.assertNotIn(KEY, json.dumps(child))
        self.assertTrue(child["OPENAI_API_KEY"].startswith("ok-"))
        port = int(child["OPENAI_BASE_URL"].split(":")[2].split("/")[0])
        with self.assertRaises(OSError):                      # closed after the child
            http.client.HTTPConnection("127.0.0.1", port, timeout=2).request("GET", "/")


if __name__ == "__main__":
    unittest.main()
