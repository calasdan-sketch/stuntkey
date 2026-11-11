"""The local page served at `/` by `stuntkey serve` (round 11 integration).

A browser sends no Authorization header, so the page opens with a ONE-TIME
link that is swapped for a cookie. The API routes keep the Bearer token."""
import http.client
import json
import re
import unittest

from stuntkey import broker, httpd, recipes
import stuntkey

CATALOG = recipes.load_recipes()
TOKEN = "t" * 43
STATUS = {"keys": [{"name": "Evil </script><b>x</b> & Co"}], "practice_cmd": "stuntkey try"}


class Page(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = httpd.make_server(CATALOG, lambda r: {}, TOKEN, broker.Policy(),
                                    page_status=lambda: STATUS, version="9.9.9")
        cls.port = cls.srv.server_address[1]
        httpd.start_background(cls.srv)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, path, headers=None):
        h = {"Host": f"127.0.0.1:{self.port}"}
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        for k, v in h.items():
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        return r.status, r.read().decode("utf-8", "replace"), r

    def cookie(self):
        s, _, r = self.get("/?c=" + self.srv.new_launch_code())
        self.assertEqual(s, 303)
        self.assertEqual(r.getheader("Location"), "/")
        return r.getheader("Set-Cookie").split(";")[0]

    def test_no_cookie_no_page(self):
        s, body, _ = self.get("/")
        self.assertEqual(s, 401)
        self.assertNotIn("{{", body)

    def test_link_gives_cookie_then_page_with_placeholders_filled(self):
        s, _, r = self.get("/?c=" + self.srv.new_launch_code())
        self.assertEqual(s, 303)
        setc = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", setc)
        self.assertIn("SameSite=Strict", setc)
        self.assertNotIn(TOKEN, setc)                 # made FROM the token, not the token
        s, body, r = self.get("/", {"Cookie": setc.split(";")[0]})
        self.assertEqual(s, 200)
        self.assertIn("text/html", r.getheader("Content-Type"))
        self.assertNotIn("{{status_json}}", body)
        self.assertNotIn("{{version}}", body)
        self.assertIn("9.9.9", body)
        self.assertNotIn(TOKEN, body)
        self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("Referrer-Policy"), "no-referrer")

    def test_status_json_cannot_break_out_of_its_script_tag(self):
        _, body, _ = self.get("/", {"Cookie": self.cookie()})
        m = re.search(r'<script type="application/json" id="sk-status">(.*?)</script>', body, re.S)
        self.assertTrue(m)
        raw = m.group(1)
        self.assertNotIn("<", raw)
        self.assertEqual(json.loads(raw), STATUS)      # escapes decode to the same data

    def test_a_link_works_once(self):
        code = self.srv.new_launch_code()
        self.assertEqual(self.get("/?c=" + code)[0], 303)
        self.assertEqual(self.get("/?c=" + code)[0], 401)

    def test_a_made_up_link_or_cookie_is_refused(self):
        self.assertEqual(self.get("/?c=nope")[0], 401)
        self.assertEqual(self.get("/", {"Cookie": "sk_page=abc"})[0], 401)

    def test_expired_link_is_refused(self):
        code = self.srv.new_launch_code()
        real = httpd.time.time
        httpd.time.time = lambda: real() + httpd.LAUNCH_SECONDS + 5
        try:
            self.assertEqual(self.get("/?c=" + code)[0], 401)
        finally:
            httpd.time.time = real

    def test_cookie_does_not_open_the_api(self):
        cookie = self.cookie()
        for path in ("/tools", "/services"):
            self.assertEqual(self.get(path, {"Cookie": cookie})[0], 401)

    def test_page_refuses_other_hosts_and_web_pages(self):
        cookie = self.cookie()
        self.assertEqual(self.get("/", {"Cookie": cookie, "Host": "evil.com"})[0], 403)
        self.assertEqual(self.get("/", {"Cookie": cookie, "Origin": "http://evil.com"})[0], 403)

    def test_no_page_when_the_server_has_none(self):
        srv = httpd.make_server(CATALOG, lambda r: {}, TOKEN, broker.Policy())
        try:
            httpd.start_background(srv)
            port = srv.server_address[1]
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
            c.putheader("Host", f"127.0.0.1:{port}")
            c.endheaders()
            self.assertEqual(c.getresponse().status, 401)   # the old behaviour: token only
        finally:
            srv.shutdown()
            srv.server_close()

    def test_page_wording_names_the_real_practice_command(self):
        body = httpd.render_page(stuntkey.__version__, {}).decode()
        self.assertIn("stuntkey try", body)
        self.assertNotIn("stuntkey selftest", body)


class AuditWording(unittest.TestCase):
    def test_audit_with_no_word_means_verify(self):
        from stuntkey import cli
        args = cli._build_parser().parse_args(["audit"])
        self.assertEqual(args.action, "verify")

    def test_an_empty_new_log_has_nothing_to_warn_about(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(broker.AuditLog(os.path.join(d, "audit.log")).describe(), "")


if __name__ == "__main__":
    unittest.main()
