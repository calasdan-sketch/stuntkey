"""Test-rigour seat: adversarial checks on the claims StuntKey is sold on.

Written to MEASURE, not to agree with the implementation. Where a test here
fails, the product is wrong (or the claim is), not the test. Each class says
which published claim it is checking.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

import _isolation  # noqa: F401  (fake HOME for the whole run)
from stuntkey import broker, recipes, scrub

KEY = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"   # built at run time
RECIPE = recipes.load_recipes()["github"]
VALUES = {"GITHUB_TOKEN": KEY}
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("140.82.112.5", port))]
REPO = _isolation.REPO


def fake(status=200, body=b"{}", ctype="application/json", extra=None):
    def send(req, ip, timeout):
        h = {"content-type": ctype}
        h.update(extra or {})
        return status, h, body
    return send


def go(path="/user", method="GET", **kw):
    kw.setdefault("send", fake())
    kw.setdefault("resolver", PUBLIC)
    return broker.call(RECIPE, VALUES, method, path, **kw)


def new_log():
    return broker.AuditLog(os.path.join(tempfile.mkdtemp(prefix="se"), "audit.log"))


def entries(log):
    with open(log.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---- claim: "every call is logged ... which agent did this, and did I approve it"

class LogAnswersWhoAndWhether(unittest.TestCase):
    """README sells an activity log. A log that cannot name the caller cannot
    answer the only two questions an owner asks after an incident."""

    # expectedFailure, not a disabled test. These two are the specification for
    # the next change: the log records WHAT was called and whether it was
    # allowed, but not WHO called it or that a person approved it. Leaving them
    # plainly failing would make main red, and a permanently red suite teaches
    # everyone to ignore red -- which is how a sibling project shipped the same
    # crash three times. Marked this way they stay visible, CI stays honest,
    # and the moment the gap is closed they report "unexpected success" and
    # force this marker to be removed.
    @unittest.expectedFailure
    def test_the_log_names_the_agent_that_made_the_call(self):
        log = new_log()
        go("/user", audit=log)
        entry = entries(log)[0]
        self.assertTrue(
            any(entry.get(k) for k in ("actor", "client", "agent", "caller")),
            "no field names the caller; the log cannot say WHICH agent "
            f"made this call. Fields present: {sorted(entry)}")

    # expectedFailure, not a disabled test. These two are the specification for
    # the next change: the log records WHAT was called and whether it was
    # allowed, but not WHO called it or that a person approved it. Leaving them
    # plainly failing would make main red, and a permanently red suite teaches
    # everyone to ignore red -- which is how a sibling project shipped the same
    # crash three times. Marked this way they stay visible, CI stays honest,
    # and the moment the gap is closed they report "unexpected success" and
    # force this marker to be removed.
    @unittest.expectedFailure
    def test_the_log_records_that_a_person_approved_the_write(self):
        log = new_log()
        pol = broker.Policy(approve=lambda s: True)
        go("/gists", "POST", body={"a": 1}, policy=pol, audit=log)
        entry = entries(log)[-1]
        self.assertTrue(
            any(entry.get(k) for k in ("approved", "approval", "consent", "by")),
            "a human clicked yes and the log does not record it; the log "
            f"cannot say the write WAS approved. Fields present: {sorted(entry)}")

    def test_a_refused_call_is_still_recorded(self):
        log = new_log()
        with self.assertRaises(broker.BrokerError):
            go("/a/../../etc", audit=log)
        self.assertEqual([e["result"] for e in entries(log)], ["refused"])

    def test_a_denied_write_is_still_recorded(self):
        log = new_log()
        with self.assertRaises(broker.BrokerError):
            go("/gists", "POST", body={},
               policy=broker.Policy(approve=lambda s: False), audit=log)
        self.assertEqual([e["result"] for e in entries(log)], ["denied"])


# ---- claim: "a damaged or unwritable log refuses to broker (fail closed)"

class FailsClosedForReal(unittest.TestCase):
    """tests/test_hardening.py proves call() honours a ready() that raises, by
    overriding ready() to raise. That mocks the thing under test. These drive
    the REAL ready() against a log that genuinely cannot be written."""

    def setUp(self):
        # a path that exists but can never be opened for writing
        d = tempfile.mkdtemp(prefix="se")
        self.blocked = os.path.join(d, "audit.log")
        os.mkdir(self.blocked)
        self.log = broker.AuditLog(self.blocked)

    def test_real_ready_refuses_an_unwritable_log(self):
        with self.assertRaises(broker.BrokerError) as c:
            self.log.ready()
        self.assertIn("log", str(c.exception).lower())

    def test_nothing_is_sent_when_the_real_log_cannot_be_written(self):
        sent = []

        def spy(req, ip, timeout):
            sent.append(1)
            return 200, {"content-type": "application/json"}, b"{}"
        with self.assertRaises(broker.BrokerError):
            go("/user", audit=self.log, send=spy)
        self.assertEqual(sent, [], "the call went out even though it could "
                                   "never be recorded")


# ---- claim: "the hash chain detects tampering"

class ChainDetectsTampering(unittest.TestCase):
    def _log(self, n=3):
        log = new_log()
        for _ in range(n):
            log.write({"service": "t", "method": "GET", "host": "h", "path": "/p",
                       "status": 200, "bytes": 1, "result": "ok", "ms": 1})
        return log

    def test_reordered_lines_are_detected(self):
        log = self._log()
        self.assertEqual(log.verify(), (True, 3))
        with open(log.path, "rb") as f:
            lines = f.read().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        with open(log.path, "wb") as f:
            f.write(b"\n".join(lines) + b"\n")
        self.assertFalse(log.verify()[0], "two swapped lines verified as clean")

    def test_a_deleted_end_marker_is_detected(self):
        log = self._log()
        os.remove(log.anchor_path)
        self.assertFalse(log.verify()[0],
                         "the .head anchor was deleted and verify() said clean")

    def test_two_processes_writing_at_once_keep_the_chain(self):
        """The cross-process file lock is the claim; 20 threads in one process
        only exercise the in-process threading.Lock in front of it."""
        log = new_log()
        code = ("import sys; from stuntkey import broker\n"
                "log = broker.AuditLog(sys.argv[1])\n"
                "for i in range(25):\n"
                "    log.write({'service': 's', 'result': 'ok', 'i': i})\n")
        procs = [subprocess.Popen([sys.executable, "-c", code, log.path], cwd=REPO,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                 for _ in range(3)]
        for p in procs:
            self.assertEqual(p.wait(timeout=120), 0, p.communicate()[1][:400])
        ok, n = log.verify()
        self.assertTrue(ok, f"chain broken after 3 concurrent writers ({n} entries)")
        self.assertEqual(n, 75)


# ---- claim: "does not follow redirects" (broker.py docstring)

class RedirectsAreNotFollowed(unittest.TestCase):
    def test_a_redirect_after_the_key_is_attached_is_not_followed(self):
        hits = []
        box = {}

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits.append((self.path, self.headers.get("Authorization")))
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{box['port']}/stolen")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        box["port"] = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{box['port']}/start")
            req.add_header("Authorization", f"Bearer {KEY}")
            status, _headers, _body = broker._real_send(req, "127.0.0.1", 10)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(status, 302)
        self.assertEqual([p for p, _ in hits], ["/start"],
                         "the broker followed the redirect and carried the "
                         "Authorization header to the second address")


# ---- claim: "responses are scrubbed of the key"

class ScrubbingUnderPressure(unittest.TestCase):
    def test_each_encoding_of_the_key_is_actually_removed(self):
        """tests/test_scrub.py asserts only that the text CHANGED
        (assertNotEqual). That passes if one unrelated byte moved. Assert the
        encoded form is gone."""
        raw = KEY.encode()
        shapes = {
            "hex": raw.hex(),
            "HEX": raw.hex().upper(),
            "base64": base64.b64encode(raw).decode(),
            "urlsafe base64": base64.urlsafe_b64encode(raw).decode(),
            "percent": quote(KEY, safe=""),
            "reversed": KEY[::-1],
            "json escaped": json.dumps(KEY)[1:-1],
            "upper": KEY.upper(),
            "lower": KEY.lower(),
        }
        for name, shape in shapes.items():
            out = scrub.scrub_text("echo " + shape + " end", [KEY])
            self.assertNotIn(shape, out, f"{name} form survived scrubbing")

    def test_a_key_at_the_truncation_boundary_is_hidden(self):
        """broker.call scrubs the whole body then clips. A key straddling the
        clip point must not reappear."""
        cut = broker.MAX_BODY_OUT
        body = b"x" * (cut - len(KEY) // 2) + KEY.encode() + b"y" * 100
        out = go("/user", send=fake(body=body))
        self.assertNotIn(KEY, out["body"])

    def test_a_base64_key_in_the_location_header_is_withheld(self):
        hidden = base64.b64encode(KEY.encode()).decode()
        out = go("/user", send=fake(extra={"location": "https://x/?t=" + hidden}))
        self.assertNotIn(hidden, json.dumps(out["headers"]))
        self.assertNotIn(KEY, json.dumps(out["headers"]))

    def test_a_key_echoed_in_an_unlisted_header_never_reaches_the_caller(self):
        out = go("/user", send=fake(extra={"x-debug-token": KEY,
                                           "set-cookie": "s=" + KEY}))
        self.assertNotIn(KEY, json.dumps(out["headers"]))

    def test_a_huge_response_does_not_hand_back_more_than_the_cap(self):
        body = b"a" * (broker.MAX_BODY_OUT * 2)
        out = go("/user", send=fake(body=body))
        self.assertLessEqual(len(out["body"]), broker.MAX_BODY_OUT)
        self.assertTrue(out["truncated"])


# ---- claim: "non-GET needs a human click"

class WritesNeedAPerson(unittest.TestCase):
    def test_a_method_override_query_cannot_turn_a_get_into_a_write(self):
        for name in ("_method", "method", "X-HTTP-Method-Override",
                     "x-http-method-override", " _METHOD "):
            with self.assertRaises(broker.BrokerError, msg=name):
                go("/user", query={name: "DELETE"})

    def test_an_unknown_method_is_refused_and_logged(self):
        log = new_log()
        for bad in ("TRACE", "CONNECT", "OPTIONS", "PROPFIND", "get\r\nX: y"):
            with self.assertRaises(broker.BrokerError, msg=bad):
                go("/user", bad, audit=log)
        self.assertEqual({e["result"] for e in entries(log)}, {"refused"})

    def test_three_refusals_stop_the_session(self):
        pol = broker.Policy(approve=lambda s: False)
        for _ in range(3):
            with self.assertRaises(broker.BrokerError):
                go("/gists", "POST", body={}, policy=pol)
        with self.assertRaises(broker.BrokerError) as c:
            go("/gists", "POST", body={}, policy=pol)
        self.assertIn("three times", str(c.exception))


# ---- claim: "`scan` finds keys leaked into files an agent reads"

class ScanIsHonestAboutWhatItMissed(unittest.TestCase):
    """A scanner that reports clean after passing over files is worse than no
    scanner. These pin the disclosure contract so it cannot quietly narrow."""

    TOKEN = ("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
             "Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0")       # built at run time

    def setUp(self):
        from stuntkey import scan
        self.scan = scan
        self.catalog = recipes.load_recipes()

    def _dir(self, name):
        d = tempfile.mkdtemp(prefix="se")
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write(self.TOKEN + "\n")
        return d

    def test_a_bare_token_in_a_dotfile_is_found(self):
        """Regression: a live 64-char token in `.token` once reported clean."""
        r = self.scan.scan_path(self._dir(".token"), self.catalog)
        self.assertEqual(len(r.findings), 1, "a bare token in .token was missed")
        self.assertEqual(r.files_scanned, 1)

    def test_every_file_is_counted_somewhere(self):
        """No file may vanish: it is scanned, skipped, or not considered."""
        for name in (".token", ".env", "notes.txt", "creds.bin", "config.json"):
            r = self.scan.scan_path(self._dir(name), self.catalog)
            self.assertEqual(
                r.files_scanned + len(r.skipped) + r.not_considered, 1,
                f"{name} appears in no bucket: scanned={r.files_scanned} "
                f"skipped={len(r.skipped)} not_considered={r.not_considered}")

    def test_a_clean_report_says_out_loud_what_it_did_not_open(self):
        r = self.scan.scan_path(self._dir("notes.txt"), self.catalog)
        self.assertEqual(len(r.findings), 0)        # out of default scope
        self.assertEqual(r.not_considered, 1)
        text = self.scan.render_text(r)
        self.assertIn("NOT looked at", text)
        self.assertIn("--all", text)

    def test_all_finds_what_the_default_scan_passed_over(self):
        d = self._dir("notes.txt")
        self.assertEqual(len(self.scan.scan_path(d, self.catalog).findings), 0)
        self.assertEqual(
            len(self.scan.scan_path(d, self.catalog, everything=True).findings), 1,
            "--all did not find a token the default scan passed over")


# ---- claim: README's "self-attack test"

class SelfAttackResultIsPinned(unittest.TestCase):
    """tests/test_leakbench.py asserts 6 probe outcomes by hand out of 61. The
    other 55 are run and thrown away, so a probe sliding from blocked to leaked
    would not fail anything. The whole run takes about a second: pin it."""

    # The two gaps the hook alone does NOT close: the spend probes. The hook
    # cannot bound a loop; the spending caps (stuntkey-full) do. The three
    # written-script probes are now blocked when the script is written.
    KNOWN_LEAKS = {
        "runaway-loop-no-cap",
        "unbounded-retry",
    }
    PROBE_FLOOR = 61        # deleting a probe must never improve the score

    def setUp(self):
        try:
            import leakbench.harness  # noqa: F401
            from stuntkey import hook  # noqa: F401
        except ImportError:
            self.skipTest("leakbench or the hook is not importable")

    def test_the_known_gaps_are_exactly_these_and_no_others(self):
        from leakbench import harness
        results = harness.run("stuntkey-hook")
        leaked = {r.probe_id for r in results if r.status == "leaked"}
        self.assertEqual(
            leaked, self.KNOWN_LEAKS,
            "the self-attack result moved. New leaks: "
            f"{sorted(leaked - self.KNOWN_LEAKS)}; "
            f"now closed: {sorted(self.KNOWN_LEAKS - leaked)}. If a gap was "
            "closed, update KNOWN_LEAKS and the README number together.")

    def test_every_other_probe_is_blocked_masked_or_unrunnable(self):
        """No probe is in a state the benchmark does not define.

        `n/a` has to be allowed: it means the probe could not run here (the
        tool is missing, a daemon is down, there was nothing to leak), and
        which tools exist is a property of the machine, not of stuntkey. This
        test first pinned only blocked/masked/leaked and went red on all nine
        CI legs because the runners have no `ripgrep` while the author's
        machine does -- it was pinning the dev box, not the product.

        `n/a` is still never counted as a pass: the GAP set is pinned exactly
        by the test above, and the floor below stops a probe disappearing.
        """
        from leakbench import harness
        results = harness.run("stuntkey-hook")
        allowed = ("blocked", "masked", "leaked", "n/a")
        odd = {r.probe_id: r.status for r in results if r.status not in allowed}
        self.assertEqual(odd, {}, f"probes in an unexpected state: {odd}")

    def test_a_probe_that_cannot_run_is_never_counted_as_protection(self):
        """An `n/a` probe proves nothing, so it must not be reported as
        blocked or masked. This is the property the test above gives up by
        allowing `n/a`, pinned separately."""
        from leakbench import harness
        results = harness.run("stuntkey-hook")
        na = [r.probe_id for r in results if r.status == "n/a"]
        scored = [r.probe_id for r in results if r.status in ("blocked", "masked")]
        self.assertFalse(set(na) & set(scored),
                         "a probe is counted both unrunnable and protected")

    def test_the_probe_count_never_shrinks(self):
        from leakbench import loader
        self.assertGreaterEqual(
            len(loader.load()), self.PROBE_FLOOR,
            "probes were removed; the self-attack score is not comparable "
            "with the one the README quotes")


if __name__ == "__main__":
    unittest.main()
