"""The selftest must pass on good code AND fail when the protections are broken."""
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from stuntkey import approve, broker, selftest


class SelftestTests(unittest.TestCase):
    def test_all_attacks_stopped(self):
        bad = [r for r in selftest.run_all() if not r["pass"]]
        self.assertEqual(bad, [])

    def test_exit_code_and_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = selftest.cmd_selftest(as_json=True)
        data = json.loads(buf.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(data["passed"], data["total"])
        self.assertGreaterEqual(data["total"], 30)

    def test_fails_when_scrubbing_is_broken(self):
        class NoScrub:
            def __init__(self, secrets):
                pass

            def feed(self, raw):
                return raw

            def flush(self):
                return b""
        with mock.patch.object(broker, "Scrubber", NoScrub), \
                mock.patch.object(broker, "loosely_contains", lambda *a, **k: False):
            results = selftest.run_all()
        self.assertTrue(any(not r["pass"] and "echoes" in r["attack"] for r in results))

    def test_fails_when_address_check_is_broken(self):
        with mock.patch.object(broker, "is_public_ip", lambda ip: True):
            results = selftest.run_all()
        self.assertTrue(any(not r["pass"] and "pointing at" in r["attack"] for r in results))

    def test_fails_when_path_check_is_broken(self):
        with mock.patch.object(broker, "check_path", lambda p: p):
            results = selftest.run_all()
        self.assertTrue(any(not r["pass"] and "Odd path" in r["attack"] for r in results))

    def test_exit_code_is_one_on_failure(self):
        with mock.patch.object(broker, "is_public_ip", lambda ip: True):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(selftest.cmd_selftest(), 1)


class MutationTests(unittest.TestCase):
    """Break one protection at a time: the matching attack MUST then fail."""

    def _failed(self):
        return {r["attack"] for r in selftest.run_all() if not r["pass"]}

    def test_aws_guard_removed(self):
        with mock.patch.object(broker, "check_sigv4_action", lambda r, u: None):
            self.assertTrue(any("AWS" in a for a in self._failed()))

    def test_log_anchor_removed(self):
        orig = broker.AuditLog._problem
        with mock.patch.object(broker.AuditLog, "_read_anchor", lambda self: None), \
                mock.patch.object(broker.AuditLog, "_problem",
                                  staticmethod(lambda n, last, ok, a, anchored=False:
                                               orig(n, last, ok, None, False))):
            failed = self._failed()
        self.assertTrue(any("Cutting the end" in a for a in failed))
        self.assertTrue(any("Deleting the activity log file" in a for a in failed))

    def test_review_limit_removed(self):
        with mock.patch.object(broker, "MAX_REVIEW", 10 ** 9):
            self.assertTrue(any("padded" in a for a in self._failed()))

    def test_disguise_check_weakened(self):
        from stuntkey import scrub
        # round 13: the interleave check also folds dashes and invisible characters,
        # so a real weakening removes both
        with mock.patch.object(scrub, "_squash", lambda t: ""), \
                mock.patch.object(scrub, "_interleaved", lambda *a, **k: False):
            failed = self._failed()
        self.assertTrue(any("dashes" in a or "invisible" in a for a in failed))

    def test_ipv6_inner_address_check_removed(self):
        import ipaddress

        def old(text):
            try:
                ip = ipaddress.ip_address(text)
            except ValueError:
                return False
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            return ip.is_global and not ip.is_multicast
        with mock.patch.object(broker, "is_public_ip", old):
            self.assertTrue(any("64:ff9b" in a or "2002:" in a for a in self._failed()))

    def test_pop_up_found_on_path(self):
        with mock.patch.object(approve, "_tool", lambda *p: "x"):
            pass                      # _tool itself is exercised below
        self.assertIsNone(approve._tool("zenity", "./kdialog"))


if __name__ == "__main__":
    unittest.main()
