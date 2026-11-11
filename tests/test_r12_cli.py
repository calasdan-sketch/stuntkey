"""Round 12: import hardening, plain status/doctor/about, install self-check.
Only fake keys; every file lives in a fresh temp folder."""
import contextlib
import io
import json
import os
import random
import sys
import tempfile
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME for the whole run)
from stuntkey import cli, cmds, connect_import, extras, keychain, recipes

FAKE = "sk-FAKE-TEST-0000-abcdefghijklmnop"


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def memory_keychain():
    old = os.environ.get("STUNTKEY_KEYCHAIN")
    os.environ["STUNTKEY_KEYCHAIN"] = "memory"
    keychain._memory.clear()
    try:
        yield
    finally:
        keychain._memory.clear()
        if old is None:
            os.environ.pop("STUNTKEY_KEYCHAIN", None)
        else:
            os.environ["STUNTKEY_KEYCHAIN"] = old


class ImportBase(unittest.TestCase):
    def setUp(self):
        self.catalog = recipes.load_recipes()
        self.var = recipes.env_vars(self.catalog["openai"])[0]

    def _import(self, data, name=".env", **kw):
        d = tempfile.mkdtemp(prefix="r12")
        path = os.path.join(d, name)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        args = mock.Mock(file=path, paste=False, yes=True, delete_source=False)
        for k, v in kw.items():
            setattr(args, k, v)
        out = io.StringIO()
        with memory_keychain():
            code = connect_import.cmd_import(args, self.catalog, out=out)
            stored = dict(keychain._memory)
        return code, out.getvalue(), stored, path


class ImportDeleteSource(ImportBase):
    def test_unimported_name_keeps_the_file(self):
        secret = "MY_UNKNOWN_SECRET=keep-me-please-1234567890\n"
        code, out, stored, path = self._import(f"{self.var}={FAKE}\n{secret}",
                                               delete_source=True)
        self.assertEqual(code, 0, out)
        self.assertTrue(os.path.exists(path))
        self.assertIn("keep-me-please", open(path).read())
        self.assertIn("did NOT delete", out)
        self.assertIn("Remove-Item", out)
        self.assertIn(FAKE, stored.values())
        self.assertNotIn(FAKE, out)

    def test_wrong_shape_keeps_the_file(self):
        code, out, stored, path = self._import(
            "Title,Url,Username,Password\nOpenAI,,me,my-login-password\n", "x.csv",
            delete_source=True)
        self.assertTrue(os.path.exists(path))
        self.assertEqual(stored, {})

    def test_everything_imported_deletes(self):
        code, out, stored, path = self._import(f"{self.var}={FAKE}\n", delete_source=True)
        self.assertEqual(code, 0, out)
        self.assertFalse(os.path.exists(path))


class ImportParsing(ImportBase):
    def test_long_space_line_is_fast(self):
        text = f"{self.var}=" + " " * 40000 + "x" + " " * 40000 + "\nA=" + " " * 40000 + "\n"
        t0 = time.monotonic()
        connect_import.parse_env(text)
        self.assertLess(time.monotonic() - t0, 1.0)

    def test_quotes_come_off_before_comments(self):
        got = dict(connect_import.parse_env(
            'A="abc" # note\nB=\'x y\' # n\nC=plain # n\nD="has # inside"\nE="a\\"b"\n'))
        self.assertEqual(got["A"], "abc")
        self.assertEqual(got["B"], "x y")
        self.assertEqual(got["C"], "plain")
        self.assertEqual(got["D"], "has # inside")
        self.assertEqual(got["E"], 'a\\"b')

    def test_last_duplicate_wins(self):
        self.assertEqual(connect_import.parse_env("A=1\nB=2\nA=3\n"),
                         [("B", "2"), ("A", "3")])
        self.assertEqual(connect_import.parse_env("A=1\nA=\n"), [])
        code, out, stored, _p = self._import(
            f"{self.var}=sk-first-first-first-first\n{self.var}={FAKE}\n")
        self.assertEqual(code, 0, out)
        self.assertEqual(list(stored.values()), [FAKE])

    def test_utf16_and_bom_files(self):
        line = f"{self.var}={FAKE}\r\n"
        for data in (line.encode("utf-16"),            # PowerShell > (BOM)
                     line.encode("utf-16-le"),         # no mark
                     line.encode("utf-16-be"),
                     b"\xef\xbb\xbf" + line.encode()):
            code, out, stored, _p = self._import(data)
            self.assertEqual(code, 0, out)
            self.assertIn(FAKE, stored.values())

    def test_deep_json_is_a_plain_error(self):
        for text in ("[" * 6000, '{"a":' * 6000 + "1" + "}" * 6000, "[" * 150 + "]" * 150):
            code, out, stored, _p = self._import(text, "d.json")
            self.assertEqual(code, 1)
            self.assertIn("Nothing was saved", out)
            self.assertNotIn("Traceback", out)

    def test_huge_csv_cell_is_a_plain_error(self):
        data = "Title,Password\nOpenAI," + "x" * 200_000 + "\n"
        code, out, stored, _p = self._import(data, "big.csv")
        self.assertEqual(code, 1)
        self.assertIn("Nothing was saved", out)
        self.assertEqual(stored, {})

    def test_over_two_megabytes_is_refused(self):
        code, out, stored, _p = self._import("A=b\n" * 600_000)
        self.assertEqual(code, 1)
        self.assertIn("too big", out)

    def test_odd_bitwarden_fields_value(self):
        bw = {"items": [{"name": "OpenAI", "login": {"password": FAKE}, "fields": 5},
                        {"name": "x", "fields": "nope"}, {"name": 7, "login": 3}]}
        code, out, stored, _p = self._import(json.dumps(bw), "b.json")
        self.assertEqual(code, 0, out)
        self.assertIn(FAKE, stored.values())

    def test_title_match_needs_the_keys_shape(self):
        bw = {"items": [{"name": "OpenAI", "login": {"password": "hunter2-my-login"}}]}
        code, out, stored, path = self._import(json.dumps(bw), "b.json", delete_source=True)
        self.assertEqual(stored, {})
        self.assertIn("skipped", out)
        self.assertIn("does not look like", out)
        self.assertNotIn("hunter2", out)
        self.assertTrue(os.path.exists(path))

    def test_good_title_match_still_saves(self):
        bw = {"items": [{"name": "OpenAI", "login": {"password": FAKE}}]}
        code, out, stored, _p = self._import(json.dumps(bw), "b.json")
        self.assertEqual(code, 0, out)
        self.assertIn(FAKE, stored.values())


class ImportNeverCrashes(ImportBase):
    def test_any_exception_becomes_a_plain_sentence(self):
        with mock.patch.object(connect_import, "parse_text", side_effect=ZeroDivisionError("boom")):
            code, out, _s, path = self._import(f"{self.var}={FAKE}\n", delete_source=True)
        self.assertEqual(code, 1)
        self.assertIn("Something unexpected", out)
        self.assertNotIn("boom", out)
        self.assertTrue(os.path.exists(path))

    def test_keychain_failure_is_plain(self):
        class Boom(Exception):
            pass
        with mock.patch.object(keychain, "store", side_effect=Boom(FAKE)):
            code, out, _s, path = self._import(f"{self.var}={FAKE}\n", delete_source=True)
        self.assertEqual(code, 1)
        self.assertNotIn(FAKE, out)
        self.assertTrue(os.path.exists(path))

    def test_fuzz_malformed_files(self):
        rng = random.Random(1234)
        pieces = [b"{", b"}", b"[", b"]", b'"', b"'", b",", b"\x00", b"\xff\xfe", b"=", b"#",
                  b"export ", b"\r\n", b"\n", b"A=", b"\xef\xbb\xbf", b'"items":', b'"fields":5',
                  b"Title,Password\n", b" " * 5000, b"\xc3(", b"OPENAI_API_KEY=" + FAKE.encode()]
        for i in range(60):
            data = b"".join(rng.choice(pieces) for _ in range(rng.randint(1, 40)))
            for name in (".env", "f.json", "f.csv"):
                code, out, stored, _p = self._import(data, name)
                self.assertIn(code, (0, 1, 2), (i, name, out))
                self.assertNotIn("Traceback", out)


class LogFactsAndStatus(unittest.TestCase):
    def test_facts_from_a_plain_file_without_stats(self):
        d = tempfile.mkdtemp(prefix="r12")
        p = os.path.join(d, "audit.log")
        with open(p, "wb") as f:
            f.write(b'{"a":1}\n' * 5)

        class Log:
            path = p
        facts = cmds.log_facts(Log())
        self.assertEqual(facts["entries"], 5)
        self.assertGreater(facts["bytes"], 0)
        self.assertIsNotNone(facts["last_write"])
        text = cmds.log_lines(facts)
        self.assertIn("5 entries", text)
        self.assertNotIn("WARNING", text)

    def test_facts_use_stats_when_present_and_survive_its_failure(self):
        class Log:
            path = None

            def stats(self):
                return {"entries": 60_000, "bytes": 5_000_000, "last_write": 1_700_000_000}
        text = cmds.log_lines(cmds.log_facts(Log()))
        self.assertIn("60000 entries", text)
        self.assertIn("WARNING", text)
        self.assertIn("audit reset", text)

        class Bad:
            path = None

            def stats(self):
                raise RuntimeError("x")
        self.assertEqual(cmds.log_lines(cmds.log_facts(Bad())), "")

    def test_overview_shows_the_log_size_line(self):
        with memory_keychain():
            code, out, err = run(["overview"])
        self.assertIn("activity log:", out)

    def test_overview_json_has_size_and_time(self):
        with memory_keychain():
            code, out, err = run(["overview", "--json"])
        data = json.loads(out)
        self.assertIn("audit_bytes", data)
        self.assertIn("audit_last_write", data)


class DoctorAndAbout(unittest.TestCase):
    def test_doctor_asks_for_the_signing_key_once(self):
        calls = []
        from stuntkey import broker, gitscan
        with memory_keychain(), \
                mock.patch.object(broker.AuditLog, "ensure_key",
                                  lambda self: calls.append(1), create=True), \
                mock.patch.object(gitscan, "doctor", lambda: {"ok": True}), \
                mock.patch.object(gitscan, "format_doctor", lambda r: "fine"):
            code, out, err = run(["doctor"])
        self.assertEqual(calls, [1])
        self.assertEqual(code, 0)

    def test_doctor_works_when_ensure_key_is_missing_or_breaks(self):
        from stuntkey import broker, gitscan
        with memory_keychain(), \
                mock.patch.object(broker.AuditLog, "ensure_key",
                                  mock.Mock(side_effect=RuntimeError("x")), create=True), \
                mock.patch.object(gitscan, "doctor", lambda: {"ok": True}), \
                mock.patch.object(gitscan, "format_doctor", lambda r: "fine"):
            code, out, err = run(["doctor"])
        self.assertEqual(code, 0)

    def test_about_names_the_program_version_and_folder(self):
        from stuntkey import __version__
        code, out, err = run(["about"])
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)
        self.assertIn("Program file:", out)
        self.assertIn("Installed in:", out)


class _Hash:
    def __init__(self, mode, value):
        self.mode, self.value = mode, value


class _Path:
    def __init__(self, path, hash_, name=None):
        self._p, self.hash = path, hash_
        self.name = name or os.path.basename(path)
        self.suffix = os.path.splitext(path)[1]

    def locate(self):
        return self._p

    def __str__(self):
        return self.name


class _Dist:
    def __init__(self, files):
        self.files = files


def _b64(data: bytes) -> str:
    import base64
    import hashlib
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


class SelfCheck(unittest.TestCase):
    def _files(self):
        d = tempfile.mkdtemp(prefix="r12")
        paths = []
        for n in ("a.py", "b.py"):
            p = os.path.join(d, n)
            with open(p, "wb") as f:
                f.write(b"print(1)\n")
            paths.append(_Path(p, _Hash("sha256", _b64(b"print(1)\n"))))
        return d, paths

    def test_untouched_files_pass(self):
        _d, files = self._files()
        res = extras.self_check(_Dist(files))
        self.assertEqual(res["state"], "ok")
        self.assertEqual(res["checked"], 2)
        self.assertIn("OK", extras.format_self_check(res))

    def test_changed_and_missing_files_are_named(self):
        _d, files = self._files()
        with open(files[0]._p, "ab") as f:
            f.write(b"# edited\n")
        os.remove(files[1]._p)
        res = extras.self_check(_Dist(files))
        self.assertEqual(res["state"], "changed")
        self.assertEqual(res["changed"], ["a.py"])
        self.assertEqual(res["missing"], ["b.py"])
        text = extras.format_self_check(res)
        self.assertIn("WARNING", text)
        self.assertIn("changed: a.py", text)
        self.assertIn("missing: b.py", text)

    def test_no_install_list_says_so_plainly(self):
        res = extras.self_check(_Dist([]))
        self.assertEqual(res["state"], "unavailable")
        self.assertIn("nothing to compare", extras.format_self_check(res))

    def test_doctor_self_flag(self):
        with mock.patch.object(extras, "self_check",
                               lambda: {"state": "ok", "checked": 3, "changed": [],
                                        "missing": [], "why": ""}):
            code, out, err = run(["doctor", "--self"])
        self.assertEqual(code, 0)
        self.assertIn("all 3 installed", out)


if __name__ == "__main__":
    unittest.main()
