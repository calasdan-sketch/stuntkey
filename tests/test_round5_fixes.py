"""Panel round 5 regressions.

1  a .env that is not valid UTF-8 (a Windows cp1252 'e-acute') is saved to
   without a traceback and keeps every byte it had.
2  a .env that is a link is refused (never written through, never silently
   replaced); the permission step never follows a link.
3  line endings: a CRLF .env stays CRLF, an LF one stays LF; the line we add
   or change uses the file's own style; a missing last newline is added in
   that style.
4  internationalised hostnames: the cross-domain check compares the xn--
   (punycode) forms, copes with trailing dots, upper case, ports and
   user@host, and the warning shows both spellings so a homograph is visible.
5  the MCP server answers -32602 (Invalid params), never a crash or -32603,
   for params that are not an object, arguments that are not an object, and
   missing or wrongly typed required arguments - and keeps running.
7  the README says validation belongs on the person's own computer: cloud
   coding agents and proxies can inject credentials and make any key "valid".
8  packaging metadata (classifiers, keywords, project URLs) and one version:
   __version__, pyproject, the MCP serverInfo and both User-Agents agree.
9  `stuntkey ... | head -1` (a closed pipe) ends quietly: no traceback,
   no "Exception ignored" at exit, no exit status 120.
9b on Windows a closed pipe is not a BrokenPipeError: the flush (or, with
   `python -u`, print() itself) raises a plain OSError(EINVAL). That is
   recognised too - on Windows only - for every command and the MCP loop.
D  the same variable set twice in a .env: the LAST line is the one dotenv
   readers, docker compose and a shell `source` use, so that is the one
   updated; `forget` removes all of them; the person is told.
Found while testing the above (not in the review):
B  a UTF-8 byte-order mark (Notepad's "UTF-8 with BOM") no longer hides a
   variable on the first line: a duplicate was appended and `forget` left
   the old key behind.
U  a malformed URL in a recipe is a RecipeError (skipped with a warning,
   a clean message in `add`), not a ValueError that takes down the catalog.
"""

import errno
import io
import json
import os
import re
import stat
import subprocess
import sys
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import _isolation
from stuntkey import __version__
from stuntkey import cli as cli_mod
from stuntkey import connect as connect_mod
from stuntkey import mcp as mcp_mod
from stuntkey import publicapis as publicapis_mod
from stuntkey import recipes as recipes_mod
from stuntkey import store as store_mod
from stuntkey import validate as validate_mod

FAKE_KEY = "sk-test-THIS-IS-A-FAKE-KEY-999"
KEY = FAKE_KEY.encode("ascii")
REPO = _isolation.REPO


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": [], "docs": "",
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


def boom(*_a, **_k):
    raise AssertionError("this must not be called")


def new_env():
    return os.path.join(_isolation.mktemp(), ".env")


def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def connect(r, env_file, key=FAKE_KEY, **kw):
    out = io.StringIO()
    args = dict(env_file=env_file, browser_open=lambda u: None,
                prompt=lambda _: key, out=out,
                validate_fn=lambda s, k: True, confirm_in=boom)
    args.update(kw)
    code = connect_mod.connect(r, **args)
    return code, out.getvalue()


# ------------------------------------------------------------------ 1


class TestNonUtf8EnvFile(unittest.TestCase):
    # "cafe" with an e-acute and an en dash as Windows Notepad saves them:
    # 0xE9 and 0x96 are not valid UTF-8
    CP1252 = "# café note – prod\r\nOTHER=café\r\n".encode("cp1252")

    def test_the_fixture_really_is_not_utf8(self):
        with self.assertRaises(UnicodeDecodeError):
            self.CP1252.decode("utf-8")

    def test_adding_a_key_keeps_every_other_byte(self):
        env = new_env()
        write_bytes(env, self.CP1252)
        stored = store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, env)
        self.assertFalse(stored.updated)
        self.assertEqual(read_bytes(env),
                         self.CP1252 + b"\r\nACME_API_KEY=" + KEY + b"\r\n")
        # and the key reads back, whatever the other lines hold
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], FAKE_KEY)

    def test_updating_a_key_changes_only_its_own_line(self):
        env = new_env()
        write_bytes(env, b"# caf\xe9\r\nACME_API_KEY=old\r\nTAIL=na\xefve\r\n")
        stored = store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, env)
        self.assertTrue(stored.updated)
        self.assertEqual(read_bytes(env), b"# caf\xe9\r\nACME_API_KEY=" + KEY
                         + b"\r\nTAIL=na\xefve\r\n")

    def test_forget_changes_only_its_own_line(self):
        env = new_env()
        write_bytes(env, b"# caf\xe9\nACME_API_KEY=old\nTAIL=na\xefve\n")
        self.assertTrue(store_mod.remove_key("ACME_API_KEY", env))
        self.assertEqual(read_bytes(env), b"# caf\xe9\nTAIL=na\xefve\n")

    def test_connect_saves_into_it_with_exit_0_and_no_traceback(self):
        env = new_env()
        write_bytes(env, self.CP1252)
        code, out = connect(recipe(), env)
        self.assertEqual(code, 0, out)
        self.assertIn("✓", out)
        self.assertNotIn(FAKE_KEY, out)
        self.assertTrue(read_bytes(env).startswith(self.CP1252))

    def test_other_non_utf8_bytes_survive_too(self):
        env = new_env()
        raw = bytes(range(0x80, 0x100)) + b"\n"          # every high byte
        write_bytes(env, raw)
        store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, env)
        self.assertEqual(read_bytes(env),
                         raw + b"\nACME_API_KEY=" + KEY + b"\n")

    def test_a_utf16_file_is_refused_not_corrupted(self):
        # Windows PowerShell's `echo X=1 > .env` writes UTF-16. Appending
        # UTF-8 to it would silently wreck it, so it is left alone.
        env = new_env()
        raw = "OTHER=1\r\n".encode("utf-16")
        write_bytes(env, raw)
        with self.assertRaises(store_mod.EnvFileRefused) as cm:
            store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, env)
        self.assertIn("UTF-8", str(cm.exception))
        self.assertNotIn(FAKE_KEY, str(cm.exception))
        with self.assertRaises(store_mod.EnvFileRefused):
            store_mod.remove_key("ACME_API_KEY", env)
        self.assertEqual(read_bytes(env), raw)
        # connect() says so before it opens a browser or asks for a key
        code, out = connect(recipe(), env, browser_open=boom, prompt=boom,
                            validate_fn=boom)
        self.assertEqual(code, 1)
        self.assertIn("UTF-8", out)
        self.assertIn("Nothing was asked for", out)
        self.assertNotIn("Traceback", out)
        self.assertEqual(read_bytes(env), raw)


# ------------------------------------------------------------------ 3


class TestLineEndings(unittest.TestCase):
    def save(self, before, var="ACME_API_KEY"):
        env = new_env()
        if before is not None:
            write_bytes(env, before)
        store_mod.store_key_result(var, FAKE_KEY, env)
        return read_bytes(env)

    def test_crlf_file_stays_crlf_when_a_line_is_added(self):
        after = self.save(b"A=1\r\nB=2\r\n")
        self.assertEqual(after, b"A=1\r\nB=2\r\n\r\nACME_API_KEY=" + KEY + b"\r\n")
        self.assertEqual(after.count(b"\n"), after.count(b"\r\n"),
                         "a bare LF crept into a CRLF file")

    def test_crlf_file_stays_crlf_when_a_line_is_updated(self):
        after = self.save(b"A=1\r\nACME_API_KEY=old\r\nB=2\r\n")
        self.assertEqual(after, b"A=1\r\nACME_API_KEY=" + KEY + b"\r\nB=2\r\n")

    def test_export_line_in_a_crlf_file(self):
        after = self.save(b"export ACME_API_KEY=old\r\n")
        self.assertEqual(after, b"export ACME_API_KEY=" + KEY + b"\r\n")

    def test_lf_file_stays_lf(self):
        after = self.save(b"A=1\nB=2\n")
        self.assertEqual(after, b"A=1\nB=2\n\nACME_API_KEY=" + KEY + b"\n")
        self.assertNotIn(b"\r", after)
        after = self.save(b"A=1\nACME_API_KEY=old\nB=2\n")
        self.assertEqual(after, b"A=1\nACME_API_KEY=" + KEY + b"\nB=2\n")

    def test_missing_final_newline_is_added_in_the_files_own_style(self):
        self.assertEqual(self.save(b"A=1\r\nB=2"),
                         b"A=1\r\nB=2\r\n\r\nACME_API_KEY=" + KEY + b"\r\n")
        self.assertEqual(self.save(b"A=1\nB=2"),
                         b"A=1\nB=2\n\nACME_API_KEY=" + KEY + b"\n")
        # our own line is the one without a newline
        self.assertEqual(self.save(b"A=1\r\nACME_API_KEY=old"),
                         b"A=1\r\nACME_API_KEY=" + KEY + b"\r\n")
        # an unrelated last line is the one without a newline
        self.assertEqual(self.save(b"ACME_API_KEY=old\r\nB=2"),
                         b"ACME_API_KEY=" + KEY + b"\r\nB=2\r\n")
        self.assertEqual(self.save(b"ACME_API_KEY=old\nB=2"),
                         b"ACME_API_KEY=" + KEY + b"\nB=2\n")

    def test_new_empty_and_style_less_files_use_lf(self):
        self.assertEqual(self.save(None), b"ACME_API_KEY=" + KEY + b"\n")
        self.assertEqual(self.save(b""), b"ACME_API_KEY=" + KEY + b"\n")
        # one line, no newline at all: nothing says CRLF, so LF
        self.assertEqual(self.save(b"A=1"), b"A=1\n\nACME_API_KEY=" + KEY + b"\n")

    def test_mixed_endings_keep_each_lines_own_ending(self):
        after = self.save(b"A=1\r\nB=2\nACME_API_KEY=old\r\nC=3\n")
        self.assertEqual(after, b"A=1\r\nB=2\nACME_API_KEY=" + KEY + b"\r\nC=3\n")

    def test_the_dominant_ending_wins_for_a_new_line(self):
        after = self.save(b"A=1\r\nB=2\r\nC=3\n")
        self.assertEqual(after, b"A=1\r\nB=2\r\nC=3\n\r\nACME_API_KEY=" + KEY + b"\r\n")

    def test_old_mac_cr_endings_are_kept_too(self):
        after = self.save(b"A=1\rACME_API_KEY=old\rB=2\r")
        self.assertEqual(after, b"A=1\rACME_API_KEY=" + KEY + b"\rB=2\r")

    def test_exotic_separators_inside_a_line_are_not_line_breaks(self):
        # str.splitlines() would cut at \x0c, \x85 and U+2028 and write the
        # pieces back with \n - rewriting a line that was never ours
        raw = ("NOTE=a\x0cb\u2028c\u0085d\r\nACME_API_KEY=old\r\n"
               "LAST=\x1ce\r\n").encode("utf-8")
        after = self.save(raw)
        self.assertEqual(after, ("NOTE=a\x0cb\u2028c\u0085d\r\nACME_API_KEY=%s\r\n"
                                 "LAST=\x1ce\r\n" % FAKE_KEY).encode("utf-8"))

    def test_forget_keeps_the_files_endings(self):
        env = new_env()
        write_bytes(env, b"A=1\r\nACME_API_KEY=old\r\nB=2\r\n")
        self.assertTrue(store_mod.remove_key("ACME_API_KEY", env))
        self.assertEqual(read_bytes(env), b"A=1\r\nB=2\r\n")
        write_bytes(env, b"A=1\nACME_API_KEY=old\nB=2\n")
        self.assertTrue(store_mod.remove_key("ACME_API_KEY", env))
        self.assertEqual(read_bytes(env), b"A=1\nB=2\n")

    def test_read_env_reports_lines_without_their_endings(self):
        env = new_env()
        write_bytes(env, b"A=1\r\nexport B=2\nC=3")
        lines, index = store_mod.read_env(env)
        self.assertEqual(lines, ["A=1", "export B=2", "C=3"])
        self.assertEqual(index, {"A": 0, "B": 1, "C": 2})


# ------------------------------------------------------------------ 2


def same_path(a, b):
    """The same file by two spellings: Windows' readlink gives the
    extended-length form (\\\\?\\C:\\...) for a link made with a plain path."""
    def norm(p):
        for prefix in ("\\\\?\\UNC\\", "\\\\?\\"):
            if p.startswith(prefix):
                p = ("\\\\" if "UNC" in prefix else "") + p[len(prefix):]
                break
        return os.path.normcase(os.path.normpath(p))
    return norm(a) == norm(b)


def make_link(test, link, target):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError, AttributeError):
        test.skipTest("symbolic links are not available here")


class TestLinkedEnvFile(unittest.TestCase):
    def setUp(self):
        self.tmp = _isolation.mktemp()
        self.target = os.path.join(self.tmp, "elsewhere.env")
        write_bytes(self.target, b"SHARED=1\n")
        os.chmod(self.target, 0o644)
        self.proj = os.path.join(self.tmp, "proj")
        os.mkdir(self.proj)
        self.env = os.path.join(self.proj, ".env")
        make_link(self, self.env, self.target)

    def assert_untouched(self):
        self.assertTrue(os.path.islink(self.env), "the link was replaced")
        self.assertTrue(same_path(os.readlink(self.env), self.target),
                        (os.readlink(self.env), self.target))
        self.assertEqual(read_bytes(self.target), b"SHARED=1\n")
        self.assertEqual(os.listdir(self.proj), [".env"], "a stray temp file")
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(self.target).st_mode), 0o644)

    def test_saving_a_key_is_refused_and_nothing_changes(self):
        with self.assertRaises(store_mod.EnvFileRefused) as cm:
            store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, self.env)
        self.assertIsInstance(cm.exception, OSError)
        self.assertIn("link", str(cm.exception))
        self.assertNotIn(FAKE_KEY, str(cm.exception))
        self.assert_untouched()

    def test_a_dangling_link_is_refused_too(self):
        os.remove(self.target)
        with self.assertRaises(store_mod.EnvFileRefused):
            store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, self.env)
        self.assertTrue(os.path.islink(self.env))
        self.assertFalse(os.path.exists(self.target), "created through the link")
        self.assertEqual(os.listdir(self.proj), [".env"])

    def test_forget_is_refused_too(self):
        with self.assertRaises(store_mod.EnvFileRefused):
            store_mod.remove_key("SHARED", self.env)
        self.assert_untouched()

    def test_write_private_is_the_last_line_of_defence(self):
        with self.assertRaises(store_mod.EnvFileRefused):
            store_mod.write_private(self.env, "ACME_API_KEY=x\n")
        self.assert_untouched()

    def test_naming_the_real_file_is_the_way_out(self):
        store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, self.target)
        self.assertEqual(read_bytes(self.target),
                         b"SHARED=1\n\nACME_API_KEY=" + KEY + b"\n")

    def test_connect_refuses_before_asking_for_the_key(self):
        code, out = connect(recipe(), self.env, browser_open=boom,
                            prompt=boom, validate_fn=boom)
        self.assertEqual(code, 1)
        self.assertIn("link", out)
        self.assertIn("--env-file", out)
        self.assertIn(self.env, out)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("validated", out)
        self.assert_untouched()

    def test_connect_with_a_custom_store_is_not_blocked_by_the_env_link(self):
        code, out = connect(recipe(), self.env,
                            store_fn=lambda var, key: "kept elsewhere")
        self.assertEqual(code, 0, out)
        self.assert_untouched()

    def test_cli_exit_code_is_non_zero_and_plain(self):
        cat = {"acme": recipe()}
        out, err = io.StringIO(), io.StringIO()
        real = connect_mod.connect

        def connect_with_fakes(*a, **kw):          # the CLI's call, minus the terminal
            return real(*a, prompt=lambda _: FAKE_KEY,
                        validate_fn=lambda s, k: True, **kw)

        with mock.patch.object(recipes_mod, "load_recipes", return_value=cat), \
                mock.patch.object(connect_mod, "connect", connect_with_fakes), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(["connect", "acme", "--no-browser",
                                 "--env-file", self.env])
        self.assertEqual(code, 1)
        text = out.getvalue() + err.getvalue()
        self.assertIn("link", text)
        self.assertNotIn("Traceback", text)
        self.assertNotIn(FAKE_KEY, text)
        self.assert_untouched()

    def test_forget_cli_reports_it_and_exits_1(self):
        out = io.StringIO()
        fake = mock.Mock(detect_backend=lambda: None, label=lambda b: "no OS keychain")
        code = cli_mod._cmd_forget(recipe(env_var="SHARED"), self.env, out=out,
                                   keychain=fake)
        self.assertEqual(code, 1)
        self.assertIn("link", out.getvalue())
        self.assert_untouched()

    @unittest.skipIf(os.name == "nt", "POSIX mode bits")
    def test_lock_down_never_follows_a_link_to_chmod_something_else(self):
        self.assertFalse(store_mod._lock_down(self.env))
        self.assertEqual(stat.S_IMODE(os.stat(self.target).st_mode), 0o644)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits")
    def test_lock_down_still_locks_a_regular_file(self):
        plain = os.path.join(self.proj, "plain.env")
        write_bytes(plain, b"X=1\n")
        os.chmod(plain, 0o644)
        self.assertTrue(store_mod._lock_down(plain))
        self.assertEqual(store_mod.file_mode(plain), 0o600)

    def test_windows_acl_step_skips_a_link_too(self):
        calls = []
        before = stat.S_IMODE(os.stat(self.target).st_mode)

        def fake_run(argv, **kw):
            calls.append(argv)
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(store_mod.os, "name", "nt"), \
                mock.patch.object(store_mod.subprocess, "run", fake_run):
            self.assertFalse(store_mod._lock_down(self.env))
        self.assertEqual(calls, [], "icacls ran against a link")
        # unchanged (on Windows a mode is only the read-only flag: 0o666 there)
        self.assertEqual(stat.S_IMODE(os.stat(self.target).st_mode), before)


# ------------------------------------------------------------------ 4


def builtin(slug):
    return recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)[slug]


class TestInternationalisedHosts(unittest.TestCase):
    def test_unicode_and_punycode_spellings_are_one_owner(self):
        same = connect_mod.same_owner
        for a, b in (
                ("https://b\u00fccher.example/keys", "https://xn--bcher-kva.example/api"),
                ("https://www.b\u00fccher.example/", "https://API.XN--BCHER-KVA.EXAMPLE/"),
                ("https://B\u00dcCHER.example/", "https://b\u00fccher.example/"),
                # NFC vs NFD spelling of the same u-umlaut
                ("https://bu\u0308cher.example/", "https://b\u00fccher.example/"),
                # an ideographic full stop is a dot to the IDNA codec
                ("https://b\u00fccher\u3002example/", "https://xn--bcher-kva.example/"),
                ("https://console.\u65e5\u672c\u8a9e.jp/", "https://api.xn--wgv71a119e.jp/")):
            self.assertTrue(same(a, b), (a, b))
            self.assertTrue(same(b, a), (b, a))

    def test_registrable_domain_is_the_punycode_form(self):
        rd = connect_mod.registrable_domain
        self.assertEqual(rd("www.b\u00fccher.example"), "xn--bcher-kva.example")
        self.assertEqual(rd("API.XN--BCHER-KVA.EXAMPLE."), "xn--bcher-kva.example")
        self.assertEqual(rd("\u0430pple.com"), "xn--pple-43d.com")
        # plain names are untouched
        self.assertEqual(rd("api.stripe.com"), "stripe.com")
        self.assertEqual(rd("127.0.0.1"), "127.0.0.1")
        self.assertEqual(rd("::1"), "::1")

    def test_a_lookalike_is_a_different_owner(self):
        same = connect_mod.same_owner
        self.assertFalse(same("https://apple.com/", "https://\u0430pple.com/"))   # Cyrillic a
        self.assertFalse(same("https://\u0430pple.com/", "https://xn--pple-43d.com.evil.example/"))
        self.assertFalse(same("https://b\u00fccher.example/", "https://bucher.example/"))

    def test_names_the_codec_rejects_fall_back_to_their_text(self):
        host = connect_mod._host
        for odd in ("https://a..b.example/", "https://" + "a" * 70 + ".example/",
                    "https://ex\u2028ample.example/", "https://b\u00fc..example/"):
            self.assertIsInstance(host(odd), str)               # no exception
            self.assertTrue(connect_mod.same_owner(odd, odd), odd)   # equal to itself ...
        # ... and not to an unrelated host
        self.assertFalse(connect_mod.same_owner("https://ex\u2028ample.example/",
                                                "https://example.example/"))
        self.assertEqual(connect_mod.registrable_domain("a..b.example"), "b.example")

    def test_trailing_dot_case_port_and_userinfo(self):
        host = connect_mod._host
        for url in ("https://API.Stripe.COM./v1", "https://api.stripe.com:8443/v1",
                    "https://user@api.stripe.com/v1", "https://u:p%40ss@API.stripe.com.:443/v1",
                    "https://api.stripe.com../v1"):
            self.assertEqual(host(url), "api.stripe.com", url)
        self.assertEqual(host("https://B\u00dcCHER.Example.:8443/x"), "xn--bcher-kva.example")
        self.assertEqual(host("https://[::1]:8443/x"), "::1")
        self.assertEqual(host("https://127.0.0.1./x"), "127.0.0.1")
        self.assertEqual(host("https:///nohost"), "")
        same = connect_mod.same_owner
        self.assertTrue(same("https://api.stripe.com./v1", "https://dashboard.stripe.com:443/apikeys"))
        self.assertTrue(same("https://user:pw@API.STRIPE.COM:8443/v1", "https://stripe.com/"))
        # the real host is the one AFTER the last @, whatever sits before it
        self.assertFalse(same("https://stripe.com@evil.example/v1", "https://dashboard.stripe.com/apikeys"))
        self.assertFalse(same("https://stripe.com:443@evil.example/v1", "https://stripe.com/"))

    def test_builtin_trusted_host_matches_whatever_the_spelling(self):
        r = builtin("anthropic")
        self.assertIn("api.anthropic.com", r["validate"]["trusted_hosts"])
        for url in ("https://API.Anthropic.com./v1/models", "https://api.anthropic.com:443/v1/models",
                    "https://me@api.anthropic.com/v1/models"):
            poisoned = dict(r, validate=dict(r["validate"], url=url))
            out = io.StringIO()
            self.assertTrue(connect_mod._require_cross_domain_confirmation(
                poisoned, out, confirm_in=boom), url)
            self.assertIn("built-in recipe", out.getvalue())
        # a different host - even one that merely contains the trusted name - still prompts
        for url in ("https://api.anthropic.com.evil.example/v1", "https://xapi.anthropic.com/v1",
                    "https://api.anthropic.com@evil.example/v1"):
            poisoned = dict(r, validate=dict(r["validate"], url=url))
            out = io.StringIO()
            self.assertFalse(connect_mod._require_cross_domain_confirmation(
                poisoned, out, confirm_in=lambda _: "no"), url)
            self.assertIn("DIFFERENT domain", out.getvalue())

    def test_a_homograph_is_visible_in_the_warning(self):
        r = recipe(key_url="https://apple.com/keys")
        r["validate"]["url"] = "https://\u0430pple.com/check"            # Cyrillic a
        out = io.StringIO()
        self.assertFalse(connect_mod._require_cross_domain_confirmation(
            r, out, confirm_in=lambda _: "no"))
        text = out.getvalue()
        self.assertIn("DIFFERENT domain", text)
        # the Unicode spelling AND the punycode one, side by side; the plain
        # name stays plain
        self.assertIn("\u0430pple.com [xn--pple-43d.com] vs apple.com", text)
        self.assertIn("xn--", text.split("vs apple.com", 1)[1])        # and it is explained
        self.assertIn("other alphabets", text)

    def test_punycode_in_the_recipe_is_shown_with_its_unicode_spelling(self):
        r = recipe(key_url="https://apple.com/keys")
        r["validate"]["url"] = "https://xn--pple-43d.com/check"
        out = io.StringIO()
        self.assertFalse(connect_mod._require_cross_domain_confirmation(
            r, out, confirm_in=lambda _: "no"))
        self.assertIn("\u0430pple.com [xn--pple-43d.com] vs apple.com", out.getvalue())

    def test_ascii_warning_is_unchanged(self):
        r = recipe()
        r["validate"]["url"] = "https://validator.evil.test/check"
        out = io.StringIO()
        self.assertFalse(connect_mod._require_cross_domain_confirmation(
            r, out, confirm_in=lambda _: "no"))
        self.assertIn("(evil.test vs acme.test).", out.getvalue())
        self.assertNotIn("alphabets", out.getvalue())
        self.assertNotIn("[", out.getvalue())

    def test_describe_domain(self):
        d = connect_mod.describe_domain
        self.assertEqual(d("stripe.com"), "stripe.com")
        self.assertEqual(d("xn--bcher-kva.example"), "b\u00fccher.example [xn--bcher-kva.example]")
        self.assertEqual(d("xn--zz.example"), "xn--zz.example")           # not valid punycode: as is
        self.assertEqual(d("b\u00fc..example"), "b\u00fc..example")      # codec rejected it: as is
        self.assertEqual(d(""), "")

    def test_a_homograph_connect_stops_before_the_key_is_asked_for(self):
        r = recipe(key_url="https://apple.com/keys")
        r["validate"]["url"] = "https://\u0430pple.com/check"
        code, out = connect(r, new_env(), confirm_in=lambda _: "", prompt=boom,
                            validate_fn=boom)
        self.assertEqual(code, 1)
        self.assertIn("xn--pple-43d.com", out)
        self.assertIn("nothing was sent", out)

    def test_warning_survives_a_console_that_cannot_print_it(self):
        # cp1252 cannot encode the Cyrillic a; cli._harden_streams() makes
        # the console replace it, and the xn-- form is still readable
        r = recipe(key_url="https://apple.com/keys")
        r["validate"]["url"] = "https://\u0430pple.com/check"
        raw = io.BytesIO()
        console = io.TextIOWrapper(raw, encoding="cp1252", errors="replace")
        connect_mod._require_cross_domain_confirmation(r, console, confirm_in=lambda _: "no")
        console.flush()
        text = raw.getvalue().decode("cp1252")
        self.assertIn("[xn--pple-43d.com]", text)


# ------------------------------------------------------------------ 5

ABSENT = object()          # "the member is not in the message at all"
PA_ENTRIES = [
    {"name": "Cat Facts", "url": "https://catfacts.example/", "auth": "No",
     "description": "Daily cat facts", "https": "Yes", "cors": "No",
     "category": "Animals"},
    {"name": "Weatherstack", "url": "https://weatherstack.example/",
     "auth": "apiKey", "description": "Real-time weather", "https": "Yes",
     "cors": "No", "category": "Weather"},
]


def request(method, params=ABSENT, rid=1):
    req = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not ABSENT:
        req["params"] = params
    return req


def tool_call(name, arguments=ABSENT, rid=1):
    params = {"name": name}
    if arguments is not ABSENT:
        params["arguments"] = arguments
    return request("tools/call", params, rid)


def handle(req):
    return mcp_mod.handle(req, {"acme": recipe()}, pa_loader=lambda: PA_ENTRIES)


def tool_text(response):
    return json.loads(response["result"]["content"][0]["text"])


class TestMcpInvalidParams(unittest.TestCase):
    NOT_OBJECTS = (None, [], [1, 2], "x", "", 0, 7, 1.5, True, False)

    def assert_invalid_params(self, response, mentions=None):
        self.assertIn("error", response, response)
        self.assertEqual(response["error"]["code"], -32602, response)
        self.assertEqual(response["jsonrpc"], "2.0")
        message = response["error"]["message"]
        self.assertNotIn("has no attribute", message)     # no Python internals
        self.assertNotIn("invalid literal", message)
        if mentions:
            self.assertIn(mentions, message)

    def test_params_that_are_not_an_object_on_tools_call(self):
        for bad in self.NOT_OBJECTS:
            r = handle(request("tools/call", bad, rid=11))
            self.assert_invalid_params(r, "params")
            self.assertEqual(r["id"], 11)

    def test_params_that_are_not_an_object_on_every_known_method(self):
        for method in ("initialize", "ping", "tools/list", "tools/call"):
            for bad in (None, [], "x", 3):
                self.assert_invalid_params(handle(request(method, bad)), "params")

    def test_an_unknown_method_is_still_method_not_found(self):
        self.assertEqual(handle(request("nope", None))["error"]["code"], -32601)

    def test_object_or_missing_params_are_fine_on_the_plain_methods(self):
        for method in ("initialize", "ping", "tools/list"):
            for params in (ABSENT, {}, {"cursor": None}):
                self.assertIn("result", handle(request(method, params)), (method, params))

    def test_tool_name_must_be_a_string(self):
        for bad in (ABSENT, None, 7, ["get_recipe"], {}):
            params = {} if bad is ABSENT else {"name": bad}
            self.assert_invalid_params(handle(request("tools/call", params)), "name")
        self.assert_invalid_params(handle(tool_call("nope", {})), "unknown tool: nope")

    def test_arguments_must_be_an_object(self):
        for tool in ("list_services", "get_recipe"):
            for bad in (None, [], ["a"], "service", 5, True):
                self.assert_invalid_params(handle(tool_call(tool, bad)), "arguments")

    def test_missing_required_arguments(self):
        for tool, arg in (("get_recipe", "service"), ("find_public_apis", "query"),
                          ("get_public_api", "name")):
            for given in (ABSENT, {}, {"other": 1}, {arg: None}):
                self.assert_invalid_params(handle(tool_call(tool, given)), arg)

    def test_wrongly_typed_arguments(self):
        for tool, given, arg in (
                ("get_recipe", {"service": 5}, "service"),
                ("get_recipe", {"service": ["acme"]}, "service"),
                ("find_public_apis", {"query": 5}, "query"),
                ("find_public_apis", {"query": "x", "limit": "abc"}, "limit"),
                ("find_public_apis", {"query": "x", "limit": True}, "limit"),
                ("find_public_apis", {"query": "x", "limit": 2.5}, "limit"),
                ("find_public_apis", {"query": "x", "auth": 3}, "auth"),
                ("find_public_apis", {"query": "x", "category": {}}, "category"),
                ("get_public_api", {"name": 7}, "name")):
            self.assert_invalid_params(handle(tool_call(tool, given)), arg)

    def test_valid_calls_still_work(self):
        for given in (ABSENT, {}, {"extra": 1}):
            self.assertEqual(tool_text(handle(tool_call("list_services", given)))
                             [0]["service"], "acme")
        r = handle(tool_call("get_recipe", {"service": "acme"}))
        self.assertIn("https://acme.test/keys", r["result"]["content"][0]["text"])
        # a service that does not exist is a tool-level error the model can read
        for service in ("nope", ""):
            r = handle(tool_call("get_recipe", {"service": service}))
            self.assertNotIn("error", r)
            self.assertTrue(r["result"]["isError"])
        # null for an OPTIONAL argument means "not given" (models send it)
        r = handle(tool_call("find_public_apis", {"query": "cat", "auth": None,
                                                  "category": None, "limit": None}))
        self.assertEqual([h["name"] for h in tool_text(r)], ["Cat Facts"])
        r = handle(tool_call("find_public_apis", {"query": "weather", "limit": 5}))
        self.assertEqual([h["name"] for h in tool_text(r)], ["Weatherstack"])
        self.assertEqual(tool_text(handle(tool_call("get_public_api",
                                                    {"name": "Cat Facts"})))["name"],
                         "Cat Facts")

    def test_the_other_error_codes_are_unchanged(self):
        self.assertEqual(mcp_mod.handle([1, 2], {})["error"]["code"], -32600)
        self.assertEqual(mcp_mod.handle({"jsonrpc": "2.0", "id": 1}, {})["error"]["code"],
                         -32600)
        self.assertEqual(handle(request("nope"))["error"]["code"], -32601)


class TestMcpServerKeepsRunning(unittest.TestCase):
    def serve(self, *messages):
        stdin = io.BytesIO("".join(json.dumps(m) + "\n" for m in messages).encode("utf-8"))
        stdout = io.BytesIO()
        code = mcp_mod.serve({"acme": recipe()}, pa_loader=lambda: PA_ENTRIES,
                             stdin=stdin, stdout=stdout)
        self.assertEqual(code, 0)
        return [json.loads(line) for line in
                stdout.getvalue().decode("utf-8").splitlines() if line]

    def test_bad_requests_get_32602_then_the_next_one_is_served(self):
        replies = self.serve(
            request("tools/call", None, 1),
            request("tools/call", [1], 2),
            tool_call("get_recipe", None, 3),
            tool_call("get_recipe", {}, 4),
            tool_call("find_public_apis", {"query": "x", "limit": "abc"}, 5),
            # notifications - no id - are never answered, however broken
            {"jsonrpc": "2.0", "method": "tools/call", "params": None},
            {"jsonrpc": "2.0", "method": "tools/call",
             "params": {"name": "get_recipe", "arguments": None}},
            {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": None},
            request("ping", rid=9),
            tool_call("get_recipe", {"service": "acme"}, 10))
        self.assertEqual([(r["id"], r.get("error", {}).get("code")) for r in replies],
                         [(1, -32602), (2, -32602), (3, -32602), (4, -32602),
                          (5, -32602), (9, None), (10, None)])
        self.assertEqual(replies[-2], {"jsonrpc": "2.0", "id": 9, "result": {}})
        self.assertIn("https://acme.test/keys", replies[-1]["result"]["content"][0]["text"])


# ------------------------------------------------------------------ 9


class _WriteFails(io.StringIO):
    """stdout whose reader has gone away: the write itself fails."""
    def write(self, text):
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")


class _FlushFails(io.StringIO):
    """stdout that buffers happily and only fails when it is flushed - what
    a real pipe does, so the error surfaces at interpreter exit."""
    def flush(self):
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")


class TestBrokenPipe(unittest.TestCase):
    def run_main(self, argv, stdout):
        err = io.StringIO()
        with mock.patch.object(sys, "stdout", stdout), redirect_stderr(err):
            code = cli_mod.main(argv)
        return code, err.getvalue()

    def test_a_failing_write_ends_quietly(self):
        code, err = self.run_main(["list"], _WriteFails())
        self.assertEqual(code, 1)
        self.assertEqual(err, "")

    def test_a_failing_flush_ends_quietly_for_normal_output(self):
        code, err = self.run_main(["list"], _FlushFails())
        self.assertEqual(code, 1)
        self.assertEqual(err, "")

    def test_a_failing_flush_ends_quietly_after_argparse_exits(self):
        # --version / --help print and exit by exception; the text is still
        # in the buffer when the interpreter would try (and fail) to flush it
        for argv in (["--version"], ["--help"], ["connect", "--help"]):
            code, err = self.run_main(argv, _FlushFails())
            self.assertEqual(code, 1, argv)
            self.assertEqual(err, "", argv)

    def test_normal_runs_and_exit_codes_are_unchanged(self):
        out = io.StringIO()
        code, err = self.run_main(["list"], out)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("stuntkey connect <service>", out.getvalue())
        with self.assertRaises(SystemExit) as cm:
            self.run_main(["--version"], io.StringIO())
        self.assertEqual(cm.exception.code, 0)
        with self.assertRaises(SystemExit) as cm:
            self.run_main(["connect"], io.StringIO())        # usage error
        self.assertEqual(cm.exception.code, 2)

    @unittest.skipIf(os.name == "nt", "POSIX pipe semantics")
    def test_a_real_closed_pipe_for_every_printing_command(self):
        def child(argv, unbuffered, stdin=None):
            env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
            if unbuffered:
                env["PYTHONUNBUFFERED"] = "1"
            r, w = os.pipe()
            os.close(r)                       # nobody will ever read this
            try:
                proc = subprocess.Popen(
                    [sys.executable, "-m", "stuntkey"] + argv, stdout=w,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE if stdin is not None else None,
                    cwd=_isolation.REPO, env=env)
            finally:
                os.close(w)
            _out, err = proc.communicate(stdin, timeout=60)
            return proc.returncode, err.decode("utf-8", "replace")

        ping = b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n'
        for unbuffered in (False, True):
            for argv, stdin in ((["list"], None), (["--version"], None),
                                (["--help"], None), (["connect", "--help"], None),
                                (["mcp"], ping)):
                code, err = child(argv, unbuffered, stdin)
                label = (argv, "unbuffered" if unbuffered else "buffered")
                self.assertEqual(err, "", label)
                self.assertIn(code, (0, 1), label)     # not 120, not a traceback


class _DeadPipe(io.BytesIO):
    """The binary layer of a stdout whose reader has gone away, behaving as
    measured on Windows 11 / Python 3.11: write() is buffered and works,
    flush() raises a plain OSError(EINVAL) - not a BrokenPipeError. It sits
    on a real pipe whose read end is closed, so "descriptor 1 was pointed at
    the null device" can be observed: from then on the same flush succeeds,
    exactly like the interpreter's own flush at exit."""

    def __init__(self, unbuffered=False):
        super().__init__()
        r, w = os.pipe()
        os.close(r)
        self.fd = w
        self.unbuffered = unbuffered      # python -u: write() fails by itself
        self.dead = True

    def fileno(self):
        return self.fd

    def probe(self):
        if not self.dead:
            return
        try:
            os.write(self.fd, b"\n")
        except BrokenPipeError:
            raise OSError(errno.EINVAL, "Invalid argument") from None

    def write(self, data):
        count = super().write(data)
        if self.unbuffered:
            self.probe()
        return count

    def flush(self):
        super().flush()
        self.probe()


PING = b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n'


class _Win32Failure(OSError):
    """An OSError as a failed Win32 call raises it on Windows: errno EINVAL
    plus a winerror (the closed-pipe error has none)."""
    winerror = 87


class TestClosedPipeOnWindows(unittest.TestCase):
    """On Windows a pipe nobody reads any more does not raise BrokenPipeError.
    print() of small output works (it is buffered); the flush raises a plain
    OSError with errno 22 (EINVAL), and with `python -u` print() itself does.
    Uncaught, the interpreter's flush at exit fails again ("Exception ignored
    ... OSError: [Errno 22]", exit status 120). Reproduced here with a stdout
    that behaves the same way and a patched platform flag."""

    def dead_stdout(self, unbuffered=False):
        pipe = _DeadPipe(unbuffered)
        stdout = io.TextIOWrapper(pipe, encoding="utf-8",
                                  write_through=unbuffered)

        def release():
            pipe.dead = False             # let the wrapper close quietly
            stdout.close()
            os.close(pipe.fd)
        self.addCleanup(release)
        return pipe, stdout

    def run_main(self, argv, stdout, windows, stdin=None):
        err = io.StringIO()
        with mock.patch.object(cli_mod, "_ON_WINDOWS", windows), \
                mock.patch.object(sys, "stdout", stdout), \
                mock.patch.object(sys, "stdin",
                                  stdin if stdin is not None else sys.stdin), \
                redirect_stderr(err):
            code = cli_mod.main(argv)
        return code, err.getvalue()

    def mcp_stdin(self):
        return io.TextIOWrapper(io.BytesIO(PING), encoding="utf-8")

    def assert_quiet_exit(self, argv, unbuffered=False, stdin=None):
        pipe, stdout = self.dead_stdout(unbuffered)
        code, err = self.run_main(argv, stdout, True, stdin)
        label = (argv, "unbuffered" if unbuffered else "buffered")
        self.assertEqual(code, 1, label)                 # no exception escaped
        self.assertEqual(err, "", label)
        os.write(pipe.fd, b"x")           # descriptor 1 now goes to the null device
        stdout.flush()                    # so the flush at interpreter exit is clean

    def test_small_output_then_a_failing_flush(self):
        self.assert_quiet_exit(["list"])

    def test_unbuffered_output_failing_inside_print(self):
        self.assert_quiet_exit(["list"], unbuffered=True)

    def test_argparse_exits_too(self):
        for argv in (["--version"], ["--help"], ["connect", "--help"]):
            self.assert_quiet_exit(argv)
            self.assert_quiet_exit(argv, unbuffered=True)

    def test_the_mcp_loop(self):
        self.assert_quiet_exit(["mcp"], stdin=self.mcp_stdin())
        self.assert_quiet_exit(["mcp"], unbuffered=True, stdin=self.mcp_stdin())

    def test_einval_is_not_swallowed_off_windows(self):
        for unbuffered in (False, True):
            for argv in (["list"], ["mcp"]):
                pipe, stdout = self.dead_stdout(unbuffered)
                stdin = self.mcp_stdin() if argv == ["mcp"] else None
                # STUNTKEY_DEBUG=1: without it main() turns the error into a
                # plain sentence and exit status 1 (tests/test_v011_round4.py)
                with mock.patch.dict(os.environ, {"STUNTKEY_DEBUG": "1"}), \
                        self.assertRaises(OSError) as cm:
                    self.run_main(argv, stdout, False, stdin)
                self.assertEqual(cm.exception.errno, errno.EINVAL)
                self.assertNotIsInstance(cm.exception, BrokenPipeError)
                # fd 1 untouched: the dead pipe still refuses (BrokenPipeError
                # on POSIX, a plain OSError(EINVAL) on Windows)
                with self.assertRaises(OSError):
                    os.write(pipe.fd, b"x")

    def test_other_errors_are_never_taken_for_a_closed_pipe(self):
        # EnvFileRefused is itself an OSError with errno EINVAL - it names a
        # file, a pipe error does not
        errors = (store_mod.EnvFileRefused(".env", store_mod.LINK_REASON),
                  OSError(errno.EINVAL, "Invalid argument", "some.file"),
                  _Win32Failure(errno.EINVAL, "The parameter is incorrect"),
                  OSError(errno.ENOENT, "No such file or directory"),
                  PermissionError(errno.EACCES, "Permission denied"))
        for windows in (False, True):
            for exc in errors:
                # stdout is a throwaway here: if the code ever did mistake
                # one of these for a closed pipe it would point *its* fd at
                # the null device, never the test runner's own
                _pipe, stdout = self.dead_stdout()
                with mock.patch.object(cli_mod, "_ON_WINDOWS", windows), \
                        mock.patch.object(sys, "stdout", stdout), \
                        mock.patch.object(cli_mod, "_main", side_effect=exc), \
                        mock.patch.dict(os.environ, {"STUNTKEY_DEBUG": "1"}):
                    with self.assertRaises(OSError) as cm:
                        cli_mod.main(["list"])
                self.assertIs(cm.exception, exc)

    def test_the_helper(self):
        pipe_errors = (BrokenPipeError(errno.EPIPE, "Broken pipe"),
                       OSError(errno.EPIPE, "Broken pipe"))
        plain_einval = OSError(errno.EINVAL, "Invalid argument")
        for windows in (False, True):
            with mock.patch.object(cli_mod, "_ON_WINDOWS", windows):
                for exc in pipe_errors:
                    self.assertTrue(cli_mod.is_closed_pipe(exc), exc)
                self.assertEqual(cli_mod.is_closed_pipe(plain_einval), windows)
                for exc in (OSError(errno.EINVAL, "Invalid argument", "f"),
                            _Win32Failure(errno.EINVAL, "The parameter is incorrect"),
                            OSError(errno.ENOENT, "No such file"),
                            ValueError("x"), KeyError("x")):
                    self.assertFalse(cli_mod.is_closed_pipe(exc), exc)

    def test_the_flag_follows_the_platform(self):
        self.assertEqual(cli_mod._ON_WINDOWS, os.name == "nt")


# -------------------------------------------------------------- extras


class TestByteOrderMark(unittest.TestCase):
    BOM = b"\xef\xbb\xbf"

    def test_the_first_line_is_found_and_the_bom_kept(self):
        env = new_env()
        write_bytes(env, self.BOM + b"ACME_API_KEY=old\r\nOTHER=1\r\n")
        stored = store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, env)
        self.assertTrue(stored.updated, "the BOM hid the variable on line 1")
        self.assertEqual(read_bytes(env),
                         self.BOM + b"ACME_API_KEY=" + KEY + b"\r\nOTHER=1\r\n")

    def test_export_prefix_behind_a_bom(self):
        env = new_env()
        write_bytes(env, self.BOM + b"export ACME_API_KEY=old\n")
        store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, env)
        self.assertEqual(read_bytes(env), self.BOM + b"export ACME_API_KEY=" + KEY + b"\n")

    def test_a_bom_file_without_our_variable_just_gets_a_line(self):
        env = new_env()
        write_bytes(env, self.BOM + b"OTHER=1\n")
        store_mod.store_key_result("ACME_API_KEY", FAKE_KEY, env)
        self.assertEqual(read_bytes(env),
                         self.BOM + b"OTHER=1\n\nACME_API_KEY=" + KEY + b"\n")

    def test_forget_removes_the_key_behind_a_bom_and_keeps_the_bom(self):
        env = new_env()
        write_bytes(env, self.BOM + b"ACME_API_KEY=old\nOTHER=1\n")
        self.assertTrue(store_mod.remove_key("ACME_API_KEY", env))
        self.assertEqual(read_bytes(env), self.BOM + b"OTHER=1\n")
        self.assertNotIn(b"old", read_bytes(env))
        # removing a later line leaves the BOM where it was
        write_bytes(env, self.BOM + b"A=1\nACME_API_KEY=old\n")
        self.assertTrue(store_mod.remove_key("ACME_API_KEY", env))
        self.assertEqual(read_bytes(env), self.BOM + b"A=1\n")

    def test_load_env_reads_the_first_variable_behind_a_bom(self):
        env = new_env()
        write_bytes(env, self.BOM + b"ACME_API_KEY=abc\nOTHER=1\n")
        self.assertEqual(store_mod.load_env(env), {"ACME_API_KEY": "abc", "OTHER": "1"})


class TestMalformedRecipeUrl(unittest.TestCase):
    BAD = ("https://[bad/keys", "https://exa[mple.com/", "https://a.com\uff0f@b.com/")

    def test_validate_recipe_raises_recipe_error(self):
        for bad in self.BAD:
            r = recipe(key_url=bad)
            with self.assertRaises(recipes_mod.RecipeError) as cm:
                recipes_mod.validate_recipe(r)
            self.assertIn("key_url", str(cm.exception))
            r = recipe()
            r["validate"]["url"] = bad
            with self.assertRaises(recipes_mod.RecipeError) as cm:
                recipes_mod.validate_recipe(r)
            self.assertIn("validate.url", str(cm.exception))

    def test_one_bad_recipe_file_never_breaks_the_catalog(self):
        d = _isolation.mktemp()
        good, bad = recipe(service="good"), recipe(service="bad", key_url=self.BAD[0])
        for r in (good, bad):
            with open(os.path.join(d, r["service"] + ".json"), "w", encoding="utf-8") as f:
                json.dump(r, f)
        err = io.StringIO()
        with redirect_stderr(err):
            catalog = recipes_mod.load_recipes(d)
        self.assertEqual(set(catalog), {"good"})
        self.assertIn("skipping bad recipe bad.json", err.getvalue())

    def test_add_reports_it_instead_of_a_traceback(self):
        answers = ["acme", "Acme", "https://[bad/keys", "ACME_API_KEY", "", "",
                   "Click new key", "", "GET", "https://acme.test/me", "bearer", "200"]
        out = io.StringIO()
        tmp = _isolation.mktemp()
        with mock.patch("builtins.input", lambda *_: answers.pop(0)), redirect_stdout(out):
            code = cli_mod._cmd_add(tmp)
        self.assertEqual(code, 1)
        self.assertIn("recipe incomplete", out.getvalue())
        self.assertIn("key_url", out.getvalue())
        self.assertEqual(os.listdir(tmp), [])


class TestDuplicateKeys(unittest.TestCase):
    """The same variable set twice in a .env. python-dotenv, Node dotenv,
    docker compose and a shell `source` all let the LAST assignment win, so
    updating the first one would save a key that never takes effect."""
    BOM = b"\xef\xbb\xbf"

    def save(self, raw, key=FAKE_KEY):
        env = new_env()
        write_bytes(env, raw)
        stored = store_mod.store_key_result("ACME_API_KEY", key, env)
        return stored, read_bytes(env)

    def test_the_last_assignment_is_the_one_updated(self):
        stored, after = self.save(
            b"ACME_API_KEY=first\nOTHER=1\nACME_API_KEY=second\n")
        self.assertEqual(
            after, b"ACME_API_KEY=first\nOTHER=1\nACME_API_KEY=" + KEY + b"\n")
        self.assertEqual((stored.updated, stored.duplicates), (True, 1))

    def test_every_earlier_line_is_left_alone(self):
        stored, after = self.save(
            b"ACME_API_KEY=a\nACME_API_KEY=b\nOTHER=1\nACME_API_KEY=c\n")
        self.assertEqual(
            after, b"ACME_API_KEY=a\nACME_API_KEY=b\nOTHER=1\nACME_API_KEY="
            + KEY + b"\n")
        self.assertEqual(stored.duplicates, 2)

    def test_crlf_file(self):
        stored, after = self.save(
            b"ACME_API_KEY=a\r\nOTHER=1\r\nACME_API_KEY=b\r\n")
        self.assertEqual(
            after, b"ACME_API_KEY=a\r\nOTHER=1\r\nACME_API_KEY=" + KEY + b"\r\n")
        self.assertEqual(stored.duplicates, 1)

    def test_file_that_is_not_utf8(self):
        stored, after = self.save(
            b"# caf\xe9\nACME_API_KEY=na\xefve\nOTHER=1\nACME_API_KEY=old\n")
        self.assertEqual(
            after, b"# caf\xe9\nACME_API_KEY=na\xefve\nOTHER=1\nACME_API_KEY="
            + KEY + b"\n")
        self.assertEqual(stored.duplicates, 1)

    def test_export_and_plain_forms(self):
        _, after = self.save(b"export ACME_API_KEY=a\nACME_API_KEY=b\n")
        self.assertEqual(after, b"export ACME_API_KEY=a\nACME_API_KEY=" + KEY + b"\n")
        _, after = self.save(b"ACME_API_KEY=a\nexport ACME_API_KEY=b\n")
        self.assertEqual(after, b"ACME_API_KEY=a\nexport ACME_API_KEY=" + KEY + b"\n")

    def test_quoted_forms(self):
        _, after = self.save(b'ACME_API_KEY="a b"\nACME_API_KEY=\'c d\'\n')
        self.assertEqual(after, b'ACME_API_KEY="a b"\nACME_API_KEY=' + KEY + b"\n")
        _, after = self.save(b"ACME_API_KEY='c d'\nACME_API_KEY=\"a b\"\n")
        self.assertEqual(after, b"ACME_API_KEY='c d'\nACME_API_KEY=" + KEY + b"\n")
        # a key that itself needs quoting is written quoted, still last
        _, after = self.save(b"ACME_API_KEY=a\nACME_API_KEY=b\n", key='ab#c d"e')
        self.assertEqual(after, b"ACME_API_KEY=a\nACME_API_KEY='ab#c d\"e'\n")

    def test_behind_a_byte_order_mark(self):
        stored, after = self.save(self.BOM + b"ACME_API_KEY=a\nACME_API_KEY=b\n")
        self.assertEqual(
            after, self.BOM + b"ACME_API_KEY=a\nACME_API_KEY=" + KEY + b"\n")
        self.assertEqual(stored.duplicates, 1)

    def test_mixed_endings_keep_the_last_lines_own(self):
        _, after = self.save(b"ACME_API_KEY=a\r\nOTHER=1\nACME_API_KEY=b\r\nTAIL=1\n")
        self.assertEqual(
            after, b"ACME_API_KEY=a\r\nOTHER=1\nACME_API_KEY=" + KEY + b"\r\nTAIL=1\n")

    def test_a_single_assignment_is_not_a_duplicate(self):
        stored, _ = self.save(b"OTHER=1\nACME_API_KEY=old\n")
        self.assertEqual((stored.updated, stored.duplicates), (True, 0))
        stored, _ = self.save(b"OTHER=1\n")
        self.assertEqual((stored.updated, stored.duplicates), (False, 0))

    def test_comments_and_other_names_are_not_duplicates(self):
        stored, after = self.save(
            b"# ACME_API_KEY=old\nacme_api_key=lower\nACME_API_KEY_2=x\n"
            b"ACME_API_KEY=real\n")
        self.assertEqual(stored.duplicates, 0)
        self.assertEqual(
            after, b"# ACME_API_KEY=old\nacme_api_key=lower\nACME_API_KEY_2=x\n"
            b"ACME_API_KEY=" + KEY + b"\n")

    def test_reading_agrees_with_the_readers_that_matter(self):
        env = new_env()
        write_bytes(env, b"ACME_API_KEY=first\nOTHER=1\nACME_API_KEY=second\n")
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], "second")
        _lines, index = store_mod.read_env(env)
        self.assertEqual(index["ACME_API_KEY"], 2)

    # -- forget removes every assignment, so no older one springs back ----

    def test_forget_removes_every_assignment(self):
        env = new_env()
        write_bytes(env, b'ACME_API_KEY=a\nOTHER=1\nexport ACME_API_KEY="b c"\n'
                         b"TAIL=1\nACME_API_KEY='c'\n")
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 3)
        self.assertEqual(read_bytes(env), b"OTHER=1\nTAIL=1\n")
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 0)

    def test_forget_in_crlf_and_non_utf8_files(self):
        env = new_env()
        write_bytes(env, b"# caf\xe9\r\nACME_API_KEY=a\r\nOTHER=na\xefve\r\n"
                         b"ACME_API_KEY=b\r\n")
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 2)
        self.assertEqual(read_bytes(env), b"# caf\xe9\r\nOTHER=na\xefve\r\n")

    def test_forget_keeps_a_byte_order_mark_when_the_first_line_goes(self):
        env = new_env()
        write_bytes(env, self.BOM + b"ACME_API_KEY=a\nACME_API_KEY=b\nOTHER=1\n")
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 2)
        self.assertEqual(read_bytes(env), self.BOM + b"OTHER=1\n")

    # -- the person is told, plainly ---------------------------------------

    def test_connect_says_which_line_it_updated(self):
        env = new_env()
        write_bytes(env, b"ACME_API_KEY=old1\nACME_API_KEY=old2\n")
        code, out = connect(recipe(), env)
        self.assertEqual(code, 0, out)
        self.assertIn(f"ACME_API_KEY appears twice in {env}; "
                      "I updated the one that takes effect", out)
        self.assertNotIn(FAKE_KEY, out)
        self.assertEqual(read_bytes(env),
                         b"ACME_API_KEY=old1\nACME_API_KEY=" + KEY + b"\n")
        write_bytes(env, b"ACME_API_KEY=1\nACME_API_KEY=2\nACME_API_KEY=3\n")
        code, out = connect(recipe(), env)
        self.assertIn(f"ACME_API_KEY appears 3 times in {env}; ", out)

    def test_connect_says_nothing_extra_without_a_duplicate(self):
        env = new_env()
        write_bytes(env, b"OTHER=1\nACME_API_KEY=old\n")
        code, out = connect(recipe(), env)
        self.assertEqual(code, 0, out)
        self.assertNotIn("appears", out)
        self.assertNotIn("note:", out)

    def test_forget_says_how_many_it_removed(self):
        env = new_env()
        write_bytes(env, b"ACME_API_KEY=a\nOTHER=1\nACME_API_KEY=b\n")
        fake = types.SimpleNamespace(detect_backend=lambda: None,
                                     label=lambda b: "no OS keychain")
        out = io.StringIO()
        code = cli_mod._cmd_forget(recipe(), env, out=out, keychain=fake)
        self.assertEqual(code, 0)
        self.assertIn(f"ACME_API_KEY appeared twice in {env}; I removed both",
                      out.getvalue())
        self.assertEqual(read_bytes(env), b"OTHER=1\n")
        write_bytes(env, b"ACME_API_KEY=a\nACME_API_KEY=b\nACME_API_KEY=c\n")
        out = io.StringIO()
        cli_mod._cmd_forget(recipe(), env, out=out, keychain=fake)
        self.assertIn(f"ACME_API_KEY appeared 3 times in {env}; I removed all 3",
                      out.getvalue())
        # a single line: no note
        write_bytes(env, b"ACME_API_KEY=a\nOTHER=1\n")
        out = io.StringIO()
        cli_mod._cmd_forget(recipe(), env, out=out, keychain=fake)
        self.assertNotIn("appeared", out.getvalue())


class TestReadmeValidationNote(unittest.TestCase):
    def test_connect_section_says_to_validate_on_your_own_computer(self):
        with open(os.path.join(REPO, "docs", "guide.md"), encoding="utf-8") as f:
            text = f.read()
        # the note belongs where validation is described
        start = text.index("## A connect, annotated")
        end = text.index("## Where the key goes")
        section = " ".join(text[start:end].split()).lower()
        for phrase in ("run it on your own computer",
                       "cloud coding agents, sandboxes and some company proxies",
                       "add their own credentials",
                       '"valid" for any key, even a made-up one'):
            self.assertIn(phrase, section)


REPO_URL = "https://github.com/calasdan-sketch/stuntkey"
HOME_URL = "https://calasautomations.com/devtools/stuntkey/"


class TestPackagingMetadata(unittest.TestCase):
    def pyproject(self):
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
            return tomllib.load(f)

    def test_license_is_the_mit_text_and_declared_as_spdx(self):
        with open(os.path.join(REPO, "LICENSE"), encoding="utf-8") as f:
            self.assertTrue(f.read().startswith("MIT License"))
        project = self.pyproject()["project"]
        self.assertEqual(project["license"], "MIT")
        self.assertEqual(project["license-files"], ["LICENSE"])
        # a "License ::" classifier next to an SPDX expression is an error
        # in setuptools >= 77
        self.assertFalse([c for c in project["classifiers"]
                          if c.startswith("License ::")])
        self.assertIn("setuptools>=77",
                      self.pyproject()["build-system"]["requires"])

    def test_classifiers_describe_the_project(self):
        classifiers = set(self.pyproject()["project"]["classifiers"])
        wanted = {
            "Development Status :: 4 - Beta",
            "Environment :: Console",
            "Intended Audience :: Developers",
            "Intended Audience :: End Users/Desktop",
            "Operating System :: Microsoft :: Windows",
            "Operating System :: MacOS",
            "Operating System :: POSIX :: Linux",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
            "Programming Language :: Python :: 3.13",
            "Programming Language :: Python :: 3.14",
            "Topic :: Security",
        }
        self.assertEqual(wanted - classifiers, set())

    def test_keywords_and_project_urls(self):
        project = self.pyproject()["project"]
        self.assertTrue(project["keywords"])
        self.assertTrue(all(isinstance(k, str) and k.strip()
                            for k in project["keywords"]))
        self.assertEqual(project["urls"],
                         {"Homepage": HOME_URL, "Issues": REPO_URL + "/issues",
                          "Source": REPO_URL,
                          "Documentation": HOME_URL,
                          "Security": REPO_URL + "/security/policy",
                          "Changelog": REPO_URL + "/blob/main/CHANGELOG.md"})
        self.assertEqual(project["authors"], [{"name": "Calas Automations Inc."}])


class TestOneVersion(unittest.TestCase):
    """The version lives in stuntkey/__init__.py and pyproject.toml; every
    other place that prints it reads it from there, so a bump cannot leave a
    stale copy behind (the public-APIs User-Agent still said 0.2.0)."""

    def test_pyproject_matches_the_package(self):
        with open(os.path.join(REPO, "pyproject.toml"), encoding="utf-8") as f:
            m = re.search(r'^version\s*=\s*"([^"]+)"', f.read(), re.M)
        self.assertEqual(m.group(1), __version__)

    def test_command_line_reports_it(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            cli_mod.main(["--version"])
        self.assertIn(__version__, out.getvalue())

    def test_mcp_server_info_reports_it(self):
        info = handle(request("initialize", {}))["result"]["serverInfo"]
        self.assertEqual(info, {"name": "stuntkey", "version": __version__})

    def test_validation_user_agent_carries_it(self):
        spec = {"url": "https://acme.test/me", "auth": {"type": "bearer"}}
        req = validate_mod._build_request(spec, FAKE_KEY)
        self.assertEqual(req.get_header("User-agent"),
                         f"stuntkey/{__version__}")

    def test_directory_download_user_agent_carries_it(self):
        seen = []

        class Reply:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"### Weather\n"

        def fake_urlopen(req, timeout=None):
            seen.append(req.get_header("User-agent"))
            return Reply()

        cache = os.path.join(_isolation.mktemp(), "public-apis.md")
        with mock.patch.object(publicapis_mod, "cache_path", lambda: cache), \
                mock.patch.object(publicapis_mod.urllib.request, "urlopen",
                                  fake_urlopen):
            publicapis_mod.fetch(refresh=True)
        self.assertEqual(seen, [f"stuntkey/{__version__}"])


if __name__ == "__main__":
    unittest.main()
