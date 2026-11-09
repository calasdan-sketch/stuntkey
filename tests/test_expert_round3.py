"""Expert round 3: forget asks first; and the items below as they were added."""

import io
import json
import os
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import cli as cli_mod
from stuntkey import clients as clients_mod
from stuntkey import gitscan as gitscan_mod
from stuntkey import scan as scan_mod
from stuntkey import scrub as scrub_mod
from stuntkey import hook as hook_mod
from stuntkey import keychain as keychain_mod
from stuntkey import recipes as recipes_mod
from stuntkey import store as store_mod

KEY = "sk-test-0123456789abcdefABCDEF"


def recipe():
    return {"service": "acme", "display": "Acme", "env_var": "ACME_API_KEY",
            "key_url": "https://acme.test/keys", "steps": [], "scopes": [],
            "docs": "", "validate": {"method": "GET", "url": "https://acme.test/me",
                                     "auth": {"type": "bearer"}, "expect": [200]}}


class FakeKeychain:
    """Stands in for the keychain module; counts deletes."""
    KeychainError = keychain_mod.KeychainError

    def __init__(self):
        self.deleted = 0

    def detect_backend(self):
        return "fake"

    def label(self, backend):
        return "fake keychain"

    def delete(self, service, env_var, backend):
        self.deleted += 1
        return True


class ForgetAsksFirst(unittest.TestCase):
    def setUp(self):
        self.env = os.path.join(_isolation.mktemp(), ".env")
        store_mod.store_key("ACME_API_KEY", KEY, self.env)
        self.cat = {"acme": recipe()}

    def main(self, *args, stdin_tty=False):
        out = io.StringIO()
        fake = FakeKeychain()
        with mock.patch.object(recipes_mod, "load_recipes", return_value=self.cat), \
                mock.patch.object(cli_mod, "_stdin_is_terminal", return_value=stdin_tty), \
                mock.patch.object(cli_mod.keychain_mod, "detect_backend",
                                  side_effect=AssertionError("touched keychain")), \
                redirect_stdout(out):
            code = cli_mod.main(["forget", "acme", "--env-file", self.env, *args])
        return code, out.getvalue(), fake

    def test_non_interactive_without_yes_removes_nothing(self):
        code, text, _ = self.main()
        self.assertEqual(code, 2)
        self.assertIn("stuntkey forget needs --yes when not run in a terminal", text)
        self.assertIn("ACME_API_KEY", store_mod.load_env(self.env))

    def test_yes_removes_as_before(self):
        fake = FakeKeychain()
        out = io.StringIO()
        self.assertIsNone(cli_mod._confirm_forget(recipe(), True, out))
        code = cli_mod._cmd_forget(recipe(), self.env, out=out, keychain=fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.deleted, 1)
        self.assertIn("fake keychain entry", out.getvalue())
        self.assertIn(f"ACME_API_KEY from {self.env}", out.getvalue())
        self.assertNotIn("ACME_API_KEY", store_mod.load_env(self.env))

    def test_answer_n_removes_nothing(self):
        for answer in ("n", "", "maybe-not"):
            out = io.StringIO()
            code = cli_mod._confirm_forget(recipe(), False, out,
                                           reader=lambda p, a=answer: a)
            self.assertEqual(code, 1, answer)
        self.assertIn("ACME_API_KEY", store_mod.load_env(self.env))

    def test_answer_y_goes_ahead(self):
        for answer in ("y", "yes"):
            self.assertIsNone(cli_mod._confirm_forget(
                recipe(), False, io.StringIO(), reader=lambda p, a=answer: a))

    def test_prompt_names_the_service(self):
        seen = []
        cli_mod._confirm_forget(recipe(), False, io.StringIO(),
                                reader=lambda p: seen.append(p) or "n")
        self.assertIn("Remove the stored Acme key? It cannot be recovered. [y/N]", seen[0])


class HookRefusesSelfDisarm(unittest.TestCase):
    DENIED = (
        "stuntkey forget openai", "oathkey forget openai", "stuntkey stop",
        "stuntkey resume", "stuntkey rotate openai", "stuntkey caps set openai 5",
        "stuntkey caps --clear", "stuntkey policy approve", "oathkey policy approve",
        "stuntkey hook uninstall", "oathkey hook uninstall", "stuntkey uninstall",
        "stuntkey install --uninstall", "oathkey install --uninstall",
        "echo {} > .claude/settings.json", "echo x >> .claude/settings.local.json",
        "echo x | tee .mcp.json", "sed -i s/stuntkey//g ~/.claude/settings.json",
        "cp evil.json ~/.claude.json", "mv evil .mcp.json", "rm .claude/settings.json",
    )
    ALLOWED = ("stuntkey list", "stuntkey doctor", "cat .claude/settings.json",
               "grep hooks .claude/settings.json", "stuntkey caps")

    def test_each_command_is_denied(self):
        for cmd in self.DENIED:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(hook_mod.steals_key(cmd, shell=True))

    def test_read_only_commands_pass(self):
        for cmd in self.ALLOWED:
            with self.subTest(cmd=cmd):
                self.assertIsNone(hook_mod.steals_key(cmd, shell=True))


class TestKeychainBackend(unittest.TestCase):
    def roundtrip(self, value):
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": value}),                 mock.patch.object(keychain_mod, "_windows", side_effect=AssertionError("real")),                 mock.patch.object(keychain_mod, "_macos", side_effect=AssertionError("real")),                 mock.patch.object(keychain_mod, "_secret_tool", side_effect=AssertionError("real")),                 mock.patch.object(keychain_mod, "_fingerprint"):
            backend = keychain_mod.detect_backend()
            self.assertIn("not secure", keychain_mod.label(backend))
            self.assertEqual(keychain_mod.store("acme", "ACME_API_KEY", KEY), backend)
            self.assertEqual(keychain_mod.read("acme", "ACME_API_KEY"), KEY)
            self.assertTrue(keychain_mod.delete("acme", "ACME_API_KEY"))
            self.assertIsNone(keychain_mod.read("acme", "ACME_API_KEY"))
            self.assertFalse(keychain_mod.delete("acme", "ACME_API_KEY"))

    def test_memory(self):
        self.roundtrip("memory")

    def test_file(self):
        folder = _isolation.mktemp()
        self.roundtrip("file:" + folder)
        self.assertTrue(os.path.exists(os.path.join(folder, "stuntkey-test-keychain.json")))

    def test_forget_never_calls_the_platform_backend(self):
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": "memory"}),                 mock.patch.object(keychain_mod, "_windows", side_effect=AssertionError("real")),                 mock.patch.object(keychain_mod, "_macos", side_effect=AssertionError("real")),                 mock.patch.object(keychain_mod, "_secret_tool", side_effect=AssertionError("real")):
            env = os.path.join(_isolation.mktemp(), ".env")
            out = io.StringIO()
            self.assertEqual(cli_mod._cmd_forget(recipe(), env, out=out), 0)
            self.assertIn("nothing stored", out.getvalue())

    def test_a_typo_never_falls_back_to_the_real_keychain(self):
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": "memroy"}):
            with self.assertRaises(keychain_mod.KeychainError):
                keychain_mod.detect_backend()

    def test_doctor_names_the_test_backend(self):
        with mock.patch.dict(os.environ, {"STUNTKEY_KEYCHAIN": "memory"}):
            text = gitscan_mod.format_doctor(gitscan_mod.doctor())
        self.assertIn("[info] keychain: test backend memory", text)


class TestWindowsLimit(unittest.TestCase):
    def test_size_check_message(self):
        keychain_mod._check_windows_size(("a" * 1280).encode("utf-16-le"))
        with self.assertRaises(keychain_mod.KeychainError) as cm:
            keychain_mod._check_windows_size(("a" * 1281).encode("utf-16-le"))
        self.assertEqual(str(cm.exception), "Windows Credential Manager keeps at "
                         "most 1280 characters per key; this one is 1281.")

    def test_store_raises_before_credwrite(self):
        import types
        ct = types_ns()
        with mock.patch.object(keychain_mod, "_win_structs",
                               return_value=types.SimpleNamespace):
            with self.assertRaises(keychain_mod.KeychainError) as cm:
                keychain_mod._windows("store", "acme", "ACME_API_KEY", "a" * 1300,
                                      ctypes_mod=ct)
        self.assertIn("this one is 1300", str(cm.exception))
        ct.windll.advapi32.CredWriteW.assert_not_called()


def types_ns():
    import ctypes
    import types
    return types.SimpleNamespace(
        windll=types.SimpleNamespace(advapi32=types.SimpleNamespace(
            CredWriteW=mock.Mock(side_effect=AssertionError("CredWriteW called")))),
        create_string_buffer=ctypes.create_string_buffer, cast=ctypes.cast,
        POINTER=ctypes.POINTER, byref=ctypes.byref, c_ubyte=ctypes.c_ubyte)


class TestDoctorHookInfo(unittest.TestCase):
    def setUp(self):
        self.dir = _isolation.mktemp()
        self.old = os.getcwd()
        os.chdir(self.dir)
        entry = clients_mod.server_entry()
        with open(os.path.join(self.dir, ".mcp.json"), "w") as f:
            json.dump({"mcpServers": {clients_mod.NAME: entry}}, f)
        self.addCleanup(os.chdir, self.old)

    def doctor(self):
        with mock.patch.object(gitscan_mod, "_doctor_stuntkey_checks",
                               wraps=gitscan_mod._doctor_stuntkey_checks):
            res = gitscan_mod.doctor()
        return res, gitscan_mod.format_doctor(res)

    def test_flags_a_missing_hook_and_stays_ready(self):
        with mock.patch.object(hook_mod, "is_installed", return_value=False):
            res, text = self.doctor()
        self.assertIn("[info] Claude Code hook: not installed (agent can still read .env). "
                      "Fix: stuntkey hook install", text)
        self.assertNotIn("Claude Code hook", " ".join(
            c["check"] for c in res["checks"] if not c["ok"]))

    def test_silent_when_installed(self):
        with mock.patch.object(hook_mod, "is_installed", return_value=True):
            _, text = self.doctor()
        self.assertNotIn("Claude Code hook", text)

    def test_is_installed_reads_the_settings(self):
        self.assertFalse(hook_mod.is_installed())
        path = hook_mod.project_settings_path()
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as f:
            json.dump({"hooks": {"PreToolUse": [hook_mod.hook_entry()]}}, f)
        self.assertTrue(hook_mod.is_installed())




class TestScanNextLine(unittest.TestCase):
    def test_text_after_each_key(self):
        root = _isolation.mktemp()
        with open(os.path.join(root, ".env"), "w", encoding="utf-8") as f:
            f.write("OPENAI_API_KEY=sk-" + "proj-Ab3dEf9Gh2Jk5Lm8Np1Qr4St7Uv0Wx\n")
        catalog = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        text = scan_mod.render_text(scan_mod.scan_path(root, catalog))
        self.assertIn("after saving, delete that line from .env or run stuntkey forget "
                      "openai, then start your app with stuntkey run openai -- "
                      "<your command>", text)


DELIMITED = ("P@ssw0rd(Zk;9xQ)mNb4&Lp", "abcDEF123|ghiJKL456|mnoPQR789",
             "Qw3\"rTy'7{Uio}p`Asd9")


class TestDelimitedKeysMasked(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(_isolation.mktemp(), "fp.json")
        for i, key in enumerate(DELIMITED):
            scrub_mod.remember_key(f"svc{i}/KEY", key, self.path)
        self.prints = scrub_mod.load_fingerprints(self.path)

    def mask(self, text):
        return scrub_mod.mask_secrets(text, self.prints)

    def test_plain_and_assignment_forms(self):
        for key in DELIMITED:
            for text in (f"the key is {key} ok", f"API_KEY={key} next",
                         "x\n" + key + "\n"):
                with self.subTest(key=key, text=text):
                    out, n = self.mask(text)
                    self.assertNotIn(key, out)
                    self.assertGreaterEqual(n, 1)

    def test_inside_json(self):
        # json.dumps escapes a quote in the key; the plain-form keys sit as they are
        for key in DELIMITED[:2]:
            text = json.dumps({"k": key})
            out, n = self.mask(text)
            self.assertNotIn(key, out)
            self.assertGreaterEqual(n, 1)

    def test_ordinary_text_is_unchanged(self):
        text = ("Plain sentences (with brackets), commas; and {braces} | pipes & more.\n"
                "def f(a, b): return [a, b]\n" * 5)
        self.assertEqual(self.mask(text), (text, 0))

    def test_whitespace_in_a_key_is_not_recorded(self):
        scrub_mod.remember_key("sp/KEY", "has a space;in it 12345", self.path)
        with open(self.path) as f:
            self.assertNotIn("sp/KEY", json.load(f)["delimited"])

    def test_forget_drops_the_record(self):
        scrub_mod.forget_key("svc0/KEY", self.path)
        with open(self.path) as f:
            self.assertNotIn("svc0/KEY", json.load(f)["delimited"])
        prints = scrub_mod.load_fingerprints(self.path)
        self.assertEqual(scrub_mod.mask_secrets(DELIMITED[0], prints)[1], 0)

    def test_time_for_one_megabyte_and_eight_keys(self):
        path = os.path.join(_isolation.mktemp(), "fp8.json")
        for i in range(8):
            scrub_mod.remember_key(f"s{i}/K", f"Ab{i}(x;y){i}Zq{'k' * (5 + i)}", path)
        prints = scrub_mod.load_fingerprints(path)
        plain = ("Plain sentences, with commas; and (brackets) in them. " * 20000)[:1_000_000]
        dense = ("{\"a\":[1,2,3],\"b\":\"x;y\"}," * 50000)[:1_000_000]
        for label, text in (("plain sentences", plain), ("dense JSON, no spaces", dense)):
            start = time.perf_counter()
            scrub_mod.mask_secrets(text, prints)
            print(f"\n  1 MB, 8 delimited keys, {label}: "
                  f"{time.perf_counter() - start:.2f} s")


class TestInstallUnreadableConfig(unittest.TestCase):
    def test_bad_json_names_path_and_line_and_exits_1(self):
        folder = _isolation.mktemp()
        path = os.path.join(folder, ".mcp.json")
        with open(path, "w") as f:
            f.write("{bad")
        lines = []
        code = clients_mod.run(["claude-code"], True, out=lines.append, cwd=folder)
        self.assertEqual(code, 1)
        self.assertIn(f"claude-code: NOT set up. {os.path.abspath(path)} is not valid "
                      f"JSON (line 1). Fix or delete it, then run stuntkey install "
                      f"again. File left untouched.", "\n".join(lines))
        with open(path) as f:
            self.assertEqual(f.read(), "{bad")
        self.assertEqual(os.listdir(folder), [".mcp.json"])


if __name__ == "__main__":
    unittest.main()
