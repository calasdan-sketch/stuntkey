"""Round 3 regression tests (panel findings on redirects, the .env write,
the install layout, and keychain storage) plus Windows portability.

No network beyond 127.0.0.1, no real keychain, no real HOME.
"""

import io
import json
import os
import re
import sys
import threading
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

import _isolation
from stuntkey import __version__
from stuntkey import cli as cli_mod
from stuntkey import connect as connect_mod
from stuntkey import keychain as keychain_mod
from stuntkey import mcp as mcp_mod
from stuntkey import recipes as recipes_mod
from stuntkey import store as store_mod
from stuntkey import validate as validate_mod

REPO = _isolation.REPO
FAKE_KEY = "sk-test-THIS-IS-A-FAKE-KEY-999"


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": ["read"], "docs": "",
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


# ------------------------------------------------------------ redirects


class _Target(BaseHTTPRequestHandler):
    """The server a redirect lands on: records every request's headers."""
    seen: list = []

    def do_GET(self):
        _Target.seen.append((self.path, dict(self.headers)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class _Redirector(BaseHTTPRequestHandler):
    """Redirects everything to `location`; same-origin when it points at
    its own port."""
    location = ""
    seen: list = []

    def do_GET(self):
        _Redirector.seen.append((self.path, dict(self.headers)))
        if self.path == "/final":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")
            return
        self.send_response(302)
        self.send_header("Location", _Redirector.location)
        self.end_headers()

    def log_message(self, *a):
        pass


def serve(handler) -> HTTPServer:
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestRedirectCredentialLeak(unittest.TestCase):
    def setUp(self):
        _Target.seen, _Redirector.seen = [], []
        self.target = serve(_Target)
        self.redir = serve(_Redirector)
        for srv in (self.target, self.redir):
            self.addCleanup(srv.server_close)       # runs after the shutdown
            self.addCleanup(srv.shutdown)

    def spec(self, auth):
        return {"method": "GET",
                "url": f"http://127.0.0.1:{self.redir.server_port}/me",
                "auth": auth, "expect": [200]}

    def test_cross_origin_redirect_never_carries_the_key(self):
        _Redirector.location = f"http://127.0.0.1:{self.target.server_port}/x"
        for auth, header in (({"type": "bearer"}, "Authorization"),
                             ({"type": "basic"}, "Authorization"),
                             ({"type": "header", "header": "X-Api-Key"},
                              "X-Api-Key")):
            _Target.seen.clear()
            with self.assertRaises(validate_mod.ValidationError) as cm:
                validate_mod.validate_key(self.spec(auth), FAKE_KEY)
            self.assertIn("different origin", str(cm.exception))
            self.assertNotIn(FAKE_KEY, str(cm.exception))
            self.assertEqual(len(_Target.seen), 1, auth)
            _path, headers = _Target.seen[0]
            lowered = {k.lower(): v for k, v in headers.items()}
            self.assertNotIn(header.lower(), lowered, auth)
            for v in headers.values():
                self.assertNotIn(FAKE_KEY, v)

    def test_same_origin_redirect_keeps_the_key(self):
        _Redirector.location = f"http://127.0.0.1:{self.redir.server_port}/final"
        ok = validate_mod.validate_key(self.spec({"type": "bearer"}), FAKE_KEY)
        self.assertTrue(ok)
        self.assertEqual([p for p, _ in _Redirector.seen], ["/me", "/final"])
        self.assertEqual(_Redirector.seen[1][1].get("Authorization"),
                         f"Bearer {FAKE_KEY}")

    def test_should_strip_auth_matrix(self):
        strip = validate_mod.should_strip_auth
        self.assertTrue(strip("https://a.test/x", "https://b.test/x"))
        self.assertTrue(strip("https://a.test/x", "http://a.test/x"))  # downgrade
        self.assertTrue(strip("https://a.test/x", "https://a.test:8443/x"))
        self.assertTrue(strip("http://a.test/x", "https://a.test/x"))
        self.assertFalse(strip("https://a.test/x", "https://a.test/y"))
        self.assertFalse(strip("https://a.test/x", "https://A.test:443/y"))
        self.assertFalse(strip("http://127.0.0.1:8000/a", "http://127.0.0.1:8000/b"))


# ---------------------------------------------------- private .env write


class TestPrivateEnvWrite(unittest.TestCase):
    def test_pre_planted_temp_file_is_never_written_through(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        planted = env + ".tmp"  # the old, guessable temp name
        with open(planted, "w", encoding="utf-8") as f:
            f.write("SENTINEL\n")
        store_mod.store_key("ACME_API_KEY", FAKE_KEY, env)
        with open(planted, encoding="utf-8") as f:
            self.assertEqual(f.read(), "SENTINEL\n",
                             "store_key wrote through a pre-planted temp file")
        with open(env, encoding="utf-8") as f:
            self.assertIn(f"ACME_API_KEY={FAKE_KEY}", f.read())
        leftovers = [n for n in os.listdir(tmp) if n not in (".env", ".env.tmp")]
        self.assertEqual(leftovers, [], "temp file left behind")

    @unittest.skipIf(os.name == "nt", "POSIX mode bits")
    def test_key_file_is_never_world_readable_even_with_open_umask(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        seen = []
        real = store_mod._lock_down

        def spy(path):
            seen.append((os.path.basename(path), store_mod.file_mode(path)))
            real(path)

        old_umask = os.umask(0)
        try:
            with mock.patch.object(store_mod, "_lock_down", spy):
                store_mod.store_key("ACME_API_KEY", FAKE_KEY, env)
        finally:
            os.umask(old_umask)
        self.assertTrue(seen)
        for name, mode in seen:
            self.assertEqual(mode, 0o600,
                             f"{name} was {oct(mode)} before lock-down")
        self.assertEqual(store_mod.file_mode(env), 0o600)

    def test_crash_before_rename_leaves_old_env_and_no_temp(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        with open(env, "w", encoding="utf-8") as f:
            f.write("OTHER=1\n")
        with mock.patch.object(store_mod.os, "replace",
                               side_effect=OSError("disk gone")):
            with self.assertRaises(OSError):
                store_mod.store_key("ACME_API_KEY", FAKE_KEY, env)
        with open(env, encoding="utf-8") as f:
            self.assertEqual(f.read(), "OTHER=1\n")
        self.assertEqual(os.listdir(tmp), [".env"],
                         "a temp file with the key was left behind")

    def test_windows_lock_down_restricts_acl_best_effort(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            return types.SimpleNamespace(returncode=0)

        with mock.patch.object(store_mod.subprocess, "run", fake_run), \
                mock.patch.dict(os.environ, {"USERNAME": "dan",
                                             "SystemRoot": "C:\\Windows"}):
            icacls = "C:\\Windows\\System32\\icacls.exe"
            self.assertTrue(store_mod._windows_owner_only("C:\\x\\.env"))
        self.assertEqual(calls, [[icacls, "C:\\x\\.env", "/inheritance:r",
                                  "/grant:r", "dan:(F)"]])
        with mock.patch.object(store_mod.subprocess, "run",
                               side_effect=OSError("no icacls")):
            self.assertFalse(store_mod._windows_owner_only("C:\\x\\.env"))

    def test_success_line_is_honest_per_platform(self):
        with mock.patch.object(store_mod.os, "name", "nt"):
            self.assertEqual(store_mod.describe_protection(), "owner-only ACL")
        with mock.patch.object(store_mod.os, "name", "posix"):
            self.assertEqual(store_mod.describe_protection(), "mode 0600")

    def test_read_env_is_utf8(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        with open(env, "w", encoding="utf-8") as f:
            f.write("# caf\u00e9 \u65e5\u672c\nOTHER=1\n")
        store_mod.store_key("ACME_API_KEY", FAKE_KEY, env)
        lines, index = store_mod.read_env(env)
        self.assertEqual(lines[0], "# caf\u00e9 \u65e5\u672c")
        self.assertEqual(set(index), {"OTHER", "ACME_API_KEY"})

    def test_every_text_open_in_package_names_an_encoding(self):
        pkg = os.path.join(REPO, "stuntkey")
        for name in os.listdir(pkg):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(pkg, name), encoding="utf-8") as f:
                src = f.read()
            for m in re.finditer(r"(?<![\w.])open\(", src):  # not x.open(
                depth, i = 1, m.end()
                while i < len(src) and depth:
                    depth += {"(": 1, ")": -1}.get(src[i], 0)
                    i += 1
                call = src[m.end():i - 1]
                if '"rb"' in call or "'rb'" in call:
                    continue
                self.assertIn("encoding=", call, f"{name}: open({call})")


# ------------------------------------------------------- install layout


class TestInstallLayout(unittest.TestCase):
    def pyproject(self):
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib needs Python 3.11+")
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
            return tomllib.load(f)

    def test_pyproject_is_explicit_and_current(self):
        data = self.pyproject()
        proj = data["project"]
        self.assertEqual(proj["version"], __version__)
        self.assertEqual(proj["license"], "MIT")
        self.assertEqual(proj["scripts"]["stuntkey"], "stuntkey.cli:main")
        self.assertTrue(proj["classifiers"])
        self.assertEqual(data["tool"]["setuptools"]["packages"], ["stuntkey"])
        self.assertEqual(data["tool"]["setuptools"]["package-data"],
                         {"stuntkey": ["recipes/*.json", "skill/*.md", "web/*.html",
                                       "web/*.css", "web/*.svg", "web/*.png"]})
        self.assertIn("setuptools>=77", data["build-system"]["requires"][0])

    def test_builtin_recipes_live_inside_the_package(self):
        self.assertEqual(os.path.dirname(recipes_mod.RECIPES_DIR),
                         os.path.dirname(os.path.abspath(recipes_mod.__file__)))
        # the old top-level recipes/ dir made setuptools' flat-layout
        # discovery refuse to build ("Multiple top-level packages")
        self.assertFalse(os.path.isdir(os.path.join(REPO, "recipes")))
        self.assertLessEqual({"github", "stripe", "resend", "openrouter"},
                             set(recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)))

    def test_user_recipes_dir_overrides_builtin_and_receives_add(self):
        user_dir = recipes_mod.user_recipes_dir()
        self.assertTrue(user_dir.startswith(_isolation.FAKE_HOME))
        catalog = recipes_mod.load_recipes()
        self.assertEqual(catalog["github"]["display"], "GitHub")
        same_server = dict(catalog["github"]["validate"])
        path = recipes_mod.save_recipe(recipe(service="github", display="My GitHub",
                                              key_url="https://github.com/settings/tokens",
                                              env_var="GITHUB_TOKEN", validate=same_server))
        try:
            self.assertEqual(os.path.dirname(path), user_dir)
            self.assertEqual(recipes_mod.load_recipes()["github"]["display"],
                             "My GitHub")
        finally:
            os.remove(path)
        self.assertEqual(recipes_mod.load_recipes()["github"]["display"], "GitHub")

    def test_user_recipe_cannot_redirect_a_builtin_key_to_another_server(self):
        import contextlib
        import io
        path = recipes_mod.save_recipe(recipe(service="github", display="Evil",
                                              key_url="https://github.com/settings/tokens"))
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                catalog = recipes_mod.load_recipes()
            self.assertEqual(catalog["github"]["display"], "GitHub")
            self.assertIn("different server", err.getvalue())
        finally:
            os.remove(path)

    def test_new_recipe_cannot_reuse_a_builtin_key_name_for_another_server(self):
        import contextlib
        import io
        path = recipes_mod.save_recipe(recipe(service="evil", display="Evil",
                                              env_var="OPENAI_API_KEY"))
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                catalog = recipes_mod.load_recipes()
            self.assertNotIn("evil", catalog)
            self.assertIn("OPENAI_API_KEY", err.getvalue())
        finally:
            os.remove(path)


# -------------------------------------------------------------- keychain


class _FakeRun:
    """subprocess.run stand-in recording argv + stdin, with canned stdout."""

    def __init__(self, stdout=b"", returncode=0):
        self.calls = []
        self.stdout, self.returncode = stdout, returncode

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw.get("input")))
        return types.SimpleNamespace(returncode=self.returncode,
                                     stdout=self.stdout, stderr=b"")


def _fake_windows_ctypes():
    """The real ctypes (Structure, POINTER, cast ...) plus a fake
    `windll.advapi32` that behaves like the Credential Manager."""
    import ctypes
    import ctypes.wintypes  # noqa: F401
    vault: dict = {}
    keepalive: list = []
    refs: list = []

    class Advapi32:
        @staticmethod
        def CredWriteW(cred_ref, flags):
            cred = refs[-1]
            blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
            vault[cred.TargetName] = (cred.Type, cred.Persist, cred.UserName, blob)
            return 1

        @staticmethod
        def CredReadW(target, ctype, flags, pcred_ref):
            if target not in vault:
                return 0
            pcred = refs[-1]
            cred = pcred._type_()
            _t, _p, user, blob = vault[target]
            buf = ctypes.create_string_buffer(blob, len(blob))
            keepalive.append(buf)
            cred.TargetName = target
            cred.UserName = user
            cred.CredentialBlobSize = len(blob)
            cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
            keepalive.append(cred)
            pcred.contents = cred
            return 1

        @staticmethod
        def CredFree(p):
            return None

        @staticmethod
        def CredDeleteW(target, ctype, flags):
            return 1 if vault.pop(target, None) is not None else 0

    fake = types.SimpleNamespace(
        Structure=ctypes.Structure, POINTER=ctypes.POINTER, c_ubyte=ctypes.c_ubyte,
        c_void_p=ctypes.c_void_p, create_string_buffer=ctypes.create_string_buffer,
        cast=ctypes.cast, string_at=ctypes.string_at, wintypes=ctypes.wintypes,
        windll=types.SimpleNamespace(advapi32=Advapi32),
        GetLastError=lambda: 5)

    def byref(obj):
        refs.append(obj)
        return ctypes.byref(obj)

    fake.byref = byref
    fake.vault = vault
    return fake


class TestKeychain(unittest.TestCase):
    def test_detect_backend_dispatch(self):
        has = lambda name: (lambda tool: tool == name)  # noqa: E731
        d = keychain_mod.detect_backend
        self.assertEqual(d("darwin", which=has("security")), keychain_mod.MACOS)
        self.assertIsNone(d("darwin", which=has("nothing")))
        win = types.SimpleNamespace(windll=object())
        self.assertEqual(d("win32", which=has("x"), ctypes_mod=win),
                         keychain_mod.WINDOWS)
        self.assertIsNone(d("win32", which=has("x"),
                            ctypes_mod=types.SimpleNamespace()))
        self.assertEqual(d("linux", which=has("secret-tool")), keychain_mod.LINUX)
        self.assertIsNone(d("linux", which=has("security")))
        self.assertIsNone(d("freebsd14", which=has("nothing")))
        self.assertEqual(keychain_mod.label(None), "no OS keychain")

    def test_macos_security_cli_gets_key_on_stdin_never_argv(self):
        run = _FakeRun(stdout=(FAKE_KEY + "\n").encode())    # the read-back
        used = keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                                  keychain_mod.MACOS, run=run)
        self.assertEqual(used, keychain_mod.MACOS)
        argv, stdin = run.calls[0]
        self.assertEqual(argv, ["security", "-i"])
        self.assertNotIn(FAKE_KEY, " ".join(argv))
        self.assertIn(f'-w "{FAKE_KEY}"', stdin.decode())
        self.assertIn('-s "stuntkey:acme"', stdin.decode())
        self.assertIn('-a "ACME_API_KEY"', stdin.decode())
        run = _FakeRun(stdout=(FAKE_KEY + "\n").encode())
        self.assertEqual(keychain_mod.read("acme", "ACME_API_KEY",
                                           keychain_mod.MACOS, run=run), FAKE_KEY)
        self.assertEqual(run.calls[0][0][:2], ["security", "find-generic-password"])
        self.assertIn("-w", run.calls[0][0])
        self.assertIsNone(keychain_mod.read("acme", "ACME_API_KEY", keychain_mod.MACOS,
                                            run=_FakeRun(returncode=44)))
        self.assertTrue(keychain_mod.delete("acme", "ACME_API_KEY",
                                            keychain_mod.MACOS, run=_FakeRun()))
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                               keychain_mod.MACOS, run=_FakeRun(returncode=1))

    def test_security_quoting(self):
        self.assertEqual(keychain_mod._security_quote('a"b\\c'), '"a\\"b\\\\c"')

    def test_linux_secret_tool_gets_key_on_stdin(self):
        run = _FakeRun(stdout=FAKE_KEY.encode())               # the read-back
        keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY, keychain_mod.LINUX, run=run)
        argv, stdin = run.calls[0]
        self.assertEqual(argv[:2], ["secret-tool", "store"])
        self.assertEqual(stdin, FAKE_KEY.encode())
        self.assertNotIn(FAKE_KEY, " ".join(argv))
        self.assertIn("account", argv)
        self.assertIn("ACME_API_KEY", argv)
        run = _FakeRun(stdout=(FAKE_KEY + "\n").encode())
        self.assertEqual(keychain_mod.read("acme", "ACME_API_KEY",
                                           keychain_mod.LINUX, run=run), FAKE_KEY)
        self.assertEqual(run.calls[0][0][:2], ["secret-tool", "lookup"])
        self.assertIsNone(keychain_mod.read("acme", "ACME_API_KEY", keychain_mod.LINUX,
                                            run=_FakeRun(returncode=1)))

    def test_windows_credential_manager_via_ctypes(self):
        ct = _fake_windows_ctypes()
        used = keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                                  keychain_mod.WINDOWS, ctypes_mod=ct)
        self.assertEqual(used, keychain_mod.WINDOWS)
        ctype, persist, user, blob = ct.vault["stuntkey:acme"]
        self.assertEqual((ctype, persist, user), (1, 2, "ACME_API_KEY"))
        self.assertEqual(blob.decode("utf-16-le"), FAKE_KEY)  # cmdkey/.NET layout
        self.assertEqual(keychain_mod.read("acme", "ACME_API_KEY",
                                           keychain_mod.WINDOWS, ctypes_mod=ct),
                         FAKE_KEY)
        self.assertIsNone(keychain_mod.read("other", "X", keychain_mod.WINDOWS,
                                            ctypes_mod=ct))
        self.assertTrue(keychain_mod.delete("acme", "ACME_API_KEY",
                                            keychain_mod.WINDOWS, ctypes_mod=ct))
        self.assertIsNone(keychain_mod.read("acme", "ACME_API_KEY",
                                            keychain_mod.WINDOWS, ctypes_mod=ct))
        ct.windll.advapi32.CredWriteW = staticmethod(lambda *a: 0)
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                               keychain_mod.WINDOWS, ctypes_mod=ct)

    def test_store_without_backend_raises(self):
        with mock.patch.object(keychain_mod, "detect_backend", return_value=None):
            with self.assertRaises(keychain_mod.KeychainError):
                keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY)
            self.assertIsNone(keychain_mod.read("acme", "ACME_API_KEY"))
            self.assertFalse(keychain_mod.delete("acme", "ACME_API_KEY"))

    def test_keychain_store_fn_falls_back_to_env_file(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        out = io.StringIO()
        fn = cli_mod.keychain_store(recipe(), env, out=out, backend=None,
                                    keychain=types.SimpleNamespace(
                                        detect_backend=lambda: None,
                                        KeychainError=keychain_mod.KeychainError,
                                        store=None, label=keychain_mod.label),
                                    ask=lambda _p: "y", interactive=lambda: True)
        desc = fn("ACME_API_KEY", FAKE_KEY)
        self.assertIn("no OS keychain is available", out.getvalue())
        self.assertIn("added ACME_API_KEY", desc)
        with open(env, encoding="utf-8") as f:
            self.assertIn(f"ACME_API_KEY={FAKE_KEY}", f.read())

    def test_keychain_store_fn_uses_backend(self):
        stored = []
        fake = types.SimpleNamespace(
            detect_backend=lambda: keychain_mod.LINUX,
            KeychainError=keychain_mod.KeychainError,
            store=lambda s, v, k, b: (stored.append((s, v, k, b)) or b),
            label=keychain_mod.label)
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        desc = cli_mod.keychain_store(recipe(), env, out=io.StringIO(),
                                      keychain=fake)("ACME_API_KEY", FAKE_KEY)
        self.assertEqual(stored, [("acme", "ACME_API_KEY", FAKE_KEY, keychain_mod.LINUX)])
        self.assertIn("Secret Service", desc)
        self.assertIn("stuntkey run acme", desc)
        self.assertNotIn(FAKE_KEY, desc)
        self.assertFalse(os.path.exists(env))

    def test_keychain_error_falls_back_to_env_file(self):
        def boom(*a):
            raise keychain_mod.KeychainError("vault locked")
        fake = types.SimpleNamespace(detect_backend=lambda: keychain_mod.MACOS,
                                     KeychainError=keychain_mod.KeychainError,
                                     store=boom, label=keychain_mod.label)
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        out = io.StringIO()
        desc = cli_mod.keychain_store(recipe(), env, out=out, keychain=fake,
                                      ask=lambda _p: "y",
                                      interactive=lambda: True)("ACME_API_KEY", FAKE_KEY)
        self.assertIn("vault locked", out.getvalue())
        self.assertIn("added ACME_API_KEY", desc)
        self.assertTrue(os.path.exists(env))

    def test_run_with_key_injects_env_only_into_the_child(self):
        seen = {}

        def fake_call(cmd, env=None):
            seen["cmd"], seen["env"] = cmd, env
            return 7

        code = keychain_mod.run_with_key(
            recipe(), ["python", "app.py"], keychain_mod.LINUX,
            env={"PATH": "/bin"}, read_fn=lambda *a: FAKE_KEY, call=fake_call)
        self.assertEqual(code, 7)
        self.assertEqual(seen["cmd"], ["python", "app.py"])
        self.assertEqual(seen["env"], {"PATH": "/bin", "ACME_API_KEY": FAKE_KEY})
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.run_with_key(recipe(), ["x"], keychain_mod.LINUX,
                                      read_fn=lambda *a: None, call=fake_call)

    def test_cli_run_and_store_flag_wiring(self):
        cat = {"acme": recipe()}
        with mock.patch.object(recipes_mod, "load_recipes", return_value=cat):
            # (a command that exists: `run` now checks the command before it
            # asks the keychain for the key)
            prog = [sys.executable, "-c", "pass"]
            # no backend on this machine -> clear message, exit 1
            with mock.patch.object(keychain_mod, "detect_backend", return_value=None):
                err = io.StringIO()
                with redirect_stderr(err):
                    self.assertEqual(cli_mod.main(["run", "acme", "--", *prog]), 1)
                # round 13: plain words, one next step (`stuntkey status`)
                self.assertIn("no safe place", err.getvalue())
            # backend present, key missing -> helpful hint, exit 1
            with mock.patch.object(keychain_mod, "detect_backend",
                                   return_value=keychain_mod.LINUX), \
                    mock.patch.object(keychain_mod, "read", return_value=None):
                err = io.StringIO()
                with redirect_stderr(err):
                    self.assertEqual(cli_mod.main(["run", "acme", "--", *prog]), 1)
                # round 11: the plain message names the one command to run, not a flag
                self.assertIn("No key saved for acme. Run `stuntkey get acme`", err.getvalue())
            # backend present, key stored -> command runs with the key
            with mock.patch.object(keychain_mod, "detect_backend",
                                   return_value=keychain_mod.LINUX), \
                    mock.patch.object(keychain_mod, "read", return_value=FAKE_KEY), \
                    mock.patch.object(keychain_mod.subprocess, "call",
                                      return_value=0) as call:
                out = io.StringIO()
                with redirect_stdout(out), mock.patch.object(cli_mod, "_is_tty", return_value=True):
                    self.assertEqual(cli_mod.main(["run", "--no-redact", "acme", "--", *prog]), 0)
                self.assertEqual(call.call_args.args[0], prog)
                self.assertEqual(call.call_args.kwargs["env"]["ACME_API_KEY"], FAKE_KEY)
                self.assertNotIn(FAKE_KEY, out.getvalue())
            # --store keychain hands connect() a store_fn; default does not
            with mock.patch.object(connect_mod, "connect", return_value=0) as c:
                cli_mod.main(["connect", "acme", "--no-browser", "--store", "keychain"])
                self.assertIsNotNone(c.call_args.kwargs["store_fn"])
                cli_mod.main(["connect", "acme", "--no-browser", "--store", "env"])
                self.assertIsNone(c.call_args.kwargs["store_fn"])

    def test_readme_states_each_os_behaviour(self):
        with open(os.path.join(REPO, "docs", "guide.md"), encoding="utf-8") as f:
            text = f.read()
        for phrase in ("macOS", "Credential Manager", "secret-tool",
                       "--store keychain", "stuntkey run"):
            self.assertIn(phrase, text)
        self.assertNotIn(".env` file storage only", text)


# --------------------------------------------------- Windows console / wire


class TestConsoleAndWire(unittest.TestCase):
    def test_connect_output_survives_cp1252_console(self):
        raw = io.BytesIO()
        console = io.TextIOWrapper(raw, encoding="cp1252", errors="strict",
                                   write_through=True)
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        with redirect_stdout(console):
            cli_mod._harden_streams()  # what main() does first
            code = connect_mod.connect(
                recipe(), env_file=env, browser_open=lambda u: None,
                prompt=lambda _: FAKE_KEY, validate_fn=lambda s, k: True)
        console.flush()
        self.assertEqual(code, 0)
        text = raw.getvalue().decode("cp1252")
        self.assertIn("never displayed, never logged", text)
        self.assertNotIn(FAKE_KEY, text)

    def test_mcp_serve_speaks_utf8_bytes(self):
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "find_public_apis",
                          "arguments": {"query": "caf\u00e9"}}}
        entries = [{"name": "Caf\u00e9 API", "description": "caf\u00e9 finder",
                    "auth": "No", "url": "https://c.test/", "category": "Food"}]
        stdin = io.BytesIO((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
        stdout = io.BytesIO()
        mcp_mod.serve({}, pa_loader=lambda: entries, stdin=stdin, stdout=stdout)
        resp = json.loads(stdout.getvalue().decode("utf-8"))
        hits = json.loads(resp["result"]["content"][0]["text"])
        self.assertEqual(hits[0]["name"], "Caf\u00e9 API")
        self.assertTrue(stdout.getvalue().isascii())  # safe on any console
        # text streams (tests, odd embedders) keep working too
        sio = io.StringIO(json.dumps(req) + "\n")
        sout = io.StringIO()
        mcp_mod.serve({}, pa_loader=lambda: entries, stdin=sio, stdout=sout)
        self.assertEqual(json.loads(sout.getvalue())["id"], 1)

    def test_test_suite_never_touches_real_home(self):
        self.assertEqual(os.path.expanduser("~"), _isolation.FAKE_HOME)
        self.assertTrue(recipes_mod.user_recipes_dir().startswith(_isolation.FAKE_HOME))


if __name__ == "__main__":
    unittest.main()
