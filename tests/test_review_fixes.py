"""Fixes from the review of the 0.8.0 rename (group A)."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from stuntkey import agentsetup, capture as capture_mod, cli as cli_mod
from stuntkey import clients, cmds, extras, gitscan, mcp as mcp_mod
from stuntkey import keychain as keychain_mod
from stuntkey import recipes as recipes_mod

CATALOG = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli_mod.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class FakeKeychain:
    """An in-memory stand-in for the OS keychain."""
    def __init__(self):
        self.data = {}

    def patches(self):
        return [
            mock.patch.object(keychain_mod, "detect_backend", lambda *a, **k: "fake"),
            mock.patch.object(keychain_mod, "store", self.store),
            mock.patch.object(keychain_mod, "read", self.read),
        ]

    def store(self, service, env_var, key, backend=None, *a, **k):
        self.data[(service, env_var)] = key
        return "fake"

    def read(self, service, env_var, backend=None, *a, **k):
        if (service, env_var) not in self.data:
            raise keychain_mod.KeychainError("not stored")
        return self.data[(service, env_var)]


class StartCommand(unittest.TestCase):
    def test_start_runs_without_a_traceback(self):
        fake_scan = {"findings": [], "incomplete": False}
        buf = io.StringIO()
        with mock.patch.object(gitscan, "scan", return_value=fake_scan), \
                contextlib.redirect_stdout(buf):
            code = cmds.cmd_start({}, ".env")
        self.assertIn(code, (0, 1))
        self.assertIn("stuntkey", buf.getvalue())
        self.assertIn("No loose keys found", buf.getvalue())

    def test_start_through_the_cli(self):
        with mock.patch.object(gitscan, "scan", return_value={"findings": []}):
            code, out, err = run_main(["start"])
        self.assertIn(code, (0, 1))
        self.assertNotIn("Traceback", err)


class McpEntryUsesKeychain(unittest.TestCase):
    def test_install_entry_names_the_keychain(self):
        self.assertEqual(clients.server_entry(True)["args"][-2:], ["--default-store", "keychain"])
        self.assertNotIn("--default-store", clients.server_entry(False)["args"])

    def test_setup_agent_names_the_keychain_for_every_client(self):
        for client in ("claude-code", "cursor", "codex"):
            self.assertEqual(agentsetup.server_entry(client, True)["args"][-2:],
                             ["--default-store", "keychain"])
            self.assertNotIn("--default-store", agentsetup.server_entry(client, False)["args"])

    def test_the_server_defaults_to_the_keychain_when_there_is_one(self):
        self.addCleanup(capture_mod.set_manager, None)
        capture_mod.set_manager(None)
        with mock.patch.object(cli_mod, "_keychain_available", return_value=True), \
                mock.patch.object(mcp_mod, "serve", return_value=0):
            cli_mod.main(["mcp"])
        self.assertEqual(capture_mod.default_manager().default_store, "keychain")

    def test_the_server_falls_back_to_env_without_one(self):
        self.addCleanup(capture_mod.set_manager, None)
        capture_mod.set_manager(None)
        with mock.patch.object(cli_mod, "_keychain_available", return_value=False), \
                mock.patch.object(mcp_mod, "serve", return_value=0):
            cli_mod.main(["mcp"])
        self.assertEqual(capture_mod.default_manager().default_store, "env")


class CapturedKeyReachesCallApi(unittest.TestCase):
    def call(self, store):
        recipe = CATALOG["github"]
        var = recipes_mod.env_vars(recipe)[0]
        fake = FakeKeychain()
        seen = {}

        def fake_call(rec, values, method, path, query, body, policy=None, audit=None, max_chars=None):
            seen["values"] = dict(values)
            return {"status": 200}
        tmp = tempfile.mkdtemp()
        with contextlib.ExitStack() as st:
            for p in fake.patches():
                st.enter_context(p)
            st.enter_context(mock.patch.dict(os.environ, {"HOME": tmp, "USERPROFILE": tmp}))
            st.enter_context(mock.patch("stuntkey.broker.call", fake_call))
            st.enter_context(mock.patch("stuntkey.broker.AuditLog", lambda p: None))
            store_fn = capture_mod._default_store(recipe, os.path.join(tmp, ".env"), store)
            store_fn(var, "ghp_" + "a" * 36)
            result = mcp_mod._call_api(CATALOG, {"service": "github", "method": "GET",
                                                 "path": "/user"})
        return result, seen, var

    def test_a_keychain_capture_is_visible_to_call_api(self):
        result, seen, var = self.call("keychain")
        self.assertFalse(result.get("isError"), result)
        self.assertEqual(seen["values"][var], "ghp_" + "a" * 36)

    def test_an_env_capture_is_not(self):
        result, seen, _ = self.call("env")
        self.assertTrue(result.get("isError"))
        self.assertNotIn("values", seen)


class RemoteSplit(unittest.TestCase):
    def test_remote_first(self):
        self.assertEqual(cli_mod.split_remote(["remote", "github", "h", "--", "ls", "-a"]),
                         (["remote", "github", "h"], ["ls", "-a"]))

    def test_after_global_options(self):
        self.assertEqual(
            cli_mod.split_remote(["--project-dir", "x", "remote", "github", "h", "--", "ls"]),
            (["--project-dir", "x", "remote", "github", "h"], ["ls"]))
        self.assertEqual(
            cli_mod.split_remote(["--project-dir=x", "remote", "github", "h", "--", "ls"])[1],
            ["ls"])

    def test_other_commands_keep_their_double_dash(self):
        argv = ["run", "github", "--", "ls"]
        self.assertEqual(cli_mod.split_remote(argv), (argv, []))

    def test_the_command_reaches_remote(self):
        seen = {}

        def fake(recipe, host, command, **kw):
            seen["command"] = command
            return 0
        d = tempfile.mkdtemp()
        with mock.patch("stuntkey.remote.run_remote", fake):
            code, _, _ = run_main(["--project-dir", d, "remote", "github", "u@h",
                                   "--", "git", "pull"])
        self.assertEqual(code, 0)
        self.assertEqual(seen["command"], ["git", "pull"])

    def test_help_shows_the_double_dash(self):
        code, out, _ = run_main(["remote", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("-- COMMAND", out)


class RotateKeepsTheStore(unittest.TestCase):
    def test_keychain_entry_means_keychain(self):
        fake = FakeKeychain()
        with contextlib.ExitStack() as st:
            for p in fake.patches():
                st.enter_context(p)
            self.assertEqual(cli_mod._store_where_key_lives(CATALOG["github"]), "env")
            var = recipes_mod.env_vars(CATALOG["github"])[0]
            fake.data[("github", var)] = "x"
            self.assertEqual(cli_mod._store_where_key_lives(CATALOG["github"]), "keychain")

    def test_rotate_passes_that_store_on(self):
        seen = {}

        def fake_connect(recipe, **kw):
            seen.update(kw)
            return 0
        with mock.patch.object(cli_mod, "_store_where_key_lives", return_value="keychain"), \
                mock.patch.object(cli_mod, "connect_service", fake_connect):
            run_main(["rotate", "github"])
        self.assertEqual(seen["store"], "keychain")
        self.assertTrue(seen["rotate"])

    def test_an_explicit_store_wins(self):
        seen = {}
        with mock.patch.object(cli_mod, "connect_service",
                               lambda recipe, **kw: seen.update(kw) or 0):
            run_main(["rotate", "github", "--store", "env"])
        self.assertEqual(seen["store"], "env")


class UnknownServiceExitsThree(unittest.TestCase):
    def test_every_command(self):
        for argv in (["get", "githb"], ["connect", "githb"], ["rotate", "githb"],
                     ["run", "githb", "echo", "hi"], ["forget", "githb"]):
            code, out, err = run_main(argv)
            self.assertEqual(code, 3, argv)
            self.assertIn("Did you mean", err, argv)
            self.assertIn("github", err, argv)
            self.assertLess(len(err.splitlines()), 3, argv)


if __name__ == "__main__":
    unittest.main()
