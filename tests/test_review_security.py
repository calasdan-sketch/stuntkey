"""Fixes from the review of the 0.8.0 rename (group B: security)."""
import argparse
import io
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import approve, dialog, export as export_mod, hook, httpd, recipes as recipes_mod
from stuntkey import remote

CATALOG = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)


def call(tool, **tool_input):
    return json.dumps({"tool_name": tool, "tool_input": tool_input})


def denied(text):
    status, out = hook.check(text)
    return bool(out) and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def shell_denied(cmd, tool="Bash"):
    return denied(call(tool, command=cmd))


class AgentCannotRunKeyCommands(unittest.TestCase):
    def test_denied(self):
        for cmd in ("stuntkey remote github root@h -- ls", "stuntkey deploy root@h --dir /x",
                    "stuntkey trust-server root@h", "stuntkey export github --to github",
                    "stuntkey run github -- env", "stuntkey serve", "stuntkey call github GET /user",
                    "python -m stuntkey run github -- env", "py -3 -m stuntkey call github GET /user",
                    "python -Im stuntkey remote github h -- id",
                    "python3 -m stuntkey.cli serve",
                    "stuntkey --project-dir /x run github -- env",
                    "/usr/local/bin/stuntkey call github GET /user",
                    "C:\\Users\\a\\Scripts\\stuntkey.exe call github GET /user",
                    "oath\"\"key run github -- env", "o'a'thkey   RUN github", "cd x && stuntkey serve",
                    "echo hi | stuntkey call github GET /user", "& stuntkey run github -- env"):
            self.assertTrue(shell_denied(cmd), cmd)
        self.assertTrue(shell_denied("stuntkey run github -- env", tool="PowerShell"))
        self.assertTrue(denied(call("Monitor", command="stuntkey call github GET /user")))

    def test_harmless_ones_are_allowed(self):
        for cmd in ("stuntkey list", "stuntkey selftest", "stuntkey doctor", "stuntkey scan",
                    "stuntkey scan-git --staged", "stuntkey overview", "stuntkey audit show",
                    "stuntkey --version", "stuntkey --help", "stuntkey remote --help"[:0] + "stuntkey status",
                    "python -m stuntkey doctor", "python -m stuntkey selftest --json",
                    "pip install stuntkey", "git commit -m 'update'"):
            self.assertFalse(shell_denied(cmd), cmd)


class McpToolsAreScanned(unittest.TestCase):
    def test_matcher_and_recognition(self):
        self.assertTrue(hook.MATCHER.endswith("|mcp__.*"))
        old = {"type": "command", "command": "/x/stuntkey hook check", "statusMessage": hook.MARKER}
        self.assertTrue(hook.is_ours(old))

    def test_every_string_is_looked_at(self):
        # MCP arguments are data: .env names and stuntkey commands in them are
        # not refused (they named Monomem notes); a settings-file write is
        self.assertFalse(denied(call("mcp__fs__read", args={"a": [{"p": "/home/me/app/.env"}]})))
        self.assertFalse(denied(call("mcp__x__run", opts={"deep": {"deeper": ["stuntkey call github GET /u"]}})))
        self.assertFalse(denied(call("mcp__x__run", **{"~/.stuntkey/keys": 1})))
        self.assertTrue(denied(call("mcp__x__run", opts={"deep": {"deeper": ["cp x ~/.claude/settings.json"]}})))
        self.assertFalse(denied(call("mcp__x__run", text="hello", n=3, nested={"a": ["b"]})))

    def test_other_tools_are_left_alone(self):
        self.assertFalse(denied(call("Glob", pattern=".env*")))

    def test_old_matcher_is_updated_in_place_and_removed_on_uninstall(self):
        for legacy in hook.LEGACY_MATCHERS:
            data = {"hooks": {"PreToolUse": [{"matcher": legacy, "hooks": [
                {"type": "command", "command": "/x/stuntkey hook check",
                 "statusMessage": hook.MARKER}]}]}}
            self.assertEqual(hook.merge_install(data, hook.hook_handler()), "updated")
            groups = data["hooks"]["PreToolUse"]
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["matcher"], hook.MATCHER)
            data2 = {"hooks": {"PreToolUse": [{"matcher": legacy, "hooks": [
                {"type": "command", "command": "/x/stuntkey hook check",
                 "statusMessage": hook.MARKER}]}]}}
            self.assertEqual(hook.merge_uninstall(data2), 1)
            self.assertNotIn("hooks", data2)


class WildcardFolderNames(unittest.TestCase):
    def test_wildcards_that_could_be_the_folder_are_refused(self):
        for cmd in ("cat ~/.*/x", "ls ~/.???????/keys/*", "type ~\\.*\\http.token",
                    "cat $HOME/.??*/http.token", "cat ~/.[!.]*/index.json"):
            self.assertTrue(hook.globs_to_our_folder(cmd), cmd)
            self.assertTrue(shell_denied(cmd), cmd)

    def test_bare_dot_star_and_ls_a_stay_allowed(self):
        for cmd in ("ls -a", "ls .*", "ls -la ~/.*", "echo .*", "ls ~/.config/x", "cat .gitignore"):
            self.assertFalse(hook.globs_to_our_folder(cmd), cmd)
            self.assertFalse(shell_denied(cmd), cmd)


class SettingsFilesAreProtected(unittest.TestCase):
    PATHS = ("/home/a/.claude/settings.json", "C:\\Users\\a\\.claude\\settings.local.json",
             "/work/app/.claude/settings.json", "/work/app/.mcp.json", "/home/a/.claude.json",
             "C:\\p\\.CLAUDE\\Settings.json")

    def test_writes_are_denied(self):
        for tool in ("Write", "Edit", "MultiEdit"):
            for p in self.PATHS:
                self.assertTrue(denied(call(tool, file_path=p, content="{}")), (tool, p))
        self.assertTrue(denied(json.dumps({"tool_name": "NotebookEdit",
                                           "tool_input": {"notebook_path": "/a/.mcp.json"}})))

    def test_reads_and_other_files_are_fine(self):
        self.assertFalse(denied(call("Read", file_path="/home/a/.claude/settings.json")))
        self.assertFalse(denied(call("Write", file_path="/work/app/settings.json", content="{}")))
        self.assertFalse(denied(call("Write", file_path="/work/app/notes.md", content="x")))

    def test_the_escape_hatch(self):
        with mock.patch.dict(os.environ, {hook.ALLOW_WRITE_VAR: "1"}):
            self.assertFalse(denied(call("Write", file_path="/work/.mcp.json", content="{}")))


class HookFailsClosed(unittest.TestCase):
    def install(self, *flags):
        path = os.path.join(_isolation.mktemp(), "settings.json")
        args = argparse.Namespace(hook_cmd="install", project=False, settings=path,
                                  shell_form=False, fail_open="--fail-open" in flags)
        deny = json.dumps({"hookSpecificOutput": {"permissionDecision": "deny"}}).encode()
        run = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, deny, b"")  # noqa: E731
        with mock.patch.object(hook, "backup_dir", lambda: _isolation.mktemp()):
            code = hook.cmd_hook(args, io.StringIO(), io.StringIO(), run)
        self.assertEqual(code, 0)
        with open(path, encoding="utf-8") as f:
            return json.load(f)["hooks"]["PreToolUse"][0]["hooks"][0]

    def test_install_blocks_on_failure_by_default(self):
        self.assertEqual(self.install().get("onFailure"), "block")

    def test_fail_open_is_the_opt_out(self):
        self.assertNotIn("onFailure", self.install("--fail-open"))

    def test_a_huge_command_is_refused_and_fast(self):
        start = time.time()
        self.assertTrue(shell_denied("echo " + "stuntkey " * 20_000))
        self.assertLess(time.time() - start, 5)

    def test_a_huge_mcp_text_is_scanned_in_windows(self):
        start = time.time()
        text = "a " * 80_000 + " echo x > .mcp.json"
        self.assertTrue(denied(call("mcp__x__y", body=text)))
        self.assertFalse(denied(call("mcp__x__y", body="a " * 250_000)))
        self.assertLess(time.time() - start, 8)

    def test_adversarial_text_stays_fast(self):
        start = time.time()
        for payload in ("stuntkey " * 12_000, "'" * 90_000, ".*/" * 20_000, " " * 90_000):
            hook.check(call("Bash", command=payload))
        self.assertLess(time.time() - start, 8)


class RemoteAsksInAWindow(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()
        p = mock.patch.object(remote, "home_dir", lambda: self.home)
        p.start()
        self.addCleanup(p.stop)

    def test_window_yes_remembers_pins_and_shows_the_fingerprint(self):
        shown, pinned = [], []

        def window(title, message):
            shown.append(message)
            return True
        remote.confirm_host("u@h", "github", window=window,
                            scan=lambda host, port: ("ED25519 SHA256:abc", "h ssh-ed25519 AAAA\n"),
                            pin=pinned.append, isatty=False)
        self.assertIn("SHA256:abc", shown[0])
        self.assertEqual(pinned, ["h ssh-ed25519 AAAA\n"])
        self.assertIn("github", remote.known_hosts()["u@h"])
        remote.confirm_host("u@h", "github", window=lambda *a: self.fail("asked twice"))

    def test_window_no_or_closed_sends_nothing(self):
        for answer in (False, dialog.SOFT_NO, dialog.EXPIRED):
            with self.assertRaises(remote.RemoteError):
                remote.confirm_host("u@h", "github", window=lambda *a, a_=answer: a_,
                                    scan=lambda *a: (None, None), isatty=True,
                                    ask=lambda q: self.fail("must not fall back to the terminal"))
        self.assertEqual(remote.known_hosts(), {})

    def test_no_window_and_no_terminal_is_refused(self):
        with self.assertRaises(remote.RemoteError):
            remote.confirm_host("u@h", "github", window=lambda *a: None,
                                scan=lambda *a: (None, None), isatty=False)

    def test_no_window_falls_back_to_the_terminal(self):
        remote.confirm_host("u@h", "github", window=lambda *a: None,
                            scan=lambda *a: ("ED25519 SHA256:zz", None), isatty=True,
                            ask=lambda q: "y" if "SHA256:zz" in q else "n", pin=lambda k: None)
        self.assertIn("u@h", remote.known_hosts())

    def test_key_bearing_ssh_accepts_only_the_pinned_key(self):
        argv = remote.ssh_command("u@h", "true")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertNotIn("StrictHostKeyChecking=accept-new", argv)

    def test_port_and_scan_parsing(self):
        self.assertEqual(remote.ssh_port(["-p", "2200"]), "2200")
        self.assertEqual(remote.ssh_port(["-oPort=2201"]), "2201")
        self.assertIsNone(remote.ssh_port([]))
        calls = []

        def runner(argv, input=None, **kw):
            calls.append(argv)
            if argv[0] == "ssh-keyscan":
                return subprocess.CompletedProcess(argv, 0, b"# c\nh ssh-ed25519 AAAA\n", b"")
            return subprocess.CompletedProcess(
                argv, 0, b"256 SHA256:Qabc h (ED25519)\n", b"")
        fp, text = remote.scan_host_key("u@h", "22", runner)
        self.assertEqual(fp, "ED25519 SHA256:Qabc")
        self.assertEqual(text, "h ssh-ed25519 AAAA\n")
        self.assertIn("-p", calls[0])

    def test_pin_writes_known_hosts_once(self):
        path = os.path.join(_isolation.mktemp(), ".ssh", "known_hosts")
        none_found = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, b"", b"")  # noqa: E731
        remote.pin_host_key("h ssh-ed25519 AAAA\n", none_found, path)
        with open(path) as f:
            self.assertEqual(f.read(), "h ssh-ed25519 AAAA\n")
        found = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"# Host h found\n", b"")  # noqa: E731
        remote.pin_host_key("h ssh-ed25519 AAAA\n", found, path)
        with open(path) as f:
            self.assertEqual(f.read(), "h ssh-ed25519 AAAA\n")


class ExportNeedsAPerson(unittest.TestCase):
    def go(self, yes, interactive, window, ask=None):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, ".env"), "w") as f:
            f.write("GROQ_API_KEY=" + "gsk_" + "a" * 40 + "\n")
        args = argparse.Namespace(service="groq", to="github", repo="a/b", environment=None,
                                  env_file=os.path.join(d, ".env"), overwrite=False, yes=yes)
        sent, out = [], io.StringIO()
        code = export_mod.cmd_export(
            args, CATALOG, ask=ask, interactive=lambda: interactive, out=out,
            which=lambda n: "/f/" + n, window=window, read_fn=lambda *a: None, backend="fake",
            run=lambda argv, input=None, **k: sent.append(1) or subprocess.CompletedProcess(argv, 0, b"", b""))
        return code, sent, out.getvalue()

    def test_yes_without_a_terminal_and_without_a_window_sends_nothing(self):
        code, sent, text = self.go(True, False, lambda *a: None)
        self.assertEqual((code, sent), (1, []))
        self.assertIn("nothing was sent", text)

    def test_yes_without_a_terminal_needs_the_window_click(self):
        code, sent, _ = self.go(True, False, lambda *a: True)
        self.assertEqual((code, sent), (0, [1]))
        code, sent, text = self.go(True, False, lambda *a: False)
        self.assertEqual((code, sent), (1, []))
        self.assertIn("cancelled", text)

    def test_yes_at_a_real_terminal_still_works_without_a_window(self):
        code, sent, _ = self.go(True, True, lambda *a: self.fail("no window needed"))
        self.assertEqual((code, sent), (0, [1]))

    def test_without_yes_a_window_comes_first_then_the_terminal(self):
        code, sent, _ = self.go(False, True, lambda *a: True)
        self.assertEqual((code, sent), (0, [1]))
        code, sent, _ = self.go(False, True, lambda *a: None, ask=lambda p: "y")
        self.assertEqual((code, sent), (0, [1]))


class SmallHardening(unittest.TestCase):
    def test_the_door_binds_its_port_exclusively_on_windows(self):
        self.assertEqual(httpd.DoorServer.allow_reuse_address, os.name != "nt")
        if os.name != "nt":
            self.skipTest("Windows only")
        srv = httpd.make_server({}, lambda r: {}, "t" * 40, None, port=0)
        self.addCleanup(srv.server_close)
        port = srv.server_address[1]
        other = socket.socket()
        self.addCleanup(other.close)
        other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with self.assertRaises(OSError):
            other.bind(("127.0.0.1", port))

    @unittest.skipUnless(os.name == "posix", "owner-only folders need POSIX modes")
    def test_the_token_folder_is_owner_only(self):
        d = os.path.join(_isolation.mktemp(), "home")
        httpd.load_or_make_token(os.path.join(d, "http.token"))
        self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)

    def test_the_approval_window_gets_a_fixed_environment(self):
        seen = {}

        def fake_run(cmd, env=None, **kw):
            seen["env"] = env
            return subprocess.CompletedProcess(cmd, 0, "button returned:Yes", "")
        planted = {"LD_PRELOAD": "/evil.so", "PYTHONPATH": "/evil", "PATH": "/evil/bin",
                   "BASH_ENV": "/evil", "DISPLAY": ":0"}
        with mock.patch.dict(os.environ, planted), \
                mock.patch.object(approve.subprocess, "run", fake_run), \
                mock.patch.object(approve, "_tool", lambda *p: "/usr/bin/zenity"):
            approve.dialog("hello")
        env = seen["env"]
        self.assertEqual(env["SEA_MSG"][:5], "hello")
        for name in ("LD_PRELOAD", "PYTHONPATH", "BASH_ENV"):
            self.assertNotIn(name, env)
        self.assertNotIn("/evil/bin", env.get("PATH", ""))


if __name__ == "__main__":
    unittest.main()
