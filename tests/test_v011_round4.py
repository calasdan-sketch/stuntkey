"""Round 4 (what a stranger gets from `pip install`): a plain message instead of
a traceback, a doctor that does not fail on programs most people lack, the
Windows rename retry, a paste prompt that refuses to show a key, and a
configuration file that keeps its permissions."""

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli, clients, fsutil, gitscan, safeprompt


def fake_key(prefix="sk-"):
    """Built at run time: no key-shaped text is stored in the repository."""
    return prefix + "".join(chr(97 + (i * 7) % 26) for i in range(30))


class ReplaceRetry(unittest.TestCase):
    def test_windows_retries_a_busy_file(self):
        calls = []

        def flaky(src, dst):
            calls.append(1)
            if len(calls) < 3:
                raise PermissionError(13, "in use")
        with mock.patch.object(sys, "platform", "win32"), \
                mock.patch.object(os, "replace", flaky), \
                mock.patch.object(fsutil.time, "sleep"):
            fsutil.replace("a", "b")
        self.assertEqual(len(calls), 3)

    def test_windows_gives_up_after_a_while(self):
        calls = []

        def busy(src, dst):
            calls.append(1)
            raise PermissionError(13, "in use")
        with mock.patch.object(sys, "platform", "win32"), \
                mock.patch.object(os, "replace", busy), \
                mock.patch.object(fsutil.time, "sleep"):
            with self.assertRaises(PermissionError):
                fsutil.replace("a", "b")
        self.assertEqual(len(calls), 8)

    def test_elsewhere_a_refusal_is_final(self):
        calls = []

        def no(src, dst):
            calls.append(1)
            raise PermissionError(13, "no")
        with mock.patch.object(sys, "platform", "linux"), mock.patch.object(os, "replace", no):
            with self.assertRaises(PermissionError):
                fsutil.replace("a", "b")
        self.assertEqual(len(calls), 1)


class PlainErrors(unittest.TestCase):
    def run_cli(self, home, *args, **env):
        e = dict(os.environ, HOME=home, USERPROFILE=home, APPDATA=home, PYTHONPATH=_isolation.REPO)
        e.update(env)
        return subprocess.run([sys.executable, "-m", "stuntkey", *args], env=e,
                              capture_output=True, text=True, timeout=120)

    @unittest.skipIf(os.name == "nt", "a path under a file is a POSIX test")
    def test_unusable_home_is_a_sentence_not_a_traceback(self):
        with tempfile.NamedTemporaryFile() as f:
            home = os.path.join(f.name, "sub")          # a folder "inside a file"
            for cmd in (["overview"], ["audit", "show"], ["stop"]):
                with self.subTest(cmd=cmd):
                    r = self.run_cli(home, *cmd)
                    self.assertEqual(r.returncode, 1, r.stderr)
                    self.assertNotIn("Traceback", r.stderr)
                    self.assertIn("could not use a file or folder", r.stderr)
                    self.assertEqual(r.stdout.count("Traceback"), 0)

    def test_unexpected_error_names_the_kind_never_the_message(self):
        secret = fake_key()
        err = io.StringIO()
        with mock.patch.object(cli, "_main", side_effect=RuntimeError(secret)), \
                contextlib.redirect_stderr(err), \
                mock.patch.dict(os.environ, {"STUNTKEY_DEBUG": ""}):
            code = cli.main(["list"])
        self.assertEqual(code, 1)
        text = err.getvalue()
        self.assertIn("RuntimeError", text)
        self.assertIn("STUNTKEY_DEBUG=1", text)
        self.assertNotIn(secret, text)
        self.assertNotIn("Traceback", text)

    def test_debug_variable_brings_the_traceback_back(self):
        with mock.patch.object(cli, "_main", side_effect=RuntimeError("x")), \
                mock.patch.dict(os.environ, {"STUNTKEY_DEBUG": "1"}):
            with self.assertRaises(RuntimeError):
                cli.main(["list"])

    def test_the_hook_keeps_its_own_failure_handling(self):
        with mock.patch.object(cli, "_main", side_effect=RuntimeError("x")), \
                mock.patch.dict(os.environ, {"STUNTKEY_DEBUG": ""}):
            with self.assertRaises(RuntimeError):
                cli.main(["hook", "check"])

    def test_an_error_about_a_file_does_not_print_the_message_of_other_errors(self):
        err = io.StringIO()
        boom = OSError(13, "Permission denied", "/some/where/file")
        with mock.patch.object(cli, "_main", side_effect=boom), contextlib.redirect_stderr(err), \
                mock.patch.dict(os.environ, {"STUNTKEY_DEBUG": ""}):
            self.assertEqual(cli.main(["status"]), 1)
        self.assertIn("/some/where/file", err.getvalue())
        self.assertIn("Permission denied", err.getvalue())


class DoctorForNewcomers(unittest.TestCase):
    def test_missing_ssh_and_git_are_not_something_to_fix(self):
        r = gitscan.doctor(env={}, which=lambda name: None)
        by = {c["check"]: c for c in r["checks"]}
        self.assertTrue(by["ssh"]["ok"])
        self.assertTrue(by["git"]["ok"])
        self.assertIn("not found", by["ssh"]["detail"])

    def test_linux_keychain_advice_names_the_package(self):
        with mock.patch.object(sys, "platform", "linux"):
            self.assertIn("libsecret-tools", gitscan._keychain_fix())
        with mock.patch.object(sys, "platform", "win32"):
            self.assertNotIn("apt", gitscan._keychain_fix())


class FindPrintsSafely(unittest.TestCase):
    def test_a_terminal_code_in_the_search_is_shown_as_text(self):
        out = io.StringIO()
        args = mock.Mock(query="\x1b]0;x\x07evil", refresh=False, auth=None, category=None, limit=5)
        with mock.patch.object(cli.pa_mod, "fetch", return_value=""), \
                mock.patch.object(cli.pa_mod, "parse", return_value=[]), \
                contextlib.redirect_stdout(out):
            cli._cmd_find(args)
        self.assertNotIn("\x1b", out.getvalue())
        self.assertNotIn("\x07", out.getvalue())


class InstallKeepsFiles(unittest.TestCase):
    def setUp(self):
        self.dir = _isolation.mktemp()

    @unittest.skipIf(os.name == "nt", "file modes are a POSIX idea")
    def test_the_config_keeps_its_permissions(self):
        path = os.path.join(self.dir, "claude_desktop_config.json")
        with open(path, "w") as f:
            f.write('{"mcpServers": {}}')
        os.chmod(path, 0o644)
        clients.apply(clients.plan(path, "mcpServers"))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)

    def test_broken_json_is_explained_and_the_exit_status_says_so(self):
        bad = os.path.join(self.dir, "mcp.json")
        with open(bad, "w") as f:
            f.write("{ broken")
        lines = []
        with mock.patch.object(clients, "targets", return_value={"cursor": (bad, "mcpServers")}):
            code = clients.run(["cursor"], True, out=lines.append)
        text = "\n".join(lines)
        self.assertEqual(code, 1)
        self.assertIn("not valid JSON", text)
        self.assertNotIn("Expecting property name", text)
        with open(bad) as f:
            self.assertEqual(f.read(), "{ broken")          # left alone


@unittest.skipUnless(os.name == "posix", "termios")
class PasteMustNotEcho(unittest.TestCase):
    def tty(self):
        s = mock.Mock()
        s.isatty.return_value = True
        s.fileno.return_value = 0
        return s

    def test_a_terminal_that_cannot_hide_typing_is_refused(self):
        import termios
        with mock.patch.object(termios, "tcgetattr", side_effect=termios.error(25, "no")):
            self.assertFalse(safeprompt.typing_can_be_hidden(self.tty()))
            with mock.patch.object(sys, "stdin", self.tty()), \
                    mock.patch.object(safeprompt.getpass, "getpass") as gp, \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(EOFError):
                    safeprompt.read_hidden("key: ")
            gp.assert_not_called()
            self.assertIn("Nothing was read", err.getvalue())

    def test_a_normal_terminal_and_a_pipe_are_fine(self):
        import termios
        with mock.patch.object(termios, "tcgetattr", return_value=[]):
            self.assertTrue(safeprompt.typing_can_be_hidden(self.tty()))
        pipe = mock.Mock()
        pipe.isatty.return_value = False
        self.assertTrue(safeprompt.typing_can_be_hidden(pipe))


class ReadmeWorksOnPyPI(unittest.TestCase):
    def test_no_link_is_relative(self):
        import re
        with open(os.path.join(_isolation.REPO, "README.md"), encoding="utf-8") as f:
            text = f.read()
        bad = [m for m in re.findall(r"\]\(([^)\s]+)\)", text)
               if not re.match(r"(https?://|#|mailto:)", m)]
        self.assertEqual(bad, [], "PyPI shows the README away from the repository: use full addresses")


if __name__ == "__main__":
    unittest.main()
