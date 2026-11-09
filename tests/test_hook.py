"""0.5.0: `stuntkey hook` - a Claude Code PreToolUse hook that refuses
.env files, and the code that adds it to settings.json without touching
anyone else's hooks."""

import contextlib
import io
import json
import os
import sys
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import hook as hook_mod


def call(tool, **tool_input):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                       "tool_input": tool_input})


def denied(stdin_text):
    status, out = hook_mod.check(stdin_text)
    assert status == 0
    return bool(out)


def run_cli(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(sys, "stdin", io.StringIO(stdin)):
        try:
            code = cli_mod.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class TestNames(unittest.TestCase):
    def test_real_env_files(self):
        for name in (".env", ".env.local", ".env.production", "prod.env", ".envrc",
                     ".ENV", ".env.staging.local"):
            self.assertTrue(hook_mod.is_env_name(name), name)

    def test_templates_and_lookalikes_are_fine(self):
        for name in (".env.example", ".env.sample", ".env.template", ".env.dist",
                     "environment.py", ".environment", "env.py", "my.environment",
                     "dotenv.js", ".envelope"):
            self.assertFalse(hook_mod.is_env_name(name), name)


class TestDecision(unittest.TestCase):
    def test_read_env_is_denied_with_the_documented_shape(self):
        status, out = hook_mod.check(call("Read", file_path="/home/me/app/.env"))
        self.assertEqual(status, 0)
        answer = json.loads(out)
        spec = answer["hookSpecificOutput"]
        self.assertEqual(spec["hookEventName"], "PreToolUse")
        self.assertEqual(spec["permissionDecision"], "deny")
        self.assertIn(".env", spec["permissionDecisionReason"])
        self.assertEqual(set(answer), {"hookSpecificOutput"})

    def test_the_reason_is_plain_words(self):
        reason = hook_mod.decision_json("because")["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertEqual(reason, "because")
        text = hook_mod.REASON.format(what="'.env'")
        self.assertIn("stuntkey run", text)

    def test_ordinary_reads_say_nothing(self):
        self.assertEqual(hook_mod.check(call("Read", file_path="/a/src/app.py")), (0, ""))

    def test_only_deny_is_ever_answered(self):
        # an "allow" would skip the person's own permission rules
        for text in (call("Read", file_path="/a/b.py"), call("Bash", command="ls")):
            self.assertNotIn("allow", hook_mod.check(text)[1])

    def test_templates_may_be_read(self):
        self.assertFalse(denied(call("Read", file_path="/a/.env.example")))

    def test_bash_commands(self):
        for cmd in ("cat .env", "grep KEY ./config/.env.local", "source .env && run",
                    "cp ~/proj/.env /tmp/x", "type C:\\proj\\.env", "less prod.env",
                    "cat .env*", "head -3 \"$PWD/.env\"", "echo hi; cat .env"):
            self.assertTrue(denied(call("Bash", command=cmd)), cmd)
        for cmd in ("ls -la", "git add .env.example", "python environment.py",
                    "cat .envelope", "npm test"):
            self.assertFalse(denied(call("Bash", command=cmd)), cmd)

    def test_grep_tool(self):
        self.assertTrue(denied(call("Grep", pattern="KEY", path="/a/.env")))
        self.assertTrue(denied(call("Grep", pattern="KEY", glob="**/.env*")))
        self.assertFalse(denied(call("Grep", pattern="KEY", path="/a/src")))

    def test_other_tools_are_not_our_business(self):
        self.assertEqual(hook_mod.check(call("Glob", file_path="/a/.env")), (0, ""))

    def test_bad_input_never_blocks(self):
        self.assertEqual(hook_mod.check("not json"), (1, ""))
        self.assertEqual(hook_mod.check("[1,2]"), (0, ""))
        self.assertEqual(hook_mod.check("null"), (0, ""))
        self.assertEqual(hook_mod.check(json.dumps({"tool_name": "Read"})), (0, ""))
        self.assertEqual(hook_mod.check(json.dumps({"tool_name": "Read", "tool_input": "x"})), (0, ""))
        self.assertEqual(hook_mod.check(json.dumps({"tool_name": "Bash", "tool_input": {"command": 5}})), (0, ""))

    def test_hostile_file_name_in_the_reason_is_escaped(self):
        out = hook_mod.check(call("Read", file_path="/a/x\x1b[31m.env"))[1]
        self.assertNotIn("\x1b", out)

    def test_cli_entry_point_prints_only_the_answer(self):
        code, out, err = run_cli("hook", "check", stdin=call("Bash", command="cat .env"))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_cli_entry_point_on_garbage_is_a_non_blocking_error(self):
        code, out, err = run_cli("hook", "check", stdin="}{")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("nothing was blocked", err)


class Settings(unittest.TestCase):
    def setUp(self):
        self.dir = _isolation.mktemp()
        self.path = os.path.join(self.dir, ".claude", "settings.json")
        # POSIX writes the shell string, Windows the exec form (`command` is
        # the program, `args` the rest): patch both sources of the program
        for name, fake in (("hook_command", lambda: "/opt/bin/stuntkey hook check"),
                           ("hook_argv", lambda: ["/opt/bin/stuntkey", "hook", "check"])):
            p = mock.patch.object(hook_mod, name, fake)
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def command_of(handler):
        """The whole command line of a stored handler, whichever form it has."""
        return " ".join([handler["command"], *handler.get("args", [])])

    def put(self, data):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(data if isinstance(data, str) else json.dumps(data))

    def get(self):
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def hook(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        args = cli_mod._build_parser().parse_args(["hook", *argv, "--settings", self.path])
        code = hook_mod.cmd_hook(args, out=out, err=err, run=ok_run)
        return code, out.getvalue(), err.getvalue()


def ok_run(command, **kw):
    done = mock.Mock()
    done.stdout = hook_mod.check(call("Read", file_path="/tmp/.env"))[1].encode()
    return done


def bad_run(command, **kw):
    done = mock.Mock()
    done.stdout = b""
    return done


class TestInstall(Settings):
    def test_creates_the_file_with_the_hook(self):
        code, out, _ = self.hook("install")
        self.assertEqual(code, 0)
        group = self.get()["hooks"]["PreToolUse"][0]
        self.assertEqual(group["matcher"], hook_mod.MATCHER)
        handler = group["hooks"][0]
        self.assertEqual(handler["type"], "command")
        self.assertEqual(self.command_of(handler), "/opt/bin/stuntkey hook check")
        self.assertEqual(handler["timeout"], hook_mod.HOOK_TIMEOUT)
        self.assertEqual(handler["statusMessage"], hook_mod.MARKER)
        self.assertIn("Restart Claude Code", out)

    def test_twice_changes_nothing(self):
        self.hook("install")
        with open(self.path, "rb") as f:
            first = f.read()
        code, out, _ = self.hook("install")
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), first)
        self.assertIn("Already installed", out)

    def test_other_hooks_and_settings_survive(self):
        mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/x/audit.sh"}]}
        other = {"matcher": "*", "hooks": [{"type": "command", "command": "echo hi", "timeout": 3}]}
        self.put({"permissions": {"allow": ["Bash(ls)"]}, "model": "opus",
                  "hooks": {"PreToolUse": [mine], "PostToolUse": [other]}})
        self.hook("install")
        data = self.get()
        self.assertEqual(data["permissions"], {"allow": ["Bash(ls)"]})
        self.assertEqual(data["model"], "opus")
        self.assertEqual(data["hooks"]["PostToolUse"][0], other)
        self.assertEqual(data["hooks"]["PostToolUse"][1]["matcher"], "^(Bash|mcp__.*)$")
        self.assertEqual(data["hooks"]["PreToolUse"][0], mine)
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 2)

    def test_a_hook_that_only_mentions_stuntkey_is_not_ours(self):
        foreign = {"matcher": "Bash", "hooks": [{"type": "command", "command": "stuntkey scan"}]}
        self.put({"hooks": {"PreToolUse": [foreign]}})
        self.hook("install")
        self.hook("uninstall")
        self.assertEqual(self.get()["hooks"]["PreToolUse"], [foreign])

    def test_a_stale_command_is_updated_not_duplicated(self):
        self.put({"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [
            {"type": "command", "command": "/old/path/stuntkey hook check", "timeout": 99}]}]}})
        self.hook("install")
        groups = self.get()["hooks"]["PreToolUse"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(self.command_of(groups[0]["hooks"][0]), "/opt/bin/stuntkey hook check")
        self.assertEqual(groups[0]["hooks"][0]["timeout"], hook_mod.HOOK_TIMEOUT)

    def test_every_change_keeps_its_own_backup_outside_the_folder(self):
        _isolation.rmtree(hook_mod.backup_dir())
        self.put({"model": "opus"})
        self.hook("install")
        self.hook("uninstall")
        self.assertFalse(os.path.exists(self.path + ".stuntkey-backup"))
        names = sorted(os.listdir(hook_mod.backup_dir()))
        self.assertEqual(len(names), 2)
        with open(os.path.join(hook_mod.backup_dir(), names[0]), encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"model": "opus"})
        with open(os.path.join(hook_mod.backup_dir(), names[1]), encoding="utf-8") as f:
            self.assertIn("hooks", json.load(f))

    def test_broken_json_is_left_alone(self):
        self.put("{ not json")
        code, out, err = self.hook("install")
        self.assertEqual(code, 2)
        with open(self.path, encoding="utf-8") as f:
            self.assertEqual(f.read(), "{ not json")
        self.assertIn("left it alone", err)

    def test_odd_shapes_are_left_alone(self):
        for data in ([1], {"hooks": []}, {"hooks": {"PreToolUse": {}}}):
            self.put(data)
            with open(self.path, encoding="utf-8") as f:
                before = f.read()
            self.assertEqual(self.hook("install")[0], 2)
            with open(self.path, encoding="utf-8") as f:
                self.assertEqual(f.read(), before)

    def test_a_hook_that_does_not_work_is_reported(self):
        args = cli_mod._build_parser().parse_args(["hook", "install", "--settings", self.path])
        out = io.StringIO()
        code = hook_mod.cmd_hook(args, out=out, err=io.StringIO(), run=bad_run)
        self.assertEqual(code, 1)
        self.assertIn("did not answer as expected", out.getvalue())

    def test_project_flag_uses_the_project_folder(self):
        old = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, old)
        args = cli_mod._build_parser().parse_args(["hook", "install", "--project"])
        hook_mod.cmd_hook(args, out=io.StringIO(), err=io.StringIO(), run=ok_run)
        self.assertTrue(os.path.exists(os.path.join(self.dir, ".claude", "settings.json")))

    def test_default_is_the_users_settings(self):
        self.assertTrue(hook_mod.user_settings_path().startswith(_isolation.FAKE_HOME))


class TestUninstallAndStatus(Settings):
    def test_removes_only_ours(self):
        other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/x/a.sh"}]}
        self.put({"hooks": {"PreToolUse": [other]}})
        self.hook("install")
        code, out, _ = self.hook("uninstall")
        self.assertEqual(code, 0)
        self.assertEqual(self.get(), {"hooks": {"PreToolUse": [other]}})

    def test_an_emptied_hooks_section_goes_away(self):
        self.put({"model": "opus"})
        self.hook("install")
        self.hook("uninstall")
        self.assertEqual(self.get(), {"model": "opus"})

    def test_a_shared_group_keeps_its_other_handlers(self):
        shared = {"matcher": "Bash", "hooks": [
            {"type": "command", "command": "/x/a.sh"},
            {"type": "command", "command": "/opt/bin/stuntkey hook check"}]}
        self.put({"hooks": {"PreToolUse": [shared]}})
        self.hook("uninstall")
        self.assertEqual(self.get()["hooks"]["PreToolUse"][0]["hooks"],
                         [{"type": "command", "command": "/x/a.sh"}])

    def test_uninstall_when_absent_changes_nothing(self):
        code, out, _ = self.hook("uninstall")
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(self.path))
        self.assertIn("nothing changed", out)

    def test_status_installed_and_not(self):
        self.assertEqual(self.hook("status")[0], 1)
        self.hook("install")
        code, out, _ = self.hook("status")
        self.assertEqual(code, 0)
        self.assertIn("blocks a test read", out)

    def test_status_flags_an_old_post_matcher_as_outdated(self):
        self.hook("install")
        data = self.get()
        data["hooks"]["PostToolUse"][0]["matcher"] = "Bash"
        self.put(data)
        code, out, _ = self.hook("status")
        self.assertIn("OUTDATED", out)
        self.assertIn("stuntkey hook install", out)
        self.assertNotIn("Bash output", out)
        self.hook("install")
        self.assertEqual(self.get()["hooks"]["PostToolUse"][0]["matcher"],
                         hook_mod.POST_MATCHER)
        self.assertNotIn("OUTDATED", self.hook("status")[1])

    def test_status_with_no_post_group_says_install_adds_it(self):
        self.hook("install")
        data = self.get()
        del data["hooks"]["PostToolUse"]
        self.put(data)
        out = self.hook("status")[1]
        self.assertIn("stuntkey hook install", out)
        self.assertNotIn("Bash output", out)

    def test_status_with_unreadable_settings_does_not_crash(self):
        self.put("{oops")
        code, out, _ = self.hook("status")
        self.assertEqual(code, 1)
        self.assertIn("cannot tell", out)


class TestCommand(unittest.TestCase):
    def test_uses_the_installed_program_by_full_path(self):
        exe = os.path.join(_isolation.mktemp(), "stuntkey")
        with mock.patch.object(hook_mod, "console_script", lambda: exe):
            cmd = hook_mod.hook_command()
        self.assertTrue(cmd.endswith(" hook check"))
        self.assertIn(exe.replace("\\", "/").split("/")[-1], cmd)
        self.assertTrue(os.path.isabs(cmd.strip('"').split(" hook check")[0].strip("'\"")))

    def test_falls_back_to_isolated_python(self):
        with mock.patch.object(hook_mod, "console_script", lambda: None):
            cmd = hook_mod.hook_command()
        self.assertIn(" -I -m stuntkey hook check", cmd)
        self.assertIn(os.path.abspath(sys.executable).replace("\\", "/").split("/")[-1], cmd)

    def test_a_path_with_spaces_is_quoted(self):
        with mock.patch.object(hook_mod, "console_script", lambda: "/opt/my tools/stuntkey"):
            self.assertIn("'/opt/my tools/stuntkey'", hook_mod.hook_command()) if os.name != "nt" else None

    def test_entry_shape_lives_in_one_function(self):
        entry = hook_mod.hook_entry(hook_mod.hook_handler(shell_form=True))
        self.assertEqual(set(entry), {"matcher", "hooks"})
        self.assertEqual(set(entry["hooks"][0]),
                         {"type", "command", "timeout", "statusMessage", "onFailure"})
