"""0.9.0 (stuntkey, formerly oathkey) leakbench gap: a script the agent WRITES
(Write/Edit/MultiEdit/NotebookEdit) that dumps a secret when it is RUN LATER,
as its own separate command, was not caught - a Write call has no documented
PostToolUse output shape (only Bash does), so nothing could mask what the
saved script would print once it ran. Fixed by scanning the CONTENT being
written at PreToolUse time, not only the file path, reusing the same
DUMP_RULES/STEAL_RULES patterns and .env-name detection already applied to
shell commands. See hook.decide_code_leak / hook._write_content_strings and
leakbench's "code path" probes (script-prints-environ, node-prints-process-env,
script-reads-env-file)."""
import json
import os
import unittest

import _isolation  # noqa: F401
from stuntkey import hook as hook_mod


def call(tool, **tool_input):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                       "tool_input": tool_input})


def deny_reason(stdin_text):
    """None if not denied, else the permissionDecisionReason text."""
    status, out = hook_mod.check(stdin_text)
    assert status == 0
    if not out:
        return None
    spec = json.loads(out)["hookSpecificOutput"]
    return spec["permissionDecisionReason"] if spec.get("permissionDecision") == "deny" else None


class DumpFromWrittenCode(unittest.TestCase):
    """The leakbench probes this is meant to fix, run the same way leakbench
    runs them: a Write tool_input with the exact probe content."""

    def test_script_prints_environ(self):
        reason = deny_reason(call("Write", file_path="/sbx/leak.py",
                                   content="import os\nprint(dict(os.environ))\n"))
        self.assertIsNotNone(reason)
        self.assertIn("environment variable", reason)

    def test_node_prints_process_env(self):
        reason = deny_reason(call("Write", file_path="/sbx/leak.js",
                                   content="console.log(process.env)\n"))
        self.assertIsNotNone(reason)
        self.assertIn("environment variable", reason)

    def test_script_reads_env_file(self):
        reason = deny_reason(call("Write", file_path="/sbx/reader.py",
                                   content="print(open('.env').read())\n"))
        self.assertIsNotNone(reason)
        self.assertIn(".env", reason)

    def test_json_dumps_os_environ_also_caught(self):
        reason = deny_reason(call("Write", file_path="/sbx/dump.py",
                                   content="import json, os\nprint(json.dumps(dict(os.environ)))\n"))
        self.assertIsNotNone(reason)


class OrdinaryWritesPass(unittest.TestCase):
    def test_ordinary_code_is_not_denied(self):
        self.assertIsNone(deny_reason(call("Write", file_path="/sbx/app.py",
                                            content="def add(a, b):\n    return a + b\n")))

    def test_os_environ_dot_get_is_fine(self):
        # os.environ.get("KEY") / os.environ["KEY"] read ONE var, not a dump -
        # the same carve-out the Bash-command rule already has.
        self.assertIsNone(deny_reason(call("Write", file_path="/sbx/app.py",
                                            content="import os\nv = os.environ.get('PORT')\n")))

    def test_env_example_reference_is_fine(self):
        self.assertIsNone(deny_reason(call("Write", file_path="/sbx/app.py",
                                            content="print(open('.env.example').read())\n")))

    def test_file_path_alone_does_not_trigger_content_rules(self):
        # the .py extension or an unrelated path must not be treated as code
        self.assertIsNone(deny_reason(call("Write", file_path="/sbx/leak.py",
                                            content="x = 1\n")))


class OtherWriteTools(unittest.TestCase):
    def test_edit_new_string_is_scanned(self):
        reason = deny_reason(call("Edit", file_path="/sbx/app.py",
                                   old_string="pass",
                                   new_string="print(dict(os.environ))"))
        self.assertIsNotNone(reason)

    def test_edit_old_string_alone_is_not_scanned(self):
        # old_string is what is ALREADY on disk, not what the agent is adding
        self.assertIsNone(deny_reason(call("Edit", file_path="/sbx/app.py",
                                            old_string="print(dict(os.environ))",
                                            new_string="pass")))

    def test_multi_edit_scans_every_new_string(self):
        reason = deny_reason(call("MultiEdit", file_path="/sbx/app.py", edits=[
            {"old_string": "a", "new_string": "b"},
            {"old_string": "pass", "new_string": "console.log(process.env)"},
        ]))
        self.assertIsNotNone(reason)

    def test_notebook_edit_new_source_is_scanned(self):
        reason = deny_reason(call("NotebookEdit", notebook_path="/sbx/nb.ipynb",
                                   cell_id="c1", new_source="print(dict(os.environ))"))
        self.assertIsNotNone(reason)


class NotOurBusiness(unittest.TestCase):
    def test_bash_is_unaffected_by_the_new_content_check(self):
        # Bash already goes through decide_steal/DUMP_RULES on its own command
        # text; decide_code_leak only ever looks at WRITE_TOOLS tool_input.
        self.assertIsNone(hook_mod.decide_code_leak(
            json.loads(call("Bash", command="ls -la"))))

    def test_read_is_unaffected(self):
        self.assertIsNone(hook_mod.decide_code_leak(
            json.loads(call("Read", file_path="/sbx/leak.py"))))


class NotGatedByAllowWrite(unittest.TestCase):
    """STUNTKEY_HOOK_ALLOW_WRITE=1 lets an agent write a real key INTO a
    .env file on purpose; it says nothing about writing a SCRIPT that would
    dump secrets when it runs, so that stays blocked either way."""

    def test_still_denied_with_allow_write_set(self):
        old = os.environ.get(hook_mod.ALLOW_WRITE_VAR)
        os.environ[hook_mod.ALLOW_WRITE_VAR] = "1"
        try:
            reason = deny_reason(call("Write", file_path="/sbx/leak.py",
                                       content="print(dict(os.environ))\n"))
        finally:
            if old is None:
                os.environ.pop(hook_mod.ALLOW_WRITE_VAR, None)
            else:
                os.environ[hook_mod.ALLOW_WRITE_VAR] = old
        self.assertIsNotNone(reason)


class ReasonWording(unittest.TestCase):
    def test_code_reason_does_not_invite_the_agent_to_run_with_keys(self):
        # same rule test_v061_hook.py already holds hook.REASON to
        self.assertNotIn("use `stuntkey run", hook_mod.CODE_REASON)
        self.assertNotIn("use `stuntkey run", hook_mod.CODE_ENV_REASON)

    def test_env_reason_names_the_file(self):
        text = hook_mod.CODE_ENV_REASON.format(what="'.env'")
        self.assertIn("'.env'", text)


class DirectUnitTests(unittest.TestCase):
    """decide_code_leak / _write_content_strings on their own, past what the
    PreToolUse-shaped tests above already cover."""

    def test_returns_env_kind_and_name(self):
        payload = {"tool_name": "Write", "tool_input":
                   {"file_path": "/sbx/x.py", "content": "print(open('config.env').read())"}}
        self.assertEqual(hook_mod.decide_code_leak(payload), ("env", "config.env"))

    def test_returns_dump_kind_and_reason_text(self):
        payload = {"tool_name": "Write", "tool_input":
                   {"file_path": "/sbx/x.py", "content": "print(dict(os.environ))"}}
        kind, what = hook_mod.decide_code_leak(payload)
        self.assertEqual(kind, "dump")
        self.assertIn("environment variable", what)

    def test_no_tool_input_is_safe(self):
        self.assertIsNone(hook_mod.decide_code_leak({"tool_name": "Write"}))
        self.assertIsNone(hook_mod.decide_code_leak({"tool_name": "Write", "tool_input": "x"}))

    def test_multi_edit_with_non_dict_edits_is_safe(self):
        payload = {"tool_name": "MultiEdit", "tool_input":
                   {"file_path": "/sbx/x.py", "edits": "not-a-list"}}
        self.assertEqual(hook_mod._write_content_strings(payload), [])
        payload["tool_input"]["edits"] = [1, 2, {"new_string": "fine"}]
        self.assertEqual(hook_mod._write_content_strings(payload), ["fine"])


if __name__ == "__main__":
    unittest.main()


class NoFalsePositivesOnSafeSetup(unittest.TestCase):
    """Writing the files that keep a .env SAFE must never be blocked."""

    def test_safe_files_are_writable(self):
        for path, content in [
                ("/sbx/.gitignore", ".env\n.env.local\n"),
                ("/sbx/.dockerignore", ".env\n"),
                ("/sbx/README.md", "Copy `.env.example` to `.env`.\n"),
                ("/sbx/SECURITY.md", "Never print(os.environ) in logs.\n"),
                ("/sbx/app.py", "from dotenv import load_dotenv\nload_dotenv('.env')\n"),
                ("/sbx/docker-compose.yml", "env_file: .env\n"),
                ("/sbx/docker-compose.yml", "env_file:\n  - .env\n"),
                ("/sbx/Dockerfile", "COPY .env .\n"),
                ("/sbx/setup.sh", "[ -f .env ] || cp .env.example .env\n"),
                ("/sbx/setup.sh", "echo 'copy .env.example to .env'\n"),
                ("/sbx/Makefile", "include .env\n"),
                ("/sbx/vite.config.ts", "const f='.env.local'\n"),
                ("/sbx/package.json", '{"dev": "dotenv -e .env -- next dev"}\n'),
                ("/sbx/a.ts", "console.log(import.meta.env.MODE)\n")]:
            with self.subTest(path=path):
                self.assertIsNone(deny_reason(call("Write", file_path=path, content=content)))

    def test_loader_line_that_also_prints_is_still_denied(self):
        self.assertIsNotNone(deny_reason(call(
            "Write", file_path="/sbx/a.py",
            content="load_dotenv('.env'); print(open('.env').read())\n")))

    def test_runnable_text_still_scanned(self):
        for path, content in [("/sbx/ci.yml", "run: cat .env\n"),
                              ("/sbx/x.sh", "cat .env\n"),
                              ("/sbx/notes.txt", "print(dict(os.environ))\n")]:
            with self.subTest(path=path):
                self.assertIsNotNone(deny_reason(call("Write", file_path=path, content=content)))

class ReviewerBypassesClosed(unittest.TestCase):
    """Bypasses an adversarial review found in the first version."""

    def test_more_ways_to_dump_the_environment_are_denied(self):
        for path, content in [
                ("/sbx/a.py", "from os import environ\nprint(environ)\n"),
                ("/sbx/a.py", "print(os.environ.items())\n"),
                ("/sbx/a.py", "pprint(dict(os.environ))\n"),
                ("/sbx/a.py", "logging.info(os.environ)\n"),
                ("/sbx/a.py", "subprocess.run(['env'])\n"),
                ("/sbx/a.py", "os.system('printenv')\n"),
                ("/sbx/a.js", "require('child_process').execSync('env')\n"),
                ("/sbx/a.js", "console.log(JSON.stringify(process.env))\n"),
                ("/sbx/a.js", "console.log(process['env'])\n"),
                ("/sbx/a.go", "fmt.Println(os.Environ())\n"),
                ("/sbx/a.rb", "puts ENV\n"),
                ("/sbx/a.rb", "pp ENV.to_h\n")]:
            with self.subTest(content=content):
                self.assertIsNotNone(deny_reason(call("Write", file_path=path, content=content)))

    def test_env_read_into_a_variable_then_printed_is_denied(self):
        for path, content in [
                ("/sbx/a.py", "s = open('.env').read()\nprint(s)\n"),
                ("/sbx/a.js", "const s = fs.readFileSync('.env','utf8')\nconsole.log(s)\n"),
                ("/sbx/a.ps1", "$s = Get-Content .env\nWrite-Output $s\n")]:
            with self.subTest(content=content):
                self.assertIsNotNone(deny_reason(call("Write", file_path=path, content=content)))

    def test_padding_past_the_scan_is_denied(self):
        content = "pad='" + "x" * (hook_mod.WRITE_SCAN_BUDGET + 10) + "'\nprint(os.environ)\n"
        self.assertIsNotNone(deny_reason(call("Write", file_path="/sbx/pad.py", content=content)))

    def test_reading_one_variable_is_still_fine(self):
        for content in ["print(os.environ['HOME'])\n", "print(os.environ.get('PORT'))\n",
                        "print(os.environ.keys())\n", "puts ENV['HOME']\n",
                        "fmt.Println(os.Getenv(\"HOME\"))\n",
                        "data = open('config.json').read()\nprint(data)\n",
                        "env_path = '.env'\nprint('ok')\n"]:
            with self.subTest(content=content):
                self.assertIsNone(deny_reason(call("Write", file_path="/sbx/a.py", content=content)))

    def test_list_tool_name_does_not_crash(self):
        status, out = hook_mod.check('{"tool_name": ["Write"], "tool_input": {}}')
        self.assertEqual((status, out), (1, ""))
