"""Cursor hook adapter, built from Cursor's published hook docs and tested with the JSON that page documents. Every file is in a temp
folder; the real check runs against a throwaway home."""
import io
import json
import os
import tempfile
import unittest

from stuntkey import cursorhook as c
from test_codexhook import DENY, SECRET, throwaway_home


def payload(event, **kw):
    return json.dumps({"conversation_id": "c", "generation_id": "g", "hook_event_name": event, "cwd": "/w", "model": "m", **kw})


class Pre(unittest.TestCase):
    def test_a_deny_becomes_cursors_permission_deny_with_both_messages(self):
        st, out, err = c.run(payload("preToolUse", tool_name="Shell", tool_input={"command": "cat .env"}), check=lambda t: (0, DENY))
        doc = json.loads(out)
        self.assertEqual((st, err, doc["permission"]), (0, "", "deny"))
        self.assertTrue(doc["user_message"] and doc["agent_message"])

    def test_silence_becomes_an_explicit_allow(self):
        st, out, _ = c.run(payload("preToolUse", tool_name="Shell", tool_input={"command": "ls"}), check=lambda t: (0, ""))
        self.assertEqual((st, json.loads(out)), (0, {"permission": "allow"}))

    def test_a_failing_check_blocks_with_exit_2_because_cursor_fails_open_by_default(self):
        self.assertEqual(c.run(payload("preToolUse", tool_name="Shell", tool_input={}), check=lambda t: (1, ""))[0], 2)

    def test_a_crashing_check_blocks(self):
        def boom(t):
            raise RuntimeError("x")
        self.assertEqual(c.run(payload("preToolUse", tool_name="Shell", tool_input={}), check=boom)[0], 2)

    def test_tool_names_and_path_fields_are_mapped(self):
        seen = []
        chk = lambda t: seen.append(json.loads(t)) or (0, "")
        c.run(payload("preToolUse", tool_name="Shell", tool_input={"command": "ls"}), check=chk)
        c.run(payload("preToolUse", tool_name="Read", tool_input={"path": "/p/.env"}), check=chk)
        c.run(payload("preToolUse", tool_name="Write", tool_input={"target_file": "/p/a", "contents": "hi"}), check=chk)
        c.run(payload("preToolUse", tool_name="MCP:search", tool_input={"q": "x"}), check=chk)
        c.run(payload("preToolUse", tool_name="Delete", tool_input={"path": "/p/.env"}), check=chk)
        self.assertEqual([s["tool_name"] for s in seen], ["Bash", "Read", "Write", "mcp__cursor__search", "Write"])
        self.assertEqual(seen[1]["tool_input"]["path"], "/p/.env")
        self.assertEqual((seen[2]["tool_input"]["file_path"], seen[2]["tool_input"]["content"]), ("/p/a", "hi"))

    def test_the_real_check_refuses_reading_an_env_file(self):
        with throwaway_home():
            st, out, _ = c.run(payload("preToolUse", tool_name="Read", tool_input={"path": "/proj/.env"}))
        self.assertEqual((st, json.loads(out)["permission"]), (0, "deny"))

    def test_the_real_check_refuses_a_shell_command_that_reads_an_env_file(self):
        with throwaway_home():
            _st, out, _ = c.run(payload("preToolUse", tool_name="Shell", tool_input={"command": "cat .env"}))
        self.assertEqual(json.loads(out)["permission"], "deny")


class Post(unittest.TestCase):
    def test_only_mcp_output_can_be_replaced(self):
        st, out, _ = c.run(payload("postToolUse", tool_name="MCP:search", tool_input={}, tool_output=json.dumps({"r": "k=SECRET"})),
                           mask=lambda v, p, **k: (v, 1))
        self.assertEqual(st, 0)
        self.assertIn("withheld", json.loads(out)["updated_mcp_tool_output"]["withheld"])

    def test_a_shell_output_cannot_be_touched_and_the_adapter_says_nothing(self):
        def boom(v, p, **k):
            raise AssertionError("must not even look: nothing can be done afterwards")
        self.assertEqual(c.run(payload("postToolUse", tool_name="Shell", tool_input={}, tool_output="{}"), mask=boom), (0, "", ""))

    def test_clean_mcp_output_says_nothing(self):
        self.assertEqual(c.run(payload("postToolUse", tool_name="MCP:x", tool_input={}, tool_output="{}"), mask=lambda v, p, **k: (v, 0)), (0, "", ""))

    def test_a_failing_mcp_check_withholds(self):
        def boom(v, p, **k):
            raise RuntimeError("x")
        _st, out, _ = c.run(payload("postToolUse", tool_name="MCP:x", tool_input={}, tool_output="{}"), mask=boom)
        self.assertIn("updated_mcp_tool_output", out)

    def test_the_real_masker_withholds_a_stored_key_in_mcp_output(self):
        from stuntkey import scrub
        with throwaway_home():
            scrub.remember_key("svc/API_KEY", SECRET)
            _st, out, _ = c.run(payload("postToolUse", tool_name="MCP:x", tool_input={}, tool_output=json.dumps({"text": "key " + SECRET})))
        self.assertIn("updated_mcp_tool_output", out)
        self.assertNotIn(SECRET, out)


class Events(unittest.TestCase):
    def test_other_events_and_garbage(self):
        self.assertEqual(c.run(payload("sessionStart")), (0, "", ""))
        for bad in ("", "nope", "[1]"):
            self.assertEqual(c.run(bad)[0], 2)


class Config(unittest.TestCase):
    def test_install_is_fail_closed_keeps_other_hooks_and_is_idempotent(self):
        other = {"version": 1, "hooks": {"preToolUse": [{"command": "./mine.sh"}], "stop": [{"command": "./a.sh"}]}}
        new, changed = c.merge_install(other)
        self.assertTrue(changed)
        mine = [e for e in new["hooks"]["preToolUse"] if c._is_ours(e)][0]
        self.assertTrue(mine["failClosed"])
        self.assertEqual(new["hooks"]["preToolUse"][0], {"command": "./mine.sh"})
        self.assertEqual(new["hooks"]["postToolUse"][0]["matcher"], "MCP:.*")        # nothing else can be hidden afterwards
        again, changed2 = c.merge_install(new)
        self.assertEqual((changed2, again), (False, new))

    def test_undo_removes_only_ours(self):
        new, _ = c.merge_install({"version": 1, "hooks": {"preToolUse": [{"command": "./mine.sh"}]}})
        gone, changed = c.remove_install(new)
        self.assertEqual((changed, gone["hooks"]), (True, {"preToolUse": [{"command": "./mine.sh"}]}))

    def test_write_status_undo_and_backup(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".cursor", "hooks.json")
            os.makedirs(os.path.dirname(p))
            with open(p, "w", encoding="utf-8") as f:
                f.write(json.dumps({"version": 1, "hooks": {"stop": [{"command": "./a.sh"}]}}))
            before = open(p, encoding="utf-8").read()
            self.assertEqual(c.cmd_install(False, path=p, out=io.StringIO()), 0)
            self.assertEqual(open(p, encoding="utf-8").read(), before)
            self.assertEqual(c.cmd_install(True, path=p, out=io.StringIO()), 0)
            self.assertEqual(c.cmd_status(path=p, out=io.StringIO()), 0)
            backups = [f for f in os.listdir(os.path.dirname(p)) if "stuntkey-backup" in f]
            self.assertEqual(open(os.path.join(os.path.dirname(p), backups[0]), encoding="utf-8").read(), before)
            self.assertEqual(c.cmd_install(True, undo=True, path=p, out=io.StringIO()), 0)
            self.assertEqual(c.cmd_status(path=p, out=io.StringIO()), 1)

    def test_a_broken_file_is_left_alone(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "hooks.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("{bad")
            self.assertEqual(c.cmd_install(True, path=p, out=io.StringIO()), 1)
            self.assertEqual(open(p, encoding="utf-8").read(), "{bad")

    def test_the_message_states_the_big_limit_and_that_it_was_not_run_in_cursor(self):
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            c.cmd_install(True, path=os.path.join(d, "hooks.json"), out=out)
            text = out.getvalue()
            self.assertIn("cannot hide or clean up the output of a shell command", text)
            self.assertIn("not yet run inside the real app", text)


class FromTheSecurityReview(unittest.TestCase):
    """Each input below was an ALLOW before the independent review. They run the REAL check against a throwaway home."""

    def _decide(self, **kw):
        with throwaway_home():
            st, out, _err = c.run(payload("preToolUse", **kw))
        return st, ("deny" if '"deny"' in out else "allow" if out.strip() else "none")

    def test_mcp_arguments_sent_as_a_json_string_are_read(self):
        self.assertEqual(self._decide(tool_name="MCP:fs_read", tool_input=json.dumps({"path": "/home/u/.ssh/id_rsa"})), (0, "deny"))

    def test_a_shell_command_given_as_a_list_or_as_cmd_is_read(self):
        self.assertEqual(self._decide(tool_name="Shell", tool_input={"command": ["bash", "-lc", "cat .env"]}), (0, "deny"))
        self.assertEqual(self._decide(tool_name="shell", tool_input={"cmd": "cat .env"}), (0, "deny"))

    def test_arguments_that_cannot_be_read_are_blocked_not_allowed(self):
        for ti in (None, 5, [1, 2]):
            self.assertEqual(self._decide(tool_name="Shell", tool_input=ti)[0], 2, ti)
        self.assertEqual(self._decide(tool_name="Shell", tool_input={"working_directory": "/p"})[0], 2)

    def test_tools_outside_the_documented_list_are_still_checked(self):
        self.assertEqual(self._decide(tool_name="StrReplace", tool_input={"path": ".env", "old_string": "a", "new_string": "b"}), (0, "deny"))
        self.assertEqual(self._decide(tool_name="SomeNewTool", tool_input={"target": "/home/u/.ssh/id_rsa"})[1], "deny")

    def test_every_path_field_is_checked_not_only_the_first(self):
        self.assertEqual(self._decide(tool_name="Read", tool_input={"file_path": "a.txt", "target_file": ".env"}), (0, "deny"))
        self.assertEqual(self._decide(tool_name="Grep", tool_input={"target_file": ".env", "pattern": "x"})[1], "deny")

    def test_a_missing_or_oddly_spelled_event_name_is_not_waved_through(self):
        for ev in (None, "", "PRETOOLUSE", "pre_tool_use"):
            with throwaway_home():
                st, out, _ = c.run(json.dumps({"hook_event_name": ev, "tool_name": "Shell", "tool_input": {"command": "cat .env"}}))
            self.assertIn((st, '"deny"' in out), ((0, True), (2, False)), ev)

    def test_the_hook_files_cannot_be_changed_by_the_agent(self):
        for cmd in ("rm ~/.cursor/hooks.json", "echo {} > ~/.cursor/hooks.json", "stuntkey hook cursor-install --undo --write"):
            self.assertEqual(self._decide(tool_name="Shell", tool_input={"command": cmd}), (0, "deny"), cmd)
        self.assertEqual(self._decide(tool_name="Delete", tool_input={"path": "/home/u/.cursor/hooks.json"}), (0, "deny"))

    def test_an_internal_crash_exits_2(self):
        from unittest import mock
        with mock.patch.object(c, "run", side_effect=RuntimeError("boom")), mock.patch("sys.stdin", io.StringIO("{}")):
            self.assertEqual(c.cmd_cursor(), 2)

    def test_odd_hooks_files_are_a_plain_message_not_a_traceback(self):
        for body in ('{"hooks": null}', '{"hooks": []}', '{"hooks": {"preToolUse": 5}}'):
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "hooks.json")
                with open(p, "w", encoding="utf-8") as f:
                    f.write(body)
                self.assertEqual(c.cmd_install(True, path=p, out=io.StringIO()), 1, body)
                self.assertEqual(open(p, encoding="utf-8").read(), body)


if __name__ == "__main__":
    unittest.main()
