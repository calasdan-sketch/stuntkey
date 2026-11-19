"""Codex CLI hook adapter. Built from Codex's published hook docs; these use the JSON that page documents. Nothing here touches a real
~/.codex or a real Codex: every file is in a temp folder, and the real masker runs against a throwaway home and keychain."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from stuntkey import codexhook as c

DENY = json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "no"}}) + "\n"
SECRET = "sk-live-0123456789abcdefghijklmnop"


def payload(event, **kw):
    return json.dumps({"session_id": "s", "cwd": "/w", "hook_event_name": event, "model": "m", "turn_id": "t", "tool_use_id": "u", **kw})


@contextlib.contextmanager
def throwaway_home():
    """A temp home with a file keychain, so the real masker can be exercised without touching anything of the person's."""
    keys = ("HOME", "USERPROFILE", "STUNTKEY_TEST_HOME", "STUNTKEY_KEYCHAIN")
    old = {k: os.environ.get(k) for k in keys}
    with tempfile.TemporaryDirectory() as d:
        os.environ.update({"HOME": d, "USERPROFILE": d, "STUNTKEY_TEST_HOME": d, "STUNTKEY_KEYCHAIN": "file:" + os.path.join(d, "kc")})
        try:
            yield d
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class Pre(unittest.TestCase):
    def test_a_deny_from_the_check_is_passed_through_in_codexs_shape(self):
        st, out, err = c.run(payload("PreToolUse", tool_name="Bash", tool_input={"command": "cat .env"}), check=lambda t: (0, DENY))
        self.assertEqual((st, err), (0, ""))
        spec = json.loads(out)["hookSpecificOutput"]
        self.assertEqual((spec["hookEventName"], spec["permissionDecision"]), ("PreToolUse", "deny"))

    def test_silence_is_allowed_and_adds_no_unsupported_fields(self):
        self.assertEqual(c.run(payload("PreToolUse", tool_name="Bash", tool_input={"command": "ls"}), check=lambda t: (0, "")), (0, "", ""))

    def test_a_failing_check_blocks_with_exit_2_because_codex_would_otherwise_continue(self):
        st, out, err = c.run(payload("PreToolUse", tool_name="Bash", tool_input={"command": "ls"}), check=lambda t: (1, ""))
        self.assertEqual((st, out), (2, ""))
        self.assertIn("blocked", err)

    def test_a_crashing_check_blocks_too(self):
        def boom(t):
            raise RuntimeError("x")
        self.assertEqual(c.run(payload("PreToolUse", tool_name="Bash", tool_input={}), check=boom)[0], 2)

    def test_apply_patch_is_checked_as_a_shell_command_carrying_the_patch_text(self):
        seen = []
        c.run(payload("PreToolUse", tool_name="apply_patch", tool_input={"command": "*** Update File: .env"}), check=lambda t: seen.append(json.loads(t)) or (0, ""))
        self.assertEqual((seen[0]["tool_name"], seen[0]["tool_input"]["command"]), ("Bash", "*** Update File: .env"))

    def test_the_real_check_refuses_an_env_file_in_a_codex_shaped_call(self):
        with throwaway_home():
            st, out, _ = c.run(payload("PreToolUse", tool_name="Bash", tool_input={"command": "cat .env"}))
        self.assertEqual(st, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_mcp_tools_are_passed_unchanged(self):
        seen = []
        c.run(payload("PreToolUse", tool_name="mcp__fs__read", tool_input={"path": "a"}), check=lambda t: seen.append(json.loads(t)) or (0, ""))
        self.assertEqual(seen[0]["tool_name"], "mcp__fs__read")


class Post(unittest.TestCase):
    def test_a_protected_key_in_the_output_withholds_the_whole_result(self):
        st, out, _ = c.run(payload("PostToolUse", tool_name="Bash", tool_input={"command": "x"}, tool_response={"output": "k=SECRET"}),
                           mask=lambda v, p, **k: (v, 1))
        doc = json.loads(out)
        self.assertEqual((st, doc["decision"]), (0, "block"))
        self.assertIn("withheld", doc["reason"])
        self.assertNotIn("updatedToolOutput", out)             # Codex does not support it

    def test_clean_output_says_nothing(self):
        self.assertEqual(c.run(payload("PostToolUse", tool_name="Bash", tool_input={}, tool_response="fine"), mask=lambda v, p, **k: (v, 0)), (0, "", ""))

    def test_a_failing_output_check_withholds_instead_of_showing(self):
        def boom(v, p, **k):
            raise RuntimeError("x")
        st, out, err = c.run(payload("PostToolUse", tool_name="Bash", tool_input={}, tool_response="x"), mask=boom)
        self.assertEqual((st, out), (2, ""))
        self.assertIn("withheld", err)

    def test_the_response_may_be_any_shape(self):
        for resp in ("text", {"stdout": "a"}, [1, "b"], {"content": [{"type": "text", "text": "z"}]}):
            self.assertEqual(c.run(payload("PostToolUse", tool_name="Bash", tool_input={}, tool_response=resp), mask=lambda v, p, **k: (v, 0))[0], 0)

    def test_the_real_masker_withholds_a_stored_key_in_a_nested_response_and_passes_a_clean_one(self):
        from stuntkey import scrub
        with throwaway_home():
            scrub.remember_key("svc/API_KEY", SECRET)
            dirty = {"content": [{"type": "text", "text": "the key is " + SECRET}], "exit_code": 0}
            st, out, _ = c.run(payload("PostToolUse", tool_name="Bash", tool_input={}, tool_response=dirty))
            self.assertEqual(st, 0)
            self.assertEqual(json.loads(out)["decision"], "block")
            self.assertNotIn(SECRET, out)
            self.assertEqual(c.run(payload("PostToolUse", tool_name="Bash", tool_input={}, tool_response={"stdout": "hello"})), (0, "", ""))


class Events(unittest.TestCase):
    def test_other_events_are_not_ours(self):
        self.assertEqual(c.run(payload("SessionStart")), (0, "", ""))

    def test_garbage_input_blocks(self):
        for bad in ("", "not json", "[1]"):
            self.assertEqual(c.run(bad)[0], 2, bad)


class Config(unittest.TestCase):
    def test_install_adds_both_events_keeps_other_hooks_and_is_idempotent(self):
        other = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool"}]}], "Stop": [{"hooks": []}]}, "description": "mine"}
        new, changed = c.merge_install(other)
        self.assertTrue(changed)
        self.assertEqual(new["description"], "mine")
        self.assertEqual(len(new["hooks"]["PreToolUse"]), 2)
        self.assertEqual(new["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "other-tool")
        self.assertIn("PostToolUse", new["hooks"])
        again, changed2 = c.merge_install(new)
        self.assertEqual((changed2, again), (False, new))

    def test_undo_removes_only_ours(self):
        new, _ = c.merge_install({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "other-tool"}]}]}})
        gone, changed = c.remove_install(new)
        self.assertTrue(changed)
        self.assertEqual(gone, {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "other-tool"}]}]}})

    def test_the_command_runs_our_adapter(self):
        self.assertIn("-m stuntkey hook codex", c.command_line())

    def test_write_keeps_a_backup_and_dry_run_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".codex", "hooks.json")
            os.makedirs(os.path.dirname(p))
            with open(p, "w", encoding="utf-8") as f:
                f.write(json.dumps({"hooks": {"Stop": []}}))
            before = open(p, encoding="utf-8").read()
            self.assertEqual(c.cmd_install(False, path=p, out=io.StringIO()), 0)
            self.assertEqual(open(p, encoding="utf-8").read(), before)             # dry run
            self.assertEqual(c.cmd_install(True, path=p, out=io.StringIO()), 0)
            self.assertIn("stuntkey", open(p, encoding="utf-8").read())
            backups = [f for f in os.listdir(os.path.dirname(p)) if "stuntkey-backup" in f]
            self.assertEqual(len(backups), 1)
            self.assertEqual(open(os.path.join(os.path.dirname(p), backups[0]), encoding="utf-8").read(), before)
            self.assertEqual(c.cmd_status(path=p, out=io.StringIO()), 0)
            self.assertEqual(c.cmd_install(True, undo=True, path=p, out=io.StringIO()), 0)
            self.assertEqual(c.cmd_status(path=p, out=io.StringIO()), 1)

    def test_a_broken_hooks_file_is_left_alone(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "hooks.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("{not json")
            self.assertEqual(c.cmd_install(True, path=p, out=io.StringIO()), 1)
            self.assertEqual(open(p, encoding="utf-8").read(), "{not json")

    def test_the_install_message_states_the_trust_step_and_the_limits(self):
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            c.cmd_install(True, path=os.path.join(d, "hooks.json"), out=out)
            text = out.getvalue()
            self.assertIn("/hooks", text)
            self.assertIn("not a complete enforcement boundary", text)
            self.assertIn("not yet run inside the real app", text)


if __name__ == "__main__":
    unittest.main()
