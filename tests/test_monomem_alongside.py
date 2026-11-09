"""Working cleanly alongside Monomem (an MCP memory server): its notes may
mention .env, `stuntkey run` or ~/.stuntkey/ without the PreToolUse hook
refusing them; a stored key in an MCP call is still refused; a stored key in
an MCP result is masked by PostToolUse; and `stuntkey wrap --undo` puts back
only the wrapped server entry."""

import io
import json
import os
import sys
import unittest

import _isolation  # noqa: F401
from stuntkey import hook as hook_mod
from stuntkey import mcpwrap
from stuntkey import recipes as recipes_mod
from stuntkey import scrub
from test_mcp_wrap_bundle import GENERIC, GITHUB, FakeKeychain, args, read, write

STORED = "zq" + "9Xr4" + "Lm2Vt8Kp3Wn7Yb5"      # no known format: only a fingerprint finds it
NOTE = ("Setup: copy .env.example to .env, then `stuntkey run github -- npm test`. "
        "Keys live in ~/.stuntkey/ and the app reads /home/me/app/.env.local.")


def pre(tool, **tool_input) -> str:
    status, out = hook_mod.check(json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}))
    assert status == 0
    return out


class McpArgumentsAreData(unittest.TestCase):
    def setUp(self):
        scrub.remember_key("svc/KEY", STORED)
        self.addCleanup(scrub.forget_key, "svc/KEY")

    def test_memory_notes_that_mention_env_and_stuntkey_pass(self):
        self.assertEqual(pre("mcp__monomem__state_write", key="setup", value=NOTE,
                             tags=[".env", "stuntkey run"]), "")
        self.assertEqual(pre("mcp__monomem__state_search", query="~/.stuntkey/ .env"), "")

    def test_a_stored_key_in_a_memory_note_is_refused(self):
        out = pre("mcp__monomem__state_write", key="k", value=f"token is {STORED}")
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertNotIn(STORED, out)

    def test_settings_file_writes_are_still_refused(self):
        out = pre("mcp__shell__exec", cmd="echo '{}' > ~/.claude/settings.json")
        self.assertIn("deny", out)

    def test_bash_keeps_every_rule(self):
        self.assertIn("deny", pre("Bash", command="cat .env"))
        self.assertIn("deny", pre("Bash", command="stuntkey run github -- env"))


class McpResultsAreMasked(unittest.TestCase):
    def setUp(self):
        scrub.remember_key("svc/KEY", STORED)
        self.addCleanup(scrub.forget_key, "svc/KEY")

    def post(self, response) -> str:
        status, out = hook_mod.check(json.dumps({
            "hook_event_name": "PostToolUse", "tool_name": "mcp__monomem__state_search",
            "tool_input": {"query": "deploy"}, "tool_response": response}))
        self.assertEqual(status, 0)
        return out

    def test_recall_result_with_a_stored_key_is_masked_in_its_own_shape(self):
        recall = [{"type": "text", "text": json.dumps(
            {"results": [{"key": "deploy", "value": f"use {STORED} for prod", "score": 0.9}]})}]
        out = self.post(recall)
        self.assertNotIn(STORED, out)
        spec = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(spec["hookEventName"], "PostToolUse")
        for field in ("updatedToolOutput", "updatedMCPToolOutput"):
            got = spec[field]
            self.assertEqual(got[0]["type"], "text")
            inner = json.loads(got[0]["text"])["results"][0]
            self.assertEqual(inner["score"], 0.9)
            self.assertIn("[REDACTED]", inner["value"])

    def test_a_plain_string_result_is_masked_and_a_clean_one_left_alone(self):
        self.assertNotIn(STORED, self.post(f"note: {STORED}"))
        self.assertEqual(self.post([{"type": "text", "text": "nothing secret"}]), "")

    def test_the_installed_post_matcher_covers_mcp_tools(self):
        self.assertEqual(hook_mod.post_entry({"type": "command"})["matcher"], "Bash|mcp__.*")


class WrapUndoTouchesOnlyTheEntry(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()
        self.root = _isolation.mktemp()
        self.kc = FakeKeychain()

    def run_wrap(self, **kw):
        out = io.StringIO()
        code = mcpwrap.cmd_wrap(args(**kw), recipes_mod.load_recipes(), out=out,
                                ask=lambda _p: "y", keychain=self.kc,
                                home=self.home, root=self.root)
        return code, out.getvalue()

    def test_undo_keeps_later_servers_and_other_keys(self):
        gh = {"command": "npx", "args": ["-y", "server-github"],
              "env": {"GITHUB_TOKEN": GITHUB}}
        path = write(os.path.join(self.home, ".claude.json"), json.dumps(
            {"numStartups": 1, "mcpServers": {"gh": gh}}, indent=2))
        code, out = self.run_wrap(client="claude-code", server="gh")
        self.assertEqual(code, 0, out)
        later = json.loads(read(path))
        later["numStartups"] = 7
        later["mcpServers"]["monomem"] = {"command": "monomem", "args": ["serve"]}
        later["projects"] = {"/x": {"allowedTools": []}}
        write(path, json.dumps(later, indent=2))
        code, out = self.run_wrap(client="claude-code", undo=True)
        self.assertEqual(code, 0, out)
        self.assertNotIn(GITHUB, out)
        now = json.loads(read(path))
        self.assertEqual(now["mcpServers"]["gh"], gh)
        self.assertEqual(now["mcpServers"]["monomem"], {"command": "monomem", "args": ["serve"]})
        self.assertEqual(now["numStartups"], 7)
        self.assertEqual(now["projects"], {"/x": {"allowedTools": []}})

    @unittest.skipIf(sys.version_info < (3, 11), "TOML needs tomllib")
    def test_toml_changed_elsewhere_is_refused_not_clobbered(self):
        path = write(os.path.join(self.home, ".codex", "config.toml"),
                     '[mcp_servers.brave]\ncommand = "npx"\nargs = ["brave"]\n\n'
                     f'[mcp_servers.brave.env]\nBRAVE_API_KEY = "{GENERIC}"\nKEEP = "1"\n')
        code, out = self.run_wrap(client="codex", server="brave")
        self.assertEqual(code, 0, out)
        changed = read(path) + '\n[mcp_servers.later]\ncommand = "l"\n'
        write(path, changed)
        code, out = self.run_wrap(client="codex", undo=True)
        self.assertEqual(code, 1, out)
        self.assertIn("Not restored", out)
        self.assertEqual(read(path), changed)


if __name__ == "__main__":
    unittest.main()
