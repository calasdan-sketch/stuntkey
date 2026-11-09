"""False alarms found scanning a real home folder: MCP tool names in a
settings allow-list, and AWS's documented sample key pair."""
import unittest

import _isolation  # noqa: F401
from stuntkey import scan


class NotKeys(unittest.TestCase):

    def test_aws_doc_keys_are_placeholders(self):
        self.assertTrue(scan.is_placeholder("AKIA" "IOSFODNN7EXAMPLE"))
        self.assertTrue(scan.is_placeholder("wJalrXUtnFEMI/K7MDENG/bPxRfiCY" "EXAMPLEKEY"))

    def test_mcp_tool_names_are_not_bare_tokens(self):
        for name in ("mcp__plugin_figma_figma__get_screenshot", "mcp__claude-in-chrome__read_page"):
            self.assertTrue(scan.MCP_TOOL_RE.match(name))

    def test_a_real_looking_bare_token_still_matches(self):
        self.assertFalse(scan.MCP_TOOL_RE.match("ghx9Qa7LmP2vR8sT4wK1zY6bN3cD5eF0"))


if __name__ == "__main__":
    unittest.main()
