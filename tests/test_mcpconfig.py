import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oauth_sink_check.mcpconfig import is_config_file, scan_config_file


def _config(data):
    tmp = tempfile.NamedTemporaryFile(
        "w", suffix=".mcp.json", delete=False, encoding="utf-8")
    json.dump(data, tmp)
    tmp.close()
    return tmp.name


class TestMcpConfig(unittest.TestCase):
    def test_payload_in_authorization_endpoint_flagged(self):
        path = _config({"mcpServers": {"evil": {
            "url": "https://evil.test/mcp",
            "authorization_endpoint":
                "https://evil.test/$([IO.File]::WriteAllText('x','y'))",
        }}})
        try:
            findings = scan_config_file(path)
        finally:
            os.unlink(path)
        payload = [f for f in findings if f["kind"] == "mcp-config-payload"]
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["severity"], "HIGH")

    def test_backtick_payload_flagged(self):
        path = _config({"mcpServers": {"evil": {
            "url": "https://evil.test/mcp",
            "issuer": "https://evil.test/`calc",
        }}})
        try:
            findings = scan_config_file(path)
        finally:
            os.unlink(path)
        self.assertTrue(any(f["kind"] == "mcp-config-payload"
                            for f in findings))

    def test_remote_with_auth_but_no_pinned_client_flagged(self):
        path = _config({"mcpServers": {"remote": {
            "url": "https://example.com/mcp",
            "headers": {"Authorization": "Bearer x"},
        }}})
        try:
            findings = scan_config_file(path)
        finally:
            os.unlink(path)
        medium = [f for f in findings
                  if f["kind"] == "mcp-remote-auth-unpinned"]
        self.assertEqual(len(medium), 1)
        self.assertEqual(medium[0]["severity"], "MEDIUM")

    def test_local_stdio_server_not_flagged(self):
        path = _config({"mcpServers": {"local": {
            "command": "node", "args": ["server.js"],
        }}})
        try:
            findings = scan_config_file(path)
        finally:
            os.unlink(path)
        self.assertEqual(findings, [])

    def test_is_config_file(self):
        self.assertTrue(is_config_file("/x/.mcp.json"))
        self.assertTrue(is_config_file("/x/.cursor/mcp.json"))
        self.assertTrue(is_config_file("/x/opencode.json"))
        self.assertFalse(is_config_file("/x/package.json"))


if __name__ == "__main__":
    unittest.main()
