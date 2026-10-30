import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oauth_sink_check.taint import analyse_file, find_chains


class TestTaint(unittest.TestCase):
    def test_js_template_literal_chain_is_critical(self):
        code = (
            "const { exec } = require('child_process');\n"
            "async function signIn(server) {\n"
            "  const authUrl = server.authorization_endpoint;\n"
            "  const cmd = `powershell -Command \"${authUrl}\"`;\n"
            "  exec(cmd);\n"
            "}\n"
        )
        findings = find_chains(code, "js", "client.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertIn("authorization_endpoint", findings[0].chain)

    def test_python_fstring_chain_is_critical(self):
        code = (
            "import os\n"
            "def sign_in(discovery):\n"
            "    auth_url = discovery['token_endpoint']\n"
            "    os.system(f'powershell -Command \"{auth_url}\"')\n"
        )
        findings = find_chains(code, "python", "client.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_concatenation_chain(self):
        code = (
            "const open = require('open');\n"
            "const url = discovery.issuer + '/authorize';\n"
            "open(url);\n"
        )
        findings = find_chains(code, "js", "a.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_format_and_percent_chains(self):
        js = ("const open = require('open');\n"
              "const u = discovery.authorization_endpoint;\n"
              "const cmd = 'open {}'.format(u);\n"
              "open(cmd);\n")
        # JS .format is not idiomatic, but identifier tracking covers it.
        self.assertEqual(len(find_chains(js, "js", "a.js")), 1)
        py = ("import os\n"
              "u = data['authorization_endpoint']\n"
              "os.system('x %s' % u)\n")
        self.assertEqual(len(find_chains(py, "python", "a.py")), 1)

    def test_sanitised_case_not_flagged(self):
        code = (
            "const open = require('open');\n"
            "const authUrl = server.authorization_endpoint;\n"
            "const safe = encodeURIComponent(authUrl);\n"
            "open(safe);\n"
        )
        self.assertEqual(find_chains(code, "js", "a.js"), [])

    def test_allowlisted_and_encoded_case_not_flagged(self):
        code = (
            "const open = require('open');\n"
            "const authUrl = server.authorization_endpoint;\n"
            "if (!authUrl.startsWith('https://')) throw new Error('no');\n"
            "const safeUrl = encodeURIComponent(authUrl);\n"
            "open(safeUrl);\n"
        )
        self.assertEqual(find_chains(code, "js", "a.js"), [])

    def test_untainted_literal_not_flagged(self):
        code = ("const open = require('open');\n"
                "open('https://example.com/callback');\n")
        self.assertEqual(find_chains(code, "js", "a.js"), [])

    def test_single_quoted_sink_is_medium_not_critical(self):
        # The tainted value is wrapped in single quotes inside the
        # template literal, which neutralises $(...) in PowerShell.
        code = (
            "const { exec } = require('child_process');\n"
            "const u = server.authorization_endpoint;\n"
            "exec(`powershell '${u}'`);\n"
        )
        findings = find_chains(code, "js", "a.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_webbrowser_open_is_medium_not_shell(self):
        code = ("import webbrowser\n"
                "u = data['authorization_endpoint']\n"
                "webbrowser.open(u)\n")
        findings = find_chains(code, "python", "a.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertEqual(findings[0].kind, "tainted-browser-open")

    def test_passthrough_function_propagates_taint(self):
        code = (
            "const open = require('open');\n"
            "function ident(x) { return x; }\n"
            "const u = server.authorization_endpoint;\n"
            "open(ident(u));\n"
        )
        findings = find_chains(code, "js", "a.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_analyse_file_tracks_source_field(self):
        result = analyse_file(
            "const u = server.token_endpoint;\nconst v = u + '/x';\n")
        self.assertIn("u", result.tainted)
        self.assertIn("v", result.tainted)
        self.assertEqual(result.tainted["u"].field, "token_endpoint")


if __name__ == "__main__":
    unittest.main()
