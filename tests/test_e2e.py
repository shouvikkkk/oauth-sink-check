import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oauth_sink_check.cli import main, scan_path
from oauth_sink_check.report import exit_code_for

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestEndToEnd(unittest.TestCase):
    def test_vulnerable_example_exits_2_with_critical(self):
        path = os.path.join(ROOT, "examples", "vulnerable")
        findings = scan_path(path)
        self.assertEqual(exit_code_for(findings), 2)
        self.assertTrue(any(f.severity == "CRITICAL" for f in findings))
        critical = [f for f in findings if f.severity == "CRITICAL"][0]
        self.assertIn("authorization_endpoint", critical.chain)
        self.assertEqual(main(["scan", path]), 2)

    def test_clean_example_exits_0(self):
        path = os.path.join(ROOT, "examples", "clean")
        findings = scan_path(path)
        self.assertEqual(findings, [])
        self.assertEqual(exit_code_for(findings), 0)
        self.assertEqual(main(["scan", path]), 0)

    def test_missing_path_exits_3(self):
        self.assertEqual(main(["scan", "/definitely/not/a/real/path"]), 3)

    def test_json_format_exits_2(self):
        path = os.path.join(ROOT, "examples", "vulnerable")
        self.assertEqual(main(["scan", path, "--format", "json"]), 2)


if __name__ == "__main__":
    unittest.main()
