import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oauth_sink_check.lockfiles import (
    classify_open, range_allows_below, range_allows_vulnerable_open,
    satisfies_range, scan_project)


def _project(files):
    tmp = tempfile.TemporaryDirectory()
    for name, content in files.items():
        path = os.path.join(tmp.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True) \
            if os.path.dirname(name) else None
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
    return tmp


def _lock(version):
    return json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "x", "version": "1.0.0"},
        "node_modules/open": {"version": version}}})


class TestRanges(unittest.TestCase):
    def test_caret_10_is_vulnerable(self):
        self.assertTrue(range_allows_vulnerable_open("^10.1.0"))

    def test_exact_11_is_clean(self):
        self.assertFalse(range_allows_vulnerable_open("11.0.4"))

    def test_caret_11_is_clean(self):
        self.assertFalse(range_allows_vulnerable_open("^11.0.0"))

    def test_tilde_10_is_vulnerable(self):
        self.assertTrue(range_allows_vulnerable_open("~10.2.0"))

    def test_bounded_range(self):
        self.assertTrue(range_allows_vulnerable_open(">=9.0.0 <11.0.0"))
        self.assertFalse(range_allows_vulnerable_open(">=11.0.0"))

    def test_satisfies(self):
        self.assertTrue(satisfies_range("10.2.0", "^10.1.0"))
        self.assertFalse(satisfies_range("11.0.0", "^10.1.0"))
        self.assertTrue(satisfies_range("10.2.5", "~10.2.0"))
        self.assertFalse(satisfies_range("10.3.0", "~10.2.0"))

    def test_classify_open(self):
        self.assertEqual(classify_open("10.2.0"), "vulnerable")
        self.assertEqual(classify_open("11.0.4"), "clean")
        self.assertEqual(classify_open("7.1.9"), "legacy_unknown")
        self.assertEqual(classify_open("7.2.0"), "vulnerable")

    def test_range_allows_below_threshold(self):
        self.assertTrue(range_allows_below("^1.0.0", (1, 18, 33)))
        self.assertFalse(range_allows_below("^2.0.0", (1, 18, 33)))


class TestScanProject(unittest.TestCase):
    def test_caret_10_without_lockfile_is_vulnerable(self):
        tmp = _project({"package.json": json.dumps(
            {"dependencies": {"open": "^10.1.0"}})})
        try:
            results = scan_project(tmp.name)
        finally:
            tmp.cleanup()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "vulnerable")

    def test_lockfile_10_2_0_is_vulnerable(self):
        tmp = _project({"package.json": json.dumps(
            {"dependencies": {"open": "^10.0.0"}}),
            "package-lock.json": _lock("10.2.0")})
        try:
            results = scan_project(tmp.name)
        finally:
            tmp.cleanup()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["resolved"], "10.2.0")

    def test_lockfile_11_0_4_is_clean(self):
        tmp = _project({"package.json": json.dumps(
            {"dependencies": {"open": "11.0.4"}}),
            "package-lock.json": _lock("11.0.4")})
        try:
            results = scan_project(tmp.name)
        finally:
            tmp.cleanup()
        self.assertEqual(results, [])

    def test_missing_lockfile_with_clean_range_is_clean(self):
        tmp = _project({"package.json": json.dumps(
            {"dependencies": {"open": "11.0.4"}})})
        try:
            results = scan_project(tmp.name)
        finally:
            tmp.cleanup()
        self.assertEqual(results, [])

    def test_missing_lockfile_is_handled_not_an_error(self):
        tmp = _project({"package.json": json.dumps({"name": "plain"})})
        try:
            results = scan_project(tmp.name)
        finally:
            tmp.cleanup()
        self.assertEqual(results, [])

    def test_affected_consumers(self):
        tmp = _project({"package.json": json.dumps(
            {"dependencies": {
                "opencode": "^1.10.0",
                "@modelcontextprotocol/inspector": "^2.0.0"}})})
        try:
            results = scan_project(tmp.name)
        finally:
            tmp.cleanup()
        self.assertEqual(
            sorted(r["package"] for r in results),
            ["@modelcontextprotocol/inspector", "opencode"])
        self.assertTrue(all(r["status"] == "affected" for r in results))

    def test_yarn_lock_best_effort(self):
        tmp = _project({"package.json": json.dumps(
            {"dependencies": {"open": "^10.0.0"}}),
            "yarn.lock": '"open@^10.0.0":\n  version "10.1.2"\n'})
        try:
            results = scan_project(tmp.name)
        finally:
            tmp.cleanup()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["resolved"], "10.1.2")


if __name__ == "__main__":
    unittest.main()
