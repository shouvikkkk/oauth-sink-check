import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oauth_sink_check.powershell import (
    PILLAR_PAYLOAD, contains_subexpression, decode_encoded_command, simulate)

BENIGN = "https://example.com/oauth/authorize?client_id=abc"


class TestPowerShellModel(unittest.TestCase):
    def test_double_quoted_subexpression_survives(self):
        result = simulate(PILLAR_PAYLOAD, "double")
        self.assertTrue(result["survives"])
        self.assertTrue(contains_subexpression(PILLAR_PAYLOAD))

    def test_single_quoted_subexpression_does_not_survive(self):
        # Note: the full Pillar payload also contains literal single
        # quotes, which WOULD break out of a single-quoted string --
        # so this case uses a quote-free subexpression payload.
        result = simulate("https://evil.test/$(whoami)", "single")
        self.assertFalse(result["survives"])

    def test_single_quote_breakout_survives(self):
        result = simulate("https://x.test/a'b", "single")
        self.assertTrue(result["survives"])

    def test_encoded_command_decodes_and_rechecks(self):
        blob = base64.b64encode(PILLAR_PAYLOAD.encode("utf-16-le")).decode()
        result = simulate(blob, "encoded")
        self.assertTrue(result["survives"])
        self.assertEqual(result["decoded"], PILLAR_PAYLOAD)

    def test_encoded_benign_command_does_not_survive(self):
        blob = base64.b64encode("Write-Host hello".encode("utf-16-le")).decode()
        result = simulate(blob, "encoded")
        self.assertFalse(result["survives"])

    def test_encoded_invalid_base64_is_not_a_finding(self):
        result = simulate("not-base64!!!", "encoded")
        self.assertFalse(result["survives"])

    def test_benign_url_passes_in_every_quoting(self):
        for quoting in ("double", "single", "unquoted"):
            self.assertFalse(simulate(BENIGN, quoting)["survives"],
                             quoting)

    def test_double_quote_breakout_survives(self):
        result = simulate('https://x.test/a"b', "double")
        self.assertTrue(result["survives"])

    def test_backtick_escape_survives_in_double_quotes(self):
        result = simulate("https://x.test/`$evil", "double")
        self.assertTrue(result["survives"])

    def test_unknown_quoting_raises(self):
        with self.assertRaises(ValueError):
            simulate(BENIGN, "weird")


if __name__ == "__main__":
    unittest.main()
