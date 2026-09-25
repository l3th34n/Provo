import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from enforcement_policy import decide_enforcement


class EnforcementPolicyTests(unittest.TestCase):
    def test_all_current_verdicts_have_explicit_actions(self):
        expected = {
            "HARDENED_VALID": "ALLOW",
            "VALID_WITH_GAPS": "ALLOW_WITH_WARNING",
            "UNTRUSTED_SIGNER": "QUARANTINE",
            "NO_PROVENANCE": "QUARANTINE",
            "TAMPERED": "BLOCK",
            "REVOKED_SIGNER": "BLOCK",
            "TIMESTAMP_INVALID": "BLOCK",
            "CREDENTIAL_INVALID": "BLOCK",
            "POLICY_VIOLATION": "BLOCK",
            "INSPECTION_ERROR": "BLOCK",
        }

        for verdict, action in expected.items():
            with self.subTest(verdict=verdict):
                decision = decide_enforcement({"verdict": verdict})
                self.assertEqual(decision["action"], action)
                self.assertEqual(decision["evaluated_verdict"], verdict)
                self.assertTrue(decision["reason_codes"])
                self.assertTrue(decision["remediation"])

    def test_unknown_verdict_fails_closed(self):
        decision = decide_enforcement({"verdict": "FUTURE_STATE"})
        self.assertEqual(decision["action"], "BLOCK")
        self.assertEqual(decision["reason_codes"], ["UNKNOWN_VERDICT_FAILED_CLOSED"])

    def test_malformed_input_fails_closed(self):
        decision = decide_enforcement(None)
        self.assertEqual(decision["action"], "BLOCK")
        self.assertEqual(decision["evaluated_verdict"], "MISSING_VERDICT")


if __name__ == "__main__":
    unittest.main()
