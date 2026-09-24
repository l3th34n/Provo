import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from timestamp_checker import check_timestamp_security


class TimestampCheckerTests(unittest.TestCase):
    def test_accepts_timestamp_only_when_validated_and_trusted(self):
        results = {
            "activeManifest": {
                "success": [
                    {"code": "timeStamp.validated"},
                    {"code": "timeStamp.trusted"},
                ]
            }
        }

        result = check_timestamp_security({"time": "2025-10-23T21:14:47Z"}, results)

        self.assertEqual(result["status"], "valid")
        self.assertTrue(result["trusted"])

    def test_rejects_mismatched_timestamp(self):
        results = {
            "activeManifest": {
                "informational": [{"code": "timeStamp.mismatch"}]
            }
        }

        result = check_timestamp_security({}, results)

        self.assertEqual(result["status"], "invalid")
        self.assertFalse(result["trusted"])

    def test_claimed_time_without_timestamp_evidence_is_unknown(self):
        result = check_timestamp_security(
            {"time": "2025-10-23T21:14:47Z"},
            {"activeManifest": {"success": [{"code": "claimSignature.validated"}]}},
        )

        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["checked"])
        self.assertEqual(result["claimed_time"], "2025-10-23T21:14:47Z")

    def test_does_not_use_an_ingredient_timestamp_for_active_manifest(self):
        results = {
            "activeManifest": {
                "success": [{"code": "claimSignature.validated"}]
            },
            "ingredientDeltas": [
                {
                    "validationDeltas": {
                        "success": [
                            {"code": "timeStamp.validated"},
                            {"code": "timeStamp.trusted"},
                        ]
                    }
                }
            ],
        }

        result = check_timestamp_security({}, results)

        self.assertEqual(result["status"], "unknown")

    def test_partial_success_is_incomplete(self):
        results = {
            "activeManifest": {
                "success": [{"code": "timeStamp.validated"}]
            }
        }

        result = check_timestamp_security({}, results)

        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["trusted"])


if __name__ == "__main__":
    unittest.main()
