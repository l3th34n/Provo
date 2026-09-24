import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from revocation_checker import check_certificate_revocation


class RevocationCheckerTests(unittest.TestCase):
    def test_reports_revoked_from_active_manifest_failure(self):
        results = {
            "activeManifest": {
                "failure": [
                    {
                        "code": "signingCredential.revoked",
                        "url": "self#jumbf=/c2pa/example/c2pa.signature",
                        "explanation": "certificate revoked",
                    }
                ]
            }
        }

        result = check_certificate_revocation(results)

        self.assertEqual(result["status"], "revoked")
        self.assertTrue(result["checked"])

    def test_reports_not_revoked_from_success(self):
        results = {
            "activeManifest": {
                "success": [
                    {"code": "signingCredential.notRevoked"}
                ]
            }
        }

        result = check_certificate_revocation(results)

        self.assertEqual(result["status"], "not_revoked")
        self.assertTrue(result["checked"])

    def test_missing_revocation_evidence_is_unknown(self):
        results = {
            "activeManifest": {
                "success": [{"code": "claimSignature.validated"}]
            }
        }

        result = check_certificate_revocation(results)

        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["checked"])

    def test_revoked_wins_over_conflicting_evidence(self):
        results = [
            {"code": "signingCredential.notRevoked"},
            {"code": "signingCredential.revoked"},
        ]

        result = check_certificate_revocation(results)

        self.assertEqual(result["status"], "revoked")


if __name__ == "__main__":
    unittest.main()
