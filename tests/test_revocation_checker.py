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

    def test_supports_current_c2pa_ocsp_code(self):
        results = {
            "activeManifest": {
                "success": [
                    {"code": "signingCredential.ocsp.notRevoked"}
                ]
            }
        }

        result = check_certificate_revocation(results)

        self.assertEqual(result["status"], "not_revoked")

    def test_reports_why_ocsp_is_unknown(self):
        results = {
            "activeManifest": {
                "informational": [
                    {
                        "code": "signingCredential.ocsp.skipped",
                        "explanation": "OCSP fetching skipped",
                    }
                ]
            }
        }

        result = check_certificate_revocation(results)

        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["checked"])
        self.assertEqual(
            result["evidence"][0]["code"],
            "signingCredential.ocsp.skipped",
        )

    def test_does_not_use_ingredient_revocation_for_active_manifest(self):
        results = {
            "activeManifest": {
                "success": [{"code": "claimSignature.validated"}]
            },
            "ingredientDeltas": [
                {
                    "validationDeltas": {
                        "success": [
                            {"code": "signingCredential.ocsp.notRevoked"}
                        ]
                    }
                }
            ],
        }

        aggregated_status = [{"code": "signingCredential.revoked"}]
        result = check_certificate_revocation(results, aggregated_status)

        self.assertEqual(result["status"], "unknown")

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

    def test_inconclusive_evidence_wins_over_not_revoked(self):
        results = {
            "activeManifest": {
                "success": [{"code": "signingCredential.notRevoked"}],
                "informational": [
                    {"code": "signingCredential.ocsp.inaccessible"}
                ],
            }
        }

        result = check_certificate_revocation(results)

        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["checked"])


if __name__ == "__main__":
    unittest.main()
