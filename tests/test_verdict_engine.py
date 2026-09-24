import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from verdict_engine import evaluate_hardened_verdict


def c2pa_result(
    *,
    state="Valid",
    success=None,
    informational=None,
    failure=None,
    revocation="not_revoked",
    timestamp="valid",
):
    return {
        "status": "manifest_found",
        "manifest_found": True,
        "validation_state": state,
        "validation_results": {
            "activeManifest": {
                "success": success or [],
                "informational": informational or [],
                "failure": failure or [],
            }
        },
        "certificate_revocation": {
            "status": revocation,
            "message": "revocation result",
            "evidence": [],
        },
        "timestamp_security": {
            "status": timestamp,
            "message": "timestamp result",
            "evidence": [],
        },
        "pipeline_audit": {
            "status": "no_flags", "checked": True, "findings": [],
            "coverage": {"sdk_signals": "checked", "ingredient_graph": "checked", "jpeg_exclusion_coverage": "checked"},
        },
    }


class VerdictEngineTests(unittest.TestCase):
    def test_no_manifest(self):
        result = evaluate_hardened_verdict(
            {"status": "no_manifest", "manifest_found": False}
        )
        self.assertEqual(result["verdict"], "NO_PROVENANCE")

    def test_inspection_error(self):
        result = evaluate_hardened_verdict(
            {
                "status": "inspection_error",
                "manifest_found": None,
                "error": "bad manifest",
            }
        )
        self.assertEqual(result["verdict"], "INSPECTION_ERROR")

    def test_tamper_evidence_has_highest_precedence(self):
        result = evaluate_hardened_verdict(
            c2pa_result(
                failure=[{"code": "assertion.dataHash.mismatch"}],
                revocation="revoked",
            )
        )
        self.assertEqual(result["verdict"], "TAMPERED")

    def test_revoked_signer(self):
        result = evaluate_hardened_verdict(c2pa_result(revocation="revoked"))
        self.assertEqual(result["verdict"], "REVOKED_SIGNER")

    def test_invalid_timestamp(self):
        result = evaluate_hardened_verdict(c2pa_result(timestamp="invalid"))
        self.assertEqual(result["verdict"], "TIMESTAMP_INVALID")

    def test_invalid_credential(self):
        result = evaluate_hardened_verdict(
            c2pa_result(failure=[{"code": "signingCredential.invalid"}])
        )
        self.assertEqual(result["verdict"], "CREDENTIAL_INVALID")

    def test_other_failure_is_policy_violation(self):
        result = evaluate_hardened_verdict(
            c2pa_result(failure=[{"code": "manifest.update.invalid"}])
        )
        self.assertEqual(result["verdict"], "POLICY_VIOLATION")

    def test_untrusted_signer(self):
        result = evaluate_hardened_verdict(
            c2pa_result(failure=[{"code": "signingCredential.untrusted"}])
        )
        self.assertEqual(result["verdict"], "UNTRUSTED_SIGNER")

    def test_valid_with_inconclusive_revocation(self):
        result = evaluate_hardened_verdict(
            c2pa_result(
                success=[{"code": "signingCredential.trusted"}],
                revocation="unknown",
            )
        )
        self.assertEqual(result["verdict"], "VALID_WITH_GAPS")
        self.assertFalse(result["hardened_valid"])

    def test_hardened_valid_requires_all_positive_evidence(self):
        result = evaluate_hardened_verdict(
            c2pa_result(
                success=[
                    {"code": "claimSignature.validated"},
                    {"code": "signingCredential.trusted"},
                    {"code": "timeStamp.validated"},
                    {"code": "timeStamp.trusted"},
                ]
            )
        )
        self.assertEqual(result["verdict"], "HARDENED_VALID")
        self.assertTrue(result["hardened_valid"])

    def test_valid_state_without_positive_signature_evidence_has_gaps(self):
        result = evaluate_hardened_verdict(
            c2pa_result(success=[{"code": "signingCredential.trusted"}])
        )
        self.assertEqual(result["verdict"], "VALID_WITH_GAPS")
        self.assertFalse(result["hardened_valid"])

    def test_ingredient_failure_does_not_override_active_manifest(self):
        result_data = c2pa_result(
            success=[
                {"code": "claimSignature.validated"},
                {"code": "signingCredential.trusted"},
            ]
        )
        result_data["validation_results"]["ingredientDeltas"] = [
            {
                "validationDeltas": {
                    "failure": [{"code": "assertion.dataHash.mismatch"}]
                }
            }
        ]

        result = evaluate_hardened_verdict(result_data)
        self.assertEqual(result["verdict"], "HARDENED_VALID")


if __name__ == "__main__":
    unittest.main()
