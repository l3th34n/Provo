import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from trust_score import calculate_provenance_trust_score


def complete_result():
    return {
        "manifest_found": True,
        "validation_state": "Valid",
        "validation_results": {"activeManifest": {"success": [
            {"code": "claimSignature.validated"},
            {"code": "signingCredential.trusted"},
        ]}},
        "certificate_revocation": {"status": "not_revoked"},
        "timestamp_security": {"status": "valid"},
        "pipeline_audit": {
            "status": "no_flags", "checked": True,
            "coverage": {
                "sdk_signals": "checked", "ingredient_graph": "checked",
                "jpeg_exclusion_coverage": "checked",
            },
        },
    }


class ProvenanceTrustScoreTests(unittest.TestCase):
    def test_complete_hardened_evidence_scores_100(self):
        score = calculate_provenance_trust_score(complete_result(), {"verdict": "HARDENED_VALID"})
        self.assertEqual(score["score"], 100)
        self.assertEqual(score["rating"], "STRONG")
        self.assertTrue(all(item["passed"] for item in score["criteria"]))

    def test_every_point_is_disclosed_by_criteria(self):
        result = complete_result()
        result["timestamp_security"]["status"] = "unknown"
        score = calculate_provenance_trust_score(result, {"verdict": "VALID_WITH_GAPS"})
        self.assertEqual(score["score"], 90)
        self.assertEqual(sum(item["earned"] for item in score["criteria"]), score["raw_score"])

    def test_tamper_verdict_caps_otherwise_positive_evidence(self):
        score = calculate_provenance_trust_score(complete_result(), {"verdict": "TAMPERED"})
        self.assertEqual(score["raw_score"], 100)
        self.assertEqual(score["score"], 10)
        self.assertEqual(score["adjustments"][0]["maximum"], 10)

    def test_no_manifest_scores_zero_without_calling_it_fake(self):
        score = calculate_provenance_trust_score(
            {"manifest_found": False}, {"verdict": "NO_PROVENANCE"}
        )
        self.assertEqual(score["score"], 0)
        self.assertIn("not an AI-generation probability", score["scope_note"])

    def test_ingredient_success_does_not_score_as_active_manifest_evidence(self):
        result = complete_result()
        result["validation_results"]["activeManifest"]["success"] = []
        result["validation_results"]["ingredientDeltas"] = [{
            "validationDeltas": {"success": [
                {"code": "claimSignature.validated"},
                {"code": "signingCredential.trusted"},
            ]}
        }]
        score = calculate_provenance_trust_score(result, {"verdict": "VALID_WITH_GAPS"})
        criteria = {item["id"]: item for item in score["criteria"]}
        self.assertFalse(criteria["claim_signature"]["passed"])
        self.assertFalse(criteria["signer_trust"]["passed"])


if __name__ == "__main__":
    unittest.main()
