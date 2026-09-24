import sys
import unittest
import tempfile
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from pipeline_audit import audit_pipeline
from verdict_engine import evaluate_hardened_verdict
from jpeg_audit import jpeg_regions


def segment(marker, payload):
    return bytes([255, marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


# Structural JPEG fixture; entropy bytes are not intended for image decoding.
APP11 = segment(0xEB, b"JP\x00\x01\x00\x00\x00\x01" + b"fixture")
JPEG = b"\xff\xd8" + APP11 + segment(0xDA, b"\x01\x01\x00\x00\x3f\x00") + b"\x11\xff\x00\x22\xff\xd0\x33\xff\xd9"


def store(ingredients=None):
    return {"active_manifest": "root", "manifests": {
        "root": {"ingredients": ingredients or []}
    }}


def otherwise_valid_result(validation_results):
    return {
        "status": "manifest_found",
        "manifest_found": True,
        "validation_state": "Valid",
        "validation_results": validation_results,
        "certificate_revocation": {"status": "not_revoked"},
        "timestamp_security": {"status": "valid"},
        "pipeline_audit": audit_pipeline(validation_results),
    }


class PipelineAuditTests(unittest.TestCase):
    def audit_bytes(self, exclusions, *, content=JPEG, manifest_store=None, detailed_store=None):
        if detailed_store is None:
            detailed_store = {"active_manifest": "root", "manifests": {"root": {
                "assertion_store": {"c2pa.hash.data": {"exclusions": exclusions}}
            }}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.jpg"
            path.write_bytes(content)
            return audit_pipeline(
                {"activeManifest": {"success": [], "failure": [], "informational": []}},
                manifest_store=manifest_store or store(), detailed_store=detailed_store,
                file_path=path,
            )

    def test_complete_app11_envelope_has_no_byte_flags(self):
        result = self.audit_bytes([{"start": 2, "length": len(APP11)}])
        self.assertEqual(result["status"], "no_flags")
        self.assertEqual(result["statistics"]["excluded_bytes"], len(APP11))

    def test_excluded_scan_bytes_are_rejected(self):
        result = self.audit_bytes([{"start": len(JPEG) - 3, "length": 1}])
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["findings"][0]["code"], "provo.exclusion.renderingBytes")
        combined = otherwise_valid_result({"activeManifest": {"failure": []}})
        combined["pipeline_audit"] = result
        self.assertEqual(evaluate_hardened_verdict(combined)["verdict"], "POLICY_VIOLATION")

    def test_excluded_jpeg_tables_are_rejected(self):
        content = b"\xff\xd8" + segment(0xDB, b"tables") + b"\xff\xd9"
        self.assertEqual(self.audit_bytes([{"start": 2, "length": 10}], content=content)["status"], "invalid")

    def test_extra_metadata_exclusion_requires_review(self):
        metadata = segment(0xE1, b"Exif payload")
        content = b"\xff\xd8" + metadata + b"\xff\xd9"
        self.assertEqual(self.audit_bytes([{"start": 2, "length": len(metadata)}], content=content)["status"], "review_required")

    def test_partial_app11_is_not_silently_approved(self):
        self.assertEqual(self.audit_bytes([{"start": 3, "length": 4}])["status"], "review_required")

    def test_range_validation(self):
        for ranges in (
            [{"start": -1, "length": 1}],
            [{"start": 0, "length": len(JPEG) + 1}],
            [{"start": True, "length": 1}],
            [{"start": 0, "length": 0}],
            [{"start": 10, "length": 4}, {"start": 11, "length": 1}],
            [{"start": 10, "length": 1}, {"start": 2, "length": 1}],
        ):
            with self.subTest(ranges=ranges):
                self.assertEqual(self.audit_bytes(ranges)["status"], "invalid")

    def test_truncated_jpeg_does_not_pass(self):
        self.assertEqual(self.audit_bytes([], content=JPEG[:-2])["status"], "review_required")

    def test_stuffed_bytes_and_restart_markers_stay_in_scan(self):
        regions = jpeg_regions(JPEG)
        self.assertEqual(regions[-2][2], "rendering")
        self.assertEqual(regions[-2][1], len(JPEG) - 2)

    def test_other_bindings_are_explicitly_unsupported(self):
        detailed = {"active_manifest": "root", "manifests": {"root": {
            "assertion_store": {"c2pa.hash.boxes": {}}
        }}}
        result = self.audit_bytes([], detailed_store=detailed)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["coverage"]["jpeg_exclusion_coverage"], "unsupported_binding")

    def test_cycle_is_rejected(self):
        graph = store([{"relationship": "parentOf", "active_manifest": "root"}])
        result = self.audit_bytes([], manifest_store=graph)
        self.assertEqual(result["status"], "invalid")
        self.assertTrue(any(f["code"] == "provo.history.cycle" for f in result["findings"]))

    def test_missing_ingredient_is_review_not_tampered(self):
        graph = store([{"relationship": "parentOf", "active_manifest": "absent"}])
        self.assertEqual(self.audit_bytes([], manifest_store=graph)["status"], "review_required")

    def test_shared_ancestor_is_not_a_cycle(self):
        graph = store([{"active_manifest": "left"}, {"active_manifest": "right"}])
        graph["manifests"].update({
            "left": {"ingredients": [{"active_manifest": "ancestor"}]},
            "right": {"ingredients": [{"active_manifest": "ancestor"}]},
            "ancestor": {},
            "unrelated": {"ingredients": [{"active_manifest": "unrelated"}]},
        })
        result = self.audit_bytes([], manifest_store=graph)
        self.assertEqual(result["status"], "no_flags")
        self.assertEqual(result["statistics"]["manifests_visited"], 4)

    def test_input_to_does_not_require_provenance(self):
        graph = store([{"relationship": "inputTo"}])
        self.assertEqual(self.audit_bytes([], manifest_store=graph)["status"], "no_flags")

    def test_extra_exclusions_prevent_a_green_verdict(self):
        validation = {"activeManifest": {
            "success": [{"code": "claimSignature.validated"}, {"code": "signingCredential.trusted"}],
            "informational": [{"code": "assertion.dataHash.additionalExclusionsPresent"}],
            "failure": [],
        }}
        result = otherwise_valid_result(validation)
        self.assertEqual(result["pipeline_audit"]["status"], "review_required")
        self.assertEqual(evaluate_hardened_verdict(result)["verdict"], "VALID_WITH_GAPS")

    def test_sdk_only_coverage_cannot_produce_full_trust(self):
        validation = {"activeManifest": {
            "success": [{"code": "claimSignature.validated"}, {"code": "signingCredential.trusted"}],
            "informational": [], "failure": [],
        }}
        result = otherwise_valid_result(validation)
        self.assertEqual(evaluate_hardened_verdict(result)["verdict"], "VALID_WITH_GAPS")
        del result["pipeline_audit"]
        self.assertEqual(evaluate_hardened_verdict(result)["verdict"], "VALID_WITH_GAPS")

    def test_unknown_ingredient_is_a_gap_not_an_attack_label(self):
        result = audit_pipeline({"activeManifest": {
            "informational": [{"code": "ingredient.unknownProvenance"}],
        }})
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["findings"][0]["category"], "ingredient_provenance")

    def test_invalid_action_reference_is_reported(self):
        result = audit_pipeline({"activeManifest": {
            "failure": [{"code": "assertion.action.ingredientMismatch"}],
        }})
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["findings"][0]["level"], "invalid")

    def test_ingredient_only_result_does_not_contaminate_active_manifest(self):
        result = audit_pipeline({
            "activeManifest": {"success": [], "informational": [], "failure": []},
            "ingredientDeltas": [{"failure": [{"code": "assertion.action.ingredientMismatch"}]}],
        })
        self.assertEqual(result["status"], "no_flags")

    def test_missing_active_results_are_unknown(self):
        self.assertEqual(audit_pipeline({"ingredientDeltas": []})["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
