"""Focused EXIF consistency tests; these do not require the native C2PA SDK."""
import sys
import tempfile
import unittest
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from exif_checker import compare_exif  # noqa: E402


def active_assertion(fields, label="c2pa.metadata"):
    return {
        "active_manifest": "signed-1",
        "manifests": {
            "signed-1": {"assertions": [{"label": label, "data": fields}]},
            "unrelated": {"assertions": [{"label": label, "data": {"tiff:Make": "Wrong"}}]},
        },
    }


class ExifConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.image_path = Path(self.temp.name) / "sample.jpg"
        image = Image.new("RGB", (2, 2))
        exif = image.getexif()
        exif[271] = "Canon"
        exif[272] = "EOS R5"
        exif[36867] = "2026:09:25 10:31:07"
        exif[305] = "Photoshop"
        image.save(self.image_path, exif=exif)

    def test_matching_active_metadata(self):
        result = compare_exif(self.image_path, active_assertion({
            "tiff:Make": "canon", "tiff:Model": "EOS R5",
            "exif:DateTimeOriginal": "2026-09-25T10:31:07", "tiff:Software": "Photoshop",
        }))
        self.assertEqual(result["status"], "match")
        self.assertEqual(sum(row["status"] == "match" for row in result["comparisons"]), 4)
        self.assertNotIn("GPS", str(result))

    def test_camera_discrepancy_not_verdict(self):
        result = compare_exif(self.image_path, active_assertion({"tiff:Make": "Nikon"}, "stds.exif"))
        self.assertEqual(result["status"], "mismatch")
        self.assertFalse(any(key in result for key in ("hardened_verdict", "authentic", "tampered")))

    def test_timezone_mismatch_is_not_evidence_of_tampering(self):
        result = compare_exif(self.image_path, active_assertion({"exif:DateTimeOriginal": "2026-09-25T10:31:07Z"}))
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["comparisons"][2]["status"], "inconclusive")

    def test_metadata_in_detailed_store(self):
        detailed = {"active_manifest": "signed-1", "manifests": {"signed-1": {
            "assertion_store": {"stds.exif": {"data": {"tiff:Make": "Canon"}}}
        }}}
        result = compare_exif(self.image_path, active_assertion({}), detailed)
        self.assertEqual(result["status"], "match")
        self.assertIn("stds.exif", result["assertion_labels"])

    def test_missing_manifest_is_neutral(self):
        result = compare_exif(self.image_path)
        self.assertEqual(result["status"], "no_c2pa_metadata")
        self.assertFalse(result["checked"])

    def test_no_exif(self):
        plain = Path(self.temp.name) / "plain.png"
        Image.new("RGB", (1, 1)).save(plain)
        self.assertEqual(compare_exif(plain)["status"], "no_exif")

    def test_different_timezone_representations_match_when_offsets_available(self):
        from exif_checker import _compare
        state, _ = _compare("capture_time", "2026:09:25 10:31:07", "2026-09-25T05:01:07Z", "+05:30", None)
        self.assertEqual(state, "match")

    def test_distinct_capture_and_signing_times_are_not_compared(self):
        sample = active_assertion({"tiff:Make": "Canon"})
        sample["manifests"]["signed-1"]["signature_info"] = {"time": "2030-01-01T00:00:00Z"}
        result = compare_exif(self.image_path, sample)
        self.assertEqual(result["status"], "match")
        self.assertEqual(result["comparisons"][2]["status"], "unavailable")

    def test_video_not_applicable(self):
        self.assertEqual(compare_exif("clip.mp4")["status"], "not_applicable")

    def test_active_manifest_only(self):
        r = compare_exif(self.image_path, active_assertion({"tiff:Make": "Canon"}))
        self.assertEqual(r["status"], "match")
        self.assertEqual(r["c2pa"]["camera_make"], "Canon")


if __name__ == "__main__":
    unittest.main()
