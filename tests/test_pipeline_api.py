"""Integration tests: run with the project's runtime dependencies installed."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
HAS_RUNTIME = all(importlib.util.find_spec(name) for name in ("c2pa", "fastapi", "httpx", "python_multipart"))


@unittest.skipUnless(HAS_RUNTIME, "Install runtime dependencies and httpx for API integration tests")
class PipelineApiTests(unittest.TestCase):
    def test_real_signed_jpeg_returns_audit_and_preserves_trust_failure(self):
        from fastapi.testclient import TestClient
        import main
        with tempfile.TemporaryDirectory() as directory, patch.object(main, "UPLOAD_DIR", Path(directory)):
            client = TestClient(main.app)
            with (ROOT / "tests/samples/original_signed.jpg").open("rb") as source:
                response = client.post("/api/upload", files={"file": ("signed.jpg", source, "image/jpeg")})
            self.assertEqual(response.status_code, 200)
            result = response.json()["c2pa"]
            self.assertEqual(result["pipeline_audit"]["coverage"]["jpeg_exclusion_coverage"], "checked")
            self.assertGreater(result["pipeline_audit"]["statistics"]["excluded_bytes"], 0)
            self.assertFalse(result["hardened_verdict"]["hardened_valid"])
            enforcement = result["hardened_verdict"]["enforcement_decision"]
            self.assertIn(enforcement["action"], {"ALLOW_WITH_WARNING", "QUARANTINE", "BLOCK"})
            self.assertTrue(enforcement["reason_codes"])
            score = result["provenance_trust_score"]
            self.assertGreaterEqual(score["score"], 0)
            self.assertLessEqual(score["score"], 100)
            self.assertEqual(sum(item["earned"] for item in score["criteria"]), score["raw_score"])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_css_and_homepage_are_served_by_the_same_app(self):
        from fastapi.testclient import TestClient
        import main
        client = TestClient(main.app)
        self.assertEqual(client.get("/").status_code, 200)
        css = client.get("/style.css")
        self.assertEqual(css.status_code, 200)
        self.assertIn("text/css", css.headers["content-type"])

    def test_real_modified_and_unsigned_samples(self):
        from c2pa_checker import check_c2pa
        modified = check_c2pa(ROOT / "tests/samples/modified.jpg")
        unsigned = check_c2pa(ROOT / "tests/samples/ordinary.jpg")
        self.assertEqual(modified["hardened_verdict"]["verdict"], "TAMPERED")
        self.assertLessEqual(modified["provenance_trust_score"]["score"], 10)
        self.assertEqual(unsigned["hardened_verdict"]["verdict"], "NO_PROVENANCE")
        self.assertEqual(unsigned["provenance_trust_score"]["score"], 0)


if __name__ == "__main__":
    unittest.main()
