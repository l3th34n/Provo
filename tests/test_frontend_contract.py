import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
MAIN = (ROOT / "backend" / "main.py").read_text(encoding="utf-8")


class FrontendBackendContractTests(unittest.TestCase):
    def test_frontend_assets_are_served_by_fastapi(self):
        self.assertIn('href="/frontend/style.css"', HTML)
        self.assertIn('app.mount("/frontend"', MAIN)

    def test_every_backend_verdict_has_a_frontend_presentation(self):
        verdicts = {
            "HARDENED_VALID",
            "VALID_WITH_GAPS",
            "UNTRUSTED_SIGNER",
            "TAMPERED",
            "REVOKED_SIGNER",
            "TIMESTAMP_INVALID",
            "CREDENTIAL_INVALID",
            "POLICY_VIOLATION",
            "NO_PROVENANCE",
            "INSPECTION_ERROR",
        }
        presentation = re.search(
            r"const verdictPresentation = \{(.*?)\n            \};",
            HTML,
            re.DOTALL,
        )
        self.assertIsNotNone(presentation)
        for verdict in verdicts:
            self.assertRegex(presentation.group(1), rf"\b{verdict}:\s*\{{")

    def test_only_hardened_valid_uses_the_safe_badge(self):
        presentation = re.search(
            r"const verdictPresentation = \{(.*?)\n            \};",
            HTML,
            re.DOTALL,
        ).group(1)
        safe_uses = re.findall(
            r"([A-Z_]+):\s*\{(?:(?!\n\s*[A-Z_]+:\s*\{).)*?badgeClass:\s*\"badge-pass\"",
            presentation,
            re.DOTALL,
        )
        self.assertEqual(safe_uses, ["HARDENED_VALID"])

    def test_missing_backend_verdict_fails_closed(self):
        self.assertIn('"VALID_WITH_GAPS"', HTML)
        self.assertIn("Missing backend verdicts deliberately fail closed", HTML)

    def test_future_features_are_not_enabled_controls(self):
        roadmap_control = re.search(
            r'<input type="checkbox" id="toggleInjection"([^>]*)>', HTML
        )
        self.assertIsNotNone(roadmap_control)
        self.assertIn("disabled", roadmap_control.group(1))
        self.assertNotIn("checked", roadmap_control.group(1))


if __name__ == "__main__":
    unittest.main()
