import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
APP = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
COMPARISON = (ROOT / "frontend" / "comparison.html").read_text(encoding="utf-8")
MAIN = (ROOT / "backend" / "main.py").read_text(encoding="utf-8")


class FrontendBackendContractTests(unittest.TestCase):
    def test_page_order_is_hero_upload_conditional_pill_then_telemetry(self):
        positions = [HTML.index(f'id="{name}"') for name in (
            "hero", "ingestion-panel", "uploadButton", "openComparisonPage", "auditSidebar"
        )]
        self.assertEqual(positions, sorted(positions))

    def test_presets_exist_only_on_dedicated_comparison_page(self):
        self.assertNotIn('id="intercept-matrix"', HTML)
        for name in ("revoked", "modified", "signed", "ordinary", "exclusion"):
            self.assertIn(f'data-eval="{name}"', COMPARISON)
            self.assertNotIn(f'data-eval="{name}"', HTML)

    def test_comparison_link_is_initially_hidden_and_uses_static_mount(self):
        self.assertRegex(HTML, r'id="openComparisonPage"[^>]*class="comparison-pill hidden"[^>]*href="/frontend/comparison.html"')
        self.assertIn('id="workbench"', COMPARISON)
        self.assertIn('class="workbench-layout hidden"', COMPARISON)
        self.assertIn('id="comparisonGate"', COMPARISON)

    def test_comparison_wording_does_not_claim_a_competing_validator(self):
        self.assertIn("C2PA Evidence Alone vs. PROVO", COMPARISON)
        self.assertNotIn("Standard Industry Reader", COMPARISON)
        self.assertIn("not proof that C2PA missed the underlying evidence", APP)

    def test_standalone_report_link_and_script_exist(self):
        self.assertRegex(HTML, r'id="openTelemetryPage"[^>]*target="_blank"[^>]*rel="noopener noreferrer"')
        self.assertIn('src="/frontend/telemetry.js"', HTML)
        self.assertTrue((ROOT / "frontend" / "telemetry.js").is_file())

    def test_frontend_assets_are_served_by_fastapi(self):
        self.assertIn('href="style.css"', HTML)
        self.assertIn("this.href = 'script.css'", HTML)
        self.assertIn('@app.get("/style.css"', MAIN)
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
            APP,
            re.DOTALL,
        )
        self.assertIsNotNone(presentation)
        for verdict in verdicts:
            self.assertRegex(presentation.group(1), rf"\b{verdict}:\s*\{{")

    def test_only_hardened_valid_uses_the_safe_badge(self):
        presentation = re.search(
            r"const verdictPresentation = \{(.*?)\n            \};",
            APP,
            re.DOTALL,
        ).group(1)
        safe_uses = re.findall(
            r"([A-Z_]+):\s*\{(?:(?!\n\s*[A-Z_]+:\s*\{).)*?badgeClass:\s*\"badge-pass\"",
            presentation,
            re.DOTALL,
        )
        self.assertEqual(safe_uses, ["HARDENED_VALID"])

    def test_missing_backend_verdict_fails_closed(self):
        self.assertIn('"VALID_WITH_GAPS"', APP)
        self.assertIn("Missing backend verdicts deliberately fail closed", APP)

    def test_enforcement_decision_is_rendered_and_fails_closed(self):
        for page in (HTML, COMPARISON):
            self.assertIn('id="resEnforcementAction"', page)
            self.assertIn('id="resEnforcementRemediation"', page)
            self.assertIn('id="resEnforcementReasons"', page)
            self.assertIn('id="resEnforcementPolicy"', page)
        self.assertIn('reason_codes: ["MISSING_ENFORCEMENT_DECISION"]', APP)
        self.assertIn('action: "BLOCK"', APP)

    def test_future_features_are_not_enabled_controls(self):
        roadmap_control = re.search(
            r'<input type="checkbox" id="toggleInjection"([^>]*)>', HTML
        )
        self.assertIsNotNone(roadmap_control)
        self.assertIn("disabled", roadmap_control.group(1))
        self.assertNotIn("checked", roadmap_control.group(1))


if __name__ == "__main__":
    unittest.main()
