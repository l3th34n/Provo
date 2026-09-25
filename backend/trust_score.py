"""Transparent scoring of verified C2PA provenance evidence.

This score measures the strength and completeness of provenance evidence. It
does not estimate whether depicted content is true, authentic, or AI-generated.
"""

from __future__ import annotations

from typing import Any


SCORE_VERSION = "1.0"
SCOPE_NOTE = (
    "Measures verified provenance evidence only. It is not an AI-generation "
    "probability and does not establish that the depicted event is true."
)

_VERDICT_CAPS = {
    "TAMPERED": (10, "Cryptographic integrity failure caps the score at 10."),
    "REVOKED_SIGNER": (15, "Revoked signer evidence caps the score at 15."),
    "CREDENTIAL_INVALID": (20, "An invalid signing credential caps the score at 20."),
    "POLICY_VIOLATION": (30, "A hardened policy violation caps the score at 30."),
    "UNTRUSTED_SIGNER": (45, "An untrusted signer caps the score at 45."),
    "TIMESTAMP_INVALID": (50, "An invalid timestamp caps the score at 50."),
    "INSPECTION_ERROR": (0, "An incomplete inspection cannot earn provenance trust."),
    "NO_PROVENANCE": (0, "No manifest means no verifiable provenance evidence was available."),
}


def _entries(value: Any):
    if isinstance(value, dict):
        if isinstance(value.get("code"), str):
            yield value
        for child in value.values():
            yield from _entries(child)
    elif isinstance(value, list):
        for child in value:
            yield from _entries(child)


def _active_success_codes(c2pa_result: dict[str, Any]) -> set[str]:
    validation = c2pa_result.get("validation_results")
    if not isinstance(validation, dict):
        return set()
    active = validation.get("activeManifest", validation)
    if not isinstance(active, dict):
        return set()
    return {entry["code"] for entry in _entries(active.get("success", []))}


def _criterion(identifier: str, label: str, weight: int, passed: bool, evidence: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "label": label,
        "weight": weight,
        "passed": passed,
        "earned": weight if passed else 0,
        "evidence": evidence,
    }


def calculate_provenance_trust_score(
    c2pa_result: Any,
    hardened_verdict: Any,
) -> dict[str, Any]:
    """Score seven disclosed positive-evidence criteria and apply safety caps."""
    c2pa = c2pa_result if isinstance(c2pa_result, dict) else {}
    hardened = hardened_verdict if isinstance(hardened_verdict, dict) else {}
    success_codes = _active_success_codes(c2pa)
    revocation = c2pa.get("certificate_revocation") or {}
    timestamp = c2pa.get("timestamp_security") or {}
    pipeline = c2pa.get("pipeline_audit") or {}
    coverage = pipeline.get("coverage") if isinstance(pipeline, dict) else {}
    pipeline_complete = (
        isinstance(coverage, dict)
        and all(coverage.get(item) == "checked" for item in (
            "sdk_signals", "ingredient_graph", "jpeg_exclusion_coverage"
        ))
    )

    criteria = [
        _criterion(
            "manifest", "C2PA manifest detected", 10,
            c2pa.get("manifest_found") is True,
            "manifest_found must be true",
        ),
        _criterion(
            "standard_validation", "Standard validation state is Valid", 15,
            str(c2pa.get("validation_state")).lower() == "valid",
            f"validation_state={c2pa.get('validation_state')}",
        ),
        _criterion(
            "claim_signature", "Active claim signature validated", 20,
            "claimSignature.validated" in success_codes,
            "claimSignature.validated in active-manifest success evidence",
        ),
        _criterion(
            "signer_trust", "Active signer trust established", 15,
            "signingCredential.trusted" in success_codes,
            "signingCredential.trusted in active-manifest success evidence",
        ),
        _criterion(
            "revocation", "Credential not revoked", 15,
            revocation.get("status") == "not_revoked",
            f"certificate_revocation.status={revocation.get('status', 'unknown')}",
        ),
        _criterion(
            "timestamp", "Trusted timestamp validated", 10,
            timestamp.get("status") == "valid",
            f"timestamp_security.status={timestamp.get('status', 'unknown')}",
        ),
        _criterion(
            "pipeline", "Pipeline audit completed without flags", 15,
            pipeline.get("checked") is True
            and pipeline.get("status") == "no_flags"
            and pipeline_complete,
            f"pipeline_audit.status={pipeline.get('status', 'missing')}; complete_coverage={pipeline_complete}",
        ),
    ]

    raw_score = sum(item["earned"] for item in criteria)
    verdict = hardened.get("verdict", "MISSING_VERDICT")
    cap = _VERDICT_CAPS.get(verdict)
    adjustments = []
    score = raw_score
    if cap is not None:
        maximum, explanation = cap
        if score > maximum:
            score = maximum
        adjustments.append({"type": "verdict_cap", "maximum": maximum, "reason": explanation})

    if score >= 90:
        rating = "STRONG"
    elif score >= 70:
        rating = "MODERATE"
    elif score >= 40:
        rating = "WEAK"
    else:
        rating = "MINIMAL"

    return {
        "score": score,
        "maximum": 100,
        "raw_score": raw_score,
        "rating": rating,
        "score_version": SCORE_VERSION,
        "evaluated_verdict": verdict,
        "criteria": criteria,
        "adjustments": adjustments,
        "scope_note": SCOPE_NOTE,
    }
