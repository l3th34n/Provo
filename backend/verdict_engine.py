"""Combine C2PA validation evidence into Provo's hardened verdict."""

from __future__ import annotations

from typing import Any


TAMPER_CODES = {
    "claimSignature.mismatch",
    "assertion.dataHash.mismatch",
    "assertion.bmffHash.mismatch",
    "assertion.boxesHash.mismatch",
    "assertion.collectionHash.mismatch",
    "assertion.multiAssetHash.mismatch",
    "assertion.hashedURI.mismatch",
    "hashedURI.mismatch",
}

CREDENTIAL_INVALID_CODES = {
    "signingCredential.invalid",
    "signingCredential.expired",
    "claimSignature.outsideValidity",
}

UNTRUSTED_SIGNER_CODE = "signingCredential.untrusted"
TRUSTED_SIGNER_CODE = "signingCredential.trusted"
VALID_SIGNATURE_CODE = "claimSignature.validated"


def _entries(value: Any):
    if isinstance(value, dict):
        if isinstance(value.get("code"), str):
            yield value
        for child in value.values():
            yield from _entries(child)
    elif isinstance(value, list):
        for child in value:
            yield from _entries(child)


def _active_validation(validation_results: Any) -> dict[str, Any]:
    """Return only the active manifest's validation buckets."""
    if not isinstance(validation_results, dict):
        return {}

    active = validation_results.get("activeManifest", validation_results)
    return active if isinstance(active, dict) else {}


def _codes(value: Any) -> set[str]:
    return {entry["code"] for entry in _entries(value)}


def _result(
    verdict: str,
    severity: str,
    summary: str,
    reasons: list[str],
    validation_state: Any,
    evidence_codes: set[str],
) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "severity": severity,
        "hardened_valid": verdict == "HARDENED_VALID",
        "summary": summary,
        "reasons": reasons,
        "standard_validation_state": validation_state,
        "evidence_codes": sorted(evidence_codes),
    }


def evaluate_hardened_verdict(c2pa_result: Any) -> dict[str, Any]:
    """Apply Provo's fail-closed hardening policy to one C2PA result."""
    if not isinstance(c2pa_result, dict):
        return _result(
            "INSPECTION_ERROR",
            "critical",
            "The verification result could not be interpreted.",
            ["The C2PA result was missing or malformed."],
            None,
            set(),
        )

    status = c2pa_result.get("status")
    validation_state = c2pa_result.get("validation_state")

    if status == "no_manifest" or c2pa_result.get("manifest_found") is False:
        return _result(
            "NO_PROVENANCE",
            "info",
            "No C2PA provenance manifest was found.",
            ["Cryptographic provenance cannot be evaluated."],
            validation_state,
            set(),
        )

    if status == "inspection_error" or c2pa_result.get("manifest_found") is None:
        reason = c2pa_result.get("error") or "C2PA inspection failed."
        return _result(
            "INSPECTION_ERROR",
            "critical",
            "Provo could not safely inspect the manifest.",
            [str(reason)],
            validation_state,
            set(),
        )

    active = _active_validation(c2pa_result.get("validation_results"))
    success_codes = _codes(active.get("success", []))
    informational_codes = _codes(active.get("informational", []))
    failure_codes = _codes(active.get("failure", []))
    all_codes = success_codes | informational_codes | failure_codes

    revocation = c2pa_result.get("certificate_revocation") or {}
    timestamp = c2pa_result.get("timestamp_security") or {}
    pipeline_audit = c2pa_result.get("pipeline_audit")
    revocation_status = revocation.get("status", "unknown")
    timestamp_status = timestamp.get("status", "unknown")

    tamper_evidence = failure_codes & TAMPER_CODES
    if tamper_evidence:
        return _result(
            "TAMPERED",
            "critical",
            "Cryptographic integrity checks indicate modified content or manifest data.",
            [f"Integrity failure: {code}" for code in sorted(tamper_evidence)],
            validation_state,
            tamper_evidence,
        )

    if revocation_status == "revoked":
        return _result(
            "REVOKED_SIGNER",
            "critical",
            "The active manifest was signed with a revoked credential.",
            [revocation.get("message", "The signing credential is revoked.")],
            validation_state,
            _codes(revocation.get("evidence", [])),
        )

    if timestamp_status == "invalid":
        timestamp_codes = _codes(timestamp.get("evidence", []))
        return _result(
            "TIMESTAMP_INVALID",
            "high",
            "The active manifest's timestamp cannot be trusted.",
            [timestamp.get("message", "Timestamp validation failed.")],
            validation_state,
            timestamp_codes,
        )

    invalid_credentials = failure_codes & CREDENTIAL_INVALID_CODES
    if invalid_credentials:
        return _result(
            "CREDENTIAL_INVALID",
            "high",
            "The active signing credential failed validity requirements.",
            [f"Credential failure: {code}" for code in sorted(invalid_credentials)],
            validation_state,
            invalid_credentials,
        )

    other_failures = failure_codes - {
        UNTRUSTED_SIGNER_CODE,
        *TAMPER_CODES,
        *CREDENTIAL_INVALID_CODES,
    }
    if other_failures:
        return _result(
            "POLICY_VIOLATION",
            "high",
            "The manifest violates Provo's hardened validation policy.",
            [f"Validation failure: {code}" for code in sorted(other_failures)],
            validation_state,
            other_failures,
        )

    if UNTRUSTED_SIGNER_CODE in failure_codes:
        return _result(
            "UNTRUSTED_SIGNER",
            "high",
            "The signature may be intact, but the signer is not trusted by the validator.",
            ["No trusted certificate chain was established for the active signer."],
            validation_state,
            {UNTRUSTED_SIGNER_CODE},
        )

    gaps = []
    gap_codes = set()

    if VALID_SIGNATURE_CODE not in success_codes:
        gaps.append("The active claim signature was not positively validated.")

    if TRUSTED_SIGNER_CODE not in success_codes:
        gaps.append("The active signer was not positively established as trusted.")

    if revocation_status != "not_revoked":
        gaps.append("Certificate revocation status is not conclusive.")
        gap_codes.update(_codes(revocation.get("evidence", [])))

    if timestamp_status != "valid":
        if timestamp_status == "incomplete":
            gaps.append("Timestamp validation evidence is incomplete.")
        else:
            gaps.append("No valid and trusted timestamp was established.")
        gap_codes.update(_codes(timestamp.get("evidence", [])))

    if str(validation_state).lower() != "valid":
        gaps.append("The standard C2PA validation state is not Valid.")

    if isinstance(pipeline_audit, dict):
        pipeline_status = pipeline_audit.get("status")
        if pipeline_status == "invalid":
            return _result(
                "POLICY_VIOLATION", "high",
                "The active manifest has a structural provenance failure.",
                [item.get("message", "Pipeline audit failure.") for item in pipeline_audit.get("findings", [])
                 if isinstance(item, dict) and item.get("level") == "invalid"] or ["The pipeline audit reported invalid provenance structure."],
                validation_state,
                {item.get("code") for item in pipeline_audit.get("findings", [])
                 if isinstance(item, dict) and isinstance(item.get("code"), str)},
            )
        coverage = pipeline_audit.get("coverage")
        complete = isinstance(coverage, dict) and all(
            coverage.get(check) == "checked"
            for check in ("sdk_signals", "ingredient_graph", "jpeg_exclusion_coverage")
        )
        if pipeline_status != "no_flags" or pipeline_audit.get("checked") is not True or not complete:
            gaps.append("Pipeline structure requires review or could not be assessed.")
            gap_codes.update(
                item["code"] for item in pipeline_audit.get("findings", [])
                if isinstance(item, dict) and isinstance(item.get("code"), str)
            )
    else:
        gaps.append("The pipeline audit result is missing or malformed.")

    if gaps:
        return _result(
            "VALID_WITH_GAPS",
            "warning",
            "No decisive attack was found, but the evidence is insufficient for hardened trust.",
            gaps,
            validation_state,
            gap_codes,
        )

    return _result(
        "HARDENED_VALID",
        "safe",
        "The active manifest passed Provo's hardened validation policy.",
        [
            "Standard C2PA validation passed.",
            "The active signer is trusted.",
            "The signing credential was not revoked at signing time.",
            "The active manifest has a valid trusted timestamp.",
            "The supported JPEG pipeline audit completed without flagged concerns.",
        ],
        validation_state,
        all_codes,
    )
