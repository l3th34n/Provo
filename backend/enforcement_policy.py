"""Translate hardened verdicts into deterministic middleware actions.

The enforcement layer deliberately consumes only the final hardened verdict.
This keeps evidence interpretation in ``verdict_engine`` and makes the policy
decision small, auditable, and safe to replace with an organisation-specific
policy in a production deployment.
"""

from __future__ import annotations

from typing import Any


POLICY_ID = "provo-default-enforcement"
POLICY_VERSION = "1.0"


_POLICY = {
    "HARDENED_VALID": {
        "action": "ALLOW",
        "reason_codes": ["PROVENANCE_POLICY_PASSED"],
        "remediation": "No enforcement remediation is required.",
    },
    "VALID_WITH_GAPS": {
        "action": "ALLOW_WITH_WARNING",
        "reason_codes": ["PROVENANCE_EVIDENCE_INCOMPLETE"],
        "remediation": "Preserve the warning and obtain the missing trust evidence before high-risk use.",
    },
    "UNTRUSTED_SIGNER": {
        "action": "QUARANTINE",
        "reason_codes": ["SIGNER_TRUST_NOT_ESTABLISHED"],
        "remediation": "Hold the asset for review or require a signer chained to an approved trust anchor.",
    },
    "NO_PROVENANCE": {
        "action": "QUARANTINE",
        "reason_codes": ["PROVENANCE_MANIFEST_MISSING"],
        "remediation": "Treat the asset as provenance-unknown and request a signed source when policy requires provenance.",
    },
    "TAMPERED": {
        "action": "BLOCK",
        "reason_codes": ["CRYPTOGRAPHIC_INTEGRITY_FAILURE"],
        "remediation": "Reject the asset and request an untampered, newly validated original.",
    },
    "REVOKED_SIGNER": {
        "action": "BLOCK",
        "reason_codes": ["SIGNER_CERTIFICATE_REVOKED"],
        "remediation": "Reject the asset and request a new signature from a non-revoked credential.",
    },
    "TIMESTAMP_INVALID": {
        "action": "BLOCK",
        "reason_codes": ["TRUSTED_TIMESTAMP_INVALID"],
        "remediation": "Reject the claimed signing time and require a valid trusted timestamp.",
    },
    "CREDENTIAL_INVALID": {
        "action": "BLOCK",
        "reason_codes": ["SIGNING_CREDENTIAL_INVALID"],
        "remediation": "Reject the asset and require re-signing with a currently valid credential.",
    },
    "POLICY_VIOLATION": {
        "action": "BLOCK",
        "reason_codes": ["HARDENED_POLICY_VIOLATION"],
        "remediation": "Reject the asset until the reported policy failure is resolved.",
    },
    "INSPECTION_ERROR": {
        "action": "BLOCK",
        "reason_codes": ["INSPECTION_FAILED_CLOSED"],
        "remediation": "Do not distribute the asset; retry in isolation or escalate for manual review.",
    },
}


def decide_enforcement(hardened_verdict: Any) -> dict[str, Any]:
    """Return a machine-readable action for a hardened verdict.

    Missing, malformed, and future unknown verdicts fail closed. This prevents
    a newly introduced backend state from being accidentally treated as safe by
    middleware clients that have not yet adopted it.
    """
    verdict = hardened_verdict.get("verdict") if isinstance(hardened_verdict, dict) else None
    rule = _POLICY.get(verdict)

    if rule is None:
        verdict = verdict if isinstance(verdict, str) and verdict else "MISSING_VERDICT"
        rule = {
            "action": "BLOCK",
            "reason_codes": ["UNKNOWN_VERDICT_FAILED_CLOSED"],
            "remediation": "Do not distribute the asset until the enforcement policy supports this verdict.",
        }

    return {
        "action": rule["action"],
        "policy_id": POLICY_ID,
        "policy_version": POLICY_VERSION,
        "evaluated_verdict": verdict,
        "reason_codes": list(rule["reason_codes"]),
        "remediation": rule["remediation"],
    }
