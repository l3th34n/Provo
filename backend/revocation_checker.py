"""Interpret certificate-revocation evidence produced by the C2PA SDK.

C2PA uses OCSP responses (usually stapled into the manifest's ``rVals``
header).  The SDK validates those responses and exposes standard validation
codes.  This module deliberately does not treat a missing code as proof that
the certificate is good.
"""

from __future__ import annotations

from typing import Any


REVOKED_CODE = "signingCredential.revoked"
NOT_REVOKED_CODE = "signingCredential.notRevoked"


def _validation_entries(value: Any):
    """Yield validation-result dictionaries from differently shaped SDK data."""
    if isinstance(value, dict):
        if isinstance(value.get("code"), str):
            yield value

        for child in value.values():
            yield from _validation_entries(child)

    elif isinstance(value, list):
        for child in value:
            yield from _validation_entries(child)


def check_certificate_revocation(
    validation_results: Any,
    validation_status: Any = None,
) -> dict[str, Any]:
    """Return a cautious, frontend-friendly signer revocation conclusion.

    ``revoked`` always wins if contradictory evidence is ever returned.  An
    ``unknown`` result is intentional: the C2PA standard permits a validator
    to skip a live OCSP query when no acceptable stapled response is present.
    """
    evidence = []
    seen = set()

    for root in (validation_results, validation_status):
        for entry in _validation_entries(root):
            code = entry.get("code")
            if code not in {REVOKED_CODE, NOT_REVOKED_CODE}:
                continue

            item = {
                "code": code,
                "url": entry.get("url"),
                "explanation": entry.get("explanation"),
            }
            fingerprint = tuple(item.items())
            if fingerprint not in seen:
                evidence.append(item)
                seen.add(fingerprint)

    codes = {item["code"] for item in evidence}

    if REVOKED_CODE in codes:
        return {
            "status": "revoked",
            "checked": True,
            "method": "c2pa_ocsp_validation",
            "message": "The signing certificate was revoked at signing time.",
            "evidence": evidence,
        }

    if NOT_REVOKED_CODE in codes:
        return {
            "status": "not_revoked",
            "checked": True,
            "method": "c2pa_ocsp_validation",
            "message": "OCSP evidence shows the certificate was not revoked at signing time.",
            "evidence": evidence,
        }

    return {
        "status": "unknown",
        "checked": False,
        "method": "c2pa_ocsp_validation",
        "message": (
            "No conclusive OCSP revocation evidence was returned by the C2PA "
            "validator; do not treat this certificate as confirmed safe."
        ),
        "evidence": [],
    }