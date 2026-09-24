"""Interpret certificate-revocation evidence from the C2PA SDK."""

from __future__ import annotations

from typing import Any


REVOKED_CODES = {
    "signingCredential.revoked",
    "signingCredential.ocsp.revoked",
}

NOT_REVOKED_CODES = {
    "signingCredential.notRevoked",
    "signingCredential.ocsp.notRevoked",
}

UNKNOWN_CODES = {
    "signingCredential.ocsp.inaccessible",
    "signingCredential.ocsp.skipped",
    "signingCredential.ocsp.unknown",
}


def _validation_entries(value: Any):
    """Find validation entries inside nested SDK results."""

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
    """Determine the active signer's revocation status."""

    evidence = []
    seen = set()

    # Only inspect the active manifest. Ingredient results must
    # not determine the current signer's revocation status.
    if (
        isinstance(validation_results, dict)
        and "activeManifest" in validation_results
    ):
        validation_results = validation_results[
            "activeManifest"
        ]

        # Top-level validation_status can contain results
        # collected from ingredient manifests.
        validation_status = None

    relevant_codes = (
        REVOKED_CODES
        | NOT_REVOKED_CODES
        | UNKNOWN_CODES
    )

    for root in (
        validation_results,
        validation_status,
    ):
        for entry in _validation_entries(root):
            code = entry.get("code")

            if code not in relevant_codes:
                continue

            item = {
                "code": code,
                "url": entry.get("url"),
                "explanation": entry.get(
                    "explanation"
                ),
            }

            fingerprint = tuple(item.items())

            if fingerprint not in seen:
                evidence.append(item)
                seen.add(fingerprint)

    codes = {
        item["code"]
        for item in evidence
    }

    # Revocation always wins if conflicting evidence exists.
    if codes & REVOKED_CODES:
        return {
            "status": "revoked",
            "checked": True,
            "method": "c2pa_ocsp_validation",
            "message": (
                "The signing certificate was revoked "
                "at signing time."
            ),
            "evidence": evidence,
        }

    if codes & NOT_REVOKED_CODES:
        return {
            "status": "not_revoked",
            "checked": True,
            "method": "c2pa_ocsp_validation",
            "message": (
                "OCSP evidence shows the certificate "
                "was not revoked at signing time."
            ),
            "evidence": evidence,
        }

    return {
        "status": "unknown",
        "checked": False,
        "method": "c2pa_ocsp_validation",
        "message": (
            "No conclusive OCSP revocation evidence "
            "was returned by the C2PA validator; "
            "do not treat this certificate as "
            "confirmed safe."
        ),
        "evidence": evidence,
    }