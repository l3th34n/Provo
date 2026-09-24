"""Hardened interpretation of C2PA time-stamp validation results."""

from __future__ import annotations

from typing import Any


VALIDATED_CODE = "timeStamp.validated"
TRUSTED_CODE = "timeStamp.trusted"

TIMESTAMP_PROBLEM_CODES = {
    "timeStamp.credentialInvalid",
    "timeStamp.malformed",
    "timeStamp.mismatch",
    "timeStamp.outsideValidity",
    "timeStamp.untrusted",
    # Some SDK messages use the spelling from the prose sections of the spec.
    "timestamp.malformed",
    "timestamp.mismatch",
    "timestamp.outsideValidity",
    "timestamp.untrusted",
}

SIGNING_TIME_PROBLEM_CODES = {
    "claimSignature.outsideValidity",
    "timeOfSigning.outsideValidity",
}


def _validation_entries(value: Any):
    if isinstance(value, dict):
        if isinstance(value.get("code"), str):
            yield value

        for child in value.values():
            yield from _validation_entries(child)

    elif isinstance(value, list):
        for child in value:
            yield from _validation_entries(child)


def _active_manifest_results(validation_results: Any) -> Any:
    """Exclude ingredient results from the active manifest's conclusion."""
    if isinstance(validation_results, dict) and "activeManifest" in validation_results:
        return validation_results["activeManifest"]
    return validation_results


def check_timestamp_security(
    signature_info: Any,
    validation_results: Any,
) -> dict[str, Any]:
    """Return a hardened timestamp verdict for the active C2PA manifest.

    A timestamp is accepted only when the SDK reports both
    ``timeStamp.validated`` and ``timeStamp.trusted``.  A time string in
    ``signature_info`` alone is merely a claimed time and is not trusted.
    """
    signature_info = signature_info if isinstance(signature_info, dict) else {}
    claimed_time = signature_info.get("time")
    relevant_codes = {
        VALIDATED_CODE,
        TRUSTED_CODE,
        *TIMESTAMP_PROBLEM_CODES,
        *SIGNING_TIME_PROBLEM_CODES,
    }

    evidence = []
    seen = set()
    for entry in _validation_entries(_active_manifest_results(validation_results)):
        code = entry.get("code")
        if code not in relevant_codes:
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
    problems = codes & (TIMESTAMP_PROBLEM_CODES | SIGNING_TIME_PROBLEM_CODES)

    if problems:
        return {
            "status": "invalid",
            "checked": True,
            "trusted": False,
            "claimed_time": claimed_time,
            "message": "The active manifest has unusable or inconsistent timestamp evidence.",
            "evidence": evidence,
        }

    if VALIDATED_CODE in codes and TRUSTED_CODE in codes:
        return {
            "status": "valid",
            "checked": True,
            "trusted": True,
            "claimed_time": claimed_time,
            "message": "The active manifest timestamp is cryptographically valid and trusted.",
            "evidence": evidence,
        }

    if VALIDATED_CODE in codes or TRUSTED_CODE in codes:
        return {
            "status": "incomplete",
            "checked": True,
            "trusted": False,
            "claimed_time": claimed_time,
            "message": "Timestamp evidence is incomplete; both validation and trust are required.",
            "evidence": evidence,
        }

    message = "No trusted cryptographic timestamp was found for the active manifest."
    if claimed_time:
        message += " A claimed signing time exists, but it is not independent proof."

    return {
        "status": "unknown",
        "checked": False,
        "trusted": False,
        "claimed_time": claimed_time,
        "message": message,
        "evidence": [],
    }
