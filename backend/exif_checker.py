"""Supplementary EXIF / active-manifest metadata consistency analysis.

EXIF is editable, and C2PA metadata is a signer's assertion, not scene truth.
A discrepancy is investigative evidence only; this module never issues a trust verdict.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
import re
from typing import Any

from PIL import Image, UnidentifiedImageError

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
METADATA_LABELS = {"stds.exif", "stds.metadata", "c2pa.metadata"}
FIELD_LABELS = {
    "camera_make": "Camera make",
    "camera_model": "Camera model",
    "capture_time": "Original capture time",
    "software": "Embedded software",
}
JSON_LD_KEYS = {
    "camera_make": ("tiff:Make",),
    "camera_model": ("tiff:Model",),
    "capture_time": ("exif:DateTimeOriginal",),
    "software": ("tiff:Software",),
}
SCOPE_NOTE = (
    "EXIF can be edited or removed. C2PA metadata is an assertion whose trust depends "
    "on manifest validation. Matches do not establish scene authenticity; "
    "discrepancies do not independently prove tampering."
)


def _clean(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("@value")
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, (str, int, float)):
        return None
    text = " ".join(str(value).replace("\x00", "").split()).strip()
    return text[:200] if text else None


def extract_exif(path: str | Path) -> dict[str, Any]:
    """Read a small, non-sensitive EXIF field allowlist; never expose GPS data."""
    if Path(path).suffix.lower() not in IMAGE_EXTENSIONS:
        return {"status": "not_applicable", "fields": {}, "message": "EXIF comparison currently supports image uploads only."}
    try:
        with Image.open(path) as image:
            metadata = image.getexif()
            try:
                exif_ifd = metadata.get_ifd(0x8769)
            except (AttributeError, KeyError, TypeError, ValueError):
                exif_ifd = {}
            fields = {
                "camera_make": _clean(metadata.get(271)),
                "camera_model": _clean(metadata.get(272)),
                "capture_time": _clean(metadata.get(36867) or exif_ifd.get(36867)),
                "software": _clean(metadata.get(305)),
            }
            offset = _clean(metadata.get(36881) or exif_ifd.get(36881))
            if fields["capture_time"] and offset:
                fields["capture_offset"] = offset
            fields = {key: value for key, value in fields.items() if value is not None}
            return {
                "status": "present" if fields else "absent",
                "fields": fields,
                "message": "Embedded EXIF fields were extracted." if fields else "No supported EXIF fields were present.",
            }
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return {"status": "error", "fields": {}, "message": "The image's EXIF metadata could not be read safely."}


def _assertion_content(entry: Any) -> dict[str, Any]:
    """Accept the SDK's normal and detailed assertion JSON wrappers."""
    if not isinstance(entry, dict):
        return {}
    candidate = entry
    for _ in range(4):
        if any(key in candidate for keys in JSON_LD_KEYS.values() for key in keys):
            return candidate
        nested = next((candidate.get(key) for key in ("data", "content", "value")
                       if isinstance(candidate.get(key), dict)), None)
        if nested is None:
            break
        candidate = nested
    return candidate if isinstance(candidate, dict) else {}


def extract_c2pa_metadata(manifest_store: Any, detailed_store: Any = None) -> dict[str, Any]:
    """Select metadata assertions belonging ONLY to the active manifest."""
    sources = []
    for store in (manifest_store, detailed_store):
        if not isinstance(store, dict):
            continue
        active_id = store.get("active_manifest")
        manifests = store.get("manifests")
        active = manifests.get(active_id) if isinstance(manifests, dict) and isinstance(active_id, str) else None
        if not isinstance(active, dict):
            continue
        assertions = active.get("assertions")
        if isinstance(assertions, list):
            for assertion in assertions:
                if isinstance(assertion, dict) and assertion.get("label") in METADATA_LABELS:
                    sources.append((assertion["label"], assertion))
        assertion_store = active.get("assertion_store")
        if isinstance(assertion_store, dict):
            for label, assertion in assertion_store.items():
                if label in METADATA_LABELS:
                    sources.append((label, assertion))

    result: dict[str, Any] = {"fields": {}, "field_sources": {}, "assertion_labels": []}
    for label, assertion in sources:
        if label not in result["assertion_labels"]:
            result["assertion_labels"].append(label)
        payload = _assertion_content(assertion)
        for field, keys in JSON_LD_KEYS.items():
            if field in result["fields"]:
                continue
            value = next((_clean(payload.get(key)) for key in keys if _clean(payload.get(key))), None)
            if value is not None:
                result["fields"][field] = value
                result["field_sources"][field] = label
        offset = _clean(payload.get("exif:OffsetTimeOriginal"))
        if "capture_time" in result["fields"] and "capture_offset" not in result["fields"] and offset:
            result["fields"]["capture_offset"] = offset
    return result


def _parse_capture_time(value: str | None, offset: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    try:
        if re.fullmatch(r"\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}", text):
            parsed = datetime.strptime(text, "%Y:%m:%d %H:%M:%S")
        else:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None and offset and re.fullmatch(r"[+-](?:0\d|1\d|2[0-3]):[0-5]\d", offset):
            sign = 1 if offset[0] == "+" else -1
            hours, minutes = map(int, offset[1:].split(":"))
            parsed = parsed.replace(tzinfo=timezone(sign * timedelta(hours=hours, minutes=minutes)))
        return parsed
    except (ValueError, OverflowError):
        return None


def _compare(field: str, embedded: str, asserted: str, embedded_offset: str | None, asserted_offset: str | None) -> tuple[str, str]:
    if field == "capture_time":
        left = _parse_capture_time(embedded, embedded_offset)
        right = _parse_capture_time(asserted, asserted_offset)
        if left is None or right is None:
            return "inconclusive", "One or both capture timestamps use an unsupported date format."
        if (left.tzinfo is None) != (right.tzinfo is None):
            return "inconclusive", "A timezone offset is missing from one capture timestamp."
        if left.tzinfo is not None:
            left, right = left.astimezone(timezone.utc), right.astimezone(timezone.utc)
        return ("match", "Capture timestamps agree.") if left == right else ("mismatch", "Capture timestamps disagree.")
    equal = embedded.casefold() == asserted.casefold()
    return ("match", "Embedded and asserted values agree.") if equal else ("mismatch", "Embedded and asserted values differ.")


def compare_exif(path: str | Path, manifest_store: Any = None, detailed_store: Any = None) -> dict[str, Any]:
    """Compare equivalent EXIF and active C2PA metadata without changing trust policy."""
    embedded = extract_exif(path)
    asserted = extract_c2pa_metadata(manifest_store, detailed_store)
    comparisons = []
    for field, label in FIELD_LABELS.items():
        actual = embedded["fields"].get(field)
        claimed = asserted["fields"].get(field)
        if actual is not None and claimed is not None:
            state, explanation = _compare(
                field, actual, claimed,
                embedded["fields"].get("capture_offset"), asserted["fields"].get("capture_offset")
            )
        else:
            state, explanation = "unavailable", "The field is absent from EXIF or the active C2PA metadata assertion."
        comparisons.append({
            "field": field, "label": label, "exif": actual, "c2pa": claimed,
            "status": state, "source_assertion": asserted["field_sources"].get(field),
            "explanation": explanation,
        })

    compared = [item for item in comparisons if item["status"] in ("match", "mismatch")]
    if embedded["status"] in ("error", "not_applicable", "absent"):
        status = {"error": "error", "not_applicable": "not_applicable", "absent": "no_exif"}[embedded["status"]]
        message = embedded["message"]
    elif not asserted["fields"]:
        status = "no_c2pa_metadata"
        message = "No comparable metadata assertions were available in the active C2PA manifest."
    elif any(item["status"] == "mismatch" for item in compared):
        status = "mismatch"
        message = "One or more comparable EXIF and C2PA metadata values differ; review the evidence."
    elif compared:
        status = "match"
        message = "Available comparable metadata values agree; authenticity is not established."
    else:
        status = "inconclusive"
        message = "Metadata exists, but no fields could be compared conclusively."

    return {
        "status": status,
        "checked": bool(compared),
        "message": message,
        "exif": embedded["fields"],
        "c2pa": asserted["fields"],
        "assertion_labels": asserted["assertion_labels"],
        "comparisons": comparisons,
        "scope_note": SCOPE_NOTE,
    }
