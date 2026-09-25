
import json
import logging
from pathlib import Path

from c2pa import Reader, C2paError

from revocation_checker import check_certificate_revocation
from timestamp_checker import check_timestamp_security
from pipeline_audit import audit_pipeline
from verdict_engine import evaluate_hardened_verdict
from exif_checker import SCOPE_NOTE, compare_exif
from trust_score import calculate_provenance_trust_score


logger = logging.getLogger("provo")


def _add_policy_outputs(result):
    """Attach the verdict first, then the score derived from disclosed evidence."""
    verdict = evaluate_hardened_verdict(result)
    result["hardened_verdict"] = verdict
    result["provenance_trust_score"] = calculate_provenance_trust_score(result, verdict)
    return result


def _safe_exif_comparison(file_path, manifest_store=None, detailed_store=None):
    """Supplementary metadata extraction cannot interrupt cryptographic inspection."""
    try:
        return compare_exif(file_path, manifest_store, detailed_store)
    except Exception:
        logger.exception("Supplementary EXIF consistency inspection failed")
        return {
            "status": "error", "checked": False, "message": "EXIF comparison could not complete.",
            "exif": {}, "c2pa": {}, "assertion_labels": [], "comparisons": [],
            "scope_note": SCOPE_NOTE,
        }


def check_c2pa(file_path):
    try:
        with Reader(str(file_path)) as reader:
            data = json.loads(reader.json())

            if not isinstance(data, dict):
                raise ValueError("C2PA reader returned a malformed manifest document")

            active_id = data.get("active_manifest")
            manifests = data.get("manifests") or {}

            if not isinstance(manifests, dict):
                raise ValueError("C2PA manifest store is malformed")
            if not active_id:
                result = {
                    "status": "no_manifest",
                    "manifest_found": False
                }
                if result.get("status") == "manifest_found":
                    result["metadata_consistency"] = _safe_exif_comparison(file_path, data, detailed_store)
                else:
                    result["metadata_consistency"] = _safe_exif_comparison(file_path)
                return _add_policy_outputs(result)

            if not isinstance(active_id, str) or active_id not in manifests:
                raise ValueError("The active manifest reference cannot be resolved")

            active = manifests[active_id]

            if not isinstance(active, dict):
                raise ValueError("Active C2PA manifest is malformed")

            validation_results = reader.get_validation_results()
            validation_status = data.get("validation_status", [])

            signature_info = active.get("signature_info", {})

            # Normal Reader JSON omits data-hash assertion bodies. The detailed
            # report supplies the actual signed exclusion offsets for auditing.
            detailed_store = None
            try:
                detailed_store = json.loads(reader.detailed_json())
            except (AttributeError, C2paError, ValueError, TypeError):
                logger.warning("Detailed manifest report unavailable; byte audit will be incomplete")

            result = {
                "status": "manifest_found",
                "manifest_found": True,
                "active_manifest": active_id,
                "claim_generator": active.get(
                    "claim_generator"
                ),
                "signature_info": signature_info,
                "assertions": [
                    item.get("label")
                    for item in active.get("assertions", [])
                    if isinstance(item, dict) and item.get("label")
                ],
                "validation_state":
                    reader.get_validation_state(),
                "validation_results": validation_results,
                "validation_status": validation_status,
                "certificate_revocation": check_certificate_revocation(
                    validation_results,
                    validation_status,
                ),
                "timestamp_security": check_timestamp_security(
                    signature_info,
                    validation_results,
                ),
                "pipeline_audit": audit_pipeline(
                    validation_results,
                    manifest_store=data,
                    detailed_store=detailed_store,
                    file_path=file_path,
                ),
            }

            if result.get("status") == "manifest_found":
                result["metadata_consistency"] = _safe_exif_comparison(file_path, data, detailed_store)
            else:
                result["metadata_consistency"] = _safe_exif_comparison(file_path)
            return _add_policy_outputs(result)

    except C2paError.ManifestNotFound:
        result = {
            "status": "no_manifest",
            "manifest_found": False
        }
        if result.get("status") == "manifest_found":
            result["metadata_consistency"] = _safe_exif_comparison(file_path, data, detailed_store)
        else:
            result["metadata_consistency"] = _safe_exif_comparison(file_path)
        return _add_policy_outputs(result)

    except (C2paError, ValueError, TypeError, OSError) as error:
        logger.warning("C2PA inspection failed: %s", error)
        result = {
            "status": "inspection_error",
            "manifest_found": None,
            "error": "The C2PA data could not be safely interpreted."
        }
        if result.get("status") == "manifest_found":
            result["metadata_consistency"] = _safe_exif_comparison(file_path, data, detailed_store)
        else:
            result["metadata_consistency"] = _safe_exif_comparison(file_path)
        return _add_policy_outputs(result)

    except Exception:
        logger.exception("Unexpected C2PA inspection failure")
        result = {
            "status": "inspection_error",
            "manifest_found": None,
            "error": "An unexpected C2PA inspection error occurred."
        }
        if result.get("status") == "manifest_found":
            result["metadata_consistency"] = _safe_exif_comparison(file_path, data, detailed_store)
        else:
            result["metadata_consistency"] = _safe_exif_comparison(file_path)
        return _add_policy_outputs(result)
