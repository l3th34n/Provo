
import json
import logging
from pathlib import Path

from c2pa import Reader, C2paError

from revocation_checker import check_certificate_revocation
from timestamp_checker import check_timestamp_security
from pipeline_audit import audit_pipeline
from verdict_engine import evaluate_hardened_verdict


logger = logging.getLogger("provo")


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
                result["hardened_verdict"] = evaluate_hardened_verdict(result)
                return result

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

            result["hardened_verdict"] = evaluate_hardened_verdict(result)
            return result

    except C2paError.ManifestNotFound:
        result = {
            "status": "no_manifest",
            "manifest_found": False
        }
        result["hardened_verdict"] = evaluate_hardened_verdict(result)
        return result

    except (C2paError, ValueError, TypeError, OSError) as error:
        logger.warning("C2PA inspection failed: %s", error)
        result = {
            "status": "inspection_error",
            "manifest_found": None,
            "error": "The C2PA data could not be safely interpreted."
        }
        result["hardened_verdict"] = evaluate_hardened_verdict(result)
        return result

    except Exception:
        logger.exception("Unexpected C2PA inspection failure")
        result = {
            "status": "inspection_error",
            "manifest_found": None,
            "error": "An unexpected C2PA inspection error occurred."
        }
        result["hardened_verdict"] = evaluate_hardened_verdict(result)
        return result
