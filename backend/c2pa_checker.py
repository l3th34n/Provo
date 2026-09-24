
import json
from pathlib import Path

from c2pa import Reader, C2paError


def check_c2pa(file_path):
    try:
        with Reader(str(file_path)) as reader:
            data = json.loads(reader.json())

            active_id = data.get("active_manifest")
            manifests = data.get("manifests", {})

            if not active_id or active_id not in manifests:
                return {
                    "status": "no_manifest",
                    "manifest_found": False
                }

            active = manifests[active_id]

            return {
                "status": "manifest_found",
                "manifest_found": True,
                "active_manifest": active_id,
                "claim_generator": active.get(
                    "claim_generator"
                ),
                "signature_info": active.get(
                    "signature_info", {}
                ),
                "assertions": [
                    item.get("label")
                    for item in active.get("assertions", [])
                ],
                "validation_state":
                    reader.get_validation_state(),
                "validation_results":
                    reader.get_validation_results()
            }

    except C2paError.ManifestNotFound:
        return {
            "status": "no_manifest",
            "manifest_found": False
        }

    except (C2paError, ValueError, OSError) as error:
        return {
            "status": "inspection_error",
            "manifest_found": None,
            "error": str(error)
        }