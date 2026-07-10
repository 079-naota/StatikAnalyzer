"""JSON export utilities."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def save_json(data: Any, output_path: str) -> Dict[str, Any]:
    """Save JSON data and return operation status."""
    result: Dict[str, Any] = {
        "success": False,
        "output_path": output_path,
        "error": None,
    }

    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        result["success"] = True
        result["output_path"] = str(path.resolve())
        return result
    except PermissionError:
        result["error"] = {"module": "exporter", "code": "permission_denied"}
        return result
    except TypeError as exc:
        result["error"] = {"module": "exporter", "code": "json_serialize_error", "message": str(exc)}
        return result
    except OSError as exc:
        result["error"] = {"module": "exporter", "code": "write_error", "message": str(exc)}
        return result
