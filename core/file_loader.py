"""File metadata collection for StatikAnalyzer.

This module only checks file accessibility and collects filesystem metadata.
It does not execute or deeply parse the target file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import os
from typing import Any, Dict


def _iso_from_timestamp(ts: float) -> str:
    """Convert a filesystem timestamp to UTC ISO-8601."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def get_file_info(file_path: str) -> Dict[str, Any]:
    """Return basic metadata for a file.

    The return format is intentionally stable so later modules can consume it.
    Even on failure, the function returns a dictionary instead of raising.
    """
    result: Dict[str, Any] = {
        "success": False,
        "file_info": {},
        "errors": [],
    }

    if not file_path or not str(file_path).strip():
        result["errors"].append({"module": "file_loader", "code": "file_path_empty"})
        return result

    path = Path(file_path).expanduser()

    try:
        resolved = path.resolve(strict=False)
    except Exception:
        resolved = path

    if not resolved.exists():
        result["errors"].append({
            "module": "file_loader",
            "code": "file_not_found",
            "message": f"File does not exist: {resolved}",
        })
        return result

    if not resolved.is_file():
        result["errors"].append({
            "module": "file_loader",
            "code": "not_a_file",
            "message": f"Path is not a regular file: {resolved}",
        })
        return result

    if not os.access(resolved, os.R_OK):
        result["errors"].append({
            "module": "file_loader",
            "code": "permission_denied",
            "message": f"File is not readable: {resolved}",
        })
        return result

    try:
        stat = resolved.stat()
        result["success"] = True
        result["file_info"] = {
            "file_name": resolved.name,
            "file_path": str(resolved),
            "extension": resolved.suffix.lower(),
            "file_size": stat.st_size,
            "created_time": _iso_from_timestamp(stat.st_ctime),
            "modified_time": _iso_from_timestamp(stat.st_mtime),
            "accessed_time": _iso_from_timestamp(stat.st_atime),
            "is_readable": True,
        }
        return result
    except PermissionError:
        result["errors"].append({"module": "file_loader", "code": "permission_denied"})
        return result
    except OSError as exc:
        result["errors"].append({
            "module": "file_loader",
            "code": "read_error",
            "message": str(exc),
        })
        return result
