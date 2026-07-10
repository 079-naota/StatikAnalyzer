"""Hash calculation utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict


def calculate_hashes(file_path: str, chunk_size: int = 1024 * 1024) -> Dict[str, Any]:
    """Calculate MD5 and SHA-256 without loading the whole file into memory."""
    result: Dict[str, Any] = {
        "success": False,
        "hashes": {},
        "errors": [],
    }

    path = Path(file_path)
    md5 = hashlib.md5()  # used only as an identifier, not for security decisions
    sha256 = hashlib.sha256()

    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
        result["success"] = True
        result["hashes"] = {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
        return result
    except FileNotFoundError:
        result["errors"].append({"module": "hash_calc", "code": "file_not_found"})
        return result
    except PermissionError:
        result["errors"].append({"module": "hash_calc", "code": "permission_denied"})
        return result
    except OSError as exc:
        result["errors"].append({"module": "hash_calc", "code": "hash_read_error", "message": str(exc)})
        return result
