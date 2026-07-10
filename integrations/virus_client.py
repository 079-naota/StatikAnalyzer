"""VirusTotal hash lookup client.

MVP policy:
- Query by SHA-256 hash only.
- Do not upload file contents.
- Work gracefully when API key is missing or rate limited.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

VT_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"


def lookup_file_hash(sha256: Optional[str], api_key: Optional[str] = None, timeout: int = 20) -> Dict[str, Any]:
    """Look up a file hash in VirusTotal API v3."""
    result: Dict[str, Any] = {
        "queried": False,
        "found": False,
        "stats": {
            "malicious": None,
            "suspicious": None,
            "harmless": None,
            "undetected": None,
            "timeout": None,
        },
        "last_analysis_date": None,
        "reputation": None,
        "error": None,
    }

    if not sha256:
        result["error"] = {"module": "virus_client", "code": "sha256_missing"}
        return result

    key = api_key or os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
    if not key:
        result["error"] = {"module": "virus_client", "code": "api_key_missing"}
        return result

    url = VT_FILE_ENDPOINT.format(sha256=sha256)
    req = urllib.request.Request(url, method="GET", headers={"x-apikey": key})

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        result.update({
            "queried": True,
            "found": True,
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0),
            },
            "last_analysis_date": attrs.get("last_analysis_date"),
            "reputation": attrs.get("reputation"),
        })
        return result
    except urllib.error.HTTPError as exc:
        result["queried"] = True
        if exc.code == 404:
            result["found"] = False
            result["error"] = {"module": "virus_client", "code": "hash_not_found", "http_status": exc.code}
        elif exc.code == 401:
            result["error"] = {"module": "virus_client", "code": "api_key_invalid", "http_status": exc.code}
        elif exc.code == 429:
            result["error"] = {"module": "virus_client", "code": "rate_limited", "http_status": exc.code}
        else:
            result["error"] = {"module": "virus_client", "code": "http_error", "http_status": exc.code}
        return result
    except urllib.error.URLError as exc:
        result["error"] = {"module": "virus_client", "code": "network_error", "message": str(exc)}
        return result
    except TimeoutError:
        result["error"] = {"module": "virus_client", "code": "timeout"}
        return result
    except Exception as exc:
        result["error"] = {"module": "virus_client", "code": "vt_unexpected_error", "message": str(exc)}
        return result
