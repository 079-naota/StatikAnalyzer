"""Entropy calculation for file/section byte data."""

from __future__ import annotations

from math import log2
from typing import Any, Dict


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in the range 0.0 to 8.0 for byte data."""
    if not data:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * log2(p)
    return round(entropy, 4)


def describe_entropy(value: float) -> str:
    """Return a simple label for triage purposes."""
    if value >= 7.2:
        return "high"
    if value >= 6.5:
        return "medium"
    return "low"


def calculate_section_entropy(section_name: str, data: bytes) -> Dict[str, Any]:
    """Calculate entropy for one section and return a stable dictionary."""
    try:
        value = shannon_entropy(data)
        return {
            "section_name": section_name,
            "entropy": value,
            "entropy_level": describe_entropy(value),
            "success": True,
            "error": None,
        }
    except Exception as exc:
        return {
            "section_name": section_name,
            "entropy": None,
            "entropy_level": "unknown",
            "success": False,
            "error": {"module": "entropy", "code": "entropy_calc_error", "message": str(exc)},
        }
