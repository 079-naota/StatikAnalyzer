"""Build compact timeline events from detailed analysis results."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_timeline_event(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Build one compact event for timeline views."""
    file_info = analysis.get("file_info", {}) or {}
    hashes = analysis.get("hashes", {}) or {}
    classification = analysis.get("classification", {}) or {}
    reasons = classification.get("reasons", []) or []

    return {
        "timestamp": analysis.get("analysis_time") or _now_iso(),
        "source": "StatikAnalyzer",
        "event_type": "file_static_analysis",
        "file_name": file_info.get("file_name", "<unknown>"),
        "file_path": file_info.get("file_path", ""),
        "sha256": hashes.get("sha256", ""),
        "classification": classification.get("classification", "unknown"),
        "risk_score": classification.get("risk_score", 0),
        "message": reasons[0] if reasons else "解析結果を生成しました",
    }


def build_timeline_events(analyses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build sorted timeline events from multiple analysis records."""
    events = [build_timeline_event(item) for item in analyses]
    return sorted(events, key=lambda x: x.get("timestamp", ""))
