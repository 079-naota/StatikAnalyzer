"""Simple self-contained HTML report generator."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Dict, List


def _badge_class(classification: str) -> str:
    if classification in {"malicious_candidate", "suspicious"}:
        return "bad"
    if classification == "clean":
        return "good"
    if classification == "non_pe":
        return "neutral"
    return "warn"


def generate_html_report(analyses: List[Dict[str, Any]], timeline_events: List[Dict[str, Any]], output_path: str) -> Dict[str, Any]:
    """Generate a compact HTML report."""
    rows = []
    for item in analyses:
        file_info = item.get("file_info", {}) or {}
        cls = item.get("classification", {}) or {}
        hashes = item.get("hashes", {}) or {}
        classification = cls.get("classification", "unknown")
        rows.append(f"""
        <tr>
          <td>{escape(file_info.get('file_name', '<unknown>'))}</td>
          <td><code>{escape(hashes.get('sha256', '')[:16])}...</code></td>
          <td><span class="badge {_badge_class(classification)}">{escape(classification)}</span></td>
          <td>{escape(str(cls.get('risk_score', 0)))}</td>
          <td>{escape('; '.join(cls.get('reasons', [])[:2]))}</td>
        </tr>
        """)

    event_cards = []
    for ev in timeline_events:
        classification = ev.get("classification", "unknown")
        event_cards.append(f"""
        <div class="event">
          <div class="time">{escape(ev.get('timestamp', ''))}</div>
          <div><strong>{escape(ev.get('file_name', '<unknown>'))}</strong>
          <span class="badge {_badge_class(classification)}">{escape(classification)}</span>
          <span class="score">score {escape(str(ev.get('risk_score', 0)))}</span></div>
          <p>{escape(ev.get('message', ''))}</p>
        </div>
        """)

    html = f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>StatikAnalyzer Report</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 32px; background: #f6f7fb; color: #222; }}
    h1, h2 {{ margin-bottom: 0.4rem; }}
    .card {{ background: white; border-radius: 16px; padding: 20px; margin: 18px 0; box-shadow: 0 6px 20px rgba(0,0,0,.06); }}
    table {{ width: 100%; border-collapse: collapse; background: white; }}
    th, td {{ text-align: left; border-bottom: 1px solid #e7e7ee; padding: 10px; vertical-align: top; }}
    th {{ background: #fbfbfd; }}
    code {{ background: #f0f1f5; padding: 2px 5px; border-radius: 6px; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 0.85rem; font-weight: 700; }}
    .good {{ background: #e4f7ea; color: #176b36; }}
    .bad {{ background: #fde8e8; color: #9a1c1c; }}
    .warn {{ background: #fff4d6; color: #7a5400; }}
    .neutral {{ background: #e8eef9; color: #244a88; }}
    .event {{ border-left: 4px solid #7d8db7; padding: 8px 0 10px 14px; margin: 12px 0; }}
    .time {{ color: #666; font-size: 0.9rem; }}
    .score {{ color: #666; margin-left: 8px; }}
  </style>
</head>
<body>
  <h1>StatikAnalyzer Report</h1>
  <p>静的解析結果のサマリーです。ファイル本体は実行していません。</p>

  <section class="card">
    <h2>Summary</h2>
    <table>
      <thead><tr><th>File</th><th>SHA-256</th><th>Class</th><th>Risk</th><th>Reason</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </section>

  <section class="card">
    <h2>Timeline</h2>
    {''.join(event_cards)}
  </section>
</body>
</html>
"""

    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        return {"success": True, "output_path": str(path.resolve()), "error": None}
    except OSError as exc:
        return {"success": False, "output_path": output_path, "error": {"module": "html_report", "code": "write_error", "message": str(exc)}}
