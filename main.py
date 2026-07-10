"""StatikAnalyzer MVP entry point.

Defensive static triage tool:
- Does not execute target files.
- Parses basic PE metadata when applicable.
- Optionally queries VirusTotal by SHA-256 hash only.
- Exports detailed JSON, timeline JSON, and HTML report.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from core.file_loader import get_file_info
from core.hash_calc import calculate_hashes
from core.pe_parser import parse_pe
from core.classifier import classify
from integrations.virus_client import lookup_file_hash
from reports.html_report import generate_html_report
from timeline.event_builder import build_timeline_events
from timeline.exporter import save_json


SUPPORTED_DEFAULT_GLOBS = ["*"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def collect_targets(target: str, recursive: bool = False) -> List[Path]:
    """Return file targets from a single file or directory."""
    path = Path(target).expanduser()
    if path.is_file():
        return [path]
    if path.is_dir():
        if recursive:
            return sorted([p for p in path.rglob("*") if p.is_file()])
        return sorted([p for p in path.iterdir() if p.is_file()])
    return [path]


def analyze_file(file_path: str, use_vt: bool = True, vt_api_key: str | None = None) -> Dict[str, Any]:
    """Run local static analysis and optional VT hash lookup for one file."""
    analysis: Dict[str, Any] = {
        "schema_version": "1.0",
        "tool": "StatikAnalyzer",
        "analysis_time": utc_now(),
        "file_info": {},
        "hashes": {},
        "pe_analysis": {},
        "vt_result": {},
        "classification": {},
        "errors": [],
    }

    file_result = get_file_info(file_path)
    analysis["errors"].extend(file_result.get("errors", []))
    analysis["file_info"] = file_result.get("file_info", {})

    if not file_result.get("success"):
        analysis["classification"] = classify(analysis)
        return analysis

    resolved_path = analysis["file_info"]["file_path"]

    hash_result = calculate_hashes(resolved_path)
    analysis["errors"].extend(hash_result.get("errors", []))
    analysis["hashes"] = hash_result.get("hashes", {})

    pe_result = parse_pe(resolved_path)
    analysis["errors"].extend(pe_result.get("errors", []))
    analysis["pe_analysis"] = pe_result

    if use_vt:
        vt_result = lookup_file_hash(analysis["hashes"].get("sha256"), api_key=vt_api_key)
        if vt_result.get("error"):
            analysis["errors"].append(vt_result["error"])
        analysis["vt_result"] = vt_result
    else:
        analysis["vt_result"] = {
            "queried": False,
            "found": False,
            "stats": {},
            "error": {"module": "virus_client", "code": "vt_disabled"},
        }

    analysis["classification"] = classify(analysis)
    return analysis


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="StatikAnalyzer MVP: defensive static file triage")
    parser.add_argument("target", help="解析対象ファイルまたはディレクトリ")
    parser.add_argument("-o", "--output-dir", default="output", help="出力ディレクトリ")
    parser.add_argument("--recursive", action="store_true", help="ディレクトリ指定時に再帰的に解析")
    parser.add_argument("--no-vt", action="store_true", help="VirusTotal照会を行わない")
    parser.add_argument("--vt-api-key", default=None, help="VirusTotal APIキー。未指定時は環境変数 VIRUSTOTAL_API_KEY / VT_API_KEY を使用")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = collect_targets(args.target, recursive=args.recursive)
    analyses: List[Dict[str, Any]] = []

    for target in targets:
        result = analyze_file(str(target), use_vt=not args.no_vt, vt_api_key=args.vt_api_key)
        analyses.append(result)
        cls = result.get("classification", {})
        file_name = result.get("file_info", {}).get("file_name", str(target))
        print(f"[{cls.get('classification', 'unknown'):>19}] score={cls.get('risk_score', 0):>3} {file_name}")

    timeline_events = build_timeline_events(analyses)

    analysis_json = output_dir / "analysis.json"
    timeline_json = output_dir / "timeline.json"
    report_html = output_dir / "report.html"

    save_json(analyses if len(analyses) != 1 else analyses[0], str(analysis_json))
    save_json(timeline_events, str(timeline_json))
    generate_html_report(analyses, timeline_events, str(report_html))

    print("\n出力完了:")
    print(f"- 詳細JSON: {analysis_json}")
    print(f"- タイムラインJSON: {timeline_json}")
    print(f"- HTMLレポート: {report_html}")


if __name__ == "__main__":
    main()
