"""Rule-based triage classifier for StatikAnalyzer."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _add(score: int, reasons: List[str], points: int, reason: str) -> int:
    reasons.append(reason)
    return score + points


def classify(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Classify a file using local PE features and optional VT stats."""
    score = 0
    reasons: List[str] = []
    warnings: List[str] = []

    file_info = analysis.get("file_info", {}) or {}
    pe_result = analysis.get("pe_analysis", {}) or {}
    vt = analysis.get("vt_result", {}) or {}
    errors = analysis.get("errors", []) or []

    if not file_info:
        return {
            "classification": "error",
            "risk_score": 100,
            "reasons": ["ファイル基本情報を取得できませんでした"],
            "warnings": [],
        }

    if not pe_result.get("is_pe"):
        pe_error_codes = {e.get("code") for e in pe_result.get("errors", []) if isinstance(e, dict)}
        structural_error_codes = {
            "invalid_e_lfanew",
            "missing_pe_signature",
            "optional_header_out_of_range",
            "section_table_out_of_range",
            "unknown_optional_header_magic",
            "pe_struct_parse_error",
        }
        if pe_error_codes & structural_error_codes:
            score = _add(score, reasons, 30, "MZやPE構造に不整合があり、壊れたPEの可能性があります")
        else:
            return {
                "classification": "non_pe",
                "risk_score": 0,
                "reasons": ["PE形式ではないため、PE解析対象外として記録しました"],
                "warnings": [],
            }

    sections = pe_result.get("sections", []) or []
    high_entropy_sections = [s for s in sections if s.get("entropy") is not None and s.get("entropy") >= 7.2]
    executable_writable_sections = [s for s in sections if "execute" in s.get("characteristics", []) and "write" in s.get("characteristics", [])]

    if high_entropy_sections:
        score = _add(score, reasons, min(25, 10 + 5 * len(high_entropy_sections)), f"高エントロピーのセクションが {len(high_entropy_sections)} 個あります")

    if executable_writable_sections:
        score = _add(score, reasons, 20, "実行可能かつ書き込み可能なセクションがあります")

    pe_info = pe_result.get("pe_info", {}) or {}
    if pe_info.get("number_of_sections", 0) >= 10:
        score = _add(score, reasons, 10, "セクション数が多く、構造確認が必要です")

    optional = pe_info.get("optional_header", {}) or {}
    dll_chars = optional.get("dll_characteristics", []) or []
    if pe_result.get("is_pe") and "nx_compat_DEP" not in dll_chars:
        warnings.append("NX/DEP互換フラグが確認できません")
    if pe_result.get("is_pe") and "dynamic_base_ASLR" not in dll_chars:
        warnings.append("ASLRフラグが確認できません")

    stats = vt.get("stats", {}) or {}
    malicious = stats.get("malicious") or 0
    suspicious = stats.get("suspicious") or 0

    if vt.get("queried") and vt.get("found"):
        if malicious >= 3:
            score = _add(score, reasons, 60, f"VirusTotalで malicious={malicious} の検知があります")
        elif malicious >= 1:
            score = _add(score, reasons, 35, f"VirusTotalで malicious={malicious} の検知があります")
        if suspicious >= 1:
            score = _add(score, reasons, 15, f"VirusTotalで suspicious={suspicious} の検知があります")
    elif vt.get("error"):
        warnings.append(f"VirusTotal照会は完了していません: {vt['error'].get('code')}")

    if errors and not reasons:
        warnings.append("解析中にエラーが記録されています")

    score = max(0, min(100, score))

    if score >= 70:
        classification = "malicious_candidate"
    elif score >= 30:
        classification = "suspicious"
    elif vt.get("queried") and not vt.get("found"):
        classification = "unknown"
        if not reasons:
            reasons.append("VirusTotalに登録がなく、ローカル解析上の強い不審点はありません")
    elif pe_result.get("is_pe"):
        classification = "clean"
        if not reasons:
            reasons.append("MVPルール上、強い不審点は確認されませんでした")
    else:
        classification = "unknown"
        if not reasons:
            reasons.append("判断材料が不足しています")

    return {
        "classification": classification,
        "risk_score": score,
        "reasons": reasons,
        "warnings": warnings,
    }
