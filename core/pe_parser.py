"""Minimal PE parser for defensive static triage.

The parser reads PE structures directly from bytes. It never executes target files.
It intentionally extracts a small, stable subset useful for MVP triage.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import struct
from typing import Any, Dict, List

from core.entropy import calculate_section_entropy

MACHINE_TYPES = {
    0x014C: "Intel 386",
    0x8664: "AMD64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}

SECTION_FLAGS = {
    0x00000020: "code",
    0x00000040: "initialized_data",
    0x00000080: "uninitialized_data",
    0x02000000: "discardable",
    0x20000000: "execute",
    0x40000000: "read",
    0x80000000: "write",
}

DLL_CHARACTERISTICS = {
    0x0040: "dynamic_base_ASLR",
    0x0100: "nx_compat_DEP",
    0x0400: "no_seh",
    0x4000: "control_flow_guard",
    0x8000: "terminal_server_aware",
}


def _read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _timestamp_to_iso(ts: int) -> str | None:
    if ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _decode_section_name(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace") or "<unnamed>"


def _flags_from_mask(mask: int, table: Dict[int, str]) -> List[str]:
    return [name for flag, name in table.items() if mask & flag]


def parse_pe(file_path: str) -> Dict[str, Any]:
    """Parse PE headers and section metadata.

    Return keys:
      success: parser completed without structural parse error
      is_pe: target is a valid enough PE for this MVP parser
      pe_info: extracted PE metadata
      sections: list of section dictionaries
      errors: non-fatal or fatal parser errors
    """
    result: Dict[str, Any] = {
        "success": False,
        "is_pe": False,
        "pe_info": {},
        "sections": [],
        "errors": [],
    }

    path = Path(file_path)

    try:
        data = path.read_bytes()
    except FileNotFoundError:
        result["errors"].append({"module": "pe_parser", "code": "file_not_found"})
        return result
    except PermissionError:
        result["errors"].append({"module": "pe_parser", "code": "permission_denied"})
        return result
    except OSError as exc:
        result["errors"].append({"module": "pe_parser", "code": "read_error", "message": str(exc)})
        return result

    if len(data) < 64:
        result["success"] = True
        result["errors"].append({"module": "pe_parser", "code": "non_pe_too_small"})
        return result

    if data[:2] != b"MZ":
        result["success"] = True
        result["errors"].append({"module": "pe_parser", "code": "non_pe_missing_mz"})
        return result

    try:
        e_lfanew = _read_u32(data, 0x3C)
    except struct.error as exc:
        result["errors"].append({"module": "pe_parser", "code": "dos_header_parse_error", "message": str(exc)})
        return result

    if e_lfanew <= 0 or e_lfanew + 24 > len(data):
        result["errors"].append({
            "module": "pe_parser",
            "code": "invalid_e_lfanew",
            "message": f"e_lfanew points outside file: {e_lfanew}",
        })
        return result

    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        result["errors"].append({"module": "pe_parser", "code": "missing_pe_signature"})
        return result

    try:
        coff_offset = e_lfanew + 4
        machine = _read_u16(data, coff_offset)
        number_of_sections = _read_u16(data, coff_offset + 2)
        time_date_stamp = _read_u32(data, coff_offset + 4)
        size_of_optional_header = _read_u16(data, coff_offset + 16)
        characteristics = _read_u16(data, coff_offset + 18)

        optional_offset = coff_offset + 20
        if optional_offset + size_of_optional_header > len(data):
            result["errors"].append({"module": "pe_parser", "code": "optional_header_out_of_range"})
            return result

        magic = _read_u16(data, optional_offset)
        if magic == 0x10B:
            pe_type = "PE32"
            image_base = _read_u32(data, optional_offset + 28)
        elif magic == 0x20B:
            pe_type = "PE32+"
            image_base = _read_u64(data, optional_offset + 24)
        else:
            result["errors"].append({
                "module": "pe_parser",
                "code": "unknown_optional_header_magic",
                "message": hex(magic),
            })
            return result

        address_of_entry_point = _read_u32(data, optional_offset + 16)
        section_alignment = _read_u32(data, optional_offset + 32)
        file_alignment = _read_u32(data, optional_offset + 36)
        size_of_image = _read_u32(data, optional_offset + 56)
        size_of_headers = _read_u32(data, optional_offset + 60)
        subsystem_value = _read_u16(data, optional_offset + 68)
        dll_characteristics = _read_u16(data, optional_offset + 70)

        section_table_offset = optional_offset + size_of_optional_header
        section_table_size = number_of_sections * 40
        if section_table_offset + section_table_size > len(data):
            result["errors"].append({"module": "pe_parser", "code": "section_table_out_of_range"})
            return result

        sections: List[Dict[str, Any]] = []
        for i in range(number_of_sections):
            off = section_table_offset + (i * 40)
            name = _decode_section_name(data[off:off + 8])
            virtual_size = _read_u32(data, off + 8)
            virtual_address = _read_u32(data, off + 12)
            size_of_raw_data = _read_u32(data, off + 16)
            pointer_to_raw_data = _read_u32(data, off + 20)
            section_characteristics = _read_u32(data, off + 36)

            raw_data = b""
            raw_data_available = False
            if size_of_raw_data > 0 and pointer_to_raw_data < len(data):
                end = min(pointer_to_raw_data + size_of_raw_data, len(data))
                raw_data = data[pointer_to_raw_data:end]
                raw_data_available = True

            entropy_result = calculate_section_entropy(name, raw_data)
            if entropy_result.get("error"):
                result["errors"].append(entropy_result["error"])

            sections.append({
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": hex(virtual_address),
                "size_of_raw_data": size_of_raw_data,
                "pointer_to_raw_data": pointer_to_raw_data,
                "raw_data_available": raw_data_available,
                "characteristics_hex": hex(section_characteristics),
                "characteristics": _flags_from_mask(section_characteristics, SECTION_FLAGS),
                "entropy": entropy_result.get("entropy"),
                "entropy_level": entropy_result.get("entropy_level"),
            })

        result.update({
            "success": True,
            "is_pe": True,
            "pe_info": {
                "dos_signature": "MZ",
                "pe_signature": "PE\\0\\0",
                "e_lfanew": e_lfanew,
                "machine": MACHINE_TYPES.get(machine, f"Unknown ({hex(machine)})"),
                "machine_hex": hex(machine),
                "number_of_sections": number_of_sections,
                "time_date_stamp": time_date_stamp,
                "compile_timestamp_utc": _timestamp_to_iso(time_date_stamp),
                "size_of_optional_header": size_of_optional_header,
                "characteristics_hex": hex(characteristics),
                "optional_header": {
                    "magic": hex(magic),
                    "type": pe_type,
                    "address_of_entry_point": hex(address_of_entry_point),
                    "image_base": hex(image_base),
                    "section_alignment": section_alignment,
                    "file_alignment": file_alignment,
                    "size_of_image": size_of_image,
                    "size_of_headers": size_of_headers,
                    "subsystem": SUBSYSTEMS.get(subsystem_value, f"Unknown ({subsystem_value})"),
                    "subsystem_value": subsystem_value,
                    "dll_characteristics_hex": hex(dll_characteristics),
                    "dll_characteristics": _flags_from_mask(dll_characteristics, DLL_CHARACTERISTICS),
                },
            },
            "sections": sections,
        })
        return result
    except struct.error as exc:
        result["errors"].append({"module": "pe_parser", "code": "pe_struct_parse_error", "message": str(exc)})
        return result
    except Exception as exc:
        result["errors"].append({"module": "pe_parser", "code": "pe_parse_unexpected_error", "message": str(exc)})
        return result
