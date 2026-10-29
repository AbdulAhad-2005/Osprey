"""FORENSICS_TOOLS — tool catalog definitions."""

from __future__ import annotations

from osprey.schemas.tools import ToolCategory, ToolDefinition, ToolSafetyLevel
from osprey.services.tool_definitions._builders import _COMMON_PARAMS, _p, _t


# ---- FORENSICS (6 tools) --------------------------------------------------

FORENSICS_TOOLS: list[ToolDefinition] = [
    _t("exiftool_extract", ToolCategory.FORENSICS, "exiftool", ToolSafetyLevel.PASSIVE,
       "Extract metadata from files (images, PDFs, etc).",
       ["metadata", "forensics", "extraction"],
       {"file_path": _p("", "Target file path"), **_COMMON_PARAMS}),
    _t("foremost_carving", ToolCategory.FORENSICS, "foremost", ToolSafetyLevel.PASSIVE,
       "File carving and recovery from disk images.",
       ["forensics", "recovery", "carving"],
       {"input_file": _p("", "Input file/image"),
        "output_dir": _p("/tmp/foremost_output", "Output directory"),
        **_COMMON_PARAMS}),
    _t("steghide_analysis", ToolCategory.FORENSICS, "steghide", ToolSafetyLevel.ACTIVE,
       "Steganography analysis and extraction.",
       ["steganography", "forensics", "extraction"],
       {"file_path": _p("", "Stego file"),
        "password": _p("", "Password (if known)"),
        **_COMMON_PARAMS}),
    _t("hashpump_attack", ToolCategory.FORENSICS, "hashpump", ToolSafetyLevel.GATED,
       "Hash length extension attack tool.",
       ["hash", "crypto", "extension"],
       {"signature": _p("", "Original signature"),
        "data": _p("", "Original data"),
        "additional_data": _p("", "Data to append"),
        "key_length": _p("", "Key length to try"),
        **_COMMON_PARAMS}),
    _t("volatility_analyze", ToolCategory.FORENSICS, "volatility", ToolSafetyLevel.ACTIVE,
       "Memory forensics analysis (Volatility 2).",
       ["memory", "forensics", "analysis"],
       {"image_path": _p("", "Memory dump path"),
        "profile": _p("", "Memory profile"),
        "plugin": _p("", "Volatility plugin"),
        **_COMMON_PARAMS}),
    _t("volatility3_analyze", ToolCategory.FORENSICS, "volatility3", ToolSafetyLevel.ACTIVE,
       "Memory forensics analysis (Volatility 3).",
       ["memory", "forensics", "analysis"],
       {"image_path": _p("", "Memory dump path"),
        "plugin": _p("", "Volatility 3 plugin"),
        **_COMMON_PARAMS}),
]
