"""Crash reporting for the fuzz engine, compatible with triage pipeline."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional


class CrashReporter:
    def __init__(self, output_dir: str) -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def report_crash(
        self,
        crash_data: dict,
        input_data: bytes,
        crash_id: str,
    ) -> Path:
        """Write crash JSON and input file. Returns path to JSON file.

        JSON schema matches what triage/pipeline.py:_normalise() expects:
        {
            "crash_id": "crash-001",
            "fault_type": "hard_fault",
            "cfsr": 131072,
            "registers": {"pc": 4680, "sp": 536903680, "lr": 4352, ...},
            "fault_address": 1073741824,
            "backtrace": [],
            "input_file": "crash-001.bin",
            "timestamp": 1709000000
        }
        """
        input_filename = f"{crash_id}.bin"

        # Write input file
        input_path = self._output_dir / input_filename
        input_path.write_bytes(input_data)

        # Build crash report JSON
        report = {
            "crash_id": crash_id,
            "fault_type": crash_data.get("fault_type", "unknown"),
            "cfsr": crash_data.get("cfsr", 0),
            "registers": crash_data.get("registers", {}),
            "fault_address": crash_data.get("fault_address", 0),
            "backtrace": crash_data.get("backtrace", []),
            "input_file": input_filename,
            "input_size": len(input_data),
            "timestamp": crash_data.get("timestamp", int(time.time())),
        }

        json_path = self._output_dir / f"{crash_id}.json"
        with json_path.open("w") as f:
            json.dump(report, f, indent=2)

        return json_path

    @staticmethod
    def deduplicate(crash_data: dict, existing_crashes: list[dict]) -> bool:
        """Returns True if crash is unique (different PC or different CFSR flags)."""
        pc = crash_data.get("registers", {}).get("pc", 0)
        cfsr = crash_data.get("cfsr", 0)

        for existing in existing_crashes:
            existing_pc = existing.get("registers", {}).get("pc", 0)
            existing_cfsr = existing.get("cfsr", 0)
            if pc == existing_pc and cfsr == existing_cfsr:
                return False  # duplicate

        return True  # unique
