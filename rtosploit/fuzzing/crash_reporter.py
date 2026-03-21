"""Crash reporting for the fuzz engine, compatible with triage pipeline."""

from __future__ import annotations

import json
import time
from pathlib import Path


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

    # Maximum byte distance between two PCs to consider them "nearby" —
    # crashes in the same function but at different call depths often land
    # within a small offset of each other.
    PC_PROXIMITY_THRESHOLD = 64

    @staticmethod
    def deduplicate(crash_data: dict, existing_crashes: list[dict]) -> bool:
        """Returns True if crash is unique.

        A crash is considered duplicate if ANY of the following match an
        existing crash:
        1. Exact PC **and** exact CFSR (original fast-path).
        2. Nearby PC (within ``PC_PROXIMITY_THRESHOLD`` bytes) **and** exact
           CFSR — catches the same fault at slightly different call depths.
        3. Matching top-3 backtrace frames (when both crashes carry a
           ``backtrace`` list with at least one entry).
        """
        pc = crash_data.get("registers", {}).get("pc", 0)
        cfsr = crash_data.get("cfsr", 0)
        backtrace = crash_data.get("backtrace", [])
        top_frames = backtrace[:3] if backtrace else []

        for existing in existing_crashes:
            existing_pc = existing.get("registers", {}).get("pc", 0)
            existing_cfsr = existing.get("cfsr", 0)

            # 1. Exact PC + CFSR (fast path)
            if pc == existing_pc and cfsr == existing_cfsr:
                return False

            # 2. Nearby PC + same CFSR
            if cfsr == existing_cfsr and abs(pc - existing_pc) <= CrashReporter.PC_PROXIMITY_THRESHOLD:
                return False

            # 3. Stack-trace dedup: top 3 frames match
            if top_frames:
                existing_bt = existing.get("backtrace", [])
                existing_top = existing_bt[:3] if existing_bt else []
                if existing_top and top_frames == existing_top:
                    return False

        return True  # unique
