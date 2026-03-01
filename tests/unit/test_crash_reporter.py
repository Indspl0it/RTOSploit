"""Tests for the fuzzing crash reporter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rtosploit.fuzzing.crash_reporter import CrashReporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _crash_data(
    fault_type: str = "hard_fault",
    cfsr: int = 131072,
    pc: int = 0x1248,
    sp: int = 0x2000_F000,
    lr: int = 0x1100,
    fault_address: int = 0x4000_0000,
    timestamp: int = 1709000000,
) -> dict:
    """Build a minimal crash_data dict matching triage pipeline schema."""
    return {
        "fault_type": fault_type,
        "cfsr": cfsr,
        "registers": {"pc": pc, "sp": sp, "lr": lr},
        "fault_address": fault_address,
        "backtrace": [],
        "timestamp": timestamp,
    }


# ---------------------------------------------------------------------------
# CrashReporter.report_crash
# ---------------------------------------------------------------------------

class TestReportCrash:
    def test_writes_valid_json(self, tmp_path: Path) -> None:
        reporter = CrashReporter(str(tmp_path / "crashes"))
        data = _crash_data()
        input_bytes = b"\xde\xad\xbe\xef"

        json_path = reporter.report_crash(data, input_bytes, "crash-001")

        assert json_path.exists()
        report = json.loads(json_path.read_text())
        assert isinstance(report, dict)

    def test_writes_input_bin_file(self, tmp_path: Path) -> None:
        reporter = CrashReporter(str(tmp_path / "crashes"))
        data = _crash_data()
        input_bytes = b"\x01\x02\x03\x04"

        reporter.report_crash(data, input_bytes, "crash-002")

        bin_path = tmp_path / "crashes" / "crash-002.bin"
        assert bin_path.exists()
        assert bin_path.read_bytes() == input_bytes

    def test_json_contains_all_required_fields(self, tmp_path: Path) -> None:
        reporter = CrashReporter(str(tmp_path / "crashes"))
        data = _crash_data()
        input_bytes = b"\xff" * 16

        json_path = reporter.report_crash(data, input_bytes, "crash-003")
        report = json.loads(json_path.read_text())

        # Fields expected by triage/pipeline.py:_normalise()
        assert report["crash_id"] == "crash-003"
        assert report["fault_type"] == "hard_fault"
        assert report["cfsr"] == 131072
        assert report["registers"] == {"pc": 0x1248, "sp": 0x2000_F000, "lr": 0x1100}
        assert report["fault_address"] == 0x4000_0000
        assert report["backtrace"] == []
        assert report["input_file"] == "crash-003.bin"
        assert report["input_size"] == 16
        assert report["timestamp"] == 1709000000

    def test_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "nested" / "crashes"
        reporter = CrashReporter(str(nested))
        data = _crash_data()

        json_path = reporter.report_crash(data, b"\x00", "crash-004")

        assert json_path.exists()
        assert nested.is_dir()

    def test_defaults_for_missing_crash_data_keys(self, tmp_path: Path) -> None:
        reporter = CrashReporter(str(tmp_path / "crashes"))
        # Minimal crash_data missing most keys
        data: dict = {}
        json_path = reporter.report_crash(data, b"\xab", "crash-005")
        report = json.loads(json_path.read_text())

        assert report["fault_type"] == "unknown"
        assert report["cfsr"] == 0
        assert report["registers"] == {}
        assert report["fault_address"] == 0
        assert report["backtrace"] == []


# ---------------------------------------------------------------------------
# CrashReporter.deduplicate
# ---------------------------------------------------------------------------

class TestDeduplicate:
    def test_unique_crash_different_pc(self) -> None:
        new = _crash_data(pc=0x2000)
        existing = [_crash_data(pc=0x1000)]
        assert CrashReporter.deduplicate(new, existing) is True

    def test_unique_crash_different_cfsr(self) -> None:
        new = _crash_data(cfsr=0x0002_0000)
        existing = [_crash_data(cfsr=0x0004_0000)]
        assert CrashReporter.deduplicate(new, existing) is True

    def test_duplicate_crash_same_pc_and_cfsr(self) -> None:
        new = _crash_data(pc=0x1248, cfsr=131072)
        existing = [_crash_data(pc=0x1248, cfsr=131072)]
        assert CrashReporter.deduplicate(new, existing) is False

    def test_empty_existing_crashes(self) -> None:
        new = _crash_data()
        assert CrashReporter.deduplicate(new, []) is True

    def test_duplicate_among_multiple_existing(self) -> None:
        new = _crash_data(pc=0x1248, cfsr=131072)
        existing = [
            _crash_data(pc=0x9999, cfsr=0),
            _crash_data(pc=0x1248, cfsr=131072),
            _crash_data(pc=0xAAAA, cfsr=1),
        ]
        assert CrashReporter.deduplicate(new, existing) is False

    def test_unique_same_pc_different_cfsr(self) -> None:
        """Same PC but different CFSR means different fault -- unique."""
        new = _crash_data(pc=0x1248, cfsr=0x0002_0000)
        existing = [_crash_data(pc=0x1248, cfsr=0x0004_0000)]
        assert CrashReporter.deduplicate(new, existing) is True

    def test_unique_same_cfsr_different_pc(self) -> None:
        """Same CFSR but different PC means different location -- unique."""
        new = _crash_data(pc=0x2000, cfsr=131072)
        existing = [_crash_data(pc=0x1000, cfsr=131072)]
        assert CrashReporter.deduplicate(new, existing) is True
