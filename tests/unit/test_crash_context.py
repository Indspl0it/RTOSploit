"""Tests for enhanced crash context capture."""

import json
import pytest
from pathlib import Path

from rtosploit.fuzzing.crash_reporter import CrashReporter


@pytest.fixture
def tmp_crash_dir(tmp_path):
    """Provide a temporary directory for crash outputs."""
    return str(tmp_path / "crashes")


@pytest.fixture
def full_crash_data():
    """Crash data dict with all rich context fields populated."""
    return {
        "fault_type": "hard_fault",
        "cfsr": 0x00020000,
        "registers": {"pc": 0x08001234, "sp": 0x20010000, "lr": 0x08001100, "xpsr": 0x61000000},
        "fault_address": 0x08001234,
        "backtrace": [],
        "timestamp": 1700000000,
        "stack_dump": "deadbeef" * 32,
        "stack_pointer": 0x20010000,
        "fault_context": "c0ffee00" * 16,
        "fault_context_base": 0x080011F4,
        "vtor": 0x08000000,
        "lr": 0x08001100,
        "xpsr": 0x61000000,
    }


@pytest.fixture
def minimal_crash_data():
    """Old-style crash data with no rich context fields."""
    return {
        "fault_type": "hard_fault",
        "cfsr": 0x00020000,
        "registers": {"pc": 0x08001234, "sp": 0x20010000},
        "fault_address": 0x08001234,
        "backtrace": [],
        "timestamp": 1700000000,
    }


class TestCrashReporterNewFields:
    """Verify CrashReporter includes and handles rich context fields."""

    def test_report_includes_new_fields(self, tmp_crash_dir, full_crash_data):
        reporter = CrashReporter(tmp_crash_dir)
        json_path = reporter.report_crash(full_crash_data, b"\x41\x42", "crash-001")

        report = json.loads(json_path.read_text())

        assert report["stack_dump"] == full_crash_data["stack_dump"]
        assert report["stack_pointer"] == 0x20010000
        assert report["fault_context"] == full_crash_data["fault_context"]
        assert report["fault_context_base"] == 0x080011F4
        assert report["vtor"] == 0x08000000
        assert report["lr"] == 0x08001100
        assert report["xpsr"] == 0x61000000

    def test_missing_new_fields_default_gracefully(self, tmp_crash_dir, minimal_crash_data):
        reporter = CrashReporter(tmp_crash_dir)
        json_path = reporter.report_crash(minimal_crash_data, b"\x00", "crash-002")

        report = json.loads(json_path.read_text())

        assert report["stack_dump"] == ""
        assert report["stack_pointer"] == 0
        assert report["fault_context"] == ""
        assert report["fault_context_base"] == 0
        assert report["vtor"] == 0
        assert report["lr"] == 0
        assert report["xpsr"] == 0

    def test_stack_dump_is_hex_string(self, tmp_crash_dir, full_crash_data):
        reporter = CrashReporter(tmp_crash_dir)
        json_path = reporter.report_crash(full_crash_data, b"\x01", "crash-003")

        report = json.loads(json_path.read_text())

        # Verify it's a valid hex string (can be decoded back to bytes)
        stack_bytes = bytes.fromhex(report["stack_dump"])
        assert len(stack_bytes) > 0
        assert isinstance(report["stack_dump"], str)

    def test_fault_context_is_hex_string(self, tmp_crash_dir, full_crash_data):
        reporter = CrashReporter(tmp_crash_dir)
        json_path = reporter.report_crash(full_crash_data, b"\x02", "crash-004")

        report = json.loads(json_path.read_text())

        fault_bytes = bytes.fromhex(report["fault_context"])
        assert len(fault_bytes) > 0
        assert isinstance(report["fault_context"], str)

    def test_round_trip_preserves_all_fields(self, tmp_crash_dir, full_crash_data):
        reporter = CrashReporter(tmp_crash_dir)
        input_data = b"\xde\xad\xbe\xef"
        crash_id = "crash-005"

        json_path = reporter.report_crash(full_crash_data, input_data, crash_id)

        # Read back
        report = json.loads(json_path.read_text())

        # Original fields preserved
        assert report["crash_id"] == crash_id
        assert report["fault_type"] == "hard_fault"
        assert report["cfsr"] == 0x00020000
        assert report["fault_address"] == 0x08001234
        assert report["input_size"] == 4
        assert report["timestamp"] == 1700000000

        # New fields preserved
        assert report["stack_dump"] == full_crash_data["stack_dump"]
        assert report["stack_pointer"] == full_crash_data["stack_pointer"]
        assert report["fault_context"] == full_crash_data["fault_context"]
        assert report["fault_context_base"] == full_crash_data["fault_context_base"]
        assert report["vtor"] == full_crash_data["vtor"]
        assert report["lr"] == full_crash_data["lr"]
        assert report["xpsr"] == full_crash_data["xpsr"]

        # Input binary preserved
        input_path = Path(tmp_crash_dir) / f"{crash_id}.bin"
        assert input_path.read_bytes() == input_data

    def test_existing_fields_unchanged(self, tmp_crash_dir, full_crash_data):
        """Ensure adding new fields didn't break existing report schema."""
        reporter = CrashReporter(tmp_crash_dir)
        json_path = reporter.report_crash(full_crash_data, b"\xff", "crash-006")

        report = json.loads(json_path.read_text())

        # All original fields must still be present
        assert "crash_id" in report
        assert "fault_type" in report
        assert "cfsr" in report
        assert "registers" in report
        assert "fault_address" in report
        assert "backtrace" in report
        assert "input_file" in report
        assert "input_size" in report
        assert "timestamp" in report

    def test_firmware_path_and_machine_name_in_report(self, tmp_crash_dir):
        """Verify firmware_path and machine_name appear in crash JSON output."""
        crash_data = {
            "fault_type": "hard_fault",
            "cfsr": 0x00020000,
            "registers": {"pc": 0x08001234, "sp": 0x20010000},
            "fault_address": 0x08001234,
            "backtrace": [],
            "timestamp": 1700000000,
            "firmware_path": "/tmp/fw.elf",
            "machine_name": "mps2-an385",
            "inject_addr": 0x20010000,
        }
        reporter = CrashReporter(tmp_crash_dir)
        json_path = reporter.report_crash(crash_data, b"\xaa", "crash-fw-001")

        report = json.loads(json_path.read_text())

        assert report["firmware_path"] == "/tmp/fw.elf"
        assert report["machine_name"] == "mps2-an385"
        assert report["inject_addr"] == 0x20010000

    def test_firmware_path_defaults_when_missing(self, tmp_crash_dir, minimal_crash_data):
        """When firmware_path/machine_name not in crash_data, defaults to empty/zero."""
        reporter = CrashReporter(tmp_crash_dir)
        json_path = reporter.report_crash(minimal_crash_data, b"\x00", "crash-fw-002")

        report = json.loads(json_path.read_text())

        assert report["firmware_path"] == ""
        assert report["machine_name"] == ""
        assert report["inject_addr"] == 0
