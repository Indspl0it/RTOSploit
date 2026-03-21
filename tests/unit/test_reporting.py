"""Tests for the RTOSploit reporting module.

Covers Finding/EngagementReport models, converters, SARIF generator,
HTML generator, and the report CLI command. No QEMU required.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from rtosploit.cli.main import cli
from rtosploit.reporting.models import (
    EngagementReport,
    Finding,
    finding_from_exploit_result,
    finding_from_fuzz_report,
)
from rtosploit.reporting.sarif import SARIFGenerator
from rtosploit.reporting.html import HTMLGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        id="test-001",
        title="Stack buffer overflow",
        severity="high",
        category="crash",
        description="Stack overflow in task_main",
        crash_type="stack_overflow",
        pc=0x0800_1234,
        fault_address=0x2000_FFFC,
        registers={"r0": 0x0, "r1": 0x1, "sp": 0x2000_FF00},
        stack_trace=[0x0800_1234, 0x0800_0100, 0x0800_0050],
        dedup_hash="abc123",
        timestamp=1700000000,
    )


@pytest.fixture
def sample_exploit_finding() -> Finding:
    return Finding(
        id="exploit-001",
        title="Exploit: freertos/heap_overflow",
        severity="critical",
        category="exploit",
        description="Heap overflow exploit",
        cve="CVE-2021-12345",
        exploit_module="freertos/heap_overflow",
        exploit_status="success",
    )


@pytest.fixture
def sample_report(sample_finding, sample_exploit_finding) -> EngagementReport:
    return EngagementReport(
        engagement_id="test-engagement-1",
        timestamp=1700000000,
        target_firmware="test_fw.bin",
        target_rtos="freertos",
        target_architecture="armv7m",
        findings=[sample_finding, sample_exploit_finding],
    )


@pytest.fixture
def empty_report() -> EngagementReport:
    return EngagementReport(
        engagement_id="empty-engagement",
        timestamp=1700000000,
        target_firmware="empty.bin",
    )


@pytest.fixture
def fuzz_report_data() -> dict:
    return {
        "id": "fuzz-001",
        "timestamp": 1700000000,
        "crash_type": "heap_buffer_overflow",
        "severity": "high",
        "pc": 0x0800_ABCD,
        "fault_address": 0x2001_0000,
        "registers": {"r0": 0x41414141, "r1": 0x0, "sp": 0x2000_FE00},
        "stack_trace": [0x0800_ABCD, 0x0800_0200],
        "input_data": "AAAA",
        "reproducer_path": "/tmp/crash_001.bin",
        "dedup_hash": "deadbeef01",
        "input_hash": "cafebabe",
    }


@pytest.fixture
def exploit_result_data() -> dict:
    return {
        "module": "freertos/tcb_overwrite",
        "status": "success",
        "target_rtos": "freertos",
        "architecture": "armv7m",
        "technique": "heap_metadata_corruption",
        "payload_delivered": True,
        "payload_type": "shellcode",
        "achieved": ["code_execution"],
        "registers_at_payload": {},
        "notes": ["Overwrote TCB linked list pointer"],
        "cve": "CVE-2023-99999",
    }


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

class TestFinding:
    def test_creation_and_field_access(self, sample_finding):
        assert sample_finding.id == "test-001"
        assert sample_finding.severity == "high"
        assert sample_finding.category == "crash"
        assert sample_finding.pc == 0x0800_1234
        assert sample_finding.fault_address == 0x2000_FFFC
        assert "sp" in sample_finding.registers
        assert len(sample_finding.stack_trace) == 3
        assert sample_finding.dedup_hash == "abc123"

    def test_defaults(self):
        f = Finding(id="x", title="t", severity="low", category="crash", description="d")
        assert f.crash_type is None
        assert f.pc is None
        assert f.registers == {}
        assert f.stack_trace == []
        assert f.timestamp == 0


# ---------------------------------------------------------------------------
# EngagementReport model
# ---------------------------------------------------------------------------

class TestEngagementReport:
    def test_creation(self, sample_report):
        assert sample_report.engagement_id == "test-engagement-1"
        assert sample_report.target_firmware == "test_fw.bin"
        assert sample_report.target_rtos == "freertos"
        assert len(sample_report.findings) == 2

    def test_empty_report(self, empty_report):
        assert empty_report.findings == []
        assert empty_report.coverage_stats is None


# ---------------------------------------------------------------------------
# Converters
# ---------------------------------------------------------------------------

class TestConverters:
    def test_finding_from_fuzz_report_full(self, fuzz_report_data):
        f = finding_from_fuzz_report(fuzz_report_data)
        assert f.id == "fuzz-001"
        assert f.category == "crash"
        assert f.crash_type == "heap_buffer_overflow"
        assert f.severity == "high"
        assert f.pc == 0x0800_ABCD
        assert f.fault_address == 0x2001_0000
        assert f.registers["r0"] == 0x41414141
        assert len(f.stack_trace) == 2
        assert f.input_data == "AAAA"
        assert f.reproducer_path == "/tmp/crash_001.bin"
        assert f.dedup_hash == "deadbeef01"
        assert "0x0800abcd" in f.title.lower()

    def test_finding_from_fuzz_report_minimal(self):
        minimal = {"crash_type": "unknown"}
        f = finding_from_fuzz_report(minimal)
        assert f.category == "crash"
        assert f.severity == "medium"  # default
        assert f.pc is None
        assert f.registers == {}
        assert f.id  # should have an auto-generated id

    def test_finding_from_exploit_result(self, exploit_result_data):
        f = finding_from_exploit_result(exploit_result_data)
        assert f.category == "exploit"
        assert f.exploit_module == "freertos/tcb_overwrite"
        assert f.exploit_status == "success"
        assert f.cve == "CVE-2023-99999"
        assert f.severity == "critical"  # has CVE
        assert "CVE-2023-99999" in f.title

    def test_finding_from_exploit_result_no_cve(self):
        data = {
            "module": "zephyr/stack_smash",
            "status": "failure",
            "target_rtos": "zephyr",
            "technique": "stack_pivot",
            "notes": [],
        }
        f = finding_from_exploit_result(data)
        assert f.severity == "medium"  # failure, no CVE
        assert f.cve is None


# ---------------------------------------------------------------------------
# SARIF generator
# ---------------------------------------------------------------------------

class TestSARIFGenerator:
    def test_produces_valid_structure(self, sample_report):
        sarif = SARIFGenerator().generate(sample_report)
        assert "$schema" in sarif
        assert "version" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run

    def test_correct_schema_and_version(self, sample_report):
        sarif = SARIFGenerator().generate(sample_report)
        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_tool_driver_name(self, sample_report):
        from rtosploit import __version__
        sarif = SARIFGenerator().generate(sample_report)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "RTOSploit"
        assert driver["version"] == __version__

    def test_severity_mapping(self, sample_report):
        sarif = SARIFGenerator().generate(sample_report)
        results = sarif["runs"][0]["results"]
        # First finding is "high" -> "error"
        assert results[0]["level"] == "error"
        # Second finding is "critical" -> "error"
        assert results[1]["level"] == "error"

    def test_severity_mapping_medium_and_info(self):
        findings = [
            Finding(id="m1", title="Med", severity="medium", category="crash",
                    description="d", dedup_hash="med1"),
            Finding(id="i1", title="Info", severity="info", category="crash",
                    description="d", dedup_hash="info1"),
        ]
        report = EngagementReport(
            engagement_id="t", timestamp=0, target_firmware="fw",
            findings=findings,
        )
        sarif = SARIFGenerator().generate(report)
        results = sarif["runs"][0]["results"]
        assert results[0]["level"] == "warning"
        assert results[1]["level"] == "note"

    def test_rules_match_unique_dedup_hashes(self, sample_report):
        sarif = SARIFGenerator().generate(sample_report)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        # sample_finding has dedup_hash "abc123", exploit_finding uses its id
        rule_ids = {r["id"] for r in rules}
        assert "abc123" in rule_ids
        assert len(rules) == 2

    def test_empty_report_valid_output(self, empty_report):
        sarif = SARIFGenerator().generate(empty_report)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_generate_json_is_string(self, sample_report):
        result = SARIFGenerator().generate_json(sample_report)
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["version"] == "2.1.0"

    def test_write_creates_file(self, sample_report, tmp_path):
        out = str(tmp_path / "test.sarif.json")
        SARIFGenerator().write(sample_report, out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"


# ---------------------------------------------------------------------------
# HTML generator
# ---------------------------------------------------------------------------

class TestHTMLGenerator:
    def test_produces_html_with_doctype(self, sample_report):
        html = HTMLGenerator().generate(sample_report)
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_contains_finding_details(self, sample_report):
        html = HTMLGenerator().generate(sample_report)
        assert "Stack buffer overflow" in html
        assert "test-engagement-1" in html
        assert "freertos" in html

    def test_empty_report_valid_output(self, empty_report):
        html = HTMLGenerator().generate(empty_report)
        assert "<!DOCTYPE html>" in html
        assert "No findings recorded" in html

    def test_write_creates_file(self, sample_report, tmp_path):
        out = str(tmp_path / "report.html")
        HTMLGenerator().write(sample_report, out)
        assert os.path.exists(out)
        with open(out) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

class TestReportCLI:
    def test_report_help(self, runner):
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0
        assert "--input-dir" in result.output
        assert "--format" in result.output
        assert "--output" in result.output

    def test_report_generates_files(self, runner, tmp_path, fuzz_report_data, exploit_result_data):
        """Create mock JSON input files and verify report generation."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        output_dir = tmp_path / "output"

        # Write sample crash JSON
        crash_file = input_dir / "crash_001.json"
        crash_file.write_text(json.dumps(fuzz_report_data))

        # Write sample exploit JSON
        exploit_file = input_dir / "exploit_001.json"
        exploit_file.write_text(json.dumps(exploit_result_data))

        result = runner.invoke(cli, [
            "report",
            "-i", str(input_dir),
            "-o", str(output_dir),
            "-f", "both",
            "--firmware", "test_fw.bin",
        ])
        assert result.exit_code == 0

        # Verify both files were created
        assert (output_dir / "report.sarif.json").exists()
        assert (output_dir / "report.html").exists()

        # Validate SARIF content
        with open(output_dir / "report.sarif.json") as f:
            sarif = json.load(f)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 2

        # Validate HTML content
        with open(output_dir / "report.html") as f:
            html = f.read()
        assert "<!DOCTYPE html>" in html

    def test_report_sarif_only(self, runner, tmp_path, fuzz_report_data):
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        output_dir = tmp_path / "output"

        (input_dir / "crash.json").write_text(json.dumps(fuzz_report_data))

        result = runner.invoke(cli, [
            "report",
            "-i", str(input_dir),
            "-o", str(output_dir),
            "-f", "sarif",
        ])
        assert result.exit_code == 0
        assert (output_dir / "report.sarif.json").exists()
        assert not (output_dir / "report.html").exists()

    def test_report_html_only(self, runner, tmp_path, fuzz_report_data):
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        output_dir = tmp_path / "output"

        (input_dir / "crash.json").write_text(json.dumps(fuzz_report_data))

        result = runner.invoke(cli, [
            "report",
            "-i", str(input_dir),
            "-o", str(output_dir),
            "-f", "html",
        ])
        assert result.exit_code == 0
        assert (output_dir / "report.html").exists()
        assert not (output_dir / "report.sarif.json").exists()

    def test_report_empty_input(self, runner, tmp_path):
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        output_dir = tmp_path / "output"

        result = runner.invoke(cli, [
            "report",
            "-i", str(input_dir),
            "-o", str(output_dir),
        ])
        assert result.exit_code == 0
