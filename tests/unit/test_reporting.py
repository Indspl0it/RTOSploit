"""Tests for the RTOSploit reporting module.

Covers Finding/EngagementReport models, converters, SARIF generator,
HTML generator, and the report CLI command. No QEMU required.
"""
from __future__ import annotations

import json
import os

import pytest
from click.testing import CliRunner

from rtosploit.cli.main import cli
from rtosploit.reporting.models import (
    CoverageStats,
    EngagementReport,
    Finding,
    FuzzCampaignStats,
    PeripheralSummary,
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
        title="Scanner: freertos/heap_overflow",
        severity="critical",
        category="scanner",
        description="Heap overflow exploit",
        cve="CVE-2021-12345",
        exploit_module="freertos/heap_overflow",
        exploit_status="success",
    )


@pytest.fixture
def sample_pip_finding() -> Finding:
    """Finding from PIP/Unicorn engine with new fields."""
    return Finding(
        id="pip-001",
        title="Crash: unmapped_access at PC=0x08001000",
        severity="high",
        category="crash",
        description="Unmapped memory access",
        crash_type="unmapped_access",
        pc=0x0800_1000,
        fault_address=0xDEAD_0000,
        stop_reason="unmapped_access",
        engine_type="unicorn",
        blocks_executed=1500,
        pip_stats={
            "total_reads": 42,
            "total_writes": 10,
            "replay_count": 30,
            "new_value_count": 12,
            "replay_percentage": 71.4,
        },
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
def full_report(sample_finding, sample_exploit_finding, sample_pip_finding) -> EngagementReport:
    """Report with all optional sections populated."""
    return EngagementReport(
        engagement_id="full-engagement-1",
        timestamp=1700000000,
        target_firmware="test_fw.elf",
        target_rtos="freertos",
        target_version="10.4.3",
        target_architecture="armv7m",
        findings=[sample_finding, sample_exploit_finding, sample_pip_finding],
        coverage_stats=CoverageStats(
            edge_count=1234,
            total_hits=56789,
            bitmap_size=65536,
            coverage_type="fermcov",
            coverage_pct=1.88,
        ),
        fuzz_stats=FuzzCampaignStats(
            executions=50000,
            crashes=12,
            unique_crashes=5,
            exec_per_sec=833.3,
            elapsed_seconds=60.0,
            corpus_size=42,
            engine_type="unicorn",
            coverage=CoverageStats(
                edge_count=1234,
                total_hits=56789,
                coverage_type="fermcov",
                coverage_pct=1.88,
            ),
        ),
        peripheral_summary=PeripheralSummary(
            total_detected=3,
            layers_run=["symbol", "register_mmio", "binary_signature"],
            mcu_family="STM32F4",
            peripherals=[
                {"name": "UART1", "type": "uart", "confidence": 1.5,
                 "confidence_level": "high", "base_address": "0x40011000",
                 "vendor": "ST", "evidence_count": 4},
                {"name": "SPI0", "type": "spi", "confidence": 0.8,
                 "confidence_level": "medium", "base_address": "0x40013000",
                 "vendor": "ST", "evidence_count": 2},
            ],
        ),
        metadata={"mcu_family": "STM32F4"},
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
def fuzz_report_data_pip() -> dict:
    """Fuzz report data from PIP/Unicorn engine."""
    return {
        "id": "pip-fuzz-001",
        "timestamp": 1700000000,
        "crash_type": "unmapped_access",
        "severity": "high",
        "pc": 0x0800_1000,
        "fault_address": 0xDEAD_0000,
        "registers": {"r0": 0x0, "sp": 0x2000_F000},
        "stack_trace": [],
        "stop_reason": "unmapped_access",
        "engine_type": "unicorn",
        "blocks_executed": 1500,
        "pip_stats": {
            "total_reads": 42,
            "total_writes": 10,
            "replay_count": 30,
            "new_value_count": 12,
            "replay_percentage": 71.4,
        },
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
        assert f.stop_reason is None
        assert f.engine_type is None
        assert f.blocks_executed == 0
        assert f.pip_stats is None

    def test_new_fields(self, sample_pip_finding):
        assert sample_pip_finding.stop_reason == "unmapped_access"
        assert sample_pip_finding.engine_type == "unicorn"
        assert sample_pip_finding.blocks_executed == 1500
        assert sample_pip_finding.pip_stats is not None
        assert sample_pip_finding.pip_stats["total_reads"] == 42
        assert sample_pip_finding.pip_stats["replay_percentage"] == 71.4


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
        assert empty_report.fuzz_stats is None
        assert empty_report.peripheral_summary is None

    def test_full_report_sections(self, full_report):
        assert full_report.coverage_stats is not None
        assert full_report.coverage_stats.edge_count == 1234
        assert full_report.coverage_stats.coverage_type == "fermcov"
        assert full_report.fuzz_stats is not None
        assert full_report.fuzz_stats.executions == 50000
        assert full_report.fuzz_stats.engine_type == "unicorn"
        assert full_report.peripheral_summary is not None
        assert full_report.peripheral_summary.total_detected == 3
        assert full_report.peripheral_summary.mcu_family == "STM32F4"


# ---------------------------------------------------------------------------
# Structured data models
# ---------------------------------------------------------------------------

class TestCoverageStats:
    def test_to_dict(self):
        cs = CoverageStats(
            edge_count=100, total_hits=500,
            coverage_type="fermcov", coverage_pct=0.15,
        )
        d = cs.to_dict()
        assert d["edge_count"] == 100
        assert d["coverage_type"] == "fermcov"
        assert d["bitmap_size"] == 65536

    def test_defaults(self):
        cs = CoverageStats()
        assert cs.edge_count == 0
        assert cs.coverage_type == "basic"


class TestFuzzCampaignStats:
    def test_to_dict(self):
        fs = FuzzCampaignStats(
            executions=1000, crashes=5, unique_crashes=3,
            exec_per_sec=166.7, elapsed_seconds=6.0,
            corpus_size=20, engine_type="unicorn",
        )
        d = fs.to_dict()
        assert d["executions"] == 1000
        assert d["engine_type"] == "unicorn"
        assert d["exec_per_sec"] == 166.7

    def test_to_dict_with_coverage(self):
        fs = FuzzCampaignStats(
            executions=100,
            coverage=CoverageStats(edge_count=50),
        )
        d = fs.to_dict()
        assert "coverage" in d
        assert d["coverage"]["edge_count"] == 50


class TestPeripheralSummary:
    def test_to_dict(self):
        ps = PeripheralSummary(
            total_detected=2,
            layers_run=["symbol", "register_mmio"],
            mcu_family="STM32F4",
            peripherals=[{"name": "UART1", "type": "uart"}],
        )
        d = ps.to_dict()
        assert d["total_detected"] == 2
        assert d["mcu_family"] == "STM32F4"
        assert len(d["peripherals"]) == 1


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

    def test_finding_from_fuzz_report_pip(self, fuzz_report_data_pip):
        """Fuzz report from PIP/Unicorn engine includes new fields."""
        f = finding_from_fuzz_report(fuzz_report_data_pip)
        assert f.stop_reason == "unmapped_access"
        assert f.engine_type == "unicorn"
        assert f.blocks_executed == 1500
        assert f.pip_stats is not None
        assert f.pip_stats["total_reads"] == 42
        assert "Stop reason: unmapped_access" in f.description
        assert "Engine: unicorn" in f.description
        assert "Blocks executed: 1500" in f.description

    def test_finding_from_exploit_result(self, exploit_result_data):
        f = finding_from_exploit_result(exploit_result_data)
        assert f.category == "scanner"
        assert f.exploit_module == "freertos/tcb_overwrite"
        assert f.exploit_status == "success"
        assert f.cve == "CVE-2023-99999"
        assert f.severity == "critical"  # has CVE
        assert "CVE-2023-99999" in f.title
        assert "Scanner:" in f.title

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

    def test_pip_finding_properties(self, sample_pip_finding):
        """SARIF output includes PIP/Unicorn-specific properties."""
        report = EngagementReport(
            engagement_id="pip-test", timestamp=0, target_firmware="fw",
            findings=[sample_pip_finding],
        )
        sarif = SARIFGenerator().generate(report)
        result = sarif["runs"][0]["results"][0]
        props = result["properties"]
        assert props["stopReason"] == "unmapped_access"
        assert props["engineType"] == "unicorn"
        assert props["blocksExecuted"] == 1500
        assert props["pipStats"]["total_reads"] == 42

    def test_full_report_run_properties(self, full_report):
        """SARIF run-level properties include fuzz stats, coverage, peripherals."""
        sarif = SARIFGenerator().generate(full_report)
        run = sarif["runs"][0]
        assert "properties" in run
        props = run["properties"]
        assert "fuzzStats" in props
        assert props["fuzzStats"]["executions"] == 50000
        assert props["fuzzStats"]["engine_type"] == "unicorn"
        assert "coverageStats" in props
        assert props["coverageStats"]["edge_count"] == 1234
        assert "peripheralSummary" in props
        assert props["peripheralSummary"]["total_detected"] == 3


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

    def test_full_report_renders_sections(self, full_report):
        """HTML report renders fuzz stats, coverage, and peripheral sections."""
        html = HTMLGenerator().generate(full_report)
        # Fuzz stats section
        assert "Fuzzing Campaign" in html
        assert "50000" in html  # executions
        assert "unicorn" in html  # engine type
        # Coverage section
        assert "Coverage" in html
        assert "1234" in html  # edge count
        assert "fermcov" in html  # coverage type
        # Peripheral section
        assert "Peripheral Detection" in html
        assert "STM32F4" in html  # MCU family
        assert "UART1" in html  # detected peripheral

    def test_pip_finding_details_rendered(self, sample_pip_finding):
        """HTML detail section includes PIP stats and stop reason."""
        report = EngagementReport(
            engagement_id="pip-html", timestamp=0, target_firmware="fw",
            findings=[sample_pip_finding],
        )
        html = HTMLGenerator().generate(report)
        assert "unmapped_access" in html  # stop reason
        assert "unicorn" in html  # engine
        assert "1500" in html  # blocks executed

    def test_category_counts_rendered(self, full_report):
        """HTML report shows category breakdown cards."""
        html = HTMLGenerator().generate(full_report)
        assert "crash" in html
        assert "scanner" in html


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
