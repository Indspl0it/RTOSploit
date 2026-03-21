"""Unit tests for the CI/CD pipeline module."""

from __future__ import annotations

import struct

import pytest
from click.testing import CliRunner

from rtosploit.ci.pipeline import CIConfig, CIPipeline
from rtosploit.cli.main import cli
from rtosploit.reporting.models import Finding


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def tiny_firmware(tmp_path):
    """Create a minimal raw firmware file for testing."""
    fw = tmp_path / "fw.bin"
    data = struct.pack("<II", 0x20002000, 0x00000101) + b"\x00" * 56
    fw.write_bytes(data)
    return str(fw)


def _make_finding(severity: str = "medium", category: str = "cve") -> Finding:
    """Helper to create a minimal Finding with a given severity."""
    return Finding(
        id=f"test-{severity}",
        title=f"Test {severity} finding",
        severity=severity,
        category=category,
        description=f"A {severity} finding for testing.",
    )


# ---------------------------------------------------------------------------
# CIConfig tests
# ---------------------------------------------------------------------------

class TestCIConfig:
    def test_defaults(self):
        cfg = CIConfig(firmware_path="/tmp/fw.bin")
        assert cfg.firmware_path == "/tmp/fw.bin"
        assert cfg.machine == "mps2-an385"
        assert cfg.fuzz_timeout == 60
        assert cfg.output_dir == "scan-output"
        assert cfg.formats == ["sarif", "html"]
        assert cfg.fail_on == "critical"
        assert cfg.skip_fuzz is False
        assert cfg.skip_cve is False
        assert cfg.minimize is True
        assert cfg.architecture == "armv7m"

    def test_custom_values(self):
        cfg = CIConfig(
            firmware_path="/opt/firmware.elf",
            machine="lm3s6965evb",
            fuzz_timeout=300,
            output_dir="/tmp/results",
            formats=["sarif"],
            fail_on="high",
            skip_fuzz=True,
            skip_cve=True,
            minimize=False,
            architecture="armv8m",
        )
        assert cfg.firmware_path == "/opt/firmware.elf"
        assert cfg.machine == "lm3s6965evb"
        assert cfg.fuzz_timeout == 300
        assert cfg.output_dir == "/tmp/results"
        assert cfg.formats == ["sarif"]
        assert cfg.fail_on == "high"
        assert cfg.skip_fuzz is True
        assert cfg.skip_cve is True
        assert cfg.minimize is False
        assert cfg.architecture == "armv8m"


# ---------------------------------------------------------------------------
# _determine_exit_code tests
# ---------------------------------------------------------------------------

class TestDetermineExitCode:
    def test_no_findings_returns_zero(self):
        cfg = CIConfig(firmware_path="/tmp/fw.bin")
        pipeline = CIPipeline(cfg)
        pipeline.findings = []
        assert pipeline._determine_exit_code() == 0

    def test_critical_finding_with_fail_on_critical_returns_one(self):
        cfg = CIConfig(firmware_path="/tmp/fw.bin", fail_on="critical")
        pipeline = CIPipeline(cfg)
        pipeline.findings = [_make_finding("critical")]
        assert pipeline._determine_exit_code() == 1

    def test_medium_finding_with_fail_on_critical_returns_zero(self):
        cfg = CIConfig(firmware_path="/tmp/fw.bin", fail_on="critical")
        pipeline = CIPipeline(cfg)
        pipeline.findings = [_make_finding("medium")]
        assert pipeline._determine_exit_code() == 0

    def test_any_finding_with_fail_on_any_returns_one(self):
        cfg = CIConfig(firmware_path="/tmp/fw.bin", fail_on="any")
        pipeline = CIPipeline(cfg)
        pipeline.findings = [_make_finding("info")]
        assert pipeline._determine_exit_code() == 1

    def test_high_finding_with_fail_on_high_returns_one(self):
        cfg = CIConfig(firmware_path="/tmp/fw.bin", fail_on="high")
        pipeline = CIPipeline(cfg)
        pipeline.findings = [_make_finding("high")]
        assert pipeline._determine_exit_code() == 1

    def test_low_finding_with_fail_on_high_returns_zero(self):
        cfg = CIConfig(firmware_path="/tmp/fw.bin", fail_on="high")
        pipeline = CIPipeline(cfg)
        pipeline.findings = [_make_finding("low")]
        assert pipeline._determine_exit_code() == 0

    def test_multiple_findings_threshold(self):
        """Only the highest severity matters against threshold."""
        cfg = CIConfig(firmware_path="/tmp/fw.bin", fail_on="high")
        pipeline = CIPipeline(cfg)
        pipeline.findings = [
            _make_finding("low"),
            _make_finding("medium"),
            _make_finding("high"),
        ]
        assert pipeline._determine_exit_code() == 1


# ---------------------------------------------------------------------------
# scan CLI --help
# ---------------------------------------------------------------------------

class TestScanCLI:
    def test_scan_help(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--firmware" in result.output
        assert "--machine" in result.output
        assert "--fuzz-timeout" in result.output
        assert "--format" in result.output
        assert "--output" in result.output
        assert "--fail-on" in result.output
        assert "--skip-fuzz" in result.output
        assert "--skip-cve" in result.output
        assert "--no-minimize" in result.output
        assert "--architecture" in result.output

    def test_scan_listed_in_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output


# ---------------------------------------------------------------------------
# Full pipeline run (skip-fuzz, skip-cve)
# ---------------------------------------------------------------------------

class TestPipelineRun:
    def test_skip_fuzz_skip_cve_exits_zero(self, tiny_firmware, tmp_path):
        """Pipeline with --skip-fuzz --skip-cve on minimal firmware completes cleanly."""
        cfg = CIConfig(
            firmware_path=tiny_firmware,
            output_dir=str(tmp_path / "out"),
            skip_fuzz=True,
            skip_cve=True,
            formats=["sarif"],
        )
        pipeline = CIPipeline(cfg)
        exit_code = pipeline.run()
        assert exit_code == 0
        assert pipeline.metadata.get("firmware_size", 0) > 0
        # Verify output file was created
        assert (tmp_path / "out" / "report.sarif.json").exists()
