"""Tests for the crash triage pipeline (classifier, minimizer, pipeline, CLI)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from rtosploit.triage.classifier import (
    Exploitability,
    ExploitabilityClassifier,
    TriageResult,
)
from rtosploit.triage.minimizer import CrashMinimizer
from rtosploit.triage.pipeline import TriagePipeline, TriagedCrash
from rtosploit.reporting.models import finding_from_triaged_crash


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _crash(crash_type: str = "HardFault", cfsr: int = 0, pc: int = 0x0800_0100,
           fault_address: int = 0, registers: dict | None = None) -> dict:
    """Build a minimal crash_data dict for classifier tests."""
    return {
        "crash_type": crash_type,
        "cfsr": cfsr,
        "pc": pc,
        "fault_address": fault_address,
        "registers": registers or {},
        "stack_trace": [],
        "pre_crash_events": [],
    }


# ---------------------------------------------------------------------------
# Exploitability enum
# ---------------------------------------------------------------------------

class TestExploitabilityEnum:
    def test_values(self):
        assert Exploitability.EXPLOITABLE.value == "exploitable"
        assert Exploitability.PROBABLY_EXPLOITABLE.value == "probably_exploitable"
        assert Exploitability.PROBABLY_NOT.value == "probably_not_exploitable"
        assert Exploitability.UNKNOWN.value == "unknown"


# ---------------------------------------------------------------------------
# TriageResult dataclass
# ---------------------------------------------------------------------------

class TestTriageResult:
    def test_creation_defaults(self):
        tr = TriageResult(exploitability=Exploitability.UNKNOWN)
        assert tr.exploitability == Exploitability.UNKNOWN
        assert tr.reasons == []
        assert tr.cfsr_flags == []
        assert tr.fault_type == "unknown"
        assert tr.write_target is None
        assert tr.pc_control is False
        assert tr.sp_control is False


# ---------------------------------------------------------------------------
# ExploitabilityClassifier
# ---------------------------------------------------------------------------

class TestClassifier:
    """Test MSEC-style classification rules for Cortex-M crashes."""

    def setup_method(self):
        self.clf = ExploitabilityClassifier()

    def test_iaccviol_exploitable(self):
        result = self.clf.classify(_crash(cfsr=1 << 0))  # IACCVIOL
        assert result.exploitability == Exploitability.EXPLOITABLE
        assert "IACCVIOL" in result.cfsr_flags

    def test_ibuserr_exploitable(self):
        result = self.clf.classify(_crash(cfsr=1 << 8))  # IBUSERR
        assert result.exploitability == Exploitability.EXPLOITABLE
        assert "IBUSERR" in result.cfsr_flags

    def test_stack_canary_violation_exploitable(self):
        result = self.clf.classify(_crash(crash_type="StackCanaryViolation"))
        assert result.exploitability == Exploitability.EXPLOITABLE
        assert any("canary" in r.lower() for r in result.reasons)

    def test_heap_metadata_corruption_exploitable(self):
        result = self.clf.classify(_crash(crash_type="HeapMetadataCorruption"))
        assert result.exploitability == Exploitability.EXPLOITABLE
        assert any("heap" in r.lower() for r in result.reasons)

    def test_daccviol_probably_exploitable(self):
        result = self.clf.classify(_crash(cfsr=1 << 1))  # DACCVIOL
        assert result.exploitability == Exploitability.PROBABLY_EXPLOITABLE
        assert "DACCVIOL" in result.cfsr_flags

    def test_mstkerr_probably_exploitable(self):
        result = self.clf.classify(_crash(cfsr=1 << 4))  # MSTKERR
        assert result.exploitability == Exploitability.PROBABLY_EXPLOITABLE
        assert "MSTKERR" in result.cfsr_flags

    def test_undefinstr_probably_not(self):
        result = self.clf.classify(_crash(cfsr=1 << 16))  # UNDEFINSTR
        assert result.exploitability == Exploitability.PROBABLY_NOT
        assert "UNDEFINSTR" in result.cfsr_flags

    def test_divbyzero_probably_not(self):
        result = self.clf.classify(_crash(cfsr=1 << 25))  # DIVBYZERO
        assert result.exploitability == Exploitability.PROBABLY_NOT
        assert "DIVBYZERO" in result.cfsr_flags

    def test_unknown_fault(self):
        result = self.clf.classify(_crash(crash_type="unknown", cfsr=0))
        assert result.exploitability == Exploitability.UNKNOWN

    def test_pc_control_detected(self):
        """PC outside normal code range triggers EXPLOITABLE + pc_control flag."""
        result = self.clf.classify(_crash(pc=0xDEAD_BEEF, cfsr=0))
        assert result.exploitability == Exploitability.EXPLOITABLE
        assert result.pc_control is True

    def test_sp_control_detected(self):
        """SP outside normal stack range sets sp_control flag."""
        result = self.clf.classify(
            _crash(cfsr=1 << 1, registers={"sp": 0x0000_0004})
        )
        assert result.sp_control is True


# ---------------------------------------------------------------------------
# CrashMinimizer
# ---------------------------------------------------------------------------

class TestMinimizer:
    def test_reduces_input_with_always_crash(self):
        """With a crash_check_fn that always returns True, input should shrink."""
        minimizer = CrashMinimizer(firmware_path="/fake/fw.elf")
        original = b"A" * 256
        result = minimizer.minimize(original, crash_check_fn=lambda _data: True)
        assert len(result) < len(original)

    def test_returns_original_if_already_minimal(self):
        """Single byte cannot be further reduced."""
        minimizer = CrashMinimizer(firmware_path="/fake/fw.elf")
        original = b"X"
        result = minimizer.minimize(original, crash_check_fn=lambda _data: True)
        assert result == original

    def test_no_check_fn_halves_once(self):
        """Without crash_check_fn, binary halve runs once."""
        minimizer = CrashMinimizer(firmware_path="/fake/fw.elf")
        original = b"A" * 100
        result = minimizer.minimize(original)
        assert len(result) == 50

    def test_minimize_file(self, tmp_path):
        """minimize_file writes reduced output and returns bytes saved."""
        minimizer = CrashMinimizer(firmware_path="/fake/fw.elf")
        inp = tmp_path / "crash_input"
        inp.write_bytes(b"B" * 200)
        out = tmp_path / "crash_input.min"

        saved = minimizer.minimize_file(str(inp), str(out))
        assert saved > 0
        assert out.read_bytes() == b"B" * 100


# ---------------------------------------------------------------------------
# TriagePipeline
# ---------------------------------------------------------------------------

class TestPipeline:
    def test_processes_crash_directory(self, tmp_path):
        """Pipeline loads JSON files, classifies, and returns TriagedCrash list."""
        # Create sample crash JSONs
        crash1 = {
            "crash_id": "crash-001",
            "fault_type": "StackCanaryViolation",
            "cfsr": 0,
            "pc": 0x0800_1234,
            "fault_address": 0,
            "registers": {"r0": 0, "sp": 0x2000_FF00},
            "backtrace": [0x0800_1234, 0x0800_0100],
            "input_file": "input_001.bin",
            "input_size": 64,
            "timestamp": 1700000000,
        }
        crash2 = {
            "crash_id": "crash-002",
            "fault_type": "HardFault",
            "cfsr": 1 << 25,  # DIVBYZERO
            "pc": 0x0800_5678,
            "fault_address": 0,
            "registers": {"sp": 0x2000_8000},
            "backtrace": [],
            "input_file": "input_002.bin",
            "input_size": 32,
            "timestamp": 1700000001,
        }

        (tmp_path / "crash-001.json").write_text(json.dumps(crash1))
        (tmp_path / "crash-002.json").write_text(json.dumps(crash2))
        # Create dummy input files so minimizer doesn't skip
        (tmp_path / "input_001.bin").write_bytes(b"\x00" * 64)
        (tmp_path / "input_002.bin").write_bytes(b"\x00" * 32)

        pipeline = TriagePipeline(
            firmware_path="/fake/fw.elf",
            minimize=False,  # skip QEMU-dependent minimization
        )
        results = pipeline.run(str(tmp_path))

        assert len(results) == 2
        # Sorted by exploitability: EXPLOITABLE first
        assert results[0].crash_id == "crash-001"
        assert results[0].triage_result.exploitability == Exploitability.EXPLOITABLE
        assert results[1].crash_id == "crash-002"
        assert results[1].triage_result.exploitability == Exploitability.PROBABLY_NOT

    def test_empty_directory(self, tmp_path):
        pipeline = TriagePipeline(firmware_path="/fake/fw.elf", minimize=False)
        results = pipeline.run(str(tmp_path))
        assert results == []


# ---------------------------------------------------------------------------
# finding_from_triaged_crash converter
# ---------------------------------------------------------------------------

class TestFindingFromTriagedCrash:
    def test_converts_exploitable(self):
        tr = TriageResult(
            exploitability=Exploitability.EXPLOITABLE,
            reasons=["Stack canary violation"],
            cfsr_flags=[],
            fault_type="StackCanaryViolation",
        )
        tc = TriagedCrash(
            crash_id="crash-test",
            original_input="/tmp/input.bin",
            minimized_input="/tmp/input.bin.min",
            triage_result=tr,
            original_size=128,
            minimized_size=32,
            crash_data={
                "fault_type": "StackCanaryViolation",
                "pc": 0x0800_AAAA,
                "fault_address": 0,
                "registers": {},
                "timestamp": 1700000000,
            },
        )
        finding = finding_from_triaged_crash(tc)
        assert finding.severity == "critical"
        assert finding.exploitability == "exploitable"
        assert finding.category == "crash"
        assert "StackCanaryViolation" in finding.title

    def test_severity_mapping(self):
        """PROBABLY_NOT maps to low severity."""
        tr = TriageResult(
            exploitability=Exploitability.PROBABLY_NOT,
            fault_type="UsageFault",
        )
        tc = TriagedCrash(
            crash_id="crash-low",
            original_input="/tmp/in.bin",
            minimized_input=None,
            triage_result=tr,
            original_size=10,
            minimized_size=None,
            crash_data={"fault_type": "UsageFault", "pc": 0x0800_0100},
        )
        finding = finding_from_triaged_crash(tc)
        assert finding.severity == "low"


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

class TestTriageCLI:
    def test_help(self):
        from rtosploit.cli.commands.triage import triage as triage_cmd

        runner = CliRunner()
        result = runner.invoke(triage_cmd, ["--help"])
        assert result.exit_code == 0
        assert "crash-dir" in result.output
        assert "firmware" in result.output
        assert "minimize" in result.output
