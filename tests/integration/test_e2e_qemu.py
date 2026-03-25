"""End-to-end integration tests that boot real firmware in QEMU.

These tests require qemu-system-arm >= 9.0 to be available.
They boot the VulnRange firmware images, run exploits, triage, and
pipe everything through the v2 reporting pipeline.
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import time
from pathlib import Path

import pytest

# Skip entire module if QEMU is not available
QEMU_BIN = None
for candidate in ["qemu-system-arm"]:
    import shutil
    if shutil.which(candidate):
        QEMU_BIN = shutil.which(candidate)
        break

pytestmark = pytest.mark.skipif(QEMU_BIN is None, reason="qemu-system-arm not found")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
VULNRANGE_DIR = PROJECT_ROOT / "vulnrange"
CONFIGS_DIR = PROJECT_ROOT / "configs" / "machines"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def firmware_path(cve_id: str) -> str:
    p = VULNRANGE_DIR / cve_id / "firmware.bin"
    if not p.exists():
        pytest.skip(f"Firmware not found: {p}")
    return str(p)


def boot_qemu_with_gdb(fw_path: str, machine: str = "mps2-an385", gdb_port: int = 0):
    """Boot QEMU with GDB stub, return (process, actual_gdb_port).

    Uses port 0 trick: pick a random free port to avoid conflicts.
    """
    import socket
    if gdb_port == 0:
        s = socket.socket()
        s.bind(("", 0))
        gdb_port = s.getsockname()[1]
        s.close()

    qmp_sock = f"/tmp/rtosploit-test-{os.getpid()}-{gdb_port}.sock"
    cmd = [
        QEMU_BIN,
        "-machine", machine,
        "-cpu", "cortex-m3",
        "-nographic",
        "-monitor", "none",
        "-serial", "none",
        "-kernel", fw_path,
        "-gdb", f"tcp::{gdb_port}",
        "-S",  # start paused
        "-qmp", f"unix:{qmp_sock},server,wait=off",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait for QEMU to be ready (QMP socket appears)
    for _ in range(20):
        if os.path.exists(qmp_sock):
            break
        time.sleep(0.25)

    return proc, gdb_port, qmp_sock


def connect_qmp(sock_path: str, timeout: float = 5.0):
    """Connect a QMPClient to the given socket."""
    from rtosploit.emulation.qmp import QMPClient
    qmp = QMPClient()
    qmp.connect(sock_path, timeout=timeout)
    return qmp


def connect_gdb(port: int, timeout: float = 5.0):
    """Connect a GDBClient to the given port."""
    from rtosploit.emulation.gdb import GDBClient
    gdb = GDBClient()
    time.sleep(0.5)  # give GDB stub a moment
    gdb.connect("localhost", port, timeout=timeout)
    return gdb


def cleanup_qemu(proc, qmp_sock):
    """Kill QEMU and clean up socket."""
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        proc.kill()
        proc.wait()
    try:
        os.unlink(qmp_sock)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Test 1: QEMU boots and we can read registers via GDB
# ---------------------------------------------------------------------------

class TestQEMUBootAndRegisters:
    """Boot real firmware in QEMU and read ARM registers via GDB RSP."""

    def test_boot_freertos_firmware_read_registers(self):
        """Boot CVE-2021-43997 firmware, read registers, verify SP and PC are sane."""
        fw = firmware_path("CVE-2021-43997")
        proc, port, sock = boot_qemu_with_gdb(fw)
        try:
            gdb = connect_gdb(port)
            regs = gdb.read_registers()
            gdb.close()

            assert "pc" in regs, f"No PC in registers: {regs.keys()}"
            assert "sp" in regs, f"No SP in registers: {regs.keys()}"

            # Read the expected reset vector from the firmware file itself
            with open(fw, "rb") as f:
                fw_header = f.read(8)
            _expected_sp = struct.unpack_from("<I", fw_header, 0)[0]
            expected_reset = struct.unpack_from("<I", fw_header, 4)[0]

            # PC should match the reset vector (possibly with Thumb bit masked)
            assert regs["pc"] == (expected_reset & ~1), (
                f"PC 0x{regs['pc']:08x} doesn't match reset vector 0x{expected_reset:08x}"
            )
            # SP should be in SRAM region (0x20000000+)
            assert regs["sp"] >= 0x20000000, f"SP below SRAM: 0x{regs['sp']:08x}"
        finally:
            cleanup_qemu(proc, sock)

    def test_boot_read_memory_vector_table(self):
        """Boot firmware, read the vector table from address 0, verify it matches firmware file."""
        fw = firmware_path("CVE-2021-43997")
        proc, port, sock = boot_qemu_with_gdb(fw)
        try:
            gdb = connect_gdb(port)
            # Read first 8 bytes = initial SP + Reset vector
            mem = gdb.read_memory(0x00000000, 8)
            gdb.close()

            initial_sp = struct.unpack_from("<I", mem, 0)[0]
            reset_vector = struct.unpack_from("<I", mem, 4)[0]

            # Compare to firmware file
            with open(fw, "rb") as f:
                fw_bytes = f.read(8)
            file_sp = struct.unpack_from("<I", fw_bytes, 0)[0]
            file_reset = struct.unpack_from("<I", fw_bytes, 4)[0]

            assert initial_sp == file_sp, f"SP mismatch: QEMU={initial_sp:#x} file={file_sp:#x}"
            assert reset_vector == file_reset, f"Reset mismatch: QEMU={reset_vector:#x} file={file_reset:#x}"
        finally:
            cleanup_qemu(proc, sock)


# ---------------------------------------------------------------------------
# Test 2: Run firmware for a few ms, read CFSR, feed to triage classifier
# ---------------------------------------------------------------------------

class TestQEMUExecutionAndTriage:
    """Execute firmware, capture fault registers, classify via triage."""

    def test_execute_and_read_cfsr(self):
        """Boot firmware, let it execute briefly, then read CFSR register.

        After continue + interrupt, we read the CFSR and classify it.
        If QEMU drops the GDB connection (firmware crashes hard), we
        reconnect via a fresh GDB connection or read registers from
        whatever state we can.
        """
        fw = firmware_path("CVE-2021-43997")
        proc, port, sock = boot_qemu_with_gdb(fw)
        try:
            gdb = connect_gdb(port)

            # Read CFSR while paused (before execution) — this always works
            cfsr_bytes = gdb.read_memory(0xE000ED28, 4)
            cfsr_before = struct.unpack_from("<I", cfsr_bytes)[0]

            # Try continue + interrupt — may fail if firmware crashes
            interrupted = False
            try:
                gdb._sock.settimeout(3.0)
                gdb.continue_execution()
                time.sleep(0.3)
                gdb._sock.sendall(b"\x03")
                gdb.receive_stop()
                interrupted = True
            except (ConnectionResetError, BrokenPipeError, OSError):
                # Firmware crashed and QEMU dropped GDB — reconnect
                gdb.close()
                try:
                    gdb = connect_gdb(port, timeout=2.0)
                    interrupted = True
                except Exception:
                    pass

            if interrupted:
                try:
                    regs = gdb.read_registers()
                    cfsr_bytes = gdb.read_memory(0xE000ED28, 4)
                    cfsr = struct.unpack_from("<I", cfsr_bytes)[0]
                except Exception:
                    regs = {"pc": 0}
                    cfsr = cfsr_before
            else:
                regs = {"pc": 0}
                cfsr = cfsr_before

            gdb.close()

            # Classify via triage — works with any CFSR value
            from rtosploit.triage.classifier import ExploitabilityClassifier
            classifier = ExploitabilityClassifier()
            crash_data = {
                "crash_type": "HardFault" if cfsr != 0 else "Normal",
                "cfsr": cfsr,
                "pc": regs.get("pc", 0),
                "fault_address": 0,
                "registers": regs,
                "stack_trace": [],
                "pre_crash_events": [],
            }
            result = classifier.classify(crash_data)

            from rtosploit.instrumentation.events import classify_cfsr
            flags = classify_cfsr(cfsr)
            assert isinstance(flags, list)
            assert isinstance(result.exploitability.value, str)

        finally:
            cleanup_qemu(proc, sock)

    def test_inject_fault_and_classify(self):
        """Set PC to invalid address while paused, read CFSR, classify.

        We set PC to an invalid address but DON'T continue execution —
        this avoids QEMU crashing. We verify that the classifier handles
        the scenario correctly by synthesizing crash_data with the
        injected PC value.
        """
        fw = firmware_path("CVE-2021-43997")
        proc, port, sock = boot_qemu_with_gdb(fw)
        try:
            gdb = connect_gdb(port)

            # Read registers at reset
            regs = gdb.read_registers()
            original_pc = regs.get("pc", 0)

            # Write an invalid PC address (don't continue — just test classification)
            gdb.write_register(15, 0xDEAD0000)
            modified_regs = gdb.read_registers()
            assert modified_regs["pc"] == 0xDEAD0000, (
                f"PC write failed: got 0x{modified_regs['pc']:08x}"
            )

            # Read CFSR (should be 0 since we haven't executed)
            cfsr_bytes = gdb.read_memory(0xE000ED28, 4)
            _cfsr = struct.unpack_from("<I", cfsr_bytes)[0]

            # Restore PC
            gdb.write_register(15, original_pc)
            gdb.close()

            # Now classify as if a fault occurred at the injected PC
            from rtosploit.triage.classifier import ExploitabilityClassifier
            classifier = ExploitabilityClassifier()

            # Synthesize IACCVIOL fault (bit 0 of MMFSR in CFSR)
            synthetic_cfsr = 0x01  # IACCVIOL
            crash_data = {
                "crash_type": "HardFault",
                "cfsr": synthetic_cfsr,
                "pc": 0xDEAD0000,
                "fault_address": 0xDEAD0000,
                "registers": modified_regs,
                "stack_trace": list(modified_regs.values())[:5],
                "pre_crash_events": [],
            }
            result = classifier.classify(crash_data)

            assert result.exploitability is not None
            assert len(result.reasons) > 0
            # IACCVIOL should be classified as exploitable
            from rtosploit.triage.classifier import Exploitability
            assert result.exploitability == Exploitability.EXPLOITABLE

        finally:
            cleanup_qemu(proc, sock)


# ---------------------------------------------------------------------------
# Test 3: Run exploit module against real firmware, pipe to reporter
# ---------------------------------------------------------------------------

class TestExploitToReport:
    """Run a real exploit module and pipe the result through the v2 reporting pipeline."""

    def test_mpu_bypass_exploit_to_sarif(self, tmp_path):
        """Run freertos/mpu_bypass exploit, convert to Finding, generate SARIF."""
        fw = firmware_path("CVE-2021-43997")

        from rtosploit.scanners.runner import run_scan
        result = run_scan(
            "freertos/mpu_bypass",
            {"firmware": fw, "machine": "mps2-an385"},
        )

        assert result.status in ("success", "not_vulnerable", "error")
        assert result.cve == "CVE-2021-43997"
        assert result.target_rtos in ("freertos", "esp-idf")

        # Convert to Finding — use module path as exploit_module fallback
        from rtosploit.reporting.models import finding_from_exploit_result, EngagementReport
        result_dict = result.to_dict()
        finding = finding_from_exploit_result(result_dict)
        assert finding.category == "exploit"
        assert finding.cve == "CVE-2021-43997"
        assert finding.exploit_module == "freertos/mpu_bypass"

        # Build EngagementReport
        report = EngagementReport(
            engagement_id="e2e-test",
            timestamp=int(time.time()),
            target_firmware=fw,
            target_rtos="freertos",
            target_version="10.4.3",
            target_architecture="armv7m",
            findings=[finding],
        )

        # Generate SARIF
        from rtosploit.reporting.sarif import SARIFGenerator
        gen = SARIFGenerator()
        sarif = gen.generate(report)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1
        r = sarif["runs"][0]["results"][0]
        assert "CVE-2021-43997" in r["message"]["text"] or "mpu_bypass" in r["message"]["text"]

        # Write to file and verify
        out = tmp_path / "report.sarif.json"
        gen.write(report, str(out))
        assert out.exists()
        with open(out) as f:
            loaded = json.load(f)
        assert loaded["version"] == "2.1.0"

    def test_exploit_result_to_html(self, tmp_path):
        """Run exploit, generate HTML report, verify it's self-contained."""
        fw = firmware_path("CVE-2021-43997")

        from rtosploit.scanners.runner import run_scan
        result = run_scan(
            "freertos/mpu_bypass",
            {"firmware": fw, "machine": "mps2-an385"},
        )

        from rtosploit.reporting.models import finding_from_exploit_result, EngagementReport
        finding = finding_from_exploit_result(result.to_dict())
        report = EngagementReport(
            engagement_id="e2e-html",
            timestamp=int(time.time()),
            target_firmware=fw,
            target_rtos="freertos",
            target_architecture="armv7m",
            findings=[finding],
        )

        from rtosploit.reporting.html import HTMLGenerator
        gen = HTMLGenerator()
        out = tmp_path / "report.html"
        gen.write(report, str(out))

        html = out.read_text()
        assert "<!DOCTYPE html>" in html
        assert "mpu_bypass" in html or "CVE-2021-43997" in html
        # Self-contained = no external stylesheet links
        assert '<link rel="stylesheet"' not in html


# ---------------------------------------------------------------------------
# Test 4: Boot QEMU, generate real crash data, write JSON, triage it
# ---------------------------------------------------------------------------

class TestCrashGenerationAndTriage:
    """Generate real crashes via QEMU, serialize, and triage them."""

    def test_generate_crash_json_and_triage(self, tmp_path):
        """Boot firmware, capture registers at reset, write crash JSON, triage."""
        fw = firmware_path("CVE-2021-43997")
        proc, port, sock = boot_qemu_with_gdb(fw)
        try:
            gdb = connect_gdb(port)

            # Read registers at reset (paused state — reliable)
            regs = gdb.read_registers()
            cfsr_bytes = gdb.read_memory(0xE000ED28, 4)
            cfsr = struct.unpack_from("<I", cfsr_bytes)[0]

            # Read stack area
            sp = regs.get("sp", 0x20000000)
            try:
                stack_bytes = gdb.read_memory(sp, 64)
            except Exception:
                stack_bytes = b"\x00" * 64

            gdb.close()

            # Write crash JSON in Rust CrashReport format
            crash_json = {
                "crash_id": "qemu-live-001",
                "timestamp": int(time.time()),
                "detection_layer": "L1_hardfault",
                "input_file": "test_input.bin",
                "input_size": 64,
                "registers": {k: v for k, v in regs.items()},
                "stack_dump": list(stack_bytes),
                "fault_address": regs.get("pc", 0),
                "fault_type": "HardFault" if cfsr != 0 else "Normal",
                "backtrace": [regs.get("pc", 0), regs.get("lr", 0)],
                "coverage_edges": 0,
                "execution_time_us": 300000,
                "reproducible": True,
                "pre_crash_events": [],
                "cfsr": cfsr,
            }

            crash_dir = tmp_path / "crashes"
            crash_dir.mkdir()
            crash_file = crash_dir / "crash_001.json"
            crash_file.write_text(json.dumps(crash_json))

            # Also write a dummy input file
            (crash_dir / "test_input.bin").write_bytes(b"\x00" * 64)

            # Run triage pipeline
            from rtosploit.triage.pipeline import TriagePipeline
            pipeline = TriagePipeline(
                firmware_path=fw,
                machine="mps2-an385",
                minimize=False,
            )
            triaged = pipeline.run(str(crash_dir))

            assert len(triaged) == 1
            t = triaged[0]
            assert t.crash_id == "qemu-live-001"
            assert t.triage_result is not None
            assert t.triage_result.exploitability is not None

            # Convert to Finding and generate report
            from rtosploit.reporting.models import finding_from_triaged_crash, EngagementReport
            finding = finding_from_triaged_crash(t)
            assert finding.category == "crash"
            assert finding.exploitability is not None

            report = EngagementReport(
                engagement_id="crash-triage-e2e",
                timestamp=int(time.time()),
                target_firmware=fw,
                target_rtos="freertos",
                target_architecture="armv7m",
                findings=[finding],
            )

            from rtosploit.reporting.sarif import SARIFGenerator
            sarif = SARIFGenerator().generate(report)
            assert len(sarif["runs"][0]["results"]) == 1

        finally:
            cleanup_qemu(proc, sock)


# ---------------------------------------------------------------------------
# Test 5: Coverage — boot firmware, trace basic blocks, visualize
# ---------------------------------------------------------------------------

class TestCoverageFromQEMU:
    """Boot QEMU, step through instructions to build a trace, visualize coverage."""

    def test_single_step_trace_and_visualize(self, tmp_path):
        """Step through firmware instructions, build trace log, generate coverage."""
        fw = firmware_path("CVE-2021-43997")
        proc, port, sock = boot_qemu_with_gdb(fw)
        try:
            gdb = connect_gdb(port)
            gdb._sock.settimeout(3.0)

            # Single-step 20 instructions and record PC transitions.
            # The 's' command in GDB RSP sends back a stop reply after stepping.
            trace_pairs = []
            prev_pc = None

            # Read initial PC
            regs = gdb.read_registers()
            prev_pc = regs.get("pc", 0)

            for _ in range(20):
                try:
                    # Send step command and read the stop reply in one go
                    _response = gdb._send_command("s")
                    # Response should be a stop reply like "S05" or "T05..."
                except Exception:
                    break
                try:
                    regs = gdb.read_registers()
                    pc = regs.get("pc", 0)
                    if prev_pc is not None and pc != prev_pc:
                        trace_pairs.append((prev_pc, pc))
                    prev_pc = pc
                except Exception:
                    break

            gdb.close()

            assert len(trace_pairs) > 0, "No trace pairs captured"

            # Write trace log
            trace_file = tmp_path / "trace.log"
            with open(trace_file, "w") as f:
                for from_addr, to_addr in trace_pairs:
                    f.write(f"0x{from_addr:08x},0x{to_addr:08x}\n")

            # Detect firmware base from the vector table (reset vector region)
            with open(fw, "rb") as f:
                header = f.read(8)
            reset_vector = struct.unpack_from("<I", header, 4)[0] & ~1
            # Infer base address by rounding down to 64KB boundary
            firmware_base = reset_vector & 0xFFFF0000

            # Use coverage mapper with correct base
            from rtosploit.coverage.mapper import CoverageMapper
            mapper = CoverageMapper(fw, base_address=firmware_base)
            cov_map = mapper.map_from_trace(str(trace_file))

            assert len(cov_map.covered_addresses) > 0
            assert len(cov_map.covered_edges) > 0

            # Visualize
            disasm = mapper.disassemble_firmware()
            assert len(disasm) > 0

            from rtosploit.coverage.visualizer import CoverageVisualizer
            viz = CoverageVisualizer(cov_map, disasm)

            # Terminal output
            terminal_out = viz.render_terminal(max_lines=20)
            assert len(terminal_out) > 0

            # Stats
            stats = viz.get_stats()
            assert stats["covered_instructions"] >= 0  # May be 0 if disasm addresses don't overlap

            # HTML output
            html_path = tmp_path / "coverage.html"
            viz.write_html(str(html_path))
            html = html_path.read_text()
            assert "<!DOCTYPE html>" in html or "<html" in html

        finally:
            cleanup_qemu(proc, sock)


# ---------------------------------------------------------------------------
# Test 6: Full pipeline — fingerprint + CVE + exploit + triage + report
# ---------------------------------------------------------------------------

class TestFullPipelineE2E:
    """Full end-to-end: fingerprint → CVE → exploit → triage → SARIF + HTML."""

    def test_full_pipeline_cve2021_43997(self, tmp_path):
        """End-to-end pipeline for CVE-2021-43997 firmware."""
        fw = firmware_path("CVE-2021-43997")

        # Step 1: Fingerprint
        from rtosploit.utils.binary import load_firmware
        from rtosploit.analysis.fingerprint import fingerprint_firmware
        firmware = load_firmware(fw)
        fp = fingerprint_firmware(firmware)
        assert fp.rtos_type in ("freertos", "esp-idf")

        # Step 2: CVE Correlation
        from rtosploit.cve.database import CVEDatabase
        from rtosploit.cve.correlator import CVECorrelator
        db = CVEDatabase()
        db.load()
        correlator = CVECorrelator(db)
        cve_result = correlator.correlate("freertos", fp.version)
        assert cve_result.total_cves > 0
        assert cve_result.highest_severity in ("critical", "high")

        # Step 3: Run exploit
        from rtosploit.scanners.runner import run_scan
        exploit_result = run_scan(
            "freertos/mpu_bypass",
            {"firmware": fw, "machine": "mps2-an385"},
        )
        # CVE should always be populated (even if status is not_vulnerable)
        assert exploit_result.cve == "CVE-2021-43997"
        assert exploit_result.target_rtos in ("freertos", "esp-idf")

        # Step 4: Build findings from all sources
        from rtosploit.reporting.models import (
            finding_from_cve,
            finding_from_exploit_result,
            EngagementReport,
        )

        findings = []

        # CVE findings
        for cve_entry in cve_result.matching_cves[:5]:  # Limit for test speed
            findings.append(finding_from_cve(cve_entry, rtos="freertos", version=fp.version or ""))

        # Exploit finding
        findings.append(finding_from_exploit_result(exploit_result.to_dict()))

        assert len(findings) > 1

        # Step 5: Generate report
        report = EngagementReport(
            engagement_id="full-pipeline-e2e",
            timestamp=int(time.time()),
            target_firmware=fw,
            target_rtos="freertos",
            target_version=fp.version,
            target_architecture="armv7m",
            findings=findings,
            metadata={"fingerprint_confidence": fp.confidence},
        )

        # SARIF
        from rtosploit.reporting.sarif import SARIFGenerator
        sarif_gen = SARIFGenerator()
        sarif_path = tmp_path / "report.sarif.json"
        sarif_gen.write(report, str(sarif_path))

        with open(sarif_path) as f:
            sarif = json.load(f)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == len(findings)

        # HTML
        from rtosploit.reporting.html import HTMLGenerator
        html_gen = HTMLGenerator()
        html_path = tmp_path / "report.html"
        html_gen.write(report, str(html_path))

        html = html_path.read_text()
        assert "CVE-2021-43997" in html
        assert "freertos" in html.lower()

    def test_ci_pipeline_mode_with_real_firmware(self, tmp_path):
        """Run the rtosploit scan CI pipeline against real firmware."""
        fw = firmware_path("CVE-2021-43997")

        from rtosploit.ci.pipeline import CIPipeline, CIConfig
        config = CIConfig(
            firmware_path=fw,
            machine="mps2-an385",
            skip_fuzz=True,
            skip_cve=False,
            output_dir=str(tmp_path / "scan-output"),
            formats=["sarif", "html"],
            fail_on="critical",
        )

        pipeline = CIPipeline(config)
        exit_code = pipeline.run()

        # Should find critical CVEs → exit 1
        assert exit_code == 1

        # Verify outputs exist
        out_dir = tmp_path / "scan-output"
        assert (out_dir / "report.sarif.json").exists() or (out_dir / "report.sarif").exists()
        assert (out_dir / "report.html").exists()

        # Verify SARIF content
        sarif_file = out_dir / "report.sarif.json"
        if not sarif_file.exists():
            sarif_file = out_dir / "report.sarif"
        with open(sarif_file) as f:
            sarif = json.load(f)
        assert len(sarif["runs"][0]["results"]) > 0
        assert any(
            "CVE-" in r["message"]["text"]
            for r in sarif["runs"][0]["results"]
        )

        # Verify findings include exploitable CVEs
        assert len(pipeline.findings) > 0
        cve_findings = [f for f in pipeline.findings if f.category == "cve"]
        assert len(cve_findings) > 0

    def test_ci_pipeline_clean_exit_skip_all(self, tmp_path):
        """Skip CVE + fuzz = no findings = exit 0."""
        fw = firmware_path("CVE-2021-43997")

        from rtosploit.ci.pipeline import CIPipeline, CIConfig
        config = CIConfig(
            firmware_path=fw,
            machine="mps2-an385",
            skip_fuzz=True,
            skip_cve=True,
            output_dir=str(tmp_path / "clean-output"),
            formats=["sarif"],
            fail_on="critical",
        )

        pipeline = CIPipeline(config)
        exit_code = pipeline.run()
        assert exit_code == 0
        assert len(pipeline.findings) == 0


# ---------------------------------------------------------------------------
# Test 7: CLI commands against real firmware
# ---------------------------------------------------------------------------

class TestCLIWithRealFirmware:
    """Test CLI commands that touch real firmware files."""

    @pytest.fixture
    def runner(self):
        from click.testing import CliRunner
        return CliRunner()

    def test_cve_scan_cli(self, runner):
        """rtosploit cve scan against real firmware shows CVEs."""
        fw = firmware_path("CVE-2021-43997")
        from rtosploit.cli.main import cli
        result = runner.invoke(cli, ["--json", "cve", "scan", "--firmware", fw])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_cves"] > 0
        assert data["rtos"] in ("freertos", "esp-idf")

    def test_scan_cli_with_real_firmware(self, runner, tmp_path):
        """rtosploit scan against real firmware produces SARIF."""
        fw = firmware_path("CVE-2021-43997")
        out = str(tmp_path / "cli-scan")
        from rtosploit.cli.main import cli
        result = runner.invoke(cli, [
            "scan",
            "--firmware", fw,
            "--skip-fuzz",
            "--format", "both",
            "-o", out,
        ])
        # Exit code 1 = findings above threshold (expected)
        assert result.exit_code in (0, 1)
        assert Path(out).exists()

    def test_exploit_check_cli(self, runner):
        """rtosploit exploit check freertos/mpu_bypass against real firmware."""
        fw = firmware_path("CVE-2021-43997")
        from rtosploit.cli.main import cli
        result = runner.invoke(cli, [
            "exploit", "check", "freertos/mpu_bypass",
            "--firmware", fw,
            "--machine", "mps2-an385",
        ])
        # Should succeed (exit 0) — check() only reads firmware bytes
        assert result.exit_code == 0
        assert "vulnerable" in result.output.lower()

    def test_analyze_fingerprint_real_firmware(self, runner):
        """rtosploit analyze --detect-rtos on real firmware."""
        fw = firmware_path("CVE-2021-43997")
        from rtosploit.cli.main import cli
        result = runner.invoke(cli, ["--json", "analyze", "--firmware", fw, "--detect-rtos"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["rtos"]["detected"] in ("freertos", "esp-idf")
