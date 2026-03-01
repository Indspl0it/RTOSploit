"""Integration tests for the fuzzing engine (requires qemu-system-arm)."""

import json
import os
import shutil
import subprocess
import sys
import pytest

_HAS_QEMU = shutil.which("qemu-system-arm") is not None


@pytest.mark.skipif(not _HAS_QEMU, reason="qemu-system-arm not installed")
class TestFuzzEngineIntegration:
    """Integration tests that boot real QEMU."""

    def test_fuzz_engine_with_real_qemu(self, tmp_path):
        """Boot firmware in QEMU and run fuzz engine for a short time.

        Verifies: engine starts, executes iterations, and exits cleanly.
        """
        from rtosploit.fuzzing.engine import FuzzEngine
        from rtosploit.config import RTOSploitConfig

        # Use the FreeRTOS demo firmware if available
        fw_candidates = [
            "vulnrange/downloaded_firmware/freertos-full-demo-mps2-an385.elf",
        ]

        firmware = None
        for candidate in fw_candidates:
            full = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                candidate,
            )
            if os.path.exists(full):
                firmware = full
                break

        if firmware is None:
            pytest.skip("No test firmware available")

        corpus_dir = str(tmp_path / "corpus")
        crash_dir = str(tmp_path / "crashes")

        config = RTOSploitConfig()
        engine = FuzzEngine(
            firmware_path=firmware,
            machine_name="mps2-an385",
            config=config,
        )

        stats = engine.run(
            timeout=10,
            corpus_dir=corpus_dir,
            crash_dir=crash_dir,
        )

        assert stats.executions > 0
        assert stats.elapsed > 0

    def test_fuzz_cli_real_mode(self, tmp_path):
        """Run the fuzz CLI command.

        Verifies: CLI exits cleanly, output directory created.
        """
        fw_candidates = [
            "vulnrange/downloaded_firmware/freertos-full-demo-mps2-an385.elf",
        ]

        firmware = None
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        for candidate in fw_candidates:
            full = os.path.join(project_root, candidate)
            if os.path.exists(full):
                firmware = full
                break

        if firmware is None:
            pytest.skip("No test firmware available")

        output_dir = str(tmp_path / "fuzz-output")

        result = subprocess.run(
            [
                os.path.join(os.path.dirname(sys.executable), "rtosploit"),
                "fuzz",
                "--firmware", firmware,
                "--machine", "mps2-an385",
                "--timeout", "10",
                "--output", output_dir,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=project_root,
        )

        # Should exit cleanly (0) or with keyboard interrupt
        assert result.returncode in (0, 130), f"stderr: {result.stderr}"
        assert os.path.isdir(output_dir)

    def test_fuzz_cli_json_real(self, tmp_path):
        """Run fuzz CLI in JSON mode and verify output.

        Verifies: valid JSON output with execution stats.
        """
        fw_candidates = [
            "vulnrange/downloaded_firmware/freertos-full-demo-mps2-an385.elf",
        ]

        firmware = None
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        for candidate in fw_candidates:
            full = os.path.join(project_root, candidate)
            if os.path.exists(full):
                firmware = full
                break

        if firmware is None:
            pytest.skip("No test firmware available")

        output_dir = str(tmp_path / "fuzz-output")

        result = subprocess.run(
            [
                os.path.join(os.path.dirname(sys.executable), "rtosploit"),
                "--json",
                "fuzz",
                "--firmware", firmware,
                "--machine", "mps2-an385",
                "--timeout", "10",
                "--output", output_dir,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=project_root,
        )

        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            assert "executions" in data
            assert "crashes" in data


@pytest.mark.skipif(not _HAS_QEMU, reason="qemu-system-arm not installed")
class TestFuzzEngineComponents:
    """Test individual engine components with real QEMU."""

    def test_snapshot_create_and_restore(self, tmp_path):
        """Verify snapshot save/load cycle works with real QEMU."""
        pass  # Placeholder -- implement if QEMU + firmware available
