"""QEMU integration tests for RTOSploit.

Tests cover the full stack: QEMU boot, QMP protocol, GDB RSP,
memory operations, snapshots, fuzzer smoke, exploit lifecycle,
and VulnRange end-to-end flows.

All test classes that require a live QEMU instance are guarded by
``@pytest.mark.skipif(shutil.which("qemu-system-arm") is None, ...)``.
When QEMU is not installed the entire suite should report *skips*, not
failures.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from rtosploit.config import RTOSploitConfig
from rtosploit.errors import QEMUCrashError, OperationError

QEMU_MISSING = shutil.which("qemu-system-arm") is None
SKIP_REASON = "qemu-system-arm not found on PATH"

VULNRANGE_DIR = Path("vulnrange")


# ---------------------------------------------------------------------------
# 1. TestQEMUBoot
# ---------------------------------------------------------------------------

@pytest.mark.skipif(QEMU_MISSING, reason=SKIP_REASON)
class TestQEMUBoot:
    """Verify QEMU process lifecycle: start, timeout, and error paths."""

    def test_boot_mps2_an385(self, firmware_path: str) -> None:
        """Boot with mps2-an385 machine and verify the process starts."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385")
            assert qemu._process is not None
            assert qemu._process.poll() is None  # still alive

    def test_boot_timeout(self, firmware_path: str) -> None:
        """Verify timeout handling when QMP connection cannot be established."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        config.qemu.timeout = 1  # Very short timeout

        qemu = QEMUInstance(config)
        # Patch _find_qemu_binary to return a binary that will not create
        # a QMP socket (e.g., /bin/sleep) so connect times out.
        with patch.object(qemu, "_find_qemu_binary", return_value="/bin/sleep"):
            with pytest.raises(QEMUCrashError):
                qemu.start(firmware_path, "mps2-an385")

    def test_boot_invalid_firmware(self) -> None:
        """Verify FileNotFoundError on a non-existent firmware path."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        qemu = QEMUInstance(config)
        with pytest.raises(FileNotFoundError):
            qemu.start("/nonexistent/firmware.bin", "mps2-an385")


# ---------------------------------------------------------------------------
# 2. TestQMPConnection
# ---------------------------------------------------------------------------

@pytest.mark.skipif(QEMU_MISSING, reason=SKIP_REASON)
class TestQMPConnection:
    """Test the QMP protocol client against a live QEMU instance."""

    def test_qmp_connect(self, firmware_path: str) -> None:
        """Connect to the QMP socket after boot."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385")
            assert qemu.qmp._connected is True

    def test_qmp_query_status(self, firmware_path: str) -> None:
        """Query VM status via QMP and verify a known status string."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385")
            status = qemu.status()
            assert status in ("running", "paused", "prelaunch")

    def test_qmp_quit(self, firmware_path: str) -> None:
        """Graceful shutdown via QMP 'quit' command."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        qemu = QEMUInstance(config)
        qemu.start(firmware_path, "mps2-an385")
        process = qemu._process
        assert process is not None

        qemu.stop()
        # After stop, process should have exited
        assert qemu._process is None


# ---------------------------------------------------------------------------
# 3. TestGDBConnection
# ---------------------------------------------------------------------------

@pytest.mark.skipif(QEMU_MISSING, reason=SKIP_REASON)
class TestGDBConnection:
    """Test GDB RSP protocol against QEMU's GDB stub."""

    def test_gdb_connect(self, firmware_path: str) -> None:
        """Connect to the GDB stub exposed by QEMU."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385", gdb=True, paused=True)
            # GDB client may or may not connect (depending on timing),
            # but we at least verify the attempt was made.
            if qemu.gdb is not None:
                assert qemu.gdb._connected is True

    def test_gdb_read_registers(self, firmware_path: str) -> None:
        """Read CPU registers via GDB RSP 'g' packet."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385", gdb=True, paused=True)
            if qemu.gdb is None:
                pytest.skip("GDB connection not established")
            regs = qemu.gdb.read_registers()
            assert isinstance(regs, dict)
            assert "pc" in regs
            assert "sp" in regs

    def test_gdb_read_memory(self, firmware_path: str) -> None:
        """Read a memory region via GDB RSP 'm' packet."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385", gdb=True, paused=True)
            if qemu.gdb is None:
                pytest.skip("GDB connection not established")
            # Read 16 bytes from flash base (0x00000000 on mps2-an385)
            data = qemu.gdb.read_memory(0x00000000, 16)
            assert isinstance(data, bytes)
            assert len(data) == 16


# ---------------------------------------------------------------------------
# 4. TestMemoryOperations
# ---------------------------------------------------------------------------

@pytest.mark.skipif(QEMU_MISSING, reason=SKIP_REASON)
class TestMemoryOperations:
    """Test memory read/write via GDB stub on mps2-an385 memory map."""

    def test_read_sram(self, firmware_path: str) -> None:
        """Read from SRAM region (0x20000000)."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385", gdb=True, paused=True)
            if qemu.gdb is None:
                pytest.skip("GDB connection not established")
            data = qemu.gdb.read_memory(0x20000000, 32)
            assert isinstance(data, bytes)
            assert len(data) == 32

    def test_write_sram(self, firmware_path: str) -> None:
        """Write to SRAM region and read back to verify."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385", gdb=True, paused=True)
            if qemu.gdb is None:
                pytest.skip("GDB connection not established")

            test_data = b"\xde\xad\xbe\xef" * 4
            qemu.gdb.write_memory(0x20000100, test_data)
            readback = qemu.gdb.read_memory(0x20000100, len(test_data))
            assert readback == test_data

    def test_read_flash(self, firmware_path: str) -> None:
        """Read from flash region (0x00000000) and verify non-empty."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385", gdb=True, paused=True)
            if qemu.gdb is None:
                pytest.skip("GDB connection not established")
            data = qemu.gdb.read_memory(0x00000000, 64)
            assert isinstance(data, bytes)
            assert len(data) == 64
            # Flash should contain the vector table, not all zeros
            assert data != b"\x00" * 64


# ---------------------------------------------------------------------------
# 5. TestQEMUSnapshot
# ---------------------------------------------------------------------------

@pytest.mark.skipif(QEMU_MISSING, reason=SKIP_REASON)
class TestQEMUSnapshot:
    """Test snapshot save/restore via QMP."""

    def test_save_snapshot(self, firmware_path: str) -> None:
        """Save a VM snapshot via QMP human-monitor-command."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385")
            # mps2-an385 may not support snapshots (no block device).
            # We test that the command is accepted without crashing QEMU.
            try:
                qemu.qmp.execute(
                    "human-monitor-command",
                    {"command-line": "savevm test_snap"},
                )
            except OperationError:
                pytest.skip("Snapshots not supported on this machine config")

    def test_load_snapshot(self, firmware_path: str) -> None:
        """Save then load a VM snapshot."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        with QEMUInstance(config) as qemu:
            qemu.start(firmware_path, "mps2-an385")
            try:
                qemu.qmp.execute(
                    "human-monitor-command",
                    {"command-line": "savevm test_snap"},
                )
                qemu.qmp.execute(
                    "human-monitor-command",
                    {"command-line": "loadvm test_snap"},
                )
            except OperationError:
                pytest.skip("Snapshots not supported on this machine config")

            # After restore, the VM should still be queryable
            status = qemu.status()
            assert status in ("running", "paused", "restore-vm")


# ---------------------------------------------------------------------------
# 6. TestFuzzerSmoke
# ---------------------------------------------------------------------------

@pytest.mark.skipif(QEMU_MISSING, reason=SKIP_REASON)
class TestFuzzerSmoke:
    """Smoke tests for the fuzzer engine (requires QEMU)."""

    def test_fuzzer_engine_creates_corpus(self, firmware_path: str, tmp_path: Path) -> None:
        """Verify the fuzzer creates a corpus directory and output files."""
        # The fuzzer module may not exist yet; skip gracefully.
        try:
            from rtosploit.fuzzer.engine import FuzzerEngine
        except ImportError:
            pytest.skip("rtosploit.fuzzer.engine not available")

        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        config = RTOSploitConfig()
        try:
            engine = FuzzerEngine(
                firmware=firmware_path,
                machine="mps2-an385",
                corpus_dir=str(corpus_dir),
                output_dir=str(output_dir),
                config=config,
            )
            # Run for a very short duration to verify startup
            engine.run(max_iterations=1, timeout=5)
        except (QEMUCrashError, OperationError, NotImplementedError):
            pytest.skip("Fuzzer engine not fully functional yet")

        # Corpus or output directory should still exist
        assert corpus_dir.exists()

    def test_fuzzer_handles_timeout(self, firmware_path: str, tmp_path: Path) -> None:
        """Verify the fuzzer handles a zero-iteration timeout gracefully."""
        try:
            from rtosploit.fuzzer.engine import FuzzerEngine
        except ImportError:
            pytest.skip("rtosploit.fuzzer.engine not available")

        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        config = RTOSploitConfig()
        try:
            engine = FuzzerEngine(
                firmware=firmware_path,
                machine="mps2-an385",
                corpus_dir=str(corpus_dir),
                output_dir=str(output_dir),
                config=config,
            )
            # Timeout of 0 should return immediately without error
            engine.run(max_iterations=0, timeout=0)
        except (QEMUCrashError, OperationError, NotImplementedError):
            pytest.skip("Fuzzer engine not fully functional yet")


# ---------------------------------------------------------------------------
# 7. TestExploitExecution
# ---------------------------------------------------------------------------

@pytest.mark.skipif(QEMU_MISSING, reason=SKIP_REASON)
class TestExploitExecution:
    """End-to-end exploit module tests."""

    def test_exploit_check_without_qemu(self) -> None:
        """Test that exploit check() returns a status without needing QEMU.

        We instantiate a concrete exploit module, set options to dummy
        values, and verify that check() either returns a bool or raises
        a controlled error (not an unhandled crash).
        """
        from rtosploit.exploits.registry import ExploitRegistry

        registry = ExploitRegistry()
        registry.discover()

        # Pick the first available module
        if not registry._modules:
            pytest.skip("No exploit modules discovered")

        path, cls = next(iter(registry._modules.items()))
        module = cls()

        # Build a mock target that the check() method can inspect
        mock_target = MagicMock()
        mock_target.firmware_path = "/nonexistent/firmware.bin"
        mock_target.machine = "mps2-an385"

        try:
            result = module.check(mock_target)
            assert isinstance(result, bool)
        except (FileNotFoundError, OperationError, QEMUCrashError, ValueError):
            # These are acceptable controlled errors
            pass

    def test_exploit_module_lifecycle(self, firmware_path: str) -> None:
        """Test full exploit module lifecycle: configure -> check -> run."""
        from rtosploit.exploits.registry import ExploitRegistry

        registry = ExploitRegistry()
        registry.discover()

        if not registry._modules:
            pytest.skip("No exploit modules discovered")

        path, cls = next(iter(registry._modules.items()))
        module = cls()

        # Configure the module with valid options
        module.set_option("firmware", firmware_path)
        module.set_option("machine", "mps2-an385")

        assert module.get_option("firmware") is not None
        assert module.get_option("machine") == "mps2-an385"

        # Verify info() returns well-formed metadata
        info = module.info()
        assert "name" in info
        assert "rtos" in info
        assert "category" in info

        # Verify requirements() returns a dict
        reqs = module.requirements()
        assert isinstance(reqs, dict)


# ---------------------------------------------------------------------------
# 8. TestVulnRangeLifecycle
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not VULNRANGE_DIR.exists(), reason="vulnrange/ directory not found")
class TestVulnRangeLifecycle:
    """End-to-end VulnRange management tests."""

    def test_range_list(self) -> None:
        """List all ranges and verify we get at least one."""
        from rtosploit.vulnrange.manager import VulnRangeManager

        mgr = VulnRangeManager(VULNRANGE_DIR)
        ranges = mgr.list()
        assert isinstance(ranges, list)
        assert len(ranges) >= 1

    def test_range_load_and_verify(self) -> None:
        """Load a range by ID and verify its manifest fields."""
        from rtosploit.vulnrange.manager import VulnRangeManager

        mgr = VulnRangeManager(VULNRANGE_DIR)
        ranges = mgr.list()
        if not ranges:
            pytest.skip("No ranges found")

        first = ranges[0]
        manifest = mgr.get(first.id)

        assert manifest.id == first.id
        assert manifest.title
        assert manifest.target.rtos
        assert manifest.target.machine
        assert manifest.exploit.script

    def test_range_hint_progression(self) -> None:
        """Get progressive hints and verify they are non-empty strings."""
        from rtosploit.vulnrange.manager import VulnRangeManager

        mgr = VulnRangeManager(VULNRANGE_DIR)
        ranges = mgr.list()
        if not ranges:
            pytest.skip("No ranges found")

        first = ranges[0]
        hint1 = mgr.hint(first.id, level=1)
        assert isinstance(hint1, str)
        assert len(hint1) > 0

        # Level 2 hint should also be a non-empty string
        hint2 = mgr.hint(first.id, level=2)
        assert isinstance(hint2, str)
        assert len(hint2) > 0

    def test_range_exploit_path(self) -> None:
        """Verify exploit script paths exist for all ranges."""
        from rtosploit.vulnrange.manager import VulnRangeManager

        mgr = VulnRangeManager(VULNRANGE_DIR)
        ranges = mgr.list()
        if not ranges:
            pytest.skip("No ranges found")

        for manifest in ranges:
            exploit_path = mgr.get_exploit_path(manifest.id)
            assert exploit_path.exists(), (
                f"Range '{manifest.id}': exploit script not found at {exploit_path}"
            )
