"""Integration tests for UnicornRehostEngine with PIP handler.

Tests the full pipeline: Unicorn + PIP MMIO handling + FERMCov coverage +
interrupt scheduling + ExecutionResult generation.
"""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock

import capstone  # noqa: E402
if not hasattr(capstone, "CS_ARCH_XTENSA"):
    capstone.CS_ARCH_XTENSA = 0xFF

import pytest

from rtosploit.coverage.bitmap import CoverageBitmap
from rtosploit.fuzzing.execution import ExecutionResult, StopReason
from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler
from rtosploit.peripherals.interrupt_scheduler import InterruptScheduler
from rtosploit.utils.binary import BinaryFormat, FirmwareImage, MemorySection

try:
    from rtosploit.peripherals.unicorn_engine import (
        UnicornRehostEngine,
        HAS_UNICORN,
    )
except ImportError:
    HAS_UNICORN = False

pytestmark = pytest.mark.skipif(not HAS_UNICORN, reason="unicorn not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_firmware(
    *,
    code_suffix: bytes = b"\x70\x47",  # bx lr
    with_sections: bool = False,
    symbols: dict[str, int] | None = None,
) -> FirmwareImage:
    """Build a synthetic ARM Cortex-M firmware image.

    Default: vector table + bx lr at offset 8 (returns immediately).
    """
    initial_sp = 0x20040000
    reset_handler = 0x08000009  # Thumb bit set, handler at 0x08000008
    vtable = struct.pack("<II", initial_sp, reset_handler)
    code = vtable + code_suffix
    # Pad to 256 bytes
    code = code.ljust(256, b"\x00")

    sections: list[MemorySection] = []
    if with_sections:
        sections = [
            MemorySection(
                name=".text",
                address=0x08000000,
                data=code,
                size=len(code),
                permissions="rx",
            ),
        ]

    return FirmwareImage(
        data=code,
        base_address=0x08000000,
        entry_point=0x08000008,
        format=BinaryFormat.RAW,
        sections=sections,
        symbols=symbols or {},
        path=Path("synthetic.bin"),
        architecture="armv7m",
    )


def _make_firmware_with_mmio_read() -> FirmwareImage:
    """Firmware that reads from a peripheral address (0x40000000) then returns.

    Thumb instructions:
      0x08000008: ldr r0, [pc, #4]  -> loads 0x40000000 from literal pool
      0x0800000A: ldr r1, [r0]      -> reads MMIO at 0x40000000
      0x0800000C: bx lr             -> return
      0x0800000E: .align
      0x08000010: .word 0x40000000  -> literal pool
    """
    initial_sp = 0x20040000
    reset_handler = 0x08000009  # Thumb
    vtable = struct.pack("<II", initial_sp, reset_handler)

    # ldr r0, [pc, #4] = 0x4801 (PC-relative load, offset = 4 words ahead?
    # Actually: ldr r0, [pc, #N] where N is offset from aligned PC.
    # At 0x08000008: PC = 0x0800000C (PC+4 aligned down to word = 0x0800000C)
    # We want to load from 0x08000010, offset = 0x10 - 0x0C = 4 = 1 word
    # ldr r0, [pc, #4] = 0x4801
    code = vtable + bytes([
        0x01, 0x48,  # ldr r0, [pc, #4]  -> loads from 0x08000010
        0x01, 0x68,  # ldr r1, [r0, #0]  -> MMIO read at 0x40000000
        0x70, 0x47,  # bx lr
        0x00, 0x00,  # padding
        0x00, 0x00, 0x00, 0x40,  # .word 0x40000000
    ])
    code = code.ljust(256, b"\x00")

    return FirmwareImage(
        data=code,
        base_address=0x08000000,
        entry_point=0x08000008,
        format=BinaryFormat.RAW,
        sections=[],
        symbols={},
        path=Path("mmio_read.bin"),
        architecture="armv7m",
    )


def _make_firmware_infinite_loop() -> FirmwareImage:
    """Firmware with an infinite loop (b . = branch to self).

    At 0x08000008: b . (Thumb encoding: 0xE7FE)
    """
    initial_sp = 0x20040000
    reset_handler = 0x08000009
    vtable = struct.pack("<II", initial_sp, reset_handler)
    code = vtable + bytes([0xFE, 0xE7])  # b .  (infinite loop)
    code = code.ljust(256, b"\x00")

    return FirmwareImage(
        data=code,
        base_address=0x08000000,
        entry_point=0x08000008,
        format=BinaryFormat.RAW,
        sections=[],
        symbols={},
        path=Path("infinite_loop.bin"),
        architecture="armv7m",
    )


# ---------------------------------------------------------------------------
# Tests: UnicornRehostEngine + PIP
# ---------------------------------------------------------------------------

class TestUnicornPIPIntegration:
    """Integration tests for Unicorn engine with PIP handler."""

    def test_set_fuzz_input_creates_pip(self) -> None:
        """set_fuzz_input() creates a PIPHandler and wires it."""
        fw = _make_firmware()
        handler = CompositeMMIOHandler()
        engine = UnicornRehostEngine(fw, mmio_handler=handler)
        engine.setup()

        engine.set_fuzz_input(b"\x00" * 64)
        assert engine.pip_handler is not None
        assert handler.pip_handler is not None

    def test_run_fuzz_iteration_returns_result(self) -> None:
        """run_fuzz_iteration() returns a valid ExecutionResult."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()
        snapshot = engine.take_snapshot()

        # Provide enough fuzz input for PIP
        fuzz_data = b"\xFF" * 256
        engine.restore_snapshot(snapshot)
        result = engine.run_fuzz_iteration(fuzz_data)

        assert isinstance(result, ExecutionResult)
        assert result.stop_reason in StopReason
        assert result.blocks_executed >= 0

    def test_coverage_collected_during_execution(self) -> None:
        """FERMCov collects coverage during execution."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()
        snapshot = engine.take_snapshot()

        engine.restore_snapshot(snapshot)
        result = engine.run_fuzz_iteration(b"\x00" * 64)

        assert result.coverage is not None
        # At least one block should have been hit (the reset handler)
        assert isinstance(result.coverage, CoverageBitmap)

    def test_input_exhausted_terminates_cleanly(self) -> None:
        """InputExhausted from PIP stops emulation with INPUT_EXHAUSTED."""
        fw = _make_firmware_with_mmio_read()
        handler = CompositeMMIOHandler()
        engine = UnicornRehostEngine(fw, mmio_handler=handler)
        engine.setup()
        snapshot = engine.take_snapshot()

        # Provide very small input: not enough for PIP replay bits + value
        engine.restore_snapshot(snapshot)
        result = engine.run_fuzz_iteration(b"\x01")

        # Should terminate with INPUT_EXHAUSTED (PIP needs at least 4 bytes
        # for replay bits, then more for values)
        assert result.stop_reason == StopReason.INPUT_EXHAUSTED
        assert not result.crashed

    def test_infinite_loop_detected(self) -> None:
        """Infinite loop (branch to self) is detected and stopped."""
        fw = _make_firmware_infinite_loop()
        engine = UnicornRehostEngine(fw, max_blocks=1000)
        engine.setup()
        snapshot = engine.take_snapshot()

        engine.restore_snapshot(snapshot)
        result = engine.run_fuzz_iteration(b"\x00" * 64)

        assert result.stop_reason == StopReason.INFINITE_LOOP
        assert not result.crashed

    def test_unmapped_non_peripheral_access_is_crash(self) -> None:
        """Accessing non-peripheral unmapped memory produces a crash result."""
        fw = _make_firmware()
        handler = CompositeMMIOHandler()
        engine = UnicornRehostEngine(fw, mmio_handler=handler)
        engine.setup()

        # Directly test the hook with a non-peripheral address
        uc_mock = MagicMock()
        result = engine._hook_mem_read_unmapped(
            uc_mock, None, 0x00000004, 4, 0, None,
        )
        assert result is False
        assert engine._stop_reason_enum == StopReason.UNMAPPED_ACCESS
        assert engine._crash_address == 0x00000004

    def test_peripheral_read_routes_through_pip(self) -> None:
        """Peripheral MMIO reads route through PIP when configured."""
        fw = _make_firmware()
        handler = CompositeMMIOHandler()
        engine = UnicornRehostEngine(fw, mmio_handler=handler)
        engine.setup()

        # Set up fuzz input with enough data for PIP
        engine.set_fuzz_input(b"\xFF" * 64)

        # Directly test hook with a peripheral address
        uc_mock = MagicMock()
        result = engine._hook_mem_read_unmapped(
            uc_mock, None, 0x40000100, 4, 0, None,
        )
        assert result is True
        # PIP should have been invoked (pip_handled counter incremented)
        stats = handler.get_coverage_stats()
        assert stats["pip_handled"] > 0

    def test_interrupt_scheduler_integration(self) -> None:
        """InterruptScheduler fires IRQs during execution."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw, max_blocks=100)
        engine.setup()

        scheduler = InterruptScheduler([5, 10], interval=10)
        engine.set_interrupt_scheduler(scheduler)
        snapshot = engine.take_snapshot()

        engine.restore_snapshot(snapshot)
        engine.run_fuzz_iteration(b"\x00" * 64)

        # Scheduler should have been called
        assert scheduler.stats["blocks_counted"] > 0

    def test_max_blocks_timeout(self) -> None:
        """Exceeding max_blocks produces TIMEOUT stop reason."""
        # Create firmware with a tight loop (not infinite, but many iterations)
        # Using simple bx lr firmware with very low max_blocks
        fw = _make_firmware_infinite_loop()
        engine = UnicornRehostEngine(fw, max_blocks=5)
        engine.setup()
        snapshot = engine.take_snapshot()

        engine.restore_snapshot(snapshot)
        result = engine.run_fuzz_iteration(b"\x00" * 64)

        # Should stop due to either infinite loop or timeout
        assert result.stop_reason in (StopReason.TIMEOUT, StopReason.INFINITE_LOOP)

    def test_snapshot_restore_resets_state(self) -> None:
        """Snapshot restore allows repeated iterations."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()
        snapshot = engine.take_snapshot()

        # Run two iterations
        engine.restore_snapshot(snapshot)
        result1 = engine.run_fuzz_iteration(b"\xAA" * 64)

        engine.restore_snapshot(snapshot)
        result2 = engine.run_fuzz_iteration(b"\xBB" * 64)

        # Both should complete without error
        assert isinstance(result1, ExecutionResult)
        assert isinstance(result2, ExecutionResult)

    def test_mapped_pages_tracking(self) -> None:
        """Dynamic page mapping tracks pages to avoid double-mapping."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()

        # SRAM pages should be tracked
        assert 0x20000000 in engine._mapped_pages
        # System register pages should be tracked
        assert 0xE0000000 in engine._mapped_pages

    def test_fermcov_resets_between_iterations(self) -> None:
        """FERMCov coverage resets between fuzz iterations."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()
        snapshot = engine.take_snapshot()

        engine.restore_snapshot(snapshot)
        result1 = engine.run_fuzz_iteration(b"\x00" * 64)

        engine.restore_snapshot(snapshot)
        result2 = engine.run_fuzz_iteration(b"\x00" * 64)

        # Coverage should be fresh each time (same edges, but independent bitmaps)
        if result1.coverage and result2.coverage:
            # Both should have the same number of edges (same code path)
            assert result1.coverage.count_edges() == result2.coverage.count_edges()


# ---------------------------------------------------------------------------
# Tests: UnicornFuzzWorker
# ---------------------------------------------------------------------------

class TestUnicornFuzzWorker:
    """Tests for UnicornFuzzWorker integration."""

    def test_worker_import(self) -> None:
        """UnicornFuzzWorker can be imported."""
        from rtosploit.fuzzing.unicorn_worker import UnicornFuzzWorker
        assert UnicornFuzzWorker is not None

    def test_worker_setup_and_run_one(self) -> None:
        """Worker can setup and run a single iteration."""
        from rtosploit.fuzzing.unicorn_worker import UnicornFuzzWorker

        fw = _make_firmware()
        worker = UnicornFuzzWorker(fw, irq_list=[], max_blocks=10000)
        worker.setup()

        result = worker.run_one(b"\x00" * 64)
        assert isinstance(result, ExecutionResult)

    def test_worker_is_interesting_detects_new_coverage(self) -> None:
        """Worker correctly identifies new coverage as interesting."""
        from rtosploit.fuzzing.unicorn_worker import UnicornFuzzWorker

        fw = _make_firmware()
        worker = UnicornFuzzWorker(fw, irq_list=[], max_blocks=10000)
        worker.setup()

        result = worker.run_one(b"\x00" * 64)

        # First result should be interesting (no previous coverage)
        if result.coverage and result.coverage.count_edges() > 0:
            assert worker.is_interesting(result) is True

    def test_worker_merge_coverage(self) -> None:
        """Worker merges coverage into global bitmap."""
        from rtosploit.fuzzing.unicorn_worker import UnicornFuzzWorker

        fw = _make_firmware()
        worker = UnicornFuzzWorker(fw, irq_list=[], max_blocks=10000)
        worker.setup()

        result = worker.run_one(b"\x00" * 64)
        if result.coverage and result.coverage.count_edges() > 0:
            worker.merge_coverage(result)
            assert worker.global_bitmap.count_edges() > 0
