"""Unit tests for the Unicorn-based rehosting engine."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import capstone  # noqa: E402 — patch before any rtosploit import
if not hasattr(capstone, "CS_ARCH_XTENSA"):
    capstone.CS_ARCH_XTENSA = 0xFF  # stub so disasm.py can load

import pytest

from rtosploit.utils.binary import BinaryFormat, FirmwareImage, MemorySection

try:
    from rtosploit.peripherals.unicorn_engine import (
        UnicornRehostEngine,
        UnicornSnapshot,
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
    with_sections: bool = False,
    symbols: dict[str, int] | None = None,
) -> FirmwareImage:
    """Build a synthetic ARM Cortex-M firmware image.

    The first 8 bytes form a minimal vector table:
      word 0: initial SP  = 0x20040000
      word 1: reset vector = 0x08000009 (Thumb bit set)
    Followed by a single Thumb instruction: ``bx lr`` (0x4770) so
    execution returns immediately when we run the engine.
    """
    import struct

    initial_sp = 0x20040000
    reset_handler = 0x08000009  # Thumb
    # Vector table + bx lr at offset 8
    code = struct.pack("<II", initial_sp, reset_handler) + b"\x70\x47"
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


# ---------------------------------------------------------------------------
# TestUnicornRehostEngine
# ---------------------------------------------------------------------------

class TestUnicornRehostEngine:
    def test_setup_loads_firmware_raw(self) -> None:
        """setup() with a raw (no sections) firmware maps memory."""
        fw = _make_firmware(with_sections=False)
        engine = UnicornRehostEngine(fw)
        engine.setup()
        # Engine should be ready (no exception)
        assert engine.execution_count == 0

    def test_setup_loads_firmware_sections(self) -> None:
        """setup() with sections maps each section independently."""
        fw = _make_firmware(with_sections=True)
        engine = UnicornRehostEngine(fw)
        engine.setup()
        assert engine.execution_count == 0

    def test_mmio_read_routes_to_handler(self) -> None:
        """Unmapped MMIO reads are routed to the CompositeMMIOHandler."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        handler = CompositeMMIOHandler()
        fw = _make_firmware(with_sections=False)
        engine = UnicornRehostEngine(fw, mmio_handler=handler)
        engine.setup()

        # Directly invoke the hook to verify routing
        # Peripheral region (0x40000000+) is unmapped on purpose
        uc_mock = MagicMock()
        result = engine._hook_mem_read_unmapped(
            uc_mock, None, 0x40000000, 4, 0, None,
        )
        assert result is True
        # The handler should have been called (fallback returns 1 for first read)

    def test_mmio_write_routes_to_handler(self) -> None:
        """Unmapped MMIO writes are routed to the CompositeMMIOHandler."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        handler = CompositeMMIOHandler()
        fw = _make_firmware(with_sections=False)
        engine = UnicornRehostEngine(fw, mmio_handler=handler)
        engine.setup()

        uc_mock = MagicMock()
        result = engine._hook_mem_write_unmapped(
            uc_mock, None, 0x40000000, 4, 0xDEADBEEF, None,
        )
        assert result is True

    def test_hal_hook_registration(self) -> None:
        """add_hal_hook stores the handler for the given address."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()

        called = False

        def my_handler() -> int:
            nonlocal called
            called = True
            return 0

        engine.add_hal_hook(0x08001000, my_handler)
        assert 0x08001000 in engine._hal_hooks
        assert engine._hal_hooks[0x08001000] is my_handler

    def test_snapshot_restore(self) -> None:
        """take_snapshot / restore_snapshot round-trips without error."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()

        snapshot = engine.take_snapshot()
        assert isinstance(snapshot, UnicornSnapshot)
        assert snapshot.context is not None

        # Restore should not raise
        engine.restore_snapshot(snapshot)

    def test_snapshot_requires_setup(self) -> None:
        """take_snapshot before setup raises RuntimeError."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        with pytest.raises(RuntimeError, match="not initialized"):
            engine.take_snapshot()

    def test_restore_requires_setup(self) -> None:
        """restore_snapshot before setup raises RuntimeError."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        dummy = UnicornSnapshot(context=b"\x00" * 16)
        with pytest.raises(RuntimeError, match="not initialized"):
            engine.restore_snapshot(dummy)

    def test_stop(self) -> None:
        """stop() sets the stopped flag and reason."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()

        engine.stop("test_reason")
        assert engine._stopped is True
        assert engine._stop_reason == "test_reason"

    def test_stop_default_reason(self) -> None:
        """stop() without argument uses 'user' as reason."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        engine.setup()

        engine.stop()
        assert engine._stop_reason == "user"

    def test_run_requires_setup(self) -> None:
        """run() before setup raises RuntimeError."""
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw)
        with pytest.raises(RuntimeError, match="setup"):
            engine.run()

    def test_mmio_stats_property(self) -> None:
        """mmio_stats delegates to the composite handler."""
        from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

        handler = CompositeMMIOHandler()
        fw = _make_firmware()
        engine = UnicornRehostEngine(fw, mmio_handler=handler)
        engine.setup()

        stats = engine.mmio_stats
        assert isinstance(stats, dict)
