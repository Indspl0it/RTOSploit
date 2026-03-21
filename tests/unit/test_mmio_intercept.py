"""Unit tests for MMIO interception via GDB watchpoints."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock

import pytest

from rtosploit.peripherals.mmio_intercept import MMIOInterceptor
from rtosploit.peripherals.models.mmio_fallback import (
    CompositeMMIOHandler,
    CortexMSystemRegisters,
    MMIOFallbackModel,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gdb() -> MagicMock:
    gdb = MagicMock()
    gdb.write_memory = MagicMock()
    gdb.read_memory = MagicMock(return_value=b"\x00\x00\x00\x00")
    gdb.set_watchpoint = MagicMock(return_value=1)
    gdb.remove_watchpoint = MagicMock()
    return gdb


def _make_handler() -> CompositeMMIOHandler:
    return CompositeMMIOHandler(
        svd_models={},
        fallback=MMIOFallbackModel(),
        system_regs=CortexMSystemRegisters(),
    )


# ---------------------------------------------------------------------------
# 1. TestMMIOInterceptor
# ---------------------------------------------------------------------------

class TestMMIOInterceptor:
    def test_handle_read_returns_value_from_handler(self) -> None:
        """Read watchpoint delegates to CompositeMMIOHandler and returns value."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)
        gdb = _make_gdb()

        # First read at unknown address -> fallback returns 0x1 (ready bit)
        result = interceptor.handle_watchpoint(
            address=0x40001000,
            is_write=False,
            gdb=gdb,
        )

        assert result == 0x00000001
        # Should write the result back to memory via GDB
        gdb.write_memory.assert_called_once()
        call_addr = gdb.write_memory.call_args[0][0]
        call_data = gdb.write_memory.call_args[0][1]
        assert call_addr == 0x40001000
        assert call_data == struct.pack("<I", 0x00000001)[:4]

    def test_handle_write_passes_to_handler(self) -> None:
        """Write watchpoint passes value to CompositeMMIOHandler."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)

        result = interceptor.handle_watchpoint(
            address=0x40001000,
            is_write=True,
            value=0xDEADBEEF,
        )

        # Write returns None
        assert result is None
        # Verify the fallback recorded the write
        assert handler.fallback.total_writes == 1

    def test_handle_read_after_write_echoes(self) -> None:
        """Read after a write to the same address returns the written value."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)
        gdb = _make_gdb()

        # Write
        interceptor.handle_watchpoint(
            address=0x40001000, is_write=True, value=0xCAFEBABE
        )
        # Read
        result = interceptor.handle_watchpoint(
            address=0x40001000, is_write=False, gdb=gdb
        )

        assert result == 0xCAFEBABE

    def test_intercept_count_increments(self) -> None:
        """intercept_count tracks total watchpoint hits."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)
        gdb = _make_gdb()

        interceptor.handle_watchpoint(0x40001000, is_write=False, gdb=gdb)
        interceptor.handle_watchpoint(0x40001000, is_write=True, value=1)
        interceptor.handle_watchpoint(0x40002000, is_write=False, gdb=gdb)

        assert interceptor.intercept_count == 3

    def test_coverage_stats_passthrough(self) -> None:
        """coverage_stats delegates to the handler's get_coverage_stats."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)
        gdb = _make_gdb()

        interceptor.handle_watchpoint(0xE000ED00, is_write=False, gdb=gdb)
        interceptor.handle_watchpoint(0x40001000, is_write=False, gdb=gdb)

        stats = interceptor.coverage_stats
        assert stats["system_handled"] == 1
        assert stats["fallback_handled"] == 1
        assert stats["total"] == 2

    def test_setup_sets_watchpoints(self) -> None:
        """setup() creates watchpoints via GDB for configured ranges."""
        handler = _make_handler()
        ranges = [(0x40000000, 0x20000000), (0xE0000000, 0x00100000)]
        interceptor = MMIOInterceptor(handler, peripheral_ranges=ranges)
        gdb = _make_gdb()

        count = interceptor.setup(gdb)

        assert count == 2
        assert gdb.set_watchpoint.call_count == 2

    def test_teardown_removes_watchpoints(self) -> None:
        """teardown() removes all previously set watchpoints."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)
        gdb = _make_gdb()

        interceptor.setup(gdb)
        interceptor.teardown(gdb)

        assert gdb.remove_watchpoint.call_count == 1

    def test_default_ranges(self) -> None:
        """Default peripheral range covers Cortex-M peripheral space."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)

        assert interceptor._ranges == [(0x40000000, 0x20000000)]

    def test_read_without_gdb_no_writeback(self) -> None:
        """Read watchpoint without GDB connection still returns value."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)

        result = interceptor.handle_watchpoint(
            address=0x40001000,
            is_write=False,
            gdb=None,
        )

        assert result == 0x00000001

    def test_system_register_read_via_interceptor(self) -> None:
        """Reading a system register address through interceptor returns correct value."""
        handler = _make_handler()
        interceptor = MMIOInterceptor(handler)
        gdb = _make_gdb()

        result = interceptor.handle_watchpoint(
            address=0xE000ED00,  # SCB CPUID
            is_write=False,
            gdb=gdb,
        )

        assert result == 0x410FC241

    def test_setup_handles_watchpoint_failure(self) -> None:
        """If setting a watchpoint fails, setup continues and returns partial count."""
        handler = _make_handler()
        ranges = [(0x40000000, 0x20000000), (0xE0000000, 0x00100000)]
        interceptor = MMIOInterceptor(handler, peripheral_ranges=ranges)
        gdb = _make_gdb()
        # First succeeds, second fails
        gdb.set_watchpoint.side_effect = [1, RuntimeError("no hw watchpoints")]

        count = interceptor.setup(gdb)

        assert count == 1
