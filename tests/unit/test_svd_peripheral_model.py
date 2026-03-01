"""Unit tests for rtosploit.peripherals.models.svd_peripheral."""

from __future__ import annotations

import pytest

from rtosploit.peripherals.svd_model import (
    SVDField,
    SVDPeripheral,
    SVDRegister,
)
from rtosploit.peripherals.models.svd_peripheral import SVDPeripheralModel


def _make_peripheral(
    name: str = "TEST",
    base_address: int = 0x40000000,
    registers: list[SVDRegister] | None = None,
    irq_numbers: list[int] | None = None,
) -> SVDPeripheral:
    """Helper to build an SVDPeripheral for testing."""
    return SVDPeripheral(
        name=name,
        base_address=base_address,
        registers=registers or [],
        irq_numbers=irq_numbers or [],
    )


# ---------------------------------------------------------------------------
# Construction and reset
# ---------------------------------------------------------------------------

class TestConstruction:
    def test_basic_construction(self):
        regs = [SVDRegister(name="CR1", offset=0x00, reset_value=0x1234)]
        periph = _make_peripheral(registers=regs)
        model = SVDPeripheralModel(periph)
        assert model.name == "TEST"
        assert model.base_addr == 0x40000000

    def test_custom_name(self):
        periph = _make_peripheral(name="UART0")
        model = SVDPeripheralModel(periph, name="my_uart")
        assert model.name == "my_uart"

    def test_reset_sets_values(self):
        regs = [
            SVDRegister(name="CR1", offset=0x00, reset_value=0xAA),
            SVDRegister(name="CR2", offset=0x04, reset_value=0xBB),
        ]
        periph = _make_peripheral(registers=regs)
        model = SVDPeripheralModel(periph)
        assert model.read_register(0x00) == 0xAA
        assert model.read_register(0x04) == 0xBB

    def test_reset_restores_after_write(self):
        regs = [SVDRegister(name="CR1", offset=0x00, reset_value=0x10)]
        periph = _make_peripheral(registers=regs)
        model = SVDPeripheralModel(periph)
        model.write_register(0x00, 0xFF)
        assert model.read_register(0x00) == 0xFF
        model.reset()
        assert model.read_register(0x00) == 0x10


# ---------------------------------------------------------------------------
# Read behavior per access type
# ---------------------------------------------------------------------------

class TestReadBehavior:
    def test_read_write_register(self):
        regs = [SVDRegister(name="DATA", offset=0x00, access="read-write", reset_value=0)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        model.write_register(0x00, 42)
        assert model.read_register(0x00) == 42

    def test_read_only_always_returns_reset(self):
        regs = [SVDRegister(name="ID", offset=0x00, access="read-only", reset_value=0xCAFE)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        # Even after write attempt, read-only returns reset value
        model.write_register(0x00, 0xDEAD)
        assert model.read_register(0x00) == 0xCAFE

    def test_write_only_returns_zero(self):
        regs = [SVDRegister(name="CMD", offset=0x00, access="write-only", reset_value=0x55)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        model.write_register(0x00, 0xFF)
        assert model.read_register(0x00) == 0

    def test_unmatched_offset_returns_zero(self):
        regs = [SVDRegister(name="CR1", offset=0x00)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        assert model.read_register(0x99) == 0


# ---------------------------------------------------------------------------
# Write behavior per access type
# ---------------------------------------------------------------------------

class TestWriteBehavior:
    def test_write_read_write_register(self):
        regs = [SVDRegister(name="DATA", offset=0x00, access="read-write")]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        model.write_register(0x00, 0xBEEF)
        assert model.read_register(0x00) == 0xBEEF

    def test_write_only_accepted(self):
        regs = [SVDRegister(name="CMD", offset=0x00, access="write-only")]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        model.write_register(0x00, 0x42)
        # Write-only reads return 0, but internal state should be stored
        assert model._registers[0x00] == 0x42

    def test_write_read_only_ignored(self):
        regs = [SVDRegister(name="ID", offset=0x00, access="read-only", reset_value=0xAA)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        model.write_register(0x00, 0xFF)
        # Value should remain at reset
        assert model._registers[0x00] == 0xAA

    def test_write_unmatched_offset_stored(self):
        """Writes to unknown offsets are still stored (firmware may read back)."""
        model = SVDPeripheralModel(_make_peripheral())
        model.write_register(0x99, 0x42)
        assert model._registers[0x99] == 0x42


# ---------------------------------------------------------------------------
# Smart status heuristics
# ---------------------------------------------------------------------------

class TestStatusHeuristics:
    def test_status_register_returns_all_set(self):
        regs = [SVDRegister(name="STATUS", offset=0x00, size=32, reset_value=0)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        assert model.read_register(0x00) == 0xFFFFFFFF

    def test_ready_register_returns_all_set(self):
        regs = [SVDRegister(name="READY", offset=0x00, size=32, reset_value=0)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        assert model.read_register(0x00) == 0xFFFFFFFF

    def test_events_register_returns_all_set(self):
        regs = [SVDRegister(name="EVENTS_READY", offset=0x00, size=32, reset_value=0)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        # EVENTS matches status pattern -> all set
        # Also matches event clear pattern -> cleared after read
        val = model.read_register(0x00)
        assert val == 0xFFFFFFFF

    def test_event_clear_on_read(self):
        regs = [SVDRegister(name="EVENTS_DONE", offset=0x00, size=32, reset_value=0)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        # First read: all-set (from status heuristic)
        val1 = model.read_register(0x00)
        assert val1 == 0xFFFFFFFF
        # After clear-on-read, internal state is 0
        # But STATUS pattern still applies, so it returns all-set again
        # (status heuristic overrides stored value)
        val2 = model.read_register(0x00)
        assert val2 == 0xFFFFFFFF

    def test_intenset_returns_all_set(self):
        regs = [SVDRegister(name="INTENSET", offset=0x00, size=32, reset_value=0)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        assert model.read_register(0x00) == 0xFFFFFFFF

    def test_normal_register_not_affected(self):
        regs = [SVDRegister(name="DATA", offset=0x00, size=32, reset_value=0)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        assert model.read_register(0x00) == 0

    def test_status_16bit_register(self):
        regs = [SVDRegister(name="STATUS", offset=0x00, size=16, reset_value=0)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        assert model.read_register(0x00) == 0xFFFF


# ---------------------------------------------------------------------------
# Access statistics
# ---------------------------------------------------------------------------

class TestAccessStats:
    def test_reads_counted(self):
        regs = [SVDRegister(name="CR1", offset=0x00)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        model.read_register(0x00)
        model.read_register(0x00)
        assert model.stats.reads == 2

    def test_writes_counted(self):
        regs = [SVDRegister(name="CR1", offset=0x00)]
        model = SVDPeripheralModel(_make_peripheral(registers=regs))
        model.write_register(0x00, 1)
        model.write_register(0x00, 2)
        assert model.stats.writes == 2

    def test_unmatched_reads_counted(self):
        model = SVDPeripheralModel(_make_peripheral())
        model.read_register(0x99)
        assert model.stats.unmatched_reads == 1
        assert model.stats.reads == 1

    def test_unmatched_writes_counted(self):
        model = SVDPeripheralModel(_make_peripheral())
        model.write_register(0x99, 0)
        assert model.stats.unmatched_writes == 1
        assert model.stats.writes == 1


# ---------------------------------------------------------------------------
# IRQ
# ---------------------------------------------------------------------------

class TestIRQ:
    def test_no_irq(self):
        model = SVDPeripheralModel(_make_peripheral())
        assert model.get_irq() is None

    def test_irq_from_svd(self):
        periph = _make_peripheral(irq_numbers=[37, 38])
        model = SVDPeripheralModel(periph)
        assert model.get_irq() == 37

    def test_svd_peripheral_property(self):
        periph = _make_peripheral(name="UART0")
        model = SVDPeripheralModel(periph)
        assert model.svd_peripheral is periph
