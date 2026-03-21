"""Unit tests for the interrupt injector."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock

import pytest

from rtosploit.peripherals.interrupt_injector import (
    InterruptInjector,
    ISREntry,
    _NVIC_ISPR_BASE,
    _SYSTEM_EXCEPTION_COUNT,
)
from rtosploit.peripherals.svd_model import SVDDevice, SVDPeripheral, SVDRegister
from rtosploit.utils.binary import BinaryFormat, FirmwareImage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_vector_table(
    base: int,
    initial_sp: int,
    reset: int,
    irq_handlers: dict[int, int],
    num_irqs: int = 32,
) -> bytes:
    """Build a Cortex-M vector table as bytes.

    Args:
        base: Firmware base address (not used in data, just for context).
        initial_sp: Initial stack pointer value.
        reset: Reset handler address (with Thumb bit).
        irq_handlers: Mapping of IRQ number -> handler address.
        num_irqs: Total number of external IRQ slots to reserve.
    """
    # System exceptions (16 entries)
    vectors = [0] * (_SYSTEM_EXCEPTION_COUNT + num_irqs)
    vectors[0] = initial_sp
    vectors[1] = reset
    # NMI, HardFault, etc. — set to distinct addresses
    vectors[2] = reset  # NMI -> same as reset for simplicity
    vectors[3] = reset  # HardFault -> same as reset

    # Fill external IRQs
    for irq, handler in irq_handlers.items():
        vectors[_SYSTEM_EXCEPTION_COUNT + irq] = handler

    return b"".join(struct.pack("<I", v) for v in vectors)


def _make_firmware_with_vectors(
    irq_handlers: dict[int, int],
    base: int = 0x08000000,
    num_irqs: int = 32,
) -> FirmwareImage:
    """Create a FirmwareImage with a valid vector table."""
    initial_sp = 0x20020000
    reset = base + 0x100 | 1  # Thumb bit set

    # Build IRQ handlers with Thumb bit
    thumb_handlers = {irq: (addr | 1) for irq, addr in irq_handlers.items()}

    data = _build_vector_table(base, initial_sp, reset, thumb_handlers, num_irqs)
    # Pad to ensure handler addresses are within range
    data += b"\x00" * max(0, 0x1000 - len(data))

    return FirmwareImage(
        data=data,
        base_address=base,
        entry_point=base,
        format=BinaryFormat.RAW,
    )


# ---------------------------------------------------------------------------
# 1. TestISRDiscovery
# ---------------------------------------------------------------------------

class TestISRDiscovery:
    def test_discover_isrs_from_valid_vector_table(self) -> None:
        """ISR discovery finds handlers in the vector table."""
        base = 0x08000000
        handlers = {
            0: base + 0x200,   # IRQ 0
            5: base + 0x300,   # IRQ 5
            10: base + 0x400,  # IRQ 10
        }
        fw = _make_firmware_with_vectors(handlers, base=base)

        injector = InterruptInjector(fw)

        isrs = injector.discovered_isrs
        irq_numbers = {isr.irq_number for isr in isrs}
        assert 0 in irq_numbers
        assert 5 in irq_numbers
        assert 10 in irq_numbers

    def test_skip_null_handlers(self) -> None:
        """Null (0x0) vector table entries are skipped."""
        base = 0x08000000
        handlers = {
            0: base + 0x200,
            # IRQ 1 not set — stays 0x0
            2: base + 0x300,
        }
        fw = _make_firmware_with_vectors(handlers, base=base)

        injector = InterruptInjector(fw)

        irq_numbers = {isr.irq_number for isr in injector.discovered_isrs}
        assert 1 not in irq_numbers

    def test_skip_erased_handlers(self) -> None:
        """0xFFFFFFFF entries (erased flash) are skipped."""
        base = 0x08000000
        # Build manually: IRQ 3 = 0xFFFFFFFF
        initial_sp = 0x20020000
        reset = base + 0x100 | 1
        num_irqs = 8
        vectors = [0] * (_SYSTEM_EXCEPTION_COUNT + num_irqs)
        vectors[0] = initial_sp
        vectors[1] = reset
        vectors[2] = reset  # NMI
        vectors[3] = reset  # HardFault
        vectors[_SYSTEM_EXCEPTION_COUNT + 0] = (base + 0x200) | 1  # IRQ 0 valid
        vectors[_SYSTEM_EXCEPTION_COUNT + 3] = 0xFFFFFFFF  # IRQ 3 erased

        data = b"".join(struct.pack("<I", v) for v in vectors)
        data += b"\x00" * max(0, 0x1000 - len(data))

        fw = FirmwareImage(
            data=data,
            base_address=base,
            entry_point=base,
            format=BinaryFormat.RAW,
        )

        injector = InterruptInjector(fw)

        irq_numbers = {isr.irq_number for isr in injector.discovered_isrs}
        assert 3 not in irq_numbers
        assert 0 in irq_numbers

    def test_cross_reference_with_svd_irq_numbers(self) -> None:
        """Discovered ISRs are annotated with SVD peripheral names."""
        base = 0x08000000
        handlers = {
            37: base + 0x200,  # USART1 IRQ
        }
        fw = _make_firmware_with_vectors(handlers, base=base, num_irqs=64)

        svd_periph = SVDPeripheral(
            name="USART1",
            base_address=0x40011000,
            irq_numbers=[37],
        )
        svd_dev = SVDDevice(name="STM32F407", peripherals=[svd_periph])

        injector = InterruptInjector(fw, svd_device=svd_dev)

        isrs = injector.discovered_isrs
        usart_isrs = [isr for isr in isrs if isr.irq_number == 37]
        assert len(usart_isrs) == 1
        assert usart_isrs[0].peripheral_name == "USART1"

    def test_injectable_irqs_property(self) -> None:
        base = 0x08000000
        handlers = {0: base + 0x200, 5: base + 0x300}
        fw = _make_firmware_with_vectors(handlers, base=base)

        injector = InterruptInjector(fw)

        irqs = injector.injectable_irqs
        assert 0 in irqs
        assert 5 in irqs

    def test_empty_vector_table(self) -> None:
        """Firmware with no valid ISR handlers results in empty discovery."""
        base = 0x08000000
        fw = _make_firmware_with_vectors({}, base=base)

        injector = InterruptInjector(fw)

        assert injector.discovered_isrs == []


# ---------------------------------------------------------------------------
# 2. TestInterruptInjection
# ---------------------------------------------------------------------------

class TestInterruptInjection:
    def _make_gdb(self) -> MagicMock:
        gdb = MagicMock()
        gdb.write_memory = MagicMock()
        gdb.read_memory = MagicMock(return_value=b"\x00\x00\x00\x00")
        return gdb

    def test_correct_nvic_ispr_register_calculation(self) -> None:
        """IRQ 37 should write to NVIC_ISPR1 (register 1), bit 5."""
        base = 0x08000000
        handlers = {37: base + 0x200}
        fw = _make_firmware_with_vectors(handlers, base=base, num_irqs=64)
        injector = InterruptInjector(fw)
        gdb = self._make_gdb()

        result = injector.inject_interrupt(37, gdb)

        assert result is True
        gdb.write_memory.assert_called_once()
        call_args = gdb.write_memory.call_args
        addr = call_args[0][0]
        data = call_args[0][1]

        # IRQ 37: register_index = 37 // 32 = 1, bit = 37 % 32 = 5
        expected_addr = _NVIC_ISPR_BASE + 1 * 4  # 0xE000E204
        expected_value = (1 << 5).to_bytes(4, "little")
        assert addr == expected_addr
        assert data == expected_value

    def test_irq_0_register_0_bit_0(self) -> None:
        """IRQ 0 should write to NVIC_ISPR0, bit 0."""
        base = 0x08000000
        handlers = {0: base + 0x200}
        fw = _make_firmware_with_vectors(handlers, base=base)
        injector = InterruptInjector(fw)
        gdb = self._make_gdb()

        injector.inject_interrupt(0, gdb)

        call_args = gdb.write_memory.call_args
        addr = call_args[0][0]
        data = call_args[0][1]
        assert addr == _NVIC_ISPR_BASE  # 0xE000E200
        assert data == (1).to_bytes(4, "little")

    def test_out_of_range_irq_returns_false(self) -> None:
        """IRQ number >= 256 or < 0 returns False."""
        base = 0x08000000
        fw = _make_firmware_with_vectors({}, base=base)
        injector = InterruptInjector(fw)
        gdb = self._make_gdb()

        assert injector.inject_interrupt(256, gdb) is False
        assert injector.inject_interrupt(-1, gdb) is False
        gdb.write_memory.assert_not_called()

    def test_injection_stats_tracking(self) -> None:
        """Injection stats track how many times each IRQ was injected."""
        base = 0x08000000
        handlers = {0: base + 0x200, 5: base + 0x300}
        fw = _make_firmware_with_vectors(handlers, base=base)
        injector = InterruptInjector(fw)
        gdb = self._make_gdb()

        injector.inject_interrupt(0, gdb)
        injector.inject_interrupt(0, gdb)
        injector.inject_interrupt(5, gdb)

        stats = injector.get_injection_stats()
        assert stats[0] == 2
        assert stats[5] == 1

    def test_reset_stats(self) -> None:
        base = 0x08000000
        handlers = {0: base + 0x200}
        fw = _make_firmware_with_vectors(handlers, base=base)
        injector = InterruptInjector(fw)
        gdb = self._make_gdb()

        injector.inject_interrupt(0, gdb)
        injector.reset_stats()
        assert injector.get_injection_stats() == {}

    def test_inject_all_discovered(self) -> None:
        """inject_all_discovered injects every discovered ISR."""
        base = 0x08000000
        handlers = {0: base + 0x200, 5: base + 0x300}
        fw = _make_firmware_with_vectors(handlers, base=base)
        injector = InterruptInjector(fw)
        gdb = self._make_gdb()

        count = injector.inject_all_discovered(gdb)

        assert count == len(injector.discovered_isrs)
        assert gdb.write_memory.call_count == count

    def test_inject_for_peripheral(self) -> None:
        """inject_for_peripheral only injects IRQs for the named peripheral."""
        base = 0x08000000
        handlers = {37: base + 0x200, 38: base + 0x300}
        fw = _make_firmware_with_vectors(handlers, base=base, num_irqs=64)

        svd_usart = SVDPeripheral(name="USART1", base_address=0x40011000, irq_numbers=[37])
        svd_usart2 = SVDPeripheral(name="USART2", base_address=0x40004400, irq_numbers=[38])
        svd_dev = SVDDevice(name="STM32F407", peripherals=[svd_usart, svd_usart2])

        injector = InterruptInjector(fw, svd_device=svd_dev)
        gdb = self._make_gdb()

        count = injector.inject_for_peripheral("USART1", gdb)
        assert count == 1

    def test_gdb_write_failure_returns_false(self) -> None:
        """If GDB write_memory raises, inject returns False."""
        base = 0x08000000
        handlers = {0: base + 0x200}
        fw = _make_firmware_with_vectors(handlers, base=base)
        injector = InterruptInjector(fw)

        gdb = self._make_gdb()
        gdb.write_memory.side_effect = RuntimeError("connection lost")

        result = injector.inject_interrupt(0, gdb)
        assert result is False
