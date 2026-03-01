"""Unit tests for rtosploit.peripherals.svd_model."""

from __future__ import annotations

import pytest

from rtosploit.peripherals.svd_model import (
    SVDDevice,
    SVDField,
    SVDPeripheral,
    SVDRegister,
)


# ---------------------------------------------------------------------------
# SVDField
# ---------------------------------------------------------------------------

class TestSVDField:
    def test_construction_defaults(self):
        f = SVDField(name="EN", bit_offset=0, bit_width=1)
        assert f.name == "EN"
        assert f.bit_offset == 0
        assert f.bit_width == 1
        assert f.access == "read-write"
        assert f.description == ""

    def test_construction_custom(self):
        f = SVDField(
            name="MODE",
            bit_offset=4,
            bit_width=3,
            access="read-only",
            description="Operating mode",
        )
        assert f.access == "read-only"
        assert f.description == "Operating mode"

    def test_bit_mask_single_bit(self):
        f = SVDField(name="EN", bit_offset=0, bit_width=1)
        assert f.bit_mask == 0x1

    def test_bit_mask_multi_bit_at_offset(self):
        f = SVDField(name="MODE", bit_offset=4, bit_width=3)
        # bits 4,5,6 -> 0b1110000 = 0x70
        assert f.bit_mask == 0x70

    def test_bit_mask_full_byte(self):
        f = SVDField(name="DATA", bit_offset=0, bit_width=8)
        assert f.bit_mask == 0xFF

    def test_bit_mask_high_bits(self):
        f = SVDField(name="ADDR", bit_offset=16, bit_width=16)
        assert f.bit_mask == 0xFFFF0000


# ---------------------------------------------------------------------------
# SVDRegister
# ---------------------------------------------------------------------------

class TestSVDRegister:
    def test_construction_defaults(self):
        r = SVDRegister(name="CR1", offset=0x00)
        assert r.name == "CR1"
        assert r.offset == 0x00
        assert r.size == 32
        assert r.reset_value == 0
        assert r.access == "read-write"
        assert r.fields == []
        assert r.description == ""

    def test_byte_size_32bit(self):
        r = SVDRegister(name="CR1", offset=0x00, size=32)
        assert r.byte_size == 4

    def test_byte_size_16bit(self):
        r = SVDRegister(name="SR", offset=0x04, size=16)
        assert r.byte_size == 2

    def test_byte_size_8bit(self):
        r = SVDRegister(name="DR", offset=0x08, size=8)
        assert r.byte_size == 1

    def test_byte_size_rounds_up(self):
        # 9-bit register -> 2 bytes
        r = SVDRegister(name="ODD", offset=0x00, size=9)
        assert r.byte_size == 2

    def test_fields_list(self):
        fields = [
            SVDField(name="EN", bit_offset=0, bit_width=1),
            SVDField(name="MODE", bit_offset=1, bit_width=2),
        ]
        r = SVDRegister(name="CR1", offset=0x00, fields=fields)
        assert len(r.fields) == 2
        assert r.fields[0].name == "EN"


# ---------------------------------------------------------------------------
# SVDPeripheral
# ---------------------------------------------------------------------------

class TestSVDPeripheral:
    def test_construction_defaults(self):
        p = SVDPeripheral(name="UART0", base_address=0x40002000)
        assert p.name == "UART0"
        assert p.base_address == 0x40002000
        assert p.registers == []
        assert p.irq_numbers == []
        assert p.derived_from == ""

    def test_size_no_registers(self):
        p = SVDPeripheral(name="UART0", base_address=0x40002000)
        assert p.size == 0x400  # default

    def test_size_from_registers(self):
        regs = [
            SVDRegister(name="CR1", offset=0x000, size=32),
            SVDRegister(name="DR", offset=0x3FC, size=32),
        ]
        p = SVDPeripheral(name="UART0", base_address=0x40002000, registers=regs)
        # max_end = 0x3FC + 4 = 0x400
        assert p.size == 0x400

    def test_size_clamps_to_minimum(self):
        regs = [SVDRegister(name="CR1", offset=0x00, size=32)]
        p = SVDPeripheral(name="UART0", base_address=0x40002000, registers=regs)
        # max_end = 4, but minimum is 0x400
        assert p.size == 0x400

    def test_get_register_by_offset_found(self):
        regs = [
            SVDRegister(name="CR1", offset=0x00),
            SVDRegister(name="SR", offset=0x04),
        ]
        p = SVDPeripheral(name="UART0", base_address=0x40002000, registers=regs)
        r = p.get_register_by_offset(0x04)
        assert r is not None
        assert r.name == "SR"

    def test_get_register_by_offset_not_found(self):
        p = SVDPeripheral(name="UART0", base_address=0x40002000)
        assert p.get_register_by_offset(0x99) is None

    def test_get_register_by_name_found(self):
        regs = [SVDRegister(name="CR1", offset=0x00)]
        p = SVDPeripheral(name="UART0", base_address=0x40002000, registers=regs)
        r = p.get_register_by_name("CR1")
        assert r is not None
        assert r.offset == 0x00

    def test_get_register_by_name_not_found(self):
        p = SVDPeripheral(name="UART0", base_address=0x40002000)
        assert p.get_register_by_name("NOSUCH") is None


# ---------------------------------------------------------------------------
# SVDDevice
# ---------------------------------------------------------------------------

class TestSVDDevice:
    def _make_device(self) -> SVDDevice:
        uart = SVDPeripheral(
            name="UART0",
            base_address=0x40002000,
            registers=[SVDRegister(name="CR1", offset=0x00)],
        )
        gpio = SVDPeripheral(
            name="GPIO",
            base_address=0x50000000,
            registers=[SVDRegister(name="OUT", offset=0x00)],
        )
        return SVDDevice(
            name="nRF52840",
            peripherals=[uart, gpio],
            cpu_name="CM4",
        )

    def test_construction_defaults(self):
        d = SVDDevice(name="TestDevice")
        assert d.name == "TestDevice"
        assert d.version == ""
        assert d.peripherals == []
        assert d.address_unit_bits == 8
        assert d.width == 32

    def test_get_peripheral_by_name_found(self):
        d = self._make_device()
        p = d.get_peripheral_by_name("UART0")
        assert p is not None
        assert p.base_address == 0x40002000

    def test_get_peripheral_by_name_not_found(self):
        d = self._make_device()
        assert d.get_peripheral_by_name("SPI") is None

    def test_get_peripheral_at_address_exact_base(self):
        d = self._make_device()
        p = d.get_peripheral_at_address(0x40002000)
        assert p is not None
        assert p.name == "UART0"

    def test_get_peripheral_at_address_within_range(self):
        d = self._make_device()
        p = d.get_peripheral_at_address(0x40002100)
        assert p is not None
        assert p.name == "UART0"

    def test_get_peripheral_at_address_not_found(self):
        d = self._make_device()
        assert d.get_peripheral_at_address(0x10000000) is None
