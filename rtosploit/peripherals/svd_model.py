"""SVD (System View Description) data model for ARM CMSIS-SVD files.

Dataclasses representing the hierarchy: Device > Peripheral > Register > Field.
Used by svd_parser.py to produce structured data from SVD XML, and by
SVDPeripheralModel to drive register-level emulation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SVDField:
    """A bit field within a register."""

    name: str
    bit_offset: int
    bit_width: int
    access: str = "read-write"  # "read-only", "write-only", "read-write"
    description: str = ""

    @property
    def bit_mask(self) -> int:
        """Bitmask covering this field's bits."""
        return ((1 << self.bit_width) - 1) << self.bit_offset


@dataclass
class SVDRegister:
    """A memory-mapped register within a peripheral."""

    name: str
    offset: int  # byte offset from peripheral base
    size: int = 32  # register width in bits
    reset_value: int = 0
    access: str = "read-write"
    fields: list[SVDField] = field(default_factory=list)
    description: str = ""

    @property
    def byte_size(self) -> int:
        """Register size in bytes (rounded up)."""
        return (self.size + 7) // 8


@dataclass
class SVDPeripheral:
    """A peripheral with registers at a base address."""

    name: str
    base_address: int
    description: str = ""
    registers: list[SVDRegister] = field(default_factory=list)
    group_name: str = ""
    irq_numbers: list[int] = field(default_factory=list)
    derived_from: str = ""

    @property
    def size(self) -> int:
        """Compute peripheral address range from registers."""
        if not self.registers:
            return 0x400  # default 1KB
        max_end = max(r.offset + r.byte_size for r in self.registers)
        # Round up to at least 0x400
        return max(0x400, max_end)

    def get_register_by_offset(self, offset: int) -> Optional[SVDRegister]:
        """Find a register by its byte offset from peripheral base."""
        for r in self.registers:
            if r.offset == offset:
                return r
        return None

    def get_register_by_name(self, name: str) -> Optional[SVDRegister]:
        """Find a register by name."""
        for r in self.registers:
            if r.name == name:
                return r
        return None


@dataclass
class SVDDevice:
    """Top-level SVD device containing all peripherals."""

    name: str
    version: str = ""
    description: str = ""
    peripherals: list[SVDPeripheral] = field(default_factory=list)
    cpu_name: str = ""
    address_unit_bits: int = 8
    width: int = 32

    def get_peripheral_by_name(self, name: str) -> Optional[SVDPeripheral]:
        """Find a peripheral by name."""
        for p in self.peripherals:
            if p.name == name:
                return p
        return None

    def get_peripheral_at_address(self, addr: int) -> Optional[SVDPeripheral]:
        """Find the peripheral whose address range contains addr."""
        for p in sorted(self.peripherals, key=lambda x: x.base_address):
            if p.base_address <= addr < p.base_address + p.size:
                return p
        return None
