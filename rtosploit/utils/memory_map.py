"""ARM Cortex-M memory map constants and helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

import yaml


class RegionType(Enum):
    CODE = auto()
    SRAM = auto()
    PERIPHERAL = auto()
    EXTERNAL_RAM = auto()
    EXTERNAL_DEVICE = auto()
    SYSTEM = auto()
    UNKNOWN = auto()


@dataclass
class MemoryRegion:
    name: str
    base: int
    size: int
    permissions: str  # "rx", "rwx", "rw", etc.
    type: RegionType = RegionType.UNKNOWN

    @property
    def end(self) -> int:
        return self.base + self.size

    def contains(self, address: int) -> bool:
        return self.base <= address < self.end

    def __repr__(self) -> str:
        return (
            f"MemoryRegion({self.name!r}, "
            f"0x{self.base:08x}-0x{self.end:08x}, {self.permissions!r})"
        )


# Standard Cortex-M architectural memory regions
CORTEX_M_ARCH_REGIONS: list[MemoryRegion] = [
    MemoryRegion("Code",            0x00000000, 0x20000000, "rx",  RegionType.CODE),
    MemoryRegion("SRAM",            0x20000000, 0x20000000, "rwx", RegionType.SRAM),
    MemoryRegion("Peripheral",      0x40000000, 0x20000000, "rw",  RegionType.PERIPHERAL),
    MemoryRegion("ExternalRAM",     0x60000000, 0x40000000, "rwx", RegionType.EXTERNAL_RAM),
    MemoryRegion("ExternalDevice",  0xA0000000, 0x40000000, "rw",  RegionType.EXTERNAL_DEVICE),
    MemoryRegion("PPB",             0xE0000000, 0x00100000, "rw",  RegionType.SYSTEM),
    MemoryRegion("VendorSpecific",  0xE0100000, 0x1FF00000, "rw",  RegionType.SYSTEM),
]


class CortexMMemoryMap:
    """Standard Cortex-M memory map for address classification."""

    def __init__(self, regions: list[MemoryRegion] | None = None) -> None:
        self._regions = regions if regions is not None else CORTEX_M_ARCH_REGIONS

    def address_to_region(self, address: int) -> MemoryRegion | None:
        """Find the architectural region containing this address."""
        for region in self._regions:
            if region.contains(address):
                return region
        return None

    def is_executable(self, address: int) -> bool:
        """Return True if the address is in a potentially executable region."""
        region = self.address_to_region(address)
        if region is None:
            return False
        return "x" in region.permissions

    def is_peripheral(self, address: int) -> bool:
        """Return True if the address is a MMIO peripheral register."""
        region = self.address_to_region(address)
        if region is None:
            return False
        return region.type in (RegionType.PERIPHERAL, RegionType.SYSTEM)

    def is_sram(self, address: int) -> bool:
        region = self.address_to_region(address)
        return region is not None and region.type == RegionType.SRAM

    def classify(self, address: int) -> RegionType:
        region = self.address_to_region(address)
        return region.type if region else RegionType.UNKNOWN


def load_machine_memory_map(machine_config_path: str | Path) -> list[MemoryRegion]:
    """Parse a machine YAML config and return a list of MemoryRegion objects."""
    path = Path(machine_config_path)
    with path.open() as f:
        config = yaml.safe_load(f)

    regions: list[MemoryRegion] = []
    memory_section = config.get("memory", {})

    type_map = {
        "flash": RegionType.CODE,
        "sram": RegionType.SRAM,
        "peripherals": RegionType.PERIPHERAL,
        "system": RegionType.SYSTEM,
        "secure_flash": RegionType.CODE,
        "secure_sram": RegionType.SRAM,
        "ccm_sram": RegionType.SRAM,
    }

    for region_name, region_cfg in memory_section.items():
        base = region_cfg["base"]
        size = region_cfg["size"]
        permissions = region_cfg.get("permissions", "rw")
        rtype = type_map.get(region_name, RegionType.UNKNOWN)
        regions.append(MemoryRegion(
            name=region_name,
            base=base,
            size=size,
            permissions=permissions,
            type=rtype,
        ))

    return regions
