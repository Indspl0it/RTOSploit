"""Resolves MMIO addresses to (peripheral_name, register_offset) tuples.

The resolver is built from a MachineConfig and is consulted by QEMU memory
hooks to annotate MemoryAccessEvents with peripheral identity before they are
published on the InstrumentationBus.
"""

from __future__ import annotations

from typing import Optional

from rtosploit.emulation.machines import MachineConfig


class PeripheralResolver:
    """Map MMIO addresses to peripheral name and register offset.

    Construction is O(n) in peripheral count; resolve() is O(n) but n is
    typically small (< 30 peripherals per board).
    """

    def __init__(self, machine_config: MachineConfig) -> None:
        # _peripherals: base_addr -> (name, size)
        self._peripherals: dict[int, tuple[str, int]] = {}
        for name, cfg in machine_config.peripherals.items():
            self._peripherals[cfg.base] = (name, cfg.size)

    def resolve(self, address: int) -> Optional[tuple[str, int]]:
        """Return ``(peripheral_name, register_offset)`` or ``None`` if *address* is not MMIO."""
        for base, (name, size) in self._peripherals.items():
            if base <= address < base + size:
                return (name, address - base)
        return None

    def is_mmio(self, address: int) -> bool:
        """Return True if *address* falls within any known peripheral range."""
        return self.resolve(address) is not None
