"""MMIO interception via GDB access watchpoints.

Sets watchpoints on peripheral address ranges and routes MMIO accesses
to the CompositeMMIOHandler for intelligent handling.
"""

from __future__ import annotations

import logging
import struct
from typing import Optional, Protocol

from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler

logger = logging.getLogger(__name__)


class GDBInterface(Protocol):
    """Protocol for GDB operations needed by MMIO interception."""
    def write_memory(self, address: int, data: bytes) -> None: ...
    def read_memory(self, address: int, size: int) -> bytes: ...
    def set_watchpoint(self, address: int, size: int, type: str) -> int: ...
    def remove_watchpoint(self, wp_id: int) -> None: ...


class MMIOInterceptor:
    """Intercepts MMIO accesses via GDB watchpoints.

    Sets access watchpoints on peripheral memory regions and routes
    read/write operations to the CompositeMMIOHandler.
    """

    def __init__(
        self,
        handler: CompositeMMIOHandler,
        peripheral_ranges: Optional[list[tuple[int, int]]] = None,
    ) -> None:
        self._handler = handler
        self._ranges = peripheral_ranges or [(0x40000000, 0x20000000)]  # Default Cortex-M
        self._watchpoint_ids: list[int] = []
        self._intercept_count: int = 0

    def setup(self, gdb: GDBInterface) -> int:
        """Set up watchpoints. Returns number of watchpoints set."""
        count = 0
        for base, size in self._ranges:
            try:
                wp_id = gdb.set_watchpoint(base, size, "access")
                self._watchpoint_ids.append(wp_id)
                count += 1
                logger.info(f"MMIO watchpoint set: 0x{base:08X}-0x{base+size:08X}")
            except Exception as e:
                logger.warning(f"Failed to set watchpoint at 0x{base:08X}: {e}")
        return count

    def teardown(self, gdb: GDBInterface) -> None:
        """Remove all watchpoints."""
        for wp_id in self._watchpoint_ids:
            try:
                gdb.remove_watchpoint(wp_id)
            except Exception:
                pass
        self._watchpoint_ids.clear()

    def handle_watchpoint(
        self,
        address: int,
        is_write: bool,
        value: int = 0,
        size: int = 4,
        gdb: Optional[GDBInterface] = None,
    ) -> Optional[int]:
        """Handle a watchpoint hit.

        For reads: returns the value to be placed in the target register.
        For writes: processes the write and returns None.
        """
        self._intercept_count += 1

        if is_write:
            self._handler.write(address, value, size)
            return None
        else:
            result = self._handler.read(address, size)
            # Write result back to memory so the CPU reads it
            if gdb is not None:
                try:
                    gdb.write_memory(address, struct.pack("<I", result)[:size])
                except Exception as e:
                    logger.warning(f"Failed to write MMIO result at 0x{address:08X}: {e}")
            return result

    @property
    def intercept_count(self) -> int:
        return self._intercept_count

    @property
    def coverage_stats(self) -> dict:
        return self._handler.get_coverage_stats()
