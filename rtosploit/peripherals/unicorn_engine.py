"""Unicorn-based firmware rehosting engine.

Alternative to QEMU+GDB for MMIO-heavy workloads. Uses Unicorn's
memory hooks for direct peripheral interception without GDB overhead.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Optional, Callable

from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler
from rtosploit.utils.binary import FirmwareImage, MemorySection

logger = logging.getLogger(__name__)

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN
    from unicorn.arm_const import (
        UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    )
    from unicorn import (
        UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
        UC_HOOK_CODE,
    )
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False


@dataclass
class UnicornSnapshot:
    """CPU state snapshot for fuzzing."""
    context: object = None  # UcContext or bytes depending on unicorn version
    memory_regions: dict[int, bytes] = field(default_factory=dict)


class UnicornRehostEngine:
    """Firmware rehosting via Unicorn CPU emulator.

    Provides direct MMIO hook callbacks without GDB overhead.
    Supports snapshot/restore for efficient fuzzing.
    """

    def __init__(
        self,
        firmware: FirmwareImage,
        mmio_handler: Optional[CompositeMMIOHandler] = None,
    ) -> None:
        if not HAS_UNICORN:
            raise ImportError("unicorn package not installed. Install with: pip install unicorn")

        self._firmware = firmware
        self._mmio_handler = mmio_handler or CompositeMMIOHandler()
        self._uc: Optional[Uc] = None
        self._hal_hooks: dict[int, Callable] = {}  # address -> handler
        self._execution_count: int = 0
        self._stopped: bool = False
        self._stop_reason: str = ""

    def setup(self) -> None:
        """Initialize Unicorn engine and load firmware."""
        # Create Unicorn instance for ARM Thumb mode
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
        uc = self._uc

        # Map memory regions from firmware sections
        if self._firmware.sections:
            for section in self._firmware.sections:
                if not section.data:
                    continue
                # Align to 4KB page boundary
                base = section.address & ~0xFFF
                size = ((section.address + section.size - base) + 0xFFF) & ~0xFFF
                size = max(size, 0x1000)
                try:
                    uc.mem_map(base, size)
                    uc.mem_write(section.address, section.data)
                except Exception:
                    pass  # Region may overlap, skip
        else:
            # Raw binary: map at base address
            base = self._firmware.base_address & ~0xFFF
            size = ((len(self._firmware.data) + 0xFFF) & ~0xFFF) + 0x1000
            uc.mem_map(base, size)
            uc.mem_write(self._firmware.base_address, self._firmware.data)

        # Map SRAM (256KB at 0x20000000)
        uc.mem_map(0x20000000, 256 * 1024)

        # Map peripheral region (catch MMIO accesses)
        # We DON'T map 0x40000000-0x60000000 — let it trigger unmapped hooks

        # Map system registers region
        uc.mem_map(0xE0000000, 0x00100000)

        # Set up hooks
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_mem_read_unmapped)
        uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_write_unmapped)
        uc.hook_add(UC_HOOK_CODE, self._hook_code)

        # Set initial SP and PC from vector table
        try:
            vtable = self._firmware.get_vector_table()
            if "initial_sp" in vtable:
                uc.reg_write(UC_ARM_REG_SP, vtable["initial_sp"])
            if "reset" in vtable:
                uc.reg_write(UC_ARM_REG_PC, vtable["reset"] & ~1)
        except (ValueError, Exception):
            uc.reg_write(UC_ARM_REG_SP, 0x20040000)
            uc.reg_write(UC_ARM_REG_PC, self._firmware.entry_point & ~1)

        logger.info("Unicorn engine setup complete")

    def add_hal_hook(self, address: int, handler: Callable) -> None:
        """Register a HAL function hook at the given address."""
        self._hal_hooks[address] = handler

    def run(self, timeout_ms: int = 10000, max_instructions: int = 0) -> str:
        """Run firmware emulation. Returns stop reason."""
        if self._uc is None:
            raise RuntimeError("Call setup() first")

        self._stopped = False
        self._stop_reason = "timeout"

        pc = self._uc.reg_read(UC_ARM_REG_PC)
        # Thumb mode: set bit 0
        start = pc | 1

        try:
            self._uc.emu_start(
                start,
                0xFFFFFFFF,  # Run until stopped
                timeout=timeout_ms * 1000,  # microseconds
                count=max_instructions or 0,
            )
        except Exception as e:
            self._stop_reason = f"error: {e}"

        return self._stop_reason

    def stop(self, reason: str = "user") -> None:
        """Stop emulation."""
        self._stopped = True
        self._stop_reason = reason
        if self._uc:
            self._uc.emu_stop()

    def take_snapshot(self) -> UnicornSnapshot:
        """Save CPU state for later restore."""
        if self._uc is None:
            raise RuntimeError("Engine not initialized")
        return UnicornSnapshot(context=self._uc.context_save())

    def restore_snapshot(self, snapshot: UnicornSnapshot) -> None:
        """Restore CPU state from snapshot."""
        if self._uc is None:
            raise RuntimeError("Engine not initialized")
        self._uc.context_restore(snapshot.context)

    def _hook_mem_read_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory reads (MMIO peripheral access)."""
        result = self._mmio_handler.read(address, size)
        # Map the page and write the result
        page_base = address & ~0xFFF
        try:
            uc.mem_map(page_base, 0x1000)
        except Exception:
            pass
        uc.mem_write(address, struct.pack("<I", result)[:size])
        return True

    def _hook_mem_write_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory writes (MMIO peripheral access)."""
        self._mmio_handler.write(address, value, size)
        # Map the page to prevent repeated unmapped faults
        page_base = address & ~0xFFF
        try:
            uc.mem_map(page_base, 0x1000)
        except Exception:
            pass
        return True

    def _hook_code(self, uc, address, size, user_data):
        """Handle code execution — check for HAL hooks."""
        self._execution_count += 1

        if address in self._hal_hooks:
            handler = self._hal_hooks[address]
            try:
                result = handler()
                if isinstance(result, int):
                    uc.reg_write(UC_ARM_REG_R0, result)
                # Jump to LR (return from function)
                lr = uc.reg_read(UC_ARM_REG_LR)
                uc.reg_write(UC_ARM_REG_PC, lr & ~1)
            except Exception as e:
                logger.warning(f"HAL hook error at 0x{address:08X}: {e}")

    @property
    def execution_count(self) -> int:
        return self._execution_count

    @property
    def mmio_stats(self) -> dict:
        return self._mmio_handler.get_coverage_stats()
