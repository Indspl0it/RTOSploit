"""Unicorn-based firmware rehosting engine with PIP, FERMCov, and interrupts.

Alternative to QEMU+GDB for MMIO-heavy workloads. Uses Unicorn's
memory hooks for direct peripheral interception without GDB overhead.

Supports:
- Peripheral Input Playback (PIP) for model-free MMIO fuzzing
- FERMCov interrupt-aware edge coverage collection
- Round-robin interrupt scheduling with WFI/WFE detection
- Snapshot/restore for efficient fuzz iterations
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Optional, Callable

from rtosploit.coverage.bitmap import FERMCovCollector
from rtosploit.fuzzing.execution import ExecutionResult, StopReason, make_result
from rtosploit.fuzzing.fuzz_input import FuzzInputStream, InputExhausted
from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler
from rtosploit.peripherals.pip_handler import PIPHandler
from rtosploit.peripherals.interrupt_scheduler import InterruptScheduler
from rtosploit.utils.binary import FirmwareImage

logger = logging.getLogger(__name__)

# Peripheral MMIO address ranges (Cortex-M)
_PERIPH_START = 0x40000000
_PERIPH_END = 0x60000000
_SYSTEM_REG_START = 0xE0000000
_SYSTEM_REG_END = 0xE0100000

# NVIC Interrupt Set Pending Register base
_NVIC_ISPR_BASE = 0xE000E200

# WFI/WFE Thumb instruction opcodes
_WFI_THUMB = 0xBF30
_WFE_THUMB = 0xBF20

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN
    from unicorn.arm_const import (
        UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,  # noqa: F401
        UC_ARM_REG_CPSR,
    )
    from unicorn import (
        UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,  # noqa: F401
        UC_HOOK_CODE, UC_HOOK_BLOCK,
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
    Supports PIP-based fuzzing, FERMCov coverage, interrupt scheduling,
    and snapshot/restore for efficient fuzz iterations.
    """

    def __init__(
        self,
        firmware: FirmwareImage,
        mmio_handler: Optional[CompositeMMIOHandler] = None,
        max_blocks: int = 500_000,
        sram_size: int = 256 * 1024,
    ) -> None:
        if not HAS_UNICORN:
            raise ImportError("unicorn package not installed. Install with: pip install unicorn")

        self._firmware = firmware
        self._mmio_handler = mmio_handler or CompositeMMIOHandler()
        self._uc: Optional[Uc] = None
        self._hal_hooks: dict[int, Callable] = {}  # address -> handler
        self._execution_count: int = 0
        self._block_count: int = 0
        self._max_blocks = max_blocks
        self._sram_size = sram_size
        self._stopped: bool = False
        self._stop_reason: str = ""
        self._stop_reason_enum: Optional[StopReason] = None
        self._crash_address: int = 0
        self._crash_type: str = ""

        # Dynamic page tracking to avoid double-mapping
        self._mapped_pages: set[int] = set()

        # Coverage collector (FERMCov: interrupt-aware)
        self._fermcov = FERMCovCollector()

        # Interrupt scheduler (configured via set_interrupt_scheduler)
        self._scheduler: Optional[InterruptScheduler] = None

        # PIP handler (configured per fuzz iteration via set_fuzz_input)
        self._pip_handler: Optional[PIPHandler] = None

        # Previous block address for infinite loop detection
        self._prev_block_address: int = 0

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _detect_memory_regions(self) -> tuple[tuple[int, int], tuple[int, int]]:
        """Detect flash and SRAM regions from firmware.

        Follows the Ember-IO approach: identify two contiguous memory
        regions (flash for code/rodata, SRAM for data/bss) rather than
        mapping individual sections which can overlap or leave gaps.

        Returns:
            ((flash_base, flash_size), (sram_base, sram_size))
        """
        flash_base = self._firmware.base_address
        flash_size = 256 * 1024  # Default 256KB

        if self._firmware.sections:
            # Classify sections by address range
            code_sections = [
                s for s in self._firmware.sections
                if s.address < 0x20000000 and s.data and len(s.data) > 0
            ]
            if code_sections:
                flash_base = min(s.address for s in code_sections) & ~0xFFF
                flash_end = max(s.address + len(s.data) for s in code_sections)
                flash_size = max(((flash_end - flash_base + 0xFFF) & ~0xFFF), 0x1000)
                # Ensure vector table is included (starts at base 0 for Cortex-M)
                if flash_base > 0 and self._firmware.base_address == 0:
                    flash_base = 0
                    flash_size = max(flash_size, ((flash_end + 0xFFF) & ~0xFFF))
        elif len(self._firmware.data) > 0:
            # Raw binary: flash = entire firmware data
            flash_size = ((len(self._firmware.data) + 0xFFF) & ~0xFFF)

        # Clamp flash to reasonable size (max 16MB)
        flash_size = min(flash_size, 16 * 1024 * 1024)

        sram_base = 0x20000000
        sram_size = ((self._sram_size + 0xFFF) & ~0xFFF)

        return (flash_base, flash_size), (sram_base, sram_size)

    def setup(self) -> None:
        """Initialize Unicorn engine and load firmware.

        Memory layout (following Ember-IO approach):
        - Flash region: R+X, contains code and read-only data
        - SRAM region: R+W, contains .data, .bss, stack, heap
        - Peripheral region (0x40000000-0x5FFFFFFF): intentionally unmapped
          so MMIO accesses trigger hooks for PIP/SVD handling
        - System registers (0xE0000000-0xE00FFFFF): R+W with defaults
        """
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
        uc = self._uc
        self._mapped_pages.clear()

        (flash_base, flash_size), (sram_base, sram_size) = self._detect_memory_regions()

        # 1. Map flash region (R+X) — code and read-only data
        uc.mem_map(flash_base, flash_size, 5)  # UC_PROT_READ | UC_PROT_EXEC
        for page in range(flash_base, flash_base + flash_size, 0x1000):
            self._mapped_pages.add(page)

        # 2. Map SRAM region (R+W+X) — data, bss, stack, heap
        # R+W+X because some firmware executes from SRAM (copied ISR trampolines)
        uc.mem_map(sram_base, sram_size, 7)  # UC_PROT_ALL
        for page in range(sram_base, sram_base + sram_size, 0x1000):
            self._mapped_pages.add(page)

        # 3. Write firmware data into mapped regions
        if self._firmware.sections:
            for section in self._firmware.sections:
                if not section.data or len(section.data) == 0:
                    continue
                # Skip peripheral and system register sections
                if _PERIPH_START <= section.address < _PERIPH_END:
                    continue
                if _SYSTEM_REG_START <= section.address < _SYSTEM_REG_END:
                    continue
                # Write section data into the appropriate mapped region
                try:
                    uc.mem_write(section.address, section.data)
                except Exception as e:
                    logger.debug(f"Could not write section {section.name} at "
                                f"0x{section.address:08X}: {e}")
        else:
            # Raw binary: write entire firmware data to flash base
            uc.mem_write(self._firmware.base_address, self._firmware.data)

        # 4. Map peripheral region (0x40000000-0x5FFFFFFF) as R+W
        # We map it so reads don't trigger UC_HOOK_MEM_READ_UNMAPPED (which
        # only fires once per page). Instead, we use UC_HOOK_MEM_READ on the
        # range to intercept EVERY read for PIP/SVD routing.
        periph_size = _PERIPH_END - _PERIPH_START
        uc.mem_map(_PERIPH_START, periph_size, 3)  # UC_PROT_READ | UC_PROT_WRITE
        for page in range(_PERIPH_START, _PERIPH_END, 0x1000):
            self._mapped_pages.add(page)

        # 5. Map system registers region (0xE0000000-0xE00FFFFF) with R+W
        uc.mem_map(_SYSTEM_REG_START, _SYSTEM_REG_END - _SYSTEM_REG_START, 3)
        for page in range(_SYSTEM_REG_START, _SYSTEM_REG_END, 0x1000):
            self._mapped_pages.add(page)

        # Set up hooks
        # Use UC_HOOK_MEM_READ on peripheral range to intercept EVERY MMIO read
        # (not just unmapped — the region is mapped but we override values via hook)
        uc.hook_add(UC_HOOK_MEM_READ, self._hook_periph_read,
                     begin=_PERIPH_START, end=_PERIPH_END - 1)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_periph_write,
                     begin=_PERIPH_START, end=_PERIPH_END - 1)
        # System register reads/writes
        uc.hook_add(UC_HOOK_MEM_READ, self._hook_sysreg_read,
                     begin=_SYSTEM_REG_START, end=_SYSTEM_REG_END - 1)
        uc.hook_add(UC_HOOK_MEM_WRITE, self._hook_sysreg_write,
                     begin=_SYSTEM_REG_START, end=_SYSTEM_REG_END - 1)
        # Unmapped access outside peripheral/system = crash
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_unmapped_access)
        uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_unmapped_access)
        uc.hook_add(UC_HOOK_BLOCK, self._hook_block)
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

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_fuzz_input(self, data: bytes) -> None:
        """Create PIPHandler from fuzz input and wire into CompositeMMIOHandler.

        Args:
            data: Raw fuzz input bytes from the fuzzer.
        """
        stream = FuzzInputStream(data)
        self._pip_handler = PIPHandler(stream)
        # Wire PIP into the composite handler
        self._mmio_handler._pip_handler = self._pip_handler

    def set_interrupt_scheduler(self, scheduler: InterruptScheduler) -> None:
        """Configure the interrupt scheduler for this engine.

        Args:
            scheduler: Pre-configured InterruptScheduler with IRQ list.
        """
        self._scheduler = scheduler

    def add_hal_hook(self, address: int, handler: Callable) -> None:
        """Register a HAL function hook at the given address."""
        self._hal_hooks[address] = handler

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self, timeout_ms: int = 10000, max_instructions: int = 0) -> str:
        """Run firmware emulation. Returns stop reason string."""
        if self._uc is None:
            raise RuntimeError("Call setup() first")

        self._stopped = False
        self._stop_reason = "timeout"
        self._stop_reason_enum = StopReason.TIMEOUT

        pc = self._uc.reg_read(UC_ARM_REG_PC)
        start = pc | 1  # Thumb mode: set bit 0

        try:
            self._uc.emu_start(
                start,
                0xFFFFFFFF,  # Run until stopped
                timeout=timeout_ms * 1000,  # microseconds
                count=max_instructions or 0,
            )
        except Exception as e:
            if not self._stopped:
                self._stop_reason = f"error: {e}"

        return self._stop_reason

    def run_fuzz_iteration(self, fuzz_input: bytes) -> ExecutionResult:
        """Run a single fuzz iteration with the given input.

        Performs: restore snapshot state, wire PIP, reset coverage,
        run until termination, collect results.

        Requires that setup() has been called and a snapshot has been
        taken and stored (call take_snapshot() after initial setup).

        Args:
            fuzz_input: Raw bytes from the fuzzer.

        Returns:
            ExecutionResult with coverage, stop reason, crash info.
        """
        if self._uc is None:
            raise RuntimeError("Call setup() first")

        # 1. Wire PIP handler with fresh fuzz input
        self.set_fuzz_input(fuzz_input)

        # 2. Reset coverage collector
        self._fermcov.reset()

        # 3. Reset interrupt scheduler
        if self._scheduler:
            self._scheduler.reset()

        # 4. Reset execution state
        self._block_count = 0
        self._prev_block_address = 0
        self._stopped = False
        self._stop_reason = "timeout"
        self._stop_reason_enum = StopReason.TIMEOUT
        self._crash_address = 0
        self._crash_type = ""

        # 5. Run Unicorn until termination
        pc = self._uc.reg_read(UC_ARM_REG_PC)
        start = pc | 1

        try:
            self._uc.emu_start(
                start,
                0xFFFFFFFF,
                timeout=30_000_000,  # 30s timeout in microseconds
                count=0,
            )
        except Exception as e:
            if not self._stopped:
                self._stop_reason = f"error: {e}"
                self._stop_reason_enum = StopReason.TIMEOUT

        # 6. Build result
        stop_reason = self._stop_reason_enum or StopReason.TIMEOUT

        # Compute input consumed
        input_consumed = 0
        pip_stats = None
        if self._pip_handler:
            pip_stats = self._pip_handler.stats.to_dict()
            input_consumed = len(fuzz_input) - self._pip_handler.remaining_input_bytes

        return make_result(
            stop_reason,
            crash_address=self._crash_address,
            crash_type=self._crash_type,
            blocks_executed=self._block_count,
            coverage=self._fermcov.bitmap,
            input_consumed=input_consumed,
            pip_stats=pip_stats,
        )

    def stop(self, reason: str = "user") -> None:
        """Stop emulation."""
        self._stopped = True
        self._stop_reason = reason
        if self._uc:
            self._uc.emu_stop()

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # MMIO hooks with PIP routing
    # ------------------------------------------------------------------

    def _hook_periph_read(self, uc, access, address, size, value, user_data):
        """Intercept EVERY read in the peripheral MMIO range.

        Routes through CompositeMMIOHandler (SVD -> PIP -> fallback).
        The peripheral region is mapped as R+W so this hook fires on every
        access, not just the first (unlike UC_HOOK_MEM_READ_UNMAPPED).
        """
        try:
            result = self._mmio_handler.read(address, size)
        except InputExhausted:
            self._stopped = True
            self._stop_reason = "input_exhausted"
            self._stop_reason_enum = StopReason.INPUT_EXHAUSTED
            uc.emu_stop()
            return
        # Write the PIP/SVD result into mapped memory so the CPU reads it
        uc.mem_write(address, struct.pack("<I", result & 0xFFFFFFFF)[:size])

    def _hook_periph_write(self, uc, access, address, size, value, user_data):
        """Intercept EVERY write in the peripheral MMIO range."""
        try:
            self._mmio_handler.write(address, value, size)
        except InputExhausted:
            self._stopped = True
            self._stop_reason = "input_exhausted"
            self._stop_reason_enum = StopReason.INPUT_EXHAUSTED
            uc.emu_stop()

    def _hook_sysreg_read(self, uc, access, address, size, value, user_data):
        """Intercept reads in the system register range (0xE0000000+)."""
        result = self._mmio_handler.read(address, size)
        uc.mem_write(address, struct.pack("<I", result & 0xFFFFFFFF)[:size])

    def _hook_sysreg_write(self, uc, access, address, size, value, user_data):
        """Intercept writes in the system register range."""
        self._mmio_handler.write(address, value, size)

    def _hook_unmapped_access(self, uc, access, address, size, value, user_data):
        """Handle unmapped access outside peripheral/system ranges = crash."""
        is_write = access in (2, 3, 4, 5)  # UC_MEM_WRITE variants
        self._stopped = True
        self._stop_reason = "unmapped_access"
        self._stop_reason_enum = StopReason.UNMAPPED_ACCESS
        self._crash_address = address
        self._crash_type = f"unmapped_{'write' if is_write else 'read'} at 0x{address:08X}"
        logger.debug("Unmapped access at 0x%08X (crash)", address)
        uc.emu_stop()
        return False

    # ------------------------------------------------------------------
    # Block hook (coverage + interrupts)
    # ------------------------------------------------------------------

    def _hook_block(self, uc, address, size, user_data):
        """Block hook: coverage recording, interrupt scheduling, loop detection."""
        self._block_count += 1

        # Check if in interrupt handler (IPSR != 0)
        try:
            cpsr = uc.reg_read(UC_ARM_REG_CPSR)
            # Exception number is in bits [8:0] of xPSR (same as CPSR on Cortex-M)
            in_interrupt = (cpsr & 0x1FF) != 0
        except Exception:
            in_interrupt = False

        # Record coverage via FERMCov
        self._fermcov.on_block(address, in_interrupt)

        # Interrupt scheduling
        if self._scheduler:
            irq = self._scheduler.on_block()
            if irq is not None:
                self._inject_irq(uc, irq)

        # Infinite loop detection: block jumps to itself
        if address == self._prev_block_address:
            self._stopped = True
            self._stop_reason = "infinite_loop"
            self._stop_reason_enum = StopReason.INFINITE_LOOP
            uc.emu_stop()
            return

        self._prev_block_address = address

        # Max blocks check
        if self._block_count >= self._max_blocks:
            self._stopped = True
            self._stop_reason = "timeout"
            self._stop_reason_enum = StopReason.TIMEOUT
            uc.emu_stop()
            return

    # ------------------------------------------------------------------
    # Code hook (WFI/WFE + HAL hooks)
    # ------------------------------------------------------------------

    def _hook_code(self, uc, address, size, user_data):
        """Instruction-level hook for WFI/WFE detection and HAL hooks."""
        self._execution_count += 1

        # WFI/WFE detection (Thumb: 2-byte instructions)
        if size == 2:
            try:
                insn_bytes = uc.mem_read(address, 2)
                opcode = int.from_bytes(insn_bytes, "little")

                if opcode == _WFI_THUMB or opcode == _WFE_THUMB:
                    # CPU is waiting for interrupt -> trigger scheduler
                    if self._scheduler:
                        irq = self._scheduler.on_wfi()
                        if irq is not None:
                            self._inject_irq(uc, irq)
                    # Skip the WFI/WFE instruction
                    uc.reg_write(UC_ARM_REG_PC, (address + 2) | 1)
                    return
            except Exception:
                pass

        # HAL hooks
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
                logger.warning("HAL hook error at 0x%08X: %s", address, e)

    # ------------------------------------------------------------------
    # Interrupt injection
    # ------------------------------------------------------------------

    def _inject_irq(self, uc, irq_number: int) -> None:
        """Inject an interrupt by writing to NVIC_ISPR."""
        register_index = irq_number // 32
        bit_position = irq_number % 32
        ispr_addr = _NVIC_ISPR_BASE + register_index * 4
        value = 1 << bit_position

        try:
            uc.mem_write(ispr_addr, struct.pack("<I", value))
            logger.debug("Injected IRQ %d via NVIC_ISPR (0x%08X)", irq_number, ispr_addr)
        except Exception as e:
            logger.debug("Failed to inject IRQ %d: %s", irq_number, e)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def execution_count(self) -> int:
        """Total instruction count."""
        return self._execution_count

    @property
    def block_count(self) -> int:
        """Total basic block count."""
        return self._block_count

    @property
    def mmio_stats(self) -> dict:
        """MMIO handler routing statistics."""
        return self._mmio_handler.get_coverage_stats()

    @property
    def fermcov(self) -> FERMCovCollector:
        """Access the FERMCov coverage collector."""
        return self._fermcov

    @property
    def scheduler(self) -> Optional[InterruptScheduler]:
        """Access the interrupt scheduler (None if not configured)."""
        return self._scheduler

    @property
    def pip_handler(self) -> Optional[PIPHandler]:
        """Access the current PIP handler (None if not configured)."""
        return self._pip_handler

    @property
    def uc(self) -> Optional[object]:
        """Access the underlying Unicorn engine (for advanced use)."""
        return self._uc
