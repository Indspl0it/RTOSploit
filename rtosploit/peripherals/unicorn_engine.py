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

    def setup(self) -> None:
        """Initialize Unicorn engine and load firmware.

        Maps firmware flash, SRAM, and system register regions.
        Intentionally does NOT map the peripheral region (0x40000000-0x5FFFFFFF)
        so MMIO accesses trigger unmapped hooks for PIP/SVD handling.
        """
        self._uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
        uc = self._uc
        self._mapped_pages.clear()

        # Map memory regions from firmware sections
        if self._firmware.sections:
            for section in self._firmware.sections:
                if not section.data:
                    continue
                # Align to 4KB page boundary
                base = section.address & ~0xFFF
                end = section.address + section.size
                size = ((end - base) + 0xFFF) & ~0xFFF
                size = max(size, 0x1000)

                # Determine permissions
                perms = section.permissions if hasattr(section, 'permissions') else "rx"
                uc_perms = 0
                if "r" in perms:
                    uc_perms |= 1  # UC_PROT_READ
                if "w" in perms:
                    uc_perms |= 2  # UC_PROT_WRITE
                if "x" in perms:
                    uc_perms |= 4  # UC_PROT_EXEC

                try:
                    uc.mem_map(base, size, uc_perms or 7)
                    uc.mem_write(section.address, section.data)
                    # Track mapped pages
                    for page in range(base, base + size, 0x1000):
                        self._mapped_pages.add(page)
                except Exception:
                    pass  # Region may overlap, skip
        else:
            # Raw binary: map at base address with R+X
            base = self._firmware.base_address & ~0xFFF
            size = ((len(self._firmware.data) + 0xFFF) & ~0xFFF) + 0x1000
            uc.mem_map(base, size, 5)  # UC_PROT_READ | UC_PROT_EXEC
            uc.mem_write(self._firmware.base_address, self._firmware.data)
            for page in range(base, base + size, 0x1000):
                self._mapped_pages.add(page)

        # Map SRAM with R+W permissions
        sram_base = 0x20000000
        sram_size = ((self._sram_size + 0xFFF) & ~0xFFF)
        uc.mem_map(sram_base, sram_size, 3)  # UC_PROT_READ | UC_PROT_WRITE
        for page in range(sram_base, sram_base + sram_size, 0x1000):
            self._mapped_pages.add(page)

        # Peripheral region (0x40000000-0x5FFFFFFF): intentionally NOT mapped
        # MMIO accesses trigger unmapped hooks -> PIP/SVD/fallback

        # Map system registers region (0xE0000000-0xE00FFFFF) with R+W
        uc.mem_map(_SYSTEM_REG_START, _SYSTEM_REG_END - _SYSTEM_REG_START, 3)
        for page in range(_SYSTEM_REG_START, _SYSTEM_REG_END, 0x1000):
            self._mapped_pages.add(page)

        # Set up hooks
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._hook_mem_read_unmapped)
        uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._hook_mem_write_unmapped)
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

    def _map_page_if_needed(self, uc, address: int) -> bool:
        """Map a 4KB page if not already mapped. Returns True if mapped."""
        page_base = address & ~0xFFF
        if page_base in self._mapped_pages:
            return True
        try:
            uc.mem_map(page_base, 0x1000, 3)  # R+W
            self._mapped_pages.add(page_base)
            return True
        except Exception:
            return False

    def _hook_mem_read_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory reads with PIP routing.

        Routing:
        - Peripheral range (0x40000000-0x5FFFFFFF): SVD -> PIP -> fallback
        - System registers (0xE0000000-0xE00FFFFF): system reg handler
        - Other: crash (unmapped non-peripheral access)
        """
        if _PERIPH_START <= address < _PERIPH_END:
            # Peripheral MMIO range -> route through composite handler
            try:
                result = self._mmio_handler.read(address, size)
            except InputExhausted:
                self._stopped = True
                self._stop_reason = "input_exhausted"
                self._stop_reason_enum = StopReason.INPUT_EXHAUSTED
                uc.emu_stop()
                return False
            self._map_page_if_needed(uc, address)
            uc.mem_write(address, struct.pack("<I", result & 0xFFFFFFFF)[:size])
            return True

        elif _SYSTEM_REG_START <= address < _SYSTEM_REG_END:
            # System registers -> composite handler routes to CortexMSystemRegisters
            result = self._mmio_handler.read(address, size)
            self._map_page_if_needed(uc, address)
            uc.mem_write(address, struct.pack("<I", result & 0xFFFFFFFF)[:size])
            return True

        else:
            # Non-peripheral unmapped access -> crash
            self._stopped = True
            self._stop_reason = "unmapped_access"
            self._stop_reason_enum = StopReason.UNMAPPED_ACCESS
            self._crash_address = address
            self._crash_type = f"unmapped_read at 0x{address:08X}"
            logger.debug("Unmapped non-peripheral read at 0x%08X", address)
            uc.emu_stop()
            return False

    def _hook_mem_write_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory writes with PIP routing."""
        if _PERIPH_START <= address < _PERIPH_END:
            # Peripheral MMIO write
            try:
                self._mmio_handler.write(address, value, size)
            except InputExhausted:
                self._stopped = True
                self._stop_reason = "input_exhausted"
                self._stop_reason_enum = StopReason.INPUT_EXHAUSTED
                uc.emu_stop()
                return False
            self._map_page_if_needed(uc, address)
            return True

        elif _SYSTEM_REG_START <= address < _SYSTEM_REG_END:
            self._mmio_handler.write(address, value, size)
            self._map_page_if_needed(uc, address)
            return True

        else:
            # Non-peripheral unmapped access -> crash
            self._stopped = True
            self._stop_reason = "unmapped_access"
            self._stop_reason_enum = StopReason.UNMAPPED_ACCESS
            self._crash_address = address
            self._crash_type = f"unmapped_write at 0x{address:08X}"
            logger.debug("Unmapped non-peripheral write at 0x%08X", address)
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
