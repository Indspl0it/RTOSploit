"""Round-robin interrupt scheduling for firmware fuzzing.

Triggers interrupts in round-robin fashion based on basic block count,
following the interrupt management approach from Ember-IO. Also triggers
an interrupt when the CPU enters sleep mode (WFI/WFE instructions).

References:
    Farrelly, Chesser, Ranasinghe. "Ember-IO: Effective Firmware Fuzzing
    with Model-Free Memory Mapped IO." ASIA CCS 2023.
    https://doi.org/10.1145/3579856.3582840
"""

from __future__ import annotations

import logging
from typing import Optional

from rtosploit.peripherals.interrupt_injector import InterruptInjector
from rtosploit.utils.binary import FirmwareImage

logger = logging.getLogger(__name__)


class InterruptScheduler:
    """Round-robin interrupt scheduler for Unicorn-based firmware emulation.

    Fires the next IRQ in its list every *interval* basic blocks.  When
    the CPU executes WFI/WFE, the next IRQ fires immediately regardless
    of the block counter (since no blocks execute during sleep).

    Args:
        irq_list: Ordered list of external IRQ numbers to cycle through.
        interval: Number of basic blocks between interrupt injections.
    """

    def __init__(self, irq_list: list[int], interval: int = 1000) -> None:
        self._irqs = list(irq_list)
        self._interval = max(1, interval)
        self._block_count: int = 0
        self._irq_index: int = 0
        self._interrupts_fired: int = 0

    # ------------------------------------------------------------------
    # Block hook
    # ------------------------------------------------------------------

    def on_block(self) -> Optional[int]:
        """Called on every basic block execution.

        Returns the IRQ number to inject if the interval has elapsed,
        or ``None`` if no interrupt should fire this block.
        """
        if not self._irqs:
            self._block_count += 1
            return None

        self._block_count += 1

        if self._block_count % self._interval != 0:
            return None

        return self._fire_next()

    # ------------------------------------------------------------------
    # WFI / WFE handling
    # ------------------------------------------------------------------

    def on_wfi(self) -> Optional[int]:
        """Called when firmware executes WFI or WFE.

        Always returns the next IRQ in the round-robin, since sleep
        means the firmware is waiting for an interrupt.  Returns ``None``
        only if the IRQ list is empty.
        """
        if not self._irqs:
            return None
        return self._fire_next()

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset block counter and IRQ index for a new execution."""
        self._block_count = 0
        self._irq_index = 0
        self._interrupts_fired = 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict[str, int]:
        """Scheduler statistics.

        Returns:
            Dict with keys ``blocks_counted``, ``interrupts_fired``,
            ``current_irq``.
        """
        current = self._irqs[self._irq_index % len(self._irqs)] if self._irqs else -1
        return {
            "blocks_counted": self._block_count,
            "interrupts_fired": self._interrupts_fired,
            "current_irq": current,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _fire_next(self) -> int:
        """Select the next IRQ in round-robin order and return it."""
        irq = self._irqs[self._irq_index % len(self._irqs)]
        self._irq_index += 1
        self._interrupts_fired += 1
        logger.debug("Firing IRQ %d (injection #%d)", irq, self._interrupts_fired)
        return irq


def discover_irqs(firmware: FirmwareImage) -> list[int]:
    """Discover injectable IRQ numbers from a firmware image.

    Uses :class:`InterruptInjector`'s ISR discovery to parse the Cortex-M
    vector table and extract external IRQ numbers that have registered
    handlers.

    Args:
        firmware: Parsed firmware image with vector table.

    Returns:
        Sorted list of external IRQ numbers with registered handlers.
    """
    injector = InterruptInjector(firmware)
    return sorted(injector.injectable_irqs)
