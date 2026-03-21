"""Intercept dispatcher — routes GDB breakpoint hits to peripheral handlers."""

from __future__ import annotations

import logging
from typing import Any, Callable, TYPE_CHECKING

from rtosploit.peripherals.model import CPUState, PeripheralModel

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class InterceptDispatcher:
    """Dispatches GDB breakpoint hits to registered peripheral handlers.

    Maintains a lookup table: address -> (model_instance, handler_method).
    When a breakpoint fires, reads CPU state, calls handler, applies result.
    """

    def __init__(self, gdb: Any) -> None:
        self._gdb = gdb
        self._bp_table: dict[int, tuple[PeripheralModel, Callable]] = {}
        self._stats: dict[int, int] = {}  # addr -> hit count

    def register(self, model: PeripheralModel, func_name: str, address: int) -> None:
        """Register a handler for a specific address.

        Finds the method on `model` decorated with @hal_handler matching func_name.
        Sets a GDB breakpoint at the address.
        """
        handler = model._find_handler(func_name)
        addr = address & ~1  # Clear thumb bit
        self._gdb.set_breakpoint(addr)
        self._bp_table[addr] = (model, handler)

    def handle_breakpoint(self, stop_addr: int) -> bool:
        """Called when GDB reports a breakpoint hit.

        Returns True if the breakpoint was handled (intercepted), False if unknown.
        """
        addr = stop_addr & ~1
        if addr not in self._bp_table:
            return False

        model, handler = self._bp_table[addr]

        # Build CPU state
        regs = self._gdb.read_registers()
        cpu_state = CPUState(regs=regs, _gdb=self._gdb)

        # Call handler
        result = handler(cpu_state)

        if result.intercept:
            # Replace function: set return value in r0, jump to LR
            if result.return_value is not None:
                self._gdb.write_register(0, result.return_value)  # r0
            lr = regs.get("lr", 0)
            self._gdb.write_register(15, lr | 1)  # pc = lr (keep thumb bit)

        self._stats[addr] = self._stats.get(addr, 0) + 1
        logger.debug(
            "Intercepted %s at 0x%08x (count=%d, intercept=%s)",
            model.name, addr, self._stats[addr], result.intercept,
        )
        return True

    @property
    def stats(self) -> dict[int, int]:
        """Return a copy of the hit count statistics."""
        return dict(self._stats)

    @property
    def registered_addresses(self) -> set[int]:
        """Return set of all registered breakpoint addresses."""
        return set(self._bp_table.keys())
