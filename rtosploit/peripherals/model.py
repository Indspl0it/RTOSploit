"""Peripheral model base classes for HALucinator-style firmware rehosting.

Provides PeripheralModel (base class for peripheral stubs), CPUState (read-only
CPU snapshot), HandlerResult (return value from handlers), and @hal_handler
decorator for registering HAL function intercepts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from rtosploit.emulation.gdb import GDBClient


# Sentinel used by @hal_handler to tag methods
_HAL_HANDLER_ATTR = "_hal_handler_funcs"


def hal_handler(func_names: list[str] | str) -> Callable:
    """Decorator to register a method as a HAL function handler.

    Usage:
        @hal_handler(['HAL_UART_Transmit', 'HAL_UART_Transmit_IT'])
        def handle_tx(self, cpu_state: CPUState) -> HandlerResult:
            ...
    """
    if isinstance(func_names, str):
        func_names = [func_names]

    def decorator(method: Callable) -> Callable:
        setattr(method, _HAL_HANDLER_ATTR, list(func_names))
        return method

    return decorator


@dataclass
class HandlerResult:
    """Result returned by a HAL function handler."""
    intercept: bool = True       # True = replace function (set PC=LR), False = let it run
    return_value: int | None = 0 # Value to put in r0 (return register)


@dataclass
class CPUState:
    """CPU state snapshot passed to HAL handlers.

    Provides read-only access to registers and helper methods for
    reading function arguments and accessing target memory.
    """
    regs: dict[str, int]
    _gdb: Any = field(default=None, repr=False)  # GDBClient, hidden from repr

    def get_arg(self, n: int) -> int:
        """Get function argument n (0-3 from r0-r3, 4+ from stack).

        ARM calling convention: first 4 args in r0-r3, rest on stack.
        """
        if n < 4:
            return self.regs.get(f"r{n}", 0)
        # Args 4+ are on the stack, starting at SP
        sp = self.regs.get("sp", 0)
        offset = (n - 4) * 4
        if self._gdb is not None:
            data = self._gdb.read_memory(sp + offset, 4)
            return int.from_bytes(data, "little")
        return 0

    def read_memory(self, addr: int, size: int) -> bytes:
        """Read target memory (delegates to GDB)."""
        if self._gdb is None:
            return b"\x00" * size
        return self._gdb.read_memory(addr, size)

    def write_memory(self, addr: int, data: bytes) -> None:
        """Write target memory (delegates to GDB)."""
        if self._gdb is not None:
            self._gdb.write_memory(addr, data)


class PeripheralModel:
    """Base class for user-defined peripheral models.

    Subclasses implement register read/write behavior and/or HAL function
    handlers. Each model represents one peripheral (e.g., UART1, RCC, GPIO_A).
    """

    def __init__(self, name: str, base_addr: int, size: int) -> None:
        self.name = name
        self.base_addr = base_addr
        self.size = size
        self._registers: dict[int, int] = {}  # offset -> value
        self._handlers: dict[str, Callable] = {}
        self._collect_handlers()

    def _collect_handlers(self) -> None:
        """Scan methods for @hal_handler decorators and build handler map."""
        for attr_name in dir(self):
            try:
                method = getattr(self, attr_name)
            except AttributeError:
                continue
            func_names = getattr(method, _HAL_HANDLER_ATTR, None)
            if func_names is not None:
                for fn in func_names:
                    self._handlers[fn] = method

    def _find_handler(self, func_name: str) -> Callable:
        """Find a registered handler method by function name.

        Raises KeyError if no handler is registered for func_name.
        """
        if func_name not in self._handlers:
            raise KeyError(
                f"No handler registered for '{func_name}' on {self.__class__.__name__}"
            )
        return self._handlers[func_name]

    def reset(self) -> None:
        """Reset all registers to default values. Override to set reset values."""
        self._registers.clear()

    def read_register(self, offset: int, size: int = 4) -> int:
        """Called when firmware reads a peripheral register at base_addr + offset.
        Override for smart behavior (e.g., clear-on-read status bits)."""
        return self._registers.get(offset, 0)

    def write_register(self, offset: int, value: int, size: int = 4) -> None:
        """Called when firmware writes a peripheral register.
        Override for side effects (e.g., writing TX data triggers transmission)."""
        self._registers[offset] = value

    def get_irq(self) -> int | None:
        """Return pending IRQ number, or None."""
        return None
