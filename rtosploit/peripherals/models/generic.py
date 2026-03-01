"""Generic peripheral models — universal handlers for common patterns."""

from __future__ import annotations

import logging

from rtosploit.peripherals.model import (
    CPUState,
    HandlerResult,
    PeripheralModel,
    hal_handler,
)

logger = logging.getLogger(__name__)


class ReturnZero(PeripheralModel):
    """Always returns 0 (HAL_OK). Use for init functions that just need to succeed."""

    @hal_handler(["__return_zero__"])
    def handle(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(intercept=True, return_value=0)

    def intercept_any(self, cpu: CPUState) -> HandlerResult:
        """Generic handler — register manually for any function."""
        return HandlerResult(intercept=True, return_value=0)


class ReturnValue(PeripheralModel):
    """Returns a configured constant value."""

    def __init__(self, name: str, base_addr: int, size: int, value: int = 0) -> None:
        super().__init__(name, base_addr, size)
        self.value = value

    @hal_handler(["__return_value__"])
    def handle(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(intercept=True, return_value=self.value)


class LogAndReturn(PeripheralModel):
    """Logs function arguments and returns 0 (HAL_OK)."""

    @hal_handler(["__log_and_return__"])
    def handle(self, cpu: CPUState) -> HandlerResult:
        args = [cpu.get_arg(i) for i in range(4)]
        logger.info(
            "[%s] called with args: r0=0x%08x r1=0x%08x r2=0x%08x r3=0x%08x",
            self.name, args[0], args[1], args[2], args[3],
        )
        return HandlerResult(intercept=True, return_value=0)
