"""Peripheral stub framework for HALucinator-style firmware rehosting."""

from rtosploit.peripherals.model import (
    CPUState,
    HandlerResult,
    PeripheralModel,
    hal_handler,
)

__all__ = ["CPUState", "HandlerResult", "PeripheralModel", "hal_handler"]
