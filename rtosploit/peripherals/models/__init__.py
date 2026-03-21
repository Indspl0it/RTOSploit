"""Built-in peripheral models for common microcontroller HALs."""

from rtosploit.peripherals.models.generic import (
    LogAndReturn,
    ReturnValue,
    ReturnZero,
)
from rtosploit.peripherals.models.mmio_fallback import (
    CompositeMMIOHandler,
    CortexMSystemRegisters,
    MMIOAccess,
    MMIOFallbackModel,
)

__all__ = [
    "CompositeMMIOHandler",
    "CortexMSystemRegisters",
    "LogAndReturn",
    "MMIOAccess",
    "MMIOFallbackModel",
    "ReturnValue",
    "ReturnZero",
]
