"""RTOSploit instrumentation layer.

Provides an event bus that QEMU hooks publish to and crash detectors /
telemetry collectors subscribe from.

Public API
----------
InstrumentationBus      — central event dispatcher
InstrumentationConfig   — configuration dataclass for the bus
InstrumentationEvent    — Union type covering all event dataclasses
EventRingBuffer         — fixed-size circular buffer used by the bus
TelemetryCollector      — aggregates events into structured telemetry
"""

from rtosploit.instrumentation.events import InstrumentationEvent  # noqa: F401
from rtosploit.instrumentation.bus import (  # noqa: F401
    InstrumentationBus,
    InstrumentationConfig,
    EventRingBuffer,
)
from rtosploit.instrumentation.telemetry import TelemetryCollector  # noqa: F401

__all__ = [
    "InstrumentationBus",
    "InstrumentationConfig",
    "InstrumentationEvent",
    "EventRingBuffer",
    "TelemetryCollector",
]
