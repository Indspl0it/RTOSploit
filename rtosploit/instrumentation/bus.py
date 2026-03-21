"""Central instrumentation event bus.

QEMU hooks publish events via InstrumentationBus.publish(); crash detectors,
telemetry collectors, and trace writers subscribe via InstrumentationBus.subscribe().

Thread-safety note
------------------
publish() acquires a threading.Lock before mutating the ring buffer and
walking the subscriber list, so it is safe to call from background threads
(e.g. QEMU I/O callbacks).  subscribe/unsubscribe also hold the same lock.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class InstrumentationConfig:
    """Controls which event categories are captured and how they are stored."""

    trace_exceptions: bool = True
    trace_memory: bool = False       # expensive — disabled by default
    trace_basic_blocks: bool = True
    trace_interrupts: bool = True
    trace_syscalls: bool = True
    trace_peripherals: bool = True
    trace_task_switches: bool = True
    trace_heap: bool = True
    trace_stack: bool = True
    log_to_file: Optional[Path] = None
    ring_buffer_size: int = 65536
    trace_level: str = "standard"    # "minimal" | "standard" | "verbose" | "off"
    trace_max_size_mb: int = 100
    sampling_rate: int = 1           # 1 = every event, N = 1-in-N sampling


# ---------------------------------------------------------------------------
# Ring buffer
# ---------------------------------------------------------------------------

class EventRingBuffer:
    """Fixed-size circular buffer of InstrumentationEvents.

    When the buffer is full the oldest event is silently overwritten (evicted).
    All operations are O(1) except get_all / get_last which are O(n).
    """

    def __init__(self, size: int = 65536) -> None:
        if size < 1:
            raise ValueError("EventRingBuffer size must be >= 1")
        self._size = size
        self._buffer: list = [None] * size
        self._head = 0   # index of the *next* write slot
        self._count = 0  # number of valid entries (0 <= count <= size)

    def push(self, event: object) -> None:
        """Append an event, overwriting the oldest if the buffer is full."""
        self._buffer[self._head] = event
        self._head = (self._head + 1) % self._size
        if self._count < self._size:
            self._count += 1

    def get_last(self, n: int) -> list:
        """Return the most recent *n* events in chronological order (oldest first).

        If fewer than *n* events have been stored, returns all stored events.
        """
        n = min(n, self._count)
        if n == 0:
            return []
        result = []
        # Walk backwards from head-1
        for i in range(n - 1, -1, -1):
            idx = (self._head - 1 - i) % self._size
            result.append(self._buffer[idx])
        return result

    def get_all(self) -> list:
        """Return all stored events in chronological order (oldest first)."""
        return self.get_last(self._count)

    def clear(self) -> None:
        """Discard all stored events and reset counters."""
        self._head = 0
        self._count = 0
        # Null out references so Python can GC the event objects
        self._buffer = [None] * self._size

    def __len__(self) -> int:
        return self._count


# ---------------------------------------------------------------------------
# Event bus
# ---------------------------------------------------------------------------

class InstrumentationBus:
    """Central event dispatcher for the RTOSploit instrumentation layer.

    Usage::

        config = InstrumentationConfig(trace_memory=False)
        bus = InstrumentationBus(config)

        collector = TelemetryCollector()
        bus.subscribe(collector.on_event)

        # QEMU hook:
        bus.publish(ExceptionEntryEvent(vector_num=3, ...))

    Thread-safety
    -------------
    publish() can be called from QEMU callback threads.  A single
    ``threading.Lock`` serialises all mutations (subscribe / unsubscribe /
    publish / reset_stats).
    """

    def __init__(self, config: InstrumentationConfig) -> None:
        self.config = config
        self._subscribers: list[Callable] = []
        self._ring_buffer = EventRingBuffer(config.ring_buffer_size)
        self._event_count = 0
        self._sample_counter = 0
        self._lock = threading.Lock()

        # Optionally wire up a TraceWriter
        self._trace_writer = None
        if config.log_to_file and config.trace_level != "off":
            from rtosploit.instrumentation.trace_writer import TraceWriter
            self._trace_writer = TraceWriter(
                log_path=config.log_to_file,
                level=config.trace_level,
                max_size_mb=config.trace_max_size_mb,
            )

    # ------------------------------------------------------------------
    # Subscriber management
    # ------------------------------------------------------------------

    def subscribe(self, callback: Callable) -> None:
        """Register *callback* to receive all published events."""
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable) -> None:
        """Remove *callback* so it no longer receives events."""
        with self._lock:
            try:
                self._subscribers.remove(callback)
            except ValueError:
                pass  # already removed — idempotent

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish(self, event: object) -> None:
        """Publish *event* to all subscribers and the ring buffer.

        Applies config-based filtering and sampling before dispatch.
        """
        # Fast path: check trace level first (no lock needed for read)
        if self.config.trace_level == "off":
            return

        if not self._should_trace(event):
            return

        # Sampling: drop events at 1/N rate (sampling_rate=1 means keep all)
        rate = self.config.sampling_rate
        if rate > 1:
            with self._lock:
                self._sample_counter += 1
                if self._sample_counter % rate != 0:
                    return
        elif rate <= 0:
            return  # rate=0 means nothing passes

        with self._lock:
            self._event_count += 1
            self._ring_buffer.push(event)
            # Snapshot subscriber list inside lock to avoid TOCTOU
            subscribers = list(self._subscribers)
            writer = self._trace_writer

        # Dispatch outside lock so subscriber callbacks can't deadlock
        for cb in subscribers:
            try:
                cb(event)
            except Exception:
                pass  # Don't let misbehaving subscribers kill the bus

        if writer is not None:
            try:
                writer.write(event)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _should_trace(self, event: object) -> bool:
        """Return True if *event* should be dispatched given current config."""
        from rtosploit.instrumentation.events import (
            ExceptionEntryEvent,
            ExceptionReturnEvent,
            MemoryAccessEvent,
            BasicBlockTransitionEvent,
            InterruptFiredEvent,
            SyscallEntryEvent,
            SyscallReturnEvent,
            PeripheralReadEvent,
            PeripheralWriteEvent,
            TaskSwitchEvent,
            HeapOperationEvent,
            StackPointerChangeEvent,
        )

        cfg = self.config

        if isinstance(event, (ExceptionEntryEvent, ExceptionReturnEvent)):
            return cfg.trace_exceptions

        if isinstance(event, MemoryAccessEvent):
            return cfg.trace_memory

        if isinstance(event, BasicBlockTransitionEvent):
            return cfg.trace_basic_blocks

        if isinstance(event, InterruptFiredEvent):
            return cfg.trace_interrupts

        if isinstance(event, (SyscallEntryEvent, SyscallReturnEvent)):
            return cfg.trace_syscalls

        if isinstance(event, (PeripheralReadEvent, PeripheralWriteEvent)):
            return cfg.trace_peripherals

        if isinstance(event, TaskSwitchEvent):
            return cfg.trace_task_switches

        if isinstance(event, HeapOperationEvent):
            return cfg.trace_heap

        if isinstance(event, StackPointerChangeEvent):
            return cfg.trace_stack

        # WatchdogTickEvent and anything unknown: always pass
        return True

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_ring_buffer(self) -> EventRingBuffer:
        return self._ring_buffer

    def get_crash_context(self, n: int = 100) -> list:
        """Return the last *n* events before crash for inclusion in a crash report."""
        with self._lock:
            return self._ring_buffer.get_last(n)

    def reset_stats(self) -> None:
        """Reset event counter and clear the ring buffer."""
        with self._lock:
            self._event_count = 0
            self._sample_counter = 0
            self._ring_buffer.clear()

    @property
    def event_count(self) -> int:
        """Total number of events that passed filtering (not dropped by sampling)."""
        with self._lock:
            return self._event_count
