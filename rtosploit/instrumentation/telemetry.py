"""Telemetry collector — subscribes to InstrumentationBus and aggregates events.

Usage::

    bus = InstrumentationBus(config)
    collector = TelemetryCollector()
    bus.subscribe(collector.on_event)

    # ... run emulation ...

    snapshot = collector.get_snapshot()
    print(snapshot.to_json())
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Summary dataclasses
# ---------------------------------------------------------------------------

@dataclass
class HeapSummary:
    allocation_count: int = 0
    free_count: int = 0
    total_allocated_bytes: int = 0
    peak_allocated_bytes: int = 0
    current_allocated_bytes: int = 0
    live_allocations: dict = field(default_factory=dict)  # addr -> size


@dataclass
class InterruptSummary:
    total_interrupts: int = 0
    interrupt_counts: dict = field(default_factory=dict)  # irq_num -> count
    max_nesting_depth: int = 0


@dataclass
class TaskSummary:
    switch_count: int = 0
    tasks_seen: set = field(default_factory=set)  # TCB addresses


@dataclass
class ExecutionSummary:
    total_instructions: int = 0
    basic_blocks_visited: int = 0
    unique_edges: int = 0
    exceptions_triggered: int = 0
    mmio_accesses: int = 0


# ---------------------------------------------------------------------------
# Snapshot (top-level container)
# ---------------------------------------------------------------------------

@dataclass
class TelemetrySnapshot:
    execution: ExecutionSummary = field(default_factory=ExecutionSummary)
    heap: HeapSummary = field(default_factory=HeapSummary)
    interrupts: InterruptSummary = field(default_factory=InterruptSummary)
    tasks: TaskSummary = field(default_factory=TaskSummary)
    session_start: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        """Return a plain-dict representation (JSON-serialisable)."""
        exec_s = self.execution
        heap_s = self.heap
        int_s = self.interrupts
        task_s = self.tasks

        return {
            "session_start": self.session_start,
            "execution": {
                "total_instructions": exec_s.total_instructions,
                "basic_blocks_visited": exec_s.basic_blocks_visited,
                "unique_edges": exec_s.unique_edges,
                "exceptions_triggered": exec_s.exceptions_triggered,
                "mmio_accesses": exec_s.mmio_accesses,
            },
            "heap": {
                "allocation_count": heap_s.allocation_count,
                "free_count": heap_s.free_count,
                "total_allocated_bytes": heap_s.total_allocated_bytes,
                "peak_allocated_bytes": heap_s.peak_allocated_bytes,
                "current_allocated_bytes": heap_s.current_allocated_bytes,
                "live_allocation_count": len(heap_s.live_allocations),
            },
            "interrupts": {
                "total_interrupts": int_s.total_interrupts,
                "interrupt_counts": int_s.interrupt_counts,
                "max_nesting_depth": int_s.max_nesting_depth,
            },
            "tasks": {
                "switch_count": task_s.switch_count,
                "unique_tasks_seen": len(task_s.tasks_seen),
                "task_tcb_addresses": sorted(task_s.tasks_seen),
            },
        }

    def to_json(self) -> str:
        """Serialise to a compact JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class TelemetryCollector:
    """Subscribes to InstrumentationBus and aggregates events into structured telemetry.

    Call ``on_event`` as the subscriber callback::

        bus.subscribe(collector.on_event)
    """

    def __init__(self) -> None:
        self._snapshot = TelemetrySnapshot()
        self._edges_seen: set = set()         # (from_addr, to_addr) tuples
        self._current_heap: dict = {}         # addr -> size (live allocations)
        self._interrupt_stack_depth: int = 0

    # ------------------------------------------------------------------
    # Event dispatch
    # ------------------------------------------------------------------

    def on_event(self, event: object) -> None:
        """Route incoming event to the appropriate aggregation handler."""
        from rtosploit.instrumentation.events import (
            ExceptionEntryEvent,
            ExceptionReturnEvent,
            MemoryAccessEvent,
            BasicBlockTransitionEvent,
            InterruptFiredEvent,
            TaskSwitchEvent,
            HeapOperationEvent,
        )

        if isinstance(event, ExceptionEntryEvent):
            self._on_exception_entry(event)

        elif isinstance(event, ExceptionReturnEvent):
            self._on_exception_return(event)

        elif isinstance(event, MemoryAccessEvent):
            self._on_memory_access(event)

        elif isinstance(event, BasicBlockTransitionEvent):
            self._on_basic_block(event)

        elif isinstance(event, InterruptFiredEvent):
            self._on_interrupt(event)

        elif isinstance(event, TaskSwitchEvent):
            self._on_task_switch(event)

        elif isinstance(event, HeapOperationEvent):
            self._on_heap_op(event)

        # All other event types are accepted but not aggregated into the
        # structured summary (e.g. WatchdogTickEvent, SyscallEntryEvent, etc.)

    # ------------------------------------------------------------------
    # Per-event handlers
    # ------------------------------------------------------------------

    def _on_exception_entry(self, event: object) -> None:
        self._snapshot.execution.exceptions_triggered += 1
        self._interrupt_stack_depth += 1
        int_s = self._snapshot.interrupts
        int_s.total_interrupts += 1
        if self._interrupt_stack_depth > int_s.max_nesting_depth:
            int_s.max_nesting_depth = self._interrupt_stack_depth

    def _on_exception_return(self, event: object) -> None:
        if self._interrupt_stack_depth > 0:
            self._interrupt_stack_depth -= 1

    def _on_memory_access(self, event: object) -> None:
        # event is MemoryAccessEvent
        if getattr(event, "is_mmio", False):
            self._snapshot.execution.mmio_accesses += 1

    def _on_basic_block(self, event: object) -> None:
        from_addr = getattr(event, "from_addr", None)
        to_addr = getattr(event, "to_addr", None)
        exec_s = self._snapshot.execution
        exec_s.basic_blocks_visited += 1

        if from_addr is not None and to_addr is not None:
            edge = (from_addr, to_addr)
            if edge not in self._edges_seen:
                self._edges_seen.add(edge)
                exec_s.unique_edges += 1

    def _on_interrupt(self, event: object) -> None:
        irq_num = getattr(event, "irq_num", -1)
        int_s = self._snapshot.interrupts
        int_s.total_interrupts += 1
        int_s.interrupt_counts[irq_num] = int_s.interrupt_counts.get(irq_num, 0) + 1

    def _on_task_switch(self, event: object) -> None:
        task_s = self._snapshot.tasks
        task_s.switch_count += 1
        from_tcb = getattr(event, "from_task_tcb_addr", None)
        to_tcb = getattr(event, "to_task_tcb_addr", None)
        if from_tcb is not None:
            task_s.tasks_seen.add(from_tcb)
        if to_tcb is not None:
            task_s.tasks_seen.add(to_tcb)

    def _on_heap_op(self, event: object) -> None:
        from rtosploit.instrumentation.events import HeapOpType

        op_type = getattr(event, "op_type", None)
        addr = getattr(event, "address", 0)
        size = getattr(event, "size", 0)
        heap_s = self._snapshot.heap

        if op_type == HeapOpType.MALLOC:
            heap_s.allocation_count += 1
            heap_s.total_allocated_bytes += size
            heap_s.current_allocated_bytes += size
            heap_s.live_allocations[addr] = size
            self._current_heap[addr] = size
            if heap_s.current_allocated_bytes > heap_s.peak_allocated_bytes:
                heap_s.peak_allocated_bytes = heap_s.current_allocated_bytes

        elif op_type == HeapOpType.FREE:
            heap_s.free_count += 1
            freed_size = self._current_heap.pop(addr, 0)
            heap_s.current_allocated_bytes = max(
                0, heap_s.current_allocated_bytes - freed_size
            )
            heap_s.live_allocations.pop(addr, None)

        elif op_type == HeapOpType.REALLOC:
            # Treat realloc as free(old) + malloc(new) at the new address
            # If addr was already tracked, remove old entry
            old_size = self._current_heap.pop(addr, 0)
            heap_s.current_allocated_bytes = max(
                0, heap_s.current_allocated_bytes - old_size
            )
            heap_s.live_allocations.pop(addr, None)

            heap_s.allocation_count += 1
            heap_s.total_allocated_bytes += size
            heap_s.current_allocated_bytes += size
            heap_s.live_allocations[addr] = size
            self._current_heap[addr] = size
            if heap_s.current_allocated_bytes > heap_s.peak_allocated_bytes:
                heap_s.peak_allocated_bytes = heap_s.current_allocated_bytes

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_snapshot(self) -> TelemetrySnapshot:
        """Return the current aggregated telemetry snapshot."""
        return self._snapshot

    def export_json(self, output_path: str) -> None:
        """Write current telemetry snapshot to a JSON file."""
        with open(output_path, "w") as f:
            f.write(self._snapshot.to_json())

    def reset(self) -> None:
        """Discard all accumulated telemetry and start fresh."""
        self._snapshot = TelemetrySnapshot()
        self._edges_seen.clear()
        self._current_heap.clear()
        self._interrupt_stack_depth = 0
