"""Typed event dataclasses for QEMU instrumentation hooks.

All events published on InstrumentationBus are instances of one of these
dataclasses.  The InstrumentationEvent union type covers all of them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Union


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AccessType(Enum):
    READ = "read"
    WRITE = "write"


class TaskSwitchTrigger(Enum):
    PENDSV = "pendsv"
    SYSTICK = "systick"
    YIELD = "yield"


class HeapOpType(Enum):
    MALLOC = "malloc"
    FREE = "free"
    REALLOC = "realloc"


class StackChangeCause(Enum):
    PUSH = "push"
    POP = "pop"
    SWITCH = "switch"
    OVERFLOW = "overflow"


# ---------------------------------------------------------------------------
# Event dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ExceptionEntryEvent:
    """Fired when an ARM exception is taken."""
    vector_num: int          # exception number (1=Reset, 3=HardFault, 14=PendSV, 15=SysTick, 16+=IRQ)
    return_addr: int         # stacked PC (where exception occurred)
    fault_addr: int          # BFAR/MMFAR if applicable, else 0
    fault_status_register: int  # CFSR value (0xE000ED28)
    hfsr: int                # HardFault Status Register (0xE000ED2C)
    event_type: str = field(default="exception_entry", init=False)

    def __post_init__(self) -> None:
        self.event_type = "exception_entry"


@dataclass
class ExceptionReturnEvent:
    """Fired when an ARM exception handler returns."""
    vector_num: int
    return_addr: int
    to_thread_mode: bool     # True = returning to thread, False = returning to handler
    event_type: str = field(default="exception_return", init=False)

    def __post_init__(self) -> None:
        self.event_type = "exception_return"


@dataclass
class MemoryAccessEvent:
    """Fired for every load/store that the hook intercepts."""
    address: int
    value: int
    size: int                # bytes: 1, 2, or 4
    access_type: AccessType
    pc: int                  # instruction address causing the access
    is_mmio: bool
    event_type: str = field(default="memory_access", init=False)

    def __post_init__(self) -> None:
        self.event_type = "memory_access"


@dataclass
class BasicBlockTransitionEvent:
    """Fired at each control-flow edge (basic block boundary)."""
    from_addr: int
    to_addr: int
    event_type: str = field(default="basic_block_transition", init=False)

    def __post_init__(self) -> None:
        self.event_type = "basic_block_transition"


@dataclass
class InterruptFiredEvent:
    """Fired when a peripheral IRQ is asserted."""
    irq_num: int
    priority: int
    timestamp_cycles: int
    event_type: str = field(default="interrupt_fired", init=False)

    def __post_init__(self) -> None:
        self.event_type = "interrupt_fired"


@dataclass
class SyscallEntryEvent:
    """Fired on SVC instruction (RTOS syscall entry)."""
    syscall_id: int
    args: list               # R0-R3 values
    caller_privilege: int    # 0 = privileged, 1 = unprivileged
    event_type: str = field(default="syscall_entry", init=False)

    def __post_init__(self) -> None:
        self.event_type = "syscall_entry"


@dataclass
class SyscallReturnEvent:
    """Fired when returning from a syscall handler."""
    syscall_id: int
    return_value: int
    event_type: str = field(default="syscall_return", init=False)

    def __post_init__(self) -> None:
        self.event_type = "syscall_return"


@dataclass
class WatchdogTickEvent:
    """Fired periodically to track coverage freshness."""
    cycles_since_last_new_edge: int
    event_type: str = field(default="watchdog_tick", init=False)

    def __post_init__(self) -> None:
        self.event_type = "watchdog_tick"


@dataclass
class PeripheralReadEvent:
    """Fired when firmware reads a peripheral register."""
    peripheral_name: str
    register_offset: int
    value_returned: int
    pc: int
    event_type: str = field(default="peripheral_read", init=False)

    def __post_init__(self) -> None:
        self.event_type = "peripheral_read"


@dataclass
class PeripheralWriteEvent:
    """Fired when firmware writes a peripheral register."""
    peripheral_name: str
    register_offset: int
    value_written: int
    pc: int
    event_type: str = field(default="peripheral_write", init=False)

    def __post_init__(self) -> None:
        self.event_type = "peripheral_write"


@dataclass
class TaskSwitchEvent:
    """Fired when the RTOS context-switches between tasks."""
    from_task_tcb_addr: int
    to_task_tcb_addr: int
    trigger: TaskSwitchTrigger
    event_type: str = field(default="task_switch", init=False)

    def __post_init__(self) -> None:
        self.event_type = "task_switch"


@dataclass
class HeapOperationEvent:
    """Fired for malloc / free / realloc calls."""
    op_type: HeapOpType
    address: int             # allocated/freed address
    size: int                # bytes (0 for free)
    caller_pc: int
    event_type: str = field(default="heap_operation", init=False)

    def __post_init__(self) -> None:
        self.event_type = "heap_operation"


@dataclass
class StackPointerChangeEvent:
    """Fired when SP changes significantly (push, pop, context switch, overflow)."""
    old_sp: int
    new_sp: int
    cause: StackChangeCause
    event_type: str = field(default="stack_pointer_change", init=False)

    def __post_init__(self) -> None:
        self.event_type = "stack_pointer_change"


# ---------------------------------------------------------------------------
# Union type covering all events
# ---------------------------------------------------------------------------

InstrumentationEvent = Union[
    ExceptionEntryEvent,
    ExceptionReturnEvent,
    MemoryAccessEvent,
    BasicBlockTransitionEvent,
    InterruptFiredEvent,
    SyscallEntryEvent,
    SyscallReturnEvent,
    WatchdogTickEvent,
    PeripheralReadEvent,
    PeripheralWriteEvent,
    TaskSwitchEvent,
    HeapOperationEvent,
    StackPointerChangeEvent,
]


# ---------------------------------------------------------------------------
# Fault classification helpers
# ---------------------------------------------------------------------------

def classify_cfsr(cfsr: int) -> list[str]:
    """Parse CFSR (0xE000ED28) bits into a list of fault cause strings.

    The Configurable Fault Status Register is 32 bits wide:
      Bits  7:0  — MemManage Fault Status Register (MMFSR)
      Bits 15:8  — BusFault Status Register (BFSR)
      Bits 31:16 — UsageFault Status Register (UFSR)
    """
    faults: list[str] = []

    # MemManage (bits 7:0)
    if cfsr & (1 << 0):  faults.append("IACCVIOL")
    if cfsr & (1 << 1):  faults.append("DACCVIOL")
    if cfsr & (1 << 3):  faults.append("MUNSTKERR")
    if cfsr & (1 << 4):  faults.append("MSTKERR")
    if cfsr & (1 << 5):  faults.append("MLSPERR")
    if cfsr & (1 << 7):  faults.append("MMARVALID")

    # BusFault (bits 15:8)
    if cfsr & (1 << 8):  faults.append("IBUSERR")
    if cfsr & (1 << 9):  faults.append("PRECISERR")
    if cfsr & (1 << 10): faults.append("IMPRECISERR")
    if cfsr & (1 << 11): faults.append("UNSTKERR")
    if cfsr & (1 << 12): faults.append("STKERR")
    if cfsr & (1 << 13): faults.append("LSPERR")
    if cfsr & (1 << 15): faults.append("BFARVALID")

    # UsageFault (bits 31:16)
    if cfsr & (1 << 16): faults.append("UNDEFINSTR")
    if cfsr & (1 << 17): faults.append("INVSTATE")
    if cfsr & (1 << 18): faults.append("INVPC")
    if cfsr & (1 << 19): faults.append("NOCP")
    if cfsr & (1 << 24): faults.append("UNALIGNED")
    if cfsr & (1 << 25): faults.append("DIVBYZERO")

    return faults


def exception_name(vector_num: int) -> str:
    """Map a Cortex-M exception vector number to its human-readable name."""
    _NAMES = {
        1:  "Reset",
        2:  "NMI",
        3:  "HardFault",
        4:  "MemManage",
        5:  "BusFault",
        6:  "UsageFault",
        11: "SVCall",
        12: "DebugMon",
        14: "PendSV",
        15: "SysTick",
    }
    if vector_num in _NAMES:
        return _NAMES[vector_num]
    if vector_num >= 16:
        return f"IRQ{vector_num - 16}"
    return f"Reserved{vector_num}"
