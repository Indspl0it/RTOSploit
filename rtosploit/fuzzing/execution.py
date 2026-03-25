"""Execution result and stop reason types for the fuzz engine.

Defines the possible termination conditions for a single firmware
execution and a dataclass capturing the full result including coverage,
crash information, and resource consumption.

References:
    Ember-IO termination conditions (Section 4):
    1. Input exhausted (clean)
    2. Unmapped memory access (crash)
    3. Memory permission violation (crash)
    4. Infinite loop / self-jumping instruction (clean)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from rtosploit.coverage.bitmap import CoverageBitmap


class StopReason(Enum):
    """Possible reasons for firmware execution to terminate."""

    INPUT_EXHAUSTED = "input_exhausted"      # Clean: fuzz input fully consumed
    UNMAPPED_ACCESS = "unmapped_access"      # Crash: wild pointer / null deref
    PERMISSION_ERROR = "permission_error"    # Crash: write to flash, exec from RAM
    INFINITE_LOOP = "infinite_loop"          # Clean: B . detected
    TIMEOUT = "timeout"                      # Max blocks or wall-clock reached
    STACK_OVERFLOW = "stack_overflow"        # Crash: SP below stack base


# Stop reasons that indicate a crash (not clean termination).
_CRASH_REASONS = frozenset({
    StopReason.UNMAPPED_ACCESS,
    StopReason.PERMISSION_ERROR,
    StopReason.STACK_OVERFLOW,
})


@dataclass
class ExecutionResult:
    """Complete result of a single fuzz execution.

    Attributes:
        stop_reason: Why execution terminated.
        crashed: ``True`` if *stop_reason* indicates a crash.
        crash_address: Faulting address (0 if no crash).
        crash_type: Human-readable crash classification (empty if no crash).
        blocks_executed: Number of basic blocks executed.
        coverage: Coverage bitmap snapshot, or ``None`` if not collected.
        input_consumed: Number of fuzz input bytes consumed.
        pip_stats: Optional PIP subsystem statistics dict.
    """

    stop_reason: StopReason
    crashed: bool
    crash_address: int = 0
    crash_type: str = ""
    blocks_executed: int = 0
    coverage: Optional[CoverageBitmap] = None
    input_consumed: int = 0
    pip_stats: Optional[dict] = field(default=None)

    @property
    def is_interesting(self) -> bool:
        """True if execution crashed or found new coverage."""
        if self.crashed:
            return True
        if self.coverage is not None and self.coverage.count_edges() > 0:
            return True
        return False


def make_result(
    stop_reason: StopReason,
    *,
    crash_address: int = 0,
    crash_type: str = "",
    blocks_executed: int = 0,
    coverage: Optional[CoverageBitmap] = None,
    input_consumed: int = 0,
    pip_stats: Optional[dict] = None,
) -> ExecutionResult:
    """Convenience factory that auto-computes the *crashed* flag.

    Args:
        stop_reason: Why execution terminated.
        crash_address: Faulting address (0 if no crash).
        crash_type: Human-readable crash classification.
        blocks_executed: Number of basic blocks executed.
        coverage: Coverage bitmap snapshot.
        input_consumed: Number of fuzz input bytes consumed.
        pip_stats: Optional PIP statistics dict.

    Returns:
        An :class:`ExecutionResult` with *crashed* set based on *stop_reason*.
    """
    return ExecutionResult(
        stop_reason=stop_reason,
        crashed=stop_reason in _CRASH_REASONS,
        crash_address=crash_address,
        crash_type=crash_type,
        blocks_executed=blocks_executed,
        coverage=coverage,
        input_consumed=input_consumed,
        pip_stats=pip_stats,
    )
