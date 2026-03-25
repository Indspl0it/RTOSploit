"""Tests for rtosploit.fuzzing.execution — StopReason and ExecutionResult."""

from __future__ import annotations

import pytest

from rtosploit.coverage.bitmap import CoverageBitmap
from rtosploit.fuzzing.execution import (
    ExecutionResult,
    StopReason,
    make_result,
    _CRASH_REASONS,
)


# ======================================================================
# StopReason enum
# ======================================================================


class TestStopReason:
    def test_all_values_accessible(self):
        assert StopReason.INPUT_EXHAUSTED.value == "input_exhausted"
        assert StopReason.UNMAPPED_ACCESS.value == "unmapped_access"
        assert StopReason.PERMISSION_ERROR.value == "permission_error"
        assert StopReason.INFINITE_LOOP.value == "infinite_loop"
        assert StopReason.TIMEOUT.value == "timeout"
        assert StopReason.STACK_OVERFLOW.value == "stack_overflow"

    def test_string_representation(self):
        assert "INPUT_EXHAUSTED" in str(StopReason.INPUT_EXHAUSTED)

    def test_enum_from_value(self):
        assert StopReason("unmapped_access") is StopReason.UNMAPPED_ACCESS

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            StopReason("nonexistent_reason")


# ======================================================================
# ExecutionResult
# ======================================================================


class TestExecutionResultConstruction:
    def test_minimal_construction(self):
        result = ExecutionResult(
            stop_reason=StopReason.INPUT_EXHAUSTED,
            crashed=False,
        )
        assert result.stop_reason is StopReason.INPUT_EXHAUSTED
        assert result.crashed is False
        assert result.crash_address == 0
        assert result.crash_type == ""
        assert result.blocks_executed == 0
        assert result.coverage is None
        assert result.input_consumed == 0
        assert result.pip_stats is None

    def test_full_construction(self):
        bm = CoverageBitmap(size=256)
        result = ExecutionResult(
            stop_reason=StopReason.UNMAPPED_ACCESS,
            crashed=True,
            crash_address=0xDEAD_BEEF,
            crash_type="null_deref",
            blocks_executed=42,
            coverage=bm,
            input_consumed=128,
            pip_stats={"replays": 10},
        )
        assert result.crashed is True
        assert result.crash_address == 0xDEAD_BEEF
        assert result.blocks_executed == 42
        assert result.coverage is bm
        assert result.pip_stats == {"replays": 10}


class TestExecutionResultCrashedFlag:
    """Different stop reasons should map to correct crashed flags."""

    def test_input_exhausted_not_crash(self):
        r = make_result(StopReason.INPUT_EXHAUSTED)
        assert r.crashed is False

    def test_unmapped_access_is_crash(self):
        r = make_result(StopReason.UNMAPPED_ACCESS)
        assert r.crashed is True

    def test_permission_error_is_crash(self):
        r = make_result(StopReason.PERMISSION_ERROR)
        assert r.crashed is True

    def test_infinite_loop_not_crash(self):
        r = make_result(StopReason.INFINITE_LOOP)
        assert r.crashed is False

    def test_timeout_not_crash(self):
        r = make_result(StopReason.TIMEOUT)
        assert r.crashed is False

    def test_stack_overflow_is_crash(self):
        r = make_result(StopReason.STACK_OVERFLOW)
        assert r.crashed is True

    def test_crash_reasons_set_complete(self):
        """Every crash-classified stop reason is in _CRASH_REASONS."""
        expected_crashes = {
            StopReason.UNMAPPED_ACCESS,
            StopReason.PERMISSION_ERROR,
            StopReason.STACK_OVERFLOW,
        }
        assert _CRASH_REASONS == expected_crashes


class TestExecutionResultIsInteresting:
    def test_crash_is_interesting(self):
        r = make_result(StopReason.UNMAPPED_ACCESS)
        assert r.is_interesting is True

    def test_new_coverage_is_interesting(self):
        bm = CoverageBitmap(size=256)
        bm.record_edge(0x100, 0x200)
        r = ExecutionResult(
            stop_reason=StopReason.INPUT_EXHAUSTED,
            crashed=False,
            coverage=bm,
        )
        assert r.is_interesting is True

    def test_no_crash_no_coverage_not_interesting(self):
        r = make_result(StopReason.INPUT_EXHAUSTED)
        assert r.is_interesting is False

    def test_empty_coverage_not_interesting(self):
        bm = CoverageBitmap(size=256)
        r = ExecutionResult(
            stop_reason=StopReason.INPUT_EXHAUSTED,
            crashed=False,
            coverage=bm,
        )
        assert r.is_interesting is False


class TestMakeResult:
    def test_auto_crash_flag(self):
        r = make_result(StopReason.STACK_OVERFLOW, crash_address=0x2000_0000)
        assert r.crashed is True
        assert r.crash_address == 0x2000_0000

    def test_auto_non_crash(self):
        r = make_result(StopReason.TIMEOUT, blocks_executed=50000)
        assert r.crashed is False
        assert r.blocks_executed == 50000

    def test_all_kwargs(self):
        bm = CoverageBitmap(size=64)
        r = make_result(
            StopReason.INPUT_EXHAUSTED,
            crash_address=0,
            crash_type="",
            blocks_executed=100,
            coverage=bm,
            input_consumed=64,
            pip_stats={"reads": 5},
        )
        assert r.input_consumed == 64
        assert r.pip_stats == {"reads": 5}
