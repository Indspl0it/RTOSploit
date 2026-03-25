"""RTOSploit fuzzing engine — snapshot-based QEMU and Unicorn firmware fuzzing."""

from rtosploit.fuzzing.corpus import CorpusManager
from rtosploit.fuzzing.crash_reporter import CrashReporter
from rtosploit.fuzzing.engine import FuzzEngine, FuzzStats, FuzzWorker
from rtosploit.fuzzing.execution import ExecutionResult, StopReason, make_result
from rtosploit.fuzzing.fuzz_input import FuzzInputStream, InputExhausted
from rtosploit.fuzzing.input_injector import FuzzableInput, InputInjector
from rtosploit.fuzzing.mutator import Mutator

# Unicorn imports are lazy to avoid circular dependency:
# fuzzing/__init__ -> unicorn_worker -> unicorn_engine -> fuzzing/execution -> fuzzing/__init__


def _get_unicorn_classes():
    from rtosploit.fuzzing.unicorn_worker import (
        UnicornFuzzEngine,
        UnicornFuzzStats,
        UnicornFuzzWorker,
    )
    return UnicornFuzzEngine, UnicornFuzzStats, UnicornFuzzWorker


__all__ = [
    "CorpusManager",
    "CrashReporter",
    "ExecutionResult",
    "FuzzEngine",
    "FuzzInputStream",
    "FuzzStats",
    "FuzzWorker",
    "FuzzableInput",
    "InputExhausted",
    "InputInjector",
    "Mutator",
    "StopReason",
    "make_result",
]
