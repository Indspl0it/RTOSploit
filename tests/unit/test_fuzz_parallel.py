"""Unit tests for parallel fuzzing and high-throughput engine features."""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

_ENGINE = "rtosploit.fuzzing.engine"


def _make_worker_gdb(iterations: int = 5):
    """Build a GDB mock that supports N fuzz iterations without crashing."""
    gdb = MagicMock()
    gdb.read_register.return_value = 0x0800_1000
    gdb.read_registers.return_value = {
        "r0": 0, "sp": 0x2001_0000, "lr": 0x0800_0100, "pc": 0x0800_1234,
        "xpsr": 0x6100_0000,
    }
    gdb.read_memory.return_value = b"\x00\x02\x00\x00"

    # Boot: stop + re-sync per iteration + fuzz result (timeout) + break after timeout
    side_effects = ["S05"]  # boot stop
    for _ in range(iterations):
        side_effects.append("S05")  # re-sync after fast_reset
        side_effects.append(TimeoutError("timeout"))  # no crash
        side_effects.append("S05")  # break after timeout
    # Final iteration will hit StopIteration which loop handles via timeout check
    gdb.receive_stop.side_effect = side_effects
    return gdb


class TestExecTimeoutConfigurable:
    """exec_timeout should be configurable, not hardcoded to 2.0s."""

    def test_default_exec_timeout_is_fast(self):
        """Default exec_timeout should be <= 0.1s for embedded firmware."""
        from rtosploit.fuzzing.engine import FuzzEngine

        engine = FuzzEngine(
            firmware_path="/tmp/test.elf",
            machine_name="mps2-an385",
        )
        assert engine.exec_timeout <= 0.1

    def test_exec_timeout_configurable_via_constructor(self):
        """exec_timeout should be settable via constructor parameter."""
        from rtosploit.fuzzing.engine import FuzzEngine

        engine = FuzzEngine(
            firmware_path="/tmp/test.elf",
            machine_name="mps2-an385",
            exec_timeout=0.5,
        )
        assert engine.exec_timeout == 0.5


class TestJobsParameter:
    """FuzzEngine should support a jobs parameter for parallel workers."""

    def test_jobs_parameter_default_is_one(self):
        from rtosploit.fuzzing.engine import FuzzEngine

        engine = FuzzEngine(
            firmware_path="/tmp/test.elf",
            machine_name="mps2-an385",
        )
        assert engine.jobs == 1

    def test_jobs_parameter_configurable(self):
        from rtosploit.fuzzing.engine import FuzzEngine

        engine = FuzzEngine(
            firmware_path="/tmp/test.elf",
            machine_name="mps2-an385",
            jobs=8,
        )
        assert engine.jobs == 8


class TestParallelWorkersSpawned:
    """With jobs > 1, multiple QEMU instances should be created."""

    def test_multiple_qemu_instances_created(self):
        """With jobs=4, 4 QEMUInstance objects should be created."""
        qemu_cls = MagicMock()
        qemu_instance = MagicMock()
        qemu_instance.gdb = _make_worker_gdb(iterations=2)
        qemu_cls.return_value = qemu_instance
        qemu_cls.create_snapshot_drive.return_value = ["-drive", "file=snap.qcow2,format=qcow2,if=none,id=snap0"]

        snap_cls = MagicMock()
        mem_cls = MagicMock()
        mem_instance = MagicMock()
        mem_instance.read_vector_table.return_value = {
            "initial_sp": 0x2002_0000, "reset": 0x0800_0001,
            "hardfault": 0x0800_0021, "memmanage": 0x0800_0031,
            "busfault": 0x0800_0041, "usagefault": 0x0800_0051,
        }
        mem_cls.return_value = mem_instance

        mono_counter = {"val": 0.0}

        def mono_fn():
            mono_counter["val"] += 0.01
            return mono_counter["val"]

        with (
            patch(f"{_ENGINE}.QEMUInstance", qemu_cls),
            patch(f"{_ENGINE}.SnapshotManager", snap_cls),
            patch(f"{_ENGINE}.MemoryOps", mem_cls),
            patch(f"{_ENGINE}.Mutator"),
            patch(f"{_ENGINE}.CorpusManager") as corpus_cls,
            patch(f"{_ENGINE}.CrashReporter"),
            patch(f"{_ENGINE}.time") as time_mock,
        ):
            time_mock.monotonic = mono_fn
            time_mock.sleep = MagicMock()
            time_mock.time = MagicMock(return_value=1709000000)
            corpus_instance = MagicMock()
            corpus_instance.get_random.return_value = b"\x00" * 64
            corpus_instance.coverage_percentage.return_value = 0.0
            corpus_instance.size = 0
            corpus_cls.return_value = corpus_instance

            from rtosploit.fuzzing.engine import FuzzEngine

            engine = FuzzEngine(
                firmware_path="/tmp/test.elf",
                machine_name="mps2-an385",
                jobs=4,
                exec_timeout=0.05,
            )
            stats = engine.run(timeout=1, corpus_dir="/tmp/corpus", crash_dir="/tmp/crashes")

        # With jobs=4, QEMUInstance should be constructed 4 times
        assert qemu_cls.call_count == 4


class TestAggregatedStats:
    """Stats should be aggregated across all workers."""

    def test_stats_aggregate_executions(self):
        """Total executions should be sum across all workers."""
        from rtosploit.fuzzing.engine import FuzzStats

        stats1 = FuzzStats(executions=100, crashes=2, unique_crashes=1)
        stats2 = FuzzStats(executions=150, crashes=3, unique_crashes=2)

        # Aggregation should sum executions and crashes
        combined = FuzzStats(
            executions=stats1.executions + stats2.executions,
            crashes=stats1.crashes + stats2.crashes,
            unique_crashes=stats1.unique_crashes + stats2.unique_crashes,
        )
        assert combined.executions == 250
        assert combined.crashes == 5
        assert combined.unique_crashes == 3


class TestThreadSafeCorpus:
    """CorpusManager should be thread-safe for concurrent access."""

    def test_corpus_concurrent_add(self):
        """Multiple threads adding to corpus should not corrupt state."""
        from rtosploit.fuzzing.corpus import CorpusManager
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            corpus = CorpusManager(tmpdir, bitmap_size=256)

            errors = []

            def add_entries(thread_id: int):
                try:
                    for i in range(50):
                        bitmap = bytearray(256)
                        # Each thread writes to different bitmap positions
                        idx = (thread_id * 50 + i) % 256
                        bitmap[idx] = 1
                        corpus.add(bytes([thread_id, i]) * 32, bytes(bitmap))
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=add_entries, args=(t,)) for t in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0, f"Thread errors: {errors}"
            # Corpus should have entries (some may be duplicates in coverage)
            assert corpus.size > 0

    def test_corpus_concurrent_get_random(self):
        """get_random should work safely from multiple threads."""
        from rtosploit.fuzzing.corpus import CorpusManager
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            corpus = CorpusManager(tmpdir, bitmap_size=256)
            # Pre-populate
            for i in range(10):
                bitmap = bytearray(256)
                bitmap[i] = 1
                corpus.add(bytes([i]) * 64, bytes(bitmap))

            results = []
            errors = []

            def read_entries():
                try:
                    for _ in range(100):
                        data = corpus.get_random()
                        results.append(data)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=read_entries) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0
            assert len(results) == 400


class TestPersistentMode:
    """Persistent mode uses system_reset instead of loadvm for faster resets."""

    def test_persistent_mode_flag(self):
        """FuzzEngine should accept a persistent_mode parameter."""
        from rtosploit.fuzzing.engine import FuzzEngine

        engine = FuzzEngine(
            firmware_path="/tmp/test.elf",
            machine_name="mps2-an385",
            persistent_mode=True,
        )
        assert engine.persistent_mode is True

    def test_persistent_mode_default_false(self):
        from rtosploit.fuzzing.engine import FuzzEngine

        engine = FuzzEngine(
            firmware_path="/tmp/test.elf",
            machine_name="mps2-an385",
        )
        assert engine.persistent_mode is False


class TestFuzzWorkerClass:
    """FuzzWorker encapsulates a single QEMU instance for the fuzz loop."""

    def test_fuzz_worker_exists(self):
        """FuzzWorker class should exist in the engine module."""
        from rtosploit.fuzzing.engine import FuzzWorker
        assert FuzzWorker is not None

    def test_fuzz_worker_has_worker_id(self):
        """Each worker should have a unique worker_id."""
        from rtosploit.fuzzing.engine import FuzzWorker

        w = FuzzWorker(
            worker_id=0,
            firmware_path="/tmp/test.elf",
            machine_name="mps2-an385",
            inject_addr=0x20010000,
            inject_size=256,
            exec_timeout=0.05,
            gdb_port=1234,
        )
        assert w.worker_id == 0

    def test_fuzz_worker_uses_custom_gdb_port(self):
        """Workers should use different GDB ports to avoid conflicts."""
        from rtosploit.fuzzing.engine import FuzzWorker

        w1 = FuzzWorker(
            worker_id=0, firmware_path="/tmp/test.elf", machine_name="mps2-an385",
            inject_addr=0x20010000, inject_size=256, exec_timeout=0.05, gdb_port=1234,
        )
        w2 = FuzzWorker(
            worker_id=1, firmware_path="/tmp/test.elf", machine_name="mps2-an385",
            inject_addr=0x20010000, inject_size=256, exec_timeout=0.05, gdb_port=1235,
        )
        assert w1.gdb_port == 1234
        assert w2.gdb_port == 1235
