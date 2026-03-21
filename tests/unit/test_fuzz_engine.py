"""Unit tests for rtosploit.fuzzing.engine — FuzzEngine orchestration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


# Patch targets — all imports inside rtosploit.fuzzing.engine
_ENGINE = "rtosploit.fuzzing.engine"


def _make_gdb_mock(crash_on_first: bool = False, iterations: int = 1):
    """Build a GDB mock.

    Args:
        crash_on_first: If True, first fuzz iteration's receive_stop returns
                        "S05" (breakpoint hit = crash); otherwise it raises
                        TimeoutError (no crash).
        iterations: Number of fuzz iterations to simulate.
    """
    gdb = MagicMock()
    gdb.read_register.return_value = 0x0800_1000  # initial PC
    gdb.read_registers.return_value = {
        "r0": 0, "r1": 0, "r2": 0, "r3": 0,
        "r4": 0, "r5": 0, "r6": 0, "r7": 0,
        "r8": 0, "r9": 0, "r10": 0, "r11": 0, "r12": 0,
        "sp": 0x2001_0000, "lr": 0x0800_0100, "pc": 0x0800_1234,
        "xpsr": 0x6100_0000,
    }
    # CFSR value = 0x0000_0200 (512) — PRECISERR bit
    gdb.read_memory.return_value = b"\x00\x02\x00\x00"

    side_effects = ["S05"]  # boot stop
    side_effects.append("S05")  # re-sync after snapshot save

    for i in range(iterations):
        side_effects.append("S05")  # iter re-sync after fast_reset
        if crash_on_first and i == 0:
            side_effects.append("S05")  # crash (breakpoint hit)
        else:
            side_effects.append(TimeoutError("timeout"))  # no crash
            side_effects.append("S05")  # break after timeout

    gdb.receive_stop.side_effect = side_effects
    return gdb


def _make_vector_table():
    """Return a vector table dict as MemoryOps.read_vector_table() would."""
    return {
        "initial_sp": 0x2002_0000,
        "reset": 0x0800_0001,
        "nmi": 0x0800_0011,
        "hardfault": 0x0800_0021,
        "memmanage": 0x0800_0031,
        "busfault": 0x0800_0041,
        "usagefault": 0x0800_0051,
    }


def _build_patches(gdb_mock=None, crash_on_first=False, iterations=1):
    """Return a dict of patch objects and the key mocks."""
    if gdb_mock is None:
        gdb_mock = _make_gdb_mock(crash_on_first=crash_on_first, iterations=iterations)

    # QEMUInstance mock
    qemu_cls = MagicMock()
    qemu_instance = MagicMock()
    qemu_instance.gdb = gdb_mock
    qemu_cls.return_value = qemu_instance
    qemu_cls.create_snapshot_drive.return_value = [
        "-drive", "file=snap.qcow2,format=qcow2,if=none,id=snap0"
    ]

    # SnapshotManager mock
    snap_cls = MagicMock()
    snap_instance = MagicMock()
    snap_cls.return_value = snap_instance

    # MemoryOps mock
    mem_cls = MagicMock()
    mem_instance = MagicMock()
    mem_instance.read_vector_table.return_value = _make_vector_table()
    mem_cls.return_value = mem_instance

    # Mutator mock
    mutator_cls = MagicMock()
    mutator_instance = MagicMock()
    mutator_instance.mutate.return_value = b"\xde\xad\xbe\xef" * 16
    mutator_cls.return_value = mutator_instance

    # CorpusManager mock
    corpus_cls = MagicMock()
    corpus_instance = MagicMock()
    corpus_instance.get_random.return_value = b"\x00" * 64
    corpus_instance.coverage_percentage.return_value = 1.5
    corpus_instance.size = 1
    corpus_cls.return_value = corpus_instance

    # CrashReporter mock
    reporter_cls = MagicMock()
    reporter_instance = MagicMock()
    reporter_cls.return_value = reporter_instance
    reporter_cls.deduplicate.return_value = True  # unique crash

    return {
        "qemu_cls": qemu_cls,
        "qemu_instance": qemu_instance,
        "snap_cls": snap_cls,
        "snap_instance": snap_instance,
        "mem_cls": mem_cls,
        "mem_instance": mem_instance,
        "mutator_cls": mutator_cls,
        "mutator_instance": mutator_instance,
        "corpus_cls": corpus_cls,
        "corpus_instance": corpus_instance,
        "reporter_cls": reporter_cls,
        "reporter_instance": reporter_instance,
        "gdb": gdb_mock,
    }


def _run_engine(mocks, timeout=1, coverage_addr=None):
    """Patch everything and run FuzzEngine.run(), returning stats.

    Uses a very short timeout so the engine exits after one iteration.
    """
    with (
        patch(f"{_ENGINE}.QEMUInstance", mocks["qemu_cls"]),
        patch(f"{_ENGINE}.SnapshotManager", mocks["snap_cls"]),
        patch(f"{_ENGINE}.MemoryOps", mocks["mem_cls"]),
        patch(f"{_ENGINE}.Mutator", mocks["mutator_cls"]),
        patch(f"{_ENGINE}.CorpusManager", mocks["corpus_cls"]),
        patch(f"{_ENGINE}.CrashReporter", mocks["reporter_cls"]),
        patch(f"{_ENGINE}.RTOSploitConfig") as cfg_mock,
    ):
        # Make RTOSploitConfig return a mock with gdb.port
        cfg_instance = MagicMock()
        cfg_instance.gdb.port = 1234
        cfg_mock.return_value = cfg_instance

        from rtosploit.fuzzing.engine import FuzzEngine

        engine = FuzzEngine(
            firmware_path="/tmp/test.elf",
            machine_name="lm3s6965evb",
            inject_addr=0x2001_0000,
            inject_size=256,
            coverage_addr=coverage_addr,
            coverage_size=65536,
            exec_timeout=0.05,
        )
        stats = engine.run(
            timeout=timeout,
            corpus_dir="/tmp/corpus",
            crash_dir="/tmp/crashes",
        )
        return stats


class TestEngineCreatesSnapshotDrive:
    """Verify create_snapshot_drive is called to set up qcow2 overlay."""

    def test_engine_creates_snapshot_drive(self):
        mocks = _build_patches(crash_on_first=False, iterations=2)
        _run_engine(mocks, timeout=1)
        mocks["qemu_cls"].create_snapshot_drive.assert_called_once()


class TestEngineBootsQEMU:
    """Verify QEMU is started with gdb=True and paused=True."""

    def test_engine_boots_qemu_with_gdb(self):
        mocks = _build_patches(crash_on_first=False, iterations=2)
        _run_engine(mocks, timeout=1)
        mocks["qemu_instance"].start.assert_called_once()
        call_kwargs = mocks["qemu_instance"].start.call_args
        assert call_kwargs.kwargs.get("gdb") is True
        assert call_kwargs.kwargs.get("paused") is True


class TestEngineReadsVectorTableAndSetsBreakpoints:
    """Verify vector table is read and breakpoints set on fault handlers."""

    def test_engine_reads_vector_table_and_sets_breakpoints(self):
        mocks = _build_patches(crash_on_first=False, iterations=2)
        _run_engine(mocks, timeout=1)

        # Vector table should be read
        mocks["mem_instance"].read_vector_table.assert_called_once()

        # Breakpoints should be set on fault handlers (with Thumb bit cleared)
        bp_calls = mocks["gdb"].set_breakpoint.call_args_list
        bp_addrs = {c[0][0] for c in bp_calls}

        vectors = _make_vector_table()
        expected_addrs = set()
        for name in ("hardfault", "memmanage", "busfault", "usagefault"):
            addr = vectors[name]
            if addr and addr != 0 and addr != 0xFFFFFFFF:
                expected_addrs.add(addr & ~1)

        assert expected_addrs.issubset(bp_addrs)


class TestEngineSavesBaseSnapshot:
    """Verify snapshot_mgr.save is called with 'fuzz_base_0'."""

    def test_engine_saves_base_snapshot(self):
        mocks = _build_patches(crash_on_first=False, iterations=2)
        _run_engine(mocks, timeout=1)
        mocks["snap_instance"].save.assert_called_once_with(
            mocks["qemu_instance"], "fuzz_base_0"
        )


class TestEngineCrashPath:
    """Simulate breakpoint hit — verify crash reporting."""

    def test_engine_crash_path(self):
        gdb = _make_gdb_mock(crash_on_first=True, iterations=2)
        mocks = _build_patches(gdb_mock=gdb)
        stats = _run_engine(mocks, timeout=1)

        assert stats.crashes >= 1
        # Registers should have been read
        gdb.read_registers.assert_called()
        # CFSR should have been read at 0xE000ED24
        from rtosploit.fuzzing.engine import CFSR_ADDR
        gdb.read_memory.assert_any_call(CFSR_ADDR, 4)
        # CrashReporter.deduplicate should have been called
        mocks["reporter_cls"].deduplicate.assert_called()


class TestEngineNoCrashPath:
    """Simulate timeout (no breakpoint hit) — verify coverage read attempted."""

    def test_engine_no_crash_path(self):
        mocks = _build_patches(crash_on_first=False, iterations=3)
        stats = _run_engine(mocks, timeout=1, coverage_addr=0x2002_0000)

        assert stats.executions >= 1
        assert stats.crashes == 0
        # Coverage bitmap should have been read
        mocks["gdb"].read_memory.assert_called()


class TestEngineRespectsTimeout:
    """Verify loop exits after the configured timeout."""

    def test_engine_respects_timeout(self):
        gdb = _make_gdb_mock(crash_on_first=False, iterations=5)
        mocks = _build_patches(gdb_mock=gdb)
        stats = _run_engine(mocks, timeout=1)

        # Should have done at least 1 execution but stopped due to timeout
        assert stats.executions >= 1
        assert stats.elapsed > 0


class TestEngineCallsOnStats:
    """Verify the on_stats callback is invoked with a stats dict."""

    def test_engine_calls_on_stats(self):
        mocks = _build_patches(crash_on_first=False, iterations=3)
        callback = MagicMock()

        with (
            patch(f"{_ENGINE}.QEMUInstance", mocks["qemu_cls"]),
            patch(f"{_ENGINE}.SnapshotManager", mocks["snap_cls"]),
            patch(f"{_ENGINE}.MemoryOps", mocks["mem_cls"]),
            patch(f"{_ENGINE}.Mutator", mocks["mutator_cls"]),
            patch(f"{_ENGINE}.CorpusManager", mocks["corpus_cls"]),
            patch(f"{_ENGINE}.CrashReporter", mocks["reporter_cls"]),
            patch(f"{_ENGINE}.RTOSploitConfig") as cfg_mock,
        ):
            cfg_instance = MagicMock()
            cfg_instance.gdb.port = 1234
            cfg_mock.return_value = cfg_instance

            from rtosploit.fuzzing.engine import FuzzEngine

            engine = FuzzEngine(
                firmware_path="/tmp/test.elf",
                machine_name="lm3s6965evb",
                inject_addr=0x2001_0000,
                inject_size=256,
                exec_timeout=0.05,
            )
            engine.run(
                timeout=1,
                corpus_dir="/tmp/corpus",
                crash_dir="/tmp/crashes",
                on_stats=callback,
            )

        assert callback.call_count >= 1
        # Check the callback received a dict with expected keys
        stats_dict = callback.call_args[0][0]
        assert "executions" in stats_dict
        assert "crashes" in stats_dict
        assert "coverage" in stats_dict
        assert "exec_per_sec" in stats_dict


class TestEngineDeduplicatesCrashes:
    """Two identical crashes — only one should be reported as unique."""

    def test_engine_deduplicates_crashes(self):
        gdb = MagicMock()
        gdb.read_register.return_value = 0x0800_1000
        gdb.read_registers.return_value = {
            "r0": 0, "r1": 0, "r2": 0, "r3": 0,
            "r4": 0, "r5": 0, "r6": 0, "r7": 0,
            "r8": 0, "r9": 0, "r10": 0, "r11": 0, "r12": 0,
            "sp": 0x2001_0000, "lr": 0x0800_0100, "pc": 0x0800_1234,
            "xpsr": 0x6100_0000,
        }
        gdb.read_memory.return_value = b"\x00\x02\x00\x00"

        # Boot stop + snapshot re-sync + iter1 (crash) + iter2 (crash) + extra
        gdb.receive_stop.side_effect = [
            "S05",  # boot stop
            "S05",  # re-sync after snapshot save
            "S05",  # iter1 re-sync
            "S05",  # iter1 fuzz — crash
            "S05",  # iter2 re-sync
            "S05",  # iter2 fuzz — crash
            # extra for further iterations
            "S05", "S05",
            "S05", "S05",
        ]

        # First dedup returns True (unique), second returns False (duplicate)
        dedup_returns = iter([True, False])

        mocks = _build_patches(gdb_mock=gdb, iterations=2)
        mocks["reporter_cls"].deduplicate.side_effect = lambda cd, el: next(dedup_returns, False)

        stats = _run_engine(mocks, timeout=1)

        # Two crashes total, but only one unique
        assert stats.crashes >= 2
        assert stats.unique_crashes == 1
        # report_crash should have been called only once (for the unique crash)
        assert mocks["reporter_instance"].report_crash.call_count == 1
