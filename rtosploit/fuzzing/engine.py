"""Snapshot-based firmware fuzzing engine with parallel worker support."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from rtosploit.config import RTOSploitConfig
from rtosploit.emulation.qemu import QEMUInstance
from rtosploit.emulation.snapshot import SnapshotManager
from rtosploit.emulation.memory import MemoryOps
from rtosploit.fuzzing.mutator import Mutator
from rtosploit.fuzzing.corpus import CorpusManager
from rtosploit.fuzzing.crash_reporter import CrashReporter
from rtosploit.fuzzing.input_injector import InputInjector

logger = logging.getLogger(__name__)

CFSR_ADDR = 0xE000ED24


@dataclass
class FuzzStats:
    """Accumulated statistics for a fuzz campaign."""

    executions: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    coverage: float = 0.0
    corpus_size: int = 0
    elapsed: float = 0.0
    exec_per_sec: float = 0.0


class FuzzWorker:
    """Single QEMU-backed fuzz worker.

    Each worker manages its own QEMU instance, GDB connection, and
    snapshot. Multiple workers run in parallel threads sharing a
    corpus and crash reporter.
    """

    def __init__(
        self,
        worker_id: int,
        firmware_path: str,
        machine_name: str,
        inject_addr: int = 0x20010000,
        inject_size: int = 256,
        exec_timeout: float = 0.05,
        gdb_port: int = 1234,
        inject_len_addr: int | None = None,
        coverage_addr: int | None = None,
        coverage_size: int = 4096,
        persistent_mode: bool = False,
        auto_rehost: bool = False,
        injector: InputInjector | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.firmware_path = firmware_path
        self.machine_name = machine_name
        self.inject_addr = inject_addr
        self.inject_size = inject_size
        self.exec_timeout = exec_timeout
        self.gdb_port = gdb_port
        self.inject_len_addr = inject_len_addr
        self.coverage_addr = coverage_addr
        self.coverage_size = coverage_size
        self.persistent_mode = persistent_mode
        self.auto_rehost = auto_rehost
        self._injector = injector
        self._stats = FuzzStats()
        self._crash_data_list: list[dict] = []
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Signal this worker to stop."""
        self._stop_event.set()

    @property
    def stats(self) -> FuzzStats:
        return self._stats

    def run(
        self,
        timeout: int,
        corpus: CorpusManager,
        mutator: Mutator,
        reporter: CrashReporter,
        config: RTOSploitConfig,
        output_dir: str,
        on_stats: Callable[[dict], None] | None = None,
    ) -> FuzzStats:
        """Run the fuzz loop for this worker.

        Args:
            timeout: Max seconds to run (0 = unlimited).
            corpus: Shared corpus manager (thread-safe).
            mutator: Mutator instance (each worker should have its own).
            reporter: Shared crash reporter.
            config: RTOSploit config.
            output_dir: Directory for worker-specific files.
            on_stats: Optional stats callback.

        Returns:
            FuzzStats for this worker.
        """
        snapshot_mgr = SnapshotManager()

        # Use passed config but override GDB port for this worker
        import copy
        config_copy = copy.deepcopy(config)
        config_copy.gdb.port = self.gdb_port

        qemu = QEMUInstance(config_copy)

        try:
            # 1. Create snapshot drive and boot QEMU
            snap_args = QEMUInstance.create_snapshot_drive(output_dir)
            qemu.start(
                self.firmware_path,
                self.machine_name,
                gdb=True,
                paused=True,
                extra_qemu_args=snap_args,
            )

            gdb = qemu.gdb
            if gdb is None:
                raise RuntimeError(
                    f"Worker {self.worker_id}: GDB connection required"
                )

            mem = MemoryOps(qemu)

            # 2. Boot firmware — give it time to initialize
            gdb.continue_execution()
            time.sleep(2.0)
            gdb.send_break()
            gdb.receive_stop(timeout=10.0)

            pc = gdb.read_register("pc")
            logger.info("Worker %d: initial PC 0x%08x", self.worker_id, pc)

            # 3. Read vector table and set breakpoints
            vectors = mem.read_vector_table()
            for name in ("hardfault", "memmanage", "busfault", "usagefault"):
                addr = vectors.get(name, 0)
                if addr and addr != 0 and addr != 0xFFFFFFFF:
                    gdb.set_breakpoint(addr & ~1)

            # 3b. Auto-rehost: set breakpoints at HAL input functions
            if self.auto_rehost and self._injector:
                for bp_addr in self._injector.get_breakpoint_addresses():
                    gdb.set_breakpoint(bp_addr & ~1)
                logger.info(
                    "Worker %d: auto-rehost set %d input breakpoints",
                    self.worker_id, self._injector.input_count,
                )

            # 4. Save base snapshot
            if not self.persistent_mode:
                snapshot_mgr.save(qemu, f"fuzz_base_{self.worker_id}")
                # Re-sync GDB after snapshot save (VM was paused/resumed)
                gdb.send_break()
                gdb.receive_stop(timeout=10.0)

            # Save register state for persistent mode
            saved_registers = gdb.read_registers()

            # 5. Fuzz loop
            start_time = time.monotonic()
            snapshot_name = f"fuzz_base_{self.worker_id}"

            while not self._stop_event.is_set():
                elapsed = time.monotonic() - start_time
                if timeout and elapsed >= timeout:
                    break

                # a. Reset target
                if self.persistent_mode:
                    # Fast reset: system_reset + restore registers via GDB
                    qemu.reset()
                    time.sleep(0.01)
                    gdb.send_break()
                    gdb.receive_stop(timeout=2.0)
                    # Restore saved register state
                    for name, val in saved_registers.items():
                        try:
                            gdb.write_register(name, val)
                        except Exception:
                            pass
                else:
                    # Snapshot-based reset
                    snapshot_mgr.fast_reset(qemu, snapshot_name)
                    gdb.send_break()
                    gdb.receive_stop(timeout=5.0)

                # b. Mutate input
                base_input = corpus.get_random()
                mutated = mutator.mutate(base_input)
                mutated = mutated[: self.inject_size]

                # c. Write input to target
                if self.auto_rehost and self._injector:
                    # Auto mode: split data across discovered input channels
                    for fuzz_input, chunk in self._injector.split_data(mutated):
                        gdb.write_memory(fuzz_input.address, chunk)
                else:
                    # Legacy mode: fixed inject address
                    gdb.write_memory(self.inject_addr, mutated)

                    if self.inject_len_addr is not None:
                        length_bytes = len(mutated).to_bytes(4, "little")
                        gdb.write_memory(self.inject_len_addr, length_bytes)

                # d. Resume and wait for stop
                gdb.continue_execution()

                is_crash = False
                try:
                    gdb.receive_stop(timeout=self.exec_timeout)
                    is_crash = True
                except TimeoutError:
                    gdb.send_break()
                    try:
                        gdb.receive_stop(timeout=0.5)
                    except TimeoutError:
                        pass

                self._stats.executions += 1

                if is_crash:
                    # Read crash data
                    registers = gdb.read_registers()
                    try:
                        cfsr_bytes = gdb.read_memory(CFSR_ADDR, 4)
                        cfsr = int.from_bytes(cfsr_bytes, "little")
                    except Exception:
                        cfsr = 0

                    crash_data = {
                        "fault_type": "hard_fault",
                        "cfsr": cfsr,
                        "registers": registers,
                        "fault_address": registers.get("pc", 0),
                        "backtrace": [],
                        "timestamp": int(time.time()),
                    }

                    if CrashReporter.deduplicate(crash_data, self._crash_data_list):
                        crash_id = f"crash-w{self.worker_id}-{self._stats.unique_crashes:06d}"
                        reporter.report_crash(crash_data, mutated, crash_id)
                        self._crash_data_list.append(crash_data)
                        self._stats.unique_crashes += 1
                        logger.info(
                            "Worker %d: crash #%d PC=0x%08x CFSR=0x%08x",
                            self.worker_id,
                            self._stats.unique_crashes,
                            registers.get("pc", 0),
                            cfsr,
                        )

                    self._stats.crashes += 1
                else:
                    # Read coverage if configured
                    if self.coverage_addr is not None:
                        try:
                            bitmap = gdb.read_memory(
                                self.coverage_addr, self.coverage_size
                            )
                            corpus.add(mutated, bitmap)
                        except Exception:
                            pass

                # Update stats
                self._stats.coverage = corpus.coverage_percentage()
                self._stats.corpus_size = corpus.size
                self._stats.elapsed = time.monotonic() - start_time
                self._stats.exec_per_sec = (
                    self._stats.executions / self._stats.elapsed
                    if self._stats.elapsed > 0
                    else 0.0
                )

                if on_stats:
                    on_stats(
                        {
                            "worker_id": self.worker_id,
                            "executions": self._stats.executions,
                            "crashes": self._stats.crashes,
                            "unique_crashes": self._stats.unique_crashes,
                            "coverage": self._stats.coverage,
                            "corpus_size": self._stats.corpus_size,
                            "elapsed": self._stats.elapsed,
                            "exec_per_sec": self._stats.exec_per_sec,
                        }
                    )

        except KeyboardInterrupt:
            logger.info("Worker %d: interrupted", self.worker_id)
        except Exception as e:
            import traceback
            logger.error(
                "Worker %d: error: %s\n%s",
                self.worker_id, e, traceback.format_exc(),
            )
        finally:
            qemu.stop()

        return self._stats


class FuzzEngine:
    """Parallel snapshot-based QEMU firmware fuzzing engine.

    Spawns N parallel workers, each with its own QEMU instance and GDB
    connection. Workers share a thread-safe corpus and crash reporter.
    Default exec_timeout is 0.05s (50ms) — embedded firmware either
    crashes immediately or runs normally, so long timeouts waste cycles.

    Algorithm per worker:
    1. Boot QEMU with firmware + GDB + qcow2 snapshot drive
    2. Wait for initial state, read vector table, set fault breakpoints
    3. Save snapshot
    4. Loop: restore → mutate → inject → resume → detect → report
    """

    def __init__(
        self,
        firmware_path: str,
        machine_name: str,
        inject_addr: int = 0x20010000,
        inject_size: int = 256,
        config: RTOSploitConfig | None = None,
        inject_len_addr: int | None = None,
        coverage_addr: int | None = None,
        coverage_size: int = 4096,
        exec_timeout: float = 0.05,
        jobs: int = 1,
        persistent_mode: bool = False,
        auto_rehost: bool = False,
        injector: InputInjector | None = None,
    ) -> None:
        self.firmware_path = firmware_path
        self.machine_name = machine_name
        self.inject_addr = inject_addr
        self.inject_size = inject_size
        self.inject_len_addr = inject_len_addr
        self.coverage_addr = coverage_addr
        self.coverage_size = coverage_size
        self.exec_timeout = exec_timeout
        self.jobs = jobs
        self.persistent_mode = persistent_mode
        self.auto_rehost = auto_rehost
        self._injector = injector
        self._config = config or RTOSploitConfig()
        self._stats = FuzzStats()

    def run(
        self,
        timeout: int = 0,
        corpus_dir: str = "corpus",
        crash_dir: str = "crashes",
        on_stats: Callable[[dict], None] | None = None,
    ) -> FuzzStats:
        """Run the parallel fuzz campaign.

        Args:
            timeout: Max seconds to run (0 = unlimited).
            corpus_dir: Directory for corpus inputs.
            crash_dir: Directory for crash outputs.
            on_stats: Callback called periodically with aggregated stats.

        Returns:
            FuzzStats with final aggregated statistics.
        """
        corpus = CorpusManager(corpus_dir)
        corpus.load_from_disk()
        reporter = CrashReporter(crash_dir)

        base_gdb_port = self._config.gdb.port
        start_time = time.monotonic()

        # Aggregated stats across all workers
        agg_lock = threading.Lock()
        agg_stats = {
            "executions": 0,
            "crashes": 0,
            "unique_crashes": 0,
            "coverage": 0.0,
            "corpus_size": 0,
            "elapsed": 0.0,
            "exec_per_sec": 0.0,
        }

        def on_worker_stats(worker_stats: dict) -> None:
            """Aggregate stats from a single worker update."""
            # We'll recalculate from all workers periodically
            pass

        workers: list[FuzzWorker] = []
        threads: list[threading.Thread] = []

        for i in range(self.jobs):
            worker = FuzzWorker(
                worker_id=i,
                firmware_path=self.firmware_path,
                machine_name=self.machine_name,
                inject_addr=self.inject_addr,
                inject_size=self.inject_size,
                exec_timeout=self.exec_timeout,
                gdb_port=base_gdb_port + i,
                inject_len_addr=self.inject_len_addr,
                coverage_addr=self.coverage_addr,
                coverage_size=self.coverage_size,
                persistent_mode=self.persistent_mode,
                auto_rehost=self.auto_rehost,
                injector=self._injector,
            )
            workers.append(worker)

            # Each worker gets its own mutator (different RNG seed)
            worker_mutator = Mutator(seed=i * 31337)
            output_dir = str(Path(crash_dir).parent / f"worker_{i}")
            Path(output_dir).mkdir(parents=True, exist_ok=True)

            t = threading.Thread(
                target=worker.run,
                kwargs={
                    "timeout": timeout,
                    "corpus": corpus,
                    "mutator": worker_mutator,
                    "reporter": reporter,
                    "config": self._config,
                    "output_dir": output_dir,
                    "on_stats": on_worker_stats,
                },
                daemon=True,
                name=f"fuzz-worker-{i}",
            )
            threads.append(t)

        # Start all workers
        for t in threads:
            t.start()

        logger.info(
            "Started %d fuzz workers (exec_timeout=%.3fs, persistent=%s)",
            self.jobs,
            self.exec_timeout,
            self.persistent_mode,
        )

        # Monitor loop — aggregate stats and call on_stats
        try:
            while any(t.is_alive() for t in threads):
                time.sleep(0.5)

                total_exec = sum(w.stats.executions for w in workers)
                total_crashes = sum(w.stats.crashes for w in workers)
                total_unique = sum(w.stats.unique_crashes for w in workers)
                elapsed = time.monotonic() - start_time
                eps = total_exec / elapsed if elapsed > 0 else 0.0

                if on_stats:
                    on_stats(
                        {
                            "executions": total_exec,
                            "crashes": total_crashes,
                            "unique_crashes": total_unique,
                            "coverage": corpus.coverage_percentage(),
                            "corpus_size": corpus.size,
                            "elapsed": elapsed,
                            "exec_per_sec": eps,
                        }
                    )

        except KeyboardInterrupt:
            logger.info("Stopping all workers...")
            for w in workers:
                w.stop()

        # Wait for all workers to finish
        for t in threads:
            t.join(timeout=5)

        # Save corpus
        corpus.save_to_disk()

        # Aggregate final stats
        elapsed = time.monotonic() - start_time
        self._stats = FuzzStats(
            executions=sum(w.stats.executions for w in workers),
            crashes=sum(w.stats.crashes for w in workers),
            unique_crashes=sum(w.stats.unique_crashes for w in workers),
            coverage=corpus.coverage_percentage(),
            corpus_size=corpus.size,
            elapsed=elapsed,
            exec_per_sec=(
                sum(w.stats.executions for w in workers) / elapsed
                if elapsed > 0
                else 0.0
            ),
        )

        logger.info(
            "Campaign done: %d executions, %d crashes (%d unique), "
            "%.1f exec/sec over %.1fs",
            self._stats.executions,
            self._stats.crashes,
            self._stats.unique_crashes,
            self._stats.exec_per_sec,
            self._stats.elapsed,
        )

        return self._stats
