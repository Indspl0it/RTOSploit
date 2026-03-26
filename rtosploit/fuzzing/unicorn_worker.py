"""Unicorn-based fuzz worker and engine for firmware fuzzing.

Provides UnicornFuzzWorker (single-threaded worker) and UnicornFuzzEngine
(multi-threaded orchestrator) that use UnicornRehostEngine with PIP-based
MMIO handling, FERMCov coverage, and interrupt scheduling.

Replaces the QEMU+GDB-based FuzzEngine/FuzzWorker for Unicorn targets.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from rtosploit.coverage.bitmap import CoverageBitmap
from rtosploit.fuzzing.execution import ExecutionResult
from rtosploit.fuzzing.mutator import Mutator
from rtosploit.peripherals.interrupt_scheduler import InterruptScheduler, discover_irqs
from rtosploit.peripherals.models.mmio_fallback import CompositeMMIOHandler
from rtosploit.peripherals.unicorn_engine import (
    HAS_UNICORN,
    UnicornRehostEngine,
    UnicornSnapshot,
)
from rtosploit.utils.binary import FirmwareImage

logger = logging.getLogger(__name__)


@dataclass
class UnicornFuzzStats:
    """Accumulated statistics for a Unicorn fuzz campaign."""

    executions: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    new_coverage: int = 0
    total_blocks: int = 0
    corpus_size: int = 0
    elapsed: float = 0.0
    exec_per_sec: float = 0.0


class UnicornFuzzWorker:
    """Single Unicorn-based fuzz worker.

    Manages a UnicornRehostEngine instance with snapshot/restore
    for efficient fuzz iteration. Each worker operates independently
    and can be run in its own thread.

    Args:
        firmware: Parsed firmware image.
        irq_list: List of external IRQ numbers to schedule.
        max_blocks: Maximum basic blocks per execution before timeout.
        irq_interval: Basic blocks between interrupt injections.
    """

    def __init__(
        self,
        firmware: FirmwareImage,
        irq_list: Optional[list[int]] = None,
        max_blocks: int = 500_000,
        irq_interval: int = 1000,
    ) -> None:
        if not HAS_UNICORN:
            raise ImportError("unicorn package not installed. Install with: pip install unicorn")

        self._firmware = firmware
        self._irq_list = irq_list if irq_list is not None else []
        self._max_blocks = max_blocks
        self._irq_interval = irq_interval
        self._engine: Optional[UnicornRehostEngine] = None
        self._snapshot: Optional[UnicornSnapshot] = None
        self._global_bitmap = CoverageBitmap()
        self._stats = UnicornFuzzStats()
        self._crash_hashes: set[int] = set()

    def setup(self) -> None:
        """Create UnicornRehostEngine, run init phase, take snapshot.

        After this call, the worker is ready for run_one() iterations.
        """
        handler = CompositeMMIOHandler()
        self._engine = UnicornRehostEngine(
            self._firmware,
            mmio_handler=handler,
            max_blocks=self._max_blocks,
        )
        self._engine.setup()

        # Configure interrupt scheduler
        if self._irq_list:
            scheduler = InterruptScheduler(self._irq_list, interval=self._irq_interval)
            self._engine.set_interrupt_scheduler(scheduler)

        # Run initial firmware boot (short) to reach a stable state
        self._engine.run(timeout_ms=1000, max_instructions=50_000)

        # Take snapshot at post-init state
        self._snapshot = self._engine.take_snapshot()

        logger.info(
            "UnicornFuzzWorker ready: %d IRQs, max_blocks=%d",
            len(self._irq_list),
            self._max_blocks,
        )

    def run_one(self, fuzz_input: bytes) -> ExecutionResult:
        """Run a single fuzz iteration.

        Args:
            fuzz_input: Raw bytes from the fuzzer/mutator.

        Returns:
            ExecutionResult with coverage, stop reason, crash info.
        """
        if self._engine is None or self._snapshot is None:
            raise RuntimeError("Call setup() first")

        # Restore snapshot to clean state
        self._engine.restore_snapshot(self._snapshot)

        # Run iteration
        result = self._engine.run_fuzz_iteration(fuzz_input)
        return result

    def is_interesting(self, result: ExecutionResult) -> bool:
        """Check if the result has new coverage not seen in global bitmap.

        Args:
            result: Result from run_one().

        Returns:
            True if the result found new edges or is a crash.
        """
        if result.crashed:
            return True
        if result.coverage is not None:
            return result.coverage.has_new_coverage(self._global_bitmap)
        return False

    def merge_coverage(self, result: ExecutionResult) -> None:
        """Merge result's coverage into the global bitmap.

        Args:
            result: Result from run_one() that was deemed interesting.
        """
        if result.coverage is not None:
            result.coverage.merge_into(self._global_bitmap)

    def fuzz_loop(
        self,
        corpus: list[bytes],
        mutator: Mutator,
        timeout: int = 0,
        callback: Optional[Callable[[ExecutionResult, bytes], None]] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> UnicornFuzzStats:
        """Run the main fuzz loop with coverage feedback.

        Args:
            corpus: Initial seed corpus (list of byte inputs).
            mutator: Mutator instance for generating new inputs.
            timeout: Maximum seconds to run (0 = unlimited).
            callback: Called for each interesting result with (result, input).
            stop_event: Threading event to signal stop from outside.

        Returns:
            Accumulated fuzz statistics.
        """
        if not corpus:
            corpus = [b"\x00" * 64]  # Default seed

        start_time = time.monotonic()
        stop = stop_event or threading.Event()

        while not stop.is_set():
            elapsed = time.monotonic() - start_time
            if timeout > 0 and elapsed >= timeout:
                break

            # Pick a base input and mutate
            base_idx = self._stats.executions % len(corpus)
            base_input = corpus[base_idx]
            fuzz_input = mutator.mutate(base_input)

            # Run iteration
            result = self.run_one(fuzz_input)
            self._stats.executions += 1
            self._stats.total_blocks += result.blocks_executed

            # Check for interesting results
            if self.is_interesting(result):
                self.merge_coverage(result)
                self._stats.new_coverage += 1

                if result.crashed:
                    crash_hash = hash((result.crash_address, result.crash_type))
                    if crash_hash not in self._crash_hashes:
                        self._crash_hashes.add(crash_hash)
                        self._stats.unique_crashes += 1
                    self._stats.crashes += 1
                else:
                    # New coverage -> add to corpus
                    corpus.append(fuzz_input)

                if callback:
                    callback(result, fuzz_input)

            # Update stats
            self._stats.corpus_size = len(corpus)
            self._stats.elapsed = time.monotonic() - start_time
            self._stats.exec_per_sec = (
                self._stats.executions / self._stats.elapsed
                if self._stats.elapsed > 0
                else 0.0
            )

        return self._stats

    @property
    def stats(self) -> UnicornFuzzStats:
        """Access accumulated statistics."""
        return self._stats

    @property
    def global_bitmap(self) -> CoverageBitmap:
        """Access the global coverage bitmap."""
        return self._global_bitmap

    @property
    def engine(self) -> Optional[UnicornRehostEngine]:
        """Access the underlying UnicornRehostEngine."""
        return self._engine


class UnicornFuzzEngine:
    """Multi-threaded Unicorn-based firmware fuzzing engine.

    Creates N UnicornFuzzWorker threads with a shared global bitmap
    and corpus, running until timeout or stop.

    Args:
        firmware_path: Path to firmware binary.
        jobs: Number of parallel worker threads.
        output_dir: Directory for crash outputs.
        timeout: Maximum seconds to run (0 = unlimited).
        max_blocks: Max basic blocks per execution.
        irq_interval: Blocks between interrupt injections.
    """

    def __init__(
        self,
        firmware_path: str,
        jobs: int = 1,
        output_dir: str = "fuzz-output",
        timeout: int = 0,
        max_blocks: int = 500_000,
        irq_interval: int = 1000,
    ) -> None:
        self._firmware_path = firmware_path
        self._jobs = max(1, jobs)
        self._output_dir = output_dir
        self._timeout = timeout
        self._max_blocks = max_blocks
        self._irq_interval = irq_interval
        self._workers: list[UnicornFuzzWorker] = []
        self._threads: list[threading.Thread] = []
        self._stop_event = threading.Event()
        self._stats = UnicornFuzzStats()

    def run(
        self,
        seeds: Optional[list[bytes]] = None,
        on_stats: Optional[Callable[[dict], None]] = None,
    ) -> UnicornFuzzStats:
        """Run the parallel fuzz campaign.

        Args:
            seeds: Initial seed corpus. Defaults to a single zero-filled input.
            on_stats: Callback called periodically with aggregated stats dict.

        Returns:
            Aggregated UnicornFuzzStats across all workers.
        """
        from rtosploit.utils.binary import load_firmware

        # Load firmware
        firmware = load_firmware(self._firmware_path)

        # Discover IRQs from vector table
        try:
            irq_list = discover_irqs(firmware)
        except Exception as e:
            logger.warning("IRQ discovery failed, continuing without interrupts: %s", e)
            irq_list = []

        logger.info(
            "UnicornFuzzEngine: %d jobs, %d IRQs discovered, max_blocks=%d",
            self._jobs,
            len(irq_list),
            self._max_blocks,
        )

        # Create output directories
        output_path = Path(self._output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        (output_path / "crashes").mkdir(exist_ok=True)
        (output_path / "corpus").mkdir(exist_ok=True)

        # Shared corpus (thread-safe via GIL for list append)
        corpus: list[bytes] = list(seeds) if seeds else [b"\x00" * 64]

        # Create workers and threads
        self._workers = []
        self._threads = []
        self._stop_event.clear()
        start_time = time.monotonic()

        for i in range(self._jobs):
            worker = UnicornFuzzWorker(
                firmware=firmware,
                irq_list=irq_list,
                max_blocks=self._max_blocks,
                irq_interval=self._irq_interval,
            )

            try:
                worker.setup()
            except Exception as e:
                logger.error("Worker %d setup failed: %s", i, e)
                continue

            self._workers.append(worker)

            mutator = Mutator(seed=i * 31337)

            def _crash_callback(result: ExecutionResult, data: bytes, wid: int = i) -> None:
                if result.crashed:
                    crash_path = output_path / "crashes" / f"crash-w{wid}-{int(time.time())}.bin"
                    crash_path.write_bytes(data)
                    logger.info(
                        "Worker %d: crash at 0x%08X (%s)",
                        wid,
                        result.crash_address,
                        result.crash_type,
                    )

            t = threading.Thread(
                target=worker.fuzz_loop,
                kwargs={
                    "corpus": corpus,
                    "mutator": mutator,
                    "timeout": self._timeout,
                    "callback": _crash_callback,
                    "stop_event": self._stop_event,
                },
                daemon=True,
                name=f"unicorn-fuzz-{i}",
            )
            self._threads.append(t)

        # Start all workers
        for t in self._threads:
            t.start()

        logger.info("Started %d Unicorn fuzz workers", len(self._workers))

        # Monitor loop
        try:
            while any(t.is_alive() for t in self._threads):
                time.sleep(0.5)

                total_exec = sum(w.stats.executions for w in self._workers)
                total_crashes = sum(w.stats.crashes for w in self._workers)
                total_unique = sum(w.stats.unique_crashes for w in self._workers)
                elapsed = time.monotonic() - start_time
                eps = total_exec / elapsed if elapsed > 0 else 0.0

                if on_stats:
                    on_stats({
                        "executions": total_exec,
                        "crashes": total_crashes,
                        "unique_crashes": total_unique,
                        "corpus_size": len(corpus),
                        "elapsed": elapsed,
                        "exec_per_sec": eps,
                    })

        except KeyboardInterrupt:
            logger.info("Stopping all Unicorn fuzz workers...")
            self._stop_event.set()

        # Wait for all threads
        for t in self._threads:
            t.join(timeout=5)

        # Aggregate final stats
        elapsed = time.monotonic() - start_time
        self._stats = UnicornFuzzStats(
            executions=sum(w.stats.executions for w in self._workers),
            crashes=sum(w.stats.crashes for w in self._workers),
            unique_crashes=sum(w.stats.unique_crashes for w in self._workers),
            new_coverage=sum(w.stats.new_coverage for w in self._workers),
            total_blocks=sum(w.stats.total_blocks for w in self._workers),
            corpus_size=len(corpus),
            elapsed=elapsed,
            exec_per_sec=(
                sum(w.stats.executions for w in self._workers) / elapsed
                if elapsed > 0
                else 0.0
            ),
        )

        logger.info(
            "Unicorn fuzz campaign done: %d executions, %d crashes (%d unique), "
            "%.1f exec/sec over %.1fs",
            self._stats.executions,
            self._stats.crashes,
            self._stats.unique_crashes,
            self._stats.exec_per_sec,
            self._stats.elapsed,
        )

        return self._stats

    def stop(self) -> None:
        """Signal all workers to stop."""
        self._stop_event.set()

    @property
    def stats(self) -> UnicornFuzzStats:
        """Access aggregated statistics."""
        return self._stats
