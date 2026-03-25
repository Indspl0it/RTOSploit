"""AFL-style 64KB writable edge coverage bitmap.

Provides a mutable bitmap for recording edge coverage during firmware
emulation, plus a FERMCov collector that separates interrupt handler edges
from main program edges to prevent interrupt timing variation from inflating
the coverage bitmap.

References:
    - AFL coverage instrumentation
    - Farrelly, Chesser, Ranasinghe. "Ember-IO: Effective Firmware Fuzzing
      with Model-Free Memory Mapped IO." ASIA CCS 2023.
      https://doi.org/10.1145/3579856.3582840
"""

from __future__ import annotations

import logging

from rtosploit.coverage.bitmap_reader import BITMAP_SIZE

logger = logging.getLogger(__name__)


class CoverageBitmap:
    """AFL-style 64KB edge coverage bitmap with write support.

    Each bucket stores a saturating 8-bit hit count for one edge hash.
    Edge IDs are computed as ``((prev_block >> 1) ^ current_block) % size``.
    """

    def __init__(self, size: int = BITMAP_SIZE) -> None:
        self._size = size
        self._bitmap = bytearray(size)

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_edge(self, prev_block: int, current_block: int) -> None:
        """Record an edge hit using AFL-style XOR hash.

        Args:
            prev_block: Address of the previous basic block (already shifted
                right by 1 in the caller, or raw address -- the shift is
                applied here).
            current_block: Address of the current basic block.
        """
        edge_id = ((prev_block >> 1) ^ current_block) % self._size
        # Saturating increment at 255
        val = self._bitmap[edge_id]
        if val < 255:
            self._bitmap[edge_id] = val + 1

    # ------------------------------------------------------------------
    # Comparison / merging
    # ------------------------------------------------------------------

    def has_new_coverage(self, other: CoverageBitmap) -> bool:
        """Return True if *self* contains edges not present in *other*.

        This is used to decide whether a test case is "interesting" --
        it found at least one edge that the global bitmap has not seen.

        Args:
            other: The global/reference bitmap to compare against.
        """
        mine = self._bitmap
        theirs = other._bitmap
        for i in range(self._size):
            if mine[i] != 0 and theirs[i] == 0:
                return True
        return False

    def merge_into(self, target: CoverageBitmap) -> None:
        """OR *self* into *target* (global bitmap merge).

        For each index, ``target[i] = max(target[i], self[i])``.

        Args:
            target: The global bitmap to merge into.
        """
        src = self._bitmap
        dst = target._bitmap
        for i in range(self._size):
            if src[i] > dst[i]:
                dst[i] = src[i]

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    def count_edges(self) -> int:
        """Return the number of distinct edges hit (non-zero buckets)."""
        return sum(1 for b in self._bitmap if b != 0)

    def count_hits(self) -> int:
        """Return the sum of all hit counts across all buckets."""
        return sum(self._bitmap)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Zero the bitmap for a new execution."""
        self._bitmap = bytearray(self._size)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Return the raw bitmap as an immutable bytes object."""
        return bytes(self._bitmap)

    @classmethod
    def from_bytes(cls, data: bytes) -> CoverageBitmap:
        """Construct a bitmap from raw bytes.

        Args:
            data: Raw bitmap bytes.  Length determines bitmap size.

        Returns:
            A new :class:`CoverageBitmap` initialised with *data*.
        """
        bm = cls(size=len(data))
        bm._bitmap = bytearray(data)
        return bm

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """The number of buckets in the bitmap."""
        return self._size

    def __len__(self) -> int:
        return self._size

    def __getitem__(self, index: int) -> int:
        return self._bitmap[index]


class FERMCovCollector:
    """Interrupt-aware coverage collector.

    Separates interrupt handler edges from main program edges to prevent
    interrupt timing variation from inflating the coverage bitmap.

    Based on: Farrelly, Chesser, Ranasinghe. "Ember-IO: Effective Firmware
    Fuzzing with Model-Free Memory Mapped IO." ASIA CCS 2023.
    https://doi.org/10.1145/3579856.3582840
    """

    def __init__(self) -> None:
        self._bitmap = CoverageBitmap()
        self._last_program_block: int = 0
        self._last_int_block: int = 0
        self._blocks_executed: int = 0

    def on_block(self, address: int, in_interrupt: bool) -> None:
        """Record a basic block execution with interrupt-aware edge tracking.

        When *in_interrupt* is ``True``, the edge is recorded using a
        separate ``last_block`` variable so that interrupt timing does not
        create spurious "new" edges in the program coverage channel.

        Args:
            address: The program counter at the start of the basic block.
            in_interrupt: Whether the CPU is currently in an interrupt
                handler (e.g. IPSR != 0 on Cortex-M).
        """
        self._blocks_executed += 1
        if in_interrupt:
            self._bitmap.record_edge(self._last_int_block, address)
            self._last_int_block = address >> 1
        else:
            self._bitmap.record_edge(self._last_program_block, address)
            self._last_program_block = address >> 1
            self._last_int_block = 0  # Reset interrupt chain

    @property
    def bitmap(self) -> CoverageBitmap:
        """The underlying coverage bitmap."""
        return self._bitmap

    @property
    def blocks_executed(self) -> int:
        """Total number of basic blocks executed."""
        return self._blocks_executed

    def reset(self) -> None:
        """Reset all coverage state for a new execution."""
        self._bitmap.reset()
        self._last_program_block = 0
        self._last_int_block = 0
        self._blocks_executed = 0
