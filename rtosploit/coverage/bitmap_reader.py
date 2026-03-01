"""Read and parse AFL-style 64KB coverage bitmaps.

The bitmap format matches the Rust fuzzer in ``crates/rtosploit-fuzzer/src/coverage.rs``.
Edge ID computation: ``((from_addr >> 1) ^ to_addr) % 65536``.
"""

from __future__ import annotations

from dataclasses import dataclass, field


BITMAP_SIZE: int = 65_536  # Match Rust fuzzer (64 KB)


@dataclass
class CoverageMap:
    """Aggregated coverage information derived from traces and/or bitmaps."""

    covered_addresses: set[int] = field(default_factory=set)
    covered_edges: list[tuple[int, int]] = field(default_factory=list)
    hot_addresses: dict[int, int] = field(default_factory=dict)  # address -> hit count
    total_instructions: int = 0
    covered_instructions: int = 0

    @property
    def coverage_percent(self) -> float:
        if self.total_instructions == 0:
            return 0.0
        return (self.covered_instructions / self.total_instructions) * 100.0


class BitmapReader:
    """Read and interpret AFL-style 64KB coverage bitmaps."""

    def __init__(self) -> None:
        pass

    def read_file(self, path: str) -> bytes:
        """Read a raw 64KB bitmap file from disk.

        Args:
            path: Filesystem path to the bitmap file.

        Returns:
            Raw bytes of the bitmap (expected to be exactly ``BITMAP_SIZE`` bytes).

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file is not exactly ``BITMAP_SIZE`` bytes.
        """
        with open(path, "rb") as f:
            data = f.read()
        if len(data) != BITMAP_SIZE:
            raise ValueError(
                f"Bitmap file is {len(data)} bytes, expected {BITMAP_SIZE} bytes"
            )
        return data

    def read_bytes(self, data: bytes) -> dict[int, int]:
        """Parse raw bitmap bytes into a dict of {edge_id: hit_count}.

        Only non-zero entries are included in the result.

        Args:
            data: Raw bitmap bytes (length should be ``BITMAP_SIZE``).

        Returns:
            Mapping from edge ID to hit count for all edges hit at least once.
        """
        result: dict[int, int] = {}
        for i, b in enumerate(data):
            if b != 0:
                result[i] = b
        return result

    def count_edges(self, data: bytes) -> int:
        """Count the number of non-zero entries in a bitmap.

        Args:
            data: Raw bitmap bytes.

        Returns:
            Number of distinct edges hit (non-zero entries).
        """
        return sum(1 for b in data if b != 0)

    @staticmethod
    def compute_edge_id(from_addr: int, to_addr: int) -> int:
        """Compute AFL-style edge hash matching the Rust implementation.

        Formula: ``((from_addr >> 1) ^ to_addr) % BITMAP_SIZE``

        Args:
            from_addr: Source address of the edge.
            to_addr: Destination address of the edge.

        Returns:
            Edge ID in the range ``[0, BITMAP_SIZE)``.
        """
        prev = from_addr >> 1
        return (prev ^ to_addr) % BITMAP_SIZE
