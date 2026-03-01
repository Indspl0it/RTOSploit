"""Coverage-guided corpus management for fuzzing."""

from __future__ import annotations

import hashlib
import os
import random
import threading
from pathlib import Path
from typing import Optional

from rtosploit.coverage.bitmap_reader import BITMAP_SIZE


class CorpusManager:
    """Thread-safe corpus manager for parallel fuzzing.

    Manages a set of fuzzing inputs, keeping only those that expand coverage.
    All public methods are thread-safe for concurrent access from multiple
    fuzz workers.
    """

    def __init__(self, corpus_dir: str, bitmap_size: int = BITMAP_SIZE) -> None:
        self._corpus_dir = Path(corpus_dir)
        self._bitmap_size = bitmap_size
        self._entries: list[bytes] = []  # in-memory corpus
        self._global_bitmap = bytearray(bitmap_size)  # union of all coverage
        self._lock = threading.Lock()
        self._corpus_dir.mkdir(parents=True, exist_ok=True)

    # ── Core API ─────────────────────────────────────────────────────────────

    def add(self, input_data: bytes, coverage_bitmap: bytes) -> bool:
        """Add input if it covers new edges. Returns True if new coverage found.

        Thread-safe: uses a lock to protect bitmap and entry list.
        """
        with self._lock:
            has_new = False
            for i in range(min(len(coverage_bitmap), self._bitmap_size)):
                if coverage_bitmap[i] != 0 and self._global_bitmap[i] == 0:
                    has_new = True
                    break

            if not has_new:
                return False

            # Update global bitmap
            for i in range(min(len(coverage_bitmap), self._bitmap_size)):
                if coverage_bitmap[i] != 0:
                    self._global_bitmap[i] = coverage_bitmap[i]

            self._entries.append(input_data)
            return True

    def get_random(self) -> bytes:
        """Return a random input from the corpus. Thread-safe."""
        with self._lock:
            if not self._entries:
                return b"\x00" * 64  # default seed
            return random.choice(self._entries)

    # ── Persistence ──────────────────────────────────────────────────────────

    def save_to_disk(self) -> None:
        """Persist all corpus entries as files."""
        for i, entry in enumerate(self._entries):
            h = hashlib.sha256(entry).hexdigest()[:16]
            path = self._corpus_dir / f"id_{i:06d}_{h}"
            if not path.exists():
                path.write_bytes(entry)

    def load_from_disk(self) -> None:
        """Load corpus entries from disk."""
        self._entries.clear()
        if self._corpus_dir.exists():
            for f in sorted(self._corpus_dir.iterdir()):
                if f.is_file():
                    self._entries.append(f.read_bytes())

    # ── Stats ────────────────────────────────────────────────────────────────

    def coverage_percentage(self) -> float:
        """Percentage of bitmap entries hit. Thread-safe."""
        with self._lock:
            if self._bitmap_size == 0:
                return 0.0
            hit = sum(1 for b in self._global_bitmap if b != 0)
            return (hit / self._bitmap_size) * 100.0

    @property
    def size(self) -> int:
        """Number of inputs in the corpus. Thread-safe."""
        with self._lock:
            return len(self._entries)
