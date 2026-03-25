"""Peripheral Input Playback (PIP) handler for model-free MMIO fuzzing.

Implements Algorithm 1 from the Ember-IO paper: each MMIO read consumes
2 bits from the fuzz input to decide whether to replay the last-seen value
or read a fresh value from the input stream. This enables efficient fuzzing
of firmware that polls status registers repeatedly, reducing the input
bytes needed by up to 8x compared to naive byte-per-read approaches.

Based on: Farrelly, Chesser, Ranasinghe. "Ember-IO: Effective Firmware
Fuzzing with Model-Free Memory Mapped IO." ASIA CCS 2023.
https://doi.org/10.1145/3579856.3582840
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from rtosploit.fuzzing.fuzz_input import FuzzInputStream

logger = logging.getLogger(__name__)

# 2-bit constant indicating "replay last value" (binary 11)
REPEAT_CONST = 0b11


class PeripheralMemoryStore:
    """Per-register last-value tracker.

    Stores the most recent value seen for each MMIO address, whether
    from a firmware write or a fuzz-input-derived read. Used by PIP
    to replay values when the replay bit pair is 0b11.
    """

    def __init__(self) -> None:
        self._values: dict[int, int] = {}
        self._access_counts: dict[int, int] = {}

    def get(self, address: int) -> int:
        """Get the last value stored for an address. Returns 0 if never accessed."""
        return self._values.get(address, 0)

    def set(self, address: int, value: int) -> None:
        """Store a value for an address (from firmware write or new fuzz value)."""
        self._values[address] = value
        self._access_counts[address] = self._access_counts.get(address, 0) + 1

    def has(self, address: int) -> bool:
        """Check if an address has ever been accessed (has a stored value)."""
        return address in self._values

    def clear(self) -> None:
        """Clear all stored values for a new execution."""
        self._values.clear()
        self._access_counts.clear()

    def addresses(self) -> list[int]:
        """Return sorted list of all accessed addresses."""
        return sorted(self._values.keys())

    def access_count(self, address: int) -> int:
        """Return total access count for an address."""
        return self._access_counts.get(address, 0)


class ReplayBitsBuffer:
    """Per-register 32-bit replay bitmask manager.

    Each 32-bit word controls 16 MMIO reads (2 bits per read).
    Bottom 2 bits are consumed first. When all 16 reads are consumed,
    a new 32-bit word is read from the fuzz input stream.

    Bit pair semantics:
        0b11 (REPEAT_CONST) -> replay last value from PeripheralMemoryStore
        anything else       -> read fresh value from fuzz input
    """

    def __init__(self) -> None:
        self._buffers: dict[int, int] = {}
        self._remaining: dict[int, int] = {}

    def needs_refill(self, address: int) -> bool:
        """Check if a register's replay bits are exhausted."""
        return address not in self._remaining or self._remaining[address] <= 0

    def refill(self, address: int, bits_word: int) -> None:
        """Load a new 32-bit word of replay bits for a register address."""
        self._buffers[address] = bits_word
        self._remaining[address] = 16  # 32 bits / 2 bits per read

    def should_replay(self, address: int, fuzz_input: FuzzInputStream) -> bool:
        """Determine whether the next read at this address should replay.

        If no buffer exists for this address or the buffer is exhausted,
        reads a new 32-bit word from the fuzz input stream. Then pops the
        bottom 2 bits and returns True if they equal REPEAT_CONST (0b11).

        Args:
            address: MMIO register address.
            fuzz_input: Fuzz input stream to read replay bits from.

        Returns:
            True if the next read should replay the last-seen value.

        Raises:
            InputExhausted: If the fuzz input stream runs out.
        """
        if self.needs_refill(address):
            bits_word = fuzz_input.read_u32()
            self.refill(address, bits_word)

        # Consume bottom 2 bits
        bits = self._buffers[address] & 0x3
        self._buffers[address] >>= 2
        self._remaining[address] -= 1

        return bits == REPEAT_CONST

    def reset(self) -> None:
        """Clear all replay buffers for a new execution."""
        self._buffers.clear()
        self._remaining.clear()


@dataclass
class PIPStats:
    """Statistics for PIP handler diagnostics."""

    total_reads: int = 0
    total_writes: int = 0
    replay_count: int = 0
    new_value_count: int = 0

    @property
    def replay_percentage(self) -> float:
        """Percentage of reads that were replays."""
        return (self.replay_count / max(self.total_reads, 1)) * 100.0

    def to_dict(self) -> dict[str, int | float]:
        """Serialize stats to dict for reporting."""
        return {
            "total_reads": self.total_reads,
            "total_writes": self.total_writes,
            "replay_count": self.replay_count,
            "new_value_count": self.new_value_count,
            "replay_percentage": self.replay_percentage,
        }

    def reset(self) -> None:
        """Reset all stats counters to zero."""
        self.total_reads = 0
        self.total_writes = 0
        self.replay_count = 0
        self.new_value_count = 0


class PIPHandler:
    """Core PIP handler implementing Ember-IO Algorithm 1.

    Manages the peripheral memory store, replay bits buffer, and fuzz
    input stream to provide model-free MMIO handling during firmware
    fuzzing.

    Algorithm:
        1. On MMIO read: read 2 bits from input (via ReplayBitsBuffer)
        2. If bits == 0b11 (REPEAT_CONST): return last value from store
        3. Else: read register-width bytes from input, store, return

    On MMIO write: store the written value so subsequent replays
    return the firmware-written value (important for control registers).
    """

    def __init__(self, fuzz_input: FuzzInputStream) -> None:
        """Initialize PIP handler with a fuzz input stream.

        Args:
            fuzz_input: The fuzz input stream to consume bytes from.
        """
        self._store = PeripheralMemoryStore()
        self._replay = ReplayBitsBuffer()
        self._input = fuzz_input
        self._stats = PIPStats()

    def mmio_read(self, address: int, size: int) -> int:
        """Handle an MMIO read using the PIP algorithm.

        Implements Algorithm 1 from the Ember-IO paper:
        1. Ensure address has a stored value (default 0)
        2. Read 2 bits from replay buffer (refilling from input if needed)
        3. If replay: return stored value
        4. Else: read size bytes from input, store, return

        Args:
            address: MMIO register address.
            size: Read width in bytes (1, 2, or 4).

        Returns:
            The register value (replayed or fresh from input).

        Raises:
            InputExhausted: If the fuzz input stream is exhausted.
        """
        # Ensure address has a stored value (default 0)
        if not self._store.has(address):
            self._store.set(address, 0)

        # Determine replay vs new value via 2-bit check
        replay = self._replay.should_replay(address, self._input)

        if replay:
            value = self._store.get(address)
            self._stats.replay_count += 1
        else:
            value = self._input.read_value(size)
            self._store.set(address, value)
            self._stats.new_value_count += 1

        self._stats.total_reads += 1
        return value

    def mmio_write(self, address: int, value: int, size: int) -> None:
        """Handle an MMIO write by storing value for future replays.

        Args:
            address: MMIO register address.
            value: Value written by firmware.
            size: Write width in bytes (unused, stored as-is).
        """
        self._store.set(address, value)
        self._stats.total_writes += 1

    @property
    def stats(self) -> PIPStats:
        """Access PIP handler statistics."""
        return self._stats

    @property
    def store(self) -> PeripheralMemoryStore:
        """Access the peripheral memory store."""
        return self._store

    @property
    def remaining_input_bytes(self) -> int:
        """Number of bytes remaining in the fuzz input stream."""
        return self._input.remaining

    def reset(self, fuzz_input: FuzzInputStream) -> None:
        """Reset for a new fuzz iteration.

        Clears replay buffers and stats. The memory store is preserved
        so firmware-written configuration values (control registers)
        carry over. Note: if a new PIPHandler is created per iteration
        instead of reusing, the store will not persist.

        Args:
            fuzz_input: New fuzz input stream for the next iteration.
        """
        self._input = fuzz_input
        self._replay.reset()
        self._stats.reset()
