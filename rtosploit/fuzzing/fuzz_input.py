"""Fuzz input stream for firmware fuzzing.

Provides a byte-stream abstraction over AFL++/libFuzzer-generated input data.
Used by the PIP (Peripheral Input Playback) handler to consume fuzz bytes
for MMIO register values and replay control bits.

Based on: Farrelly, Chesser, Ranasinghe. "Ember-IO: Effective Firmware
Fuzzing with Model-Free Memory Mapped IO." ASIA CCS 2023.
https://doi.org/10.1145/3579856.3582840
"""

from __future__ import annotations

import logging
import struct

logger = logging.getLogger(__name__)


class InputExhausted(Exception):
    """Raised when the fuzz input stream is fully consumed.

    This signals the emulation engine to terminate the current execution,
    matching Ember-IO's termination condition 1: "Peripheral is read and
    input buffer is empty."
    """

    pass


class FuzzInputStream:
    """Byte stream over fuzzer-generated input with position tracking.

    Provides typed reads (u8, u16, u32) in little-endian format and
    tracks consumption statistics for diagnostics.
    """

    def __init__(self, data: bytes) -> None:
        """Initialize with a byte buffer.

        Args:
            data: Raw bytes from the fuzzer (e.g., AFL++ test case).
        """
        self._data = data
        self._pos = 0
        self._total_bytes_consumed = 0
        self._total_reads = 0

    @property
    def is_exhausted(self) -> bool:
        """True when all input has been consumed."""
        return self._pos >= len(self._data)

    @property
    def remaining(self) -> int:
        """Number of bytes remaining in the buffer."""
        return max(0, len(self._data) - self._pos)

    def read_bytes(self, count: int) -> bytes:
        """Read N raw bytes from the input stream.

        Args:
            count: Number of bytes to read.

        Returns:
            The requested bytes.

        Raises:
            InputExhausted: If not enough bytes remain.
        """
        if self._pos + count > len(self._data):
            raise InputExhausted(
                f"Need {count} bytes but only {self.remaining} remain"
            )
        result = self._data[self._pos : self._pos + count]
        self._pos += count
        self._total_bytes_consumed += count
        self._total_reads += 1
        return result

    def read_u8(self) -> int:
        """Read a single unsigned byte."""
        return self.read_bytes(1)[0]

    def read_u16(self) -> int:
        """Read a 16-bit little-endian unsigned integer."""
        return struct.unpack_from("<H", self.read_bytes(2))[0]

    def read_u32(self) -> int:
        """Read a 32-bit little-endian unsigned integer."""
        return struct.unpack_from("<I", self.read_bytes(4))[0]

    def read_value(self, size: int) -> int:
        """Read a value of the given byte width (1, 2, or 4).

        Dispatches to read_u8, read_u16, or read_u32 based on size.

        Args:
            size: Register width in bytes (1, 2, or 4).

        Returns:
            The value read from the stream.

        Raises:
            ValueError: If size is not 1, 2, or 4.
            InputExhausted: If not enough bytes remain.
        """
        if size == 1:
            return self.read_u8()
        if size == 2:
            return self.read_u16()
        if size == 4:
            return self.read_u32()
        raise ValueError(f"Unsupported read size: {size}")

    @property
    def stats(self) -> dict[str, int]:
        """Diagnostic statistics about stream consumption."""
        return {
            "total_size": len(self._data),
            "position": self._pos,
            "remaining": self.remaining,
            "bytes_consumed": self._total_bytes_consumed,
            "read_count": self._total_reads,
        }

    def reset(self) -> None:
        """Rewind stream to the beginning for re-use with the same data."""
        self._pos = 0
        self._total_bytes_consumed = 0
        self._total_reads = 0
