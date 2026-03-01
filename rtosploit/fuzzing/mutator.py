"""AFL-style byte-level input mutator for firmware fuzzing."""

from __future__ import annotations

import random
import struct
from typing import Optional


# Interesting values for injection (common boundary/edge cases)
INTERESTING_8 = [0, 1, 0x7F, 0x80, 0xFF]
INTERESTING_16 = [0, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF]
INTERESTING_32 = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]


class Mutator:
    """Pure-Python AFL-style mutator with reproducible randomness."""

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    # ------------------------------------------------------------------
    # Strategies
    # ------------------------------------------------------------------

    def bit_flip(self, data: bytes, num_bits: int = 1) -> bytes:
        """Flip *num_bits* random bits."""
        if not data:
            return b""
        buf = bytearray(data)
        total_bits = len(buf) * 8
        for _ in range(num_bits):
            bit_idx = self._rng.randint(0, total_bits - 1)
            byte_idx, bit_off = divmod(bit_idx, 8)
            buf[byte_idx] ^= 1 << bit_off
        return bytes(buf)

    def byte_flip(self, data: bytes, num_bytes: int = 1) -> bytes:
        """Flip *num_bytes* random bytes (XOR with 0xFF)."""
        if not data:
            return b""
        buf = bytearray(data)
        for _ in range(num_bytes):
            idx = self._rng.randint(0, len(buf) - 1)
            buf[idx] ^= 0xFF
        return bytes(buf)

    def arithmetic(self, data: bytes) -> bytes:
        """Add or subtract a small value (1..35) at a random byte position."""
        if not data:
            return b""
        buf = bytearray(data)
        idx = self._rng.randint(0, len(buf) - 1)
        delta = self._rng.randint(1, 35)
        if self._rng.randint(0, 1):
            buf[idx] = (buf[idx] + delta) & 0xFF
        else:
            buf[idx] = (buf[idx] - delta) & 0xFF
        return bytes(buf)

    def interesting_values(self, data: bytes) -> bytes:
        """Replace bytes at a random position with an interesting value."""
        if not data:
            return b""
        buf = bytearray(data)
        length = len(buf)

        # Decide width based on available room
        widths = [1]
        if length >= 2:
            widths.append(2)
        if length >= 4:
            widths.append(4)

        width = self._rng.choice(widths)

        if width == 1:
            idx = self._rng.randint(0, length - 1)
            val = self._rng.choice(INTERESTING_8)
            buf[idx] = val & 0xFF
        elif width == 2:
            idx = self._rng.randint(0, length - 2)
            val = self._rng.choice(INTERESTING_16)
            endian = self._rng.choice(("<H", ">H"))
            struct.pack_into(endian, buf, idx, val & 0xFFFF)
        else:  # width == 4
            idx = self._rng.randint(0, length - 4)
            val = self._rng.choice(INTERESTING_32)
            endian = self._rng.choice(("<I", ">I"))
            struct.pack_into(endian, buf, idx, val & 0xFFFFFFFF)

        return bytes(buf)

    def havoc(self, data: bytes, rounds: int = 16) -> bytes:
        """Chain *rounds* random mutations."""
        if not data:
            return b""
        buf = data
        strategies = [
            self.bit_flip,
            self.byte_flip,
            self.arithmetic,
            self.interesting_values,
        ]
        for _ in range(rounds):
            fn = self._rng.choice(strategies)
            buf = fn(buf)
        return buf

    def splice(self, data1: bytes, data2: bytes) -> bytes:
        """Splice two inputs at a random midpoint."""
        if not data1 and not data2:
            return b""
        if not data1:
            return bytes(data2)
        if not data2:
            return bytes(data1)
        mid1 = self._rng.randint(1, len(data1))
        mid2 = self._rng.randint(0, len(data2) - 1)
        return bytes(data1[:mid1]) + bytes(data2[mid2:])

    def mutate(self, data: bytes) -> bytes:
        """Pick a random strategy and apply it."""
        if not data:
            return b""
        strategies = [
            self.bit_flip,
            self.byte_flip,
            self.arithmetic,
            self.interesting_values,
            lambda d: self.havoc(d, rounds=self._rng.randint(2, 8)),
        ]
        fn = self._rng.choice(strategies)
        return fn(data)
