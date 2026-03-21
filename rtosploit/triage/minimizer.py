"""Crash input minimizer — binary search reduction for QEMU-based crash reproduction."""

from __future__ import annotations

import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class CrashMinimizer:
    """Minimize crash-triggering inputs via binary search reduction.

    If a crash_check_fn is provided, it is called with candidate bytes
    and must return True if the crash still reproduces.  Without one,
    a simple binary reduction is performed (no verification).
    """

    def __init__(
        self,
        firmware_path: str,
        machine: str = "mps2-an385",
        timeout: int = 5,
    ) -> None:
        self.firmware_path = firmware_path
        self.machine = machine
        self.timeout = timeout

    def minimize(
        self,
        input_data: bytes,
        crash_check_fn: Optional[Callable[[bytes], bool]] = None,
    ) -> bytes:
        """Minimize *input_data* while preserving the crash.

        Returns the smallest input found (may be unchanged if already
        minimal).
        """
        if len(input_data) <= 1:
            return input_data

        best = input_data

        # Phase 1: binary search — halve repeatedly
        best = self._binary_halve(best, crash_check_fn)

        # Phase 2: byte-by-byte trimming from the end
        best = self._trim_tail(best, crash_check_fn)

        return best

    def minimize_file(
        self,
        input_path: str,
        output_path: str,
        crash_check_fn: Optional[Callable[[bytes], bool]] = None,
    ) -> int:
        """Minimize a crash input file and write the result.

        Returns the number of bytes saved (original_size - minimized_size).
        """
        with open(input_path, "rb") as fh:
            original = fh.read()

        minimized = self.minimize(original, crash_check_fn)

        with open(output_path, "wb") as fh:
            fh.write(minimized)

        saved = len(original) - len(minimized)
        logger.info(
            "Minimized %s: %d -> %d bytes (saved %d)",
            input_path,
            len(original),
            len(minimized),
            saved,
        )
        return saved

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _binary_halve(
        data: bytes,
        check_fn: Optional[Callable[[bytes], bool]],
    ) -> bytes:
        """Repeatedly halve data, keeping the smallest version that crashes."""
        best = data
        size = len(data)

        while size > 1:
            candidate_size = size // 2
            candidate = best[:candidate_size]

            if check_fn is not None:
                if check_fn(candidate):
                    best = candidate
                    size = candidate_size
                else:
                    # Cannot halve further — the smaller half doesn't crash
                    break
            else:
                # No verification — just halve once
                best = candidate
                break

        return best

    @staticmethod
    def _trim_tail(
        data: bytes,
        check_fn: Optional[Callable[[bytes], bool]],
    ) -> bytes:
        """Remove bytes one at a time from the end."""
        if check_fn is None:
            return data

        best = data
        i = len(best) - 1
        while i > 0:
            candidate = best[:i]
            if check_fn(candidate):
                best = candidate
                i = len(best) - 1
            else:
                i -= 1

        return best
