"""Writes instrumentation events to a rotating log file.

Level filtering
---------------
- ``"off"``      — nothing written (file is never opened)
- ``"minimal"``  — ExceptionEntryEvent only
- ``"standard"`` — ExceptionEntryEvent + TaskSwitchEvent + HeapOperationEvent
- ``"verbose"``  — all events

Log rotation
------------
After each write the file size is checked.  When it exceeds *max_size_bytes*
the current file is closed, renamed to ``<path>.<rotation_count>``, and a new
file is opened at the original path.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional


class TraceWriter:
    """Write instrumentation events to a levelled, rotating log file."""

    def __init__(
        self,
        log_path: Path,
        level: str = "standard",
        max_size_mb: int = 100,
    ) -> None:
        self.log_path = Path(log_path)
        self.level = level
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._file = None
        self._rotation_count = 0

        if level != "off":
            self._open()

    # ------------------------------------------------------------------
    # File management
    # ------------------------------------------------------------------

    def _open(self) -> None:
        """Open (or reopen after rotation) the log file for appending."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.log_path, "a", buffering=1)  # line-buffered

    def _check_rotation(self) -> None:
        """Rotate if the log file has grown beyond max_size_bytes."""
        try:
            if os.path.getsize(self.log_path) > self.max_size_bytes:
                self._rotate()
        except OSError:
            pass  # file disappeared between write and stat — harmless

    def _rotate(self) -> None:
        """Close the current file, rename it, and open a new one."""
        if self._file:
            self._file.close()
            self._file = None
        self._rotation_count += 1
        rotated = Path(f"{self.log_path}.{self._rotation_count}")
        try:
            self.log_path.rename(rotated)
        except OSError:
            pass  # If rename fails, continue writing to original path
        self._open()

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _should_write(self, event: object) -> bool:
        """Return True if *event* should be written at the current level."""
        from rtosploit.instrumentation.events import (
            ExceptionEntryEvent,
            TaskSwitchEvent,
            HeapOperationEvent,
        )

        if self.level == "verbose":
            return True
        if self.level == "minimal":
            return isinstance(event, ExceptionEntryEvent)
        if self.level == "standard":
            return isinstance(event, (ExceptionEntryEvent, TaskSwitchEvent, HeapOperationEvent))
        return False

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    def _format_event(self, event: object) -> str:
        """Format *event* as a single log line."""
        ts = f"{time.time():.3f}"
        event_type = getattr(event, "event_type", type(event).__name__)
        return f"[{ts}] {event_type}: {event!r}"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, event: object) -> None:
        """Write *event* to the log if it passes level filtering."""
        if self._file is None or self.level == "off":
            return
        if not self._should_write(event):
            return
        try:
            self._file.write(self._format_event(event) + "\n")
        except OSError:
            return
        self._check_rotation()

    def flush(self) -> None:
        """Flush the underlying file buffer."""
        if self._file:
            try:
                self._file.flush()
            except OSError:
                pass

    def close(self) -> None:
        """Flush and close the log file."""
        if self._file:
            try:
                self._file.flush()
                self._file.close()
            except OSError:
                pass
            finally:
                self._file = None

    def __del__(self) -> None:
        self.close()
