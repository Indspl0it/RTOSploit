"""Session state for interactive mode."""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any, Optional


def normalize_path(raw: str) -> Path:
    """Normalize a user-supplied path, converting Windows paths under WSL.

    Handles:
        C:\\Users\\foo\\bar.bin  -> /mnt/c/Users/foo/bar.bin  (WSL)
        C:/Users/foo/bar.bin   -> /mnt/c/Users/foo/bar.bin  (WSL)
        /home/user/bar.bin     -> /home/user/bar.bin         (passthrough)
        ~/bar.bin              -> expanded home path
    """
    stripped = raw.strip().strip('"').strip("'")

    # Detect Windows-style drive letter (e.g. C:\... or D:/...)
    win_drive = re.match(r"^([A-Za-z]):[/\\]", stripped)
    if win_drive:
        # Check if we're running under WSL
        is_wsl = "microsoft" in platform.uname().release.lower()
        if is_wsl:
            drive = win_drive.group(1).lower()
            rest = stripped[3:].replace("\\", "/")
            return Path(f"/mnt/{drive}/{rest}").resolve()
        else:
            # Native Windows — use PureWindowsPath then convert
            return Path(PureWindowsPath(stripped)).resolve()

    return Path(stripped).expanduser().resolve()


@dataclass
class FirmwareContext:
    """Loaded firmware with analysis results."""
    path: Path
    image: Any  # FirmwareImage
    fingerprint: Optional[Any] = None  # RTOSFingerprint
    machine: Optional[str] = None
    machine_config: Optional[Any] = None  # MachineConfig
    qemu: Optional[Any] = None  # QEMUInstance

    @property
    def size_kb(self) -> float:
        return self.path.stat().st_size / 1024

    @property
    def rtos_name(self) -> str:
        if self.fingerprint is None:
            return "Unknown"
        return self.fingerprint.rtos_type.capitalize()

    @property
    def rtos_version(self) -> str:
        if self.fingerprint is None or self.fingerprint.version is None:
            return ""
        return self.fingerprint.version

    @property
    def arch_name(self) -> str:
        return getattr(self.image, "architecture", "unknown")


@dataclass
class InteractiveSession:
    """Top-level session state for interactive mode."""
    firmware: Optional[FirmwareContext] = None
    output_dir: Path = field(default_factory=lambda: Path("./results"))
    debug: bool = False
    history: list[str] = field(default_factory=list)

    @property
    def has_firmware(self) -> bool:
        return self.firmware is not None

    @property
    def has_qemu(self) -> bool:
        return self.has_firmware and self.firmware.qemu is not None
