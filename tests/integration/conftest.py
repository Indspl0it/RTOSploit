"""Shared fixtures for QEMU integration tests."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest


QEMU_BINARY = "qemu-system-arm"


@pytest.fixture
def qemu_available() -> bool:
    """Return True if qemu-system-arm is found on PATH."""
    return shutil.which(QEMU_BINARY) is not None


@pytest.fixture
def firmware_path(tmp_path: Path) -> str:
    """Create a minimal ARM Cortex-M firmware binary and return its path.

    The binary contains a valid vector table (initial SP + reset handler)
    followed by a Thumb infinite loop at the reset address so QEMU has
    something to execute without immediately faulting.

    Skips if the file cannot be created for any reason.
    """
    # ARM Cortex-M vector table layout (little-endian):
    #   0x00: Initial SP  = 0x20001000
    #   0x04: Reset vector = 0x08000041 (Thumb bit set)
    # Pad remaining vectors with the same reset address.
    sp_init = (0x20001000).to_bytes(4, "little")
    reset_addr = (0x08000041).to_bytes(4, "little")  # Thumb entry

    # 16 vectors (64 bytes)
    vectors = sp_init + reset_addr + (reset_addr * 14)

    # Thumb infinite loop at offset 0x40 (address 0x08000040):
    #   b.n .  =>  0xe7fe
    code = b"\xfe\xe7"

    firmware = vectors + code
    # Pad to 256 bytes for a realistic minimum image
    firmware += b"\x00" * (256 - len(firmware))

    fw_file = tmp_path / "test_firmware.bin"
    fw_file.write_bytes(firmware)
    return str(fw_file)
