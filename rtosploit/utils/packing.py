"""Struct packing utilities — pwntools-compatible helpers for embedded targets."""

from __future__ import annotations

import struct


def p8(value: int) -> bytes:
    """Pack as 8-bit unsigned little-endian."""
    return struct.pack("<B", value & 0xFF)


def u8(data: bytes, offset: int = 0) -> int:
    """Unpack 8-bit unsigned."""
    return struct.unpack_from("<B", data, offset)[0]


def p16(value: int) -> bytes:
    """Pack as 16-bit unsigned little-endian."""
    return struct.pack("<H", value & 0xFFFF)


def u16(data: bytes, offset: int = 0) -> int:
    """Unpack 16-bit unsigned little-endian."""
    return struct.unpack_from("<H", data, offset)[0]


def p32(value: int) -> bytes:
    """Pack as 32-bit unsigned little-endian."""
    return struct.pack("<I", value & 0xFFFFFFFF)


def u32(data: bytes, offset: int = 0) -> int:
    """Unpack 32-bit unsigned little-endian."""
    return struct.unpack_from("<I", data, offset)[0]


def p64(value: int) -> bytes:
    """Pack as 64-bit unsigned little-endian."""
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def u64(data: bytes, offset: int = 0) -> int:
    """Unpack 64-bit unsigned little-endian."""
    return struct.unpack_from("<Q", data, offset)[0]


def align_up(value: int, alignment: int) -> int:
    """Round value up to next multiple of alignment."""
    if alignment == 0:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def align_down(value: int, alignment: int) -> int:
    """Round value down to previous multiple of alignment."""
    if alignment == 0:
        return value
    return value & ~(alignment - 1)


def hexdump(data: bytes, base_address: int = 0, width: int = 16) -> str:
    """Format bytes as a hex dump with ASCII sidebar."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        addr = base_address + i
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        # Pad hex part if chunk is short
        hex_part = hex_part.ljust(width * 3 - 1)
        lines.append(f"0x{addr:08x}:  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)
