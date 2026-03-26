"""ARM Cortex-M stack unwinding for crash backtrace reconstruction."""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)


class MemoryReader(Protocol):
    """Protocol for reading memory (works with GDBClient or MemoryOps)."""

    def read_memory(self, address: int, size: int) -> bytes: ...


@dataclass
class StackFrame:
    """A single frame in the call stack."""

    address: int
    sp: int
    function: str = ""

    def __str__(self) -> str:
        if self.function:
            return f"0x{self.address:08x} <{self.function}> (sp=0x{self.sp:08x})"
        return f"0x{self.address:08x} (sp=0x{self.sp:08x})"


def _read_u32(reader: MemoryReader, address: int) -> int | None:
    """Read a little-endian 32-bit word, returning None on failure."""
    try:
        data = reader.read_memory(address, 4)
        if len(data) < 4:
            return None
        return struct.unpack("<I", data)[0]
    except Exception:
        return None


def _is_in_range(value: int, range_tuple: tuple[int, int]) -> bool:
    return range_tuple[0] <= value <= range_tuple[1]


def _resolve_symbol(
    address: int, reverse_symbols: dict[int, str] | None
) -> str:
    """Find the closest symbol at or before address."""
    if not reverse_symbols:
        return ""
    best_addr = -1
    best_name = ""
    for sym_addr, sym_name in reverse_symbols.items():
        if sym_addr <= address and sym_addr > best_addr:
            best_addr = sym_addr
            best_name = sym_name
    return best_name


def _build_reverse_symbols(
    symbols: dict[str, int] | None,
) -> dict[int, str] | None:
    """Invert name->address to address->name."""
    if not symbols:
        return None
    return {addr: name for name, addr in symbols.items()}


def _unwind_fp_chain(
    reader: MemoryReader,
    registers: dict[str, int],
    reverse_symbols: dict[int, str] | None,
    max_frames: int,
    code_range: tuple[int, int],
    stack_range: tuple[int, int],
) -> list[StackFrame]:
    """Unwind using the r7 frame pointer chain."""
    frames: list[StackFrame] = []

    pc = registers.get("pc")
    if pc is None:
        return frames

    real_pc = pc & ~1
    frames.append(
        StackFrame(
            address=real_pc,
            sp=registers.get("sp", 0),
            function=_resolve_symbol(real_pc, reverse_symbols),
        )
    )

    lr = registers.get("lr")
    if lr is not None and _is_in_range(lr & ~1, code_range):
        real_lr = lr & ~1
        frames.append(
            StackFrame(
                address=real_lr,
                sp=registers.get("sp", 0),
                function=_resolve_symbol(real_lr, reverse_symbols),
            )
        )

    fp = registers.get("r7")
    if fp is None or not _is_in_range(fp, stack_range):
        return frames

    seen_fps: set[int] = set()
    current_fp = fp

    while len(frames) < max_frames:
        if current_fp in seen_fps:
            break
        seen_fps.add(current_fp)

        if not _is_in_range(current_fp, stack_range):
            break
        if current_fp % 4 != 0:
            break

        saved_fp = _read_u32(reader, current_fp)
        saved_lr = _read_u32(reader, current_fp + 4)

        if saved_fp is None or saved_lr is None:
            break

        real_addr = saved_lr & ~1
        if not _is_in_range(real_addr, code_range):
            break

        frames.append(
            StackFrame(
                address=real_addr,
                sp=current_fp,
                function=_resolve_symbol(real_addr, reverse_symbols),
            )
        )

        if saved_fp == 0 or saved_fp == current_fp:
            break
        if not _is_in_range(saved_fp, stack_range):
            break

        current_fp = saved_fp

    return frames


def _unwind_stack_scan(
    reader: MemoryReader,
    registers: dict[str, int],
    reverse_symbols: dict[int, str] | None,
    max_frames: int,
    code_range: tuple[int, int],
    stack_range: tuple[int, int],
) -> list[StackFrame]:
    """Scan stack for return addresses as a fallback strategy."""
    frames: list[StackFrame] = []

    pc = registers.get("pc")
    sp = registers.get("sp")
    if pc is None or sp is None:
        return frames

    real_pc = pc & ~1
    frames.append(
        StackFrame(
            address=real_pc,
            sp=sp,
            function=_resolve_symbol(real_pc, reverse_symbols),
        )
    )

    lr = registers.get("lr")
    if lr is not None and _is_in_range(lr & ~1, code_range):
        real_lr = lr & ~1
        frames.append(
            StackFrame(
                address=real_lr,
                sp=sp,
                function=_resolve_symbol(real_lr, reverse_symbols),
            )
        )

    if not _is_in_range(sp, stack_range):
        return frames

    scan_limit = min(sp + 1024, stack_range[1])
    current = sp
    prev_addr: int | None = None

    while current < scan_limit and len(frames) < max_frames:
        word = _read_u32(reader, current)
        if word is not None and _is_in_range(word & ~1, code_range):
            real_addr = word & ~1
            if real_addr != prev_addr:
                already_have = any(f.address == real_addr for f in frames)
                if not already_have:
                    frames.append(
                        StackFrame(
                            address=real_addr,
                            sp=current,
                            function=_resolve_symbol(
                                real_addr, reverse_symbols
                            ),
                        )
                    )
                    prev_addr = real_addr
        current += 4

    return frames


def unwind_stack(
    reader: MemoryReader,
    registers: dict[str, int],
    symbols: dict[str, int] | None = None,
    max_frames: int = 32,
    code_range: tuple[int, int] = (0x08000000, 0x08FFFFFF),
    stack_range: tuple[int, int] = (0x20000000, 0x2007FFFF),
) -> list[StackFrame]:
    """Walk the stack and return a list of StackFrames.

    Uses two strategies:
    1. Frame pointer chain: Follow r7 (Thumb) as frame pointer
    2. Stack scanning: Scan stack for return addresses in code range

    Args:
        reader: Object with read_memory(address, size) -> bytes
        registers: Dict with at least "pc", "lr", "sp", "r7" keys
        symbols: Optional symbol table (name -> address) for resolution
        max_frames: Maximum frames to unwind
        code_range: (start, end) tuple for valid code addresses
        stack_range: (start, end) tuple for valid stack addresses

    Returns:
        List of StackFrame from most recent to oldest
    """
    if not registers:
        return []

    reverse_symbols = _build_reverse_symbols(symbols)

    frames = _unwind_fp_chain(
        reader, registers, reverse_symbols, max_frames, code_range, stack_range
    )

    if len(frames) < 2:
        logger.debug(
            "Frame pointer chain yielded %d frames, falling back to stack scan",
            len(frames),
        )
        frames = _unwind_stack_scan(
            reader,
            registers,
            reverse_symbols,
            max_frames,
            code_range,
            stack_range,
        )

    return frames


def format_backtrace(frames: list[StackFrame]) -> str:
    """Format backtrace as a human-readable string."""
    lines = []
    for i, frame in enumerate(frames):
        lines.append(f"  #{i}: {frame}")
    return "\n".join(lines) if lines else "  (no backtrace available)"
