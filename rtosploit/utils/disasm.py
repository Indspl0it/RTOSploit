"""Capstone-based disassembly utilities for ARM Thumb2 and RISC-V."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

import capstone

from .binary import FirmwareImage


@dataclass
class Instruction:
    address: int
    mnemonic: str
    op_str: str
    bytes: bytes
    size: int

    def __str__(self) -> str:
        return f"0x{self.address:08x}:  {self.bytes.hex():<12}  {self.mnemonic} {self.op_str}"


ARCH_MAP = {
    "armv7m": (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
    "armv8m": (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
    "riscv32": (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV32),
}


def _make_cs(arch: str) -> capstone.Cs:
    if arch not in ARCH_MAP:
        raise ValueError(f"Unsupported architecture: {arch!r}. Choose from: {list(ARCH_MAP)}")
    cs_arch, cs_mode = ARCH_MAP[arch]
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    return md


def disassemble(
    data: bytes,
    base_address: int,
    arch: str = "armv7m",
    max_insns: int = 0,
) -> list[Instruction]:
    """Disassemble bytes starting at base_address. max_insns=0 means unlimited."""
    md = _make_cs(arch)
    results = []
    for insn in md.disasm(data, base_address):
        results.append(Instruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes=bytes(insn.bytes),
            size=insn.size,
        ))
        if max_insns and len(results) >= max_insns:
            break
    return results


def disassemble_iter(
    data: bytes,
    base_address: int,
    arch: str = "armv7m",
) -> Iterator[Instruction]:
    """Iterator-based disassembly (memory-efficient for large binaries)."""
    md = _make_cs(arch)
    for insn in md.disasm(data, base_address):
        yield Instruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes=bytes(insn.bytes),
            size=insn.size,
        )


def disassemble_at(
    firmware: FirmwareImage,
    address: int,
    max_insns: int = 64,
    arch: str = "armv7m",
) -> list[Instruction]:
    """Disassemble from a specific address within a FirmwareImage."""
    # ARM Thumb addresses have LSB set; strip it for actual address
    actual_addr = address & ~1 if arch in ("armv7m", "armv8m") else address
    offset = actual_addr - firmware.base_address
    if offset < 0 or offset >= len(firmware.data):
        raise ValueError(f"Address 0x{address:08x} not in firmware image")
    return disassemble(firmware.data[offset:], actual_addr, arch, max_insns)


_FUNCTION_RETURN_MNEMONICS = frozenset(["pop", "bx", "ldmia", "ldmdb"])
_FUNCTION_RETURN_OPS = frozenset(["pc", "lr"])


def _is_function_return(insn: Instruction) -> bool:
    """Heuristic: detect function-ending instructions."""
    m = insn.mnemonic.lower()
    if m == "bx" and "lr" in insn.op_str.lower():
        return True
    if m in ("pop", "ldmia", "ldmdb") and "pc" in insn.op_str.lower():
        return True
    return False


def disassemble_function(
    firmware: FirmwareImage,
    address: int,
    arch: str = "armv7m",
    max_insns: int = 512,
) -> list[Instruction]:
    """Disassemble from address until function return or max_insns reached."""
    result = []
    for insn in disassemble_at(firmware, address, max_insns, arch):
        result.append(insn)
        if _is_function_return(insn):
            break
    return result


# ARM Thumb2 function prologue byte patterns
_THUMB2_PUSH_LR = bytes([0x10, 0xB5])   # PUSH {R4, LR}  — common 2-byte form
_THUMB2_PUSH_LR2 = bytes([0xF0, 0xB5])  # PUSH {R4-R7, LR}
_THUMB2_PUSH_ALL = bytes([0xFF, 0xB5])  # PUSH {R0-R7, LR}


def find_prologue_pattern(firmware: FirmwareImage, arch: str = "armv7m") -> list[int]:
    """Scan binary for function prologue patterns. Returns list of start addresses."""
    if arch not in ("armv7m", "armv8m"):
        return []

    data = firmware.data
    base = firmware.base_address
    addresses = []

    # Scan for PUSH {..., LR} patterns (little-endian Thumb2)
    # Pattern: any byte 0x00-0xFF followed by 0xB5 (PUSH with LR bit set)
    i = 0
    while i < len(data) - 1:
        if data[i + 1] == 0xB5:  # PUSH with LR
            # Verify it's aligned and preceded by reasonable code
            addr = base + i
            if addr % 2 == 0:  # Thumb instructions are 2-byte aligned
                addresses.append(addr)
            i += 2
        else:
            i += 2  # Step by 2 (Thumb minimum instruction size)

    return addresses


def find_instruction_pattern(
    firmware: FirmwareImage,
    pattern_bytes: bytes,
    mask_bytes: bytes | None = None,
) -> list[int]:
    """Search for a byte pattern (with optional mask) across the firmware image."""
    data = firmware.data
    base = firmware.base_address
    addresses = []
    plen = len(pattern_bytes)

    if mask_bytes is None:
        mask_bytes = b"\xff" * plen

    for i in range(len(data) - plen + 1):
        match = all(
            (data[i + j] & mask_bytes[j]) == (pattern_bytes[j] & mask_bytes[j])
            for j in range(plen)
        )
        if match:
            addresses.append(base + i)

    return addresses
