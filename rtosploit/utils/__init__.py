"""Shared utility functions: binary loading, disassembly, memory map, packing."""

from .binary import (
    BinaryFormat,
    FirmwareImage,
    MemorySection,
    detect_format,
    load_firmware,
    load_elf,
    load_ihex,
    load_raw,
    load_srec,
)
from .disasm import (
    Instruction,
    disassemble,
    disassemble_at,
    disassemble_function,
    disassemble_iter,
    find_instruction_pattern,
    find_prologue_pattern,
)
from .memory_map import (
    CortexMMemoryMap,
    MemoryRegion,
    RegionType,
    load_machine_memory_map,
)
from .packing import (
    align_down,
    align_up,
    hexdump,
    p16,
    p32,
    p64,
    p8,
    u16,
    u32,
    u64,
    u8,
)

__all__ = [
    "BinaryFormat", "FirmwareImage", "MemorySection",
    "detect_format", "load_firmware", "load_elf", "load_ihex", "load_raw", "load_srec",
    "Instruction", "disassemble", "disassemble_at", "disassemble_function",
    "disassemble_iter", "find_instruction_pattern", "find_prologue_pattern",
    "CortexMMemoryMap", "MemoryRegion", "RegionType", "load_machine_memory_map",
    "align_down", "align_up", "hexdump",
    "p16", "p32", "p64", "p8", "u16", "u32", "u64", "u8",
]
