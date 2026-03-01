"""Binary firmware loading — ELF, Intel HEX, Motorola S-Record, and raw formats."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from elftools.elf.elffile import ELFFile


class BinaryFormat(Enum):
    ELF = auto()
    IHEX = auto()
    SREC = auto()
    RAW = auto()


@dataclass
class MemorySection:
    name: str
    address: int
    data: bytes
    size: int
    permissions: str  # e.g. "rx", "rwx", "rw"


@dataclass
class FirmwareImage:
    """Loaded firmware image with metadata."""
    data: bytes
    base_address: int
    entry_point: int
    format: BinaryFormat
    sections: list[MemorySection] = field(default_factory=list)
    symbols: dict[str, int] = field(default_factory=dict)
    path: Path = field(default_factory=lambda: Path("."))
    architecture: str = "unknown"  # "armv7m" | "armv8m" | "riscv32" | "unknown"

    def read_word(self, address: int) -> int:
        """Read a 4-byte little-endian word at the given address."""
        offset = address - self.base_address
        if offset < 0 or offset + 4 > len(self.data):
            raise ValueError(f"Address 0x{address:08x} out of range for firmware image")
        return struct.unpack_from("<I", self.data, offset)[0]

    def read_bytes(self, address: int, size: int) -> bytes:
        """Read arbitrary bytes at the given address."""
        offset = address - self.base_address
        if offset < 0 or offset + size > len(self.data):
            raise ValueError(
                f"Address range 0x{address:08x}+{size} out of range for firmware image"
            )
        return self.data[offset : offset + size]

    def get_vector_table(self) -> dict[str, int]:
        """Read the Cortex-M vector table from the start of the image."""
        VECTOR_NAMES = [
            "initial_sp",
            "reset",
            "nmi",
            "hardfault",
            "memmanage",
            "busfault",
            "usagefault",
            "reserved_7",
            "reserved_8",
            "reserved_9",
            "reserved_10",
            "svc",
            "debugmon",
            "reserved_13",
            "pendsv",
            "systick",
        ]
        table = {}
        base = self.base_address
        for i, name in enumerate(VECTOR_NAMES):
            try:
                value = self.read_word(base + i * 4)
                table[name] = value
            except ValueError:
                break
        return table


def _detect_elf_architecture(elf: ELFFile) -> str:
    """Detect architecture from ELF headers and attributes."""
    from elftools.elf.sections import ARMAttributesSection

    _ELF_MACHINE_TO_ARCH = {
        40:  "arm",       # EM_ARM — refine via attributes
        183: "aarch64",   # EM_AARCH64
        243: "riscv32",   # EM_RISCV — refine via EI_CLASS
        94:  "xtensa",    # EM_XTENSA
        8:   "mips",      # EM_MIPS
        83:  "avr",       # EM_AVR
        105: "msp430",    # EM_MSP430
        20:  "ppc",       # EM_PPC
    }

    e_machine = elf.header.e_machine
    # Handle string enum values from pyelftools
    if isinstance(e_machine, str):
        _NAME_TO_NUM = {
            "EM_ARM": 40, "EM_AARCH64": 183, "EM_RISCV": 243,
            "EM_XTENSA": 94, "EM_MIPS": 8, "EM_AVR": 83,
            "EM_MSP430": 105, "EM_PPC": 20,
        }
        e_machine = _NAME_TO_NUM.get(e_machine, -1)

    arch = _ELF_MACHINE_TO_ARCH.get(e_machine, "unknown")

    # Layer 2: ARM build attributes for precise Cortex-M/A/R detection
    if arch == "arm":
        for section in elf.iter_sections():
            if isinstance(section, ARMAttributesSection):
                for subsec in section.subsections:
                    for subsubsec in subsec.subsubsections:
                        profile = None
                        cpu_name = None
                        for attr in subsubsec.iter_attributes():
                            if attr.tag == "TAG_CPU_ARCH_PROFILE":
                                profile = attr.value
                            elif attr.tag == "TAG_CPU_NAME":
                                cpu_name = attr.value
                        if profile == 0x4D or (isinstance(profile, str) and profile == "M"):
                            # M-profile: check for v8-M cores
                            if cpu_name and any(v8m in cpu_name for v8m in ("M33", "M23", "M55", "M85")):
                                return "armv8m"
                            return "armv7m"
                        elif profile == 0x41 or (isinstance(profile, str) and profile == "A"):
                            return "arm"
                        elif profile == 0x52 or (isinstance(profile, str) and profile == "R"):
                            return "arm"
        # No attributes section — default to armv7m for EM_ARM
        return "armv7m"

    # Layer 3: RISC-V refinement
    if arch == "riscv32":
        ei_class = elf.header.e_ident.EI_CLASS
        if isinstance(ei_class, str):
            if ei_class == "ELFCLASS64":
                return "riscv64"
        elif ei_class == 2:  # ELFCLASS64
            return "riscv64"
        # Check for RVE (embedded) via e_flags
        e_flags = elf.header.e_flags
        if isinstance(e_flags, int) and (e_flags & 0x8):  # EF_RISCV_RVE
            return "riscv32e"

    return arch


def _detect_raw_architecture(data: bytes) -> str:
    """Detect architecture from raw binary heuristics."""
    if len(data) == 0:
        return "unknown"

    # ESP32 factory binary: first byte is 0xE9
    if data[0] == 0xE9:
        return "xtensa"

    # Cortex-M vector table: first 8 bytes are initial_sp and reset_vector
    if len(data) >= 8:
        sp, reset = struct.unpack_from("<II", data, 0)
        if (0x2000_0000 <= sp <= 0x2100_0000
                and 0x0000_0001 <= reset <= 0x1000_0000
                and (reset & 1)):
            return "armv7m"

    return "unknown"


def detect_format(path: Path) -> BinaryFormat:
    """Detect binary format from file content."""
    with path.open("rb") as f:
        header = f.read(4)

    if header[:4] == b"\x7fELF":
        return BinaryFormat.ELF

    # Check Intel HEX (text file starting with ':')
    try:
        with path.open("r", encoding="ascii", errors="ignore") as f:
            first_line = f.readline().strip()
        if first_line.startswith(":"):
            return BinaryFormat.IHEX
        if first_line.startswith("S"):
            return BinaryFormat.SREC
    except Exception:
        pass

    return BinaryFormat.RAW


def load_elf(path: Path) -> FirmwareImage:
    """Load an ELF firmware file."""
    raw = path.read_bytes()
    sections: list[MemorySection] = []
    symbols: dict[str, int] = {}
    entry_point = 0
    base_address: Optional[int] = None

    with path.open("rb") as f:
        elf = ELFFile(f)
        entry_point = elf.header.e_entry

        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD" and seg.header.p_filesz > 0:
                addr = seg.header.p_paddr
                if base_address is None or addr < base_address:
                    base_address = addr

        for section in elf.iter_sections():
            if section.header.sh_addr == 0:
                continue
            flags = section.header.sh_flags
            perms = ""
            if flags & 0x4:
                perms += "r"
            if flags & 0x2:
                perms += "w"
            if flags & 0x1:
                perms += "x"
            sections.append(MemorySection(
                name=section.name,
                address=section.header.sh_addr,
                data=section.data(),
                size=section.header.sh_size,
                permissions=perms or "r",
            ))

        # Extract symbols
        symtab = elf.get_section_by_name(".symtab")
        if symtab:
            for sym in symtab.iter_symbols():
                if sym.name and sym["st_value"] != 0:
                    symbols[sym.name] = sym["st_value"]

        # Detect architecture
        architecture = _detect_elf_architecture(elf)

    if base_address is None:
        base_address = 0

    # Build flat data blob from sections ordered by address
    if sections:
        sorted_sections = sorted(sections, key=lambda s: s.address)
        end_addr = max(s.address + s.size for s in sorted_sections)
        flat_size = end_addr - base_address
        flat = bytearray(flat_size)
        for sec in sorted_sections:
            off = sec.address - base_address
            end = off + len(sec.data)
            if 0 <= off < flat_size:
                flat[off:end] = sec.data[:flat_size - off]
        data = bytes(flat)
    else:
        data = raw

    return FirmwareImage(
        data=data,
        base_address=base_address,
        entry_point=entry_point,
        format=BinaryFormat.ELF,
        sections=sections,
        symbols=symbols,
        path=path,
        architecture=architecture,
    )


def load_ihex(path: Path) -> FirmwareImage:
    """Load an Intel HEX file."""
    segments: dict[int, bytearray] = {}
    base_addr = 0
    extended_linear = 0
    extended_segment = 0
    entry_point = 0

    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line.startswith(":"):
                continue
            data = bytes.fromhex(line[1:])
            byte_count = data[0]
            address = struct.unpack(">H", data[1:3])[0]
            rec_type = data[3]
            payload = data[4 : 4 + byte_count]

            if rec_type == 0x00:  # Data
                abs_addr = (extended_linear << 16) + (extended_segment << 4) + address
                seg_base = abs_addr & ~0xFFFF
                if seg_base not in segments:
                    segments[seg_base] = bytearray()
                seg = segments[seg_base]
                offset = abs_addr - seg_base
                needed = offset + len(payload)
                if len(seg) < needed:
                    seg.extend(b"\xff" * (needed - len(seg)))
                seg[offset : offset + len(payload)] = payload
            elif rec_type == 0x01:  # EOF
                break
            elif rec_type == 0x02:  # Extended Segment Address
                extended_segment = struct.unpack(">H", payload)[0]
            elif rec_type == 0x04:  # Extended Linear Address
                extended_linear = struct.unpack(">H", payload)[0]
            elif rec_type == 0x05:  # Start Linear Address
                entry_point = struct.unpack(">I", payload)[0]

    if not segments:
        raise ValueError("No data records found in Intel HEX file")

    base_addr = min(segments.keys())
    end_addr = max(base + len(data) for base, data in segments.items())
    flat = bytearray(b"\xff" * (end_addr - base_addr))
    for seg_base, seg_data in segments.items():
        offset = seg_base - base_addr
        flat[offset : offset + len(seg_data)] = seg_data

    return FirmwareImage(
        data=bytes(flat),
        base_address=base_addr,
        entry_point=entry_point,
        format=BinaryFormat.IHEX,
        path=path,
    )


def load_srec(path: Path) -> FirmwareImage:
    """Load a Motorola S-Record file."""
    min_addr: Optional[int] = None
    max_addr = 0
    chunks: list[tuple[int, bytes]] = []
    entry_point = 0

    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("S"):
                continue
            rec_type = line[1]
            data = bytes.fromhex(line[2:])
            # byte_count = data[0]  # includes address + checksum

            if rec_type in ("1", "2", "3"):
                addr_len = {"1": 2, "2": 3, "3": 4}[rec_type]
                addr = int.from_bytes(data[1 : 1 + addr_len], "big")
                payload = data[1 + addr_len : -1]  # exclude checksum
                chunks.append((addr, payload))
                end = addr + len(payload)
                if min_addr is None or addr < min_addr:
                    min_addr = addr
                if end > max_addr:
                    max_addr = end
            elif rec_type in ("7", "8", "9"):
                addr_len = {"7": 4, "8": 3, "9": 2}[rec_type]
                entry_point = int.from_bytes(data[1 : 1 + addr_len], "big")

    if min_addr is None:
        raise ValueError("No data records found in S-Record file")

    flat = bytearray(b"\xff" * (max_addr - min_addr))
    for addr, payload in chunks:
        offset = addr - min_addr
        flat[offset : offset + len(payload)] = payload

    return FirmwareImage(
        data=bytes(flat),
        base_address=min_addr,
        entry_point=entry_point,
        format=BinaryFormat.SREC,
        path=path,
    )


def load_raw(path: Path, base_address: int) -> FirmwareImage:
    """Load a raw binary file. base_address must be provided by caller."""
    data = path.read_bytes()
    architecture = _detect_raw_architecture(data)
    # Entry point for raw ARM binaries is typically base+1 (Thumb mode) or base+4 (reset vector)
    entry_point = base_address + 4  # conservative default; caller can override
    return FirmwareImage(
        data=data,
        base_address=base_address,
        entry_point=entry_point,
        format=BinaryFormat.RAW,
        path=path,
        architecture=architecture,
    )


def load_firmware(
    path: str | Path,
    base_address: int = 0,
) -> FirmwareImage:
    """Auto-detect format and load firmware. For RAW format, base_address is required."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Firmware file not found: {path}")

    fmt = detect_format(path)

    if fmt == BinaryFormat.ELF:
        return load_elf(path)
    elif fmt == BinaryFormat.IHEX:
        return load_ihex(path)
    elif fmt == BinaryFormat.SREC:
        return load_srec(path)
    else:
        return load_raw(path, base_address)
