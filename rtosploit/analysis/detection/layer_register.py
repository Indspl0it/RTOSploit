"""Layer 4: MMIO register detection via Capstone disassembly."""

from __future__ import annotations

import re
from typing import Optional

from rtosploit.analysis.detection.evidence import Evidence, EvidenceType, EVIDENCE_WEIGHTS
from rtosploit.analysis.detection.vendor_maps import get_vendor_peripheral_map, PeripheralMapEntry
from rtosploit.peripherals.svd_model import SVDDevice
from rtosploit.utils.binary import FirmwareImage
from rtosploit.utils.disasm import disassemble_iter


# Peripheral address ranges by architecture
_PERIPHERAL_RANGES: dict[str, list[tuple[int, int]]] = {
    "armv7m": [(0x40000000, 0x60000000)],
    "armv8m": [(0x40000000, 0x60000000)],
    "xtensa": [(0x3FF00000, 0x40000000)],
    "riscv32": [(0x10000000, 0x20000000)],
}


def _is_peripheral_address(address: int, arch: str) -> bool:
    """Check if address falls in peripheral MMIO space."""
    ranges = _PERIPHERAL_RANGES.get(arch, _PERIPHERAL_RANGES.get("armv7m", []))
    return any(lo <= address < hi for lo, hi in ranges)


def _build_peripheral_lookup(
    svd_device: Optional[SVDDevice],
    mcu_family: str,
) -> list[PeripheralMapEntry]:
    """Build peripheral map from SVD or vendor fallback."""
    entries: list[PeripheralMapEntry] = []

    if svd_device:
        for periph in svd_device.peripherals:
            # Infer type from peripheral name/group
            ptype = _infer_peripheral_type(periph.name, periph.group_name)
            entries.append(PeripheralMapEntry(
                name=periph.name,
                base_address=periph.base_address,
                size=periph.size,
                peripheral_type=ptype,
            ))

    if not entries:
        entries = get_vendor_peripheral_map(mcu_family)

    return entries


def _infer_peripheral_type(name: str, group_name: str) -> str:
    """Infer peripheral type from SVD peripheral name."""
    combined = (name + " " + group_name).upper()
    type_keywords = [
        ("UART", "uart"), ("USART", "uart"), ("SPI", "spi"),
        ("I2C", "i2c"), ("TWI", "i2c"), ("GPIO", "gpio"),
        ("TIM", "timer"), ("ADC", "adc"), ("DAC", "dac"),
        ("DMA", "dma"), ("RCC", "clock"), ("CAN", "can"),
        ("USB", "usb"), ("WDT", "wdt"), ("RTC", "rtc"),
        ("FLASH", "flash"), ("RADIO", "radio"), ("RNG", "rng"),
    ]
    for keyword, ptype in type_keywords:
        if keyword in combined:
            return ptype
    return "unknown"


def _lookup_peripheral(
    address: int,
    periph_map: list[PeripheralMapEntry],
) -> Optional[tuple[str, str, str, int]]:
    """Lookup address in peripheral map.

    Returns (periph_name, register_name, peripheral_type, offset) or None.
    """
    for entry in periph_map:
        if entry.base_address <= address < entry.base_address + entry.size:
            offset = address - entry.base_address
            reg_name = f"REG_0x{offset:03X}"
            return entry.name, reg_name, entry.peripheral_type, offset
    return None


def detect_from_registers(
    firmware: FirmwareImage,
    mcu_family: str = "",
    svd_device: Optional[SVDDevice] = None,
) -> list[Evidence]:
    """Detect peripherals from MMIO register accesses found via disassembly."""
    arch = firmware.architecture
    if arch not in _PERIPHERAL_RANGES:
        return []

    periph_map = _build_peripheral_lookup(svd_device, mcu_family)
    if not periph_map:
        return []

    evidence: list[Evidence] = []
    seen_addresses: set[int] = set()

    # Only scan executable sections
    exec_sections = [
        s for s in firmware.sections
        if "x" in s.permissions and s.data and len(s.data) > 0
    ]

    if not exec_sections:
        # Fallback: scan entire firmware data for raw binaries
        exec_sections_data = [(firmware.data, firmware.base_address)]
    else:
        exec_sections_data = [(s.data, s.address) for s in exec_sections]

    for section_data, section_base in exec_sections_data:
        # Lightweight register tracking
        reg_values: dict[int, int] = {}  # register_num -> known_value

        for insn in disassemble_iter(section_data, section_base, arch):
            mnemonic = insn.mnemonic.lower()
            op = insn.op_str

            # Clear tracking at branches/calls
            if mnemonic in ("b", "bl", "bx", "blx", "cbz", "cbnz", "bne", "beq",
                           "bgt", "blt", "bge", "ble", "bhi", "blo", "bcc", "bcs",
                           "pop", "ret", "jalr", "jal"):
                reg_values.clear()
                continue

            # Track MOVW Rn, #imm16
            if mnemonic == "movw":
                m = re.match(r"r(\d+),\s*#(0x[0-9a-fA-F]+|\d+)", op)
                if m:
                    reg_num = int(m.group(1))
                    imm = int(m.group(2), 0)
                    reg_values[reg_num] = imm & 0xFFFF
                continue

            # Track MOVT Rn, #imm16
            if mnemonic == "movt":
                m = re.match(r"r(\d+),\s*#(0x[0-9a-fA-F]+|\d+)", op)
                if m:
                    reg_num = int(m.group(1))
                    imm = int(m.group(2), 0)
                    if reg_num in reg_values:
                        reg_values[reg_num] = (reg_values[reg_num] & 0xFFFF) | ((imm & 0xFFFF) << 16)
                    else:
                        reg_values[reg_num] = (imm & 0xFFFF) << 16
                continue

            # Track MOV Rn, #imm (simple immediate)
            if mnemonic == "mov" or mnemonic == "movs":
                m = re.match(r"r(\d+),\s*#(0x[0-9a-fA-F]+|\d+)", op)
                if m:
                    reg_num = int(m.group(1))
                    imm = int(m.group(2), 0)
                    reg_values[reg_num] = imm
                continue

            # Track LDR Rn, [PC, #imm] — literal pool load
            if mnemonic == "ldr" and "[pc" in op.lower():
                m = re.match(r"r(\d+),\s*\[pc,\s*#(0x[0-9a-fA-F]+|\d+)\]", op, re.IGNORECASE)
                if m:
                    reg_num = int(m.group(1))
                    pc_offset = int(m.group(2), 0)
                    # PC is aligned to 4 bytes for literal pool loads
                    pc_aligned = (insn.address + 4) & ~3
                    literal_addr = pc_aligned + pc_offset
                    try:
                        value = firmware.read_word(literal_addr)
                        reg_values[reg_num] = value
                    except (ValueError, IndexError):
                        pass
                continue

            # Track LDR Rn, =value (pseudo-instruction, shows as ldr rN, [pc, #off])
            if mnemonic == "ldr":
                m = re.match(r"r(\d+),\s*\[pc\]", op, re.IGNORECASE)
                if m:
                    # Already handled above
                    continue

            # Detect STR Rx, [Rn, #offset] — register write
            if mnemonic in ("str", "strh", "strb"):
                m = re.match(r"r\d+,\s*\[r(\d+)(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]", op)
                if m:
                    base_reg = int(m.group(1))
                    offset = int(m.group(2), 0) if m.group(2) else 0
                    if base_reg in reg_values:
                        target_addr = reg_values[base_reg] + offset
                        if _is_peripheral_address(target_addr, arch) and target_addr not in seen_addresses:
                            seen_addresses.add(target_addr)
                            result = _lookup_peripheral(target_addr, periph_map)
                            if result:
                                p_name, r_name, p_type, r_offset = result
                                evidence.append(Evidence(
                                    type=EvidenceType.REGISTER_WRITE,
                                    peripheral=p_name,
                                    weight=EVIDENCE_WEIGHTS[EvidenceType.REGISTER_WRITE],
                                    detail=f"MMIO write to {p_name}.{r_name} at 0x{target_addr:08X}",
                                    address=insn.address,
                                    vendor="",
                                    peripheral_type=p_type,
                                    register_name=r_name,
                                    register_offset=r_offset,
                                ))
                continue

            # Detect LDR Rx, [Rn, #offset] — register read (not literal pool)
            if mnemonic in ("ldr", "ldrh", "ldrb") and "[pc" not in op.lower():
                m = re.match(r"r(\d+),\s*\[r(\d+)(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]", op)
                if m:
                    base_reg = int(m.group(2))
                    offset = int(m.group(3), 0) if m.group(3) else 0
                    if base_reg in reg_values:
                        target_addr = reg_values[base_reg] + offset
                        if _is_peripheral_address(target_addr, arch) and target_addr not in seen_addresses:
                            seen_addresses.add(target_addr)
                            result = _lookup_peripheral(target_addr, periph_map)
                            if result:
                                p_name, r_name, p_type, r_offset = result
                                evidence.append(Evidence(
                                    type=EvidenceType.REGISTER_READ,
                                    peripheral=p_name,
                                    weight=EVIDENCE_WEIGHTS[EvidenceType.REGISTER_READ],
                                    detail=f"MMIO read from {p_name}.{r_name} at 0x{target_addr:08X}",
                                    address=insn.address,
                                    vendor="",
                                    peripheral_type=p_type,
                                    register_name=r_name,
                                    register_offset=r_offset,
                                ))

    return evidence
