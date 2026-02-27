"""ARM Cortex-M MPU configuration analysis."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from rtosploit.utils.binary import FirmwareImage

# ARM Cortex-M MPU register addresses
MPU_CTRL = 0xE000ED94
MPU_RNR  = 0xE000ED98
MPU_RBAR = 0xE000ED9C
MPU_RASR = 0xE000EDA0

# SRAM address range
SRAM_START = 0x20000000
SRAM_END   = 0x3FFFFFFF


@dataclass
class MPURegion:
    region_number: int
    base_address: int
    size: int        # in bytes
    permissions: int  # AP field (0-7)
    executable: bool  # True = NOT XN (executable)
    enabled: bool


@dataclass
class MPUConfig:
    mpu_present: bool
    regions_configured: int
    regions: list[MPURegion] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)


def _parse_rasr(rasr_value: int) -> dict:
    """
    Parse ARM MPU RASR register.

    Bit layout:
      [28]    XN   — execute-never
      [26:24] AP   — access permissions
      [5:1]   SIZE — encoded size; actual = 2^(SIZE+1) bytes
      [0]     ENABLE
    """
    xn     = bool((rasr_value >> 28) & 0x1)
    ap     = (rasr_value >> 24) & 0x7
    size_f = (rasr_value >> 1) & 0x1F
    enable = bool(rasr_value & 0x1)

    actual_size = 2 ** (size_f + 1) if size_f > 0 else 0

    return {
        "xn": xn,
        "ap": ap,
        "size_field": size_f,
        "size_bytes": actual_size,
        "enable": enable,
        "executable": not xn,
    }


def _find_mpu_writes(firmware: FirmwareImage) -> list[tuple[int, int, int]]:
    """
    Scan firmware for ARM Thumb2 sequences that write to MPU registers.

    We look for the pattern:
      LDR Rn, [PC, #offset]  or  MOV Rn, #imm32
      STR Rn, [Rm]
    where the store target resolves to an MPU register address.

    Simplified heuristic: search for 4-byte little-endian representations
    of MPU register addresses in the instruction stream. When a firmware
    loads these addresses into a register and then does a store, the address
    literal will appear verbatim in the .rodata or as a PC-relative load.

    Returns list of (fw_offset, mpu_reg_addr, value) — value is 0 when
    the actual runtime value cannot be statically determined.
    """
    data = firmware.data
    results: list[tuple[int, int, int]] = []
    mpu_regs = {MPU_CTRL, MPU_RNR, MPU_RBAR, MPU_RASR}

    # Search for 4-byte little-endian literal of each MPU register address
    for reg_addr in mpu_regs:
        encoded = struct.pack("<I", reg_addr)
        start = 0
        while True:
            idx = data.find(encoded, start)
            if idx < 0:
                break
            fw_addr = firmware.base_address + idx
            results.append((fw_addr, reg_addr, 0))
            start = idx + 4

    return results


def _detect_vulnerabilities(regions: list[MPURegion]) -> list[str]:
    """Identify insecure MPU configurations."""
    vulns: list[str] = []

    enabled_regions = [r for r in regions if r.enabled]

    if not enabled_regions:
        vulns.append("No MPU regions enabled — MPU likely disabled")
        return vulns

    for r in enabled_regions:
        # SRAM executable
        if SRAM_START <= r.base_address <= SRAM_END and r.executable:
            vulns.append(
                f"SRAM region {r.region_number} is executable (no XN) — "
                f"base=0x{r.base_address:08x}"
            )
        # Full read-write access
        if r.permissions == 3:
            vulns.append(
                f"Region {r.region_number} has full read-write access (AP=3)"
            )

    return vulns


def check_mpu(firmware: FirmwareImage) -> MPUConfig:
    """
    Analyse MPU configuration from firmware.

    Strategy:
    1. Search for MPU register address literals in the image.
    2. Where RBAR/RASR pairs are found adjacent, attempt to extract
       the stored values by reading the preceding LDR literal pool word.
    3. Build MPURegion list and run vulnerability detection.
    """
    writes = _find_mpu_writes(firmware)
    mpu_present = len(writes) > 0

    regions: list[MPURegion] = []
    region_number = 0

    data = firmware.data
    base = firmware.base_address

    # Look for adjacent RBAR + RASR address literals (separated by 0-32 bytes)
    rbar_offsets = [
        (fw_addr - base, fw_addr, val)
        for fw_addr, reg_addr, val in writes
        if reg_addr == MPU_RBAR
    ]

    for rbar_fw_off, rbar_addr, _ in rbar_offsets:
        # Try to find a value stored to RBAR: look for a 4-byte word
        # immediately before the RBAR address literal that looks like
        # a valid Cortex-M RBAR value (base address aligned, region bits in [3:0])
        if rbar_fw_off >= 4:
            rbar_val = struct.unpack_from("<I", data, rbar_fw_off - 4)[0]
        else:
            rbar_val = 0

        # Look for RASR literal within 16 bytes after RBAR literal
        rasr_search_start = rbar_fw_off + 4
        rasr_search_end   = min(rbar_fw_off + 20, len(data) - 4)
        rasr_val = None

        encoded_rasr = struct.pack("<I", MPU_RASR)
        for off in range(rasr_search_start, rasr_search_end):
            if data[off:off+4] == encoded_rasr:
                # Try to read value immediately before RASR address
                if off >= 4:
                    rasr_val = struct.unpack_from("<I", data, off - 4)[0]
                break

        if rasr_val is None:
            continue

        parsed = _parse_rasr(rasr_val)
        base_addr = rbar_val & 0xFFFFFFE0  # mask off region bits

        regions.append(MPURegion(
            region_number=region_number,
            base_address=base_addr,
            size=parsed["size_bytes"],
            permissions=parsed["ap"],
            executable=parsed["executable"],
            enabled=parsed["enable"],
        ))
        region_number += 1

    vulns = _detect_vulnerabilities(regions)

    return MPUConfig(
        mpu_present=mpu_present,
        regions_configured=len(regions),
        regions=regions,
        vulnerabilities=vulns,
    )
