"""FreeRTOS / RTOS heap allocator detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from rtosploit.utils.binary import FirmwareImage

if TYPE_CHECKING:
    from rtosploit.analysis.fingerprint import RTOSFingerprint


@dataclass
class HeapInfo:
    allocator_type: str  # "heap_1" | "heap_2" | "heap_3" | "heap_4" | "heap_5" | "threadx_byte_pool" | "zephyr_slab" | "unknown"
    heap_base: Optional[int]
    heap_size: Optional[int]
    block_size: Optional[int]  # for fixed-size allocators
    evidence: list[str] = field(default_factory=list)


def _scan_strings_raw(data: bytes) -> list[str]:
    """Extract all printable ASCII strings >= 4 chars from raw bytes."""
    strings = []
    current: list[str] = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                strings.append("".join(current))
            current = []
    if len(current) >= 4:
        strings.append("".join(current))
    return strings


def _detect_freertos_heap4(firmware: FirmwareImage) -> tuple[float, dict]:
    """
    Look for BlockLink_t list traversal pattern.

    ARM Thumb2: LDR Rx, [Ry, #0] is encoded as 0x00 0x68 (LDR Rx, [Ry])
    followed by LDR Rz, [Rx, #4] encoded as 0x40 0x68.
    This is the canonical pattern for pxNextFreeBlock/xBlockSize traversal.
    """
    data = firmware.data
    evidence: list[str] = []

    # ARM Thumb2 LDR Rx,[Ry,#0] = 0x68 in the upper nibble of encoding
    # Pattern: LDR r0,[r0] (0x00 0x68) then LDR r0,[r0,#4] (0x40 0x68)
    # More permissive: look for the xBlockSize offset read (0x40 0x68 or 0x41 0x68)
    ldr_next = bytes([0x00, 0x68])  # LDR r0, [r0, #0]
    ldr_size = bytes([0x40, 0x68])  # LDR r0, [r0, #4]

    found_traversal = False
    i = 0
    while i < len(data) - 4:
        if data[i:i+2] == ldr_next and data[i+2:i+4] == ldr_size:
            addr = firmware.base_address + i
            evidence.append(f"BlockLink traversal pattern at 0x{addr:08x} (LDR+LDR #0,#4)")
            found_traversal = True
            break
        i += 2

    confidence = 0.4 if found_traversal else 0.0
    result = {"evidence": evidence}
    return confidence, result


def _detect_freertos_heap_variant(firmware: FirmwareImage) -> str:
    """
    Determine which FreeRTOS heap variant is present.

    - heap_5: has 'vPortDefineHeapRegions'
    - heap_1: no 'vPortFree' present (no free operation)
    - heap_4: default (coalescing allocator)
    """
    data = firmware.data
    strings = _scan_strings_raw(data)
    full_text = " ".join(strings)

    if "vPortDefineHeapRegions" in full_text:
        return "heap_5"

    if "vPortFree" not in full_text:
        return "heap_1"

    return "heap_4"


def _detect_heap_base(firmware: FirmwareImage) -> Optional[int]:
    """
    Estimate heap base by finding a large run of zeros in SRAM address space.

    Cortex-M SRAM is typically at 0x20000000+. We scan the firmware flat data
    for a zero region of >= 256 bytes that, when mapped to the address space,
    would fall in SRAM.
    """
    data = firmware.data
    base = firmware.base_address
    sram_start = 0x20000000

    min_zero_run = 256
    run_start = -1
    run_len = 0

    for i, b in enumerate(data):
        if b == 0:
            if run_start < 0:
                run_start = i
            run_len += 1
        else:
            if run_len >= min_zero_run:
                addr = base + run_start
                if addr >= sram_start:
                    return addr
            run_start = -1
            run_len = 0

    if run_len >= min_zero_run:
        addr = base + run_start
        if addr >= sram_start:
            return addr

    return None


def detect_heap(firmware: FirmwareImage, rtos: "RTOSFingerprint") -> HeapInfo:
    """Detect heap allocator type and layout from firmware image."""
    evidence: list[str] = []

    if rtos.rtos_type == "freertos":
        variant = _detect_freertos_heap_variant(firmware)
        confidence, heap4_result = _detect_freertos_heap4(firmware)
        evidence.extend(heap4_result.get("evidence", []))
        evidence.append(f"FreeRTOS heap variant detected: {variant}")

        heap_base = _detect_heap_base(firmware)
        if heap_base is not None:
            evidence.append(f"Candidate heap base in SRAM: 0x{heap_base:08x}")

        return HeapInfo(
            allocator_type=variant,
            heap_base=heap_base,
            heap_size=None,
            block_size=None,
            evidence=evidence,
        )

    elif rtos.rtos_type == "threadx":
        evidence.append("ThreadX byte pool allocator inferred from RTOS type")
        heap_base = _detect_heap_base(firmware)
        if heap_base is not None:
            evidence.append(f"Candidate heap base in SRAM: 0x{heap_base:08x}")
        return HeapInfo(
            allocator_type="threadx_byte_pool",
            heap_base=heap_base,
            heap_size=None,
            block_size=None,
            evidence=evidence,
        )

    elif rtos.rtos_type == "zephyr":
        evidence.append("Zephyr memory slab allocator inferred from RTOS type")
        heap_base = _detect_heap_base(firmware)
        return HeapInfo(
            allocator_type="zephyr_slab",
            heap_base=heap_base,
            heap_size=None,
            block_size=None,
            evidence=evidence,
        )

    else:
        return HeapInfo(
            allocator_type="unknown",
            heap_base=None,
            heap_size=None,
            block_size=None,
            evidence=["RTOS type unknown; cannot determine heap allocator"],
        )
