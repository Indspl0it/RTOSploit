"""Layer 6: Zephyr devicetree extraction for peripheral detection."""

from __future__ import annotations

import re

from rtosploit.analysis.detection.evidence import Evidence, EvidenceType, EVIDENCE_WEIGHTS
from rtosploit.analysis.fingerprint import _scan_firmware_strings
from rtosploit.utils.binary import FirmwareImage


# Devicetree node patterns: peripheral@base_address
_DT_NODE_PATTERN = re.compile(
    r"(uart|usart|spi|i2c|twi|gpio|timer|pwm|adc|dac|wdt|rtc|can|"
    r"ethernet|eth|usb|dma|flash|serial)@([0-9a-fA-F]{4,8})",
    re.IGNORECASE,
)

# Zephyr DT macro patterns (compiled into binary)
_DT_MACRO_PATTERNS: list[tuple[str, str, str]] = [
    (r"DT_N_S_(uart|usart|spi|i2c|twi|gpio|timer)_S_", "zephyr", "DT node macro"),
    (r"DT_CHOSEN_zephyr_(console|shell_uart|bt_uart)", "uart", "DT chosen UART"),
    (r"DT_CHOSEN_zephyr_(flash|storage)", "flash", "DT chosen flash"),
    (r"__device_dts_ord_\d+", "", "DT device ordinal"),
]

# Type normalization map
_TYPE_NORMALIZE: dict[str, str] = {
    "usart": "uart",
    "twi": "i2c",
    "serial": "uart",
    "eth": "ethernet",
}


def detect_from_devicetree(firmware: FirmwareImage) -> list[Evidence]:
    """Detect peripherals from Zephyr devicetree data embedded in firmware."""
    strings = _scan_firmware_strings(firmware)
    if not strings:
        return []

    full_text = "\n".join(strings)
    evidence: list[Evidence] = []
    seen: set[str] = set()  # Dedup by peripheral name

    # 1. Scan for peripheral@address patterns
    for match in _DT_NODE_PATTERN.finditer(full_text):
        ptype_raw = match.group(1).lower()
        base_addr_str = match.group(2)
        base_addr = int(base_addr_str, 16)

        ptype = _TYPE_NORMALIZE.get(ptype_raw, ptype_raw)
        peripheral_name = f"{ptype.upper()}@0x{base_addr:X}"

        if peripheral_name in seen:
            continue
        seen.add(peripheral_name)

        evidence.append(Evidence(
            type=EvidenceType.DEVICETREE_LABEL,
            peripheral=peripheral_name,
            weight=EVIDENCE_WEIGHTS[EvidenceType.DEVICETREE_LABEL],
            detail=f"Devicetree node: {match.group(0)}",
            address=base_addr,
            vendor="zephyr",
            peripheral_type=ptype,
        ))

    # 2. Scan for DT macro patterns
    for pattern, ptype_override, desc in _DT_MACRO_PATTERNS:
        matches = re.findall(pattern, full_text)
        if not matches:
            continue

        for m in matches:
            if ptype_override:
                ptype = ptype_override
            else:
                ptype = _TYPE_NORMALIZE.get(m.lower(), m.lower()) if isinstance(m, str) else ""

            if not ptype:
                continue

            peripheral_name = ptype.upper()
            key = f"macro:{peripheral_name}:{desc}"
            if key in seen:
                continue
            seen.add(key)

            evidence.append(Evidence(
                type=EvidenceType.DEVICETREE_LABEL,
                peripheral=peripheral_name,
                weight=EVIDENCE_WEIGHTS[EvidenceType.DEVICETREE_LABEL],
                detail=f"{desc}: {m}",
                vendor="zephyr",
                peripheral_type=ptype,
            ))

    return evidence
