"""Layer 1: Symbol-based peripheral detection via HAL database."""

from __future__ import annotations

import re

from rtosploit.analysis.detection.evidence import Evidence, EvidenceType, EVIDENCE_WEIGHTS
from rtosploit.peripherals.hal_database import HALDatabase
from rtosploit.utils.binary import FirmwareImage


def detect_from_symbols(firmware: FirmwareImage) -> list[Evidence]:
    """Detect peripherals from firmware symbol table using HAL database."""
    if not firmware.symbols:
        return []

    db = HALDatabase()
    matches = db.match_firmware_symbols(firmware.symbols)
    evidence: list[Evidence] = []

    for entry, addr in matches:
        # Infer instance from symbol name (e.g., HAL_UART1_Init -> UART1)
        peripheral_name = _infer_peripheral_name(entry.symbol, entry.peripheral_type)

        evidence.append(Evidence(
            type=EvidenceType.SYMBOL,
            peripheral=peripheral_name,
            weight=EVIDENCE_WEIGHTS[EvidenceType.SYMBOL],
            detail=f"HAL symbol: {entry.symbol} ({entry.vendor})",
            address=addr,
            vendor=entry.vendor,
            peripheral_type=entry.peripheral_type,
        ))

    return evidence


def _infer_peripheral_name(symbol: str, peripheral_type: str) -> str:
    """Extract peripheral instance name from symbol.

    Examples:
        HAL_UART_Receive -> UART
        HAL_UART1_Init -> UART1
        nrf_drv_spi_transfer -> SPI
        nrfx_uarte_init -> UARTE
    """
    # Look for type + number pattern
    ptype_upper = peripheral_type.upper()
    match = re.search(rf'({ptype_upper}\d+)', symbol, re.IGNORECASE)
    if match:
        return match.group(1).upper()

    # Fallback: just the peripheral type
    return ptype_upper
