"""Layer 3: ELF relocation table analysis for peripheral detection."""

from __future__ import annotations

from rtosploit.analysis.detection.evidence import Evidence, EvidenceType, EVIDENCE_WEIGHTS
from rtosploit.peripherals.hal_database import HALDatabase
from rtosploit.utils.binary import FirmwareImage


def detect_from_relocations(firmware: FirmwareImage) -> list[Evidence]:
    """Detect peripherals from ELF relocation entries.

    Relocations survive partial stripping since .dynsym is needed by
    the dynamic linker. This layer catches peripherals that have no
    symbols in .symtab but do have relocation references.
    """
    if not firmware.relocations:
        return []

    db = HALDatabase()
    evidence: list[Evidence] = []
    seen_symbols: set[str] = set()

    for reloc in firmware.relocations:
        if not reloc.symbol_name or reloc.symbol_name in seen_symbols:
            continue

        entry = db.lookup_symbol(reloc.symbol_name)
        if entry is None:
            continue

        seen_symbols.add(reloc.symbol_name)
        peripheral_name = entry.peripheral_type.upper()

        evidence.append(Evidence(
            type=EvidenceType.RELOCATION,
            peripheral=peripheral_name,
            weight=EVIDENCE_WEIGHTS[EvidenceType.RELOCATION],
            detail=f"Relocation: {reloc.symbol_name} at offset 0x{reloc.offset:08x}",
            address=reloc.offset,
            vendor=entry.vendor,
            peripheral_type=entry.peripheral_type,
        ))

    return evidence
