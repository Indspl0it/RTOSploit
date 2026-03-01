"""Layer 5: Function signature matching for inlined HAL patterns."""

from __future__ import annotations

from rtosploit.analysis.detection.evidence import Evidence, EvidenceType, EVIDENCE_WEIGHTS
from rtosploit.analysis.detection.signatures import SIGNATURES
from rtosploit.utils.binary import FirmwareImage, MemorySection
from rtosploit.utils.disasm import disassemble

# Max bytes to scan per section to avoid timeout on large firmware
_MAX_SCAN_BYTES = 512 * 1024  # 512 KB


def _find_pattern_in_data(
    data: bytes,
    base: int,
    pattern: bytes,
    mask: bytes,
) -> list[int]:
    """Scan data for byte pattern with mask. Returns addresses."""
    plen = len(pattern)
    limit = min(len(data) - plen + 1, _MAX_SCAN_BYTES)
    addresses = []
    for i in range(limit):
        if all(
            (data[i + j] & mask[j]) == (pattern[j] & mask[j])
            for j in range(plen)
        ):
            addresses.append(base + i)
            if len(addresses) >= 50:
                break
    return addresses


def detect_from_signatures(firmware: FirmwareImage) -> list[Evidence]:
    """Detect peripherals by matching known HAL init binary signatures."""
    arch = firmware.architecture
    if arch not in ("armv7m", "armv8m"):
        return []

    # Only scan executable sections
    exec_sections = [
        s for s in firmware.sections
        if "x" in s.permissions and s.data and len(s.data) > 0
    ]
    if not exec_sections:
        # Fallback for raw binaries: use firmware data with size limit
        exec_sections = [MemorySection(
            name=".text",
            address=firmware.base_address,
            data=firmware.data[:_MAX_SCAN_BYTES],
            size=min(len(firmware.data), _MAX_SCAN_BYTES),
            permissions="rx",
        )]

    evidence: list[Evidence] = []
    seen: set[str] = set()  # Dedup by signature name

    for sig in SIGNATURES:
        if sig.name in seen:
            continue

        # Scan each executable section for anchor bytes
        all_hits: list[int] = []
        for sec in exec_sections:
            hits = _find_pattern_in_data(
                sec.data, sec.address, sig.anchor_bytes, sig.anchor_mask
            )
            all_hits.extend(hits)
            if len(all_hits) >= 50:
                break

        if not all_hits:
            continue

        # For each hit, disassemble a window and check mnemonic sequence
        for hit_addr in all_hits[:50]:  # Limit to avoid excessive scanning
            # Calculate window start
            window_start = max(hit_addr - sig.pre_context_bytes, firmware.base_address)
            window_end = min(
                hit_addr + sig.post_context_bytes,
                firmware.base_address + len(firmware.data),
            )
            offset = window_start - firmware.base_address
            window_data = firmware.data[offset:window_end - firmware.base_address]

            if not window_data:
                continue

            try:
                insns = disassemble(window_data, window_start, arch)
            except Exception:
                continue

            mnemonics = [i.mnemonic.lower() for i in insns]
            if sig.matches_sequence(mnemonics):
                seen.add(sig.name)
                evidence.append(Evidence(
                    type=EvidenceType.BINARY_PATTERN,
                    peripheral=sig.peripheral,
                    weight=EVIDENCE_WEIGHTS[EvidenceType.BINARY_PATTERN],
                    detail=f"Signature match: {sig.name} at 0x{hit_addr:08X}",
                    address=hit_addr,
                    vendor=sig.vendor,
                    peripheral_type=sig.peripheral_type,
                ))
                break  # One match per signature is enough

    return evidence
