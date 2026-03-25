"""Evidence model for peripheral detection engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EvidenceType(Enum):
    SYMBOL = "symbol"
    SDK_STRING = "sdk_string"
    RELOCATION = "relocation"
    REGISTER_WRITE = "register_write"
    REGISTER_READ = "register_read"
    BINARY_PATTERN = "binary_pattern"
    DEVICETREE_LABEL = "devicetree_label"


EVIDENCE_WEIGHTS: dict[EvidenceType, float] = {
    EvidenceType.REGISTER_WRITE: 0.9,
    EvidenceType.REGISTER_READ: 0.8,
    EvidenceType.DEVICETREE_LABEL: 0.8,
    EvidenceType.BINARY_PATTERN: 0.7,
    EvidenceType.RELOCATION: 0.7,
    EvidenceType.SYMBOL: 0.6,
    EvidenceType.SDK_STRING: 0.4,
}


@dataclass
class Evidence:
    """A single piece of evidence for peripheral detection."""
    type: EvidenceType
    peripheral: str  # e.g., "UART1", "SPI0"
    weight: float
    detail: str  # Human-readable description
    address: Optional[int] = None
    vendor: str = ""
    peripheral_type: str = ""  # "uart", "spi", "i2c", etc.
    register_name: str = ""
    register_offset: int = 0


class ConfidenceLevel(Enum):
    HIGH = "high"      # > 1.2
    MEDIUM = "medium"  # 0.6 - 1.2
    LOW = "low"        # < 0.6


@dataclass
class PeripheralDetection:
    """A detected peripheral with aggregated evidence.

    Attributes:
        confidence: Evidence accumulation score — the sum of all evidence
            weights for this peripheral.  This is NOT a probability and CAN
            exceed 1.0 when multiple independent evidence sources (symbol,
            register access, devicetree, etc.) all corroborate the same
            peripheral.  Higher values indicate stronger multi-layer
            agreement.  Use ``confidence_level`` for a coarse HIGH/MEDIUM/LOW
            classification.
    """
    name: str
    peripheral_type: str
    confidence: float  # Sum of evidence weights (can exceed 1.0)
    evidence: list[Evidence] = field(default_factory=list)
    base_address: Optional[int] = None
    vendor: str = ""
    instance: bool = False  # True if name contains instance number (e.g., UART1)

    @property
    def confidence_level(self) -> ConfidenceLevel:
        if self.confidence > 1.2:
            return ConfidenceLevel.HIGH
        elif self.confidence >= 0.6:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW


@dataclass
class DetectionResult:
    """Complete result from the detection engine."""
    architecture: str = "unknown"
    vendor_scores: dict[str, float] = field(default_factory=dict)
    peripherals: dict[str, PeripheralDetection] = field(default_factory=dict)
    mcu_family: str = "unknown"
    layers_run: list[str] = field(default_factory=list)
    total_evidence: int = 0

    def to_dict(self) -> dict:
        return {
            "architecture": self.architecture,
            "mcu_family": self.mcu_family,
            "vendor_scores": self.vendor_scores,
            "layers_run": self.layers_run,
            "total_evidence": self.total_evidence,
            "peripherals": {
                name: {
                    "name": det.name,
                    "type": det.peripheral_type,
                    "confidence": round(det.confidence, 3),
                    "confidence_note": "evidence accumulation score (sum of weights), not a probability — values > 1.0 indicate strong multi-layer agreement",
                    "confidence_level": det.confidence_level.value,
                    "base_address": f"0x{det.base_address:08x}" if det.base_address is not None else None,
                    "vendor": det.vendor,
                    "instance": det.instance,
                    "evidence_count": len(det.evidence),
                    "evidence": [
                        {
                            "type": e.type.value,
                            "detail": e.detail,
                            "weight": e.weight,
                            "address": f"0x{e.address:08x}" if e.address is not None else None,
                        }
                        for e in det.evidence
                    ],
                }
                for name, det in sorted(self.peripherals.items(), key=lambda x: -x[1].confidence)
            },
        }
