"""Multi-layer peripheral detection engine."""

from rtosploit.analysis.detection.evidence import (
    ConfidenceLevel,
    DetectionResult,
    Evidence,
    EvidenceType,
    PeripheralDetection,
)

__all__ = [
    "detect_peripherals",
    "ConfidenceLevel",
    "DetectionResult",
    "Evidence",
    "EvidenceType",
    "PeripheralDetection",
]


def detect_peripherals(firmware, mcu_family="", svd_device=None, layers=None):
    """Detect peripherals using multi-layer analysis.

    This is a convenience re-export. The actual implementation is in aggregator.py.
    """
    from rtosploit.analysis.detection.aggregator import detect_peripherals as _detect
    return _detect(firmware, mcu_family=mcu_family, svd_device=svd_device, layers=layers)
