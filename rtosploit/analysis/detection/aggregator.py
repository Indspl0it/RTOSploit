"""Aggregation engine — combines evidence from all detection layers."""

from __future__ import annotations

import re
from typing import Optional

from rtosploit.analysis.detection.evidence import (
    DetectionResult,
    Evidence,
    PeripheralDetection,
)
from rtosploit.peripherals.svd_model import SVDDevice
from rtosploit.utils.binary import FirmwareImage


# Layer registry: name -> (import_path, function_name, needs_extra_args)
_LAYERS = {
    "symbol": ("rtosploit.analysis.detection.layer_symbol", "detect_from_symbols", False),
    "string": ("rtosploit.analysis.detection.layer_string", "detect_from_strings", False),
    "relocation": ("rtosploit.analysis.detection.layer_relocation", "detect_from_relocations", False),
    "register": ("rtosploit.analysis.detection.layer_register", "detect_from_registers", True),
    "signature": ("rtosploit.analysis.detection.layer_signature", "detect_from_signatures", False),
    "devicetree": ("rtosploit.analysis.detection.layer_devicetree", "detect_from_devicetree", False),
}

ALL_LAYERS = list(_LAYERS.keys())


def detect_peripherals(
    firmware: FirmwareImage,
    mcu_family: str = "",
    svd_device: Optional[SVDDevice] = None,
    layers: Optional[list[str]] = None,
) -> DetectionResult:
    """Run multi-layer peripheral detection.

    Args:
        firmware: Loaded firmware image
        mcu_family: MCU family hint (auto-detected if empty)
        svd_device: SVD device model (auto-loaded if MCU known)
        layers: List of layer names to run (default: all)

    Returns:
        DetectionResult with aggregated peripheral detections
    """
    # Auto-detect MCU family if not provided
    if not mcu_family:
        mcu_family = _detect_mcu_family(firmware)

    # Auto-load SVD if MCU known and no SVD provided
    if svd_device is None and mcu_family != "unknown":
        svd_device = _try_load_svd(mcu_family)

    # Determine which layers to run
    layer_names = layers if layers else ALL_LAYERS

    # Collect all evidence
    all_evidence: list[Evidence] = []
    layers_run: list[str] = []

    for layer_name in layer_names:
        if layer_name not in _LAYERS:
            continue

        module_path, func_name, needs_extra = _LAYERS[layer_name]
        try:
            import importlib
            mod = importlib.import_module(module_path)
            func = getattr(mod, func_name)

            if needs_extra:
                layer_evidence = func(firmware, mcu_family=mcu_family, svd_device=svd_device)
            else:
                layer_evidence = func(firmware)

            all_evidence.extend(layer_evidence)
            layers_run.append(layer_name)
        except Exception:
            # Layer failed — skip silently, other layers continue
            layers_run.append(f"{layer_name}:error")

    # Aggregate evidence into peripheral detections
    peripherals = _aggregate_evidence(all_evidence)

    # Compute vendor scores
    vendor_scores = _compute_vendor_scores(all_evidence)

    return DetectionResult(
        architecture=firmware.architecture,
        vendor_scores=vendor_scores,
        peripherals=peripherals,
        mcu_family=mcu_family,
        layers_run=layers_run,
        total_evidence=len(all_evidence),
    )


def _detect_mcu_family(firmware: FirmwareImage) -> str:
    """Auto-detect MCU family from firmware."""
    try:
        from rtosploit.analysis.fingerprint import _detect_mcu_family as detect_mcu
        family, _ = detect_mcu(firmware)
        return family
    except Exception:
        return "unknown"


def _try_load_svd(mcu_family: str) -> Optional[SVDDevice]:
    """Try to load SVD device from cache."""
    try:
        from rtosploit.peripherals.svd_cache import SVDCache
        cache = SVDCache()
        return cache.get_svd_device(mcu_family)
    except Exception:
        return None


def _aggregate_evidence(evidence_list: list[Evidence]) -> dict[str, PeripheralDetection]:
    """Group evidence by peripheral and build PeripheralDetection objects."""
    groups: dict[str, list[Evidence]] = {}
    for ev in evidence_list:
        name = ev.peripheral.upper()
        if name not in groups:
            groups[name] = []
        groups[name].append(ev)

    peripherals: dict[str, PeripheralDetection] = {}
    for name, evs in groups.items():
        confidence = sum(e.weight for e in evs)

        # Determine peripheral type by majority vote
        type_votes: dict[str, int] = {}
        for e in evs:
            if e.peripheral_type:
                type_votes[e.peripheral_type] = type_votes.get(e.peripheral_type, 0) + 1
        peripheral_type = max(type_votes, key=type_votes.get) if type_votes else "unknown"

        # Find base address from evidence
        base_address = None
        for e in evs:
            if e.address is not None and e.type.value in ("register_write", "register_read", "devicetree_label"):
                base_address = e.address
                break

        # Determine vendor
        vendor = ""
        for e in evs:
            if e.vendor:
                vendor = e.vendor
                break

        # Instance detection: name contains a digit
        instance = bool(re.search(r"\d", name))

        peripherals[name] = PeripheralDetection(
            name=name,
            peripheral_type=peripheral_type,
            confidence=confidence,
            evidence=evs,
            base_address=base_address,
            vendor=vendor,
            instance=instance,
        )

    return peripherals


def _compute_vendor_scores(evidence_list: list[Evidence]) -> dict[str, float]:
    """Compute normalized vendor confidence scores."""
    vendor_weights: dict[str, float] = {}
    for ev in evidence_list:
        if ev.vendor:
            vendor_weights[ev.vendor] = vendor_weights.get(ev.vendor, 0) + ev.weight

    if not vendor_weights:
        return {}

    max_weight = max(vendor_weights.values())
    if max_weight == 0:
        return {}

    return {v: round(w / max_weight, 3) for v, w in vendor_weights.items()}
