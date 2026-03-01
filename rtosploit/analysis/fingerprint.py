"""RTOS fingerprinting via string and binary pattern scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from rtosploit.utils.binary import FirmwareImage


@dataclass
class RTOSFingerprint:
    rtos_type: str  # "freertos" | "threadx" | "zephyr" | "rtems" | "unknown"
    version: Optional[str]
    confidence: float  # 0.0 to 1.0
    evidence: list[str] = field(default_factory=list)


def _scan_strings(data: bytes) -> list[str]:
    """Extract all printable ASCII strings from raw bytes."""
    strings = []
    current = []
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


def _extract_version_from_strings(strings: list[str], patterns: list[str]) -> Optional[str]:
    """Try to extract a version string matching known patterns."""
    for s in strings:
        for pat in patterns:
            m = re.search(pat, s)
            if m:
                return m.group(1)
    return None


def _detect_freertos(firmware: FirmwareImage) -> tuple[float, Optional[str], list[str]]:
    """Detect FreeRTOS by scanning for known strings and binary patterns."""
    markers = [
        "FreeRTOS",
        "pvPortMalloc",
        "vTaskStartScheduler",
        "xQueueCreate",
        "FreeRTOS Kernel V",
        "FreeRTOS V10.",
        "FreeRTOS V11.",
    ]

    data = firmware.data
    strings = _scan_strings(data)
    full_text = " ".join(strings)

    evidence: list[str] = []
    hits = 0

    for marker in markers:
        if marker in full_text:
            evidence.append(f"String found: '{marker}'")
            hits += 1

    # Scan for ARM Thumb PUSH instruction prefix (0x2D 0xE9)
    thumb_push = bytes([0x2D, 0xE9])
    count = data.count(thumb_push)
    if count > 0:
        evidence.append(f"ARM Thumb2 PUSH prologue found {count} times (0x2DE9)")

    # Version extraction
    version = _extract_version_from_strings(
        strings,
        [
            r"FreeRTOS Kernel V(\d+\.\d+[\.\d]*)",
            r"FreeRTOS V(\d+\.\d+[\.\d]*)",
        ],
    )
    if version:
        evidence.append(f"Version extracted: {version}")

    # Confidence: scale by how many strong markers found
    if hits == 0:
        confidence = 0.0
    elif hits == 1:
        confidence = 0.35
    elif hits == 2:
        confidence = 0.55
    elif hits == 3:
        confidence = 0.70
    else:
        confidence = min(0.95, 0.70 + (hits - 3) * 0.08)

    return confidence, version, evidence


def _detect_threadx(firmware: FirmwareImage) -> tuple[float, Optional[str], list[str]]:
    """Detect ThreadX by scanning for known strings."""
    markers = [
        "ThreadX",
        "tx_kernel_enter",
        "tx_thread_create",
        "_tx_initialize",
        "Azure RTOS ThreadX",
    ]

    data = firmware.data
    strings = _scan_strings(data)
    full_text = " ".join(strings)

    evidence: list[str] = []
    hits = 0

    for marker in markers:
        if marker in full_text:
            evidence.append(f"String found: '{marker}'")
            hits += 1

    # Version extraction from "Azure RTOS ThreadX vX.Y.Z" or similar
    version = _extract_version_from_strings(
        strings,
        [
            r"Azure RTOS ThreadX[^\d]*(\d+\.\d+[\.\d]*)",
            r"ThreadX[^\d]*v?(\d+\.\d+[\.\d]*)",
        ],
    )
    if version:
        evidence.append(f"Version extracted: {version}")

    if hits == 0:
        confidence = 0.0
    elif hits == 1:
        confidence = 0.35
    elif hits == 2:
        confidence = 0.60
    else:
        confidence = min(0.95, 0.60 + (hits - 2) * 0.10)

    return confidence, version, evidence


def _detect_zephyr(firmware: FirmwareImage) -> tuple[float, Optional[str], list[str]]:
    """Detect Zephyr RTOS by scanning for known strings."""
    markers = [
        "zephyr",
        "k_thread_create",
        "k_sem_init",
        "Zephyr OS",
    ]

    data = firmware.data
    strings = _scan_strings(data)
    full_text = " ".join(strings)

    evidence: list[str] = []
    hits = 0

    for marker in markers:
        if marker in full_text:
            evidence.append(f"String found: '{marker}'")
            hits += 1

    # CONFIG_ prefix is a strong Zephyr indicator if multiple occurrences
    config_count = full_text.count("CONFIG_")
    if config_count >= 3:
        evidence.append(f"CONFIG_ prefix found {config_count} times (Zephyr Kconfig)")
        hits += 1

    # Version extraction
    version = _extract_version_from_strings(
        strings,
        [
            r"Zephyr OS v(\d+\.\d+[\.\d]*)",
            r"Zephyr OS build (\S+)",
        ],
    )
    if version:
        evidence.append(f"Version extracted: {version}")

    if hits == 0:
        confidence = 0.0
    elif hits == 1:
        confidence = 0.35
    elif hits == 2:
        confidence = 0.60
    else:
        confidence = min(0.95, 0.60 + (hits - 2) * 0.10)

    return confidence, version, evidence


def _detect_rtems(firmware: FirmwareImage) -> tuple[float, Optional[str], list[str]]:
    """Detect RTEMS by scanning for known strings."""
    markers = [
        "RTEMS",
        "rtems_task_create",
        "rtems_semaphore",
        "RTEMS_SUCCESSFUL",
    ]

    data = firmware.data
    strings = _scan_strings(data)
    full_text = " ".join(strings)

    evidence: list[str] = []
    hits = 0

    for marker in markers:
        if marker in full_text:
            evidence.append(f"String found: '{marker}'")
            hits += 1

    version = _extract_version_from_strings(
        strings,
        [r"RTEMS[^\d]*(\d+\.\d+[\.\d]*)"],
    )
    if version:
        evidence.append(f"Version extracted: {version}")

    if hits == 0:
        confidence = 0.0
    elif hits == 1:
        confidence = 0.35
    elif hits == 2:
        confidence = 0.60
    else:
        confidence = min(0.95, 0.60 + (hits - 2) * 0.10)

    return confidence, version, evidence


def _detect_espressif(firmware: FirmwareImage) -> tuple[float, Optional[str], list[str]]:
    """Detect ESP-IDF (Espressif IoT Development Framework) by scanning for known strings.

    ESP-IDF wraps FreeRTOS internally, so detection also notes the underlying RTOS.
    """
    markers = [
        "ESP-IDF",
        "esp_idf",
        "IDF_VER",
        "esp_err_t",
        "esp_event",
        "esp_wifi",
        "esp_ble",
        "DROM",
        "IROM",
        "rtc_fast",
        "rtc_slow",
        "esp_chip_info",
        "CONFIG_IDF_TARGET",
        "sdkconfig",
        "menuconfig",
        "abort() was called at PC",
        "esp_ota",
        "esp_flash",
        "esp_partition",
    ]

    data = firmware.data
    strings = _scan_strings(data)
    full_text = " ".join(strings)

    evidence: list[str] = []
    hits = 0

    for marker in markers:
        if marker in full_text:
            evidence.append(f"String found: '{marker}'")
            hits += 1

    # Check for ESP32 memory segment markers in raw binary
    esp32_segments = [b"DROM", b"IROM", b"rtc_fast", b"rtc_slow"]
    for seg in esp32_segments:
        if seg in data and f"String found: '{seg.decode()}'" not in evidence:
            evidence.append(f"Binary marker: {seg.decode()}")
            hits += 1

    # Version extraction
    version = _extract_version_from_strings(
        strings,
        [
            r"IDF_VER[:\s]*v?(\d+\.\d+[\.\d]*)",
            r"ESP-IDF v?(\d+\.\d+[\.\d]*)",
            r"v(\d+\.\d+\.\d+)[\-\s]",
        ],
    )
    if version:
        evidence.append(f"Version extracted: {version}")

    # Note that ESP-IDF uses FreeRTOS internally
    if hits > 0:
        evidence.append("underlying_rtos: freertos (ESP-IDF wraps FreeRTOS)")

    # Confidence: scale by how many strong markers found
    if hits == 0:
        confidence = 0.0
    elif hits == 1:
        confidence = 0.35
    elif hits == 2:
        confidence = 0.55
    elif hits == 3:
        confidence = 0.70
    else:
        confidence = min(0.95, 0.70 + (hits - 3) * 0.05)

    return confidence, version, evidence


def fingerprint_firmware(firmware: FirmwareImage) -> RTOSFingerprint:
    """Run all RTOS detectors and return the best match."""
    detectors = [
        ("esp-idf", _detect_espressif),
        ("freertos", _detect_freertos),
        ("threadx", _detect_threadx),
        ("zephyr", _detect_zephyr),
        ("rtems", _detect_rtems),
    ]

    best_rtos = "unknown"
    best_confidence = 0.0
    best_version: Optional[str] = None
    best_evidence: list[str] = []

    for rtos_type, detector in detectors:
        confidence, version, evidence = detector(firmware)
        if confidence > best_confidence:
            best_confidence = confidence
            best_rtos = rtos_type
            best_version = version
            best_evidence = evidence

    if best_confidence < 0.2:
        return RTOSFingerprint(
            rtos_type="unknown",
            version=None,
            confidence=best_confidence,
            evidence=[],
        )

    return RTOSFingerprint(
        rtos_type=best_rtos,
        version=best_version,
        confidence=best_confidence,
        evidence=best_evidence,
    )
