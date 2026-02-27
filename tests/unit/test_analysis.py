"""Unit tests for the rtosploit.analysis package."""

from __future__ import annotations

import struct

import pytest

from rtosploit.utils.binary import FirmwareImage, BinaryFormat
from rtosploit.analysis.fingerprint import (
    RTOSFingerprint,
    fingerprint_firmware,
    _detect_freertos,
    _detect_threadx,
    _detect_zephyr,
)
from rtosploit.analysis.heap_detect import HeapInfo, detect_heap
from rtosploit.analysis.mpu_check import (
    MPUConfig,
    MPURegion,
    _parse_rasr,
    _detect_vulnerabilities,
    check_mpu,
)
from rtosploit.analysis.strings import (
    extract_strings,
    categorize_string,
    find_format_string_vulnerabilities,
    extract_rtos_strings,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_firmware_with_strings(*strings: str, base: int = 0x08000000) -> FirmwareImage:
    """Build a synthetic FirmwareImage embedding the given null-terminated strings."""
    data = b"\x00" * 0x100  # leading padding
    for s in strings:
        data += s.encode("ascii") + b"\x00"
    data += b"\x00" * 0x100
    return FirmwareImage(
        data=data,
        base_address=base,
        format=BinaryFormat.RAW,
        entry_point=base,
        symbols={},
    )


def make_empty_firmware(size: int = 0x400, base: int = 0x08000000) -> FirmwareImage:
    """Build a firmware image filled with zero bytes (no strings)."""
    return FirmwareImage(
        data=b"\x00" * size,
        base_address=base,
        format=BinaryFormat.RAW,
        entry_point=base,
        symbols={},
    )


# ---------------------------------------------------------------------------
# 1. fingerprint_firmware — FreeRTOS detection
# ---------------------------------------------------------------------------

def test_fingerprint_freertos_detected():
    fw = make_firmware_with_strings(
        "FreeRTOS",
        "pvPortMalloc",
        "vTaskStartScheduler",
        "xQueueCreate",
    )
    fp = fingerprint_firmware(fw)
    assert fp.rtos_type == "freertos"
    assert fp.confidence >= 0.5


# ---------------------------------------------------------------------------
# 2. fingerprint_firmware — ThreadX detection
# ---------------------------------------------------------------------------

def test_fingerprint_threadx_detected():
    fw = make_firmware_with_strings(
        "ThreadX",
        "tx_kernel_enter",
        "tx_thread_create",
    )
    fp = fingerprint_firmware(fw)
    assert fp.rtos_type == "threadx"
    assert fp.confidence >= 0.5


# ---------------------------------------------------------------------------
# 3. fingerprint_firmware — Zephyr detection
# ---------------------------------------------------------------------------

def test_fingerprint_zephyr_detected():
    fw = make_firmware_with_strings(
        "Zephyr OS",
        "k_thread_create",
        "k_sem_init",
        "zephyr",
    )
    fp = fingerprint_firmware(fw)
    assert fp.rtos_type == "zephyr"
    assert fp.confidence >= 0.5


# ---------------------------------------------------------------------------
# 4. fingerprint_firmware — unknown when no markers
# ---------------------------------------------------------------------------

def test_fingerprint_unknown_no_markers():
    fw = make_empty_firmware()
    fp = fingerprint_firmware(fw)
    assert fp.rtos_type == "unknown"


# ---------------------------------------------------------------------------
# 5. Version extraction from FreeRTOS version string
# ---------------------------------------------------------------------------

def test_fingerprint_freertos_version_extraction():
    fw = make_firmware_with_strings(
        "FreeRTOS",
        "pvPortMalloc",
        "vTaskStartScheduler",
        "FreeRTOS Kernel V10.4.3",
    )
    fp = fingerprint_firmware(fw)
    assert fp.rtos_type == "freertos"
    assert fp.version == "10.4.3"


# ---------------------------------------------------------------------------
# 6. Version extraction — FreeRTOS V11 shorthand
# ---------------------------------------------------------------------------

def test_fingerprint_freertos_v11_shorthand():
    fw = make_firmware_with_strings(
        "FreeRTOS",
        "pvPortMalloc",
        "FreeRTOS V11.0.1",
    )
    fp = fingerprint_firmware(fw)
    assert fp.rtos_type == "freertos"
    assert fp.version is not None
    assert fp.version.startswith("11")


# ---------------------------------------------------------------------------
# 7. extract_strings — correct addresses and content
# ---------------------------------------------------------------------------

def test_extract_strings_basic():
    # Build firmware: 0x100 zero padding then "Hello\0World\0"
    data = b"\x00" * 0x100 + b"Hello\x00World\x00" + b"\x00" * 0x10
    fw = FirmwareImage(
        data=data,
        base_address=0x08000000,
        format=BinaryFormat.RAW,
        entry_point=0x08000000,
        symbols={},
    )
    strings = extract_strings(fw)
    texts = [s for _, s in strings]
    assert "Hello" in texts
    assert "World" in texts


def test_extract_strings_min_length_filtered():
    data = b"\x00" * 0x10 + b"Hi\x00" + b"LongString\x00" + b"\x00" * 0x10
    fw = FirmwareImage(
        data=data,
        base_address=0x0,
        format=BinaryFormat.RAW,
        entry_point=0x0,
        symbols={},
    )
    strings = extract_strings(fw, min_length=4)
    texts = [s for _, s in strings]
    assert "Hi" not in texts          # too short
    assert "LongString" in texts


def test_extract_strings_address_correct():
    pad = 0x200
    data = b"\x00" * pad + b"Marker\x00" + b"\x00" * 0x10
    base = 0x08000000
    fw = FirmwareImage(
        data=data,
        base_address=base,
        format=BinaryFormat.RAW,
        entry_point=base,
        symbols={},
    )
    strings = extract_strings(fw)
    found = [(addr, s) for addr, s in strings if s == "Marker"]
    assert found, "Expected 'Marker' in extracted strings"
    addr, _ = found[0]
    assert addr == base + pad


# ---------------------------------------------------------------------------
# 8. categorize_string — each category
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("s,expected", [
    ("https://example.com/api", "url"),
    ("http://192.168.1.1/config", "url"),
    ("/etc/passwd", "path"),
    ("/home/user/file.bin", "path"),
    ("1.2.3", "version"),
    ("v10.4.0-rc1", "version"),
    ("Error: assertion failed", "error"),
    ("ASSERT: null pointer", "error"),
    ("debug output enabled", "debug"),
    ("trace: entering function", "debug"),
    ("printf format: %s", "format_string"),
    ("write %d bytes to %x", "format_string"),
    ("CONFIG_HEAP_SIZE", "config"),
    ("malloc_task_create", "function"),
    ("Hello World! 123 random text", "other"),
])
def test_categorize_string(s, expected):
    assert categorize_string(s) == expected


# ---------------------------------------------------------------------------
# 9. find_format_string_vulnerabilities — flags %n strings
# ---------------------------------------------------------------------------

def test_find_format_string_vulnerabilities_flags_pct_n():
    fw = make_firmware_with_strings(
        "safe string no specifier",
        "user input: %n overwrite",
        "also: %s injection",
        "clean string here",
    )
    vulns = find_format_string_vulnerabilities(fw)
    vuln_strings = [s for _, s in vulns]
    assert any("%n" in s for s in vuln_strings), "Expected %n string flagged"


def test_find_format_string_vulnerabilities_no_false_positives():
    fw = make_firmware_with_strings(
        "clean string one",
        "another safe string",
        "no format specifiers here",
    )
    vulns = find_format_string_vulnerabilities(fw)
    assert vulns == []


# ---------------------------------------------------------------------------
# 10. _parse_rasr — correct field extraction
# ---------------------------------------------------------------------------

def test_parse_rasr_fields():
    # Construct RASR: XN=0, AP=3, SIZE=17 (2^18=256KB), ENABLE=1
    # AP in bits [26:24], SIZE in bits [5:1], ENABLE in bit 0
    ap = 3
    size_field = 17  # actual = 2^18 = 262144
    xn = 0
    enable = 1
    rasr = (xn << 28) | (ap << 24) | (size_field << 1) | enable

    parsed = _parse_rasr(rasr)
    assert parsed["ap"] == 3
    assert parsed["size_bytes"] == 2 ** (17 + 1)
    assert parsed["xn"] == False
    assert parsed["enable"] == True
    assert parsed["executable"] == True


def test_parse_rasr_xn_set():
    # XN=1 means NOT executable
    rasr = (1 << 28) | (1 << 24) | (0b01010 << 1) | 1
    parsed = _parse_rasr(rasr)
    assert parsed["xn"] == True
    assert parsed["executable"] == False


# ---------------------------------------------------------------------------
# 11. _detect_vulnerabilities — flags SRAM executable region
# ---------------------------------------------------------------------------

def test_detect_vulnerabilities_sram_executable():
    region = MPURegion(
        region_number=0,
        base_address=0x20000000,  # SRAM
        size=0x10000,
        permissions=3,
        executable=True,
        enabled=True,
    )
    vulns = _detect_vulnerabilities([region])
    assert any("executable" in v.lower() for v in vulns), (
        "Expected SRAM executable vulnerability flagged"
    )


def test_detect_vulnerabilities_no_enabled_regions():
    region = MPURegion(
        region_number=0,
        base_address=0x20000000,
        size=0x10000,
        permissions=3,
        executable=True,
        enabled=False,
    )
    vulns = _detect_vulnerabilities([region])
    assert any("disabled" in v.lower() or "no mpu" in v.lower() for v in vulns)


def test_detect_vulnerabilities_full_access_ap3():
    region = MPURegion(
        region_number=2,
        base_address=0x08000000,
        size=0x80000,
        permissions=3,
        executable=False,
        enabled=True,
    )
    vulns = _detect_vulnerabilities([region])
    assert any("ap=3" in v.lower() or "full" in v.lower() for v in vulns)


# ---------------------------------------------------------------------------
# 12. detect_heap — FreeRTOS firmware returns a HeapInfo
# ---------------------------------------------------------------------------

def test_detect_heap_freertos():
    fw = make_firmware_with_strings(
        "FreeRTOS",
        "pvPortMalloc",
        "vPortFree",
        "vTaskStartScheduler",
    )
    fp = RTOSFingerprint(
        rtos_type="freertos",
        version=None,
        confidence=0.8,
        evidence=[],
    )
    info = detect_heap(fw, fp)
    assert isinstance(info, HeapInfo)
    assert info.allocator_type in {"heap_1", "heap_2", "heap_3", "heap_4", "heap_5"}


def test_detect_heap_freertos_heap5_detected():
    fw = make_firmware_with_strings(
        "FreeRTOS",
        "pvPortMalloc",
        "vPortFree",
        "vPortDefineHeapRegions",
    )
    fp = RTOSFingerprint(
        rtos_type="freertos",
        version=None,
        confidence=0.8,
        evidence=[],
    )
    info = detect_heap(fw, fp)
    assert info.allocator_type == "heap_5"


def test_detect_heap_unknown_rtos():
    fw = make_empty_firmware()
    fp = RTOSFingerprint(
        rtos_type="unknown",
        version=None,
        confidence=0.0,
        evidence=[],
    )
    info = detect_heap(fw, fp)
    assert info.allocator_type == "unknown"


# ---------------------------------------------------------------------------
# 13. extract_rtos_strings — FreeRTOS filters task names
# ---------------------------------------------------------------------------

def test_extract_rtos_strings_freertos():
    fw = make_firmware_with_strings(
        "IdleTask",
        "TimerTask",
        "This is a very long string that should NOT be a task name",
        "FreeRTOS",
    )
    results = extract_rtos_strings(fw, "freertos")
    texts = [s for _, s in results]
    assert "IdleTask" in texts
    assert "TimerTask" in texts
    # Long strings with spaces should be excluded
    assert not any("very long string" in t for t in texts)


# ---------------------------------------------------------------------------
# 14. extract_rtos_strings — Zephyr filters CONFIG_ strings
# ---------------------------------------------------------------------------

def test_extract_rtos_strings_zephyr():
    fw = make_firmware_with_strings(
        "CONFIG_HEAP_SIZE",
        "CONFIG_NUM_THREADS",
        "not a config string",
        "Zephyr OS",
    )
    results = extract_rtos_strings(fw, "zephyr")
    texts = [s for _, s in results]
    assert "CONFIG_HEAP_SIZE" in texts
    assert "CONFIG_NUM_THREADS" in texts
    assert "not a config string" not in texts


# ---------------------------------------------------------------------------
# 15. RTOSFingerprint dataclass initialises correctly
# ---------------------------------------------------------------------------

def test_rtos_fingerprint_defaults():
    fp = RTOSFingerprint(rtos_type="freertos", version="10.4.3", confidence=0.9)
    assert fp.evidence == []
    assert fp.rtos_type == "freertos"
    assert fp.confidence == 0.9
