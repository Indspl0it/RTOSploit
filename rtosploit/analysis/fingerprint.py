"""RTOS fingerprinting via symbol table, string, and binary pattern scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from rtosploit.utils.binary import FirmwareImage


@dataclass
class RTOSFingerprint:
    rtos_type: str  # "freertos" | "threadx" | "zephyr" | "rtems" | "esp-idf" | "unknown"
    version: Optional[str]
    confidence: float  # 0.0 to 1.0
    evidence: list[str] = field(default_factory=list)
    architecture: str = "unknown"
    mcu_family: str = "unknown"  # "nrf52", "stm32f4", "esp32", etc.
    vector_table: dict[str, int] = field(default_factory=dict)
    memory_map: list[dict] = field(default_factory=list)
    input_interfaces: list[str] = field(default_factory=list)
    symbol_count: int = 0


# ---------------------------------------------------------------------------
# RTOS symbol signatures
# ---------------------------------------------------------------------------

_RTOS_SYMBOLS: dict[str, list[str]] = {
    "freertos": [
        "vTaskStartScheduler",
        "pvPortMalloc",
        "xQueueGenericCreate",
        "xQueueCreate",
        "xTaskCreate",
        "xTaskCreateStatic",
        "vTaskDelay",
        "vTaskDelete",
        "xSemaphoreCreateMutex",
        "vPortFree",
        "xTimerCreate",
        "xEventGroupCreate",
    ],
    "threadx": [
        "tx_kernel_enter",
        "tx_thread_create",
        "_tx_initialize_kernel_enter",
        "tx_semaphore_create",
        "tx_queue_create",
        "tx_mutex_create",
        "tx_byte_pool_create",
        "tx_block_pool_create",
        "tx_timer_create",
    ],
    "zephyr": [
        "k_thread_create",
        "k_sem_init",
        "z_cstart",
        "k_mutex_init",
        "k_msgq_init",
        "k_timer_init",
        "z_thread_entry",
        "k_work_init",
    ],
    "rtems": [
        "rtems_task_create",
        "rtems_semaphore_create",
        "rtems_message_queue_create",
        "rtems_timer_create",
        "rtems_interrupt_handler_install",
    ],
    "esp-idf": [
        "esp_wifi_init",
        "esp_event_loop_create",
        "esp_event_loop_create_default",
        "esp_netif_init",
        "esp_ota_begin",
        "esp_flash_init",
        "esp_chip_info",
    ],
}

# ---------------------------------------------------------------------------
# RTOS string markers (for string-based fallback)
# ---------------------------------------------------------------------------

_RTOS_STRINGS: dict[str, list[str]] = {
    "freertos": [
        "FreeRTOS",
        "FreeRTOS Kernel V",
        "pvPortMalloc",
        "vTaskStartScheduler",
        "xQueueCreate",
    ],
    "threadx": [
        "ThreadX",
        "tx_kernel_enter",
        "tx_thread_create",
        "_tx_initialize",
        "Azure RTOS ThreadX",
    ],
    "zephyr": [
        "zephyr",
        "k_thread_create",
        "k_sem_init",
        "Zephyr OS",
    ],
    "rtems": [
        "RTEMS",
        "rtems_task_create",
        "rtems_semaphore",
        "RTEMS_SUCCESSFUL",
    ],
    "esp-idf": [
        "ESP-IDF",
        "esp_idf",
        "IDF_VER",
        "esp_err_t",
        "esp_event",
        "esp_wifi",
        "CONFIG_IDF_TARGET",
        "DROM",
        "IROM",
        "esp_chip_info",
        "sdkconfig",
        "abort() was called at PC",
        "esp_ota",
        "esp_flash",
        "esp_partition",
    ],
}

# ---------------------------------------------------------------------------
# Version patterns per RTOS
# ---------------------------------------------------------------------------

_VERSION_PATTERNS: dict[str, list[str]] = {
    "freertos": [
        r"FreeRTOS Kernel V(\d+\.\d+[\.\d]*)",
        r"FreeRTOS V(\d+\.\d+[\.\d]*)",
    ],
    "threadx": [
        r"Azure RTOS ThreadX[^\d]*(\d+\.\d+[\.\d]*)",
        r"ThreadX[^\d]*v?(\d+\.\d+[\.\d]*)",
    ],
    "zephyr": [
        r"Zephyr OS v(\d+\.\d+[\.\d]*)",
        r"Zephyr OS build v?(\d+\.\d+[\.\d]*)",
    ],
    "rtems": [
        r"RTEMS[^\d]*(\d+\.\d+[\.\d]*)",
    ],
    "esp-idf": [
        r"IDF_VER[:\s]*v?(\d+\.\d+[\.\d]*)",
        r"ESP-IDF v?(\d+\.\d+[\.\d]*)",
        r"IDF version\s*:\s*v?(\d+\.\d+[\.\d]*)",
        r"(?:[Ii][Dd][Ff]|[Ee][Ss][Pp]).{0,20}v(\d+\.\d+\.\d+)",
    ],
}

# ---------------------------------------------------------------------------
# MCU family detection tables
# ---------------------------------------------------------------------------

_MCU_SYMBOL_PREFIXES: list[tuple[list[str], str]] = [
    (["nrf_", "NRF_", "NRFX_", "nrfx_", "softdevice", "sd_ble"], "nrf52"),
    (["STM32", "stm32", "__HAL_RCC"], "stm32"),
    (["esp_", "CONFIG_IDF", "esp_idf"], "esp32"),
    (["LPC_", "CHIP_LPC", "Chip_"], "lpc"),
    (["cyhal_", "CYBLE_"], "psoc"),
    (["sam_", "SAMD", "SAME"], "sam"),
    (["ti_", "MAP_", "ROM_"], "ti"),
]

_MCU_PATH_FRAGMENTS: list[tuple[str, str]] = [
    ("nrfx/", "nrf52"),
    ("nrf_sdk", "nrf52"),
    ("nrf5", "nrf52"),
    ("stm32", "stm32"),
    ("esp-idf", "esp32"),
    ("esp32", "esp32"),
    ("lpc", "lpc"),
    ("samd", "sam"),
]

_MCU_FLASH_BASES: list[tuple[int, str]] = [
    (0x08000000, "stm32"),
    (0x00400000, "sam"),       # Atmel SAM
    (0x10000000, "rp2040"),    # RPi Pico
]

# ---------------------------------------------------------------------------
# Input interface patterns
# ---------------------------------------------------------------------------

_INTERFACE_PATTERNS: list[tuple[str, list[str]]] = [
    ("uart", ["uart", "UART", "usart", "USART", "serial"]),
    ("spi", ["spi_", "SPI_", "spi_transfer"]),
    ("i2c", ["i2c_", "I2C_", "twi_", "TWI_"]),
    ("ble", ["ble_", "BLE_", "gap_", "gatt_", "sd_ble", "bt_"]),
    ("usb", ["usb_", "USB_", "USBD_", "tud_"]),
    ("ethernet", ["eth_", "ETH_", "lwip", "LWIP", "tcp_", "udp_"]),
    ("wifi", ["wifi_", "WIFI_", "esp_wifi", "wlan_"]),
    ("can", ["can_", "CAN_", "canbus"]),
    ("adc", ["adc_", "ADC_", "nrf_adc", "HAL_ADC"]),
    ("gpio", ["gpio_", "GPIO_", "nrf_gpio", "HAL_GPIO"]),
]


# ---------------------------------------------------------------------------
# String scanning (section-aware)
# ---------------------------------------------------------------------------

def _scan_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Extract printable ASCII strings from raw bytes."""
    strings = []
    current: list[str] = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


def _scan_firmware_strings(firmware: FirmwareImage) -> list[str]:
    """Extract strings from firmware, using sections for ELF to avoid zero-fill."""
    if firmware.sections:
        all_strings: list[str] = []
        for sec in firmware.sections:
            if sec.data and len(sec.data) > 0:
                all_strings.extend(_scan_strings(sec.data))
        return all_strings
    return _scan_strings(firmware.data)


# ---------------------------------------------------------------------------
# Symbol-based RTOS detection (highest confidence)
# ---------------------------------------------------------------------------

def _detect_from_symbols(firmware: FirmwareImage) -> dict[str, tuple[float, list[str]]]:
    """Check firmware.symbols against known RTOS function names.

    Returns {rtos_type: (confidence, evidence_list)} for each RTOS with hits.
    """
    if not firmware.symbols:
        return {}

    sym_names = set(firmware.symbols.keys())
    results: dict[str, tuple[float, list[str]]] = {}

    for rtos, signatures in _RTOS_SYMBOLS.items():
        hits = [s for s in signatures if s in sym_names]
        if not hits:
            continue
        n = len(hits)
        if n == 1:
            conf = 0.60
        elif n == 2:
            conf = 0.80
        else:
            conf = min(0.98, 0.80 + (n - 2) * 0.05)
        evidence = [f"Symbol: {s}" for s in hits]
        results[rtos] = (conf, evidence)

    return results


# ---------------------------------------------------------------------------
# String-based RTOS detection (fallback for raw binaries)
# ---------------------------------------------------------------------------

def _detect_from_strings(firmware: FirmwareImage) -> dict[str, tuple[float, Optional[str], list[str]]]:
    """Scan firmware strings for RTOS markers.

    Returns {rtos_type: (confidence, version, evidence_list)}.
    """
    strings = _scan_firmware_strings(firmware)
    full_text = " ".join(strings)
    results: dict[str, tuple[float, Optional[str], list[str]]] = {}

    for rtos, markers in _RTOS_STRINGS.items():
        evidence: list[str] = []
        hits = 0
        for marker in markers:
            if marker in full_text:
                evidence.append(f"String: '{marker}'")
                hits += 1

        if hits == 0:
            continue

        # Version extraction
        version = None
        if rtos in _VERSION_PATTERNS:
            for pat in _VERSION_PATTERNS[rtos]:
                for s in strings:
                    m = re.search(pat, s)
                    if m:
                        version = m.group(1)
                        evidence.append(f"Version: {version}")
                        break
                if version:
                    break

        # Extra Zephyr heuristic
        if rtos == "zephyr":
            config_count = full_text.count("CONFIG_")
            if config_count >= 3:
                evidence.append(f"CONFIG_ prefix x{config_count} (Zephyr Kconfig)")
                hits += 1

        # Confidence scaling
        if hits == 1:
            conf = 0.35
        elif hits == 2:
            conf = 0.55
        elif hits == 3:
            conf = 0.70
        else:
            conf = min(0.95, 0.70 + (hits - 3) * 0.05)

        results[rtos] = (conf, version, evidence)

    return results


# ---------------------------------------------------------------------------
# MCU family detection
# ---------------------------------------------------------------------------

def _detect_mcu_family(firmware: FirmwareImage) -> tuple[str, list[str]]:
    """Detect MCU family from symbols, strings, memory map, and architecture.

    Symbol-based evidence is weighted higher (2 votes) than string/path
    fragments (1 vote) because symbols are a more reliable indicator —
    string fragments can appear in cross-compiled toolchain paths unrelated
    to the actual target MCU.
    """
    evidence: list[str] = []
    candidates: dict[str, int] = {}  # mcu -> vote count

    # 1. Symbol prefix matching (weight=2: more reliable than strings)
    if firmware.symbols:
        sym_names_lower = " ".join(firmware.symbols.keys())
        for prefixes, mcu in _MCU_SYMBOL_PREFIXES:
            for prefix in prefixes:
                if prefix in sym_names_lower:
                    candidates[mcu] = candidates.get(mcu, 0) + 2
                    evidence.append(f"Symbol prefix '{prefix}' -> {mcu}")
                    break  # one prefix per group is enough

    # 2. String/path fragment matching (weight=1)
    strings = _scan_firmware_strings(firmware)
    full_text = " ".join(strings)
    for fragment, mcu in _MCU_PATH_FRAGMENTS:
        if fragment in full_text:
            candidates[mcu] = candidates.get(mcu, 0) + 1
            evidence.append(f"String fragment '{fragment}' -> {mcu}")

    # 3. Flash base address heuristic
    if firmware.sections:
        for sec in firmware.sections:
            for flash_base, mcu in _MCU_FLASH_BASES:
                if sec.address == flash_base:
                    candidates[mcu] = candidates.get(mcu, 0) + 1
                    evidence.append(f"Flash base 0x{flash_base:08x} -> {mcu}")

    # 4. Architecture-based inference
    if firmware.architecture == "xtensa":
        candidates["esp32"] = candidates.get("esp32", 0) + 1
        evidence.append("Architecture xtensa -> esp32")

    if not candidates:
        # nRF52 special case: if architecture is armv7m and we have FreeRTOS symbols
        # but no specific MCU markers, check for nRF-specific patterns in symbol names
        if firmware.symbols:
            sym_text = " ".join(firmware.symbols.keys())
            if any(p in sym_text for p in ["nrf", "NRF", "nrfx", "softdevice", "sd_"]):
                return "nrf52", ["nRF symbol patterns found"]
        return "unknown", []

    # Return the MCU with the most votes
    best_mcu = max(candidates, key=lambda k: candidates[k])
    return best_mcu, evidence


# ---------------------------------------------------------------------------
# Hardware info extraction
# ---------------------------------------------------------------------------

def _extract_memory_map(firmware: FirmwareImage) -> list[dict]:
    """Build memory map from firmware sections."""
    mem_map = []
    for sec in firmware.sections:
        mem_map.append({
            "name": sec.name,
            "address": sec.address,
            "size": sec.size,
            "permissions": sec.permissions,
        })
    return sorted(mem_map, key=lambda m: m["address"])


def _detect_input_interfaces(firmware: FirmwareImage) -> list[str]:
    """Detect input peripherals from symbol/string names."""
    search_text = ""
    if firmware.symbols:
        search_text = " ".join(firmware.symbols.keys())

    detected = []
    for iface, patterns in _INTERFACE_PATTERNS:
        for pat in patterns:
            if pat in search_text:
                detected.append(iface)
                break
    return sorted(set(detected))


# ---------------------------------------------------------------------------
# Main fingerprinting function
# ---------------------------------------------------------------------------

def fingerprint_firmware(firmware: FirmwareImage) -> RTOSFingerprint:
    """Run all RTOS detectors and return the best match with hardware info."""

    best_rtos = "unknown"
    best_confidence = 0.0
    best_version: Optional[str] = None
    best_evidence: list[str] = []

    # 1. Symbol-based detection (highest confidence signal)
    sym_results = _detect_from_symbols(firmware)

    # 2. String-based detection (fallback / supplement)
    str_results = _detect_from_strings(firmware)

    # 3. Combine: symbol results take priority, strings supplement
    all_rtos = set(list(sym_results.keys()) + list(str_results.keys()))

    for rtos in all_rtos:
        combined_conf = 0.0
        combined_evidence: list[str] = []
        version = None

        if rtos in sym_results:
            sym_conf, sym_ev = sym_results[rtos]
            combined_conf = sym_conf
            combined_evidence.extend(sym_ev)

        if rtos in str_results:
            str_conf, str_ver, str_ev = str_results[rtos]
            # If we already have symbol evidence, strings boost slightly
            if combined_conf > 0:
                combined_conf = min(0.99, combined_conf + 0.05)
                combined_evidence.extend(str_ev)
            else:
                combined_conf = str_conf
                combined_evidence.extend(str_ev)
            version = str_ver

        if combined_conf > best_confidence:
            best_confidence = combined_conf
            best_rtos = rtos
            best_evidence = combined_evidence
            best_version = version

    # ESP-IDF special case: if we detect FreeRTOS symbols AND esp-idf markers, prefer esp-idf
    if best_rtos == "freertos" and "esp-idf" in sym_results:
        best_rtos = "esp-idf"
        esp_conf, esp_ev = sym_results["esp-idf"]
        best_evidence.extend(esp_ev)
        best_evidence.append("underlying_rtos: freertos (ESP-IDF wraps FreeRTOS)")
        best_confidence = max(best_confidence, esp_conf)
    elif best_rtos == "freertos" and "esp-idf" in str_results:
        str_conf, str_ver, str_ev = str_results["esp-idf"]
        if str_conf >= 0.50:
            best_rtos = "esp-idf"
            best_evidence.extend(str_ev)
            best_evidence.append("underlying_rtos: freertos (ESP-IDF wraps FreeRTOS)")
            if str_ver:
                best_version = str_ver

    if best_confidence < 0.2:
        best_rtos = "unknown"
        best_evidence = []

    # 4. MCU family detection
    mcu_family, mcu_evidence = _detect_mcu_family(firmware)
    best_evidence.extend(mcu_evidence)

    # 5. Hardware info extraction
    vector_table = {}
    if firmware.architecture in ("armv7m", "armv8m"):
        try:
            vector_table = firmware.get_vector_table()
        except ValueError:
            pass

    memory_map = _extract_memory_map(firmware)
    input_interfaces = _detect_input_interfaces(firmware)

    return RTOSFingerprint(
        rtos_type=best_rtos,
        version=best_version,
        confidence=best_confidence,
        evidence=best_evidence,
        architecture=firmware.architecture,
        mcu_family=mcu_family,
        vector_table=vector_table,
        memory_map=memory_map,
        input_interfaces=input_interfaces,
        symbol_count=len(firmware.symbols) if firmware.symbols else 0,
    )
