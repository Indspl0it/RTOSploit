"""Layer 2: SDK string fingerprinting for peripheral detection."""

from __future__ import annotations

import re
from typing import Optional

from rtosploit.analysis.detection.evidence import Evidence, EvidenceType, EVIDENCE_WEIGHTS
from rtosploit.analysis.fingerprint import _scan_firmware_strings
from rtosploit.utils.binary import FirmwareImage


# SDK-specific peripheral string patterns that survive in stripped binaries
# Format: (regex_pattern, peripheral_type, vendor, description)
_STRING_PATTERNS: list[tuple[str, str, str, str]] = [
    # STM32 HAL source file names (embedded in assert strings)
    (r"stm32\w+_hal_uart\.c", "uart", "stm32", "STM32 HAL UART source"),
    (r"stm32\w+_hal_usart\.c", "uart", "stm32", "STM32 HAL USART source"),
    (r"stm32\w+_hal_spi\.c", "spi", "stm32", "STM32 HAL SPI source"),
    (r"stm32\w+_hal_i2c\.c", "i2c", "stm32", "STM32 HAL I2C source"),
    (r"stm32\w+_hal_gpio\.c", "gpio", "stm32", "STM32 HAL GPIO source"),
    (r"stm32\w+_hal_tim\.c", "timer", "stm32", "STM32 HAL Timer source"),
    (r"stm32\w+_hal_adc\.c", "adc", "stm32", "STM32 HAL ADC source"),
    (r"stm32\w+_hal_can\.c", "can", "stm32", "STM32 HAL CAN source"),
    (r"stm32\w+_hal_dma\.c", "dma", "stm32", "STM32 HAL DMA source"),
    (r"stm32\w+_hal_rcc\.c", "clock", "stm32", "STM32 HAL RCC source"),
    (r"stm32\w+_hal_flash\.c", "flash", "stm32", "STM32 HAL Flash source"),
    (r"stm32\w+_hal_pcd\.c", "usb", "stm32", "STM32 HAL USB source"),

    # Nordic SDK driver references
    (r"nrf_drv_uart", "uart", "nrf5", "Nordic UART driver"),
    (r"nrfx_uarte", "uart", "nrf5", "Nordic UARTE driver"),
    (r"nrf_drv_spi", "spi", "nrf5", "Nordic SPI driver"),
    (r"nrfx_spim", "spi", "nrf5", "Nordic SPIM driver"),
    (r"nrf_drv_twi", "i2c", "nrf5", "Nordic TWI driver"),
    (r"nrfx_twim", "i2c", "nrf5", "Nordic TWIM driver"),
    (r"nrf_drv_gpiote", "gpio", "nrf5", "Nordic GPIO driver"),
    (r"nrf_drv_timer", "timer", "nrf5", "Nordic Timer driver"),
    (r"nrf_drv_wdt", "wdt", "nrf5", "Nordic WDT driver"),
    (r"nrf_radio", "radio", "nrf5", "Nordic Radio driver"),

    # ESP-IDF function/module strings
    (r"uart_driver_install", "uart", "esp32", "ESP-IDF UART driver"),
    (r"uart_param_config", "uart", "esp32", "ESP-IDF UART config"),
    (r"spi_bus_initialize", "spi", "esp32", "ESP-IDF SPI bus init"),
    (r"spi_device_transmit", "spi", "esp32", "ESP-IDF SPI transmit"),
    (r"i2c_driver_install", "i2c", "esp32", "ESP-IDF I2C driver"),
    (r"i2c_param_config", "i2c", "esp32", "ESP-IDF I2C config"),
    (r"gpio_config", "gpio", "esp32", "ESP-IDF GPIO config"),
    (r"esp_wifi_init", "wifi", "esp32", "ESP-IDF WiFi init"),
    (r"esp_wifi_start", "wifi", "esp32", "ESP-IDF WiFi start"),

    # Zephyr devicetree node patterns
    (r"uart@[0-9a-fA-F]+", "uart", "zephyr", "Zephyr DT UART node"),
    (r"spi@[0-9a-fA-F]+", "spi", "zephyr", "Zephyr DT SPI node"),
    (r"i2c@[0-9a-fA-F]+", "i2c", "zephyr", "Zephyr DT I2C node"),
    (r"gpio@[0-9a-fA-F]+", "gpio", "zephyr", "Zephyr DT GPIO node"),

    # Generic peripheral keywords (low weight, only as supplement)
    (r"UART[0-9]? (error|timeout|overflow)", "uart", "", "UART error string"),
    (r"SPI[0-9]? (error|timeout)", "spi", "", "SPI error string"),
    (r"I2C[0-9]? (error|timeout|nack)", "i2c", "", "I2C error string"),
]


def detect_from_strings(firmware: FirmwareImage) -> list[Evidence]:
    """Detect peripherals from SDK-specific strings in firmware."""
    strings = _scan_firmware_strings(firmware)
    if not strings:
        return []

    full_text = "\n".join(strings)
    evidence: list[Evidence] = []
    seen: set[tuple[str, str]] = set()  # Dedup by (pattern_desc, peripheral_type)

    for pattern, ptype, vendor, desc in _STRING_PATTERNS:
        key = (desc, ptype)
        if key in seen:
            continue

        matches = re.findall(pattern, full_text, re.IGNORECASE)
        if not matches:
            continue

        seen.add(key)
        peripheral_name = ptype.upper()

        # Try to extract instance number from match
        for m in matches:
            instance = _extract_instance(m, ptype)
            if instance:
                peripheral_name = instance
                break

        evidence.append(Evidence(
            type=EvidenceType.SDK_STRING,
            peripheral=peripheral_name,
            weight=EVIDENCE_WEIGHTS[EvidenceType.SDK_STRING],
            detail=f"{desc}: {matches[0]}",
            vendor=vendor,
            peripheral_type=ptype,
        ))

    return evidence


def _extract_instance(text: str, peripheral_type: str) -> Optional[str]:
    """Try to extract a peripheral instance name like UART1 from a string match."""
    ptype_upper = peripheral_type.upper()
    match = re.search(rf'({ptype_upper}\d+)', text, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return None
