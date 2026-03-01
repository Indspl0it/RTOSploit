"""Hardcoded vendor peripheral memory maps for MCU families without SVD."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PeripheralMapEntry:
    """A peripheral in a vendor memory map."""
    name: str
    base_address: int
    size: int
    peripheral_type: str  # "uart", "spi", "i2c", "gpio", etc.


# STM32F4xx peripheral map (~27 entries)
_STM32F4_MAP: list[PeripheralMapEntry] = [
    PeripheralMapEntry("USART1", 0x40011000, 0x400, "uart"),
    PeripheralMapEntry("USART2", 0x40004400, 0x400, "uart"),
    PeripheralMapEntry("USART3", 0x40004800, 0x400, "uart"),
    PeripheralMapEntry("UART4",  0x40004C00, 0x400, "uart"),
    PeripheralMapEntry("UART5",  0x40005000, 0x400, "uart"),
    PeripheralMapEntry("USART6", 0x40011400, 0x400, "uart"),
    PeripheralMapEntry("SPI1",   0x40013000, 0x400, "spi"),
    PeripheralMapEntry("SPI2",   0x40003800, 0x400, "spi"),
    PeripheralMapEntry("SPI3",   0x40003C00, 0x400, "spi"),
    PeripheralMapEntry("I2C1",   0x40005400, 0x400, "i2c"),
    PeripheralMapEntry("I2C2",   0x40005800, 0x400, "i2c"),
    PeripheralMapEntry("I2C3",   0x40005C00, 0x400, "i2c"),
    PeripheralMapEntry("GPIOA",  0x40020000, 0x400, "gpio"),
    PeripheralMapEntry("GPIOB",  0x40020400, 0x400, "gpio"),
    PeripheralMapEntry("GPIOC",  0x40020800, 0x400, "gpio"),
    PeripheralMapEntry("GPIOD",  0x40020C00, 0x400, "gpio"),
    PeripheralMapEntry("GPIOE",  0x40021000, 0x400, "gpio"),
    PeripheralMapEntry("RCC",    0x40023800, 0x400, "clock"),
    PeripheralMapEntry("TIM1",   0x40010000, 0x400, "timer"),
    PeripheralMapEntry("TIM2",   0x40000000, 0x400, "timer"),
    PeripheralMapEntry("TIM3",   0x40000400, 0x400, "timer"),
    PeripheralMapEntry("TIM4",   0x40000800, 0x400, "timer"),
    PeripheralMapEntry("ADC1",   0x40012000, 0x400, "adc"),
    PeripheralMapEntry("DMA1",   0x40026000, 0x400, "dma"),
    PeripheralMapEntry("DMA2",   0x40026400, 0x400, "dma"),
    PeripheralMapEntry("FLASH",  0x40023C00, 0x400, "flash"),
    PeripheralMapEntry("CAN1",   0x40006400, 0x400, "can"),
    PeripheralMapEntry("USB_OTG_FS", 0x50000000, 0x40000, "usb"),
]

# nRF52 peripheral map (~17 entries)
_NRF52_MAP: list[PeripheralMapEntry] = [
    PeripheralMapEntry("UART0",   0x40002000, 0x1000, "uart"),
    PeripheralMapEntry("UARTE0",  0x40002000, 0x1000, "uart"),
    PeripheralMapEntry("SPI0",    0x40003000, 0x1000, "spi"),
    PeripheralMapEntry("SPI1",    0x40004000, 0x1000, "spi"),
    PeripheralMapEntry("TWI0",    0x40003000, 0x1000, "i2c"),
    PeripheralMapEntry("TWI1",    0x40004000, 0x1000, "i2c"),
    PeripheralMapEntry("GPIOTE",  0x40006000, 0x1000, "gpio"),
    PeripheralMapEntry("TIMER0",  0x40008000, 0x1000, "timer"),
    PeripheralMapEntry("TIMER1",  0x40009000, 0x1000, "timer"),
    PeripheralMapEntry("TIMER2",  0x4000A000, 0x1000, "timer"),
    PeripheralMapEntry("RTC0",    0x4000B000, 0x1000, "rtc"),
    PeripheralMapEntry("RNG",     0x4000D000, 0x1000, "rng"),
    PeripheralMapEntry("WDT",     0x40010000, 0x1000, "wdt"),
    PeripheralMapEntry("RADIO",   0x40001000, 0x1000, "radio"),
    PeripheralMapEntry("GPIO",    0x50000000, 0x1000, "gpio"),
    PeripheralMapEntry("NVMC",    0x4001E000, 0x1000, "flash"),
    PeripheralMapEntry("FICR",    0x10000000, 0x1000, "system"),
]

# ESP32 peripheral map (~13 entries)
_ESP32_MAP: list[PeripheralMapEntry] = [
    PeripheralMapEntry("UART0",  0x3FF40000, 0x1000, "uart"),
    PeripheralMapEntry("UART1",  0x3FF50000, 0x1000, "uart"),
    PeripheralMapEntry("UART2",  0x3FF6E000, 0x1000, "uart"),
    PeripheralMapEntry("SPI0",   0x3FF43000, 0x1000, "spi"),
    PeripheralMapEntry("SPI1",   0x3FF42000, 0x1000, "spi"),
    PeripheralMapEntry("SPI2",   0x3FF64000, 0x1000, "spi"),
    PeripheralMapEntry("SPI3",   0x3FF65000, 0x1000, "spi"),
    PeripheralMapEntry("I2C0",   0x3FF53000, 0x1000, "i2c"),
    PeripheralMapEntry("I2C1",   0x3FF67000, 0x1000, "i2c"),
    PeripheralMapEntry("GPIO",   0x3FF44000, 0x1000, "gpio"),
    PeripheralMapEntry("TIMER0", 0x3FF5F000, 0x1000, "timer"),
    PeripheralMapEntry("TIMER1", 0x3FF60000, 0x1000, "timer"),
    PeripheralMapEntry("RTC",    0x3FF48000, 0x1000, "rtc"),
    PeripheralMapEntry("WIFI",   0x3FF73000, 0x1000, "wifi"),
]

_VENDOR_MAPS: dict[str, list[PeripheralMapEntry]] = {
    "stm32": _STM32F4_MAP,
    "stm32f4": _STM32F4_MAP,
    "nrf52": _NRF52_MAP,
    "nrf52832": _NRF52_MAP,
    "nrf52840": _NRF52_MAP,
    "esp32": _ESP32_MAP,
}


def get_vendor_peripheral_map(mcu_family: str) -> list[PeripheralMapEntry]:
    """Get the peripheral map for a given MCU family. Returns empty list if unknown."""
    return _VENDOR_MAPS.get(mcu_family.lower(), [])


def lookup_address(mcu_family: str, address: int) -> Optional[PeripheralMapEntry]:
    """Look up a peripheral by address in the vendor map."""
    for entry in get_vendor_peripheral_map(mcu_family):
        if entry.base_address <= address < entry.base_address + entry.size:
            return entry
    return None
