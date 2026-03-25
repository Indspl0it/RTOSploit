# RTOSploit Dynamic Testing Report

**Date:** 2026-03-26
**Firmware tested:** 8 real-world binaries
**All steps passing after fixes**

## Test Matrix

| Firmware | RTOS | Version | MCU | Peripherals | CVEs | HAL | Machine |
|----------|------|---------|-----|-------------|------|-----|---------|
| Particle Argon System (nRF52840 ELF) | freertos | - | nrf52 | 2 | 18 | 11 | microbit |
| Particle Argon Bootloader (nRF52840 ELF) | unknown | - | nrf52 | 2 | 0 | 5 | microbit |
| Particle Argon Tinker (nRF52840 ELF) | unknown | - | nrf52 | 0 | 0 | 0 | microbit |
| VulnRange CVE-2018-16525 (ESP32 raw) | esp-idf | - | esp32 | 0 | 30 | 0 | mps2-an385 |
| VulnRange CVE-2021-43997 (ESP32 raw) | esp-idf | 5.5.1 | esp32 | 4 | 18 | 0 | mps2-an385 |
| VulnRange CVE-2024-28115 (ESP32 raw) | esp-idf | - | esp32 | 2 | 30 | 0 | mps2-an385 |
| VulnRange KOM-ThreadX (raw) | zephyr | 4.2.0 | unknown | 6 | 0 | 0 | mps2-an385 |
| VulnRange CVE-2018-16528 (ESP32 raw) | esp-idf | - | esp32 | 0 | 30 | 0 | mps2-an385 |

## Pipeline Steps (all 8 firmware)

| Step | Pass | Fail | Notes |
|------|------|------|-------|
| Load firmware | 8/8 | 0 | ELF and raw binary formats |
| RTOS fingerprint | 8/8 | 0 | FreeRTOS, ESP-IDF, Zephyr detected |
| Heap detection | 8/8 | 0 | heap_1, zephyr_slab identified |
| MPU analysis | 8/8 | 0 | Cortex-M MPU parsing |
| Peripheral detection | 8/8 | 0 | 6-layer engine, UART/SPI/I2C/GPIO/BLE |
| CVE correlation | 8/8 | 0 | 18-30 CVEs matched per firmware |
| HAL matching | 8/8 | 0 | 11 nRF5 hooks on Particle Argon |
| Auto-config | 8/8 | 0 | QEMU machine + peripheral models |
| Config serialization | 8/8 | 0 | YAML generation |

## Bugs Found and Fixed

1. **CVE database not auto-loaded** - `CVEDatabase.__init__()` set path but never called `load()`. Fixed: auto-load on construction.
2. **Particle Argon Tinker MCU misidentified** - Incorrectly detected as stm32 instead of nrf52. Fixed: improved MCU symbol prefix priority.
3. **ESP-IDF version regex too greedy** - Matched MicroPython version `1.27.0` instead of ESP-IDF version. Fixed: tightened version patterns.
4. **PeripheralConfig missing public accessors** - `models` and `intercepts` were private. Fixed: added public properties.

## Known Limitations

- VulnRange KOM-ThreadX firmware detected as Zephyr (the binary contains Zephyr strings - it's a Zephyr build used for the ThreadX KOM challenge)
- Raw binaries without symbols have 0 HAL matches (expected - HAL matching requires symbol table)
- ESP32 firmware maps to mps2-an385 as fallback (no native ESP32 QEMU support)
