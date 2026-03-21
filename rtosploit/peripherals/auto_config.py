"""Auto-configuration generator for peripheral rehosting.

Given a FirmwareImage and optional fingerprint/SVD data, generates a complete
PeripheralConfig with model specs and intercept hooks — zero manual config needed.

Phase 3 of the Layered Hybrid Firmware Rehosting plan.
"""

from __future__ import annotations

import logging
from typing import Optional

import yaml

from rtosploit.analysis.fingerprint import RTOSFingerprint, fingerprint_firmware
from rtosploit.peripherals.config import InterceptSpec, PeripheralConfig, PeripheralModelSpec
from rtosploit.peripherals.hal_database import HALDatabase, HALFunctionEntry
from rtosploit.peripherals.svd_cache import SVDCache
from rtosploit.peripherals.svd_model import SVDDevice, SVDPeripheral
from rtosploit.utils.binary import FirmwareImage

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 3.1 MCU-to-QEMU Machine Mapping
# ---------------------------------------------------------------------------

# MCU family -> QEMU machine name
_MCU_TO_MACHINE: dict[str, str] = {
    "stm32f1": "stm32vldiscovery",
    "stm32f2": "netduino2",
    "stm32f4": "netduino2",
    "stm32l4": "b-l475e-iot01a",
    "nrf51": "microbit",
    "nrf52": "microbit",
    "nrf52832": "microbit",
    "nrf52840": "microbit",
    "lm3s": "lm3s6965evb",
    "mps2": "mps2-an385",
    "rp2040": "mps2-an385",  # fallback, no native support
    "sam": "mps2-an385",
    "esp32": "mps2-an385",  # fallback
}

# Architecture fallbacks
_ARCH_FALLBACK_MACHINE: dict[str, str] = {
    "armv7m": "mps2-an385",
    "armv8m": "mps2-an505",
    "riscv32": "sifive_e",
}


def resolve_qemu_machine(mcu_family: str, architecture: str = "armv7m") -> str:
    """Resolve QEMU machine name from MCU family, with architecture fallback."""
    key = mcu_family.lower()
    machine = _MCU_TO_MACHINE.get(key)
    if machine is not None:
        return machine

    # Try prefix match: "stm32f407" -> "stm32f4"
    for prefix in sorted(_MCU_TO_MACHINE.keys(), key=len, reverse=True):
        if key.startswith(prefix):
            return _MCU_TO_MACHINE[prefix]

    # Architecture fallback
    arch_key = architecture.lower()
    return _ARCH_FALLBACK_MACHINE.get(arch_key, "mps2-an385")


# ---------------------------------------------------------------------------
# Model class selection map
# ---------------------------------------------------------------------------

_MODEL_CLASS_MAP: dict[tuple[str, str], str] = {
    ("stm32", "uart"): "rtosploit.peripherals.models.stm32_hal.STM32UART",
    ("stm32", "spi"): "rtosploit.peripherals.models.stm32_hal.STM32SPI",
    ("stm32", "i2c"): "rtosploit.peripherals.models.stm32_hal.STM32I2C",
    ("stm32", "gpio"): "rtosploit.peripherals.models.stm32_hal.STM32GPIO",
    ("stm32", "clock"): "rtosploit.peripherals.models.stm32_hal.STM32RCC",
    ("stm32", "flash"): "rtosploit.peripherals.models.stm32_hal.STM32Flash",
    ("stm32", "timer"): "rtosploit.peripherals.models.stm32_hal.STM32Timer",
    ("stm32", "init"): "rtosploit.peripherals.models.stm32_hal.STM32HALBase",
    ("nrf5", "uart"): "rtosploit.peripherals.models.nrf5_hal.NRF5UART",
    ("nrf5", "spi"): "rtosploit.peripherals.models.nrf5_hal.NRF5SPI",
    ("nrf5", "i2c"): "rtosploit.peripherals.models.nrf5_hal.NRF5TWI",
    ("nrf5", "gpio"): "rtosploit.peripherals.models.nrf5_hal.NRF5GPIO",
    ("nrf5", "ble"): "rtosploit.peripherals.models.nrf5_hal.NRF5BLE",
    ("nrf5", "timer"): "rtosploit.peripherals.models.nrf5_hal.NRF5Timer",
    ("nrf5", "init"): "rtosploit.peripherals.models.nrf5_hal.NRF5Base",
    ("nrf5", "clock"): "rtosploit.peripherals.models.nrf5_hal.NRF5Base",
    ("nrf5", "power"): "rtosploit.peripherals.models.nrf5_hal.NRF5Base",
    ("zephyr", "uart"): "rtosploit.peripherals.models.zephyr_hal.ZephyrUART",
    ("zephyr", "spi"): "rtosploit.peripherals.models.zephyr_hal.ZephyrSPI",
    ("zephyr", "i2c"): "rtosploit.peripherals.models.zephyr_hal.ZephyrI2C",
    ("zephyr", "gpio"): "rtosploit.peripherals.models.zephyr_hal.ZephyrGPIO",
    ("zephyr", "ble"): "rtosploit.peripherals.models.zephyr_hal.ZephyrBLE",
    ("zephyr", "init"): "rtosploit.peripherals.models.zephyr_hal.ZephyrBase",
}

_DEFAULT_MODEL_CLASS = "rtosploit.peripherals.models.generic.ReturnZero"

# ---------------------------------------------------------------------------
# Critical peripheral whitelist — always include even if not directly referenced
# ---------------------------------------------------------------------------

_CRITICAL_PERIPHERAL_TYPES: set[str] = {"clock", "power", "flash"}
_CRITICAL_PERIPHERAL_NAMES: set[str] = {"RCC", "CLOCK", "POWER", "FLASH", "NVIC"}

# ---------------------------------------------------------------------------
# Vendor detection from MCU family
# ---------------------------------------------------------------------------

_MCU_TO_VENDOR: dict[str, str] = {
    "stm32": "stm32",
    "stm32f1": "stm32",
    "stm32f2": "stm32",
    "stm32f4": "stm32",
    "stm32l4": "stm32",
    "nrf51": "nrf5",
    "nrf52": "nrf5",
    "nrf52832": "nrf5",
    "nrf52840": "nrf5",
    "lm3s": "stm32",  # TI Stellaris, closest HAL match
    "mps2": "stm32",
    "rp2040": "stm32",
    "sam": "stm32",
    "esp32": "zephyr",
    "lpc": "stm32",
}


def _vendor_from_mcu(mcu_family: str) -> str:
    """Resolve vendor name from MCU family for model class selection."""
    key = mcu_family.lower()
    vendor = _MCU_TO_VENDOR.get(key)
    if vendor:
        return vendor
    # Prefix match
    for prefix in sorted(_MCU_TO_VENDOR.keys(), key=len, reverse=True):
        if key.startswith(prefix):
            return _MCU_TO_VENDOR[prefix]
    return "stm32"  # safest default — most complete model set


def _vendor_from_fingerprint(fingerprint: RTOSFingerprint) -> str:
    """Extract vendor from fingerprint RTOS type or MCU family."""
    if fingerprint.rtos_type == "zephyr":
        return "zephyr"
    return _vendor_from_mcu(fingerprint.mcu_family)


# ---------------------------------------------------------------------------
# 3.3 SVD-aware Peripheral Filtering
# ---------------------------------------------------------------------------

def _filter_peripherals_by_usage(
    svd_device: SVDDevice,
    firmware: FirmwareImage,
) -> list[SVDPeripheral]:
    """Filter SVD peripherals to those actually used by firmware.

    Checks:
    1. Symbol names that reference the peripheral name
    2. MMIO address ranges present in firmware data sections
    3. Critical peripheral whitelist (always included)
    """
    used: list[SVDPeripheral] = []
    seen_names: set[str] = set()

    # Build searchable text from symbol names
    sym_text = ""
    if firmware.symbols:
        sym_text = " ".join(firmware.symbols.keys()).lower()

    # Collect firmware data address ranges for MMIO detection
    data_ranges: list[tuple[int, int]] = []
    if firmware.sections:
        for sec in firmware.sections:
            if sec.data and len(sec.data) > 0:
                data_ranges.append((sec.address, sec.address + sec.size))

    for periph in svd_device.peripherals:
        name_upper = periph.name.upper()
        name_lower = periph.name.lower()

        # Always include critical peripherals
        if name_upper in _CRITICAL_PERIPHERAL_NAMES:
            if name_upper not in seen_names:
                used.append(periph)
                seen_names.add(name_upper)
            continue

        # Check group_name against critical list
        if periph.group_name and periph.group_name.upper() in _CRITICAL_PERIPHERAL_NAMES:
            if name_upper not in seen_names:
                used.append(periph)
                seen_names.add(name_upper)
            continue

        # Check if symbols reference this peripheral
        if sym_text and name_lower in sym_text:
            if name_upper not in seen_names:
                used.append(periph)
                seen_names.add(name_upper)
            continue

        # Check MMIO address overlap with firmware constants
        # Search for the base address as a 4-byte LE value in firmware data
        if firmware.data and len(firmware.data) >= 4:
            import struct
            addr_bytes = struct.pack("<I", periph.base_address)
            if addr_bytes in firmware.data:
                if name_upper not in seen_names:
                    used.append(periph)
                    seen_names.add(name_upper)
                    continue

    return used


# ---------------------------------------------------------------------------
# 3.2 AutoConfigGenerator
# ---------------------------------------------------------------------------

class AutoConfigGenerator:
    """Generates peripheral configuration from firmware analysis."""

    def __init__(self) -> None:
        self._hal_db = HALDatabase()
        self._svd_cache = SVDCache()

    def generate(
        self,
        firmware: FirmwareImage,
        fingerprint: Optional[RTOSFingerprint] = None,
        mcu_family: str = "",
        svd_device: Optional[SVDDevice] = None,
    ) -> tuple[PeripheralConfig, dict]:
        """Auto-generate complete peripheral config.

        Returns:
            (config, summary_dict) where summary contains detection metadata.
        """
        # Step 1: Fingerprint if not provided
        if fingerprint is None:
            fingerprint = fingerprint_firmware(firmware)
            logger.info(
                "Auto-fingerprinted: rtos=%s mcu=%s confidence=%.2f",
                fingerprint.rtos_type,
                fingerprint.mcu_family,
                fingerprint.confidence,
            )

        # Step 2: Determine MCU family
        effective_mcu = mcu_family or fingerprint.mcu_family
        if effective_mcu == "unknown":
            effective_mcu = "stm32"  # safest default for ARM Cortex-M
            logger.warning("MCU family unknown, defaulting to stm32")

        # Step 3: Load SVD device if not provided
        if svd_device is None:
            svd_device = self._svd_cache.get_svd_device(effective_mcu)
            if svd_device is not None:
                logger.info("Loaded SVD for %s: %s", effective_mcu, svd_device.name)
            else:
                logger.info("No SVD available for %s, using HAL-only config", effective_mcu)

        # Step 4: Determine vendor for model class selection
        vendor = _vendor_from_fingerprint(fingerprint)

        # Step 5: Match firmware symbols against HAL database
        hal_matches: list[tuple[HALFunctionEntry, int]] = []
        if firmware.symbols:
            hal_matches = self._hal_db.match_firmware_symbols(firmware.symbols)
            logger.info("Matched %d HAL functions in firmware", len(hal_matches))

        # Step 6: Build intercept specs from matched symbols
        intercepts = self._generate_hal_hooks(firmware, fingerprint)

        # Step 7: Build peripheral model specs from SVD + matches
        models = self._generate_svd_models(effective_mcu, svd_device, firmware)

        # Step 8: If no SVD models, build from HAL matches alone
        if not models and hal_matches:
            models = self._generate_models_from_hal(hal_matches, vendor)

        # Step 9: Ensure critical peripherals are present
        models = self._ensure_critical_peripherals(models, vendor, effective_mcu)

        # Step 10: Prioritize init ordering
        intercepts = self._prioritize_init_order(intercepts)

        # Build symbol table from firmware
        symbols: dict[int, str] = {}
        if firmware.symbols:
            for name, addr in firmware.symbols.items():
                symbols[addr] = name

        config = PeripheralConfig(
            models=models,
            intercepts=intercepts,
            symbols=symbols,
        )

        # Build summary
        peripheral_types_found = sorted(set(
            entry.peripheral_type for entry, _ in hal_matches
        ))
        summary = {
            "mcu_family": effective_mcu,
            "vendor": vendor,
            "rtos_type": fingerprint.rtos_type,
            "qemu_machine": resolve_qemu_machine(effective_mcu, fingerprint.architecture),
            "hal_matches": len(hal_matches),
            "peripheral_types": peripheral_types_found,
            "model_count": len(models),
            "intercept_count": len(intercepts),
            "svd_available": svd_device is not None,
            "architecture": fingerprint.architecture,
            "confidence": fingerprint.confidence,
        }

        return config, summary

    # -------------------------------------------------------------------
    # Internal: HAL hook generation
    # -------------------------------------------------------------------

    def _generate_hal_hooks(
        self,
        firmware: FirmwareImage,
        fingerprint: RTOSFingerprint,
    ) -> list[InterceptSpec]:
        """Build InterceptSpec list from firmware symbols matched against HAL DB."""
        if not firmware.symbols:
            return []

        matches = self._hal_db.match_firmware_symbols(firmware.symbols)
        intercepts: list[InterceptSpec] = []
        seen: set[str] = set()

        for entry, addr in matches:
            # Deduplicate by symbol name
            if entry.symbol in seen:
                continue
            seen.add(entry.symbol)

            intercepts.append(InterceptSpec(
                model_class=entry.model_class,
                function=entry.symbol,
                address=addr,
                symbol=entry.symbol,
            ))

        return intercepts

    # -------------------------------------------------------------------
    # Internal: SVD-based model generation
    # -------------------------------------------------------------------

    def _generate_svd_models(
        self,
        mcu_family: str,
        svd_device: Optional[SVDDevice],
        firmware: FirmwareImage,
    ) -> list[PeripheralModelSpec]:
        """Build PeripheralModelSpec list from SVD peripherals filtered by usage."""
        if svd_device is None:
            return []

        vendor = _vendor_from_mcu(mcu_family)
        used_peripherals = _filter_peripherals_by_usage(svd_device, firmware)
        models: list[PeripheralModelSpec] = []
        seen_names: set[str] = set()

        for periph in used_peripherals:
            if periph.name in seen_names:
                continue
            seen_names.add(periph.name)

            peripheral_type = self._classify_svd_peripheral(periph)
            model_class = self._select_model_class(vendor, peripheral_type)

            irq = periph.irq_numbers[0] if periph.irq_numbers else None

            models.append(PeripheralModelSpec(
                name=periph.name.lower(),
                model_class=model_class,
                base_addr=periph.base_address,
                size=periph.size,
                irq=irq,
            ))

        return models

    def _classify_svd_peripheral(self, periph: SVDPeripheral) -> str:
        """Classify an SVD peripheral into a type string for model selection."""
        name = periph.name.upper()
        group = (periph.group_name or "").upper()
        desc = (periph.description or "").lower()

        # Check name patterns
        type_patterns: list[tuple[list[str], str]] = [
            (["UART", "USART", "LPUART"], "uart"),
            (["SPI", "QSPI"], "spi"),
            (["I2C", "TWI"], "i2c"),
            (["GPIO", "GPIOTE"], "gpio"),
            (["RCC", "CLOCK", "CMU", "SCG"], "clock"),
            (["FLASH", "FMC", "NVM"], "flash"),
            (["TIM", "TIMER", "RTC", "WDT", "WDG", "IWDG", "WWDG"], "timer"),
            (["BLE", "RADIO"], "ble"),
            (["PWR", "POWER", "PMU"], "power"),
            (["NVIC", "SCB"], "init"),
        ]

        search_text = f"{name} {group}"
        for patterns, ptype in type_patterns:
            for pattern in patterns:
                if pattern in search_text:
                    return ptype

        # Fallback: check description
        desc_patterns: list[tuple[str, str]] = [
            ("serial", "uart"),
            ("spi", "spi"),
            ("i2c", "i2c"),
            ("gpio", "gpio"),
            ("clock", "clock"),
            ("flash", "flash"),
            ("timer", "timer"),
            ("bluetooth", "ble"),
            ("power", "power"),
        ]
        for keyword, ptype in desc_patterns:
            if keyword in desc:
                return ptype

        return "init"  # generic fallback

    def _select_model_class(self, vendor: str, peripheral_type: str) -> str:
        """Return dotted Python import path for the model class."""
        key = (vendor.lower(), peripheral_type.lower())
        return _MODEL_CLASS_MAP.get(key, _DEFAULT_MODEL_CLASS)

    # -------------------------------------------------------------------
    # Internal: Model generation from HAL matches (no SVD)
    # -------------------------------------------------------------------

    def _generate_models_from_hal(
        self,
        hal_matches: list[tuple[HALFunctionEntry, int]],
        vendor: str,
    ) -> list[PeripheralModelSpec]:
        """Build models from HAL function matches when SVD is unavailable.

        Groups matched functions by peripheral_type and creates one model per type.
        Uses default base addresses since we don't have SVD data.
        """
        # Default base addresses per type (common STM32F4 layout)
        _DEFAULT_BASES: dict[str, int] = {
            "uart": 0x40011000,
            "spi": 0x40013000,
            "i2c": 0x40005400,
            "gpio": 0x40020000,
            "clock": 0x40023800,
            "flash": 0x40023C00,
            "timer": 0x40000000,
            "ble": 0x40000000,
            "init": 0x00000000,
            "power": 0x40007000,
        }

        types_seen: set[str] = set()
        models: list[PeripheralModelSpec] = []

        for entry, _ in hal_matches:
            ptype = entry.peripheral_type
            if ptype in types_seen:
                continue
            types_seen.add(ptype)

            model_class = self._select_model_class(vendor, ptype)
            base_addr = _DEFAULT_BASES.get(ptype, 0x40000000)

            models.append(PeripheralModelSpec(
                name=ptype,
                model_class=model_class,
                base_addr=base_addr,
                size=0x400,
            ))

        return models

    # -------------------------------------------------------------------
    # Internal: Ensure critical peripherals present
    # -------------------------------------------------------------------

    def _ensure_critical_peripherals(
        self,
        models: list[PeripheralModelSpec],
        vendor: str,
        mcu_family: str,
    ) -> list[PeripheralModelSpec]:
        """Ensure RCC/CLOCK, FLASH, and POWER models are always included."""
        existing_types: set[str] = set()
        for m in models:
            # Classify existing models by checking the model_class path
            for (v, t), cls in _MODEL_CLASS_MAP.items():
                if m.model_class == cls:
                    existing_types.add(t)
                    break

        # Also classify by name as fallback
        for m in models:
            name_upper = m.name.upper()
            if any(crit in name_upper for crit in _CRITICAL_PERIPHERAL_NAMES):
                for ptype in _CRITICAL_PERIPHERAL_TYPES:
                    type_keywords = {
                        "clock": ["RCC", "CLOCK", "CMU"],
                        "flash": ["FLASH", "FMC"],
                        "power": ["PWR", "POWER"],
                    }
                    for kw in type_keywords.get(ptype, []):
                        if kw in name_upper:
                            existing_types.add(ptype)

        # Add missing critical peripherals
        _CRITICAL_DEFAULTS: dict[str, tuple[str, int]] = {
            "clock": ("rcc", 0x40023800),
            "flash": ("flash", 0x40023C00),
        }

        result = list(models)
        for ptype, (name, base_addr) in _CRITICAL_DEFAULTS.items():
            if ptype not in existing_types:
                model_class = self._select_model_class(vendor, ptype)
                result.append(PeripheralModelSpec(
                    name=name,
                    model_class=model_class,
                    base_addr=base_addr,
                    size=0x400,
                ))
                logger.info("Added critical peripheral: %s (%s)", name, ptype)

        return result

    # -------------------------------------------------------------------
    # Internal: Init ordering
    # -------------------------------------------------------------------

    def _prioritize_init_order(
        self,
        specs: list[InterceptSpec],
    ) -> list[InterceptSpec]:
        """Reorder intercept specs for vendor-specific init ordering.

        STM32: HAL_Init must come first, then SystemClock_Config / RCC
        nRF5: nrf_drv_clock_init first, then power, then SoftDevice
        Zephyr: device_get_binding / device_is_ready first
        """
        # Assign priority scores (lower = earlier)
        priority_map: dict[str, int] = {
            # STM32 init sequence
            "HAL_Init": 0,
            "HAL_IncTick": 1,
            "SystemClock_Config": 2,
            "HAL_RCC_OscConfig": 3,
            "HAL_RCC_ClockConfig": 4,
            "HAL_RCC_GetSysClockFreq": 5,
            # nRF5 init sequence
            "nrf_drv_clock_init": 0,
            "nrf_drv_clock_lfclk_request": 1,
            "nrf_drv_clock_hfclk_request": 2,
            "nrf_pwr_mgmt_init": 3,
            "nrf_log_init": 4,
            "nrf_sdh_enable_request": 5,
            "nrf_sdh_ble_enable": 6,
            "nrf_crypto_init": 7,
            # Zephyr init
            "device_get_binding": 0,
            "device_is_ready": 1,
        }
        default_priority = 100

        def sort_key(spec: InterceptSpec) -> int:
            return priority_map.get(spec.function, default_priority)

        return sorted(specs, key=sort_key)


# ---------------------------------------------------------------------------
# 3.4 YAML Config Serialization
# ---------------------------------------------------------------------------

def serialize_config(config: PeripheralConfig) -> str:
    """Export PeripheralConfig to YAML with comments.

    Produces a human-readable YAML file suitable for manual editing
    or passing to PeripheralConfig.load().
    """
    lines: list[str] = [
        "# Auto-generated peripheral configuration",
        "# Generated by rtosploit.peripherals.auto_config",
        "#",
        "# Edit this file to customize peripheral models and intercepts.",
        "",
    ]

    # Peripherals section
    models = config.get_models()
    if models:
        lines.append("peripherals:")
        for model in models:
            lines.append(f"  {model.name}:")
            lines.append(f"    model: {model.model_class}")
            lines.append(f"    base_addr: 0x{model.base_addr:08X}")
            lines.append(f"    size: 0x{model.size:X}")
            if model.irq is not None:
                lines.append(f"    irq: {model.irq}")
            if model.args:
                lines.append("    args:")
                for k, v in model.args.items():
                    lines.append(f"      {k}: {_yaml_value(v)}")
            lines.append("")
    else:
        lines.append("peripherals: {}")
        lines.append("")

    # Intercepts section
    intercepts = config.get_intercepts()
    if intercepts:
        lines.append("# HAL function intercepts — hooks that replace SDK calls")
        lines.append("intercepts:")
        for ic in intercepts:
            lines.append(f"  - class: {ic.model_class}")
            lines.append(f"    function: {ic.function}")
            if ic.symbol:
                lines.append(f"    symbol: {ic.symbol}")
            if ic.address is not None:
                lines.append(f"    addr: 0x{ic.address:08X}")
            lines.append("")
    else:
        lines.append("intercepts: []")
        lines.append("")

    # Symbols section
    symbols = config.get_symbols()
    if symbols:
        lines.append("# Manual symbol table (address -> name)")
        lines.append("symbols:")
        for addr in sorted(symbols.keys()):
            lines.append(f"  0x{addr:08X}: {symbols[addr]}")
        lines.append("")
    else:
        lines.append("symbols: {}")
        lines.append("")

    return "\n".join(lines)


def _yaml_value(v: object) -> str:
    """Format a value for inline YAML output."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(v)
    if isinstance(v, str):
        # Quote if contains special chars
        if any(c in v for c in ":#{}[]&*!|>'\","):
            return f'"{v}"'
        return v
    # Fallback: use yaml dump for complex types
    return yaml.dump(v, default_flow_style=True).strip()
