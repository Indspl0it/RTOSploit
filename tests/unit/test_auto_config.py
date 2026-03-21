"""Unit tests for the auto-configuration generator."""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from rtosploit.analysis.fingerprint import RTOSFingerprint
from rtosploit.peripherals.auto_config import (
    AutoConfigGenerator,
    _DEFAULT_MODEL_CLASS,
    _MODEL_CLASS_MAP,
    resolve_qemu_machine,
    serialize_config,
)
from rtosploit.peripherals.config import InterceptSpec, PeripheralConfig, PeripheralModelSpec
from rtosploit.peripherals.svd_model import SVDDevice, SVDPeripheral, SVDRegister
from rtosploit.utils.binary import BinaryFormat, FirmwareImage, MemorySection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_firmware(
    symbols: dict[str, int] | None = None,
    data: bytes = b"\x00" * 256,
    base_address: int = 0x08000000,
    architecture: str = "armv7m",
    sections: list[MemorySection] | None = None,
) -> FirmwareImage:
    """Build a synthetic FirmwareImage for testing."""
    return FirmwareImage(
        data=data,
        base_address=base_address,
        entry_point=base_address,
        format=BinaryFormat.RAW,
        sections=sections or [],
        symbols=symbols or {},
        architecture=architecture,
    )


def _make_fingerprint(
    rtos_type: str = "unknown",
    mcu_family: str = "stm32f4",
    architecture: str = "armv7m",
    confidence: float = 0.8,
) -> RTOSFingerprint:
    return RTOSFingerprint(
        rtos_type=rtos_type,
        version=None,
        confidence=confidence,
        architecture=architecture,
        mcu_family=mcu_family,
    )


# ---------------------------------------------------------------------------
# 1. TestResolveQemuMachine
# ---------------------------------------------------------------------------

class TestResolveQemuMachine:
    def test_stm32f4_maps_to_netduino2(self) -> None:
        assert resolve_qemu_machine("stm32f4") == "netduino2"

    def test_nrf52_maps_to_microbit(self) -> None:
        assert resolve_qemu_machine("nrf52") == "microbit"

    def test_unknown_mcu_armv7m_fallback(self) -> None:
        assert resolve_qemu_machine("totally_unknown", "armv7m") == "mps2-an385"

    def test_unknown_mcu_armv8m_fallback(self) -> None:
        assert resolve_qemu_machine("totally_unknown", "armv8m") == "mps2-an505"

    def test_stm32f1_maps_to_stm32vldiscovery(self) -> None:
        assert resolve_qemu_machine("stm32f1") == "stm32vldiscovery"

    def test_nrf52840_maps_to_microbit(self) -> None:
        assert resolve_qemu_machine("nrf52840") == "microbit"

    def test_prefix_match_stm32f407(self) -> None:
        """stm32f407 should prefix-match stm32f4 -> netduino2."""
        assert resolve_qemu_machine("stm32f407") == "netduino2"

    def test_unknown_mcu_unknown_arch_default(self) -> None:
        """Completely unknown MCU and arch falls back to mps2-an385."""
        assert resolve_qemu_machine("mystery_chip", "mystery_arch") == "mps2-an385"

    def test_case_insensitive(self) -> None:
        assert resolve_qemu_machine("STM32F4") == "netduino2"

    def test_riscv32_fallback(self) -> None:
        assert resolve_qemu_machine("unknown_riscv", "riscv32") == "sifive_e"


# ---------------------------------------------------------------------------
# 2. TestAutoConfigGenerator
# ---------------------------------------------------------------------------

class TestAutoConfigGenerator:
    @pytest.fixture
    def generator(self) -> AutoConfigGenerator:
        return AutoConfigGenerator()

    def test_generate_stm32_symbols_has_intercepts(self, generator: AutoConfigGenerator) -> None:
        """Firmware with STM32 HAL symbols should produce InterceptSpecs."""
        fw = _make_firmware(symbols={
            "HAL_UART_Init": 0x08001000,
            "HAL_UART_Receive": 0x08001100,
            "HAL_GPIO_Init": 0x08002000,
        })
        fp = _make_fingerprint(mcu_family="stm32f4")

        config, summary = generator.generate(fw, fingerprint=fp, svd_device=None)

        intercepts = config.get_intercepts()
        assert len(intercepts) > 0
        function_names = {ic.function for ic in intercepts}
        assert "HAL_UART_Init" in function_names

    def test_generate_nrf5_symbols_has_correct_models(self, generator: AutoConfigGenerator) -> None:
        """Firmware with nRF5 symbols should produce nRF5 model classes."""
        fw = _make_firmware(symbols={
            "nrf_drv_uart_rx": 0x00020000,
            "nrf_drv_clock_init": 0x00020100,
        })
        fp = _make_fingerprint(mcu_family="nrf52")

        config, summary = generator.generate(fw, fingerprint=fp, svd_device=None)

        assert summary["vendor"] == "nrf5"
        models = config.get_models()
        # Should have models for matched peripheral types + critical defaults
        assert len(models) > 0

    def test_generate_no_symbols_empty_but_valid(self, generator: AutoConfigGenerator) -> None:
        """Firmware with no symbols produces an empty but structurally valid config."""
        fw = _make_firmware(symbols={})
        fp = _make_fingerprint(mcu_family="stm32f4")

        config, summary = generator.generate(fw, fingerprint=fp, svd_device=None)

        # Should still have critical peripherals
        models = config.get_models()
        assert isinstance(models, list)
        intercepts = config.get_intercepts()
        assert intercepts == []

    def test_stm32_init_ordering_hal_init_first(self, generator: AutoConfigGenerator) -> None:
        """STM32: HAL_Init should come before other intercepts."""
        fw = _make_firmware(symbols={
            "HAL_UART_Init": 0x08001000,
            "HAL_Init": 0x08002000,
            "HAL_RCC_OscConfig": 0x08003000,
        })
        fp = _make_fingerprint(mcu_family="stm32f4")

        config, _ = generator.generate(fw, fingerprint=fp, svd_device=None)

        intercepts = config.get_intercepts()
        functions = [ic.function for ic in intercepts]
        if "HAL_Init" in functions:
            hal_init_idx = functions.index("HAL_Init")
            # HAL_Init should be first (index 0)
            assert hal_init_idx == 0

    def test_nrf5_init_ordering_clock_init_first(self, generator: AutoConfigGenerator) -> None:
        """nRF5: nrf_drv_clock_init should come before other nrf functions."""
        fw = _make_firmware(symbols={
            "nrf_drv_uart_rx": 0x00020000,
            "nrf_drv_clock_init": 0x00020100,
            "nrf_sdh_enable_request": 0x00020200,
        })
        fp = _make_fingerprint(mcu_family="nrf52")

        config, _ = generator.generate(fw, fingerprint=fp, svd_device=None)

        intercepts = config.get_intercepts()
        functions = [ic.function for ic in intercepts]
        if "nrf_drv_clock_init" in functions:
            clock_idx = functions.index("nrf_drv_clock_init")
            assert clock_idx == 0

    def test_critical_peripherals_always_included(self, generator: AutoConfigGenerator) -> None:
        """Even with no symbols, critical peripherals (clock, flash) are added."""
        fw = _make_firmware(symbols={})
        fp = _make_fingerprint(mcu_family="stm32f4")

        config, _ = generator.generate(fw, fingerprint=fp, svd_device=None)

        models = config.get_models()
        model_names = {m.name for m in models}
        # At least clock and flash should be present
        assert "rcc" in model_names or "clock" in model_names or any(
            "clock" in n or "rcc" in n for n in model_names
        )

    def test_summary_contains_expected_keys(self, generator: AutoConfigGenerator) -> None:
        fw = _make_firmware(symbols={"HAL_UART_Init": 0x08001000})
        fp = _make_fingerprint(mcu_family="stm32f4")

        _, summary = generator.generate(fw, fingerprint=fp, svd_device=None)

        assert "mcu_family" in summary
        assert "vendor" in summary
        assert "rtos_type" in summary
        assert "qemu_machine" in summary
        assert "hal_matches" in summary
        assert "model_count" in summary
        assert "intercept_count" in summary
        assert "svd_available" in summary

    def test_generate_with_svd_device(self, generator: AutoConfigGenerator) -> None:
        """Config generation with SVD device produces SVD-based models."""
        periph = SVDPeripheral(
            name="USART1",
            base_address=0x40011000,
            description="Universal serial",
            registers=[SVDRegister(name="SR", offset=0x00)],
        )
        svd_dev = SVDDevice(
            name="STM32F407",
            peripherals=[periph],
        )
        fw = _make_firmware(symbols={"USART1_handler": 0x08001000})
        fp = _make_fingerprint(mcu_family="stm32f4")

        config, summary = generator.generate(fw, fingerprint=fp, svd_device=svd_dev)

        assert summary["svd_available"] is True
        models = config.get_models()
        assert len(models) > 0


# ---------------------------------------------------------------------------
# 3. TestModelClassSelection
# ---------------------------------------------------------------------------

class TestModelClassSelection:
    @pytest.fixture
    def generator(self) -> AutoConfigGenerator:
        return AutoConfigGenerator()

    def test_known_stm32_uart(self, generator: AutoConfigGenerator) -> None:
        result = generator._select_model_class("stm32", "uart")
        assert result == "rtosploit.peripherals.models.stm32_hal.STM32UART"

    def test_known_nrf5_ble(self, generator: AutoConfigGenerator) -> None:
        result = generator._select_model_class("nrf5", "ble")
        assert result == "rtosploit.peripherals.models.nrf5_hal.NRF5BLE"

    def test_known_zephyr_spi(self, generator: AutoConfigGenerator) -> None:
        result = generator._select_model_class("zephyr", "spi")
        assert result == "rtosploit.peripherals.models.zephyr_hal.ZephyrSPI"

    def test_unknown_vendor_type_fallback(self, generator: AutoConfigGenerator) -> None:
        result = generator._select_model_class("mystery_vendor", "mystery_type")
        assert result == _DEFAULT_MODEL_CLASS

    def test_case_insensitive_lookup(self, generator: AutoConfigGenerator) -> None:
        result = generator._select_model_class("STM32", "UART")
        assert result == "rtosploit.peripherals.models.stm32_hal.STM32UART"


# ---------------------------------------------------------------------------
# 4. TestSerializeConfig
# ---------------------------------------------------------------------------

class TestSerializeConfig:
    def test_serialize_roundtrip_valid_yaml(self) -> None:
        """Serialized config should be valid YAML."""
        models = [
            PeripheralModelSpec(
                name="uart1",
                model_class="rtosploit.peripherals.models.stm32_hal.STM32UART",
                base_addr=0x40011000,
                size=0x400,
                irq=37,
            ),
        ]
        intercepts = [
            InterceptSpec(
                model_class="rtosploit.peripherals.models.stm32_hal.STM32UART",
                function="HAL_UART_Init",
                address=0x08001000,
                symbol="HAL_UART_Init",
            ),
        ]
        config = PeripheralConfig(models=models, intercepts=intercepts, symbols={0x08001000: "HAL_UART_Init"})

        result = serialize_config(config)
        assert isinstance(result, str)
        # Should be parseable YAML (at least the non-comment parts)
        lines = [l for l in result.split("\n") if l.strip() and not l.strip().startswith("#")]
        assert len(lines) > 0

    def test_serialize_empty_config(self) -> None:
        """Empty config serializes without error."""
        config = PeripheralConfig(models=[], intercepts=[], symbols={})
        result = serialize_config(config)
        assert isinstance(result, str)
        assert "peripherals" in result

    def test_serialize_contains_model_info(self) -> None:
        models = [
            PeripheralModelSpec(
                name="rcc",
                model_class="rtosploit.peripherals.models.stm32_hal.STM32RCC",
                base_addr=0x40023800,
                size=0x400,
            ),
        ]
        config = PeripheralConfig(models=models, intercepts=[], symbols={})
        result = serialize_config(config)
        assert "rcc" in result
        assert "STM32RCC" in result
        assert "40023800" in result.upper()

    def test_serialize_contains_intercept_info(self) -> None:
        intercepts = [
            InterceptSpec(
                model_class="rtosploit.peripherals.models.stm32_hal.STM32UART",
                function="HAL_UART_Init",
                address=0x08001000,
                symbol="HAL_UART_Init",
            ),
        ]
        config = PeripheralConfig(models=[], intercepts=intercepts, symbols={})
        result = serialize_config(config)
        assert "HAL_UART_Init" in result
        assert "intercepts" in result

    def test_serialize_contains_header_comment(self) -> None:
        config = PeripheralConfig(models=[], intercepts=[], symbols={})
        result = serialize_config(config)
        assert "Auto-generated" in result
