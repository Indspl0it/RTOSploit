"""Integration tests for the peripheral detection engine against real firmware.

These tests require actual firmware files and are skipped when not available.
Mark with @pytest.mark.integration for CI exclusion.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rtosploit.analysis.detection.evidence import (
    ConfidenceLevel,
    DetectionResult,
    EvidenceType,
)
from rtosploit.utils.binary import FirmwareImage, BinaryFormat, MemorySection


# ---------------------------------------------------------------------------
# Test firmware paths (relative to project root)
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

PARTICLE_FW = _PROJECT_ROOT / "test-firmware" / "particle_fw" / "6.3.4" / "argon" / "release" / "argon-system-part1@6.3.4.elf"
ZEPHYR_HELLO = _PROJECT_ROOT / "test-firmware" / "zephyr" / "hello_world.elf"


# ---------------------------------------------------------------------------
# Particle Argon (nRF52840-based)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not PARTICLE_FW.exists(), reason="Test firmware not available")
class TestParticleArgonDetection:
    @pytest.fixture(scope="class")
    def fw(self) -> FirmwareImage:
        from rtosploit.utils.binary import load_firmware
        return load_firmware(str(PARTICLE_FW))

    @pytest.fixture(scope="class")
    def result(self, fw: FirmwareImage) -> DetectionResult:
        from rtosploit.analysis.detection import detect_peripherals
        return detect_peripherals(fw)

    def test_detects_peripherals(self, result: DetectionResult) -> None:
        assert len(result.peripherals) >= 1, (
            f"Expected at least 1 peripheral, got {len(result.peripherals)}: "
            f"{list(result.peripherals.keys())}"
        )

    def test_has_evidence(self, result: DetectionResult) -> None:
        assert result.total_evidence > 0

    def test_mcu_family_detected(self, result: DetectionResult) -> None:
        assert result.mcu_family != "unknown", (
            f"MCU family should be detected, got '{result.mcu_family}'"
        )

    def test_architecture_is_arm(self, result: DetectionResult) -> None:
        assert result.architecture in ("armv7m", "armv8m"), (
            f"Expected ARM architecture, got '{result.architecture}'"
        )

    def test_detects_ble(self, result: DetectionResult) -> None:
        ble_peripherals = {
            name: det for name, det in result.peripherals.items()
            if det.peripheral_type == "ble"
        }
        assert len(ble_peripherals) > 0, (
            f"Expected BLE peripheral, found: {list(result.peripherals.keys())}"
        )

    def test_vendor_scores_present(self, result: DetectionResult) -> None:
        assert len(result.vendor_scores) > 0

    def test_layers_were_run(self, result: DetectionResult) -> None:
        assert len(result.layers_run) > 0

    def test_to_dict_serializable(self, result: DetectionResult) -> None:
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "peripherals" in d
        assert "architecture" in d
        assert "mcu_family" in d
        assert "vendor_scores" in d

        # Verify all values are JSON-serializable types
        import json
        json_str = json.dumps(d)
        assert len(json_str) > 0

    def test_all_peripherals_have_valid_confidence(self, result: DetectionResult) -> None:
        for name, det in result.peripherals.items():
            assert det.confidence > 0, f"{name} has non-positive confidence"
            assert det.confidence_level in (
                ConfidenceLevel.HIGH,
                ConfidenceLevel.MEDIUM,
                ConfidenceLevel.LOW,
            )

    def test_evidence_types_are_valid(self, result: DetectionResult) -> None:
        for name, det in result.peripherals.items():
            for ev in det.evidence:
                assert isinstance(ev.type, EvidenceType)
                assert ev.weight > 0


# ---------------------------------------------------------------------------
# Zephyr Hello World (if available)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not ZEPHYR_HELLO.exists(), reason="Zephyr test firmware not available")
class TestZephyrHelloWorldDetection:
    @pytest.fixture(scope="class")
    def fw(self) -> FirmwareImage:
        from rtosploit.utils.binary import load_firmware
        return load_firmware(str(ZEPHYR_HELLO))

    @pytest.fixture(scope="class")
    def result(self, fw: FirmwareImage) -> DetectionResult:
        from rtosploit.analysis.detection import detect_peripherals
        return detect_peripherals(fw)

    def test_detects_peripherals(self, result: DetectionResult) -> None:
        assert len(result.peripherals) >= 1

    def test_has_evidence(self, result: DetectionResult) -> None:
        assert result.total_evidence > 0

    def test_detects_uart_for_console(self, result: DetectionResult) -> None:
        uart_peripherals = {
            name: det for name, det in result.peripherals.items()
            if det.peripheral_type == "uart"
        }
        assert len(uart_peripherals) > 0, (
            "Zephyr hello_world should use UART for console output"
        )


# ---------------------------------------------------------------------------
# Synthetic integration test (always runs)
# ---------------------------------------------------------------------------

class TestSyntheticIntegration:
    """Integration test using a synthetic firmware image that exercises
    multiple detection layers without needing real firmware files."""

    def _make_synthetic_firmware(self) -> FirmwareImage:
        """Build firmware with strings, symbols, and relocations that
        should trigger multiple detection layers."""
        # Embed SDK strings
        strings_data = b"\x00" * 0x100
        for s in [
            "stm32f4xx_hal_uart.c",
            "stm32f4xx_hal_spi.c",
            "nrf_drv_uart",
            "uart@40002000",
            "DT_CHOSEN_zephyr_console",
        ]:
            strings_data += s.encode("ascii") + b"\x00"
        strings_data += b"\x00" * 0x100

        section = MemorySection(
            name=".rodata",
            address=0x08000000,
            data=strings_data,
            size=len(strings_data),
            permissions="r",
        )

        return FirmwareImage(
            data=strings_data,
            base_address=0x08000000,
            entry_point=0x08000000,
            format=BinaryFormat.ELF,
            sections=[section],
            symbols={
                "HAL_UART_Receive": 0x08001000,
                "HAL_GPIO_ReadPin": 0x08002000,
                "HAL_SPI_Transmit": 0x08003000,
            },
            relocations=[],
            path=Path("."),
            architecture="armv7m",
        )

    def test_multi_layer_detection(self) -> None:
        from rtosploit.analysis.detection import detect_peripherals

        fw = self._make_synthetic_firmware()
        result = detect_peripherals(fw, mcu_family="stm32f4", layers=["symbol", "string", "devicetree"])

        assert result.total_evidence > 0
        assert len(result.peripherals) >= 2

        # Should detect UART from multiple sources
        uart_peripherals = {
            name: det for name, det in result.peripherals.items()
            if det.peripheral_type == "uart"
        }
        assert len(uart_peripherals) >= 1

    def test_result_to_dict_roundtrip(self) -> None:
        from rtosploit.analysis.detection import detect_peripherals
        import json

        fw = self._make_synthetic_firmware()
        result = detect_peripherals(fw, mcu_family="stm32f4", layers=["symbol", "string"])

        d = result.to_dict()
        json_str = json.dumps(d, indent=2)
        parsed = json.loads(json_str)

        assert parsed["architecture"] == "armv7m"
        assert parsed["mcu_family"] == "stm32f4"
        assert isinstance(parsed["peripherals"], dict)

    def test_vendor_scores_normalized(self) -> None:
        from rtosploit.analysis.detection import detect_peripherals

        fw = self._make_synthetic_firmware()
        result = detect_peripherals(fw, mcu_family="stm32f4", layers=["symbol", "string", "devicetree"])

        if result.vendor_scores:
            max_score = max(result.vendor_scores.values())
            assert max_score == 1.0, "Vendor scores should be normalized with max=1.0"
            for vendor, score in result.vendor_scores.items():
                assert 0 <= score <= 1.0, f"Vendor '{vendor}' score {score} out of range"

    def test_layers_run_tracking(self) -> None:
        from rtosploit.analysis.detection import detect_peripherals

        fw = self._make_synthetic_firmware()
        result = detect_peripherals(fw, mcu_family="stm32f4", layers=["symbol", "string"])

        assert "symbol" in result.layers_run
        assert "string" in result.layers_run
        assert "register" not in result.layers_run
