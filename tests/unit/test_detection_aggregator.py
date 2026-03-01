"""Unit tests for the peripheral detection aggregator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from rtosploit.analysis.detection.evidence import (
    ConfidenceLevel,
    DetectionResult,
    Evidence,
    EvidenceType,
    EVIDENCE_WEIGHTS,
    PeripheralDetection,
)
from rtosploit.analysis.detection.aggregator import (
    ALL_LAYERS,
    _aggregate_evidence,
    _compute_vendor_scores,
    detect_peripherals,
)
from rtosploit.utils.binary import (
    BinaryFormat,
    FirmwareImage,
    MemorySection,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_firmware(architecture: str = "armv7m") -> FirmwareImage:
    data = b"\x00" * 0x400
    return FirmwareImage(
        data=data,
        base_address=0x08000000,
        entry_point=0x08000000,
        format=BinaryFormat.ELF,
        sections=[],
        symbols={},
        relocations=[],
        path=Path("."),
        architecture=architecture,
    )


def _make_evidence(
    peripheral: str = "UART",
    etype: EvidenceType = EvidenceType.SYMBOL,
    weight: float = 0.6,
    vendor: str = "stm32",
    peripheral_type: str = "uart",
    address: int | None = None,
) -> Evidence:
    return Evidence(
        type=etype,
        peripheral=peripheral,
        weight=weight,
        detail=f"Test evidence for {peripheral}",
        address=address,
        vendor=vendor,
        peripheral_type=peripheral_type,
    )


# ---------------------------------------------------------------------------
# _aggregate_evidence
# ---------------------------------------------------------------------------

class TestAggregateEvidence:
    def test_empty_evidence(self) -> None:
        result = _aggregate_evidence([])
        assert result == {}

    def test_single_evidence(self) -> None:
        ev = _make_evidence("UART1")
        result = _aggregate_evidence([ev])
        assert "UART1" in result
        pd = result["UART1"]
        assert pd.name == "UART1"
        assert pd.confidence == 0.6
        assert pd.peripheral_type == "uart"
        assert pd.vendor == "stm32"
        assert len(pd.evidence) == 1

    def test_multiple_evidence_same_peripheral(self) -> None:
        evs = [
            _make_evidence("UART1", EvidenceType.SYMBOL, 0.6),
            _make_evidence("UART1", EvidenceType.SDK_STRING, 0.4),
            _make_evidence("UART1", EvidenceType.REGISTER_WRITE, 0.9, address=0x40011000),
        ]
        result = _aggregate_evidence(evs)
        assert "UART1" in result
        pd = result["UART1"]
        assert pd.confidence == pytest.approx(0.6 + 0.4 + 0.9)
        assert len(pd.evidence) == 3

    def test_peripheral_type_majority_vote(self) -> None:
        evs = [
            _make_evidence("USART1", peripheral_type="uart"),
            _make_evidence("USART1", peripheral_type="uart"),
            _make_evidence("USART1", peripheral_type="serial"),
        ]
        result = _aggregate_evidence(evs)
        # "uart" has 2 votes, "serial" has 1 -> uart wins
        assert result["USART1"].peripheral_type == "uart"

    def test_instance_detection_with_digit(self) -> None:
        ev = _make_evidence("UART1")
        result = _aggregate_evidence([ev])
        assert result["UART1"].instance is True

    def test_instance_detection_without_digit(self) -> None:
        ev = _make_evidence("UART")
        result = _aggregate_evidence([ev])
        assert result["UART"].instance is False

    def test_base_address_from_register_evidence(self) -> None:
        evs = [
            _make_evidence("USART2", EvidenceType.SYMBOL, address=0x08001000),
            _make_evidence(
                "USART2", EvidenceType.REGISTER_WRITE, address=0x40004400,
            ),
        ]
        result = _aggregate_evidence(evs)
        # register_write address should be used for base_address
        assert result["USART2"].base_address == 0x40004400

    def test_grouping_is_case_insensitive(self) -> None:
        evs = [
            _make_evidence("uart1"),
            _make_evidence("UART1"),
        ]
        result = _aggregate_evidence(evs)
        # Both should be grouped under "UART1"
        assert "UART1" in result
        assert len(result["UART1"].evidence) == 2

    def test_multiple_different_peripherals(self) -> None:
        evs = [
            _make_evidence("UART1", peripheral_type="uart"),
            _make_evidence("SPI0", peripheral_type="spi"),
            _make_evidence("I2C1", peripheral_type="i2c"),
        ]
        result = _aggregate_evidence(evs)
        assert len(result) == 3
        assert "UART1" in result
        assert "SPI0" in result
        assert "I2C1" in result


# ---------------------------------------------------------------------------
# _compute_vendor_scores
# ---------------------------------------------------------------------------

class TestComputeVendorScores:
    def test_empty_evidence(self) -> None:
        assert _compute_vendor_scores([]) == {}

    def test_single_vendor(self) -> None:
        evs = [
            _make_evidence(vendor="stm32", weight=0.6),
            _make_evidence(vendor="stm32", weight=0.4),
        ]
        scores = _compute_vendor_scores(evs)
        assert "stm32" in scores
        assert scores["stm32"] == 1.0  # Normalized to max

    def test_multiple_vendors_normalized(self) -> None:
        evs = [
            _make_evidence(vendor="stm32", weight=0.9),
            _make_evidence(vendor="stm32", weight=0.6),
            _make_evidence(vendor="nrf5", weight=0.6),
        ]
        scores = _compute_vendor_scores(evs)
        assert scores["stm32"] == 1.0  # 1.5 / 1.5 = 1.0
        assert scores["nrf5"] == pytest.approx(0.6 / 1.5, abs=0.01)

    def test_empty_vendor_ignored(self) -> None:
        evs = [
            _make_evidence(vendor=""),
            _make_evidence(vendor="stm32", weight=0.6),
        ]
        scores = _compute_vendor_scores(evs)
        assert "" not in scores
        assert "stm32" in scores


# ---------------------------------------------------------------------------
# detect_peripherals (integration with mocking)
# ---------------------------------------------------------------------------

class TestDetectPeripherals:
    @patch("rtosploit.analysis.detection.aggregator._detect_mcu_family")
    @patch("rtosploit.analysis.detection.aggregator._try_load_svd")
    def test_runs_specified_layers_only(self, mock_svd, mock_mcu) -> None:
        mock_mcu.return_value = "stm32f4"
        mock_svd.return_value = None

        fw = _make_firmware()

        # Patch individual layer functions
        mock_symbol_ev = [_make_evidence("UART1", EvidenceType.SYMBOL)]
        mock_string_ev = [_make_evidence("SPI", EvidenceType.SDK_STRING, 0.4, peripheral_type="spi")]

        with patch(
            "rtosploit.analysis.detection.layer_symbol.detect_from_symbols",
            return_value=mock_symbol_ev,
        ), patch(
            "rtosploit.analysis.detection.layer_string.detect_from_strings",
            return_value=mock_string_ev,
        ):
            result = detect_peripherals(fw, layers=["symbol", "string"])

        assert "symbol" in result.layers_run
        assert "string" in result.layers_run
        assert "register" not in result.layers_run
        assert result.total_evidence == 2

    @patch("rtosploit.analysis.detection.aggregator._detect_mcu_family")
    @patch("rtosploit.analysis.detection.aggregator._try_load_svd")
    def test_auto_detect_mcu_family(self, mock_svd, mock_mcu) -> None:
        mock_mcu.return_value = "nrf52840"
        mock_svd.return_value = None

        fw = _make_firmware()
        result = detect_peripherals(fw, layers=[])
        assert result.mcu_family == "nrf52840"

    @patch("rtosploit.analysis.detection.aggregator._detect_mcu_family")
    @patch("rtosploit.analysis.detection.aggregator._try_load_svd")
    def test_explicit_mcu_family_skips_detection(self, mock_svd, mock_mcu) -> None:
        mock_svd.return_value = None

        fw = _make_firmware()
        result = detect_peripherals(fw, mcu_family="esp32", layers=[])
        mock_mcu.assert_not_called()
        assert result.mcu_family == "esp32"

    @patch("rtosploit.analysis.detection.aggregator._detect_mcu_family")
    @patch("rtosploit.analysis.detection.aggregator._try_load_svd")
    def test_layer_error_does_not_crash(self, mock_svd, mock_mcu) -> None:
        mock_mcu.return_value = "unknown"
        mock_svd.return_value = None

        fw = _make_firmware()

        with patch(
            "rtosploit.analysis.detection.layer_symbol.detect_from_symbols",
            side_effect=RuntimeError("boom"),
        ):
            result = detect_peripherals(fw, layers=["symbol"])

        assert "symbol:error" in result.layers_run
        assert result.total_evidence == 0

    @patch("rtosploit.analysis.detection.aggregator._detect_mcu_family")
    @patch("rtosploit.analysis.detection.aggregator._try_load_svd")
    def test_unknown_layer_skipped(self, mock_svd, mock_mcu) -> None:
        mock_mcu.return_value = "unknown"
        mock_svd.return_value = None

        fw = _make_firmware()
        result = detect_peripherals(fw, layers=["nonexistent_layer"])
        assert result.layers_run == []
        assert result.total_evidence == 0

    @patch("rtosploit.analysis.detection.aggregator._detect_mcu_family")
    @patch("rtosploit.analysis.detection.aggregator._try_load_svd")
    def test_result_architecture(self, mock_svd, mock_mcu) -> None:
        mock_mcu.return_value = "unknown"
        mock_svd.return_value = None

        fw = _make_firmware(architecture="xtensa")
        result = detect_peripherals(fw, layers=[])
        assert result.architecture == "xtensa"

    def test_all_layers_list(self) -> None:
        expected = {"symbol", "string", "relocation", "register", "signature", "devicetree"}
        assert set(ALL_LAYERS) == expected

    @patch("rtosploit.analysis.detection.aggregator._detect_mcu_family")
    @patch("rtosploit.analysis.detection.aggregator._try_load_svd")
    def test_aggregation_end_to_end(self, mock_svd, mock_mcu) -> None:
        """Multiple layers producing evidence for the same peripheral are aggregated."""
        mock_mcu.return_value = "stm32f4"
        mock_svd.return_value = None

        fw = _make_firmware()

        symbol_ev = [_make_evidence("UART1", EvidenceType.SYMBOL, 0.6)]
        string_ev = [_make_evidence("UART1", EvidenceType.SDK_STRING, 0.4)]

        with patch(
            "rtosploit.analysis.detection.layer_symbol.detect_from_symbols",
            return_value=symbol_ev,
        ), patch(
            "rtosploit.analysis.detection.layer_string.detect_from_strings",
            return_value=string_ev,
        ):
            result = detect_peripherals(fw, layers=["symbol", "string"])

        assert "UART1" in result.peripherals
        pd = result.peripherals["UART1"]
        assert pd.confidence == pytest.approx(1.0)
        assert len(pd.evidence) == 2
        assert pd.confidence_level == ConfidenceLevel.MEDIUM
