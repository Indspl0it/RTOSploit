"""Unit tests for the peripheral detection evidence model."""

from __future__ import annotations

import pytest

from rtosploit.analysis.detection.evidence import (
    ConfidenceLevel,
    DetectionResult,
    Evidence,
    EvidenceType,
    EVIDENCE_WEIGHTS,
    PeripheralDetection,
)


# ---------------------------------------------------------------------------
# EvidenceType enum
# ---------------------------------------------------------------------------

class TestEvidenceType:
    def test_all_types_present(self) -> None:
        expected = {
            "SYMBOL", "SDK_STRING", "RELOCATION",
            "REGISTER_WRITE", "REGISTER_READ",
            "BINARY_PATTERN", "DEVICETREE_LABEL",
        }
        actual = {e.name for e in EvidenceType}
        assert actual == expected

    def test_values_are_strings(self) -> None:
        for e in EvidenceType:
            assert isinstance(e.value, str)

    def test_value_format(self) -> None:
        assert EvidenceType.SYMBOL.value == "symbol"
        assert EvidenceType.SDK_STRING.value == "sdk_string"
        assert EvidenceType.REGISTER_WRITE.value == "register_write"
        assert EvidenceType.REGISTER_READ.value == "register_read"
        assert EvidenceType.BINARY_PATTERN.value == "binary_pattern"
        assert EvidenceType.DEVICETREE_LABEL.value == "devicetree_label"
        assert EvidenceType.RELOCATION.value == "relocation"


# ---------------------------------------------------------------------------
# EVIDENCE_WEIGHTS
# ---------------------------------------------------------------------------

class TestEvidenceWeights:
    def test_contains_all_types(self) -> None:
        for etype in EvidenceType:
            assert etype in EVIDENCE_WEIGHTS, f"Missing weight for {etype.name}"

    def test_weights_are_positive_floats(self) -> None:
        for etype, weight in EVIDENCE_WEIGHTS.items():
            assert isinstance(weight, float)
            assert weight > 0

    def test_register_write_highest(self) -> None:
        assert EVIDENCE_WEIGHTS[EvidenceType.REGISTER_WRITE] == 0.9

    def test_sdk_string_lowest(self) -> None:
        assert EVIDENCE_WEIGHTS[EvidenceType.SDK_STRING] == 0.4

    def test_ordering(self) -> None:
        w = EVIDENCE_WEIGHTS
        assert w[EvidenceType.REGISTER_WRITE] > w[EvidenceType.REGISTER_READ]
        assert w[EvidenceType.REGISTER_READ] >= w[EvidenceType.DEVICETREE_LABEL]
        assert w[EvidenceType.SYMBOL] > w[EvidenceType.SDK_STRING]


# ---------------------------------------------------------------------------
# Evidence dataclass
# ---------------------------------------------------------------------------

class TestEvidence:
    def test_construction_minimal(self) -> None:
        ev = Evidence(
            type=EvidenceType.SYMBOL,
            peripheral="UART1",
            weight=0.6,
            detail="HAL symbol: HAL_UART_Init",
        )
        assert ev.type == EvidenceType.SYMBOL
        assert ev.peripheral == "UART1"
        assert ev.weight == 0.6
        assert ev.detail == "HAL symbol: HAL_UART_Init"
        assert ev.address is None
        assert ev.vendor == ""
        assert ev.peripheral_type == ""
        assert ev.register_name == ""
        assert ev.register_offset == 0

    def test_construction_all_fields(self) -> None:
        ev = Evidence(
            type=EvidenceType.REGISTER_WRITE,
            peripheral="USART2",
            weight=0.9,
            detail="MMIO write to USART2.CR1",
            address=0x40004400,
            vendor="stm32",
            peripheral_type="uart",
            register_name="CR1",
            register_offset=0x00,
        )
        assert ev.address == 0x40004400
        assert ev.vendor == "stm32"
        assert ev.peripheral_type == "uart"
        assert ev.register_name == "CR1"


# ---------------------------------------------------------------------------
# ConfidenceLevel
# ---------------------------------------------------------------------------

class TestConfidenceLevel:
    def test_enum_values(self) -> None:
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"


# ---------------------------------------------------------------------------
# PeripheralDetection
# ---------------------------------------------------------------------------

class TestPeripheralDetection:
    def test_confidence_level_high(self) -> None:
        pd = PeripheralDetection(
            name="UART1",
            peripheral_type="uart",
            confidence=1.5,
        )
        assert pd.confidence_level == ConfidenceLevel.HIGH

    def test_confidence_level_medium_upper_bound(self) -> None:
        pd = PeripheralDetection(
            name="SPI",
            peripheral_type="spi",
            confidence=1.2,
        )
        assert pd.confidence_level == ConfidenceLevel.MEDIUM

    def test_confidence_level_medium_lower_bound(self) -> None:
        pd = PeripheralDetection(
            name="SPI",
            peripheral_type="spi",
            confidence=0.6,
        )
        assert pd.confidence_level == ConfidenceLevel.MEDIUM

    def test_confidence_level_low(self) -> None:
        pd = PeripheralDetection(
            name="I2C",
            peripheral_type="i2c",
            confidence=0.4,
        )
        assert pd.confidence_level == ConfidenceLevel.LOW

    def test_confidence_level_boundary_above_1_2(self) -> None:
        pd = PeripheralDetection(name="X", peripheral_type="x", confidence=1.2001)
        assert pd.confidence_level == ConfidenceLevel.HIGH

    def test_confidence_level_boundary_below_0_6(self) -> None:
        pd = PeripheralDetection(name="X", peripheral_type="x", confidence=0.5999)
        assert pd.confidence_level == ConfidenceLevel.LOW

    def test_default_evidence_list(self) -> None:
        pd = PeripheralDetection(name="UART", peripheral_type="uart", confidence=1.0)
        assert pd.evidence == []

    def test_instance_flag(self) -> None:
        pd = PeripheralDetection(
            name="UART1",
            peripheral_type="uart",
            confidence=1.0,
            instance=True,
        )
        assert pd.instance is True


# ---------------------------------------------------------------------------
# DetectionResult
# ---------------------------------------------------------------------------

class TestDetectionResult:
    def _make_result(self) -> DetectionResult:
        ev = Evidence(
            type=EvidenceType.SYMBOL,
            peripheral="UART1",
            weight=0.6,
            detail="HAL symbol: HAL_UART_Init",
            address=0x08001000,
            vendor="stm32",
            peripheral_type="uart",
        )
        pd = PeripheralDetection(
            name="UART1",
            peripheral_type="uart",
            confidence=1.3,
            evidence=[ev],
            base_address=0x40011000,
            vendor="stm32",
            instance=True,
        )
        return DetectionResult(
            architecture="armv7m",
            vendor_scores={"stm32": 1.0, "nrf5": 0.3},
            peripherals={"UART1": pd},
            mcu_family="stm32f4",
            layers_run=["symbol", "string"],
            total_evidence=5,
        )

    def test_to_dict_top_level_keys(self) -> None:
        result = self._make_result()
        d = result.to_dict()
        assert d["architecture"] == "armv7m"
        assert d["mcu_family"] == "stm32f4"
        assert d["vendor_scores"] == {"stm32": 1.0, "nrf5": 0.3}
        assert d["layers_run"] == ["symbol", "string"]
        assert d["total_evidence"] == 5

    def test_to_dict_peripheral_keys(self) -> None:
        result = self._make_result()
        d = result.to_dict()
        assert "UART1" in d["peripherals"]
        uart = d["peripherals"]["UART1"]
        assert uart["name"] == "UART1"
        assert uart["type"] == "uart"
        assert uart["confidence"] == 1.3
        assert uart["confidence_level"] == "high"
        assert uart["base_address"] == "0x40011000"
        assert uart["vendor"] == "stm32"
        assert uart["instance"] is True
        assert uart["evidence_count"] == 1

    def test_to_dict_evidence_serialization(self) -> None:
        result = self._make_result()
        d = result.to_dict()
        uart = d["peripherals"]["UART1"]
        ev = uart["evidence"][0]
        assert ev["type"] == "symbol"
        assert ev["detail"] == "HAL symbol: HAL_UART_Init"
        assert ev["weight"] == 0.6
        assert ev["address"] == "0x08001000"

    def test_to_dict_null_base_address(self) -> None:
        pd = PeripheralDetection(name="SPI", peripheral_type="spi", confidence=0.6)
        result = DetectionResult(peripherals={"SPI": pd})
        d = result.to_dict()
        assert d["peripherals"]["SPI"]["base_address"] is None

    def test_to_dict_null_evidence_address(self) -> None:
        ev = Evidence(
            type=EvidenceType.SDK_STRING,
            peripheral="GPIO",
            weight=0.4,
            detail="test",
        )
        pd = PeripheralDetection(
            name="GPIO",
            peripheral_type="gpio",
            confidence=0.4,
            evidence=[ev],
        )
        result = DetectionResult(peripherals={"GPIO": pd})
        d = result.to_dict()
        assert d["peripherals"]["GPIO"]["evidence"][0]["address"] is None

    def test_to_dict_sorted_by_confidence_desc(self) -> None:
        low = PeripheralDetection(name="A", peripheral_type="a", confidence=0.3)
        high = PeripheralDetection(name="B", peripheral_type="b", confidence=2.0)
        mid = PeripheralDetection(name="C", peripheral_type="c", confidence=1.0)
        result = DetectionResult(peripherals={"A": low, "B": high, "C": mid})
        d = result.to_dict()
        names = list(d["peripherals"].keys())
        assert names == ["B", "C", "A"]

    def test_defaults(self) -> None:
        result = DetectionResult()
        assert result.architecture == "unknown"
        assert result.vendor_scores == {}
        assert result.peripherals == {}
        assert result.mcu_family == "unknown"
        assert result.layers_run == []
        assert result.total_evidence == 0
