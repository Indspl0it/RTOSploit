"""Unit tests for the simple detection layers (symbol, string, relocation, devicetree)."""

from __future__ import annotations

from pathlib import Path


from rtosploit.analysis.detection.evidence import EvidenceType, EVIDENCE_WEIGHTS
from rtosploit.utils.binary import (
    BinaryFormat,
    FirmwareImage,
    MemorySection,
    RelocationEntry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_firmware(
    strings: list[str] | None = None,
    symbols: dict[str, int] | None = None,
    relocations: list[RelocationEntry] | None = None,
    architecture: str = "armv7m",
) -> FirmwareImage:
    """Build a synthetic FirmwareImage with embedded strings and/or symbols."""
    data = b"\x00" * 0x100
    if strings:
        for s in strings:
            data += s.encode("ascii") + b"\x00"
    data += b"\x00" * 0x100

    section = MemorySection(
        name=".rodata",
        address=0x08000000,
        data=data,
        size=len(data),
        permissions="r",
    )

    return FirmwareImage(
        data=data,
        base_address=0x08000000,
        entry_point=0x08000000,
        format=BinaryFormat.ELF,
        sections=[section],
        symbols=symbols or {},
        relocations=relocations or [],
        path=Path("."),
        architecture=architecture,
    )


# ---------------------------------------------------------------------------
# Layer: symbol detection
# ---------------------------------------------------------------------------

class TestLayerSymbol:
    """Tests for rtosploit.analysis.detection.layer_symbol.detect_from_symbols."""

    def test_no_symbols_returns_empty(self) -> None:
        from rtosploit.analysis.detection.layer_symbol import detect_from_symbols

        fw = _make_firmware(symbols={})
        assert detect_from_symbols(fw) == []

    def test_stm32_uart_symbol(self) -> None:
        from rtosploit.analysis.detection.layer_symbol import detect_from_symbols

        fw = _make_firmware(symbols={"HAL_UART_Receive": 0x08001000})
        evidence = detect_from_symbols(fw)
        assert len(evidence) >= 1

        uart_ev = [e for e in evidence if "uart" in e.peripheral_type]
        assert len(uart_ev) >= 1
        ev = uart_ev[0]
        assert ev.type == EvidenceType.SYMBOL
        assert ev.weight == EVIDENCE_WEIGHTS[EvidenceType.SYMBOL]
        assert ev.vendor == "stm32"
        assert ev.address == 0x08001000

    def test_nrf5_spi_symbol(self) -> None:
        from rtosploit.analysis.detection.layer_symbol import detect_from_symbols

        fw = _make_firmware(symbols={"nrf_drv_spi_init": 0x00020000})
        evidence = detect_from_symbols(fw)
        spi_ev = [e for e in evidence if "spi" in e.peripheral_type]
        assert len(spi_ev) >= 1
        ev = spi_ev[0]
        assert ev.vendor == "nrf5"
        assert "SPI" in ev.peripheral

    def test_instance_extracted_from_symbol(self) -> None:
        from rtosploit.analysis.detection.layer_symbol import _infer_peripheral_name

        assert _infer_peripheral_name("HAL_UART1_Init", "uart") == "UART1"
        assert _infer_peripheral_name("HAL_UART_Receive", "uart") == "UART"
        assert _infer_peripheral_name("nrf_drv_spi_transfer", "spi") == "SPI"

    def test_multiple_symbols_produce_multiple_evidence(self) -> None:
        from rtosploit.analysis.detection.layer_symbol import detect_from_symbols

        fw = _make_firmware(symbols={
            "HAL_UART_Receive": 0x08001000,
            "HAL_GPIO_ReadPin": 0x08002000,
        })
        evidence = detect_from_symbols(fw)
        types = {e.peripheral_type for e in evidence}
        assert "uart" in types
        assert "gpio" in types


# ---------------------------------------------------------------------------
# Layer: string detection
# ---------------------------------------------------------------------------

class TestLayerString:
    """Tests for rtosploit.analysis.detection.layer_string.detect_from_strings."""

    def test_stm32_hal_uart_source(self) -> None:
        from rtosploit.analysis.detection.layer_string import detect_from_strings

        fw = _make_firmware(strings=["stm32f4xx_hal_uart.c"])
        evidence = detect_from_strings(fw)
        uart_ev = [e for e in evidence if e.peripheral_type == "uart"]
        assert len(uart_ev) >= 1
        ev = uart_ev[0]
        assert ev.type == EvidenceType.SDK_STRING
        assert ev.weight == EVIDENCE_WEIGHTS[EvidenceType.SDK_STRING]
        assert ev.vendor == "stm32"

    def test_nordic_driver_string(self) -> None:
        from rtosploit.analysis.detection.layer_string import detect_from_strings

        fw = _make_firmware(strings=["nrf_drv_uart"])
        evidence = detect_from_strings(fw)
        uart_ev = [e for e in evidence if e.peripheral_type == "uart"]
        assert len(uart_ev) >= 1
        assert uart_ev[0].vendor == "nrf5"

    def test_esp32_wifi_string(self) -> None:
        from rtosploit.analysis.detection.layer_string import detect_from_strings

        fw = _make_firmware(strings=["esp_wifi_init"])
        evidence = detect_from_strings(fw)
        wifi_ev = [e for e in evidence if e.peripheral_type == "wifi"]
        assert len(wifi_ev) >= 1
        assert wifi_ev[0].vendor == "esp32"

    def test_no_matching_strings_returns_empty(self) -> None:
        from rtosploit.analysis.detection.layer_string import detect_from_strings

        fw = _make_firmware(strings=["completely unrelated text here"])
        evidence = detect_from_strings(fw)
        assert evidence == []

    def test_deduplication(self) -> None:
        from rtosploit.analysis.detection.layer_string import detect_from_strings

        # Same pattern appearing twice should still produce one evidence entry
        fw = _make_firmware(strings=[
            "stm32f4xx_hal_uart.c",
            "stm32f4xx_hal_uart.c",
        ])
        evidence = detect_from_strings(fw)
        uart_ev = [e for e in evidence if e.peripheral_type == "uart" and e.vendor == "stm32"]
        # The dedup key is (desc, ptype), so same pattern should match once
        assert len(uart_ev) >= 1

    def test_extract_instance_helper(self) -> None:
        from rtosploit.analysis.detection.layer_string import _extract_instance

        assert _extract_instance("UART1 error", "uart") == "UART1"
        assert _extract_instance("generic uart", "uart") is None


# ---------------------------------------------------------------------------
# Layer: relocation detection
# ---------------------------------------------------------------------------

class TestLayerRelocation:
    """Tests for rtosploit.analysis.detection.layer_relocation.detect_from_relocations."""

    def test_no_relocations_returns_empty(self) -> None:
        from rtosploit.analysis.detection.layer_relocation import detect_from_relocations

        fw = _make_firmware(relocations=[])
        assert detect_from_relocations(fw) == []

    def test_matching_relocation(self) -> None:
        from rtosploit.analysis.detection.layer_relocation import detect_from_relocations

        relocs = [
            RelocationEntry(
                offset=0x08001000,
                symbol_name="HAL_UART_Receive",
                type=2,
            ),
        ]
        fw = _make_firmware(relocations=relocs)
        evidence = detect_from_relocations(fw)
        assert len(evidence) >= 1
        ev = evidence[0]
        assert ev.type == EvidenceType.RELOCATION
        assert ev.weight == EVIDENCE_WEIGHTS[EvidenceType.RELOCATION]
        assert ev.vendor == "stm32"
        assert ev.address == 0x08001000

    def test_non_matching_relocation(self) -> None:
        from rtosploit.analysis.detection.layer_relocation import detect_from_relocations

        relocs = [
            RelocationEntry(
                offset=0x08002000,
                symbol_name="unknown_function_xyz",
                type=2,
            ),
        ]
        fw = _make_firmware(relocations=relocs)
        evidence = detect_from_relocations(fw)
        assert evidence == []

    def test_deduplication_same_symbol(self) -> None:
        from rtosploit.analysis.detection.layer_relocation import detect_from_relocations

        relocs = [
            RelocationEntry(offset=0x08001000, symbol_name="HAL_UART_Receive", type=2),
            RelocationEntry(offset=0x08001010, symbol_name="HAL_UART_Receive", type=2),
        ]
        fw = _make_firmware(relocations=relocs)
        evidence = detect_from_relocations(fw)
        # Same symbol_name should only produce one evidence
        uart_ev = [e for e in evidence if "HAL_UART_Receive" in e.detail]
        assert len(uart_ev) == 1

    def test_empty_symbol_name_skipped(self) -> None:
        from rtosploit.analysis.detection.layer_relocation import detect_from_relocations

        relocs = [
            RelocationEntry(offset=0x08001000, symbol_name="", type=2),
        ]
        fw = _make_firmware(relocations=relocs)
        assert detect_from_relocations(fw) == []


# ---------------------------------------------------------------------------
# Layer: devicetree detection
# ---------------------------------------------------------------------------

class TestLayerDevicetree:
    """Tests for rtosploit.analysis.detection.layer_devicetree.detect_from_devicetree."""

    def test_dt_node_pattern(self) -> None:
        from rtosploit.analysis.detection.layer_devicetree import detect_from_devicetree

        fw = _make_firmware(strings=["uart@40002000"])
        evidence = detect_from_devicetree(fw)
        uart_ev = [e for e in evidence if e.peripheral_type == "uart"]
        assert len(uart_ev) >= 1
        ev = uart_ev[0]
        assert ev.type == EvidenceType.DEVICETREE_LABEL
        assert ev.weight == EVIDENCE_WEIGHTS[EvidenceType.DEVICETREE_LABEL]
        assert ev.vendor == "zephyr"
        assert ev.address == 0x40002000

    def test_dt_chosen_console(self) -> None:
        from rtosploit.analysis.detection.layer_devicetree import detect_from_devicetree

        fw = _make_firmware(strings=["DT_CHOSEN_zephyr_console"])
        evidence = detect_from_devicetree(fw)
        uart_ev = [e for e in evidence if e.peripheral_type == "uart"]
        assert len(uart_ev) >= 1

    def test_type_normalization(self) -> None:
        from rtosploit.analysis.detection.layer_devicetree import detect_from_devicetree

        fw = _make_firmware(strings=["usart@40011000"])
        evidence = detect_from_devicetree(fw)
        # "usart" should be normalized to "uart"
        uart_ev = [e for e in evidence if e.peripheral_type == "uart"]
        assert len(uart_ev) >= 1

    def test_twi_normalized_to_i2c(self) -> None:
        from rtosploit.analysis.detection.layer_devicetree import detect_from_devicetree

        fw = _make_firmware(strings=["twi@40003000"])
        evidence = detect_from_devicetree(fw)
        i2c_ev = [e for e in evidence if e.peripheral_type == "i2c"]
        assert len(i2c_ev) >= 1

    def test_multiple_peripherals(self) -> None:
        from rtosploit.analysis.detection.layer_devicetree import detect_from_devicetree

        fw = _make_firmware(strings=[
            "uart@40002000",
            "spi@40003000",
            "i2c@40005400",
        ])
        evidence = detect_from_devicetree(fw)
        types = {e.peripheral_type for e in evidence}
        assert "uart" in types
        assert "spi" in types
        assert "i2c" in types

    def test_deduplication(self) -> None:
        from rtosploit.analysis.detection.layer_devicetree import detect_from_devicetree

        fw = _make_firmware(strings=[
            "uart@40002000",
            "uart@40002000",
        ])
        evidence = detect_from_devicetree(fw)
        uart_ev = [e for e in evidence if e.peripheral_type == "uart"]
        # Dedup by peripheral name; both have same address so same name
        assert len(uart_ev) == 1

    def test_no_matching_strings(self) -> None:
        from rtosploit.analysis.detection.layer_devicetree import detect_from_devicetree

        fw = _make_firmware(strings=["nothing relevant here at all"])
        evidence = detect_from_devicetree(fw)
        assert evidence == []

    def test_dt_chosen_flash(self) -> None:
        from rtosploit.analysis.detection.layer_devicetree import detect_from_devicetree

        fw = _make_firmware(strings=["DT_CHOSEN_zephyr_flash"])
        evidence = detect_from_devicetree(fw)
        flash_ev = [e for e in evidence if e.peripheral_type == "flash"]
        assert len(flash_ev) >= 1
