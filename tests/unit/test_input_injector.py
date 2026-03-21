"""Unit tests for the fuzz input injector."""

from __future__ import annotations

from pathlib import Path

import capstone  # noqa: E402 — patch before any rtosploit import
if not hasattr(capstone, "CS_ARCH_XTENSA"):
    capstone.CS_ARCH_XTENSA = 0xFF  # stub so disasm.py can load


from rtosploit.fuzzing.input_injector import FuzzableInput, InputInjector
from rtosploit.utils.binary import BinaryFormat, FirmwareImage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_firmware(symbols: dict[str, int] | None = None) -> FirmwareImage:
    """Build a minimal synthetic FirmwareImage with optional symbols."""
    return FirmwareImage(
        data=b"\x00" * 256,
        base_address=0x08000000,
        entry_point=0x08000000,
        format=BinaryFormat.RAW,
        symbols=symbols or {},
        path=Path("synthetic.bin"),
        architecture="armv7m",
    )


# ---------------------------------------------------------------------------
# TestFuzzableInput
# ---------------------------------------------------------------------------

class TestFuzzableInput:
    def test_construction(self) -> None:
        inp = FuzzableInput(
            symbol="HAL_UART_Receive",
            address=0x08001000,
            peripheral_type="uart",
            vendor="stm32",
        )
        assert inp.symbol == "HAL_UART_Receive"
        assert inp.address == 0x08001000
        assert inp.peripheral_type == "uart"
        assert inp.vendor == "stm32"

    def test_default_buffer_size(self) -> None:
        inp = FuzzableInput(
            symbol="test", address=0, peripheral_type="uart", vendor="stm32",
        )
        assert inp.buffer_size == 256

    def test_default_priority(self) -> None:
        inp = FuzzableInput(
            symbol="test", address=0, peripheral_type="uart", vendor="stm32",
        )
        assert inp.priority == 0


# ---------------------------------------------------------------------------
# TestInputInjector
# ---------------------------------------------------------------------------

class TestInputInjector:
    def test_discover_with_uart_symbols(self) -> None:
        """Firmware containing HAL_UART_Receive should yield a uart input."""
        fw = _make_firmware({
            "HAL_UART_Receive": 0x08001000,
            "HAL_Init": 0x08000100,  # not an input function
        })
        injector = InputInjector.discover(fw)

        assert injector.input_count == 1
        inp = injector.inputs[0]
        assert inp.symbol == "HAL_UART_Receive"
        assert inp.peripheral_type == "uart"
        assert inp.vendor == "stm32"
        assert inp.priority == 100  # uart priority from _TYPE_PRIORITY

    def test_discover_with_nrf5_uart(self) -> None:
        """nrf_drv_uart_rx is semantic='input' and should be discovered."""
        fw = _make_firmware({"nrf_drv_uart_rx": 0x00020000})
        injector = InputInjector.discover(fw)

        assert injector.input_count == 1
        assert injector.inputs[0].symbol == "nrf_drv_uart_rx"
        assert injector.inputs[0].vendor == "nrf5"

    def test_discover_multiple_input_types(self) -> None:
        """Multiple input symbols from different peripheral types."""
        fw = _make_firmware({
            "HAL_UART_Receive": 0x08001000,
            "HAL_SPI_Receive": 0x08002000,
            "HAL_I2C_Master_Receive": 0x08003000,
        })
        injector = InputInjector.discover(fw)

        assert injector.input_count == 3
        # Should be sorted by priority: uart(100) > spi(70) > i2c(60)
        types = [inp.peripheral_type for inp in injector.inputs]
        assert types == ["uart", "spi", "i2c"]

    def test_discover_no_symbols(self) -> None:
        """Firmware with no symbols yields empty injector."""
        fw = _make_firmware({})
        injector = InputInjector.discover(fw)

        assert injector.input_count == 0
        assert injector.inputs == []

    def test_discover_no_input_symbols(self) -> None:
        """Firmware with only output/init symbols yields empty injector."""
        fw = _make_firmware({
            "HAL_UART_Transmit": 0x08001000,
            "HAL_Init": 0x08000100,
        })
        injector = InputInjector.discover(fw)

        assert injector.input_count == 0

    def test_split_data_proportional(self) -> None:
        """Split distributes bytes proportional to priority."""
        inputs = [
            FuzzableInput(
                symbol="uart_rx", address=0x1000,
                peripheral_type="uart", vendor="stm32", priority=100,
            ),
            FuzzableInput(
                symbol="spi_rx", address=0x2000,
                peripheral_type="spi", vendor="stm32", priority=100,
            ),
        ]
        injector = InputInjector(inputs)
        data = bytes(range(100))
        result = injector.split_data(data)

        assert len(result) == 2
        # Equal priority -> roughly equal split
        assert result[0][0].symbol == "uart_rx"
        assert result[1][0].symbol == "spi_rx"
        total_bytes = sum(len(chunk) for _, chunk in result)
        assert total_bytes == 100

    def test_split_data_single_input(self) -> None:
        """Single input gets all bytes."""
        inputs = [
            FuzzableInput(
                symbol="uart_rx", address=0x1000,
                peripheral_type="uart", vendor="stm32", priority=100,
            ),
        ]
        injector = InputInjector(inputs)
        data = b"\xAA\xBB\xCC\xDD"
        result = injector.split_data(data)

        assert len(result) == 1
        assert result[0][1] == data

    def test_split_data_empty(self) -> None:
        """Empty data returns empty list."""
        inputs = [
            FuzzableInput(
                symbol="uart_rx", address=0x1000,
                peripheral_type="uart", vendor="stm32", priority=100,
            ),
        ]
        injector = InputInjector(inputs)
        result = injector.split_data(b"")

        assert result == []

    def test_split_data_no_inputs(self) -> None:
        """No inputs returns empty list regardless of data."""
        injector = InputInjector([])
        result = injector.split_data(b"\x01\x02\x03")

        assert result == []

    def test_split_data_updates_total_injected(self) -> None:
        """split_data accumulates total_injected counter."""
        inputs = [
            FuzzableInput(
                symbol="uart_rx", address=0x1000,
                peripheral_type="uart", vendor="stm32", priority=100,
            ),
        ]
        injector = InputInjector(inputs)
        assert injector.total_injected == 0

        injector.split_data(b"\x01\x02\x03")
        assert injector.total_injected == 3

        injector.split_data(b"\x04\x05")
        assert injector.total_injected == 5

    def test_get_breakpoint_addresses(self) -> None:
        """get_breakpoint_addresses returns address for each input."""
        inputs = [
            FuzzableInput(
                symbol="uart_rx", address=0x08001000,
                peripheral_type="uart", vendor="stm32", priority=100,
            ),
            FuzzableInput(
                symbol="spi_rx", address=0x08002000,
                peripheral_type="spi", vendor="stm32", priority=70,
            ),
        ]
        injector = InputInjector(inputs)
        addrs = injector.get_breakpoint_addresses()

        assert addrs == [0x08001000, 0x08002000]

    def test_get_breakpoint_addresses_empty(self) -> None:
        """Empty injector has no breakpoint addresses."""
        injector = InputInjector([])
        assert injector.get_breakpoint_addresses() == []

    def test_to_dict(self) -> None:
        """to_dict serializes injector state."""
        inputs = [
            FuzzableInput(
                symbol="HAL_UART_Receive", address=0x08001000,
                peripheral_type="uart", vendor="stm32", priority=100,
            ),
        ]
        injector = InputInjector(inputs)
        injector.split_data(b"\x01\x02\x03")

        d = injector.to_dict()

        assert d["input_count"] == 1
        assert d["total_injected"] == 3
        assert len(d["inputs"]) == 1
        entry = d["inputs"][0]
        assert entry["symbol"] == "HAL_UART_Receive"
        assert entry["address"] == "0x08001000"
        assert entry["type"] == "uart"
        assert entry["vendor"] == "stm32"
        assert entry["priority"] == 100
