"""Unit tests for the HAL function database."""

from __future__ import annotations

import pytest

from rtosploit.peripherals.hal_database import HALDatabase


@pytest.fixture
def db() -> HALDatabase:
    return HALDatabase()


class TestHALDatabaseLoading:
    def test_database_loads(self, db: HALDatabase) -> None:
        assert db.size > 100

    def test_get_vendors(self, db: HALDatabase) -> None:
        vendors = db.get_vendors()
        assert vendors == ["nrf5", "stm32", "zephyr"]

    def test_get_peripheral_types(self, db: HALDatabase) -> None:
        types = db.get_peripheral_types()
        for expected in ["uart", "spi", "i2c", "gpio", "ble", "timer", "clock", "flash"]:
            assert expected in types

    def test_all_entries_have_required_fields(self, db: HALDatabase) -> None:
        for i in range(db.size):
            entry = db._entries[i]
            assert entry.symbol, f"Entry {i} missing symbol"
            assert entry.vendor, f"Entry {i} missing vendor"
            assert entry.peripheral_type, f"Entry {i} missing peripheral_type"
            assert entry.semantic, f"Entry {i} missing semantic"
            assert entry.model_class, f"Entry {i} missing model_class"
            assert entry.handler_name, f"Entry {i} missing handler_name"

    def test_no_duplicate_symbols(self, db: HALDatabase) -> None:
        symbols = [e.symbol for e in db._entries]
        assert len(symbols) == len(set(symbols)), f"Duplicate symbols found: {[s for s in symbols if symbols.count(s) > 1]}"


class TestSymbolLookup:
    def test_lookup_symbol_found(self, db: HALDatabase) -> None:
        entry = db.lookup_symbol("HAL_UART_Receive")
        assert entry is not None
        assert entry.vendor == "stm32"
        assert entry.peripheral_type == "uart"
        assert entry.semantic == "input"

    def test_lookup_symbol_not_found(self, db: HALDatabase) -> None:
        entry = db.lookup_symbol("nonexistent_function_xyz")
        assert entry is None

    def test_lookup_nrf5_symbol(self, db: HALDatabase) -> None:
        entry = db.lookup_symbol("nrf_drv_uart_rx")
        assert entry is not None
        assert entry.vendor == "nrf5"
        assert entry.peripheral_type == "uart"
        assert entry.semantic == "input"

    def test_lookup_zephyr_symbol(self, db: HALDatabase) -> None:
        entry = db.lookup_symbol("uart_fifo_read")
        assert entry is not None
        assert entry.vendor == "zephyr"
        assert entry.peripheral_type == "uart"
        assert entry.semantic == "input"


class TestVendorLookup:
    def test_lookup_vendor_stm32(self, db: HALDatabase) -> None:
        entries = db.lookup_vendor("stm32")
        assert len(entries) >= 40

    def test_lookup_vendor_nrf5(self, db: HALDatabase) -> None:
        entries = db.lookup_vendor("nrf5")
        assert len(entries) >= 50

    def test_lookup_vendor_zephyr(self, db: HALDatabase) -> None:
        entries = db.lookup_vendor("zephyr")
        assert len(entries) >= 20

    def test_lookup_vendor_nonexistent(self, db: HALDatabase) -> None:
        entries = db.lookup_vendor("nonexistent")
        assert entries == []


class TestPeripheralLookup:
    def test_lookup_peripheral_uart(self, db: HALDatabase) -> None:
        entries = db.lookup_peripheral("uart")
        vendors = set(e.vendor for e in entries)
        assert "stm32" in vendors
        assert "nrf5" in vendors
        assert "zephyr" in vendors

    def test_lookup_peripheral_ble(self, db: HALDatabase) -> None:
        entries = db.lookup_peripheral("ble")
        vendors = set(e.vendor for e in entries)
        assert "nrf5" in vendors
        assert "zephyr" in vendors


class TestSemanticQueries:
    def test_get_input_functions(self, db: HALDatabase) -> None:
        inputs = db.get_input_functions()
        assert len(inputs) > 0
        for entry in inputs:
            assert entry.semantic == "input"


class TestFirmwareSymbolMatching:
    def test_match_firmware_symbols(self, db: HALDatabase) -> None:
        symbols = {
            "HAL_UART_Receive": 0x08001000,
            "HAL_GPIO_ReadPin": 0x08002000,
            "some_unknown_func": 0x08003000,
        }
        matches = db.match_firmware_symbols(symbols)
        assert len(matches) == 2
        matched_syms = {e.symbol for e, _ in matches}
        assert "HAL_UART_Receive" in matched_syms
        assert "HAL_GPIO_ReadPin" in matched_syms

    def test_match_firmware_symbols_nrf5(self, db: HALDatabase) -> None:
        symbols = {
            "nrf_drv_uart_rx": 0x00020000,
            "nrf_drv_clock_init": 0x00020100,
            "main": 0x00020200,
        }
        matches = db.match_firmware_symbols(symbols)
        assert len(matches) == 2
        matched_syms = {e.symbol for e, _ in matches}
        assert "nrf_drv_uart_rx" in matched_syms
        assert "nrf_drv_clock_init" in matched_syms

    def test_match_firmware_symbols_addresses_preserved(self, db: HALDatabase) -> None:
        symbols = {"HAL_UART_Receive": 0x08001234}
        matches = db.match_firmware_symbols(symbols)
        assert len(matches) == 1
        entry, addr = matches[0]
        assert addr == 0x08001234

    def test_match_firmware_symbols_empty(self, db: HALDatabase) -> None:
        matches = db.match_firmware_symbols({})
        assert matches == []
