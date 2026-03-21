"""Unit tests for rtosploit.peripherals.config."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import yaml

from rtosploit.peripherals.config import (
    InterceptSpec,
    PeripheralConfig,
    PeripheralModelSpec,
    SymbolResolver,
    _import_class,
)


# ---------------------------------------------------------------------------
# PeripheralModelSpec / InterceptSpec
# ---------------------------------------------------------------------------

class TestDataclasses:
    def test_model_spec_defaults(self):
        spec = PeripheralModelSpec(
            name="uart1",
            model_class="rtosploit.peripherals.models.stm32_hal.STM32UART",
            base_addr=0x40011000,
            size=0x400,
        )
        assert spec.irq is None
        assert spec.args == {}

    def test_intercept_spec(self):
        spec = InterceptSpec(
            model_class="pkg.Cls",
            function="HAL_Init",
            symbol="HAL_Init",
        )
        assert spec.address is None
        assert spec.symbol == "HAL_Init"


# ---------------------------------------------------------------------------
# PeripheralConfig.load / _parse
# ---------------------------------------------------------------------------

class TestPeripheralConfigLoad:
    def test_load_valid_yaml(self, tmp_path):
        config_data = {
            "peripherals": {
                "uart1": {
                    "model": "pkg.STM32UART",
                    "base_addr": "0x40011000",
                    "size": "0x400",
                    "irq": 37,
                    "args": {"uart_id": 1},
                },
            },
            "intercepts": [
                {
                    "class": "pkg.STM32UART",
                    "function": "HAL_UART_Init",
                    "symbol": "HAL_UART_Init",
                },
                {
                    "class": "pkg.STM32RCC",
                    "function": "HAL_RCC_OscConfig",
                    "addr": "0x08001300",
                },
            ],
            "symbols": {
                "0x08001234": "HAL_UART_Init",
                "0x08001300": "HAL_UART_Transmit",
            },
        }

        yaml_file = tmp_path / "test_config.yaml"
        yaml_file.write_text(yaml.dump(config_data))

        config = PeripheralConfig.load(str(yaml_file))

        models = config.get_models()
        assert len(models) == 1
        assert models[0].name == "uart1"
        assert models[0].base_addr == 0x40011000
        assert models[0].size == 0x400
        assert models[0].irq == 37
        assert models[0].args == {"uart_id": 1}

        intercepts = config.get_intercepts()
        assert len(intercepts) == 2
        assert intercepts[0].function == "HAL_UART_Init"
        assert intercepts[0].symbol == "HAL_UART_Init"
        assert intercepts[0].address is None
        assert intercepts[1].address == 0x08001300

        symbols = config.get_symbols()
        assert symbols[0x08001234] == "HAL_UART_Init"

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            PeripheralConfig.load("/nonexistent/path.yaml")

    def test_load_empty_sections(self, tmp_path):
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text(yaml.dump({}))
        config = PeripheralConfig.load(str(yaml_file))
        assert config.get_models() == []
        assert config.get_intercepts() == []
        assert config.get_symbols() == {}

    def test_load_integer_base_addr(self, tmp_path):
        """Test that integer base_addr (not hex string) works."""
        config_data = {
            "peripherals": {
                "gpio": {
                    "model": "pkg.GPIO",
                    "base_addr": 0x40020000,
                    "size": 0x400,
                },
            },
        }
        yaml_file = tmp_path / "int_addr.yaml"
        yaml_file.write_text(yaml.dump(config_data))
        config = PeripheralConfig.load(str(yaml_file))
        assert config.get_models()[0].base_addr == 0x40020000


# ---------------------------------------------------------------------------
# _import_class
# ---------------------------------------------------------------------------

class TestImportClass:
    def test_import_known_class(self):
        cls = _import_class("rtosploit.peripherals.model.PeripheralModel")
        from rtosploit.peripherals.model import PeripheralModel
        assert cls is PeripheralModel

    def test_import_invalid_path(self):
        with pytest.raises(ImportError):
            _import_class("NoModule")


# ---------------------------------------------------------------------------
# SymbolResolver (with mock ELF)
# ---------------------------------------------------------------------------

class TestSymbolResolver:
    def test_resolve_with_mock_elf(self, tmp_path):
        """Test SymbolResolver with a mocked ELF file."""
        # We mock pyelftools to avoid needing a real ELF
        mock_symbol1 = MagicMock()
        mock_symbol1.name = "HAL_UART_Init"
        mock_symbol1.entry.st_value = 0x08001234

        mock_symbol2 = MagicMock()
        mock_symbol2.name = "HAL_RCC_OscConfig"
        mock_symbol2.entry.st_value = 0x08001300

        mock_symbol3 = MagicMock()
        mock_symbol3.name = "main"
        mock_symbol3.entry.st_value = 0x08000100

        mock_section = MagicMock()
        mock_section.header.sh_type = "SHT_SYMTAB"
        mock_section.iter_symbols.return_value = [mock_symbol1, mock_symbol2, mock_symbol3]

        mock_elf = MagicMock()
        mock_elf.iter_sections.return_value = [mock_section]

        with patch("rtosploit.peripherals.config.SymbolResolver._parse_elf"):
            resolver = SymbolResolver.__new__(SymbolResolver)
            resolver._symbols = {
                "HAL_UART_Init": 0x08001234,
                "HAL_RCC_OscConfig": 0x08001300,
                "main": 0x08000100,
            }

        assert resolver.resolve("HAL_UART_Init") == 0x08001234
        assert resolver.resolve("HAL_RCC_OscConfig") == 0x08001300
        assert resolver.resolve("NonExistent") is None

    def test_find_hal_functions(self):
        with patch("rtosploit.peripherals.config.SymbolResolver._parse_elf"):
            resolver = SymbolResolver.__new__(SymbolResolver)
            resolver._symbols = {
                "HAL_UART_Init": 0x08001234,
                "HAL_RCC_OscConfig": 0x08001300,
                "main": 0x08000100,
                "HAL_GPIO_Init": 0x08001400,
            }

        hal_funcs = resolver.find_hal_functions("HAL_")
        assert len(hal_funcs) == 3
        assert "main" not in hal_funcs
        assert "HAL_UART_Init" in hal_funcs


# ---------------------------------------------------------------------------
# PeripheralConfig.load_from_elf
# ---------------------------------------------------------------------------

class TestLoadFromElf:
    def test_resolves_symbols(self, tmp_path):
        config_data = {
            "peripherals": {},
            "intercepts": [
                {
                    "class": "pkg.STM32UART",
                    "function": "HAL_UART_Init",
                    "symbol": "HAL_UART_Init",
                },
                {
                    "class": "pkg.STM32RCC",
                    "function": "HAL_RCC_OscConfig",
                    "symbol": "HAL_RCC_OscConfig",
                },
                {
                    "class": "pkg.STM32RCC",
                    "function": "HAL_Missing",
                    "symbol": "HAL_Missing",
                },
            ],
        }
        yaml_file = tmp_path / "resolve_test.yaml"
        yaml_file.write_text(yaml.dump(config_data))

        # Mock the SymbolResolver
        with patch("rtosploit.peripherals.config.SymbolResolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = lambda name: {
                "HAL_UART_Init": 0x08001234,
                "HAL_RCC_OscConfig": 0x08001300,
            }.get(name)

            config = PeripheralConfig.load_from_elf(
                "dummy.elf", str(yaml_file)
            )

        intercepts = config.get_intercepts()
        assert intercepts[0].address == 0x08001234
        assert intercepts[1].address == 0x08001300
        assert intercepts[2].address is None  # not found
