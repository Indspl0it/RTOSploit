"""Peripheral configuration loader and ELF symbol resolver."""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class PeripheralModelSpec:
    """Specification for instantiating a peripheral model."""
    name: str
    model_class: str       # e.g. "rtosploit.peripherals.models.stm32_hal.STM32UART"
    base_addr: int
    size: int
    irq: int | None = None
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class InterceptSpec:
    """Specification for a single function intercept."""
    model_class: str       # class that owns the handler
    function: str          # HAL function name (matches @hal_handler)
    address: int | None = None   # resolved address
    symbol: str | None = None    # symbol name to resolve from ELF


class SymbolResolver:
    """Extract function addresses from ELF symbol tables."""

    def __init__(self, elf_path: str) -> None:
        """Parse ELF and build symbol -> address mapping using pyelftools."""
        self._symbols: dict[str, int] = {}
        self._parse_elf(elf_path)

    def _parse_elf(self, elf_path: str) -> None:
        from elftools.elf.elffile import ELFFile

        with open(elf_path, "rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if section.header.sh_type not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                    continue
                for symbol in section.iter_symbols():
                    if symbol.name and symbol.entry.st_value != 0:
                        # Store function symbols (STT_FUNC) and others
                        self._symbols[symbol.name] = symbol.entry.st_value

    def resolve(self, symbol_name: str) -> int | None:
        """Return address of symbol, or None if not found."""
        return self._symbols.get(symbol_name)

    def find_hal_functions(self, prefix: str = "HAL_") -> dict[str, int]:
        """Find all functions matching a prefix (e.g., 'HAL_' for STM32 HAL)."""
        return {
            name: addr
            for name, addr in self._symbols.items()
            if name.startswith(prefix)
        }

    @property
    def all_symbols(self) -> dict[str, int]:
        """Return a copy of all resolved symbols."""
        return dict(self._symbols)


class PeripheralConfig:
    """Loads peripheral model configuration from YAML.

    Config format:
        peripherals:
          uart1:
            model: rtosploit.peripherals.models.stm32_hal.STM32UART
            base_addr: 0x40011000
            size: 0x400
            irq: 37
            args:
              uart_id: 1

        intercepts:
          - class: rtosploit.peripherals.models.stm32_hal.STM32UART
            function: HAL_UART_Init
            symbol: HAL_UART_Init

        symbols:
          0x08001234: HAL_UART_Init
    """

    def __init__(
        self,
        models: list[PeripheralModelSpec],
        intercepts: list[InterceptSpec],
        symbols: dict[int, str],
    ) -> None:
        self._models = models
        self._intercepts = intercepts
        self._symbols = symbols

    @staticmethod
    def load(yaml_path: str) -> PeripheralConfig:
        """Load configuration from a YAML file."""
        path = Path(yaml_path)
        if not path.exists():
            raise FileNotFoundError(f"Peripheral config not found: {yaml_path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Invalid peripheral config: expected dict, got {type(data).__name__}")

        return PeripheralConfig._parse(data)

    @staticmethod
    def load_from_elf(elf_path: str, model_config: str) -> PeripheralConfig:
        """Load config and auto-resolve symbol addresses from ELF file."""
        config = PeripheralConfig.load(model_config)
        resolver = SymbolResolver(elf_path)

        # Resolve symbol-based intercepts
        for intercept in config._intercepts:
            if intercept.address is None and intercept.symbol is not None:
                addr = resolver.resolve(intercept.symbol)
                if addr is not None:
                    intercept.address = addr
                    logger.info(
                        "Resolved %s -> 0x%08x", intercept.symbol, addr
                    )
                else:
                    logger.warning(
                        "Symbol not found in ELF: %s", intercept.symbol
                    )

        return config

    @staticmethod
    def _parse(data: dict) -> PeripheralConfig:
        """Parse a config dict into PeripheralConfig."""
        models: list[PeripheralModelSpec] = []
        intercepts: list[InterceptSpec] = []
        symbols: dict[int, str] = {}

        # Parse peripherals
        for name, spec in data.get("peripherals", {}).items():
            base_addr = spec.get("base_addr", 0)
            if isinstance(base_addr, str):
                base_addr = int(base_addr, 16)
            size = spec.get("size", 0)
            if isinstance(size, str):
                size = int(size, 16)
            irq = spec.get("irq")

            models.append(PeripheralModelSpec(
                name=name,
                model_class=spec["model"],
                base_addr=base_addr,
                size=size,
                irq=irq,
                args=spec.get("args", {}),
            ))

        # Parse intercepts
        for item in data.get("intercepts", []):
            addr = item.get("addr")
            if isinstance(addr, str):
                addr = int(addr, 16)
            intercepts.append(InterceptSpec(
                model_class=item["class"],
                function=item["function"],
                address=addr,
                symbol=item.get("symbol"),
            ))

        # Parse manual symbol table
        for addr_key, sym_name in data.get("symbols", {}).items():
            addr_int = int(addr_key) if isinstance(addr_key, int) else int(str(addr_key), 0)
            symbols[addr_int] = sym_name

        return PeripheralConfig(
            models=models,
            intercepts=intercepts,
            symbols=symbols,
        )

    def get_models(self) -> list[PeripheralModelSpec]:
        """Return list of peripheral model specifications."""
        return list(self._models)

    def get_intercepts(self) -> list[InterceptSpec]:
        """Return list of intercept specifications."""
        return list(self._intercepts)

    def get_symbols(self) -> dict[int, str]:
        """Return manual symbol table."""
        return dict(self._symbols)

    def instantiate_models(self) -> dict[str, Any]:
        """Import and instantiate all configured peripheral models.

        Returns:
            Dict mapping model class name to instantiated PeripheralModel.
        """
        instances: dict[str, Any] = {}
        for spec in self._models:
            cls = _import_class(spec.model_class)
            instance = cls(spec.name, spec.base_addr, spec.size, **spec.args)
            instances[spec.model_class] = instance
        return instances


def _import_class(dotted_path: str) -> type:
    """Import a class from a dotted module path like 'pkg.mod.ClassName'."""
    module_path, _, class_name = dotted_path.rpartition(".")
    if not module_path:
        raise ImportError(f"Invalid class path: {dotted_path}")
    module = importlib.import_module(module_path)
    return getattr(module, class_name)
