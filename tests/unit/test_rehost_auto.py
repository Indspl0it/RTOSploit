"""Integration-style tests for auto-rehost mode in RehostingEngine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import capstone  # noqa: E402 — patch before any rtosploit import
if not hasattr(capstone, "CS_ARCH_XTENSA"):
    capstone.CS_ARCH_XTENSA = 0xFF  # stub so disasm.py can load

import pytest

from rtosploit.peripherals.rehost import RehostingEngine


# ---------------------------------------------------------------------------
# TestAutoMode
# ---------------------------------------------------------------------------

class TestAutoMode:
    def test_construction_auto_mode(self) -> None:
        """RehostingEngine(auto_mode=True) stores the flag."""
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            auto_mode=True,
        )
        assert engine.auto_mode is True
        assert engine.firmware_path == "test.elf"
        assert engine.machine_name == "stm32f4"
        assert engine.peripheral_config_path is None

    def test_construction_manual_mode(self) -> None:
        """Default construction has auto_mode=False."""
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
        )
        assert engine.auto_mode is False

    def test_get_auto_summary_before_setup(self) -> None:
        """get_auto_summary returns empty dict before auto_setup is called."""
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            auto_mode=True,
        )
        summary = engine.get_auto_summary()
        assert summary == {}

    def test_composite_mmio_before_setup(self) -> None:
        """composite_mmio is None before auto_setup."""
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            auto_mode=True,
        )
        assert engine.composite_mmio is None

    def test_manual_mode_requires_config(self) -> None:
        """Manual mode with no peripheral_config raises on setup."""
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            auto_mode=False,
        )
        qemu = MagicMock()
        qemu.gdb = MagicMock()

        with pytest.raises(ValueError, match="No peripheral config"):
            engine.setup(qemu)

    def test_auto_mode_delegates_to_auto_setup(self) -> None:
        """auto_mode=True with no config delegates setup() -> auto_setup()."""
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            auto_mode=True,
        )
        qemu = MagicMock()
        qemu.gdb = MagicMock()

        with patch.object(engine, "auto_setup", return_value=MagicMock()) as mock_auto:
            engine.setup(qemu)
            mock_auto.assert_called_once_with(qemu)

    def test_auto_mode_with_explicit_config_uses_manual(self) -> None:
        """auto_mode=True but explicit peripheral_config uses manual path."""
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            peripheral_config="peripherals.yaml",
            auto_mode=True,
        )
        qemu = MagicMock()
        qemu.gdb = MagicMock()

        # With peripheral_config set, setup should NOT call auto_setup
        with patch.object(engine, "auto_setup") as mock_auto:
            # It will fail loading the YAML, but auto_setup should NOT be called
            try:
                engine.setup(qemu)
            except Exception:
                pass
            mock_auto.assert_not_called()

    def test_get_auto_summary_returns_copy(self) -> None:
        """get_auto_summary returns a copy, not the internal dict."""
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            auto_mode=True,
        )
        summary1 = engine.get_auto_summary()
        summary2 = engine.get_auto_summary()
        assert summary1 is not summary2

    def test_construction_with_all_params(self) -> None:
        """RehostingEngine accepts config parameter."""
        config = {"some_key": "some_value"}
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            peripheral_config="config.yaml",
            config=config,
            auto_mode=True,
        )
        assert engine.firmware_path == "test.elf"
        assert engine.machine_name == "stm32f4"
        assert engine.peripheral_config_path == "config.yaml"
        assert engine.auto_mode is True
