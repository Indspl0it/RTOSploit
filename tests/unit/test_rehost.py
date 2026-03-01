"""Unit tests for rtosploit.peripherals.rehost."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
import yaml

from rtosploit.peripherals.rehost import (
    RehostingEngine,
    build_unimplemented_device_args,
)


class TestBuildUnimplementedDeviceArgs:
    @patch("rtosploit.peripherals.rehost.shutil.which", return_value="/usr/bin/qemu-system-arm")
    @patch("rtosploit.peripherals.rehost.subprocess.run")
    def test_default_args_when_supported(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(stdout="name \"unimplemented\"")
        args = build_unimplemented_device_args()
        assert len(args) == 2
        assert args[0] == "-device"
        assert "unimplemented" in args[1]
        assert "0x40000000" in args[1]

    @patch("rtosploit.peripherals.rehost.shutil.which", return_value="/usr/bin/qemu-system-arm")
    @patch("rtosploit.peripherals.rehost.subprocess.run")
    def test_custom_base_and_size(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(stdout="name \"unimplemented\"")
        args = build_unimplemented_device_args(base=0x50000000, size=0x1000)
        assert "0x50000000" in args[1]
        assert "0x1000" in args[1]

    @patch("rtosploit.peripherals.rehost.shutil.which", return_value="/usr/bin/qemu-system-arm")
    @patch("rtosploit.peripherals.rehost.subprocess.run")
    def test_returns_empty_when_unsupported(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(stdout="no matching device")
        args = build_unimplemented_device_args()
        assert args == []

    @patch("rtosploit.peripherals.rehost.shutil.which", return_value=None)
    def test_returns_empty_when_no_qemu(self, mock_which):
        args = build_unimplemented_device_args()
        assert args == []


class TestRehostingEngine:
    def _make_config_file(self, tmp_path):
        """Create a minimal peripheral config YAML."""
        config_data = {
            "peripherals": {
                "test_model": {
                    "model": "rtosploit.peripherals.models.generic.ReturnZero",
                    "base_addr": 0x40000000,
                    "size": 0x400,
                },
            },
            "intercepts": [
                {
                    "class": "rtosploit.peripherals.models.generic.ReturnZero",
                    "function": "__return_zero__",
                    "addr": "0x08001000",
                },
            ],
        }
        yaml_file = tmp_path / "test_periph.yaml"
        yaml_file.write_text(yaml.dump(config_data))
        return str(yaml_file)

    def test_construction(self):
        engine = RehostingEngine(
            firmware_path="test.elf",
            machine_name="stm32f4",
            peripheral_config="config.yaml",
        )
        assert engine.firmware_path == "test.elf"
        assert engine.machine_name == "stm32f4"
        assert engine.dispatcher is None

    def test_setup_requires_gdb(self):
        engine = RehostingEngine("test.elf", "stm32f4", "config.yaml")
        qemu = MagicMock()
        qemu.gdb = None
        with pytest.raises(RuntimeError, match="GDB connection required"):
            engine.setup(qemu)

    def test_setup_requires_config(self):
        engine = RehostingEngine("test.elf", "stm32f4", peripheral_config=None)
        qemu = MagicMock()
        qemu.gdb = MagicMock()
        with pytest.raises(ValueError, match="No peripheral config"):
            engine.setup(qemu)

    def test_setup_registers_intercepts(self, tmp_path):
        config_file = self._make_config_file(tmp_path)
        engine = RehostingEngine("test.bin", "stm32f4", config_file)

        gdb = MagicMock()
        qemu = MagicMock()
        qemu.gdb = gdb

        dispatcher = engine.setup(qemu)

        assert dispatcher is not None
        assert 0x08001000 in dispatcher.registered_addresses
        assert engine.dispatcher is dispatcher

    def test_setup_skips_unresolved_intercepts(self, tmp_path):
        config_data = {
            "peripherals": {
                "test": {
                    "model": "rtosploit.peripherals.models.generic.ReturnZero",
                    "base_addr": 0x40000000,
                    "size": 0x400,
                },
            },
            "intercepts": [
                {
                    "class": "rtosploit.peripherals.models.generic.ReturnZero",
                    "function": "__return_zero__",
                    "symbol": "NoSuchSymbol",
                    # No addr — and symbol won't resolve for .bin
                },
            ],
        }
        yaml_file = tmp_path / "unresolved.yaml"
        yaml_file.write_text(yaml.dump(config_data))

        engine = RehostingEngine("test.bin", "stm32f4", str(yaml_file))
        qemu = MagicMock()
        qemu.gdb = MagicMock()

        dispatcher = engine.setup(qemu)
        # Should skip the unresolved intercept
        assert len(dispatcher.registered_addresses) == 0
