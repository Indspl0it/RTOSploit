"""Tests for the debug crash CLI command.

Covers: crash JSON loading, input binary loading, CLI help, mock QEMU replay,
and error handling for missing files.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from rtosploit.cli.main import cli
from rtosploit.cli.commands.debug_crash import _load_crash_data, _decode_cfsr, _print_crash_context


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def crash_data():
    """Sample crash data matching CrashReporter.report_crash() schema."""
    return {
        "crash_id": "crash-w0-000001",
        "fault_type": "hard_fault",
        "cfsr": 131072,
        "registers": {
            "pc": 4680,
            "sp": 536903680,
            "lr": 4352,
            "r0": 0,
            "r1": 256,
            "r2": 0,
            "r3": 0,
        },
        "fault_address": 1073741824,
        "backtrace": [],
        "input_file": "crash-w0-000001.bin",
        "input_size": 256,
        "timestamp": 1709000000,
    }


@pytest.fixture
def crash_dir(tmp_path, crash_data):
    """Create a temporary crash directory with JSON and binary files."""
    json_path = tmp_path / "crash-w0-000001.json"
    json_path.write_text(json.dumps(crash_data))

    bin_path = tmp_path / "crash-w0-000001.bin"
    bin_path.write_bytes(b"\xaa" * 256)

    return tmp_path


@pytest.fixture
def crash_json_file(crash_dir):
    """Return path to the crash JSON file."""
    return str(crash_dir / "crash-w0-000001.json")


@pytest.fixture
def tiny_firmware(tmp_path):
    """Create a minimal raw firmware file for testing."""
    fw = tmp_path / "fw.bin"
    import struct
    data = struct.pack("<II", 0x20002000, 0x00000101) + b"\x00" * 56
    fw.write_bytes(data)
    return str(fw)


# --- Unit tests for helper functions ---

class TestLoadCrashData:
    """Tests for _load_crash_data()."""

    def test_load_from_json_file(self, crash_json_file, crash_data):
        loaded, input_bytes = _load_crash_data(crash_json_file)
        assert loaded["crash_id"] == "crash-w0-000001"
        assert loaded["fault_type"] == "hard_fault"
        assert len(input_bytes) == 256

    def test_load_from_directory(self, crash_dir, crash_data):
        loaded, input_bytes = _load_crash_data(str(crash_dir))
        assert loaded["crash_id"] == "crash-w0-000001"
        assert len(input_bytes) == 256

    def test_load_directory_picks_most_recent(self, tmp_path):
        """When multiple crash files exist, use the most recent."""
        import time

        # Create first crash
        data1 = {
            "crash_id": "crash-w0-000001",
            "fault_type": "hard_fault",
            "registers": {"pc": 100},
            "input_file": "crash-w0-000001.bin",
        }
        (tmp_path / "crash-w0-000001.json").write_text(json.dumps(data1))
        (tmp_path / "crash-w0-000001.bin").write_bytes(b"\x01" * 16)

        # Ensure different mtime
        time.sleep(0.05)

        # Create second crash (more recent)
        data2 = {
            "crash_id": "crash-w0-000002",
            "fault_type": "bus_fault",
            "registers": {"pc": 200},
            "input_file": "crash-w0-000002.bin",
        }
        (tmp_path / "crash-w0-000002.json").write_text(json.dumps(data2))
        (tmp_path / "crash-w0-000002.bin").write_bytes(b"\x02" * 32)

        loaded, input_bytes = _load_crash_data(str(tmp_path))
        assert loaded["crash_id"] == "crash-w0-000002"
        assert len(input_bytes) == 32

    def test_missing_json_in_directory(self, tmp_path):
        with pytest.raises(Exception, match="No crash JSON files found"):
            _load_crash_data(str(tmp_path))

    def test_invalid_json(self, tmp_path):
        bad_json = tmp_path / "crash-bad.json"
        bad_json.write_text("{not valid json")
        with pytest.raises(Exception, match="Invalid JSON"):
            _load_crash_data(str(bad_json))

    def test_missing_required_fields(self, tmp_path):
        incomplete = tmp_path / "crash-incomplete.json"
        incomplete.write_text(json.dumps({"crash_id": "test"}))
        with pytest.raises(Exception, match="Missing required field"):
            _load_crash_data(str(incomplete))

    def test_missing_input_binary(self, tmp_path):
        data = {
            "crash_id": "crash-w0-999999",
            "fault_type": "hard_fault",
            "registers": {"pc": 0},
            "input_file": "crash-w0-999999.bin",
        }
        (tmp_path / "crash-w0-999999.json").write_text(json.dumps(data))
        # Don't create the .bin file
        with pytest.raises(Exception, match="Crash input binary not found"):
            _load_crash_data(str(tmp_path / "crash-w0-999999.json"))

    def test_nonexistent_path(self, tmp_path):
        with pytest.raises(Exception, match="Path does not exist"):
            _load_crash_data(str(tmp_path / "nonexistent"))

    def test_fallback_to_crash_id_bin(self, tmp_path):
        """When input_file is missing from JSON, fall back to <crash_id>.bin."""
        data = {
            "crash_id": "crash-w0-000003",
            "fault_type": "hard_fault",
            "registers": {"pc": 0},
        }
        (tmp_path / "crash-w0-000003.json").write_text(json.dumps(data))
        (tmp_path / "crash-w0-000003.bin").write_bytes(b"\x03" * 8)

        loaded, input_bytes = _load_crash_data(str(tmp_path / "crash-w0-000003.json"))
        assert len(input_bytes) == 8


class TestDecodeCfsr:
    """Tests for CFSR bit decoding."""

    def test_undefinstr_bit(self):
        # Bit 16 = UNDEFINSTR = 0x10000 = 65536
        flags = _decode_cfsr(65536)
        assert any("UNDEFINSTR" in f for f in flags)

    def test_invstate_bit(self):
        # Bit 17 = INVSTATE = 0x20000 = 131072
        flags = _decode_cfsr(131072)
        assert any("INVSTATE" in f for f in flags)

    def test_multiple_bits(self):
        # Bit 9 (PRECISERR) + Bit 15 (BFARVALID) = 0x200 + 0x8000
        flags = _decode_cfsr(0x8200)
        assert len(flags) == 2
        assert any("PRECISERR" in f for f in flags)
        assert any("BFARVALID" in f for f in flags)

    def test_zero_cfsr(self):
        assert _decode_cfsr(0) == []


# --- CLI tests ---

class TestDebugCrashCLI:
    """Tests for the debug crash CLI command."""

    def test_debug_group_help(self, runner):
        result = runner.invoke(cli, ["debug", "--help"])
        assert result.exit_code == 0
        assert "Debug commands" in result.output

    def test_crash_subcommand_help(self, runner):
        result = runner.invoke(cli, ["debug", "crash", "--help"])
        assert result.exit_code == 0
        assert "Replay a crash input" in result.output
        assert "--firmware" in result.output
        assert "--machine" in result.output
        assert "--inject-addr" in result.output

    def test_crash_missing_firmware(self, runner, crash_json_file):
        result = runner.invoke(cli, [
            "debug", "crash", crash_json_file,
            "--firmware", "/nonexistent/fw.bin",
            "--machine", "mps2-an385",
        ])
        # Click validates Path(exists=True) before our code runs
        assert result.exit_code != 0

    def test_crash_json_output(self, runner, crash_json_file, tiny_firmware):
        result = runner.invoke(cli, [
            "--json",
            "debug", "crash", crash_json_file,
            "--firmware", tiny_firmware,
            "--machine", "mps2-an385",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["crash_id"] == "crash-w0-000001"
        assert data["fault_type"] == "hard_fault"
        assert data["status"] == "loaded"
        assert data["input_size"] == 256
        assert data["inject_addr"] == "0x20010000"

    def test_crash_json_output_custom_inject(self, runner, crash_json_file, tiny_firmware):
        result = runner.invoke(cli, [
            "--json",
            "debug", "crash", crash_json_file,
            "--firmware", tiny_firmware,
            "--machine", "mps2-an385",
            "--inject-addr", "0x20020000",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["inject_addr"] == "0x20020000"

    def test_crash_invalid_inject_addr(self, runner, crash_json_file, tiny_firmware):
        result = runner.invoke(cli, [
            "debug", "crash", crash_json_file,
            "--firmware", tiny_firmware,
            "--machine", "mps2-an385",
            "--inject-addr", "not-hex",
        ])
        assert result.exit_code != 0

    @patch("rtosploit.cli.commands.debug_crash.QEMUInstance", autospec=False)
    @patch("rtosploit.cli.commands.debug_crash.RTOSploitConfig", autospec=False)
    def test_crash_with_mock_qemu(self, mock_config_cls, mock_qemu_cls,
                                   runner, crash_json_file, tiny_firmware):
        """Test full replay flow with mocked QEMU."""
        mock_config = MagicMock()
        mock_config_cls.return_value = mock_config

        mock_instance = MagicMock()
        mock_qemu_cls.return_value = mock_instance

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.wait.side_effect = KeyboardInterrupt
        mock_instance._process = mock_process

        mock_gdb = MagicMock()
        mock_instance.gdb = mock_gdb

        result = runner.invoke(cli, [
            "debug", "crash", crash_json_file,
            "--firmware", tiny_firmware,
            "--machine", "mps2-an385",
        ])

        # Command should complete (KeyboardInterrupt is caught)
        assert result.exit_code == 0 or result.exit_code is None

        # Verify QEMU was started with correct args
        mock_qemu_cls.assert_called_once_with(mock_config)
        mock_instance.start.assert_called_once_with(
            firmware_path=tiny_firmware,
            machine_name="mps2-an385",
            gdb=True,
            paused=True,
        )

        # Verify crash input was injected
        mock_gdb.write_memory.assert_called_once_with(0x20010000, b"\xaa" * 256)

        # Verify breakpoint was set at fault address
        mock_gdb.set_breakpoint.assert_called_once_with(1073741824)

        # Verify cleanup
        mock_instance.stop.assert_called_once()

    @patch("rtosploit.cli.commands.debug_crash.QEMUInstance", autospec=False)
    @patch("rtosploit.cli.commands.debug_crash.RTOSploitConfig", autospec=False)
    def test_crash_no_gdb_client_error(self, mock_config_cls, mock_qemu_cls,
                                        runner, crash_json_file, tiny_firmware):
        """Test error when GDB client is None after start."""
        mock_config_cls.return_value = MagicMock()

        mock_instance = MagicMock()
        mock_qemu_cls.return_value = mock_instance
        mock_instance._process = MagicMock(pid=99)
        mock_instance.gdb = None  # GDB not initialized

        result = runner.invoke(cli, [
            "debug", "crash", crash_json_file,
            "--firmware", tiny_firmware,
            "--machine", "mps2-an385",
        ])

        assert result.exit_code == 1

    def test_crash_directory_input(self, runner, crash_dir, tiny_firmware):
        result = runner.invoke(cli, [
            "--json",
            "debug", "crash", str(crash_dir),
            "--firmware", tiny_firmware,
            "--machine", "mps2-an385",
        ])
        assert result.exit_code == 0
        # Output may contain stderr status line before JSON; extract the JSON block
        output = result.output
        json_start = output.index("{")
        data = json.loads(output[json_start:])
        assert data["crash_id"] == "crash-w0-000001"


class TestAutoFillFromCrashJSON:
    """Tests for auto-filling firmware/machine from crash JSON."""

    def test_firmware_and_machine_from_crash_json(self, runner, tmp_path):
        """When --firmware and --machine are omitted, use crash JSON values."""
        # Create firmware file at the path stored in crash JSON
        fw_path = tmp_path / "fw.bin"
        import struct
        fw_path.write_bytes(struct.pack("<II", 0x20002000, 0x00000101) + b"\x00" * 56)

        crash_data = {
            "crash_id": "crash-w0-000010",
            "fault_type": "hard_fault",
            "cfsr": 131072,
            "registers": {"pc": 4680, "sp": 536903680},
            "fault_address": 1073741824,
            "backtrace": [],
            "input_file": "crash-w0-000010.bin",
            "input_size": 16,
            "timestamp": 1709000000,
            "firmware_path": str(fw_path),
            "machine_name": "mps2-an385",
            "inject_addr": 0x20020000,
        }
        json_path = tmp_path / "crash-w0-000010.json"
        json_path.write_text(json.dumps(crash_data))
        (tmp_path / "crash-w0-000010.bin").write_bytes(b"\xbb" * 16)

        # Invoke without --firmware and --machine, use --json to avoid QEMU
        result = runner.invoke(cli, [
            "--json",
            "debug", "crash", str(json_path),
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["firmware"] == str(fw_path)
        assert data["machine"] == "mps2-an385"
        assert data["inject_addr"] == "0x20020000"

    def test_missing_firmware_and_machine_errors(self, runner, tmp_path):
        """Error when no --firmware/--machine and crash JSON lacks them too."""
        crash_data = {
            "crash_id": "crash-w0-000011",
            "fault_type": "hard_fault",
            "registers": {"pc": 0},
            "input_file": "crash-w0-000011.bin",
        }
        json_path = tmp_path / "crash-w0-000011.json"
        json_path.write_text(json.dumps(crash_data))
        (tmp_path / "crash-w0-000011.bin").write_bytes(b"\x00" * 8)

        result = runner.invoke(cli, [
            "debug", "crash", str(json_path),
        ])
        assert result.exit_code != 0

    def test_cli_firmware_overrides_crash_json(self, runner, tmp_path):
        """CLI --firmware takes precedence over crash JSON firmware_path."""
        fw_cli = tmp_path / "cli_fw.bin"
        import struct
        fw_cli.write_bytes(struct.pack("<II", 0x20002000, 0x00000101) + b"\x00" * 56)

        crash_data = {
            "crash_id": "crash-w0-000012",
            "fault_type": "hard_fault",
            "registers": {"pc": 0},
            "fault_address": 0,
            "input_file": "crash-w0-000012.bin",
            "firmware_path": "/nonexistent/fw.elf",
            "machine_name": "mps2-an385",
        }
        json_path = tmp_path / "crash-w0-000012.json"
        json_path.write_text(json.dumps(crash_data))
        (tmp_path / "crash-w0-000012.bin").write_bytes(b"\x00" * 8)

        result = runner.invoke(cli, [
            "--json",
            "debug", "crash", str(json_path),
            "--firmware", str(fw_cli),
            "--machine", "lm3s6965evb",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["firmware"] == str(fw_cli)
        assert data["machine"] == "lm3s6965evb"


class TestPrintCrashContext:
    """Tests for _print_crash_context() output."""

    def test_prints_without_error(self, crash_data, capsys):
        """Verify _print_crash_context doesn't raise."""
        _print_crash_context(crash_data)

    def test_prints_with_empty_registers(self):
        data = {
            "crash_id": "test-001",
            "fault_type": "usage_fault",
            "registers": {},
        }
        _print_crash_context(data)

    def test_prints_with_no_cfsr(self):
        data = {
            "crash_id": "test-002",
            "fault_type": "bus_fault",
            "registers": {"pc": 0x1000},
        }
        _print_crash_context(data)

    def test_prints_with_backtrace(self):
        data = {
            "crash_id": "test-003",
            "fault_type": "hard_fault",
            "registers": {"pc": 0x800},
            "backtrace": [0x800, 0x400, 0x100],
        }
        _print_crash_context(data)
