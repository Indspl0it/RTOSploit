"""Unit tests for rtosploit.emulation modules.

All tests use mocks — no real QEMU process is required.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch, call

import pytest
import yaml

from rtosploit.emulation.machines import (
    PeripheralConfig,
    load_machine,
    list_machines,
    _parse_machine_yaml,
)
from rtosploit.emulation.qmp import QMPClient
from rtosploit.emulation.gdb import GDBClient, _checksum
from rtosploit.emulation.memory import MemoryOps, _parse_xp_output
from rtosploit.emulation.snapshot import SnapshotManager
from rtosploit.errors import (
    InvalidConfigError,
    UnknownMachineError,
    OperationError,
    QEMUCrashError,
)


# ---------------------------------------------------------------------------
# Helper: minimal machine YAML dict
# ---------------------------------------------------------------------------

def _minimal_machine_yaml(name: str = "test-machine") -> dict:
    return {
        "machine": {
            "name": name,
            "qemu_machine": "mps2-an385",
            "cpu": "cortex-m3",
            "architecture": "armv7m",
        },
        "memory": {
            "flash": {"base": 0x00000000, "size": 0x00400000, "permissions": "rx"},
            "sram": {"base": 0x20000000, "size": 0x00400000, "permissions": "rwx"},
        },
        "peripherals": {
            "uart0": {"base": 0x40004000, "size": 0x1000, "irq": 0},
            "systick": {"base": 0xE000E010, "size": 0x10, "builtin": True},
        },
    }


# ===========================================================================
# 1. MachineConfig tests
# ===========================================================================

class TestMachineConfig:
    """Tests for machine configuration loading and validation."""

    def test_parse_minimal_yaml(self):
        """MachineConfig fields are correctly parsed from a minimal YAML dict."""
        data = _minimal_machine_yaml()
        config = _parse_machine_yaml(data, "test")

        assert config.name == "test-machine"
        assert config.qemu_machine == "mps2-an385"
        assert config.cpu == "cortex-m3"
        assert config.architecture == "armv7m"

    def test_peripheral_parsed(self):
        """Peripherals are parsed into PeripheralConfig objects."""
        data = _minimal_machine_yaml()
        config = _parse_machine_yaml(data, "test")

        assert "uart0" in config.peripherals
        uart = config.peripherals["uart0"]
        assert isinstance(uart, PeripheralConfig)
        assert uart.base == 0x40004000
        assert uart.size == 0x1000
        assert uart.irq == 0
        assert uart.builtin is False

    def test_builtin_peripheral(self):
        """Peripherals with builtin=True are parsed correctly."""
        data = _minimal_machine_yaml()
        config = _parse_machine_yaml(data, "test")

        systick = config.peripherals["systick"]
        assert systick.builtin is True
        assert systick.irq is None

    def test_memory_regions_present(self):
        """Memory regions are stored in the config."""
        data = _minimal_machine_yaml()
        config = _parse_machine_yaml(data, "test")

        assert "flash" in config.memory
        assert "sram" in config.memory

    def test_missing_required_field_raises(self):
        """InvalidConfigError is raised when required fields are missing."""
        data = _minimal_machine_yaml()
        del data["machine"]["cpu"]

        with pytest.raises(InvalidConfigError, match="cpu"):
            _parse_machine_yaml(data, "test")

    def test_overlapping_memory_raises(self):
        """InvalidConfigError is raised when memory regions overlap."""
        data = _minimal_machine_yaml()
        # Make flash and sram overlap
        data["memory"]["sram"]["base"] = 0x00200000  # overlaps with flash (0..0x400000)

        with pytest.raises(InvalidConfigError, match="overlap"):
            _parse_machine_yaml(data, "test")

    def test_peripheral_missing_base_raises(self):
        """InvalidConfigError is raised for peripherals without 'base'."""
        data = _minimal_machine_yaml()
        data["peripherals"]["bad"] = {"size": 0x100}

        with pytest.raises(InvalidConfigError, match="base"):
            _parse_machine_yaml(data, "test")

    def test_load_machine_by_name_mps2(self):
        """load_machine('mps2-an385') loads from configs/machines/."""
        config = load_machine("mps2-an385")
        assert config.name == "mps2-an385"
        assert config.cpu == "cortex-m3"
        assert config.architecture == "armv7m"

    def test_load_machine_by_name_stm32(self):
        """load_machine('stm32f4') loads the STM32F4 config."""
        config = load_machine("stm32f4")
        assert config.name == "stm32f4"
        assert config.cpu == "cortex-m4"

    def test_load_machine_from_path(self, tmp_path):
        """load_machine accepts a direct YAML file path."""
        machine_yaml = tmp_path / "my-machine.yaml"
        data = _minimal_machine_yaml("custom-board")
        machine_yaml.write_text(yaml.dump(data))

        config = load_machine(str(machine_yaml))
        assert config.name == "custom-board"

    def test_load_machine_unknown_raises(self):
        """UnknownMachineError is raised for unknown machine names."""
        with pytest.raises(UnknownMachineError, match="nonexistent-board"):
            load_machine("nonexistent-board")

    def test_load_machine_path_not_found_raises(self):
        """InvalidConfigError is raised for missing file paths."""
        with pytest.raises(InvalidConfigError, match="not found"):
            load_machine("/tmp/does-not-exist.yaml")


# ===========================================================================
# 2. list_machines() tests
# ===========================================================================

class TestListMachines:
    """Tests for list_machines() scanning configs/machines/."""

    def test_list_machines_returns_tuples(self):
        """list_machines() returns a list of 3-tuples."""
        machines = list_machines()
        assert isinstance(machines, list)
        assert len(machines) > 0
        for item in machines:
            assert len(item) == 3, f"Expected 3-tuple, got {item}"
            name, cpu, arch = item
            assert isinstance(name, str)
            assert isinstance(cpu, str)
            assert isinstance(arch, str)

    def test_list_machines_includes_known(self):
        """list_machines() includes the bundled machine configs."""
        machines = list_machines()
        names = [m[0] for m in machines]
        assert "mps2-an385" in names
        assert "stm32f4" in names

    def test_list_machines_custom_dir(self, tmp_path):
        """list_machines() with a patched configs dir returns custom machines."""
        # Create a temporary config
        machine_data = _minimal_machine_yaml("custom-test")
        yaml_file = tmp_path / "custom-test.yaml"
        yaml_file.write_text(yaml.dump(machine_data))

        with patch("rtosploit.emulation.machines._get_configs_dir", return_value=tmp_path):
            machines = list_machines()

        names = [m[0] for m in machines]
        assert "custom-test" in names

    def test_list_machines_empty_dir(self, tmp_path):
        """list_machines() returns empty list for empty directory."""
        with patch("rtosploit.emulation.machines._get_configs_dir", return_value=tmp_path):
            machines = list_machines()
        assert machines == []


# ===========================================================================
# 3. QMPClient tests
# ===========================================================================

class TestQMPClient:
    """Tests for the QMP client (mocked socket)."""

    def _make_mock_socket(self, responses: list[bytes]) -> MagicMock:
        """Create a mock socket that yields responses in sequence."""
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = responses
        return mock_sock

    def test_read_response_parses_greeting(self):
        """_read_response() correctly parses a QMP greeting line."""
        client = QMPClient()
        greeting = {"QMP": {"version": {"qemu": {"major": 9, "minor": 2, "micro": 0}}}}
        raw = json.dumps(greeting).encode() + b"\n"

        mock_sock = MagicMock()
        mock_sock.recv.return_value = raw
        client._sock = mock_sock

        result = client._read_response()
        assert "QMP" in result

    def test_read_response_buffers_events(self):
        """_read_response() buffers event messages and returns the next non-event."""
        client = QMPClient()
        event = {"event": "STOP", "data": {}, "timestamp": {}}
        response = {"return": {}}
        raw = (json.dumps(event) + "\n" + json.dumps(response) + "\n").encode()

        mock_sock = MagicMock()
        mock_sock.recv.return_value = raw
        client._sock = mock_sock

        result = client._read_response()
        assert "return" in result
        assert len(client._events) == 1
        assert client._events[0]["event"] == "STOP"

    def test_read_response_partial_reads(self):
        """_read_response() handles data arriving in multiple recv() chunks."""
        client = QMPClient()
        response = {"return": {"status": "running"}}
        full = json.dumps(response).encode() + b"\n"
        # Split into 2 chunks
        chunk1 = full[:5]
        chunk2 = full[5:]

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [chunk1, chunk2]
        client._sock = mock_sock

        result = client._read_response()
        assert result == {"return": {"status": "running"}}

    def test_execute_returns_return_value(self):
        """execute() sends a command and returns the 'return' field."""
        client = QMPClient()
        client._sock = MagicMock()

        response = {"return": {"status": "running", "running": True}}
        client._read_response = MagicMock(return_value=response)

        result = client.execute("query-status")
        assert result == {"status": "running", "running": True}
        client._sock.sendall.assert_called_once()

    def test_execute_raises_on_error(self):
        """execute() raises OperationError when QMP returns an error."""
        client = QMPClient()
        client._sock = MagicMock()

        error_response = {"error": {"class": "GenericError", "desc": "device not found"}}
        client._read_response = MagicMock(return_value=error_response)

        with pytest.raises(OperationError, match="device not found"):
            client.execute("query-block")

    def test_get_events_returns_buffered(self):
        """get_events() returns and clears buffered events."""
        client = QMPClient()
        client._events = [
            {"event": "STOP", "data": {}},
            {"event": "RESUME", "data": {}},
        ]
        # Mock socket for non-blocking drain
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = BlockingIOError
        client._sock = mock_sock

        events = client.get_events()
        assert len(events) == 2
        assert events[0]["event"] == "STOP"
        assert client._events == []  # Cleared after return

    def test_connect_retry_on_failure(self):
        """connect() retries up to 10 times before raising QEMUCrashError."""
        client = QMPClient()

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = FileNotFoundError("no such file")
            mock_socket_cls.return_value = mock_sock

            with patch("time.sleep"):  # Don't actually sleep in tests
                with pytest.raises(QEMUCrashError, match="Failed to connect"):
                    client.connect("/tmp/nonexistent.sock", timeout=1.0)

            # Should have tried 10 times
            assert mock_sock.connect.call_count == 10

    def test_close_clears_connection(self):
        """close() sets _connected to False and clears the socket."""
        client = QMPClient()
        client._sock = MagicMock()
        client._connected = True

        client.close()

        assert not client._connected
        assert client._sock is None


# ===========================================================================
# 4. GDBClient tests
# ===========================================================================

class TestGDBClient:
    """Tests for GDB RSP client (mocked socket)."""

    def test_checksum_calculation(self):
        """RSP checksum is sum of bytes mod 256."""
        assert _checksum("g") == ord("g") % 256
        assert _checksum("OK") == (ord("O") + ord("K")) % 256
        assert _checksum("") == 0

    def test_send_packet_format(self):
        """_send_packet() sends correctly formatted RSP packet."""
        client = GDBClient()
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"+"  # ACK
        client._sock = mock_sock

        client._send_packet("g")

        sent_data = mock_sock.sendall.call_args[0][0].decode("latin-1")
        assert sent_data.startswith("$g#")
        # Checksum for 'g' is 103 % 256 = 103 = 0x67
        assert sent_data.endswith(f"#{_checksum('g'):02x}")

    def test_recv_packet_validates_checksum(self):
        """_recv_packet() accepts packets with valid checksums."""
        client = GDBClient()
        mock_sock = MagicMock()

        payload = "OK"
        csum = _checksum(payload)
        _raw_response = f"$OK#{csum:02x}".encode("latin-1")

        # recv calls: read until '$', then packet body + checksum
        _call_responses = [b"$"] + [c.to_bytes(1, "little") for c in b"OK#"] + [
            bytes([csum >> 4 | (csum & 0xF0), csum & 0x0F])
        ]
        # Simpler: return the entire packet as body
        mock_sock.recv.side_effect = [b"$", b"OK#", f"{csum:02x}".encode()]
        client._sock = mock_sock

        # Use the full packet approach
        mock_sock.recv.side_effect = None
        mock_sock.recv.return_value = b""

        # Build full response
        full_packet = f"$OK#{csum:02x}".encode("latin-1")

        def recv_side_effect(size):
            nonlocal full_packet
            chunk = full_packet[:size]
            full_packet = full_packet[size:]
            if not chunk:
                raise Exception("No more data")
            return chunk

        mock_sock.recv.side_effect = recv_side_effect
        result = client._recv_packet()
        assert result == "OK"

    def test_recv_packet_rejects_bad_checksum(self):
        """_recv_packet() raises OperationError on checksum mismatch."""
        client = GDBClient()
        mock_sock = MagicMock()

        # Correct payload would have checksum 0x4f+0x4b=0x9a -> 0x9a
        # We send 0x00 as the checksum (wrong)
        bad_packet = b"$OK#00"

        def recv_side_effect(size):
            nonlocal bad_packet
            chunk = bad_packet[:size]
            bad_packet = bad_packet[size:]
            if not chunk:
                raise Exception("empty")
            return chunk

        mock_sock.recv.side_effect = recv_side_effect
        client._sock = mock_sock

        with pytest.raises(OperationError, match="checksum"):
            client._recv_packet()

    def test_read_registers_parses_response(self):
        """read_registers() parses the 'g' command response correctly."""
        client = GDBClient()

        # Build a fake 'g' response: 17 registers * 8 hex chars each
        # r0 = 0xDEADBEEF (little-endian: EF BE AD DE)
        r0_value = 0xDEADBEEF
        r0_bytes = r0_value.to_bytes(4, "little")
        # All other regs = 0
        register_hex = r0_bytes.hex() + "00000000" * 16

        client._send_command = MagicMock(return_value=register_hex)
        registers = client.read_registers()

        assert registers["r0"] == 0xDEADBEEF
        assert registers["r1"] == 0
        assert "pc" in registers
        assert "sp" in registers

    def test_read_memory_returns_bytes(self):
        """read_memory() parses hex response into bytes."""
        client = GDBClient()
        # Memory read response: 4 bytes "DEADBEEF" -> b'\xDE\xAD\xBE\xEF'
        client._send_command = MagicMock(return_value="deadbeef")

        result = client.read_memory(0x20000000, 4)
        assert result == bytes.fromhex("deadbeef")

    def test_read_memory_error_raises(self):
        """read_memory() raises OperationError on E## error response."""
        client = GDBClient()
        client._send_command = MagicMock(return_value="E03")

        with pytest.raises(OperationError, match="Memory read failed"):
            client.read_memory(0x20000000, 4)

    def test_set_breakpoint_sends_z0(self):
        """set_breakpoint() sends Z0 command."""
        client = GDBClient()
        client._send_command = MagicMock(return_value="OK")

        client.set_breakpoint(0x08000400)
        client._send_command.assert_called_once_with("Z0,8000400,2")

    def test_write_register_sends_p_command(self):
        """write_register() sends P command with little-endian value."""
        client = GDBClient()
        client._send_command = MagicMock(return_value="OK")

        client.write_register(15, 0x08000001)  # PC = 0x08000001
        cmd = client._send_command.call_args[0][0]
        assert cmd.startswith("Pf=")  # reg 15 = 0xf
        # Value 0x08000001 in little-endian: 01 00 00 08
        assert "01000008" in cmd


# ===========================================================================
# 5. MemoryOps tests
# ===========================================================================

class TestMemoryOps:
    """Tests for MemoryOps QMP memory access."""

    def _make_qemu_mock(self) -> MagicMock:
        """Create a minimal QEMUInstance mock with a QMPClient mock."""
        qemu = MagicMock()
        qemu.qmp = MagicMock()
        qemu.gdb = None
        return qemu

    def test_read_parses_xp_output(self):
        """MemoryOps.read() parses QMP xp output correctly."""
        qemu = self._make_qemu_mock()
        # Simulate QEMU xp output format
        xp_output = "0x20000000: 0xde 0xad 0xbe 0xef"
        qemu.qmp.execute.return_value = xp_output

        mem = MemoryOps(qemu)
        result = mem.read(0x20000000, 4)

        assert result == bytes([0xde, 0xad, 0xbe, 0xef])
        qemu.qmp.execute.assert_called_once_with(
            "human-monitor-command",
            {"command-line": "xp /4bx 0x20000000"}
        )

    def test_parse_xp_output_single_line(self):
        """_parse_xp_output() handles single-line xp output."""
        output = "0x20000000: 0x01 0x02 0x03 0x04"
        result = _parse_xp_output(output, 4)
        assert result == bytes([0x01, 0x02, 0x03, 0x04])

    def test_parse_xp_output_multi_line(self):
        """_parse_xp_output() handles multi-line xp output."""
        output = (
            "0x20000000: 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08\n"
            "0x20000008: 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f 0x10"
        )
        result = _parse_xp_output(output, 16)
        assert len(result) == 16
        assert result[0] == 0x01
        assert result[15] == 0x10

    def test_parse_xp_output_truncates_to_size(self):
        """_parse_xp_output() truncates to expected_bytes."""
        output = "0x20000000: 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08"
        result = _parse_xp_output(output, 4)
        assert len(result) == 4
        assert result == bytes([0x01, 0x02, 0x03, 0x04])

    def test_read_register_uses_gdb(self):
        """read_register() delegates to GDB client when connected."""
        qemu = self._make_qemu_mock()
        mock_gdb = MagicMock()
        mock_gdb._connected = True
        mock_gdb.read_registers.return_value = {"pc": 0x08000001, "sp": 0x20001000}
        qemu.gdb = mock_gdb

        mem = MemoryOps(qemu)
        pc = mem.read_register("pc")

        assert pc == 0x08000001
        mock_gdb.read_registers.assert_called_once()

    def test_read_register_no_gdb_raises(self):
        """read_register() raises OperationError when no GDB connection."""
        qemu = self._make_qemu_mock()
        qemu.gdb = None

        mem = MemoryOps(qemu)
        with pytest.raises(OperationError, match="GDB RSP"):
            mem.read_register("pc")

    def test_dump_calls_memsave(self):
        """dump() calls QMP memsave command."""
        qemu = self._make_qemu_mock()
        qemu.qmp.execute.return_value = {}

        mem = MemoryOps(qemu)
        mem.dump(0x20000000, 0x1000, "/tmp/dump.bin")

        qemu.qmp.execute.assert_called_once_with(
            "memsave",
            {"val": 0x20000000, "size": 0x1000, "filename": "/tmp/dump.bin"}
        )


# ===========================================================================
# 6. SnapshotManager tests
# ===========================================================================

class TestSnapshotManager:
    """Tests for SnapshotManager QMP snapshot operations."""

    def _make_qemu_mock(self) -> MagicMock:
        qemu = MagicMock()
        qemu.qmp = MagicMock()
        qemu.qmp.execute.return_value = {}
        return qemu

    def test_save_calls_correct_qmp_commands(self):
        """save() pauses VM, calls savevm, then resumes."""
        qemu = self._make_qemu_mock()
        manager = SnapshotManager()

        manager.save(qemu, "fuzzing-base")

        qemu.pause.assert_called_once()
        qemu.qmp.execute.assert_any_call("human-monitor-command", {"command-line": "savevm fuzzing-base"})
        qemu.resume.assert_called_once()

    def test_save_stores_metadata(self):
        """save() stores metadata in the internal index."""
        qemu = self._make_qemu_mock()
        manager = SnapshotManager()

        manager.save(qemu, "checkpoint-1")

        assert "checkpoint-1" in manager._metadata
        assert manager._metadata["checkpoint-1"]["name"] == "checkpoint-1"
        assert "timestamp" in manager._metadata["checkpoint-1"]

    def test_load_calls_loadvm(self):
        """load() calls QMP loadvm with the snapshot name."""
        qemu = self._make_qemu_mock()
        manager = SnapshotManager()

        manager.load(qemu, "fuzzing-base")

        qemu.qmp.execute.assert_called_once_with("human-monitor-command", {"command-line": "loadvm fuzzing-base"})

    def test_delete_calls_delvm(self):
        """delete() calls QMP delvm and removes from metadata."""
        qemu = self._make_qemu_mock()
        manager = SnapshotManager()
        manager._metadata["old-snap"] = {"name": "old-snap", "timestamp": 0}

        manager.delete(qemu, "old-snap")

        qemu.qmp.execute.assert_called_once_with("human-monitor-command", {"command-line": "delvm old-snap"})
        assert "old-snap" not in manager._metadata

    def test_list_snapshots_returns_qmp_result(self):
        """list_snapshots() returns the QMP query-snapshots result."""
        qemu = self._make_qemu_mock()
        snap_list = [
            {"name": "snap1", "id": "1"},
            {"name": "snap2", "id": "2"},
        ]
        qemu.qmp.execute.return_value = snap_list

        manager = SnapshotManager()
        result = manager.list_snapshots(qemu)

        assert len(result) == 2
        assert result[0]["name"] == "snap1"
        qemu.qmp.execute.assert_called_once_with("query-snapshots")

    def test_fast_reset_calls_loadvm_then_cont(self):
        """fast_reset() calls loadvm then cont in sequence."""
        qemu = self._make_qemu_mock()
        manager = SnapshotManager()

        manager.fast_reset(qemu, "fuzz-base")

        calls = qemu.qmp.execute.call_args_list
        assert calls[0] == call("human-monitor-command", {"command-line": "loadvm fuzz-base"})
        assert calls[1] == call("cont")

    def test_save_persists_index_to_disk(self, tmp_path):
        """save() writes metadata index to disk when index_path is set."""
        qemu = self._make_qemu_mock()
        index_file = tmp_path / "snapshots.json"
        manager = SnapshotManager(index_path=str(index_file))

        manager.save(qemu, "test-snap")

        assert index_file.exists()
        data = json.loads(index_file.read_text())
        assert "test-snap" in data

    def test_load_raises_on_qmp_error(self):
        """load() raises OperationError if QMP returns an error."""
        qemu = self._make_qemu_mock()
        qemu.qmp.execute.side_effect = OperationError("snapshot not found")

        manager = SnapshotManager()
        with pytest.raises(OperationError, match="snapshot not found"):
            manager.load(qemu, "nonexistent")
