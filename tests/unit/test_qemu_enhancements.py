"""Unit tests for QEMUInstance enhancements (Phase 2).

Tests extra_qemu_args passthrough and create_snapshot_drive.
All tests use mocks -- no real QEMU process is required.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from rtosploit.config import RTOSploitConfig
from rtosploit.emulation.qemu import QEMUInstance
from rtosploit.errors import QEMUCrashError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_instance() -> QEMUInstance:
    """Create a QEMUInstance with default config and a mock QMP socket path."""
    inst = QEMUInstance(RTOSploitConfig())
    inst._qmp_socket_path = "/tmp/test-qmp.sock"
    return inst


def _stub_machine() -> MagicMock:
    """Return a minimal MachineConfig-like mock."""
    m = MagicMock()
    m.qemu_machine = "mps2-an385"
    m.cpu = "cortex-m3"
    m.memory = {}
    return m


# ---------------------------------------------------------------------------
# _build_command_line: extra_args
# ---------------------------------------------------------------------------

class TestBuildCommandLineExtraArgs:
    """Verify _build_command_line accepts and appends extra_args."""

    @patch.object(QEMUInstance, "_find_qemu_binary", return_value="/usr/bin/qemu-system-arm")
    def test_extra_args_appended(self, _find_bin: MagicMock) -> None:
        inst = _make_instance()
        machine = _stub_machine()
        extra = ["-drive", "file=/tmp/snap.qcow2,format=qcow2,if=none,id=snap0"]

        cmd = inst._build_command_line(machine, "/fw.elf", extra_args=extra)

        # The last two elements should be the extra args
        assert cmd[-2:] == extra

    @patch.object(QEMUInstance, "_find_qemu_binary", return_value="/usr/bin/qemu-system-arm")
    def test_no_extra_args(self, _find_bin: MagicMock) -> None:
        inst = _make_instance()
        machine = _stub_machine()

        cmd_without = inst._build_command_line(machine, "/fw.elf")
        cmd_none = inst._build_command_line(machine, "/fw.elf", extra_args=None)

        # Both should produce the same command
        assert cmd_without == cmd_none
        # Neither should contain drive args
        assert "-drive" not in cmd_without

    @patch.object(QEMUInstance, "_find_qemu_binary", return_value="/usr/bin/qemu-system-arm")
    def test_extra_args_come_after_standard_flags(self, _find_bin: MagicMock) -> None:
        inst = _make_instance()
        machine = _stub_machine()
        extra = ["-extra-flag"]

        cmd = inst._build_command_line(machine, "/fw.elf", gdb=True, paused=True, extra_args=extra)

        # -S (paused) and -gdb should appear before extra args
        s_idx = cmd.index("-S")
        extra_idx = cmd.index("-extra-flag")
        assert extra_idx > s_idx


# ---------------------------------------------------------------------------
# start(): extra_qemu_args passthrough
# ---------------------------------------------------------------------------

class TestStartExtraQemuArgs:
    """Verify start() passes extra_qemu_args to _build_command_line."""

    @patch.object(QEMUInstance, "_find_qemu_binary", return_value="/usr/bin/qemu-system-arm")
    @patch("rtosploit.emulation.qemu.load_firmware")
    @patch("rtosploit.emulation.qemu.load_machine")
    @patch("subprocess.Popen")
    @patch.object(QEMUInstance, "_build_command_line", return_value=["qemu", "args"])
    def test_extra_args_forwarded(
        self,
        mock_build: MagicMock,
        mock_popen: MagicMock,
        mock_load_machine: MagicMock,
        mock_load_fw: MagicMock,
        _find_bin: MagicMock,
        tmp_path: Path,
    ) -> None:
        fw = tmp_path / "fw.elf"
        fw.touch()

        mock_load_machine.return_value = _stub_machine()
        mock_popen.return_value = MagicMock()

        inst = QEMUInstance(RTOSploitConfig())
        inst.qmp = MagicMock()

        extra = ["-drive", "file=/snap.qcow2,format=qcow2,if=none,id=snap0"]
        inst.start(str(fw), "mps2-an385", extra_qemu_args=extra)

        # _build_command_line should have been called with extra_args=extra
        mock_build.assert_called_once()
        _, kwargs = mock_build.call_args
        assert kwargs.get("extra_args") == extra


# ---------------------------------------------------------------------------
# create_snapshot_drive
# ---------------------------------------------------------------------------

class TestCreateSnapshotDrive:
    """Verify create_snapshot_drive creates qcow2 and returns correct args."""

    @patch("subprocess.run")
    def test_creates_qcow2_and_returns_args(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        output_dir = str(tmp_path)

        args = QEMUInstance.create_snapshot_drive(output_dir)

        expected_path = str(tmp_path / "rtosploit-snap.qcow2")

        # Verify qemu-img was called correctly
        mock_run.assert_called_once()
        run_args = mock_run.call_args[0][0]
        assert run_args[0] == "qemu-img"
        assert "create" in run_args
        assert "-f" in run_args
        assert "qcow2" in run_args
        assert expected_path in run_args
        assert "64M" in run_args

        # Verify returned QEMU args
        assert args[0] == "-drive"
        assert f"file={expected_path}" in args[1]
        assert "format=qcow2" in args[1]
        assert "if=none" in args[1]
        assert "id=snap0" in args[1]

    @patch("subprocess.run")
    def test_raises_on_qemu_img_failure(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=1, stderr="qemu-img: error")

        with pytest.raises(QEMUCrashError, match="qemu-img"):
            QEMUInstance.create_snapshot_drive(str(tmp_path))

    @patch("subprocess.run", side_effect=FileNotFoundError("qemu-img not found"))
    def test_raises_on_missing_qemu_img(self, mock_run: MagicMock, tmp_path: Path) -> None:
        with pytest.raises(QEMUCrashError, match="qemu-img"):
            QEMUInstance.create_snapshot_drive(str(tmp_path))
