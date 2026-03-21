"""QEMU process management for firmware emulation."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from rtosploit.config import RTOSploitConfig
from rtosploit.errors import QEMUCrashError, OperationError
from rtosploit.emulation.machines import MachineConfig, load_machine
from rtosploit.emulation.qmp import QMPClient
from rtosploit.utils.binary import load_firmware


_MIN_QEMU_VERSION = (8, 0)


class QEMUInstance:
    """Manages a single QEMU process for firmware emulation.

    Handles process lifecycle, QMP communication, GDB stub setup,
    and context manager cleanup.
    """

    def __init__(self, config: RTOSploitConfig) -> None:
        self._config = config
        self._process: Optional[subprocess.Popen] = None  # type: ignore[type-arg]
        self._qmp_tmp_dir: Optional[str] = None
        self._qmp_socket_path: Optional[str] = None
        self.qmp = QMPClient()
        self.gdb: Optional[Any] = None  # GDBClient, imported lazily
        self._machine: Optional[MachineConfig] = None

    _ARCH_TO_QEMU = {
        "arm": "qemu-system-arm",
        "aarch64": "qemu-system-aarch64",
        "xtensa": "qemu-system-xtensa",
        "riscv32": "qemu-system-riscv32",
        "riscv64": "qemu-system-riscv64",
        "mips": "qemu-system-mips",
    }

    def _find_qemu_binary(self, architecture: str = "arm") -> str:
        """Find a suitable QEMU system binary for the given architecture.

        Checks the configured binary name and PATH. Verifies version >= 8.0.

        Args:
            architecture: Target architecture (arm, xtensa, riscv32, etc.).

        Returns:
            Absolute path to the QEMU binary.

        Raises:
            QEMUCrashError: If QEMU is not found or version is too old.
        """
        arch_binary = self._ARCH_TO_QEMU.get(architecture, f"qemu-system-{architecture}")
        candidates = [
            self._config.qemu.binary,
            f"{arch_binary}-rtosploit",  # Custom-built binary
            arch_binary,
        ]

        for candidate in candidates:
            path = shutil.which(candidate)
            if path is None:
                continue

            # Check version
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                version_line = result.stdout.splitlines()[0] if result.stdout else ""
                # Parse "QEMU emulator version X.Y.Z"
                parts = version_line.split()
                for i, part in enumerate(parts):
                    if part == "version" and i + 1 < len(parts):
                        ver_str = parts[i + 1]
                        ver_nums = [int(x) for x in ver_str.split(".")[:2] if x.isdigit()]
                        if len(ver_nums) >= 2:
                            major, minor = ver_nums[0], ver_nums[1]
                            if (major, minor) >= _MIN_QEMU_VERSION:
                                return path
                        break
            except (subprocess.TimeoutExpired, ValueError, OSError):
                pass

        raise QEMUCrashError(
            f"{arch_binary} >= {_MIN_QEMU_VERSION[0]}.{_MIN_QEMU_VERSION[1]} not found. "
            f"Install via: apt-get install {arch_binary} or build from source."
        )

    def _build_command_line(
        self,
        machine: MachineConfig,
        firmware_path: str,
        gdb: bool = False,
        paused: bool = False,
        extra_args: list[str] | None = None,
    ) -> list[str]:
        """Build the QEMU command-line arguments.

        Args:
            machine: Machine configuration.
            firmware_path: Path to the firmware file.
            gdb: If True, enable GDB stub on the configured port.
            paused: If True, start QEMU paused (waiting for 'continue' from GDB/QMP).

        Returns:
            List of command-line arguments (including the binary path).
        """
        qemu_bin = self._find_qemu_binary(machine.architecture)

        cmd = [
            qemu_bin,
            "-machine", machine.qemu_machine,
            "-cpu", machine.cpu,
            "-nographic",
            "-monitor", "none",
            "-serial", "stdio",
            "-qmp", f"unix:{self._qmp_socket_path},server,wait=off",
        ]

        # Firmware loading
        firmware = Path(firmware_path)
        if firmware.suffix in (".elf", ""):
            cmd.extend(["-kernel", firmware_path])
        else:
            # Raw binary — load at flash base address
            flash_base = 0
            if "flash" in machine.memory:
                flash_base = int(machine.memory["flash"].get("base", 0))
            cmd.extend([
                "-device", f"loader,file={firmware_path},addr=0x{flash_base:08x}"
            ])

        if gdb:
            port = self._config.gdb.port
            cmd.extend(["-gdb", f"tcp::{port}"])

        if paused:
            cmd.append("-S")

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    @staticmethod
    def create_snapshot_drive(output_dir: str) -> list[str]:
        """Create a qcow2 overlay for QEMU savevm snapshots.

        Runs ``qemu-img create`` to produce a 64 MiB qcow2 image that can be
        used as a pflash block device, which is required for QEMU's savevm /
        loadvm snapshot support.

        Args:
            output_dir: Directory where the qcow2 file will be created.

        Returns:
            QEMU command-line arguments to attach the drive.

        Raises:
            QEMUCrashError: If qemu-img is not found or fails to create the image.
        """
        path = str(Path(output_dir) / "rtosploit-snap.qcow2")

        try:
            result = subprocess.run(
                ["qemu-img", "create", "-f", "qcow2", path, "64M"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, OSError) as e:
            raise QEMUCrashError(f"qemu-img not found or failed: {e}") from e

        if result.returncode != 0:
            raise QEMUCrashError(
                f"qemu-img create failed (exit {result.returncode}): {result.stderr}"
            )

        return ["-drive", f"file={path},format=qcow2,if=none,id=snap0"]

    def start(
        self,
        firmware_path: str,
        machine_name: str,
        gdb: bool = False,
        paused: bool = False,
        extra_qemu_args: list[str] | None = None,
    ) -> None:
        """Start a QEMU process and connect QMP.

        Args:
            firmware_path: Path to the firmware image.
            machine_name: Machine name or path to load.
            gdb: If True, expose GDB stub.
            paused: If True, start the CPU paused.
            extra_qemu_args: Additional QEMU command-line arguments to append.

        Raises:
            QEMUCrashError: If QEMU fails to start or QMP connection fails.
            FileNotFoundError: If firmware_path does not exist.
        """
        fw_path = Path(firmware_path)
        if not fw_path.exists():
            raise FileNotFoundError(f"Firmware not found: {firmware_path}")

        # Validate firmware can be loaded (raises on parse errors)
        load_firmware(fw_path)

        machine = load_machine(machine_name)
        self._machine = machine

        # Generate unique QMP socket path inside a secure temp directory
        self._qmp_tmp_dir = tempfile.mkdtemp(prefix="rtosploit-")
        self._qmp_socket_path = os.path.join(self._qmp_tmp_dir, "qmp.sock")

        cmd = self._build_command_line(
            machine, firmware_path, gdb=gdb, paused=paused, extra_args=extra_qemu_args
        )

        try:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as e:
            raise QEMUCrashError(f"Failed to start QEMU process: {e}") from e

        # Wait for QMP socket to appear and connect
        timeout = self._config.qemu.timeout
        try:
            self.qmp.connect(self._qmp_socket_path, timeout=min(timeout, 5.0))
        except QEMUCrashError as e:
            self.stop()
            raise QEMUCrashError(f"QEMU started but QMP connection failed: {e}") from e

        # Connect GDB client if requested
        if gdb:
            from rtosploit.emulation.gdb import GDBClient
            self.gdb = GDBClient()
            # Give QEMU a moment to set up the GDB stub
            time.sleep(0.5)
            try:
                self.gdb.connect("localhost", self._config.gdb.port)
            except OperationError:
                # GDB connection is optional — continue without it
                self.gdb = None

    def stop(self) -> None:
        """Stop the QEMU process.

        Sends QMP 'quit', waits for graceful exit, then SIGKILL if needed.
        Cleans up the QMP socket file.
        """
        # Try graceful QMP quit first
        try:
            if self.qmp._connected:
                self.qmp.execute("quit")
        except Exception:
            pass

        self.qmp.close()

        if self.gdb is not None:
            try:
                self.gdb.close()
            except Exception:
                pass
            self.gdb = None

        if self._process is not None:
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Force kill
                try:
                    self._process.kill()
                    self._process.wait(timeout=2)
                except Exception:
                    pass
            self._process = None

        # Clean up temporary directory (contains QMP socket)
        if self._qmp_tmp_dir and os.path.exists(self._qmp_tmp_dir):
            shutil.rmtree(self._qmp_tmp_dir, ignore_errors=True)
            self._qmp_tmp_dir = None
        self._qmp_socket_path = None

    def reset(self) -> None:
        """Reset the emulated system via QMP system_reset."""
        self.qmp.execute("system_reset")

    def pause(self) -> None:
        """Pause CPU execution via QMP stop."""
        self.qmp.execute("stop")

    def resume(self) -> None:
        """Resume CPU execution via QMP cont."""
        self.qmp.execute("cont")

    def status(self) -> str:
        """Query the VM running status.

        Returns:
            Status string: "running", "paused", "shutdown", etc.
        """
        result = self.qmp.execute("query-status")
        if isinstance(result, dict):
            return result.get("status", "unknown")
        return "unknown"

    def is_running(self) -> bool:
        """Check if QEMU process is alive and VM is in running state.

        Returns:
            True if process is alive AND status is "running".
        """
        if self._process is None:
            return False
        if self._process.poll() is not None:
            return False
        try:
            return self.status() == "running"
        except Exception:
            return False

    def __enter__(self) -> "QEMUInstance":
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def __del__(self) -> None:
        """Destructor: ensure process is cleaned up."""
        try:
            self.stop()
        except Exception:
            pass
