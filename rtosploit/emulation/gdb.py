"""GDB Remote Serial Protocol (RSP) client for ARM Cortex-M targets."""

from __future__ import annotations

import socket
from typing import Any, Optional

from rtosploit.errors import OperationError


# ARM Cortex-M register layout for RSP 'g' packet (little-endian 32-bit each)
# Registers 0-12: r0-r12, 13: SP, 14: LR, 15: PC, 16: xPSR
_CORTEX_M_REGISTERS = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
    "xpsr",
]


def _checksum(data: str) -> int:
    """Compute the RSP checksum (sum of bytes mod 256)."""
    return sum(ord(c) for c in data) % 256


class GDBClient:
    """Client for the GDB Remote Serial Protocol (RSP) over TCP.

    Used to control and inspect firmware running in QEMU's GDB stub.
    """

    def __init__(self) -> None:
        self._sock: Optional[socket.socket] = None
        self._connected = False

    def connect(self, host: str, port: int, timeout: float = 5.0) -> None:
        """Connect to QEMU's GDB RSP stub over TCP.

        Args:
            host: Host where QEMU is running (usually "localhost").
            port: GDB stub port (default 1234).
            timeout: Socket timeout in seconds.

        Raises:
            OperationError: If connection fails.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            self._sock = sock
            self._connected = True

            # Send '?' to query the initial stop reason and verify connection
            self._send_packet("?")
            # Read and discard the initial stop reply (e.g. "S05")
            try:
                self._recv_packet()
            except Exception:
                pass  # Some stubs don't send an initial reply

        except (ConnectionRefusedError, OSError) as e:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
            raise OperationError(f"Failed to connect to GDB stub at {host}:{port}: {e}")

    def _send_packet(self, data: str) -> None:
        """Send an RSP packet: $data#checksum.

        Args:
            data: Packet payload (unescaped).
        """
        if self._sock is None:
            raise OperationError("GDB client is not connected")
        csum = _checksum(data)
        packet = f"${data}#{csum:02x}"
        self._sock.sendall(packet.encode("latin-1"))

        # Wait for '+' acknowledgement
        ack = self._sock.recv(1)
        if ack != b"+":
            # Some configurations run with acks disabled — continue anyway
            pass

    def _recv_packet(self) -> str:
        """Receive an RSP packet and validate checksum.

        Returns:
            Packet payload string.

        Raises:
            OperationError: On socket error, checksum mismatch, or invalid format.
        """
        if self._sock is None:
            raise OperationError("GDB client is not connected")

        buf = b""
        # Read until we find start of packet '$'
        while True:
            c = self._sock.recv(1)
            if not c:
                raise OperationError("GDB socket closed unexpectedly")
            if c == b"$":
                break
            # Could be '+'/'-' acks or other noise — skip

        # Read packet body until '#'
        while b"#" not in buf:
            chunk = self._sock.recv(1024)
            if not chunk:
                raise OperationError("GDB socket closed during packet receive")
            buf += chunk

        # Split at '#'
        body, rest = buf.split(b"#", 1)
        # Read exactly 2 checksum bytes if not already in rest
        while len(rest) < 2:
            rest += self._sock.recv(1)

        received_csum = int(rest[:2], 16)
        data_str = body.decode("latin-1")
        expected_csum = _checksum(data_str)

        if received_csum != expected_csum:
            # Send '-' NAK
            self._sock.sendall(b"-")
            raise OperationError(
                f"GDB RSP checksum mismatch: got {received_csum:02x}, "
                f"expected {expected_csum:02x}"
            )

        # Send '+' ACK
        self._sock.sendall(b"+")
        return data_str

    def _send_command(self, cmd: str) -> str:
        """Send a command packet and receive the response."""
        self._send_packet(cmd)
        return self._recv_packet()

    def read_registers(self) -> dict[str, int]:
        """Read all ARM Cortex-M registers via the 'g' command.

        Returns:
            Dict mapping register names to their 32-bit values.
        """
        response = self._send_command("g")
        # Response is a hex string: 4 bytes (8 hex chars) per register, little-endian
        registers: dict[str, int] = {}
        bytes_per_reg = 8  # 4 bytes = 8 hex chars
        for i, name in enumerate(_CORTEX_M_REGISTERS):
            offset = i * bytes_per_reg
            if offset + bytes_per_reg > len(response):
                break
            hex_val = response[offset:offset + bytes_per_reg]
            # Little-endian: bytes are in memory order, need to reverse for value
            try:
                raw = bytes.fromhex(hex_val)
                value = int.from_bytes(raw, "little")
                registers[name] = value
            except ValueError:
                registers[name] = 0
        return registers

    def write_register(self, reg_num: int, value: int) -> None:
        """Write a single register via the 'P' command.

        Args:
            reg_num: Register number (0=r0, 13=sp, 14=lr, 15=pc, 16=xpsr).
            value: 32-bit value to write.
        """
        # Value is encoded little-endian in the packet
        raw = value.to_bytes(4, "little")
        hex_val = raw.hex()
        response = self._send_command(f"P{reg_num:x}={hex_val}")
        if response != "OK":
            raise OperationError(f"Failed to write register {reg_num}: {response}")

    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory via the 'm' command.

        Args:
            address: Start address.
            size: Number of bytes to read.

        Returns:
            Raw bytes read from target memory.
        """
        response = self._send_command(f"m{address:x},{size:x}")
        if response.startswith("E"):
            raise OperationError(f"Memory read failed at 0x{address:08x}: {response}")
        try:
            return bytes.fromhex(response)
        except ValueError:
            raise OperationError(f"Invalid memory read response: {response!r}")

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory via the 'M' command.

        Args:
            address: Start address.
            data: Bytes to write.
        """
        hex_data = data.hex()
        response = self._send_command(f"M{address:x},{len(data):x}:{hex_data}")
        if response != "OK":
            raise OperationError(f"Memory write failed at 0x{address:08x}: {response}")

    def set_breakpoint(self, address: int) -> None:
        """Set a Thumb software breakpoint via 'Z0'.

        Args:
            address: Breakpoint address (Thumb mode — must be 2-byte aligned).
        """
        response = self._send_command(f"Z0,{address:x},2")
        if response not in ("OK", ""):
            raise OperationError(f"Failed to set breakpoint at 0x{address:08x}: {response}")

    def remove_breakpoint(self, address: int) -> None:
        """Remove a Thumb software breakpoint via 'z0'.

        Args:
            address: Breakpoint address to remove.
        """
        response = self._send_command(f"z0,{address:x},2")
        if response not in ("OK", ""):
            raise OperationError(f"Failed to remove breakpoint at 0x{address:08x}: {response}")

    def set_watchpoint(self, address: int, size: int, wp_type: str = "write") -> None:
        """Set a hardware watchpoint.

        Args:
            address: Watch address.
            size: Watch region size in bytes.
            wp_type: One of "write" (Z2), "read" (Z3), or "access" (Z4).
        """
        type_map = {"write": "Z2", "read": "Z3", "access": "Z4"}
        if wp_type not in type_map:
            raise OperationError(f"Unknown watchpoint type '{wp_type}'. Use: write, read, access")
        cmd_prefix = type_map[wp_type]
        response = self._send_command(f"{cmd_prefix},{address:x},{size:x}")
        if response not in ("OK", ""):
            raise OperationError(
                f"Failed to set {wp_type} watchpoint at 0x{address:08x}: {response}"
            )

    def continue_execution(self) -> None:
        """Continue execution via the 'c' command.

        Note: This command does not wait for a stop reply — use receive_stop() for that.
        """
        if self._sock is None:
            raise OperationError("GDB client is not connected")
        self._send_packet("c")

    def single_step(self) -> None:
        """Single-step execution via the 's' command."""
        if self._sock is None:
            raise OperationError("GDB client is not connected")
        self._send_packet("s")

    def receive_stop(self) -> str:
        """Wait for and receive a stop reply packet.

        Returns:
            Stop reply string (e.g. "S05" for SIGTRAP).
        """
        return self._recv_packet()

    def detach(self) -> None:
        """Detach from the target via 'D' and close the socket."""
        if self._sock is not None:
            try:
                self._send_command("D")
            except Exception:
                pass
        self.close()

    def close(self) -> None:
        """Close the GDB socket connection."""
        self._connected = False
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self) -> "GDBClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
