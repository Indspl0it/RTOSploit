"""Unit tests for GDBClient enhancements: send_break, receive_stop timeout, read_register.

All tests use mocks — no real QEMU process is required.
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

import pytest

from rtosploit.emulation.gdb import GDBClient
from rtosploit.errors import OperationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_connected_client() -> tuple[GDBClient, MagicMock]:
    """Return a GDBClient with a mocked socket, bypassing connect()."""
    client = GDBClient()
    mock_sock = MagicMock(spec=socket.socket)
    client._sock = mock_sock
    client._connected = True
    return client, mock_sock


# ---------------------------------------------------------------------------
# send_break
# ---------------------------------------------------------------------------

class TestSendBreak:
    """Tests for GDBClient.send_break()."""

    def test_sends_0x03_byte(self):
        client, mock_sock = _make_connected_client()
        client.send_break()
        mock_sock.sendall.assert_called_once_with(b"\x03")

    def test_raises_when_not_connected(self):
        client = GDBClient()
        with pytest.raises(OperationError, match="not connected"):
            client.send_break()


# ---------------------------------------------------------------------------
# receive_stop with timeout
# ---------------------------------------------------------------------------

class TestReceiveStopTimeout:
    """Tests for GDBClient.receive_stop() timeout parameter."""

    def test_raises_timeout_error_on_socket_timeout(self):
        client, mock_sock = _make_connected_client()
        mock_sock.gettimeout.return_value = 5.0
        # Simulate socket.timeout when trying to receive
        mock_sock.recv.side_effect = socket.timeout("timed out")

        with pytest.raises(TimeoutError, match="timed out after 3.0s"):
            client.receive_stop(timeout=3.0)

        # Verify timeout was set and restored
        mock_sock.settimeout.assert_any_call(3.0)
        mock_sock.settimeout.assert_called_with(5.0)

    def test_returns_stop_reason_on_success(self):
        client, mock_sock = _make_connected_client()
        mock_sock.gettimeout.return_value = 5.0

        # Simulate receiving a valid RSP packet "$S05#b8" then ACK
        # _recv_packet reads: '$' then body+checksum
        # First recv(1) calls find '$', then recv(1024) gets "S05#b8", then ACK send
        recv_sequence = [
            b"$",       # start marker
            b"S05#b8",  # body + checksum
        ]
        mock_sock.recv.side_effect = recv_sequence

        result = client.receive_stop(timeout=7.0)
        assert result == "S05"

        # Verify timeout was set and restored
        mock_sock.settimeout.assert_any_call(7.0)
        mock_sock.settimeout.assert_called_with(5.0)

    def test_restores_timeout_even_on_other_errors(self):
        client, mock_sock = _make_connected_client()
        mock_sock.gettimeout.return_value = 5.0
        # Simulate socket closed (recv returns empty bytes)
        mock_sock.recv.side_effect = [b""]

        with pytest.raises(OperationError):
            client.receive_stop(timeout=2.0)

        # Timeout must still be restored
        mock_sock.settimeout.assert_called_with(5.0)


# ---------------------------------------------------------------------------
# read_register (by name)
# ---------------------------------------------------------------------------

class TestReadRegister:
    """Tests for GDBClient.read_register(name)."""

    def test_returns_correct_register_value(self):
        client, mock_sock = _make_connected_client()

        # Build a fake 'g' response: 17 registers, 8 hex chars each
        # We want pc (index 15) = 0x08001234
        reg_values = [0] * 17
        reg_values[15] = 0x08001234  # pc

        hex_response = ""
        for val in reg_values:
            raw = val.to_bytes(4, "little")
            hex_response += raw.hex()

        # Mock _send_command to return the hex response
        client._send_command = MagicMock(return_value=hex_response)

        result = client.read_register("pc")
        assert result == 0x08001234
        client._send_command.assert_called_once_with("g")

    def test_raises_operation_error_for_unknown_register(self):
        client, mock_sock = _make_connected_client()

        # Build minimal 'g' response
        hex_response = "00000000" * 17
        client._send_command = MagicMock(return_value=hex_response)

        with pytest.raises(OperationError, match="not found"):
            client.read_register("nonexistent")

    def test_returns_sp_value(self):
        client, mock_sock = _make_connected_client()

        reg_values = [0] * 17
        reg_values[13] = 0x20008000  # sp

        hex_response = ""
        for val in reg_values:
            raw = val.to_bytes(4, "little")
            hex_response += raw.hex()

        client._send_command = MagicMock(return_value=hex_response)

        result = client.read_register("sp")
        assert result == 0x20008000
