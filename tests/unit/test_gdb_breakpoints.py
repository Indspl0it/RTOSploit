"""Tests for GDB symbol-based breakpoint support."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from rtosploit.emulation.gdb import GDBClient
from rtosploit.errors import OperationError


@pytest.fixture
def gdb():
    """Create a GDBClient with a symbol table loaded."""
    client = GDBClient()
    client.set_symbol_table({
        "main": 0x08000100,
        "pvPortMalloc": 0x08001001,  # Thumb bit set (odd)
        "vTaskDelay": 0x08002000,
        "xQueueSend": 0x08003000,
        "HAL_UART_Receive": 0x08004001,  # Thumb bit set
    })
    return client


class TestSetSymbolTable:
    def test_stores_symbols(self, gdb):
        assert gdb._symbols["main"] == 0x08000100
        assert gdb._symbols["pvPortMalloc"] == 0x08001001

    def test_copies_dict(self):
        """Mutating the original dict should not affect the client."""
        client = GDBClient()
        symbols = {"foo": 0x1000}
        client.set_symbol_table(symbols)
        symbols["bar"] = 0x2000
        assert "bar" not in client._symbols

    def test_replaces_previous(self, gdb):
        gdb.set_symbol_table({"newSymbol": 0x9000})
        assert "main" not in gdb._symbols
        assert gdb._symbols["newSymbol"] == 0x9000


class TestSetBreakpointByName:
    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_exact_match(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        addr = gdb.set_breakpoint_by_name("main")
        assert addr == 0x08000100
        mock_send.assert_called_with("Z0,8000100,2")

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_case_insensitive_match(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        addr = gdb.set_breakpoint_by_name("MAIN")
        assert addr == 0x08000100

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_case_insensitive_mixed(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        addr = gdb.set_breakpoint_by_name("hal_uart_receive")
        assert addr == 0x08004000  # Thumb bit cleared

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_substring_match(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        addr = gdb.set_breakpoint_by_name("Malloc")
        assert addr == 0x08001000  # Thumb bit cleared from 0x08001001

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_substring_match_queue(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        addr = gdb.set_breakpoint_by_name("Queue")
        assert addr == 0x08003000

    def test_unknown_symbol_raises(self, gdb):
        with pytest.raises(OperationError, match="not found"):
            gdb.set_breakpoint_by_name("nonexistent_func")

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_ambiguous_substring_raises(self, mock_recv, mock_send, gdb):
        """'0800' matches multiple symbols — should raise."""
        gdb._connected = True
        gdb.set_symbol_table({
            "foo_task": 0x1000,
            "bar_task": 0x2000,
        })
        with pytest.raises(OperationError, match="Ambiguous"):
            gdb.set_breakpoint_by_name("task")

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_thumb_bit_clearing_odd(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        addr = gdb.set_breakpoint_by_name("pvPortMalloc")
        # 0x08001001 -> 0x08001000 (Thumb bit cleared)
        assert addr == 0x08001000
        mock_send.assert_called_with("Z0,8001000,2")

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_thumb_bit_clearing_even(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        addr = gdb.set_breakpoint_by_name("vTaskDelay")
        # 0x08002000 already even — should stay the same
        assert addr == 0x08002000


class TestListBreakpoints:
    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_empty_initially(self, mock_recv, mock_send):
        client = GDBClient()
        assert client.list_breakpoints() == {}

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_tracks_named_breakpoints(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        gdb.set_breakpoint_by_name("main")
        gdb.set_breakpoint_by_name("vTaskDelay")
        bps = gdb.list_breakpoints()
        assert bps == {
            "main": 0x08000100,
            "vTaskDelay": 0x08002000,
        }

    @patch.object(GDBClient, "_send_packet")
    @patch.object(GDBClient, "_recv_packet", return_value="OK")
    def test_returns_copy(self, mock_recv, mock_send, gdb):
        gdb._connected = True
        gdb.set_breakpoint_by_name("main")
        bps = gdb.list_breakpoints()
        bps["injected"] = 0xDEAD
        assert "injected" not in gdb.list_breakpoints()
