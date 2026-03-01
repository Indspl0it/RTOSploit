"""Unit tests for rtosploit.peripherals.model."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rtosploit.peripherals.model import (
    CPUState,
    HandlerResult,
    PeripheralModel,
    hal_handler,
    _HAL_HANDLER_ATTR,
)


# ---------------------------------------------------------------------------
# HandlerResult
# ---------------------------------------------------------------------------

class TestHandlerResult:
    def test_defaults(self):
        r = HandlerResult()
        assert r.intercept is True
        assert r.return_value == 0

    def test_custom_values(self):
        r = HandlerResult(intercept=False, return_value=42)
        assert r.intercept is False
        assert r.return_value == 42

    def test_none_return(self):
        r = HandlerResult(return_value=None)
        assert r.return_value is None


# ---------------------------------------------------------------------------
# CPUState
# ---------------------------------------------------------------------------

class TestCPUState:
    def test_get_arg_r0_through_r3(self):
        regs = {"r0": 100, "r1": 200, "r2": 300, "r3": 400, "sp": 0x20000000}
        cpu = CPUState(regs=regs)
        assert cpu.get_arg(0) == 100
        assert cpu.get_arg(1) == 200
        assert cpu.get_arg(2) == 300
        assert cpu.get_arg(3) == 400

    def test_get_arg_from_stack(self):
        regs = {"sp": 0x20001000}
        gdb = MagicMock()
        gdb.read_memory.return_value = (500).to_bytes(4, "little")
        cpu = CPUState(regs=regs, _gdb=gdb)
        val = cpu.get_arg(4)
        gdb.read_memory.assert_called_once_with(0x20001000, 4)
        assert val == 500

    def test_get_arg_from_stack_offset(self):
        regs = {"sp": 0x20001000}
        gdb = MagicMock()
        gdb.read_memory.return_value = (999).to_bytes(4, "little")
        cpu = CPUState(regs=regs, _gdb=gdb)
        val = cpu.get_arg(6)  # arg 6 = sp + (6-4)*4 = sp+8
        gdb.read_memory.assert_called_once_with(0x20001008, 4)
        assert val == 999

    def test_get_arg_no_gdb_returns_zero(self):
        regs = {"sp": 0x20001000}
        cpu = CPUState(regs=regs)
        assert cpu.get_arg(5) == 0

    def test_read_memory_delegates_to_gdb(self):
        gdb = MagicMock()
        gdb.read_memory.return_value = b"\x01\x02\x03\x04"
        cpu = CPUState(regs={}, _gdb=gdb)
        data = cpu.read_memory(0x08000000, 4)
        gdb.read_memory.assert_called_once_with(0x08000000, 4)
        assert data == b"\x01\x02\x03\x04"

    def test_read_memory_no_gdb(self):
        cpu = CPUState(regs={})
        data = cpu.read_memory(0x08000000, 4)
        assert data == b"\x00\x00\x00\x00"

    def test_write_memory_delegates_to_gdb(self):
        gdb = MagicMock()
        cpu = CPUState(regs={}, _gdb=gdb)
        cpu.write_memory(0x20000000, b"\xaa\xbb")
        gdb.write_memory.assert_called_once_with(0x20000000, b"\xaa\xbb")

    def test_write_memory_no_gdb_noop(self):
        cpu = CPUState(regs={})
        cpu.write_memory(0x20000000, b"\xaa")  # Should not raise


# ---------------------------------------------------------------------------
# @hal_handler decorator
# ---------------------------------------------------------------------------

class TestHalHandler:
    def test_single_function(self):
        @hal_handler("HAL_UART_Init")
        def handler(self, cpu):
            pass
        assert getattr(handler, _HAL_HANDLER_ATTR) == ["HAL_UART_Init"]

    def test_multiple_functions(self):
        @hal_handler(["HAL_UART_Transmit", "HAL_UART_Transmit_IT"])
        def handler(self, cpu):
            pass
        assert getattr(handler, _HAL_HANDLER_ATTR) == [
            "HAL_UART_Transmit",
            "HAL_UART_Transmit_IT",
        ]


# ---------------------------------------------------------------------------
# PeripheralModel
# ---------------------------------------------------------------------------

class TestPeripheralModel:
    def test_construction(self):
        m = PeripheralModel("uart1", 0x40011000, 0x400)
        assert m.name == "uart1"
        assert m.base_addr == 0x40011000
        assert m.size == 0x400

    def test_register_read_default(self):
        m = PeripheralModel("test", 0x40000000, 0x100)
        assert m.read_register(0x00) == 0
        assert m.read_register(0x04) == 0

    def test_register_write_and_read(self):
        m = PeripheralModel("test", 0x40000000, 0x100)
        m.write_register(0x04, 0xDEADBEEF)
        assert m.read_register(0x04) == 0xDEADBEEF

    def test_reset_clears_registers(self):
        m = PeripheralModel("test", 0x40000000, 0x100)
        m.write_register(0x00, 42)
        m.reset()
        assert m.read_register(0x00) == 0

    def test_get_irq_default_none(self):
        m = PeripheralModel("test", 0x40000000, 0x100)
        assert m.get_irq() is None

    def test_handler_collection(self):
        class MyPeripheral(PeripheralModel):
            @hal_handler("HAL_Init")
            def handle_init(self, cpu):
                return HandlerResult()

            @hal_handler(["HAL_Foo", "HAL_Bar"])
            def handle_multi(self, cpu):
                return HandlerResult()

        m = MyPeripheral("test", 0, 0)
        assert "HAL_Init" in m._handlers
        assert "HAL_Foo" in m._handlers
        assert "HAL_Bar" in m._handlers

    def test_find_handler_found(self):
        class MyPeripheral(PeripheralModel):
            @hal_handler("HAL_Init")
            def handle_init(self, cpu):
                return HandlerResult(return_value=99)

        m = MyPeripheral("test", 0, 0)
        handler = m._find_handler("HAL_Init")
        result = handler(CPUState(regs={}))
        assert result.return_value == 99

    def test_find_handler_not_found(self):
        m = PeripheralModel("test", 0, 0)
        with pytest.raises(KeyError, match="No handler registered"):
            m._find_handler("NonExistent")

    def test_subclass_override_read(self):
        class SmartPeripheral(PeripheralModel):
            def read_register(self, offset, size=4):
                if offset == 0x0C:  # status register: always ready
                    return 0x01
                return super().read_register(offset, size)

        m = SmartPeripheral("smart", 0x40000000, 0x100)
        assert m.read_register(0x0C) == 0x01
        assert m.read_register(0x00) == 0
