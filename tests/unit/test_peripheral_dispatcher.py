"""Unit tests for rtosploit.peripherals.dispatcher."""

from __future__ import annotations

from unittest.mock import MagicMock, call

import pytest

from rtosploit.peripherals.model import (
    CPUState,
    HandlerResult,
    PeripheralModel,
    hal_handler,
)
from rtosploit.peripherals.dispatcher import InterceptDispatcher


class StubUART(PeripheralModel):
    """Test peripheral model."""

    @hal_handler("HAL_UART_Init")
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(intercept=True, return_value=0)

    @hal_handler("HAL_UART_Transmit")
    def handle_tx(self, cpu: CPUState) -> HandlerResult:
        buf = cpu.get_arg(1)
        length = cpu.get_arg(2)
        return HandlerResult(intercept=True, return_value=length)


class PassthroughModel(PeripheralModel):
    """Model that lets the function run."""

    @hal_handler("HAL_Passthrough")
    def handle_pass(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(intercept=False)


def _make_gdb(regs=None):
    """Create a mock GDBClient."""
    gdb = MagicMock()
    if regs is None:
        regs = {
            "r0": 0, "r1": 0x20002000, "r2": 16, "r3": 1000,
            "sp": 0x20008000, "lr": 0x08001001, "pc": 0x08002000,
            "xpsr": 0x01000000,
        }
    gdb.read_registers.return_value = regs
    return gdb


class TestInterceptDispatcher:
    def test_register_sets_breakpoint(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        model = StubUART("uart1", 0x40011000, 0x400)
        disp.register(model, "HAL_UART_Init", 0x08001234)
        gdb.set_breakpoint.assert_called_once_with(0x08001234)

    def test_register_clears_thumb_bit(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        model = StubUART("uart1", 0x40011000, 0x400)
        disp.register(model, "HAL_UART_Init", 0x08001235)  # thumb bit set
        gdb.set_breakpoint.assert_called_once_with(0x08001234)

    def test_handle_known_breakpoint_intercepts(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        model = StubUART("uart1", 0x40011000, 0x400)
        disp.register(model, "HAL_UART_Init", 0x08001234)

        result = disp.handle_breakpoint(0x08001234)
        assert result is True

        # Should write r0=0 (return value) and pc=lr|1
        gdb.write_register.assert_any_call(0, 0)  # r0 = return_value
        gdb.write_register.assert_any_call(15, 0x08001001)  # pc = lr | 1

    def test_handle_unknown_breakpoint(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        result = disp.handle_breakpoint(0x08009999)
        assert result is False

    def test_handle_with_thumb_bit_in_stop_addr(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        model = StubUART("uart1", 0x40011000, 0x400)
        disp.register(model, "HAL_UART_Init", 0x08001234)

        # Stop addr may have thumb bit set
        result = disp.handle_breakpoint(0x08001235)
        assert result is True

    def test_passthrough_does_not_modify_pc(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        model = PassthroughModel("pass", 0, 0)
        disp.register(model, "HAL_Passthrough", 0x08002000)

        disp.handle_breakpoint(0x08002000)

        # When intercept=False, should NOT write r0 or pc
        gdb.write_register.assert_not_called()

    def test_stats_tracking(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        model = StubUART("uart1", 0x40011000, 0x400)
        disp.register(model, "HAL_UART_Init", 0x08001234)

        disp.handle_breakpoint(0x08001234)
        disp.handle_breakpoint(0x08001234)
        disp.handle_breakpoint(0x08001234)

        assert disp.stats[0x08001234] == 3

    def test_registered_addresses(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        model = StubUART("uart1", 0x40011000, 0x400)
        disp.register(model, "HAL_UART_Init", 0x08001234)
        disp.register(model, "HAL_UART_Transmit", 0x08001300)

        assert disp.registered_addresses == {0x08001234, 0x08001300}

    def test_register_unknown_handler_raises(self):
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)
        model = StubUART("uart1", 0x40011000, 0x400)
        with pytest.raises(KeyError):
            disp.register(model, "NonExistent", 0x08001234)

    def test_handler_receives_cpu_state(self):
        """Verify the handler gets a valid CPUState with correct register values."""
        regs = {"r0": 0xAAAA, "r1": 0xBBBB, "sp": 0x20008000, "lr": 0x08001001, "pc": 0x08002000}
        gdb = _make_gdb(regs)
        disp = InterceptDispatcher(gdb)

        received_args = {}

        class InspectModel(PeripheralModel):
            @hal_handler("HAL_Inspect")
            def handle(self, cpu: CPUState) -> HandlerResult:
                received_args["r0"] = cpu.get_arg(0)
                received_args["r1"] = cpu.get_arg(1)
                return HandlerResult(return_value=0)

        model = InspectModel("inspect", 0, 0)
        disp.register(model, "HAL_Inspect", 0x08002000)
        disp.handle_breakpoint(0x08002000)

        assert received_args["r0"] == 0xAAAA
        assert received_args["r1"] == 0xBBBB

    def test_return_value_none_skips_r0_write(self):
        """When return_value is None, r0 should not be written."""
        gdb = _make_gdb()
        disp = InterceptDispatcher(gdb)

        class NoneReturnModel(PeripheralModel):
            @hal_handler("HAL_NoReturn")
            def handle(self, cpu: CPUState) -> HandlerResult:
                return HandlerResult(intercept=True, return_value=None)

        model = NoneReturnModel("nr", 0, 0)
        disp.register(model, "HAL_NoReturn", 0x08003000)
        disp.handle_breakpoint(0x08003000)

        # Only pc should be written (reg 15), not r0 (reg 0)
        calls = gdb.write_register.call_args_list
        reg_nums = [c[0][0] for c in calls]
        assert 0 not in reg_nums  # r0 not written
        assert 15 in reg_nums     # pc written
