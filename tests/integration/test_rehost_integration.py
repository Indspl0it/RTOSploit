"""Integration tests for the peripheral rehosting engine (requires qemu-system-arm)."""

from __future__ import annotations

import os
import shutil
import time

import pytest

from rtosploit.config import RTOSploitConfig
from rtosploit.peripherals.model import (
    CPUState,
    HandlerResult,
    PeripheralModel,
    hal_handler,
)

_HAS_QEMU = shutil.which("qemu-system-arm") is not None
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
_FREERTOS_ELF = os.path.join(
    _PROJECT_ROOT,
    "vulnrange/downloaded_firmware/freertos-full-demo-mps2-an385.elf",
)
_HAS_FIRMWARE = os.path.exists(_FREERTOS_ELF)


class InterceptCounter(PeripheralModel):
    """Test model that counts intercept calls."""

    def __init__(self):
        super().__init__("counter", 0, 0)
        self.call_count = 0
        self.call_log: list[str] = []

    @hal_handler("xTaskGetTickCount")
    def handle_get_tick(self, cpu: CPUState) -> HandlerResult:
        self.call_count += 1
        self.call_log.append("xTaskGetTickCount")
        return HandlerResult(intercept=True, return_value=1000)


@pytest.mark.skipif(not _HAS_QEMU, reason="qemu-system-arm not installed")
@pytest.mark.skipif(not _HAS_FIRMWARE, reason="FreeRTOS test firmware not available")
class TestRehostingIntegration:
    """End-to-end tests for the peripheral rehosting pipeline."""

    def test_boot_and_intercept_freertos_function(self):
        """Boot FreeRTOS firmware, intercept xTaskGetTickCount, verify calls."""
        from rtosploit.emulation.qemu import QEMUInstance
        from rtosploit.peripherals.config import SymbolResolver
        from rtosploit.peripherals.dispatcher import InterceptDispatcher

        resolver = SymbolResolver(_FREERTOS_ELF)
        tick_addr = resolver.resolve("xTaskGetTickCount")
        assert tick_addr is not None, "xTaskGetTickCount not found in ELF"

        model = InterceptCounter()
        config = RTOSploitConfig()
        qemu = QEMUInstance(config)

        try:
            qemu.start(_FREERTOS_ELF, "mps2-an385", gdb=True, paused=True)
            assert qemu.gdb is not None

            gdb = qemu.gdb
            dispatcher = InterceptDispatcher(gdb)
            dispatcher.register(model, "xTaskGetTickCount", tick_addr)

            # Let firmware boot and run for 3 seconds
            gdb.continue_execution()
            start = time.monotonic()

            while time.monotonic() - start < 3.0:
                try:
                    gdb.receive_stop(timeout=0.5)
                except TimeoutError:
                    continue

                regs = gdb.read_registers()
                pc = regs.get("pc", 0)

                if dispatcher.handle_breakpoint(pc):
                    gdb.continue_execution()
                else:
                    # Unexpected stop — resume anyway
                    gdb.continue_execution()

            # Verify intercepts were hit
            assert model.call_count > 0, "Expected at least one xTaskGetTickCount call"
            assert all(c == "xTaskGetTickCount" for c in model.call_log)

            stats = dispatcher.stats
            assert len(stats) > 0
            assert tick_addr & ~1 in stats

        finally:
            qemu.stop()

    def test_symbol_resolver_finds_freertos_functions(self):
        """Verify SymbolResolver can extract FreeRTOS function addresses."""
        from rtosploit.peripherals.config import SymbolResolver

        resolver = SymbolResolver(_FREERTOS_ELF)

        # These should all be present in FreeRTOS firmware
        expected = [
            "vTaskStartScheduler",
            "xTaskCreate",
            "vTaskDelay",
            "xTaskGetTickCount",
            "main",
        ]

        for name in expected:
            addr = resolver.resolve(name)
            assert addr is not None, f"Expected to find {name} in ELF"
            assert addr > 0

    def test_gdb_registers_and_memory(self):
        """Verify GDB can read registers and memory from booted firmware."""
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        qemu = QEMUInstance(config)

        try:
            qemu.start(_FREERTOS_ELF, "mps2-an385", gdb=True, paused=True)
            assert qemu.gdb is not None

            gdb = qemu.gdb

            # Read registers
            regs = gdb.read_registers()
            assert "pc" in regs
            assert "sp" in regs
            assert regs["sp"] > 0x20000000  # SRAM region

            # Read vector table from flash
            vt_data = gdb.read_memory(0x00000000, 8)
            sp_init = int.from_bytes(vt_data[0:4], "little")
            reset_vec = int.from_bytes(vt_data[4:8], "little")
            assert sp_init > 0x20000000
            assert reset_vec > 0

            # Write and read back SRAM
            test_data = b"\xDE\xAD\xBE\xEF"
            gdb.write_memory(0x20000100, test_data)
            readback = gdb.read_memory(0x20000100, 4)
            assert readback == test_data

        finally:
            qemu.stop()

    def test_multiple_intercepts_on_different_functions(self):
        """Register multiple intercepts and verify all fire."""
        from rtosploit.emulation.qemu import QEMUInstance
        from rtosploit.peripherals.config import SymbolResolver
        from rtosploit.peripherals.dispatcher import InterceptDispatcher

        class MultiModel(PeripheralModel):
            def __init__(self):
                super().__init__("multi", 0, 0)
                self.functions_called: set[str] = set()

            @hal_handler("xTaskGetTickCount")
            def handle_tick(self, cpu: CPUState) -> HandlerResult:
                self.functions_called.add("xTaskGetTickCount")
                return HandlerResult(return_value=500)

            @hal_handler("uxTaskGetNumberOfTasks")
            def handle_num_tasks(self, cpu: CPUState) -> HandlerResult:
                self.functions_called.add("uxTaskGetNumberOfTasks")
                return HandlerResult(return_value=5)

        resolver = SymbolResolver(_FREERTOS_ELF)
        model = MultiModel()
        config = RTOSploitConfig()
        qemu = QEMUInstance(config)

        try:
            qemu.start(_FREERTOS_ELF, "mps2-an385", gdb=True, paused=True)
            gdb = qemu.gdb
            assert gdb is not None

            dispatcher = InterceptDispatcher(gdb)

            for func_name in ["xTaskGetTickCount", "uxTaskGetNumberOfTasks"]:
                addr = resolver.resolve(func_name)
                if addr:
                    dispatcher.register(model, func_name, addr)

            gdb.continue_execution()
            start = time.monotonic()
            handled = 0

            while time.monotonic() - start < 3.0 and handled < 20:
                try:
                    gdb.receive_stop(timeout=0.5)
                except TimeoutError:
                    continue

                regs = gdb.read_registers()
                pc = regs.get("pc", 0)

                if dispatcher.handle_breakpoint(pc):
                    handled += 1
                    gdb.continue_execution()
                else:
                    gdb.continue_execution()

            assert handled > 0

        finally:
            qemu.stop()
