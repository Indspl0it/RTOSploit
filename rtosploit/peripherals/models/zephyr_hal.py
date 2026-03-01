"""Zephyr RTOS peripheral models for firmware rehosting.

Implements handlers for Zephyr's device driver APIs, allowing Zephyr-based
firmware to run in QEMU without real hardware peripherals.
"""

from __future__ import annotations

import logging

from rtosploit.peripherals.model import (
    CPUState,
    HandlerResult,
    PeripheralModel,
    hal_handler,
)

logger = logging.getLogger(__name__)


class ZephyrBase(PeripheralModel):
    """Core Zephyr functions: device binding, readiness checks, sleep.

    device_get_binding returns a fake non-zero device pointer so firmware
    proceeds. Sleep functions skip the delay and return immediately.
    """

    def __init__(
        self,
        name: str = "zephyr_base",
        base_addr: int = 0,
        size: int = 0,
    ) -> None:
        super().__init__(name, base_addr, size)
        self._device_counter = 0xDEAD0000

    @hal_handler("device_get_binding")
    def handle_get_binding(self, cpu: CPUState) -> HandlerResult:
        self._device_counter += 1
        return HandlerResult(return_value=self._device_counter)

    @hal_handler("device_is_ready")
    def handle_is_ready(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=1)  # true

    @hal_handler(["k_sleep", "k_msleep"])
    def handle_sleep(self, cpu: CPUState) -> HandlerResult:
        delay = cpu.get_arg(0)
        logger.debug("k_sleep/k_msleep(%d) -- skipped", delay)
        return HandlerResult(return_value=0)

    @hal_handler("k_busy_wait")
    def handle_busy_wait(self, cpu: CPUState) -> HandlerResult:
        delay_us = cpu.get_arg(0)
        logger.debug("k_busy_wait(%d us) -- skipped", delay_us)
        return HandlerResult(return_value=None)  # void


class ZephyrUART(PeripheralModel):
    """Zephyr UART model with RX buffer injection.

    TX data is logged, RX reads from an injectable buffer.
    Supports both IRQ-driven and polled UART APIs.
    """

    def __init__(
        self,
        name: str = "zephyr_uart0",
        base_addr: int = 0x40002000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.tx_log: list[bytes] = []
        self.rx_buffer: bytearray = bytearray()

    def inject_rx(self, data: bytes) -> None:
        """Inject data into the receive buffer for the firmware to read."""
        self.rx_buffer.extend(data)

    @hal_handler("uart_irq_rx_enable")
    def handle_irq_rx_enable(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("uart_irq_rx_disable")
    def handle_irq_rx_disable(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("uart_fifo_read")
    def handle_fifo_read(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(1)
        size = cpu.get_arg(2)
        if buf_ptr and size > 0:
            available = min(size, len(self.rx_buffer))
            if available > 0:
                data = bytes(self.rx_buffer[:available])
                del self.rx_buffer[:available]
                cpu.write_memory(buf_ptr, data)
            return HandlerResult(return_value=available)
        return HandlerResult(return_value=0)

    @hal_handler("uart_fifo_fill")
    def handle_fifo_fill(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(1)
        size = cpu.get_arg(2)
        if buf_ptr and size > 0:
            data = cpu.read_memory(buf_ptr, size)
            self.tx_log.append(data)
            logger.debug("Zephyr UART TX: %r", data)
        return HandlerResult(return_value=size)  # all bytes sent

    @hal_handler("uart_poll_in")
    def handle_poll_in(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(1)
        if len(self.rx_buffer) > 0 and buf_ptr:
            byte = bytes([self.rx_buffer[0]])
            del self.rx_buffer[0:1]
            cpu.write_memory(buf_ptr, byte)
            return HandlerResult(return_value=0)  # 0 = success
        return HandlerResult(return_value=-1)  # -1 = no data

    @hal_handler("uart_poll_out")
    def handle_poll_out(self, cpu: CPUState) -> HandlerResult:
        char_val = cpu.get_arg(1)
        self.tx_log.append(bytes([char_val & 0xFF]))
        return HandlerResult(return_value=None)  # void


class ZephyrSPI(PeripheralModel):
    """Zephyr SPI model.

    All SPI operations return 0 (success). RX buffers are filled with zeros.
    """

    def __init__(
        self,
        name: str = "zephyr_spi0",
        base_addr: int = 0x40003000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.tx_log: list[bytes] = []

    @hal_handler(["spi_transceive", "spi_read"])
    def handle_transceive(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)

    @hal_handler("spi_write")
    def handle_write(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)


class ZephyrI2C(PeripheralModel):
    """Zephyr I2C model.

    All I2C operations return 0 (success). RX buffers are filled with zeros.
    """

    def __init__(
        self,
        name: str = "zephyr_i2c0",
        base_addr: int = 0x40003000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.tx_log: list[bytes] = []

    @hal_handler(["i2c_transfer", "i2c_read"])
    def handle_transfer(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)

    @hal_handler("i2c_write")
    def handle_write(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)


class ZephyrGPIO(PeripheralModel):
    """Zephyr GPIO model with pin state tracking.

    Tracks pin state as a dictionary for set/get/toggle operations.
    """

    def __init__(
        self,
        name: str = "zephyr_gpio0",
        base_addr: int = 0x50000000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self._pin_state: dict[int, int] = {}

    @hal_handler("gpio_pin_configure")
    def handle_configure(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)

    @hal_handler("gpio_pin_set")
    def handle_set(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(1)
        value = cpu.get_arg(2)
        self._pin_state[pin] = value
        return HandlerResult(return_value=0)

    @hal_handler("gpio_pin_get")
    def handle_get(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(1)
        value = self._pin_state.get(pin, 0)
        return HandlerResult(return_value=value)

    @hal_handler("gpio_pin_toggle")
    def handle_toggle(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(1)
        current = self._pin_state.get(pin, 0)
        self._pin_state[pin] = 0 if current else 1
        return HandlerResult(return_value=0)


class ZephyrBLE(PeripheralModel):
    """Zephyr BLE stub.

    All BLE operations return 0 (success).
    """

    def __init__(
        self,
        name: str = "zephyr_ble",
        base_addr: int = 0,
        size: int = 0,
    ) -> None:
        super().__init__(name, base_addr, size)

    @hal_handler("bt_enable")
    def handle_bt_enable(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)

    @hal_handler("bt_le_adv_start")
    def handle_adv_start(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)

    @hal_handler("bt_le_scan_start")
    def handle_scan_start(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)

    @hal_handler("bt_le_scan_stop")
    def handle_scan_stop(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)
