"""Unit tests for Zephyr RTOS peripheral models."""

from __future__ import annotations

from unittest.mock import MagicMock


from rtosploit.peripherals.model import CPUState
from rtosploit.peripherals.models.zephyr_hal import (
    ZephyrBase,
    ZephyrBLE,
    ZephyrGPIO,
    ZephyrI2C,
    ZephyrSPI,
    ZephyrUART,
)


def _cpu(r0=0, r1=0, r2=0, r3=0, gdb=None):
    """Create a CPUState with given argument registers."""
    regs = {"r0": r0, "r1": r1, "r2": r2, "r3": r3, "sp": 0x20008000, "lr": 0x08001001}
    return CPUState(regs=regs, _gdb=gdb)


# ---------------------------------------------------------------------------
# ZephyrBase
# ---------------------------------------------------------------------------

class TestZephyrBase:
    def test_zephyr_base_device_get_binding(self):
        m = ZephyrBase()
        result = m._find_handler("device_get_binding")(_cpu())
        assert result.intercept is True
        assert result.return_value != 0  # non-zero pointer
        assert result.return_value > 0xDEAD0000

    def test_zephyr_base_device_get_binding_unique(self):
        m = ZephyrBase()
        r1 = m._find_handler("device_get_binding")(_cpu())
        r2 = m._find_handler("device_get_binding")(_cpu())
        assert r1.return_value != r2.return_value  # unique pointers

    def test_zephyr_base_device_is_ready(self):
        m = ZephyrBase()
        result = m._find_handler("device_is_ready")(_cpu())
        assert result.return_value == 1

    def test_zephyr_base_k_sleep(self):
        m = ZephyrBase()
        result = m._find_handler("k_sleep")(_cpu(r0=100))
        assert result.return_value == 0

    def test_zephyr_base_k_msleep(self):
        m = ZephyrBase()
        result = m._find_handler("k_msleep")(_cpu(r0=500))
        assert result.return_value == 0

    def test_zephyr_base_k_busy_wait(self):
        m = ZephyrBase()
        result = m._find_handler("k_busy_wait")(_cpu(r0=1000))
        assert result.return_value is None  # void


# ---------------------------------------------------------------------------
# ZephyrUART
# ---------------------------------------------------------------------------

class TestZephyrUART:
    def test_zephyr_uart_irq_rx_enable(self):
        m = ZephyrUART()
        result = m._find_handler("uart_irq_rx_enable")(_cpu())
        assert result.return_value is None  # void

    def test_zephyr_uart_irq_rx_disable(self):
        m = ZephyrUART()
        result = m._find_handler("uart_irq_rx_disable")(_cpu())
        assert result.return_value is None  # void

    def test_zephyr_uart_fifo_read_with_data(self):
        gdb = MagicMock()
        m = ZephyrUART()
        m.inject_rx(b"\xAA\xBB\xCC")
        result = m._find_handler("uart_fifo_read")(_cpu(r1=0x20003000, r2=3, gdb=gdb))
        assert result.return_value == 3
        gdb.write_memory.assert_called_once_with(0x20003000, b"\xAA\xBB\xCC")
        assert len(m.rx_buffer) == 0

    def test_zephyr_uart_fifo_read_empty(self):
        gdb = MagicMock()
        m = ZephyrUART()
        result = m._find_handler("uart_fifo_read")(_cpu(r1=0x20003000, r2=4, gdb=gdb))
        assert result.return_value == 0
        gdb.write_memory.assert_not_called()

    def test_zephyr_uart_fifo_read_partial(self):
        gdb = MagicMock()
        m = ZephyrUART()
        m.inject_rx(b"\x01\x02")
        result = m._find_handler("uart_fifo_read")(_cpu(r1=0x20003000, r2=4, gdb=gdb))
        assert result.return_value == 2
        gdb.write_memory.assert_called_once_with(0x20003000, b"\x01\x02")

    def test_zephyr_uart_fifo_fill_logs(self):
        gdb = MagicMock()
        gdb.read_memory.return_value = b"hello zephyr"
        m = ZephyrUART()
        result = m._find_handler("uart_fifo_fill")(_cpu(r1=0x20002000, r2=12, gdb=gdb))
        assert result.return_value == 12
        assert len(m.tx_log) == 1
        assert m.tx_log[0] == b"hello zephyr"

    def test_zephyr_uart_poll_in_with_data(self):
        gdb = MagicMock()
        m = ZephyrUART()
        m.inject_rx(b"\x42")
        result = m._find_handler("uart_poll_in")(_cpu(r1=0x20003000, gdb=gdb))
        assert result.return_value == 0  # success
        gdb.write_memory.assert_called_once_with(0x20003000, b"\x42")
        assert len(m.rx_buffer) == 0

    def test_zephyr_uart_poll_in_empty(self):
        m = ZephyrUART()
        result = m._find_handler("uart_poll_in")(_cpu(r1=0x20003000))
        assert result.return_value == -1  # no data

    def test_zephyr_uart_poll_out(self):
        m = ZephyrUART()
        result = m._find_handler("uart_poll_out")(_cpu(r1=0x41))
        assert result.return_value is None  # void
        assert m.tx_log == [b"\x41"]


# ---------------------------------------------------------------------------
# ZephyrSPI
# ---------------------------------------------------------------------------

class TestZephyrSPI:
    def test_zephyr_spi_transceive(self):
        m = ZephyrSPI()
        result = m._find_handler("spi_transceive")(_cpu())
        assert result.return_value == 0

    def test_zephyr_spi_read(self):
        m = ZephyrSPI()
        result = m._find_handler("spi_read")(_cpu())
        assert result.return_value == 0

    def test_zephyr_spi_write(self):
        m = ZephyrSPI()
        result = m._find_handler("spi_write")(_cpu())
        assert result.return_value == 0


# ---------------------------------------------------------------------------
# ZephyrI2C
# ---------------------------------------------------------------------------

class TestZephyrI2C:
    def test_zephyr_i2c_transfer(self):
        m = ZephyrI2C()
        result = m._find_handler("i2c_transfer")(_cpu())
        assert result.return_value == 0

    def test_zephyr_i2c_read(self):
        m = ZephyrI2C()
        result = m._find_handler("i2c_read")(_cpu())
        assert result.return_value == 0

    def test_zephyr_i2c_write(self):
        m = ZephyrI2C()
        result = m._find_handler("i2c_write")(_cpu())
        assert result.return_value == 0


# ---------------------------------------------------------------------------
# ZephyrGPIO
# ---------------------------------------------------------------------------

class TestZephyrGPIO:
    def test_zephyr_gpio_configure(self):
        m = ZephyrGPIO()
        result = m._find_handler("gpio_pin_configure")(_cpu())
        assert result.return_value == 0

    def test_zephyr_gpio_set_get(self):
        m = ZephyrGPIO()
        m._find_handler("gpio_pin_set")(_cpu(r1=5, r2=1))
        result = m._find_handler("gpio_pin_get")(_cpu(r1=5))
        assert result.return_value == 1

    def test_zephyr_gpio_get_default(self):
        m = ZephyrGPIO()
        result = m._find_handler("gpio_pin_get")(_cpu(r1=7))
        assert result.return_value == 0

    def test_zephyr_gpio_toggle(self):
        m = ZephyrGPIO()
        # Default is 0, toggle to 1
        m._find_handler("gpio_pin_toggle")(_cpu(r1=3))
        result = m._find_handler("gpio_pin_get")(_cpu(r1=3))
        assert result.return_value == 1

        # Toggle back to 0
        m._find_handler("gpio_pin_toggle")(_cpu(r1=3))
        result = m._find_handler("gpio_pin_get")(_cpu(r1=3))
        assert result.return_value == 0

    def test_zephyr_gpio_set_returns_zero(self):
        m = ZephyrGPIO()
        result = m._find_handler("gpio_pin_set")(_cpu(r1=1, r2=1))
        assert result.return_value == 0

    def test_zephyr_gpio_toggle_returns_zero(self):
        m = ZephyrGPIO()
        result = m._find_handler("gpio_pin_toggle")(_cpu(r1=1))
        assert result.return_value == 0


# ---------------------------------------------------------------------------
# ZephyrBLE
# ---------------------------------------------------------------------------

class TestZephyrBLE:
    def test_zephyr_ble_enable(self):
        m = ZephyrBLE()
        result = m._find_handler("bt_enable")(_cpu())
        assert result.return_value == 0

    def test_zephyr_ble_adv_start(self):
        m = ZephyrBLE()
        result = m._find_handler("bt_le_adv_start")(_cpu())
        assert result.return_value == 0

    def test_zephyr_ble_scan_start(self):
        m = ZephyrBLE()
        result = m._find_handler("bt_le_scan_start")(_cpu())
        assert result.return_value == 0

    def test_zephyr_ble_scan_stop(self):
        m = ZephyrBLE()
        result = m._find_handler("bt_le_scan_stop")(_cpu())
        assert result.return_value == 0
